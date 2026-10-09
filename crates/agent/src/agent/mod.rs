//! Pull mode: connects out, long-polls for jobs, runs them and posts the results; repeats the
//! remembered jobs and buffers their results while StatusTick is unreachable; forwards relayed heartbeat pings and
//! discovered Kubernetes Services.
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};
use statustick_checks::proxy::proxy_label;
use tokio::sync::{Notify, watch};

use crate::VERSION;
use crate::buffer::{JobMemory, LineBuffer, Log, result_buffer};
use crate::client::{CallError, Client, REPLACED, now_ms};
use crate::config::Config;
use crate::metrics::{AgentMetrics, Snapshot};
use crate::relay::{PingAllowList, RelayAnswer, ping_buffer};
use crate::schema::valid_schedule;
use crate::settings::MAX_CONCURRENCY;

mod connection;
mod discovery;
mod relay;
mod results;
mod sharing;

const MAX_JOBS_PER_CALL: usize = 20;
const MAX_RESULTS_PER_CALL: usize = 20;
const MAX_POLL_WAIT_SECONDS: u64 = 30;
const HEARTBEAT_CHECK: Duration = Duration::from_secs(5);
const BACKOFF_BASE_MS: f64 = 1000.0;
const BACKOFF_MAX_MS: f64 = 60000.0;
const MIN_EMPTY_POLL_MS: u64 = 1000;
const IDLE_WAKE: Duration = Duration::from_secs(3600);
const SHUTDOWN_GRACE_MS: i64 = 8000;
const GOODBYE_MS: i64 = 5000;
const OFFLINE_TICK: Duration = Duration::from_secs(1);
const OFFLINE_CHECKS_FOR_MS: i64 = 60 * 60 * 1000;
const MAX_LATE_RESULTS_PER_CALL: usize = 500;
const MAX_LATE_RESULTS_BYTES: usize = 200 * 1024;
const READY_WITHIN_MS: i64 = 2 * 60 * 1000;
const RELAY_BATCH: Duration = Duration::from_secs(1);
const MAX_RELAYED_PINGS_PER_CALL: usize = 500;
const DISCOVERY_DEBOUNCE_MS: u64 = 2000;
const DISCOVERY_RESYNC: Duration = Duration::from_secs(5 * 60);
const DISCOVERY_RETRY_MS: u64 = 30000;
const DISCOVERY_BUSY_RETRY_MS: u64 = 15000;
const MAX_DISCOVERED_PER_CALL: usize = 500;
const MAX_SKIPPED_LOGGED: usize = 20;
const METRICS_PUSH: Duration = Duration::from_secs(60);

/// Exponential backoff with jitter: half of the ceiling plus a random part of the other half.
pub fn backoff_delay(attempt: u32) -> u64 {
    let ceiling = BACKOFF_MAX_MS.min(BACKOFF_BASE_MS * 2f64.powi(attempt.min(30) as i32));
    (ceiling / 2.0 + rand::random::<f64>() * ceiling / 2.0).round() as u64
}

fn iso(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map(statustick_checks::util::iso).unwrap_or_default()
}

/// Bounds how many checks run at once; a smaller size lets running checks finish and starts no new one above it.
pub struct Slots {
    state: Mutex<(usize, usize)>,
    changed: Notify,
}

pub struct Slot(Arc<Slots>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.state.lock().expect("slots").0 -= 1;
        self.0.changed.notify_waiters();
    }
}

impl Slots {
    pub fn new(size: usize) -> Arc<Self> {
        Arc::new(Slots { state: Mutex::new((0, size)), changed: Notify::new() })
    }

    pub fn active(&self) -> usize {
        self.state.lock().expect("slots").0
    }

    pub fn size(&self) -> usize {
        self.state.lock().expect("slots").1
    }

    pub fn free(&self) -> usize {
        let (active, size) = *self.state.lock().expect("slots");
        size.saturating_sub(active)
    }

    pub fn resize(&self, size: usize) {
        self.state.lock().expect("slots").1 = size;
        self.changed.notify_waiters();
    }

    pub async fn wait_for_free(&self) {
        loop {
            let notified = self.changed.notified();
            if self.free() > 0 {
                return;
            }
            notified.await;
        }
    }

    pub async fn idle(&self) {
        loop {
            let notified = self.changed.notified();
            if self.active() == 0 {
                return;
            }
            notified.await;
        }
    }

    /// Waits for a free slot and takes it in the same step, so two waiters never share one.
    pub async fn take_when_free(self: &Arc<Self>) -> Slot {
        loop {
            let notified = self.changed.notified();
            {
                let mut state = self.state.lock().expect("slots");
                if state.0 < state.1 {
                    state.0 += 1;
                    return Slot(self.clone());
                }
            }
            notified.await;
        }
    }

    pub fn take(self: &Arc<Self>) -> Slot {
        self.state.lock().expect("slots").0 += 1;
        Slot(self.clone())
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum State {
    Connected,
    Disconnected,
    TokenRejected,
    TokenRotated,
    TokenRevoked,
    ProxyRefused,
    UpdateRequired,
    Replaced,
}

struct Pending {
    result: Value,
    expires_at: Option<i64>,
    late: Option<Value>,
}

struct Server {
    max_jobs: usize,
    poll_wait_seconds: u64,
    heartbeat_seconds: i64,
}

impl Default for Server {
    fn default() -> Self {
        Server { max_jobs: 20, poll_wait_seconds: 25, heartbeat_seconds: 30 }
    }
}

struct Relay {
    list: PingAllowList,
    pings: LineBuffer,
}

#[derive(Default)]
struct Discovery {
    desired: Option<Arc<dyn Fn() -> Option<Vec<Value>> + Send + Sync>>,
    timer: bool,
    sending: bool,
    dirty: bool,
    skipped: String,
    limit_logged: bool,
}

struct Inner {
    server: Server,
    location: Option<Value>,
    state: Option<State>,
    attempt: u32,
    pending: Vec<Pending>,
    flushing: bool,
    heartbeating: bool,
    buffer: LineBuffer,
    memory: JobMemory,
    outage_since: Option<i64>,
    offline: bool,
    uploading: bool,
    upload_refused: bool,
    offline_limit_logged: bool,
    sharing_metrics: bool,
    paused: bool,
    connects: u64,
    relay: Option<Relay>,
    relay_timer: bool,
    relaying: bool,
    relay_refused: bool,
    discovery: Discovery,
}

/// Browser checks on this agent: their runs at once, the sandbox and Chromium's state.
pub struct Browser {
    pub support: crate::browser::BrowserSupport,
    pub sandbox: statustick_browser::Sandbox,
    pub slots: Arc<Slots>,
    pub chromium: Arc<crate::browser::ChromiumRuntime>,
}

pub struct Agent {
    config: Config,
    pub browser: Option<Browser>,
    chromium_changes: Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<&'static str>>>,
    pub client: Client,
    log: Log,
    pub slots: Arc<Slots>,
    pub metrics: AgentMetrics,
    inner: Mutex<Inner>,
    stop_tx: watch::Sender<bool>,
    machine: Box<dyn Fn() -> Value + Send + Sync>,
    work_done: Notify,
}

fn sharing_line(choice: Option<bool>) -> &'static str {
    match choice {
        Some(false) => "Sharing agent health with StatusTick: off for good (STATUSTICK_SHARE_METRICS=false).",
        Some(true) => "Sharing agent health with StatusTick: on (STATUSTICK_SHARE_METRICS=true). It sends its metrics every minute.",
        None => "Sharing agent health with StatusTick: off until the agent's setting in the dashboard turns it on.",
    }
}

fn version_parts(version: &str) -> [u64; 3] {
    let found = regex::Regex::new(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?").expect("valid pattern");
    let Some(captures) = found.captures(version) else { return [0, 0, 0] };
    let part = |index: usize| captures.get(index).and_then(|part| part.as_str().parse().ok()).unwrap_or(0);
    [part(1), part(2), part(3)]
}

/// The lines the agent logs on connect when it is older than StatusTick recommends or will soon require.
pub fn update_notices(version: &str, answer: &Value) -> Vec<String> {
    let older = |other: &str| version_parts(version) < version_parts(other);
    if let Some(upcoming) = answer.get("upcomingMinimum").filter(|upcoming| upcoming.is_object())
        && let (Some(minimum), Some(from)) = (upcoming.get("version").and_then(Value::as_str), upcoming.get("from").and_then(Value::as_str))
        && older(minimum)
    {
        let day: String = from.chars().take(10).collect();
        return vec![format!("Update required from {day}: StatusTick will refuse agents older than {minimum} (this agent runs {version}).")];
    }
    match answer.get("recommendedVersion").and_then(Value::as_str) {
        Some(recommended) if !recommended.is_empty() && older(recommended) => {
            vec![format!("Update available: version {recommended} (this agent runs {version}).")]
        }
        _ => Vec::new(),
    }
}

fn late_of(job: &Value, checked_at: &str, entry: &Value) -> Option<Value> {
    let kind = job.get("type").and_then(Value::as_str).unwrap_or("");
    if kind == "browser" || kind == "ssl" {
        return None;
    }
    let (monitor_id, _) = valid_schedule(job.get("schedule"))?;
    Some(json!({ "monitorId": monitor_id, "checkedAt": checked_at, "result": entry["result"] }))
}

fn os_name() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    }
}

fn arch_name() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

fn whole(value: Option<&Value>, min: i64, max: i64) -> Option<i64> {
    value.and_then(Value::as_f64).filter(|number| number.fract() == 0.0 && *number >= min as f64 && *number <= max as f64).map(|number| number as i64)
}

impl Agent {
    pub fn new(
        config: Config,
        log: Log,
        machine: Box<dyn Fn() -> Value + Send + Sync>,
        browser: Option<(crate::browser::BrowserSupport, statustick_browser::Sandbox)>,
    ) -> Arc<Self> {
        let settings = &config.settings;
        let dir = settings.buffer_dir.as_deref();
        let relay =
            settings.relay_port.map(|_| Relay { list: PingAllowList::new(dir, log.clone()), pings: ping_buffer(settings.buffer_size, dir, log.clone()) });
        let inner = Inner {
            server: Server::default(),
            location: None,
            state: None,
            attempt: 0,
            pending: Vec::new(),
            flushing: false,
            heartbeating: false,
            buffer: result_buffer(settings.buffer_size, dir, log.clone()),
            memory: JobMemory::new(dir, log.clone(), now_ms()),
            outage_since: None,
            offline: false,
            uploading: false,
            upload_refused: false,
            offline_limit_logged: false,
            sharing_metrics: settings.share_metrics == Some(true),
            paused: false,
            connects: 0,
            relay,
            relay_timer: false,
            relaying: false,
            relay_refused: false,
            discovery: Discovery::default(),
        };
        let client = Client::new(&settings.url, &settings.token, config.proxy.as_ref());
        let metrics = AgentMetrics::new(VERSION, settings.relay_port.is_some(), browser.is_some());
        let slots = Slots::new(settings.concurrency);
        let (stop_tx, _) = watch::channel(false);
        let (changes_tx, changes_rx) = tokio::sync::mpsc::unbounded_channel();
        let browser = browser.map(|(support, sandbox)| Browser {
            slots: Slots::new(support.concurrency),
            support,
            sandbox,
            chromium: crate::browser::ChromiumRuntime::new(
                Box::new(move |state| {
                    let _ = changes_tx.send(state);
                }),
                crate::browser::CHROMIUM_IDLE,
            ),
        });
        Arc::new(Agent {
            config,
            browser,
            chromium_changes: Mutex::new(Some(changes_rx)),
            client,
            log,
            slots,
            metrics,
            inner: Mutex::new(inner),
            stop_tx,
            machine,
            work_done: Notify::new(),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("agent state")
    }

    fn log(&self, line: &str) {
        (self.log)(line);
    }

    pub fn stopped(&self) -> bool {
        *self.stop_tx.borrow()
    }

    /// Waits [ms] or until the agent stops.
    async fn wait(&self, ms: u64) {
        let mut stop = self.stop_tx.subscribe();
        if *stop.borrow() {
            return;
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(ms)) => {}
            _ = stop.changed() => {}
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        let inner = self.lock();
        Snapshot {
            connected: inner.state == Some(State::Connected),
            last_contact_ms: self.client.last_call_ms(),
            jobs: self.slots.active(),
            buffer_results: inner.buffer.count(),
            buffer_dropped_total: inner.buffer.dropped_total,
            browser_runs_active: self.browser.as_ref().map(|browser| browser.slots.active()).unwrap_or(0),
            browser_concurrency: self.browser.as_ref().map(|browser| browser.slots.size()).unwrap_or(0),
        }
    }

    /// For `/readyz`: connected, and StatusTick answered a call in the last two minutes.
    pub fn ready(&self) -> bool {
        !self.stopped() && self.lock().state == Some(State::Connected) && now_ms() - self.client.last_call_ms() < READY_WITHIN_MS
    }

    pub fn paused(&self) -> bool {
        self.lock().paused
    }

    fn set_state(&self, state: State, message: &str) {
        let changed = {
            let mut inner = self.lock();
            let changed = inner.state != Some(state);
            inner.state = Some(state);
            changed
        };
        if changed {
            self.log(message);
        }
    }

    fn every(self: &Arc<Self>, period: Duration, tick: fn(&Arc<Agent>)) {
        let agent = self.clone();
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(period);
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            timer.tick().await;
            let mut stop = agent.stop_tx.subscribe();
            loop {
                tokio::select! {
                    _ = timer.tick() => tick(&agent),
                    _ = stop.changed() => return,
                }
            }
        });
    }

    /// Browser runs also wait for one of the BROWSER_CONCURRENCY slots, so they cannot use up the host's memory.
    async fn run_one(self: &Arc<Self>, job: &Value) -> Value {
        let Some(browser) = self.browser.as_ref().filter(|_| job.get("type").and_then(Value::as_str) == Some("browser")) else {
            return crate::jobs::run_job(job).await;
        };
        let lease_id = job.get("leaseId").cloned().unwrap_or(Value::Null);
        if browser.slots.size() == 0 {
            return json!({ "leaseId": lease_id, "result": { "status": "error", "responseTime": 0, "error": "Browser runs are off on this agent." } });
        }
        let _slot = browser.slots.take_when_free().await;
        let check = crate::jobs::without_nulls(job.get("check"));
        browser.chromium.started();
        let outcome = crate::browser::run_browser_check(&browser.sandbox, &check).await;
        browser.chromium.finished(outcome.is_ok());
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(message) => {
                let result = crate::jobs::for_platform(
                    json!({ "status": "error", "responseTime": 0, "error": crate::browser::browser_error(&message) }).as_object().cloned().unwrap_or_default(),
                );
                return json!({ "leaseId": lease_id, "result": result });
            }
        };
        let (mut screenshot, mut trace) = (false, false);
        let lease = lease_id.as_str().unwrap_or("").to_string();
        for artifact in outcome.artifacts {
            // A run without its files still counts; the dashboard then shows no screenshot or trace.
            if self.client.upload_artifact(&lease, artifact.name, artifact.data).await.is_ok() {
                if artifact.kind == "screenshot" { screenshot = true } else { trace = true }
            }
        }
        json!({ "leaseId": lease_id, "result": crate::jobs::for_platform(crate::browser::documented_browser_result(&outcome.run, screenshot, trace)) })
    }

    /// StatusTick learns of each Chromium change at once; while not connected, the next connect carries it.
    async fn chromium_changed(&self, state: &'static str) {
        if self.stopped() || self.client.agent_id().is_none() {
            return;
        }
        let _ = self.client.heartbeat(Some(&json!({ "chromium": state }))).await;
    }

    fn heartbeat_if_quiet(self: &Arc<Self>) {
        {
            let mut inner = self.lock();
            let quiet = now_ms() - self.client.last_call_ms();
            if self.stopped() || inner.heartbeating || self.client.agent_id().is_none() || quiet < inner.server.heartbeat_seconds * 1000 {
                return;
            }
            inner.heartbeating = true;
        }
        let agent = self.clone();
        tokio::spawn(async move {
            let _ = agent.client.heartbeat(None).await;
            agent.lock().heartbeating = false;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backs_off_exponentially_up_to_one_minute() {
        for _ in 0..20 {
            let first = backoff_delay(0);
            assert!((500..=1000).contains(&first));
            let late = backoff_delay(10);
            assert!((30000..=60000).contains(&late));
        }
    }

    #[test]
    fn tells_an_old_agent_to_update() {
        let required =
            update_notices("1.0.0", &json!({ "upcomingMinimum": { "version": "1.2.0", "from": "2026-11-01T00:00:00Z" }, "recommendedVersion": "1.3.0" }));
        assert_eq!(required, vec!["Update required from 2026-11-01: StatusTick will refuse agents older than 1.2.0 (this agent runs 1.0.0)."]);
        assert_eq!(update_notices("1.0.0", &json!({ "recommendedVersion": "1.0.1" })), vec!["Update available: version 1.0.1 (this agent runs 1.0.0)."]);
        assert!(update_notices("1.1.0", &json!({ "recommendedVersion": "1.0.1" })).is_empty());
    }

    #[tokio::test]
    async fn lets_a_waiting_task_run_once_a_slot_is_free() {
        let slots = Slots::new(1);
        let slot = slots.take();
        assert_eq!(slots.free(), 0);
        let waiting = {
            let slots = slots.clone();
            tokio::spawn(async move { slots.wait_for_free().await })
        };
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!waiting.is_finished());
        drop(slot);
        tokio::time::timeout(Duration::from_secs(1), waiting).await.unwrap().unwrap();
        slots.resize(3);
        assert_eq!(slots.free(), 3);
    }
}
