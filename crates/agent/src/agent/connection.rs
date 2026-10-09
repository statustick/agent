//! Connecting, the long-poll loop, settings from StatusTick and shutdown.
use super::*;

impl Agent {
    pub async fn run(self: &Arc<Self>) {
        let settings = &self.config.settings;
        let proxy = self.config.proxy.as_ref().map(|proxy| format!(" through proxy {}", proxy_label(proxy))).unwrap_or_default();
        let ca = settings.ca_file.as_ref().map(|file| format!(", extra CA certificates from {file}")).unwrap_or_default();
        let health = settings.health_port.map(|port| format!(", health checks on port {port}")).unwrap_or_default();
        let relay = settings.relay_port.map(|port| format!(", heartbeat relay on {}:{port}", settings.relay_host)).unwrap_or_default();
        let discovery = if settings.discovery { ", Kubernetes service discovery" } else { "" };
        let browser = self
            .browser
            .as_ref()
            .map(|browser| format!(", browser checks with Playwright {} ({} at a time)", statustick_browser::PLAYWRIGHT_VERSION, browser.support.concurrency))
            .unwrap_or_default();
        self.log(&format!(
            "StatusTick agent {VERSION} starting: host {}, {} checks at a time{browser}, {}{proxy}{ca}{health}{relay}{discovery}",
            settings.host_name, settings.concurrency, settings.url
        ));
        if let Some(mut changes) = self.chromium_changes.lock().expect("chromium changes").take() {
            let agent = self.clone();
            tokio::spawn(async move {
                while let Some(state) = changes.recv().await {
                    agent.chromium_changed(state).await;
                }
            });
        }
        self.log(sharing_line(settings.share_metrics));
        self.every(METRICS_PUSH, |agent| {
            let agent = agent.clone();
            tokio::spawn(async move { agent.push_metrics().await });
        });
        self.every(HEARTBEAT_CHECK, |agent| agent.heartbeat_if_quiet());
        self.every(OFFLINE_TICK, |agent| agent.offline_tick());
        self.every(DISCOVERY_RESYNC, |agent| agent.discovery_changed(0));
        while !self.stopped() {
            let attempt = async {
                if self.client.agent_id().is_none() {
                    self.connect().await?;
                }
                self.poll_once().await
            };
            match attempt.await {
                Ok(()) => self.lock().attempt = 0,
                Err(_) if self.stopped() => break,
                Err(error) => self.handle_error(error).await,
            }
        }
    }

    pub async fn stop(self: &Arc<Self>) {
        let started = now_ms();
        self.stop_tx.send_replace(true);
        let _ = tokio::time::timeout(Duration::from_millis(SHUTDOWN_GRACE_MS as u64), self.drain()).await;
        self.goodbye(GOODBYE_MS.min(started + SHUTDOWN_GRACE_MS - now_ms())).await;
    }

    /// Only a connected agent says it; after `agent.replaced` or a refused token there is no session to end.
    pub(super) async fn goodbye(&self, timeout_ms: i64) {
        if self.client.agent_id().is_none() || self.client.replaced() || timeout_ms <= 0 {
            return;
        }
        let _ = self.client.goodbye(Duration::from_millis(timeout_ms as u64)).await;
    }

    pub(super) async fn drain(self: &Arc<Self>) {
        self.slots.idle().await;
        loop {
            let done = self.work_done.notified();
            if !self.lock().flushing {
                break;
            }
            done.await;
        }
        self.flush().await;
        loop {
            let done = self.work_done.notified();
            if !self.lock().relaying {
                break;
            }
            done.await;
        }
        self.relay_upload().await;
    }

    pub(super) async fn connect(self: &Arc<Self>) -> Result<(), CallError> {
        let request = {
            let inner = self.lock();
            let mut body = Map::new();
            body.insert("hostName".into(), Value::from(self.config.settings.host_name.clone()));
            body.insert("os".into(), Value::from(os_name()));
            body.insert("arch".into(), Value::from(arch_name()));
            let mut capabilities = json!({ "browser": self.browser.as_ref().map(|browser| browser.support.json()) });
            if inner.relay.is_some() {
                capabilities["relay"] = Value::Bool(true);
            }
            body.insert("capabilities".into(), capabilities);
            if let Some(buffering) = inner.buffer.buffering() {
                body.insert("buffering".into(), buffering);
            }
            if let Some(share) = self.config.settings.share_metrics {
                body.insert("shareMetrics".into(), Value::Bool(share));
            }
            if let Value::Object(machine) = (self.machine)() {
                body.extend(machine);
            }
            body.insert("chromium".into(), Value::from(self.browser.as_ref().map(|browser| browser.chromium.state()).unwrap_or("off")));
            body.insert("envSettings".into(), json!(self.config.machine_settings));
            let browser_runs = self.browser.as_ref().map(|browser| browser.slots.size()).unwrap_or(0);
            body.insert(
                "applied".into(),
                json!({ "browserConcurrency": browser_runs, "concurrency": self.slots.size(), "shareMetrics": inner.sharing_metrics }),
            );
            Value::Object(body)
        };
        let answer = self.client.connect(&request).await?;
        let reconnect = {
            let mut inner = self.lock();
            inner.connects += 1;
            inner.connects > 1
        };
        if reconnect {
            self.metrics.reconnected();
        }
        self.apply_settings(answer.get("settings"), answer.get("shareMetrics"));
        let relay_line = {
            let mut inner = self.lock();
            inner.upload_refused = false;
            inner.relay_refused = false;
            let relay_line = inner.relay.as_mut().and_then(|relay| {
                relay.list.update(answer.get("relay"));
                (!relay.list.received()).then_some("Heartbeat relay: StatusTick sent no ping list; the relay answers 503 until it does.")
            });
            let mut server = Server::default();
            if let Some(config) = answer.get("config").and_then(Value::as_object) {
                if let Some(max) = config.get("maxJobs").and_then(Value::as_f64) {
                    server.max_jobs = max.max(0.0) as usize;
                }
                if let Some(wait) = config.get("pollWaitSeconds").and_then(Value::as_f64) {
                    server.poll_wait_seconds = wait.max(0.0) as u64;
                }
                if let Some(heartbeat) = config.get("heartbeatSeconds").and_then(Value::as_f64) {
                    server.heartbeat_seconds = heartbeat as i64;
                }
            }
            inner.server = server;
            inner.location = answer.get("location").filter(|location| location.is_object()).cloned();
            relay_line
        };
        if let Some(line) = relay_line {
            self.log(line);
        }
        self.mark_connected();
        for notice in update_notices(VERSION, &answer) {
            self.log(&notice);
        }
        Ok(())
    }

    pub(super) fn mark_connected(self: &Arc<Self>) {
        let location = self
            .lock()
            .location
            .as_ref()
            .and_then(|location| location.get("name"))
            .and_then(Value::as_str)
            .map(|name| format!(" (location \"{name}\")"))
            .unwrap_or_default();
        let id = self.client.agent_id().unwrap_or_default();
        self.set_state(State::Connected, &format!("Connected to {} as {id}{location}.", self.config.settings.url));
        self.end_outage();
        self.start_upload();
        self.start_relay();
        if self.lock().discovery.dirty {
            self.start_discovery();
        }
    }

    /// The agent's dashboard settings from a connect or lease answer, applied at once and logged once per change. A
    /// value set on the machine wins.
    pub(super) fn apply_settings(&self, settings: Option<&Value>, share_metrics: Option<&Value>) {
        let share_health = settings.and_then(|settings| settings.get("shareHealth")).and_then(Value::as_bool);
        self.share_metrics(share_health.or_else(|| share_metrics.and_then(Value::as_bool)));
        let Some(settings) = settings.filter(|settings| settings.is_object()) else { return };
        if !self.config.machine_settings.contains(&"STATUSTICK_CONCURRENCY")
            && let Some(max) = whole(settings.get("maxChecks"), 1, MAX_CONCURRENCY as i64)
            && max as usize != self.slots.size()
        {
            self.log(&format!("Checks at once: {} → {max}, from the dashboard", self.slots.size()));
            self.slots.resize(max as usize);
        }
        if let Some(browser) = &self.browser
            && !self.config.machine_settings.contains(&"BROWSER_CONCURRENCY")
            && let Some(runs) = whole(settings.get("browserRuns"), 0, crate::browser::MAX_BROWSER_CONCURRENCY as i64)
            && runs as usize != browser.slots.size()
        {
            let shown = |runs: usize| if runs == 0 { "Off".to_string() } else { runs.to_string() };
            self.log(&format!("Browser runs at once: {} → {}, from the dashboard", shown(browser.slots.size()), shown(runs as usize)));
            browser.slots.resize(runs as usize);
            browser.chromium.enable(runs > 0);
        }
        if let Some(paused) = settings.get("paused").and_then(Value::as_bool) {
            let changed = {
                let mut inner = self.lock();
                let changed = inner.paused != paused;
                inner.paused = paused;
                changed
            };
            if changed {
                self.log(if paused { "Paused from the dashboard" } else { "Resumed from the dashboard" });
            }
        }
    }

    pub(super) async fn poll_once(self: &Arc<Self>) -> Result<(), CallError> {
        self.slots.wait_for_free().await;
        if self.stopped() {
            return Ok(());
        }
        let (max, wait, relay) = {
            let inner = self.lock();
            let max = self.slots.free().min(inner.server.max_jobs).clamp(1, MAX_JOBS_PER_CALL);
            let relay = inner.relay.as_ref().map(|relay| relay.list.version.clone().unwrap_or_default());
            (max, inner.server.poll_wait_seconds.min(MAX_POLL_WAIT_SECONDS), relay)
        };
        let started = Instant::now();
        let mut stop = self.stop_tx.subscribe();
        let answer = tokio::select! {
            answer = self.client.lease_jobs(max, wait, relay.as_deref()) => answer?,
            _ = stop.changed() => return Ok(()),
        };
        if let Some(relay) = self.lock().relay.as_mut()
            && let Some(list) = answer.get("relay").filter(|list| !list.is_null())
        {
            relay.list.update(Some(list));
        }
        self.apply_settings(answer.get("settings"), answer.get("shareMetrics"));
        self.mark_connected();
        let jobs: Vec<Value> = if self.paused() {
            Vec::new()
        } else {
            answer.get("jobs").and_then(Value::as_array).map(|jobs| jobs.iter().take(max).cloned().collect()).unwrap_or_default()
        };
        if jobs.is_empty() && started.elapsed() < Duration::from_millis(MIN_EMPTY_POLL_MS) {
            self.wait(MIN_EMPTY_POLL_MS).await;
        }
        for job in jobs {
            self.lock().memory.remember(&job, now_ms());
            let slot = self.slots.take();
            let agent = self.clone();
            tokio::spawn(async move {
                let checked_at = iso(now_ms());
                let entry = agent.run_one(&job).await;
                let result = &entry["result"];
                agent.metrics.check(
                    job["type"].as_str().unwrap_or(""),
                    &result["status"].as_str().map(str::to_string).unwrap_or_else(|| result["status"].to_string()),
                    result["responseTime"].as_f64().unwrap_or(f64::NAN),
                );
                let late = late_of(&job, &checked_at, &entry);
                drop(slot);
                agent.queue_result(entry, job.get("expiresAt").and_then(Value::as_str), late);
            });
        }
        Ok(())
    }

    pub(super) async fn handle_error(self: &Arc<Self>, error: CallError) {
        if error.is_outage() {
            self.lock().outage_since.get_or_insert(now_ms());
            self.offline_tick();
        } else {
            self.end_outage();
        }
        let url = &self.config.settings.url;
        if error.status() == Some(426) {
            self.client.forget_agent();
            let message = error.body_text("message").filter(|message| !message.is_empty()).unwrap_or_else(|| {
                let minimum = match &error {
                    CallError::Api { body, .. } => {
                        body.get("minimumVersion").map(|version| version.as_str().map(str::to_string).unwrap_or_else(|| version.to_string()))
                    }
                    _ => None,
                };
                match minimum {
                    Some(minimum) => format!("Install version {minimum} or later."),
                    None => "Install the latest version.".into(),
                }
            });
            self.set_state(State::UpdateRequired, &format!("Update required: {message} Polling stopped."));
            return self.idle_until_stopped().await;
        }
        if error.code() == Some(REPLACED) {
            self.client.forget_agent();
            self.set_state(
                State::Replaced,
                "Another machine connected with this agent's token. This one stopped taking checks; give each machine its own agent.",
            );
            return self.idle_until_stopped().await;
        }
        let message_or = |fallback: &str| error.body_text("message").filter(|message| !message.is_empty()).unwrap_or_else(|| fallback.to_string());
        let proxy_status = match &error {
            CallError::Network { proxy_status, .. } => *proxy_status,
            _ => None,
        };
        match error.code() {
            Some("agent.unauthorized") => self.client.forget_agent(),
            Some("token.unauthorized") => {
                self.client.forget_agent();
                self.set_state(State::TokenRejected, "Token rejected: check STATUSTICK_TOKEN, or rotate this agent's token on its page in StatusTick and restart with the new one. Retrying with backoff.");
            }
            Some("token.rotated") => {
                self.client.forget_agent();
                self.set_state(State::TokenRotated, &format!("{}. Retrying with backoff.", message_or("Token rotated; set the new STATUSTICK_TOKEN")));
            }
            Some("token.revoked") => {
                self.client.forget_agent();
                self.set_state(State::TokenRevoked, &format!("{}. Retrying with backoff.", message_or("Token revoked; set a new STATUSTICK_TOKEN")));
            }
            _ => match (&self.config.proxy, proxy_status) {
                (Some(proxy), Some(status)) => {
                    self.set_state(
                        State::ProxyRefused,
                        &format!("Proxy {} blocked the connection to {url}: HTTP {status}. Retrying with backoff.", proxy_label(proxy)),
                    );
                }
                _ if error.status() != Some(429) => {
                    let through = self.config.proxy.as_ref().map(|proxy| format!(" (through proxy {})", proxy_label(proxy))).unwrap_or_default();
                    self.set_state(State::Disconnected, &format!("Disconnected: {}{through}. Retrying with backoff.", error.describe()));
                }
                _ => {}
            },
        }
        let delay = error.retry_after_ms().unwrap_or_else(|| {
            let mut inner = self.lock();
            let attempt = inner.attempt;
            inner.attempt += 1;
            backoff_delay(attempt)
        });
        self.wait(delay).await;
    }

    pub(super) async fn idle_until_stopped(&self) {
        while !self.stopped() {
            self.wait(IDLE_WAKE.as_millis() as u64).await;
        }
    }
}
