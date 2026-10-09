//! Browser checks on the agent: each run is its own `node run.mts` of the sandbox (`sandbox/`),
//! as one of the run users when the container allows it, behind a proxy that applies the agent's target policy.
pub mod proxy;

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};
use statustick_browser::sandbox::random_uuid;
use statustick_browser::validate::{ScriptError, validate_script, validate_variables};
use statustick_browser::{Artifact, CHROMIUM_VERSION, PLAYWRIGHT_VERSION, RunError, Sandbox, error_result, run_result};
use statustick_checks::util::utf16_prefix;

use crate::settings::{Env, env_value};
use proxy::RunProxy;

pub const RUNNER_DIR: &str = "/runner";
pub const RUN_AS: &str = "/usr/local/bin/statustick-run-as";
pub const MAX_BROWSER_CONCURRENCY: usize = 8;
const DEFAULT_BROWSER_CONCURRENCY: usize = 1;
pub const CHROMIUM_IDLE: Duration = Duration::from_secs(5 * 60);
/// A browser script can put page text into its error texts and step titles, so they leave cut short.
pub const MAX_BROWSER_ERROR_CHARS: usize = 200;
pub const MAX_STEP_TITLE_CHARS: usize = 120;
const POLICY: &str = "target not allowed by agent policy";

/// What the agent reports as browser support; null without the runner files or with BROWSER_CONCURRENCY=0.
#[derive(Clone, Debug)]
pub struct BrowserSupport {
    pub concurrency: usize,
}

impl BrowserSupport {
    pub fn json(&self) -> Value {
        json!({ "playwright": PLAYWRIGHT_VERSION, "chromium": CHROMIUM_VERSION, "concurrency": self.concurrency })
    }
}

/// BROWSER_CONCURRENCY: 0 to 8, default 1.
pub fn browser_concurrency(env: &Env) -> Result<usize, String> {
    let message = || "BROWSER_CONCURRENCY must be a whole number from 0 to 8".to_string();
    match env_value(env, "BROWSER_CONCURRENCY") {
        None | Some("") => Ok(DEFAULT_BROWSER_CONCURRENCY),
        Some(text) => text
            .trim()
            .parse::<f64>()
            .ok()
            .filter(|n| n.fract() == 0.0 && (0.0..=MAX_BROWSER_CONCURRENCY as f64).contains(n))
            .map(|n| n as usize)
            .ok_or_else(message),
    }
}

/// The image has the runner files and the browsers path; without them, or with BROWSER_CONCURRENCY=0, no support.
pub fn browser_support(env: &Env, runner_dir: &Path) -> Result<Option<BrowserSupport>, String> {
    if !runner_dir.join("run.mts").exists() || env_value(env, "PLAYWRIGHT_BROWSERS_PATH").is_none_or(str::is_empty) {
        return Ok(None);
    }
    let concurrency = browser_concurrency(env)?;
    Ok((concurrency > 0).then_some(BrowserSupport { concurrency }))
}

/// The sandbox, with run users when STATUSTICK_BROWSER_ISOLATION allows them and the container lets the agent switch:
/// the line to log, or the start error with `user` when it cannot.
pub async fn sandbox(isolation: &str, browsers: &str) -> Result<(Sandbox, Option<String>), String> {
    let plain = || Sandbox::new(RUNNER_DIR.into(), std::env::temp_dir(), browsers.into(), None, MAX_BROWSER_CONCURRENCY);
    if isolation == "off" {
        return Ok((plain(), None));
    }
    let isolated = Sandbox::new(RUNNER_DIR.into(), std::env::temp_dir(), browsers.into(), Some(RUN_AS.into()), MAX_BROWSER_CONCURRENCY);
    if isolated.isolation_available().await {
        return Ok((isolated, Some("Browser runs are isolated: each runs as its own user.".into())));
    }
    let missing = "the container must have the SETUID and SETGID capabilities and no \"no-new-privileges\" option";
    if isolation == "user" {
        return Err(format!("STATUSTICK_BROWSER_ISOLATION=user: {missing}"));
    }
    Ok((plain(), Some(format!("Browser runs are not isolated from the agent's user: {missing}. See \"Browser checks\" in the agent docs."))))
}

/// `off`, `starting`, `ready` or `failed`.
pub type ChromiumState = &'static str;

struct RuntimeState {
    state: ChromiumState,
    active: usize,
    enabled: bool,
    generation: u64,
}

/// Chromium on this agent: off until the first browser run, ready while runs keep coming, off again after the idle
/// time. Each run still gets its own fresh browser that ends with the run.
pub struct ChromiumRuntime {
    state: Mutex<RuntimeState>,
    on_change: Box<dyn Fn(ChromiumState) + Send + Sync>,
    idle: Duration,
}

impl ChromiumRuntime {
    pub fn new(on_change: Box<dyn Fn(ChromiumState) + Send + Sync>, idle: Duration) -> Arc<Self> {
        Arc::new(ChromiumRuntime { state: Mutex::new(RuntimeState { state: "off", active: 0, enabled: true, generation: 0 }), on_change, idle })
    }

    pub fn state(&self) -> ChromiumState {
        self.state.lock().expect("chromium").state
    }

    fn set(&self, state: ChromiumState) {
        let changed = {
            let mut inner = self.state.lock().expect("chromium");
            let changed = inner.state != state;
            inner.state = state;
            changed
        };
        if changed {
            (self.on_change)(state);
        }
    }

    pub fn started(&self) {
        let off = {
            let mut inner = self.state.lock().expect("chromium");
            inner.active += 1;
            inner.generation += 1;
            inner.state == "off"
        };
        if off {
            self.set("starting");
        }
    }

    pub fn finished(self: &Arc<Self>, ok: bool) {
        self.set(if ok { "ready" } else { "failed" });
        let (idle_now, generation) = {
            let mut inner = self.state.lock().expect("chromium");
            inner.active -= 1;
            (inner.active == 0, inner.generation)
        };
        if !idle_now {
            return;
        }
        if !self.state.lock().expect("chromium").enabled {
            self.set("off");
            return;
        }
        let runtime = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(runtime.idle).await;
            let still_idle = {
                let inner = runtime.state.lock().expect("chromium");
                inner.active == 0 && inner.generation == generation
            };
            if still_idle {
                runtime.set("off");
            }
        });
    }

    pub fn enable(&self, enabled: bool) {
        let off = {
            let mut inner = self.state.lock().expect("chromium");
            inner.enabled = enabled;
            if !enabled && inner.active == 0 {
                inner.generation += 1;
                true
            } else {
                false
            }
        };
        if off {
            self.set("off");
        }
    }
}

/// One run's result and its screenshot and trace.
pub struct BrowserOutcome {
    pub run: Map<String, Value>,
    pub artifacts: Vec<Artifact>,
}

fn script_error(message: &str) -> BrowserOutcome {
    let mut run = error_result(&random_uuid(), Instant::now(), message);
    run.insert("durationMs".into(), Value::from(0));
    BrowserOutcome { run, artifacts: Vec::new() }
}

/// Runs one browser check in its own process and fresh browser, with the runner's 2-minute limit, behind a proxy for
/// this run that applies the agent's target policy. A refusal fails the run. Err when the runner could not start.
pub async fn run_browser_check(sandbox: &Sandbox, check: &Map<String, Value>) -> Result<BrowserOutcome, String> {
    let language = check.get("language").filter(|language| language.is_string());
    let (script, file_name) = match validate_script(check.get("script"), language) {
        Ok(valid) => valid,
        Err(ScriptError(message)) => return Ok(script_error(&message)),
    };
    let variables = match validate_variables(check.get("variables")) {
        Ok(variables) => variables,
        Err(ScriptError(message)) => return Ok(script_error(&message)),
    };
    let proxy = RunProxy::start().await.map_err(|error| error.to_string())?;
    let run_id = random_uuid();
    let started = Instant::now();
    let mut job = Map::new();
    job.insert("script".into(), Value::from(script));
    job.insert("fileName".into(), Value::from(file_name));
    job.insert("variables".into(), Value::Object(variables));
    let (mut run, artifacts, guard_refused) = match sandbox.run(&job, &proxy.url).await {
        Ok(output) => {
            let (run, artifacts) = run_result(&run_id, &output);
            (run, artifacts, output.refused)
        }
        Err(RunError::Start(message)) => return Err(message),
        Err(problem) => (error_result(&run_id, started, problem.message()), Vec::new(), false),
    };
    let refused = proxy.refused().or_else(|| guard_refused.then(|| POLICY.to_string()));
    if let Some(reason) = refused {
        run.insert("status".into(), Value::from("error"));
        run.insert("failedStep".into(), Value::Null);
        run.insert("error".into(), Value::from(reason));
    }
    Ok(BrowserOutcome { run, artifacts })
}

/// The browser error text that may leave.
pub fn browser_error(message: &str) -> String {
    utf16_prefix(message, MAX_BROWSER_ERROR_CHARS).to_string()
}

fn title(value: Option<&Value>) -> Value {
    let text = match value {
        Some(Value::String(text)) => text.clone(),
        Some(other) => statustick_browser::validate::js_string(other),
        None => "undefined".into(),
    };
    Value::from(utf16_prefix(&text, MAX_STEP_TITLE_CHARS))
}

const TEST_STATUSES: [&str; 5] = ["passed", "failed", "timedOut", "skipped", "interrupted"];

/// The documented fields of a browser run, rebuilt from the untrusted report with texts cut short.
pub fn documented_browser_result(run: &Map<String, Value>, screenshot: bool, trace: bool) -> Map<String, Value> {
    let error = run.get("error").and_then(Value::as_str).filter(|error| !error.is_empty()).map(browser_error);
    let status = match run.get("status").and_then(Value::as_str) {
        Some("passed") => "up",
        Some("failed") => "down",
        _ => "error",
    };
    let tests: Vec<Value> = run
        .get("tests")
        .and_then(Value::as_array)
        .map(|tests| {
            tests
                .iter()
                .map(|test| {
                    let status = test.get("status").and_then(Value::as_str).filter(|status| TEST_STATUSES.contains(status)).unwrap_or("failed");
                    let steps: Vec<Value> = test
                        .get("steps")
                        .and_then(Value::as_array)
                        .map(|steps| {
                            steps
                                .iter()
                                .map(|step| {
                                    json!({
                                        "title": title(step.get("title")),
                                        "durationMs": step.get("durationMs"),
                                        "status": if step.get("status").and_then(Value::as_str) == Some("passed") { "passed" } else { "failed" },
                                    })
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    json!({ "title": title(test.get("title")), "status": status, "durationMs": test.get("durationMs"), "steps": steps })
                })
                .collect()
        })
        .unwrap_or_default();
    let failed_step = run.get("failedStep").filter(|step| statustick_checks::util::truthy(Some(step))).map(|step| title(Some(step))).unwrap_or(Value::Null);
    let mut answer = Map::new();
    answer.insert("status".into(), Value::from(status));
    answer.insert("responseTime".into(), run.get("durationMs").cloned().unwrap_or(Value::from(0)));
    if let Some(error) = &error {
        answer.insert("error".into(), Value::from(error.clone()));
    }
    answer.insert(
        "browser".into(),
        json!({
            "status": run.get("status"),
            "durationMs": run.get("durationMs"),
            "failedStep": failed_step,
            "error": error,
            "tests": tests,
            "webVitals": run.get("webVitals"),
            "artifacts": { "screenshot": screenshot, "trace": trace },
            "playwright": run.get("playwright"),
        }),
    );
    answer
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Env {
        pairs.iter().map(|(name, value)| (name.to_string(), value.to_string())).collect()
    }

    #[test]
    fn needs_the_runner_files_the_browsers_path_and_a_valid_concurrency() {
        let dir = std::env::temp_dir().join(format!("agent-runner-{}", random_uuid()));
        std::fs::create_dir_all(&dir).unwrap();
        let browsers = ("PLAYWRIGHT_BROWSERS_PATH", "/ms-playwright");
        assert!(browser_support(&env(&[browsers]), &dir).unwrap().is_none());
        std::fs::write(dir.join("run.mts"), "").unwrap();
        assert!(browser_support(&env(&[]), &dir).unwrap().is_none());
        assert_eq!(browser_support(&env(&[browsers]), &dir).unwrap().unwrap().concurrency, 1);
        assert!(browser_support(&env(&[browsers, ("BROWSER_CONCURRENCY", "0")]), &dir).unwrap().is_none());
        assert_eq!(
            browser_support(&env(&[browsers, ("BROWSER_CONCURRENCY", "9")]), &dir).unwrap_err(),
            "BROWSER_CONCURRENCY must be a whole number from 0 to 8"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn cuts_texts_and_counts_an_unknown_test_status_as_failed() {
        let run = json!({
            "runId": "r1", "status": "failed", "durationMs": 4200, "failedStep": "s".repeat(300), "error": "e".repeat(300),
            "tests": [{ "title": "t".repeat(300), "status": "weird", "durationMs": 10, "steps": [{ "title": "open", "durationMs": 5, "status": "passed" }] }],
            "webVitals": null, "playwright": "1.63.0"
        });
        let answer = documented_browser_result(run.as_object().unwrap(), true, false);
        assert_eq!(answer["status"], "down");
        assert_eq!(answer["responseTime"], 4200);
        assert_eq!(answer["error"].as_str().unwrap().len(), MAX_BROWSER_ERROR_CHARS);
        let browser = &answer["browser"];
        assert_eq!(browser["failedStep"].as_str().unwrap().len(), MAX_STEP_TITLE_CHARS);
        assert_eq!(browser["tests"][0]["status"], "failed");
        assert_eq!(browser["tests"][0]["title"].as_str().unwrap().len(), MAX_STEP_TITLE_CHARS);
        assert_eq!(browser["artifacts"], json!({ "screenshot": true, "trace": false }));
        assert!(browser.get("runId").is_none());
    }

    #[tokio::test]
    async fn chromium_starts_with_a_run_and_is_off_again_after_the_idle_time() {
        let seen: Arc<Mutex<Vec<ChromiumState>>> = Arc::default();
        let record = seen.clone();
        let runtime = ChromiumRuntime::new(Box::new(move |state| record.lock().unwrap().push(state)), Duration::from_millis(50));
        runtime.started();
        runtime.finished(true);
        tokio::time::sleep(Duration::from_millis(150)).await;
        runtime.started();
        runtime.finished(false);
        runtime.enable(false);
        assert_eq!(*seen.lock().unwrap(), vec!["starting", "ready", "off", "starting", "failed", "off"]);
    }
}
