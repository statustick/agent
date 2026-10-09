//! Browser runs of StatusTick's drones and agents: the request checks, the process
//! sandbox around its `run.mts`, and the run's result from Playwright's report.
pub mod result;
pub mod sandbox;
pub mod validate;

use std::time::Instant;

use base64::Engine;
use serde_json::{Map, Value, json};

pub use sandbox::{RunError, RunOutput, Sandbox};

pub const PLAYWRIGHT_VERSION: &str = env!("PLAYWRIGHT_VERSION");
pub const CHROMIUM_VERSION: &str = env!("CHROMIUM_VERSION");
/// Each run's memory limit, in MB, as the package's limits name it.
pub const MEMORY_LIMIT_MB: u64 = 2048;

/// A run's screenshot or trace: `screenshot` or `trace`, the file name and its bytes.
pub struct Artifact {
    pub kind: &'static str,
    pub name: &'static str,
    pub data: Vec<u8>,
}

/// The answer of a run that went over a limit or gave no result, as the package's `executeRun` answers it.
pub fn error_result(run_id: &str, started: Instant, message: &str) -> Map<String, Value> {
    json!({
        "runId": run_id,
        "status": "error",
        "durationMs": started.elapsed().as_millis() as i64,
        "failedStep": null,
        "error": message,
        "tests": [],
        "webVitals": null,
        "artifacts": { "screenshot": null, "trace": null },
        "playwright": PLAYWRIGHT_VERSION,
    })
    .as_object()
    .cloned()
    .unwrap_or_default()
}

/// The run's result (with `artifacts` still null) and its screenshot and trace, from what the sandbox gave.
pub fn run_result(run_id: &str, output: &RunOutput) -> (Map<String, Value>, Vec<Artifact>) {
    let (built, screenshot, trace) = result::build_result(&output.report);
    let mut artifacts = Vec::new();
    for (kind, name, path) in [("screenshot", "screenshot.png", screenshot), ("trace", "trace.zip", trace)] {
        let content = path.and_then(|path| output.files.get(&path).and_then(Value::as_str).map(str::to_string));
        if let Some(data) = content.and_then(|content| base64::engine::general_purpose::STANDARD.decode(content).ok()) {
            artifacts.push(Artifact { kind, name, data });
        }
    }
    let mut answer = Map::new();
    answer.insert("runId".into(), Value::from(run_id));
    answer.extend(built);
    answer.insert("artifacts".into(), json!({ "screenshot": null, "trace": null }));
    answer.insert("playwright".into(), Value::from(PLAYWRIGHT_VERSION));
    (answer, artifacts)
}
