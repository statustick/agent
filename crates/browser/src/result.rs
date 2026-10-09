//! The run result from Playwright's JSON report.
//! The report comes from the sandbox and is not trusted: every field may be missing or of another type.
use base64::Engine;
use serde_json::{Map, Value, json};
use statustick_checks::util::truthy;

const MAX_ERROR_CHARS: usize = 4000;
pub const MAX_SNAPSHOT_CHARS: usize = 30 * 1024;
const MAX_URL_CHARS: usize = 2048;
const MAX_TITLE_CHARS: usize = 300;

fn text(value: Option<&Value>) -> &str {
    value.and_then(Value::as_str).unwrap_or("")
}

fn number(value: Option<&Value>) -> f64 {
    value.and_then(Value::as_f64).unwrap_or(0.0)
}

fn list(value: Option<&Value>) -> Vec<Value> {
    value.and_then(Value::as_array).cloned().unwrap_or_default()
}

/// The first [units] UTF-16 units of [text], as `slice(0, units)` in JavaScript.
fn utf16_cut(text: &str, units: usize) -> String {
    statustick_checks::util::utf16_prefix(text, units).to_string()
}

fn clean(message: Option<&Value>) -> String {
    let raw = match message {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => crate::validate::js_string(other),
    };
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            while let Some(next) = chars.peek().copied() {
                if next.is_ascii_digit() || next == ';' {
                    chars.next();
                } else {
                    if next.is_ascii_alphabetic() {
                        chars.next();
                    } else {
                        out.push('\u{1b}');
                        out.push('[');
                    }
                    break;
                }
            }
            continue;
        }
        out.push(c);
    }
    utf16_cut(out.trim(), MAX_ERROR_CHARS)
}

struct Collected {
    title: String,
    result: Value,
}

fn join(parts: &[&str]) -> String {
    parts.iter().filter(|part| !part.is_empty()).copied().collect::<Vec<_>>().join(" > ")
}

fn collect_tests(suite: &Value, prefix: &str, out: &mut Vec<Collected>) {
    let title = join(&[prefix, text(suite.get("title"))]);
    for spec in list(suite.get("specs")) {
        for test in list(spec.get("tests")) {
            let results = list(test.get("results"));
            out.push(Collected { title: join(&[&title, text(spec.get("title"))]), result: results.last().cloned().unwrap_or_else(|| json!({})) });
        }
    }
    for child in list(suite.get("suites")) {
        collect_tests(&child, &title, out);
    }
}

fn all_tests(report: &Value) -> Vec<Collected> {
    let mut tests = Vec::new();
    for suite in list(report.get("suites")) {
        let mut root = suite.as_object().cloned().unwrap_or_default();
        root.insert("title".into(), Value::from(""));
        collect_tests(&Value::Object(root), "", &mut tests);
    }
    tests
}

fn passing(result: &Value) -> bool {
    matches!(result.get("status").and_then(Value::as_str), Some("passed" | "skipped"))
}

fn flatten_steps(steps: Option<&Value>, prefix: &str, out: &mut Vec<Value>) {
    for step in list(steps) {
        let title = if prefix.is_empty() { text(step.get("title")).to_string() } else { format!("{prefix} > {}", text(step.get("title"))) };
        let failed = truthy(step.get("error"));
        out.push(json!({ "title": title, "durationMs": number(step.get("duration")).round() as i64, "status": if failed { "failed" } else { "passed" } }));
        flatten_steps(step.get("steps"), &title, out);
    }
}

fn failed_step_of(steps: Option<&Value>, prefix: &str) -> Option<String> {
    for step in list(steps) {
        if !truthy(step.get("error")) {
            continue;
        }
        let title = if prefix.is_empty() { text(step.get("title")).to_string() } else { format!("{prefix} > {}", text(step.get("title"))) };
        return Some(failed_step_of(step.get("steps"), &title).unwrap_or(title));
    }
    None
}

fn attachment_path(result: &Value, name: &str) -> Option<String> {
    list(result.get("attachments"))
        .into_iter()
        .find(|entry| text(entry.get("name")) == name && !text(entry.get("path")).is_empty())
        .map(|entry| text(entry.get("path")).to_string())
}

fn attachment_json(result: &Value, name: &str) -> Option<Value> {
    let attachment =
        list(result.get("attachments")).into_iter().find(|entry| text(entry.get("name")) == name && entry.get("body").is_some_and(Value::is_string))?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(text(attachment.get("body"))).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Set by the sandbox's `vitals.cts`; each value is null when the page did not report it or reported nonsense.
fn web_vitals_of(result: &Value) -> Value {
    let Some(raw) = attachment_json(result, "web-vitals").filter(Value::is_object) else { return Value::Null };
    let mut vitals = Map::new();
    for (name, max) in [("lcpMs", 600000.0), ("cls", 1000.0), ("tbtMs", 600000.0)] {
        let value = raw.get(name).filter(|value| value.as_f64().is_some_and(|number| number >= 0.0 && number <= max)).cloned().unwrap_or(Value::Null);
        vitals.insert(name.into(), value);
    }
    Value::Object(vitals)
}

/// The test result a run is described by: the first failing test, else the last one.
pub fn source_result(report: &Value) -> Value {
    let tests = all_tests(report);
    tests.iter().find(|test| !passing(&test.result)).or(tests.last()).map(|test| test.result.clone()).unwrap_or_else(|| json!({}))
}

/// `status`, `durationMs`, `failedStep`, `error`, `tests` and `webVitals` of a run, and the sandbox paths of its
/// screenshot and trace.
pub fn build_result(report: &Value) -> (Map<String, Value>, Option<String>, Option<String>) {
    let tests = all_tests(report);
    let load_errors: Vec<String> = list(report.get("errors")).iter().map(|error| clean(error.get("message"))).filter(|message| !message.is_empty()).collect();
    let summaries: Vec<Value> = tests
        .iter()
        .map(|test| {
            let mut steps = Vec::new();
            flatten_steps(test.result.get("steps"), "", &mut steps);
            let status = test.result.get("status").filter(|status| truthy(Some(status))).cloned().unwrap_or(Value::from("failed"));
            json!({ "title": test.title, "status": status, "durationMs": number(test.result.get("duration")).round() as i64, "steps": steps })
        })
        .collect();
    let failing = tests.iter().find(|test| !passing(&test.result));
    let passed = !tests.is_empty() && failing.is_none() && load_errors.is_empty();
    let error = if let Some(failing) = failing {
        let message = failing.result.get("error").and_then(|error| error.get("message")).filter(|message| truthy(Some(message)));
        Value::from(match message {
            Some(message) => clean(Some(message)),
            None => clean(Some(&Value::from(format!(
                "Test ended with status {}",
                failing.result.get("status").map(crate::validate::js_string).unwrap_or_else(|| "undefined".into())
            )))),
        })
    } else if let Some(first) = load_errors.first() {
        Value::from(first.clone())
    } else if tests.is_empty() {
        Value::from("The script has no tests.")
    } else {
        Value::Null
    };
    let source = failing.or(tests.last()).map(|test| test.result.clone()).unwrap_or_else(|| json!({}));
    let reported = report.pointer("/stats/duration").and_then(Value::as_f64).filter(|duration| *duration != 0.0);
    let duration = reported.unwrap_or_else(|| summaries.iter().map(|test| test["durationMs"].as_f64().unwrap_or(0.0)).sum());
    let mut result = Map::new();
    result.insert("status".into(), Value::from(if passed { "passed" } else { "failed" }));
    result.insert("durationMs".into(), Value::from(duration.round() as i64));
    result.insert("failedStep".into(), failing.and_then(|test| failed_step_of(test.result.get("steps"), "")).map(Value::from).unwrap_or(Value::Null));
    result.insert("error".into(), error);
    result.insert("tests".into(), Value::from(summaries));
    result.insert("webVitals".into(), web_vitals_of(&source));
    (result, attachment_path(&source, "screenshot"), attachment_path(&source, "trace"))
}

fn cut(value: Option<&Value>, max: usize) -> (String, bool) {
    let all = text(value);
    let kept = utf16_cut(all, max);
    let was_cut = kept.len() < all.len();
    (kept, was_cut)
}

/// The page snapshot `vitals.cts` attached, with every field checked and cut again.
pub fn page_snapshot_of(report: &Value) -> Value {
    let Some(raw) = attachment_json(&source_result(report), "page-snapshot").filter(Value::is_object) else { return Value::Null };
    let (aria, aria_cut) = cut(raw.get("ariaSnapshot"), MAX_SNAPSHOT_CHARS);
    let (visible, text_cut) = cut(raw.get("text"), MAX_SNAPSHOT_CHARS);
    json!({
        "url": cut(raw.get("url"), MAX_URL_CHARS).0,
        "title": cut(raw.get("title"), MAX_TITLE_CHARS).0,
        "ariaSnapshot": aria,
        "text": visible,
        "truncated": raw.get("truncated") == Some(&Value::Bool(true)) || aria_cut || text_cut,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(title: &str, duration: f64, extra: Value) -> Value {
        let mut step = json!({ "title": title, "duration": duration });
        if let Value::Object(fields) = extra {
            step.as_object_mut().unwrap().extend(fields);
        }
        step
    }

    fn report(result: Value) -> Value {
        let mut base = json!({
            "status": "passed",
            "duration": 2345.6,
            "steps": [step("open home", 812.0, json!({})), step("pay", 1200.0, json!({}))],
            "attachments": [
                { "name": "screenshot", "contentType": "image/png", "path": "/runner/work/out/checkout/test-finished-1.png" },
                { "name": "trace", "contentType": "application/zip", "path": "/runner/work/out/checkout/trace.zip" }
            ]
        });
        base.as_object_mut().unwrap().extend(result.as_object().cloned().unwrap_or_default());
        json!({ "suites": [{ "title": "check.spec.ts", "suites": [{ "title": "checkout", "specs": [{ "title": "buys a plan", "tests": [{ "results": [base] }] }] }] }], "errors": [], "stats": { "duration": 2500 } })
    }

    #[test]
    fn reports_a_passing_run_with_each_step() {
        let (result, screenshot, trace) = build_result(&report(json!({})));
        assert_eq!(result["status"], "passed");
        assert_eq!(result["error"], Value::Null);
        assert_eq!(result["durationMs"], 2500);
        assert_eq!(
            result["tests"],
            json!([{ "title": "checkout > buys a plan", "status": "passed", "durationMs": 2346, "steps": [
                { "title": "open home", "durationMs": 812, "status": "passed" },
                { "title": "pay", "durationMs": 1200, "status": "passed" }
            ] }])
        );
        assert_eq!(screenshot.as_deref(), Some("/runner/work/out/checkout/test-finished-1.png"));
        assert_eq!(trace.as_deref(), Some("/runner/work/out/checkout/trace.zip"));
    }

    #[test]
    fn names_the_deepest_failing_step_and_strips_colors() {
        let error = json!({ "message": "\u{1b}[31mTimeout 5000ms exceeded.\u{1b}[39m waiting for locator('#pay')" });
        let (result, ..) = build_result(&report(json!({
            "status": "failed",
            "error": error,
            "steps": [step("open home", 800.0, json!({})), step("pay", 5100.0, json!({ "error": error, "steps": [step("fill card", 100.0, json!({})), step("click pay", 5000.0, json!({ "error": error }))] }))]
        })));
        assert_eq!(result["status"], "failed");
        assert_eq!(result["failedStep"], "pay > click pay");
        assert_eq!(result["error"], "Timeout 5000ms exceeded. waiting for locator('#pay')");
    }

    #[test]
    fn fails_on_load_errors_no_tests_and_malformed_reports() {
        let (result, ..) =
            build_result(&json!({ "suites": [], "errors": [{ "message": "SyntaxError: Unexpected token (3:5)" }], "stats": { "duration": 10 } }));
        assert_eq!(result["error"], "SyntaxError: Unexpected token (3:5)");
        let (result, ..) = build_result(&json!({ "suites": [], "errors": [], "stats": { "duration": 5 } }));
        assert_eq!(result["error"], "The script has no tests.");
        assert_eq!(build_result(&Value::Null).0["status"], "failed");
        assert_eq!(build_result(&json!({ "suites": [{ "specs": [{ "tests": [{}] }] }] })).0["status"], "failed");
        let (timed_out, ..) = build_result(&report(json!({ "status": "timedOut", "error": { "message": "Test timeout of 60000ms exceeded." } })));
        assert_eq!(timed_out["failedStep"], Value::Null);
        assert_eq!(timed_out["error"], "Test timeout of 60000ms exceeded.");
    }

    #[test]
    fn reads_web_vitals_and_page_snapshots() {
        let body = |value: &str| base64::engine::general_purpose::STANDARD.encode(value);
        let vitals = |text: &str| json!({ "attachments": [{ "name": "web-vitals", "contentType": "application/json", "body": body(text) }] });
        assert_eq!(
            build_result(&report(vitals(r#"{"lcpMs":1830,"cls":0.042,"tbtMs":-5}"#))).0["webVitals"],
            json!({ "lcpMs": 1830, "cls": 0.042, "tbtMs": null })
        );
        assert_eq!(build_result(&report(vitals("not json"))).0["webVitals"], Value::Null);
        let snapshot = json!({ "attachments": [{ "name": "page-snapshot", "body": body(&json!({ "url": "https://x.example/", "title": "T", "ariaSnapshot": "a".repeat(MAX_SNAPSHOT_CHARS + 5), "text": "hi" }).to_string()) }] });
        let page = page_snapshot_of(&report(snapshot));
        assert_eq!(page["title"], "T");
        assert_eq!(page["truncated"], true);
        assert_eq!(page["ariaSnapshot"].as_str().unwrap().len(), MAX_SNAPSHOT_CHARS);
        assert_eq!(page_snapshot_of(&report(json!({}))), Value::Null);
    }
}
