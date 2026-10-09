//! Runs one leased job with the check engine and keeps its result within what may leave the network.
use serde_json::{Map, Value, json};
use statustick_checks::http::MAX_BODY_BYTES;
use statustick_checks::util::utf16_prefix;

use crate::database;
use crate::schema::{DATABASE_TYPES, header_mismatch, is_check_type, only_documented_fields, required, validate_check};

const MAX_RESPONSE_TIME_MS: f64 = 600000.0;
const MAX_ERROR_LENGTH: usize = 2000;

/// The platform sends null for unset fields; dropping them lets the checks' defaults apply.
pub fn without_nulls(check: Option<&Value>) -> Map<String, Value> {
    check
        .and_then(Value::as_object)
        .map(|fields| fields.iter().filter(|(_, value)| !value.is_null()).map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default()
}

fn problem_of(kind: &str, check: &Map<String, Value>) -> Option<String> {
    if !is_check_type(kind) {
        return Some(format!("Unsupported check type: {kind}"));
    }
    let missing: Vec<&str> = required(kind).iter().copied().filter(|field| check.get(*field).is_none_or(|value| value.as_str() == Some(""))).collect();
    if !missing.is_empty() {
        return Some(format!("Missing {}", missing.join(", ")));
    }
    if kind == "http" && check.get("body").and_then(Value::as_str).is_some_and(|body| body.len() > MAX_BODY_BYTES) {
        return Some("Request body is larger than 64 KB".to_string());
    }
    None
}

/// Keeps a result inside the bounds the platform accepts (protocol v1, "Post results").
pub fn for_platform(mut result: Map<String, Value>) -> Value {
    let time = match result.get("responseTime") {
        Some(Value::Number(number)) => number.as_f64().unwrap_or(0.0),
        Some(Value::String(text)) => text.trim().parse().unwrap_or(f64::NAN),
        Some(Value::Bool(flag)) => f64::from(u8::from(*flag)),
        Some(Value::Null) => 0.0,
        _ => f64::NAN,
    };
    let clamped = if time.is_finite() { time.clamp(0.0, MAX_RESPONSE_TIME_MS) } else { 0.0 };
    result.insert("responseTime".into(), if clamped.fract() == 0.0 { Value::from(clamped as i64) } else { Value::from(clamped) });
    if let Some(error) = result.get("error").filter(|error| !error.is_null()) {
        let text = match error {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        };
        result.insert("error".into(), Value::from(utf16_prefix(&text, MAX_ERROR_LENGTH)));
    }
    Value::Object(result)
}

pub fn error_result(message: &str) -> Value {
    for_platform(json!({ "status": "error", "responseTime": 0, "error": message }).as_object().cloned().unwrap_or_default())
}

async fn run_check(kind: &str, check: &Map<String, Value>) -> Value {
    if DATABASE_TYPES.contains(&kind) {
        return database::database_check(kind, check, &crate::settings::process_env()).await;
    }
    statustick_checks::run_check(kind, check)
        .await
        .unwrap_or_else(|| json!({ "status": "error", "responseTime": 0, "error": format!("Unsupported check type: {kind}") }))
}

/// Runs one leased job: `{leaseId, result}`. Never fails.
pub async fn run_job(job: &Value) -> Value {
    let lease_id = job.get("leaseId").cloned().unwrap_or(Value::Null);
    let kind = job.get("type").and_then(Value::as_str).unwrap_or("").to_string();
    let raw = without_nulls(job.get("check"));
    let validated = if is_check_type(&kind) { validate_check(&kind, &raw) } else { Ok(raw.clone()) };
    let check = validated.as_ref().cloned().unwrap_or(raw);
    let problem = match &validated {
        Err(problem) => Some(problem.clone()),
        Ok(_) => problem_of(&kind, &check),
    };
    if let Some(problem) = problem {
        return json!({ "leaseId": lease_id, "result": error_result(&problem) });
    }
    let mut answer = run_check(&kind, &check).await.as_object().cloned().unwrap_or_default();
    let mut header_failed = false;
    if kind == "http"
        && let (Some(Value::Object(expected)), Some(Value::Object(details))) = (check.get("expectedHeaders"), answer.get_mut("details"))
    {
        let headers = details.get("headers").and_then(Value::as_object).cloned().unwrap_or_default();
        let mismatch = header_mismatch(expected, &headers);
        header_failed = !mismatch.is_null();
        details.insert("headerMismatch".into(), mismatch);
    }
    if header_failed && answer.get("status").and_then(Value::as_str) == Some("up") {
        answer.insert("status".into(), Value::from("down"));
    }
    json!({ "leaseId": lease_id, "result": for_platform(only_documented_fields(&kind, &answer)) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn refuses_jobs_it_cannot_run() {
        let unknown = run_job(&json!({ "leaseId": "l1", "type": "ftp", "check": {} })).await;
        assert_eq!(unknown, json!({ "leaseId": "l1", "result": { "status": "error", "responseTime": 0, "error": "Unsupported check type: ftp" } }));
        let missing = run_job(&json!({ "leaseId": "l2", "type": "tcp", "check": { "host": "", "port": null } })).await;
        assert_eq!(missing["result"]["error"], "Missing host, port");
        let invalid = run_job(&json!({ "leaseId": "l3", "type": "tcp", "check": { "host": "a", "port": "x" } })).await;
        assert_eq!(invalid["result"]["error"], "Invalid port");
        let big = run_job(&json!({ "leaseId": "l4", "type": "http", "check": { "url": "https://a", "body": "x".repeat(65537) } })).await;
        assert_eq!(big["result"]["error"], "Request body is larger than 64 KB");
    }

    #[test]
    fn bounds_response_time_and_error_length() {
        let result = for_platform(json!({ "status": "down", "responseTime": 9e9, "error": "e".repeat(3000) }).as_object().cloned().unwrap());
        assert_eq!(result["responseTime"], 600000);
        assert_eq!(result["error"].as_str().unwrap().len(), 2000);
        assert_eq!(for_platform(json!({ "status": "up", "responseTime": -1 }).as_object().cloned().unwrap())["responseTime"], 0);
    }
}
