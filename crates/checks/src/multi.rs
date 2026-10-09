//! Multi checks: several HTTP, TCP, ping and DNS checks in one request, each answered with its own fields echoed.
use std::time::Instant;

use serde_json::{Map, Value};

use crate::dns::{has_records, resolve_dns};
use crate::http::{check_status, make_http_request, multi_options};
use crate::ping::icmp_probe;
use crate::targets::resolve_allowed;
use crate::tcp::{connect, port_of};
use crate::util::{Failure, elapsed_ms, string_field, timeout_field};

async fn run(check: &Map<String, Value>, start: Instant) -> Result<Vec<(&'static str, Value)>, Failure> {
    let host = || check.get("host").and_then(Value::as_str).unwrap_or("").to_string();
    match check.get("type").and_then(Value::as_str) {
        Some("http") => {
            let result = make_http_request(check.get("url").and_then(Value::as_str).unwrap_or(""), &multi_options(check)).await?;
            let headers = serde_json::to_value(&result.headers).unwrap_or(Value::Null);
            Ok(vec![
                ("status", Value::from(check_status(&result))),
                ("responseTime", Value::from(elapsed_ms(start))),
                ("httpStatus", Value::from(result.status)),
                ("details", serde_json::json!({ "headers": headers })),
            ])
        }
        Some("tcp") => {
            let address = resolve_allowed(&host(), 0).await?[0];
            let up = connect(address, port_of(check), timeout_field(check, "timeout", 10000.0)).await.is_ok();
            Ok(vec![("status", Value::from(if up { "up" } else { "down" })), ("responseTime", Value::from(elapsed_ms(start)))])
        }
        Some("ping") => {
            let address = resolve_allowed(&host(), 0).await?[0];
            let answer = icmp_probe(address, 1, timeout_field(check, "timeout", 10000.0)).await.ok();
            let alive = answer.as_ref().is_some_and(|answer| answer.alive());
            let time = answer.and_then(|answer| answer.first_time()).map(Value::from).unwrap_or_else(|| Value::from(elapsed_ms(start)));
            Ok(vec![("status", Value::from(if alive { "up" } else { "down" })), ("responseTime", time)])
        }
        Some("dns") => {
            let record_type = string_field(check, "recordType").unwrap_or_else(|| "A".to_string());
            let records =
                resolve_dns(check.get("hostname").and_then(Value::as_str).unwrap_or(""), &record_type, timeout_field(check, "timeout", 10000.0)).await?;
            let up = has_records(&records);
            let list = match records {
                Value::Array(items) => Value::Array(items),
                single => Value::Array(vec![single]),
            };
            Ok(vec![("status", Value::from(if up { "up" } else { "down" })), ("responseTime", Value::from(elapsed_ms(start))), ("records", list)])
        }
        _ => Ok(vec![("status", Value::from("error")), ("error", Value::from("Unknown check type")), ("responseTime", Value::from(elapsed_ms(start)))]),
    }
}

/// One item of a multi check: its own fields, then what the check found.
pub async fn multi_item(check: &Value) -> Value {
    let start = Instant::now();
    let fields = check.as_object().cloned().unwrap_or_default();
    let found = match run(&fields, start).await {
        Ok(found) => found,
        Err(failure) => vec![("status", Value::from("error")), ("error", Value::from(failure.message)), ("responseTime", Value::from(elapsed_ms(start)))],
    };
    let mut result = fields;
    for (key, value) in found {
        result.insert(key.to_string(), value);
    }
    Value::Object(result)
}

/// The items in request order, run together or one after another.
pub async fn multi_check(checks: &[Value], parallel: bool) -> (Vec<Value>, i64) {
    let start = Instant::now();
    let results = if parallel {
        futures_util::future::join_all(checks.iter().map(multi_item)).await
    } else {
        let mut results = Vec::new();
        for check in checks {
            results.push(multi_item(check).await);
        }
        results
    };
    (results, elapsed_ms(start))
}
