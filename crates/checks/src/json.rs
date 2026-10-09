//! JSON path assertions on an HTTP response body. Failure texts name the path but never a value from the body.
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

pub const MAX_JSON_ASSERTIONS: usize = 5;

static PATH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\$((\.[A-Za-z_][A-Za-z0-9_-]*)|(\[\d+\]))*$").expect("valid pattern"));
static STEP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.([A-Za-z_][A-Za-z0-9_-]*)|\[(\d+)\]").expect("valid pattern"));

pub fn valid_json_path(path: &str) -> bool {
    PATH.is_match(path)
}

enum Step {
    Name(String),
    Index(f64),
}

fn steps(path: &str) -> Vec<Step> {
    STEP.captures_iter(path)
        .map(|capture| match capture.get(1) {
            Some(name) => Step::Name(name.as_str().to_string()),
            None => Step::Index(capture[2].parse::<f64>().unwrap_or(f64::INFINITY)),
        })
        .collect()
}

fn lookup<'a>(document: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = document;
    for step in steps(path) {
        current = match (step, current) {
            (Step::Index(index), Value::Array(items)) if index < items.len() as f64 => &items[index as usize],
            (Step::Name(name), Value::Object(fields)) => fields.get(&name)?,
            _ => return None,
        };
    }
    Some(current)
}

/// `===` between a JSON value and an assertion's `equals`.
fn strictly_equal(value: &Value, expected: &Value) -> bool {
    match (value, expected) {
        (Value::Number(a), Value::Number(b)) => a.as_f64() == b.as_f64(),
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Null, Value::Null) => true,
        _ => false,
    }
}

/// The first failing assertion as a message, or None when all pass. [assertions] are the request's `json` items.
pub fn check_json(body: &str, assertions: &[Value]) -> Option<String> {
    let path_of = |assertion: &Value| {
        assertion.get("path").map(|path| match path {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        })
    };
    let first = assertions.first().and_then(path_of).unwrap_or_else(|| "$".to_string());
    let Ok(document) = serde_json::from_str::<Value>(body.trim_matches(|c: char| matches!(c, ' ' | '\t' | '\n' | '\r'))) else {
        return Some(format!("The response is not JSON, so {first} cannot be checked"));
    };
    for assertion in assertions {
        let Some(path) = path_of(assertion) else {
            return Some("A JSON assertion has no path".into());
        };
        if !valid_json_path(&path) {
            return Some(format!("JSON path {path} is not valid"));
        }
        let found = lookup(&document, &path);
        if let Some(exists) = assertion.as_object().filter(|fields| fields.contains_key("exists")).map(|fields| crate::util::truthy(fields.get("exists"))) {
            if exists && found.is_none() {
                return Some(format!("JSON path {path} is missing in the response"));
            }
            if !exists && found.is_some() {
                return Some(format!("JSON path {path} is in the response, expected it absent"));
            }
        } else {
            let Some(value) = found else {
                return Some(format!("JSON path {path} is missing in the response"));
            };
            if !assertion.get("equals").is_some_and(|expected| strictly_equal(value, expected)) {
                return Some(format!("JSON path {path} is not the expected value"));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn check(body: &str, assertions: Value) -> Option<String> {
        check_json(body, assertions.as_array().unwrap())
    }

    #[test]
    fn passes_values_and_presence() {
        let body = r#"{"status":"ok","count":1,"data":{"items":[{"id":7,"done":true,"note":null}]}}"#;
        assert_eq!(
            check(
                body,
                json!([{"path": "$.status", "equals": "ok"}, {"path": "$.count", "equals": 1.0}, {"path": "$.data.items[0].done", "equals": true}, {"path": "$.data.items[0].note", "equals": null}, {"path": "$.error", "exists": false}])
            ),
            None
        );
        assert_eq!(check(body, json!([{"path": "$.count", "equals": "1"}])).unwrap(), "JSON path $.count is not the expected value");
        assert_eq!(check(body, json!([{"path": "$.data.items[1]", "exists": true}])).unwrap(), "JSON path $.data.items[1] is missing in the response");
        assert_eq!(check(body, json!([{"path": "$.missing", "equals": null}])).unwrap(), "JSON path $.missing is missing in the response");
        assert_eq!(check(body, json!([{"path": "$.status", "exists": false}])).unwrap(), "JSON path $.status is in the response, expected it absent");
        assert_eq!(check("<html>", json!([{"path": "$.a", "exists": true}])).unwrap(), "The response is not JSON, so $.a cannot be checked");
        assert_eq!(check(body, json!([{"path": "$..x", "exists": true}])).unwrap(), "JSON path $..x is not valid");
    }

    #[test]
    fn validates_paths() {
        assert!(valid_json_path("$"));
        assert!(valid_json_path("$.a_b-c[0].d"));
        assert!(!valid_json_path("$.0"));
        assert!(!valid_json_path("$['a']"));
    }
}
