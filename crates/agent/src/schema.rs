//! The fixed shapes of agent jobs and of the results that leave the customer's network. A job is
//! data: fields outside the schema are dropped, a field of the wrong type refuses the job, and nothing in it is run.
use serde_json::{Map, Value, json};
use statustick_checks::json::{MAX_JSON_ASSERTIONS, valid_json_path};

#[derive(Clone, Copy)]
enum Field {
    Text,
    Number,
    Boolean,
    StringMap,
    IpVersion,
    Assets,
    JsonAssertions,
    Method,
    OneOf(&'static [&'static str]),
}

use Field::*;

pub const CHECK_TYPES: [&str; 13] = ["http", "tcp", "ping", "dns", "mcp", "grpc", "smtp", "imap", "ssl", "postgres", "mysql", "redis", "mongodb"];
pub const DATABASE_TYPES: [&str; 4] = ["postgres", "mysql", "redis", "mongodb"];
const HTTP_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

const DATABASE: &[(&str, Field)] = &[
    ("host", Text),
    ("port", Number),
    ("database", Text),
    ("user", Text),
    ("password", Text),
    ("userEnv", Text),
    ("passwordEnv", Text),
    ("tls", Boolean),
    ("tlsVerify", Boolean),
    ("expectedValue", Text),
    ("timeout", Number),
];

const MAIL: &[(&str, Field)] = &[
    ("host", Text),
    ("port", Number),
    ("tlsMode", OneOf(&["NONE", "STARTTLS", "TLS"])),
    ("tlsVerify", Boolean),
    ("requireStartTLS", Boolean),
    ("timeout", Number),
    ("ipVersion", IpVersion),
];

fn schema(kind: &str) -> Option<Vec<(&'static str, Field)>> {
    Some(match kind {
        "http" => vec![
            ("url", Text),
            ("method", Method),
            ("timeout", Number),
            ("expectedStatus", Number),
            ("expectedText", Text),
            ("textMode", OneOf(&["contains", "not_contains"])),
            ("caseSensitive", Boolean),
            ("headers", StringMap),
            ("expectedHeaders", StringMap),
            ("body", Text),
            ("bodyType", OneOf(&["RAW", "JSON", "FORM_PARAMS"])),
            ("followRedirects", Boolean),
            ("ipVersion", IpVersion),
            ("assets", Assets),
            ("json", JsonAssertions),
        ],
        "tcp" => vec![("host", Text), ("port", Number), ("timeout", Number), ("ipVersion", IpVersion)],
        "ping" => vec![("host", Text), ("timeout", Number), ("count", Number), ("ipVersion", IpVersion)],
        "dns" => vec![
            ("hostname", Text),
            ("recordType", OneOf(&["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"])),
            ("timeout", Number),
            ("expectedIP", Text),
            ("expectedValue", Text),
        ],
        "mcp" => vec![("url", Text), ("authHeaderName", Text), ("authHeaderValue", Text), ("timeout", Number)],
        "grpc" => vec![
            ("host", Text),
            ("port", Number),
            ("service", Text),
            ("tlsMode", OneOf(&["NONE", "TLS"])),
            ("tlsVerify", Boolean),
            ("timeout", Number),
            ("ipVersion", IpVersion),
        ],
        "smtp" | "imap" => MAIL.to_vec(),
        "ssl" => vec![("host", Text), ("port", Number), ("timeout", Number)],
        "postgres" | "mysql" => {
            let mut fields = DATABASE.to_vec();
            fields.push(("query", Text));
            fields
        }
        "redis" | "mongodb" => DATABASE.to_vec(),
        _ => return None,
    })
}

pub fn is_check_type(kind: &str) -> bool {
    CHECK_TYPES.contains(&kind)
}

fn json_assertion(value: &Value) -> bool {
    let Some(object) = value.as_object() else { return false };
    let Some(path) = object.get("path").and_then(Value::as_str) else { return false };
    if !valid_json_path(path) {
        return false;
    }
    let rest: Vec<(&String, &Value)> = object.iter().filter(|(key, _)| *key != "path").collect();
    match rest.as_slice() {
        [(key, value)] if *key == "exists" => value.is_boolean(),
        [(key, value)] if *key == "equals" => value.is_null() || value.is_string() || value.is_number() || value.is_boolean(),
        _ => false,
    }
}

fn fits(field: Field, value: &Value) -> bool {
    match field {
        Method => value.as_str().is_some_and(|text| HTTP_METHODS.contains(&text.to_uppercase().as_str())),
        OneOf(values) => value.as_str().is_some_and(|text| values.contains(&text)),
        Text => value.is_string(),
        Number => value.as_f64().is_some_and(f64::is_finite),
        Boolean => value.is_boolean(),
        IpVersion => matches!(value, Value::String(text) if text == "4" || text == "6") || value.as_f64().is_some_and(|number| number == 4.0 || number == 6.0),
        StringMap => value.as_object().is_some_and(|map| map.values().all(Value::is_string)),
        Assets => value
            .as_object()
            .is_some_and(|map| map.iter().all(|(key, item)| key == "ignoreHosts" && item.as_array().is_some_and(|hosts| hosts.iter().all(Value::is_string)))),
        JsonAssertions => value.as_array().is_some_and(|items| items.len() <= MAX_JSON_ASSERTIONS && items.iter().all(json_assertion)),
    }
}

/// The job's check with only schema fields kept, or the reason it is refused.
pub fn validate_check(kind: &str, check: &Map<String, Value>) -> Result<Map<String, Value>, String> {
    let fields = schema(kind).unwrap_or_default();
    let mut kept = Map::new();
    for (name, value) in check {
        let Some((_, field)) = fields.iter().find(|(field_name, _)| field_name == name) else { continue };
        if !fits(*field, value) {
            return Err(format!("Invalid {name}"));
        }
        kept.insert(name.clone(), value.clone());
    }
    Ok(kept)
}

pub fn required(kind: &str) -> &'static [&'static str] {
    match kind {
        "http" | "mcp" => &["url"],
        "ping" | "ssl" => &["host"],
        "dns" => &["hostname"],
        _ => &["host", "port"],
    }
}

const MIN_INTERVAL_SECONDS: i64 = 10;
const MAX_INTERVAL_SECONDS: i64 = 86400;

fn monitor_id(text: &str) -> bool {
    text.strip_prefix("mnt_").is_some_and(|rest| (1..=64).contains(&rest.len()) && rest.bytes().all(|byte| byte.is_ascii_alphanumeric()))
}

/// A job's `schedule` when it is well formed: `(monitorId, intervalSeconds)`.
pub fn valid_schedule(value: Option<&Value>) -> Option<(String, i64)> {
    let object = value?.as_object()?;
    let id = object.get("monitorId")?.as_str().filter(|id| monitor_id(id))?;
    let interval = object.get("intervalSeconds")?.as_f64().filter(|seconds| seconds.fract() == 0.0)? as i64;
    (MIN_INTERVAL_SECONDS..=MAX_INTERVAL_SECONDS).contains(&interval).then(|| (id.to_string(), interval))
}

const DATABASE_RESULT: (&[&str], &[&str]) = (&["status", "responseTime", "error", "errorCode"], &["connectTime", "authTime", "queryTime", "value"]);
const PROTOCOL_RESULT: (&[&str], &[&str]) = (
    &["status", "responseTime", "error", "errorCode"],
    &["servingStatus", "grpcStatus", "greetingCode", "startTLSOffered", "tlsVersion", "certificateExpiresAt", "certificateDaysLeft"],
);

/// Every result field that may leave the network, per check type: top-level names and `details` names.
pub fn result_fields(kind: &str) -> (&'static [&'static str], &'static [&'static str]) {
    match kind {
        "http" => {
            (&["status", "responseTime", "httpStatus", "error", "errorType"], &["textMatch", "headerMismatch", "assets", "legacyTLS", "tlsVersion", "weakKey"])
        }
        "tcp" => (&["status", "responseTime", "error", "errorCode"], &[]),
        "ping" => (&["status", "responseTime", "packetLoss", "error"], &["alive", "min", "max", "avg", "stddev", "method", "note"]),
        "dns" => (&["status", "responseTime", "records", "recordCount", "error", "errorCode"], &[]),
        "mcp" => (
            &["status", "responseTime", "error", "errorCode"],
            &["protocolVersion", "serverName", "serverVersion", "toolCount", "toolsHash", "initializeTime", "toolsListTime"],
        ),
        "grpc" | "smtp" | "imap" => PROTOCOL_RESULT,
        "ssl" => (&["status", "responseTime", "error", "errorCode", "certificate", "legacyTLS", "tlsVersion", "weakKey"], &[]),
        _ => DATABASE_RESULT,
    }
}

/// Keeps only the documented result fields; asset checks keep counts and the status of each failed asset.
pub fn only_documented_fields(kind: &str, result: &Map<String, Value>) -> Map<String, Value> {
    let (top, details) = result_fields(kind);
    let mut answer = Map::new();
    for name in top {
        if let Some(value) = result.get(*name) {
            answer.insert(name.to_string(), value.clone());
        }
    }
    if let Some(Value::Object(found)) = result.get("details")
        && !details.is_empty()
    {
        let mut kept = Map::new();
        for name in details {
            if let Some(value) = found.get(*name) {
                kept.insert(name.to_string(), value.clone());
            }
        }
        if let Some(assets) = kept.get("assets").cloned() {
            let failed: Vec<Value> = assets
                .get("failed")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .map(|item| {
                            let mut entry = Map::new();
                            for name in ["status", "error"] {
                                if let Some(value) = item.get(name) {
                                    entry.insert(name.into(), value.clone());
                                }
                            }
                            Value::Object(entry)
                        })
                        .collect()
                })
                .unwrap_or_default();
            let mut shape = Map::new();
            if let Some(checked) = assets.get("checked") {
                shape.insert("checked".into(), checked.clone());
            }
            shape.insert("failed".into(), Value::from(failed));
            kept.insert("assets".into(), Value::Object(shape));
        }
        answer.insert("details".into(), Value::Object(kept));
    }
    answer
}

/// The first of [expected] response headers (names ignore case) that [actual] lacks or has with another value.
pub fn header_mismatch(expected: &Map<String, Value>, actual: &Map<String, Value>) -> Value {
    let lower: Vec<(String, &Value)> = actual.iter().map(|(name, value)| (name.to_lowercase(), value)).collect();
    for (name, value) in expected {
        // A later duplicate header name wins.
        match lower.iter().rev().find(|(candidate, _)| *candidate == name.to_lowercase()) {
            None => return json!({ "name": name, "reason": "missing" }),
            Some((_, found)) if *found != value => return json!({ "name": name, "reason": "different" }),
            _ => {}
        }
    }
    Value::Null
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(value: Value) -> Map<String, Value> {
        value.as_object().cloned().unwrap()
    }

    #[test]
    fn drops_unknown_fields_and_refuses_wrong_types() {
        let kept = validate_check("http", &map(json!({ "url": "https://a", "method": "post", "extra": 1, "ipVersion": 6 }))).unwrap();
        assert_eq!(Value::Object(kept), json!({ "url": "https://a", "method": "post", "ipVersion": 6 }));
        assert_eq!(validate_check("http", &map(json!({ "url": 1 }))).unwrap_err(), "Invalid url");
        assert_eq!(validate_check("tcp", &map(json!({ "host": "a", "port": "80" }))).unwrap_err(), "Invalid port");
        assert_eq!(validate_check("dns", &map(json!({ "hostname": "a", "recordType": "PTR" }))).unwrap_err(), "Invalid recordType");
        assert_eq!(validate_check("http", &map(json!({ "url": "a", "json": [{ "path": "$.a", "equals": 1, "exists": true }] }))).unwrap_err(), "Invalid json");
        assert!(validate_check("http", &map(json!({ "url": "a", "assets": { "ignoreHosts": ["x"] } }))).is_ok());
    }

    #[test]
    fn keeps_only_documented_result_fields() {
        let result = map(json!({
            "status": "up", "responseTime": 3, "httpStatus": 200, "url": "https://secret",
            "details": { "headers": { "set-cookie": "x" }, "textMatch": true, "assets": { "checked": 2, "failed": [{ "url": "https://x", "status": 404 }] } }
        }));
        assert_eq!(
            Value::Object(only_documented_fields("http", &result)),
            json!({ "status": "up", "responseTime": 3, "httpStatus": 200, "details": { "textMatch": true, "assets": { "checked": 2, "failed": [{ "status": 404 }] } } })
        );
    }

    #[test]
    fn reads_well_formed_schedules_only() {
        assert_eq!(valid_schedule(Some(&json!({ "monitorId": "mnt_1", "intervalSeconds": 60 }))), Some(("mnt_1".into(), 60)));
        assert_eq!(valid_schedule(Some(&json!({ "monitorId": "mnt_1", "intervalSeconds": 5 }))), None);
        assert_eq!(valid_schedule(Some(&json!({ "monitorId": "x_1", "intervalSeconds": 60 }))), None);
    }

    #[test]
    fn names_the_first_missing_or_different_header() {
        let actual = map(json!({ "Content-Type": "text/html", "x-a": "1" }));
        assert_eq!(header_mismatch(&map(json!({ "content-type": "text/html" })), &actual), Value::Null);
        assert_eq!(header_mismatch(&map(json!({ "X-A": "2" })), &actual), json!({ "name": "X-A", "reason": "different" }));
        assert_eq!(header_mismatch(&map(json!({ "x-b": "1" })), &actual), json!({ "name": "x-b", "reason": "missing" }));
    }
}
