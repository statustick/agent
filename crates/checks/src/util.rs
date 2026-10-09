use std::fmt;
use std::time::Instant;

use serde_json::{Map, Value};

/// A check failure: the message, an error code (`ECONNREFUSED`, `ENOTFOUND`, …) and the error name StatusTick reports.
#[derive(Debug, Clone, PartialEq)]
pub struct Failure {
    pub message: String,
    pub code: Option<String>,
    pub name: String,
}

impl Failure {
    pub fn new(message: impl Into<String>, code: Option<&str>, name: &str) -> Self {
        Failure { message: message.into(), code: code.map(str::to_string), name: name.to_string() }
    }

    pub fn coded(message: impl Into<String>, code: &str) -> Self {
        Failure::new(message, Some(code), "Error")
    }

    pub fn plain(message: impl Into<String>) -> Self {
        Failure::new(message, None, "Error")
    }

    pub fn is(&self, code: &str) -> bool {
        self.code.as_deref() == Some(code)
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Failure {}

/// Now in UTC, ISO 8601 with milliseconds.
pub fn now_iso() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

pub fn iso(time: chrono::DateTime<chrono::Utc>) -> String {
    time.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Whole milliseconds since [start].
pub fn elapsed_ms(start: Instant) -> i64 {
    (start.elapsed().as_secs_f64() * 1000.0).round() as i64
}

/// The errno name StatusTick reports as an error code.
pub fn errno_name(errno: i32) -> Option<&'static str> {
    let names: &[(i32, &str)] = &[
        (libc::ECONNREFUSED, "ECONNREFUSED"),
        (libc::ECONNRESET, "ECONNRESET"),
        (libc::ECONNABORTED, "ECONNABORTED"),
        (libc::ETIMEDOUT, "ETIMEDOUT"),
        (libc::EHOSTUNREACH, "EHOSTUNREACH"),
        (libc::ENETUNREACH, "ENETUNREACH"),
        (libc::ENETDOWN, "ENETDOWN"),
        (libc::EHOSTDOWN, "EHOSTDOWN"),
        (libc::EADDRNOTAVAIL, "EADDRNOTAVAIL"),
        (libc::EADDRINUSE, "EADDRINUSE"),
        (libc::EACCES, "EACCES"),
        (libc::EPERM, "EPERM"),
        (libc::EPIPE, "EPIPE"),
        (libc::EAFNOSUPPORT, "EAFNOSUPPORT"),
        (libc::EINVAL, "EINVAL"),
        (libc::EMFILE, "EMFILE"),
        (libc::ENOBUFS, "ENOBUFS"),
        (libc::EPROTONOSUPPORT, "EPROTONOSUPPORT"),
    ];
    names.iter().find(|(number, _)| *number == errno).map(|(_, name)| *name)
}

/// The error code of an I/O error, `EIO` when it has no errno name.
pub fn io_code(error: &std::io::Error) -> String {
    if let Some(name) = error.raw_os_error().and_then(errno_name) {
        return name.to_string();
    }
    match error.kind() {
        std::io::ErrorKind::ConnectionRefused => "ECONNREFUSED",
        std::io::ErrorKind::ConnectionReset => "ECONNRESET",
        std::io::ErrorKind::ConnectionAborted => "ECONNABORTED",
        std::io::ErrorKind::TimedOut => "ETIMEDOUT",
        std::io::ErrorKind::BrokenPipe => "EPIPE",
        std::io::ErrorKind::UnexpectedEof => "ECONNRESET",
        std::io::ErrorKind::PermissionDenied => "EACCES",
        std::io::ErrorKind::AddrNotAvailable => "EADDRNOTAVAIL",
        _ => "EIO",
    }
    .to_string()
}

/// `connect ECONNREFUSED 127.0.0.1:443`.
pub fn connect_failure(error: &std::io::Error, address: std::net::IpAddr, port: u16) -> Failure {
    let code = io_code(error);
    Failure::coded(format!("connect {code} {address}:{port}"), &code)
}

/// Whether a request field is set: absent, null, false, 0 and "" are not.
pub fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64().is_some_and(|n| n != 0.0 && !n.is_nan()),
        Some(Value::String(text)) => !text.is_empty(),
        Some(_) => true,
    }
}

/// A field as a string; a number is written in its shortest form.
pub fn string_field(request: &Map<String, Value>, name: &str) -> Option<String> {
    match request.get(name)? {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number_text(number.as_f64().unwrap_or(0.0))),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

/// A field as a number; a numeric string counts.
pub fn number_field(request: &Map<String, Value>, name: &str) -> Option<f64> {
    match request.get(name)? {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

pub fn bool_field(request: &Map<String, Value>, name: &str) -> Option<bool> {
    match request.get(name)? {
        Value::Bool(flag) => Some(*flag),
        Value::Null => None,
        other => Some(truthy(Some(other))),
    }
}

/// A timeout in milliseconds with its default; anything under 1 ms is 1 ms.
pub fn timeout_field(request: &Map<String, Value>, name: &str, default: f64) -> std::time::Duration {
    let value = match request.get(name) {
        None | Some(Value::Null) => default,
        Some(_) => number_field(request, name).unwrap_or(default),
    };
    std::time::Duration::from_millis(if value.is_finite() && value >= 1.0 { value as u64 } else { 1 })
}

/// The shortest text of a number: `1`, `0.5`, `1e+21`. StatusTick compares these texts.
pub fn number_text(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity".to_string() } else { "-Infinity".to_string() };
    }
    if value == value.trunc() && value.abs() < 1e21 {
        return format!("{}", value as i64);
    }
    let mut buffer = ryu_js::Buffer::new();
    buffer.format(value).to_string()
}

/// The first [units] UTF-16 code units of [text]; StatusTick limits lengths in UTF-16 units.
pub fn utf16_prefix(text: &str, units: usize) -> &str {
    let mut count = 0;
    for (index, character) in text.char_indices() {
        count += character.len_utf16();
        if count > units {
            return &text[..index];
        }
    }
    text
}

/// UTF-16 code unit order, the order StatusTick sorts names in.
pub fn utf16_order(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// A JSON object from pairs, without the `None` values.
pub fn object(pairs: Vec<(&str, Option<Value>)>) -> Value {
    let mut map = Map::new();
    for (key, value) in pairs {
        if let Some(value) = value {
            map.insert(key.to_string(), value);
        }
    }
    Value::Object(map)
}
