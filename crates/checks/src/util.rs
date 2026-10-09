use std::fmt;
use std::time::Instant;

use serde_json::{Map, Value};

/// A failure as StatusTick expects it: the message, the Node.js-style code and the error name.
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

    /// A plain `Error` with a code, as Node.js system errors are.
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

/// `new Date().toISOString()`.
pub fn now_iso() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

pub fn iso(time: chrono::DateTime<chrono::Utc>) -> String {
    time.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// `Math.round(performance.now() - start)`.
pub fn elapsed_ms(start: Instant) -> i64 {
    (start.elapsed().as_secs_f64() * 1000.0).round() as i64
}

/// The errno names Node.js puts in `error.code`.
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

/// The code of an I/O error as Node.js names it.
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

/// `connect ECONNREFUSED 127.0.0.1:443`, the message of a failed Node.js connect.
pub fn connect_failure(error: &std::io::Error, address: std::net::IpAddr, port: u16) -> Failure {
    let code = io_code(error);
    Failure::coded(format!("connect {code} {address}:{port}"), &code)
}

/// JavaScript truthiness of a JSON value; absent is falsy.
pub fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64().is_some_and(|n| n != 0.0 && !n.is_nan()),
        Some(Value::String(text)) => !text.is_empty(),
        Some(_) => true,
    }
}

/// A field as a string; numbers are written as JavaScript would.
pub fn string_field(request: &Map<String, Value>, name: &str) -> Option<String> {
    match request.get(name)? {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(js_number(number.as_f64().unwrap_or(0.0))),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

/// A field as a number, as JavaScript coerces a numeric string.
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

/// A timeout in milliseconds with its default; JavaScript timers treat a negative or missing delay as 1 ms.
pub fn timeout_field(request: &Map<String, Value>, name: &str, default: f64) -> std::time::Duration {
    let value = match request.get(name) {
        None | Some(Value::Null) => default,
        Some(_) => number_field(request, name).unwrap_or(default),
    };
    std::time::Duration::from_millis(if value.is_finite() && value >= 1.0 { value as u64 } else { 1 })
}

/// `String(number)` for a finite number.
pub fn js_number(value: f64) -> String {
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

/// The first [units] UTF-16 code units of [text], as `String.prototype.slice(0, units)` keeps them.
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

/// JavaScript's `<` on strings: UTF-16 code unit order.
pub fn utf16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// Builds a JSON object from pairs, leaving out `None` values as `JSON.stringify` leaves out `undefined`.
pub fn object(pairs: Vec<(&str, Option<Value>)>) -> Value {
    let mut map = Map::new();
    for (key, value) in pairs {
        if let Some(value) = value {
            map.insert(key.to_string(), value);
        }
    }
    Value::Object(map)
}
