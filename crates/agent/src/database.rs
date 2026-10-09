//! Database checks on private agents: connect, log in and run one read-only command. Only timings, a
//! short error and, when the job has expectedValue, the one compared value leave the network.
use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};
use statustick_checks::connection::{Stream, Target as TlsTarget, connect_tls};
use statustick_checks::targets::{AllowRule, bound_to, parse_allow_list, resolve_allowed};
use statustick_checks::util::{Failure, bool_field, connect_failure, js_number, number_field, string_field, utf16_prefix};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::settings::{Env, env_value};

mod mongodb;
mod mysql;
mod postgres;
mod redis;

const SECRET_PREFIX: &str = "STATUSTICK_SECRET_";
const DEFAULT_TIMEOUT_MS: f64 = 10000.0;
const MAX_VALUE_LENGTH: usize = 200;
const MAX_ERROR_LENGTH: usize = 200;

/// Where a driver connects: [address] is the one the target policy allowed; [host] stays the TLS server name.
#[derive(Clone, Debug)]
pub struct Target {
    pub host: String,
    pub address: IpAddr,
    pub port: u16,
    pub database: Option<String>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub tls: bool,
    pub tls_verify: bool,
}

/// A failure with the driver's error code: a SQLSTATE, a MySQL error name or number, a MongoDB code, or a socket code.
#[derive(Debug, Clone)]
pub struct DriverError {
    pub message: String,
    pub code: Option<String>,
    /// Our own problem with its error code, reported as it is.
    pub own: bool,
}

impl DriverError {
    pub fn new(message: impl Into<String>, code: Option<&str>) -> Self {
        DriverError { message: message.into(), code: code.map(str::to_string), own: false }
    }

    pub fn problem(message: impl Into<String>, code: &str) -> Self {
        DriverError { message: message.into(), code: Some(code.to_string()), own: true }
    }
}

impl From<Failure> for DriverError {
    fn from(failure: Failure) -> Self {
        DriverError::new(failure.message, failure.code.as_deref())
    }
}

/// An open, logged-in connection.
pub enum Session {
    Postgres(postgres::Session),
    MySQL(mysql::Session),
    Redis(redis::Session),
    MongoDB(mongodb::Session),
}

impl Session {
    async fn run(&mut self, query: Option<&str>, timeout_ms: u64) -> Result<Value, DriverError> {
        match self {
            Session::Postgres(session) => session.run(query, timeout_ms).await,
            Session::MySQL(session) => session.run(query, timeout_ms).await,
            Session::Redis(session) => session.run().await,
            Session::MongoDB(session) => session.run().await,
        }
    }

    async fn close(self) {
        match self {
            Session::Postgres(session) => session.close().await,
            Session::MySQL(session) => session.close().await,
            Session::Redis(session) => session.close().await,
            Session::MongoDB(_) => {}
        }
    }
}

/// The agent's environment variable [name], read only when it starts with STATUSTICK_SECRET_.
pub fn read_secret(field: &str, name: &str, env: &Env) -> Result<String, DriverError> {
    let valid = name
        .strip_prefix(SECRET_PREFIX)
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'));
    if !valid {
        return Err(DriverError::problem(
            format!("{field} {name} is not allowed: the agent only reads variables that start with {SECRET_PREFIX}"),
            "SECRET_NOT_ALLOWED",
        ));
    }
    if name.ends_with("_HOSTS") {
        return Err(DriverError::problem(format!("{field} {name} is not allowed: a _HOSTS variable lists the hosts of a secret"), "SECRET_NOT_ALLOWED"));
    }
    env_value(env, name).map(str::to_string).ok_or_else(|| DriverError::problem(format!("{field} {name} is not set on the agent"), "SECRET_MISSING"))
}

struct Binding {
    name: String,
    rules: Vec<AllowRule>,
}

fn secret_bindings(user_env: Option<&str>, password_env: Option<&str>, env: &Env) -> Result<Vec<Binding>, DriverError> {
    let mut names: Vec<&str> = Vec::new();
    for name in [user_env, password_env].into_iter().flatten().filter(|name| !name.is_empty()) {
        if !names.contains(&name) {
            names.push(name);
        }
    }
    let mut bindings = Vec::new();
    for name in names {
        let setting = format!("{name}_HOSTS");
        match parse_allow_list(env_value(env, &setting).unwrap_or(""), &setting).map_err(|message| DriverError::problem(message, "SECRET_NOT_ALLOWED"))? {
            Some(rules) => bindings.push(Binding { name: name.to_string(), rules }),
            None if env_value(env, "STATUSTICK_REQUIRE_SECRET_HOSTS") == Some("true") => {
                return Err(DriverError::problem(format!("{name} is not bound to a host: set {setting} on the agent"), "SECRET_NOT_ALLOWED"));
            }
            None => {}
        }
    }
    Ok(bindings)
}

/// Without [address] only lists of host names are decided, so no DNS lookup is needed.
fn check_bindings(bindings: &[Binding], host: &str, address: Option<IpAddr>) -> Result<(), DriverError> {
    for Binding { name, rules } in bindings {
        if address.is_none() && rules.iter().any(|rule| matches!(rule, AllowRule::Range(_))) {
            continue;
        }
        if !bound_to(rules, host, address) {
            return Err(DriverError::problem(format!("{name} may not be sent to {host}: it is not in {name}_HOSTS"), "SECRET_NOT_ALLOWED"));
        }
    }
    Ok(())
}

/// Trimmed text is equal, or both sides are numbers with the same value ("1.0" and "1").
pub fn same_value(actual: &str, expected: &str) -> bool {
    let (a, b) = (actual.trim(), expected.trim());
    if a == b {
        return true;
    }
    let number = |text: &str| text.parse::<f64>().ok().filter(|value| value.is_finite());
    !a.is_empty() && !b.is_empty() && matches!((number(a), number(b)), (Some(x), Some(y)) if x == y)
}

/// A query answer as text, as `String(value)` in JavaScript: null is empty, objects are JSON.
pub fn value_text(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(text) => text.clone(),
        Value::Number(number) => number.as_f64().map(js_number).unwrap_or_else(|| number.to_string()),
        Value::Bool(flag) => flag.to_string(),
        other => other.to_string(),
    }
}

fn scrub(message: &str, password: Option<&str>) -> String {
    let text = match password.filter(|password| !password.is_empty()) {
        Some(password) => message.split(password).collect::<Vec<_>>().join("***"),
        None => message.to_string(),
    };
    utf16_prefix(&text, MAX_ERROR_LENGTH).to_string()
}

const AUTH_CODES: [&str; 7] = ["28P01", "28000", "ER_ACCESS_DENIED_ERROR", "ER_DBACCESS_DENIED_ERROR", "ER_ACCESS_DENIED_NO_PASSWORD_ERROR", "13", "18"];
const TIMEOUT_CODES: [&str; 4] = ["ETIMEDOUT", "57014", "ER_QUERY_TIMEOUT", "ER_STATEMENT_TIMEOUT"];

#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Connect,
    Auth,
    Query,
}

fn auth_message(message: &str) -> bool {
    let lower = message.to_lowercase();
    message.starts_with("WRONGPASS") || message.starts_with("NOAUTH") || lower.contains("authentication failed") || lower.contains("password must be")
}

fn failure_of(error: &DriverError, phase: Phase) -> (String, String) {
    if error.own {
        return (error.code.clone().unwrap_or_default(), error.message.clone());
    }
    let code = error.code.as_deref();
    if code.is_some_and(|code| TIMEOUT_CODES.contains(&code)) {
        return ("TIMEOUT".into(), "Timed out".into());
    }
    let message = if error.message.is_empty() { code.unwrap_or("Connection failed").to_string() } else { error.message.clone() };
    if code.is_some_and(|code| AUTH_CODES.contains(&code)) || auth_message(&message) {
        return ("AUTH_FAILED".into(), message);
    }
    // Database messages can quote data, so a failed query reports only its error code.
    if phase == Phase::Query {
        return ("QUERY_FAILED".into(), code.map(|code| format!("Query failed ({code})")).unwrap_or_else(|| "Query failed".into()));
    }
    ("CONNECT_FAILED".into(), message)
}

/// A TCP connection to the allowed address, failing as Node.js's `net.connect` does.
pub async fn connect_tcp(target: &Target) -> Result<TcpStream, DriverError> {
    TcpStream::connect((target.address, target.port)).await.map_err(|error| connect_failure(&error, target.address, target.port).into())
}

/// TLS over [stream] with Node.js's verification: the chain and, with tlsVerify, the host name.
pub async fn secure<S: Stream + 'static>(target: &Target, stream: S) -> Result<Box<dyn Stream>, DriverError> {
    let tls_target = TlsTarget { host: target.host.clone(), address: target.address, port: target.port };
    let tls = connect_tls(&tls_target, target.tls_verify, &[], stream).await?;
    Ok(Box::new(tls))
}

/// A plain or TLS stream to the target, for the drivers that speak their protocol over it.
pub async fn open_stream(target: &Target) -> Result<Box<dyn Stream>, DriverError> {
    let tcp = connect_tcp(target).await?;
    let _ = tcp.set_nodelay(true);
    if target.tls { secure(target, tcp).await } else { Ok(Box::new(tcp)) }
}

pub async fn read_exact(stream: &mut Box<dyn Stream>, buffer: &mut [u8]) -> Result<(), DriverError> {
    stream.read_exact(buffer).await.map(|_| ()).map_err(|error| DriverError::new(error.to_string(), Some(&statustick_checks::util::io_code(&error))))
}

pub async fn write_all(stream: &mut Box<dyn Stream>, bytes: &[u8]) -> Result<(), DriverError> {
    stream.write_all(bytes).await.map_err(|error| DriverError::new(error.to_string(), Some(&statustick_checks::util::io_code(&error))))
}

async fn open(kind: &str, target: &Target, connected: &mut Option<Instant>) -> Result<Session, DriverError> {
    match kind {
        "postgres" => postgres::open(target, connected).await.map(Session::Postgres),
        "mysql" => mysql::open(target, connected).await.map(Session::MySQL),
        "redis" => redis::open(target, connected).await.map(Session::Redis),
        _ => mongodb::open(target, connected).await.map(Session::MongoDB),
    }
}

fn elapsed(from: Instant) -> i64 {
    from.elapsed().as_millis() as i64
}

/// Runs one database check. Never fails.
pub async fn database_check(kind: &str, request: &Map<String, Value>, env: &Env) -> Value {
    let start = Instant::now();
    let timeout_ms = number_field(request, "timeout").unwrap_or(DEFAULT_TIMEOUT_MS);
    let timeout = Duration::from_millis(timeout_ms.max(0.0) as u64);
    let host = string_field(request, "host").unwrap_or_default();
    let user_env = string_field(request, "userEnv").filter(|name| !name.is_empty());
    let password_env = string_field(request, "passwordEnv").filter(|name| !name.is_empty());
    let database = string_field(request, "database");

    let prepared = (|| {
        let user = match &user_env {
            Some(name) => Some(read_secret("userEnv", name, env)?),
            None => string_field(request, "user"),
        };
        let password = match &password_env {
            Some(name) => Some(read_secret("passwordEnv", name, env)?),
            None => string_field(request, "password"),
        };
        let bindings = secret_bindings(user_env.as_deref(), password_env.as_deref(), env)?;
        check_bindings(&bindings, &host, None)?;
        if kind == "redis" && database.as_ref().is_some_and(|database| database.is_empty() || !database.bytes().all(|b| b.is_ascii_digit())) {
            return Err(DriverError::problem("database must be a Redis database number", "INVALID_DATABASE"));
        }
        Ok((user, password, bindings))
    })();
    let (user, password, bindings) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => return json!({ "status": "error", "responseTime": 0, "error": error.message, "errorCode": error.code }),
    };

    let deadline = tokio::time::Instant::now() + timeout;
    let timed_out = || DriverError::problem(format!("Timed out after {} ms", js_number(timeout_ms)), "TIMEOUT");
    let work = async {
        let address = match tokio::time::timeout_at(deadline, resolve_allowed(&host, 0)).await {
            Err(_) => return Err((timed_out(), Phase::Connect)),
            Ok(Ok(addresses)) => addresses[0],
            Ok(Err(failure)) if failure.is("TARGET_NOT_ALLOWED") => {
                return Ok(json!({ "status": "down", "responseTime": elapsed(start), "error": failure.message, "errorCode": "TARGET_NOT_ALLOWED" }));
            }
            Ok(Err(failure)) => return Err((failure.into(), Phase::Connect)),
        };
        if let Err(error) = check_bindings(&bindings, &host, Some(address)) {
            return Ok(json!({ "status": "error", "responseTime": elapsed(start), "error": error.message, "errorCode": error.code }));
        }
        let target = Target {
            host: host.clone(),
            address,
            port: number_field(request, "port").unwrap_or(0.0) as u16,
            database: database.clone(),
            user: user.clone(),
            password: password.clone(),
            tls: bool_field(request, "tls").unwrap_or(false),
            tls_verify: bool_field(request, "tlsVerify").unwrap_or(true),
        };
        let opened_at = Instant::now();
        let mut connected: Option<Instant> = None;
        let opening = tokio::time::timeout_at(deadline, open(kind, &target, &mut connected)).await;
        let phase = if connected.is_some() { Phase::Auth } else { Phase::Connect };
        let mut session = match opening {
            Err(_) => return Err((timed_out(), phase)),
            Ok(Err(error)) => return Err((error, phase)),
            Ok(Ok(session)) => session,
        };
        let logged_in_at = Instant::now();
        let connected_at = connected.unwrap_or(logged_in_at);
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now()).as_millis().max(1) as u64;
        let query = string_field(request, "query").filter(|query| !query.is_empty());
        let answer = match tokio::time::timeout_at(deadline, session.run(query.as_deref(), remaining)).await {
            Err(_) => return Err((timed_out(), Phase::Query)),
            Ok(Err(error)) => return Err((error, Phase::Query)),
            Ok(Ok(answer)) => answer,
        };
        let details = json!({
            "connectTime": connected_at.duration_since(opened_at).as_millis() as i64,
            "authTime": logged_in_at.duration_since(connected_at).as_millis() as i64,
            "queryTime": elapsed(logged_in_at),
        });
        tokio::spawn(session.close());
        let Some(expected) = string_field(request, "expectedValue") else {
            return Ok(json!({ "status": "up", "responseTime": elapsed(start), "details": details }));
        };
        let text = value_text(&answer);
        let mut details = details;
        details["value"] = Value::from(utf16_prefix(&text, MAX_VALUE_LENGTH));
        if same_value(&text, &expected) {
            return Ok(json!({ "status": "up", "responseTime": elapsed(start), "details": details }));
        }
        Ok(
            json!({ "status": "down", "responseTime": elapsed(start), "details": details, "error": "The value is not the expected value", "errorCode": "UNEXPECTED_VALUE" }),
        )
    };
    match work.await {
        Ok(result) => result,
        Err((error, phase)) => {
            let (code, message) = failure_of(&error, phase);
            json!({ "status": "down", "responseTime": elapsed(start), "error": scrub(&message, password.as_deref()), "errorCode": code })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Env {
        pairs.iter().map(|(name, value)| (name.to_string(), value.to_string())).collect()
    }

    fn request(value: Value) -> Map<String, Value> {
        value.as_object().cloned().unwrap()
    }

    #[test]
    fn compares_trimmed_text_and_numbers() {
        assert!(same_value(" ok ", "ok"));
        assert!(same_value("1.0", "1"));
        assert!(!same_value("", "0"));
        assert!(!same_value("a", "b"));
        assert_eq!(value_text(&json!(1.5)), "1.5");
        assert_eq!(value_text(&json!(null)), "");
        assert_eq!(value_text(&json!({ "a": 1 })), "{\"a\":1}");
    }

    #[tokio::test]
    async fn reads_secrets_only_from_statustick_secret_variables_and_their_hosts() {
        let wrong = database_check("postgres", &request(json!({ "host": "db", "port": 5432, "passwordEnv": "HOME" })), &env(&[])).await;
        assert_eq!(wrong["errorCode"], "SECRET_NOT_ALLOWED");
        assert_eq!(wrong["status"], "error");
        let missing = database_check("postgres", &request(json!({ "host": "db", "port": 5432, "passwordEnv": "STATUSTICK_SECRET_DB" })), &env(&[])).await;
        assert_eq!(missing["error"], "passwordEnv STATUSTICK_SECRET_DB is not set on the agent");
        assert_eq!(missing["errorCode"], "SECRET_MISSING");
        let bound = env(&[("STATUSTICK_SECRET_DB", "pw"), ("STATUSTICK_SECRET_DB_HOSTS", "db.internal")]);
        let elsewhere =
            database_check("postgres", &request(json!({ "host": "other.internal", "port": 5432, "passwordEnv": "STATUSTICK_SECRET_DB" })), &bound).await;
        assert_eq!(elsewhere["error"], "STATUSTICK_SECRET_DB may not be sent to other.internal: it is not in STATUSTICK_SECRET_DB_HOSTS");
        let required = env(&[("STATUSTICK_SECRET_DB", "pw"), ("STATUSTICK_REQUIRE_SECRET_HOSTS", "true")]);
        let unbound = database_check("mysql", &request(json!({ "host": "db", "port": 3306, "passwordEnv": "STATUSTICK_SECRET_DB" })), &required).await;
        assert_eq!(unbound["error"], "STATUSTICK_SECRET_DB is not bound to a host: set STATUSTICK_SECRET_DB_HOSTS on the agent");
        let redis = database_check("redis", &request(json!({ "host": "db", "port": 6379, "database": "one" })), &env(&[])).await;
        assert_eq!(redis["errorCode"], "INVALID_DATABASE");
    }

    #[test]
    fn maps_driver_failures_to_codes_without_quoting_query_errors() {
        assert_eq!(failure_of(&DriverError::new("password authentication failed for user \"x\"", Some("28P01")), Phase::Auth).0, "AUTH_FAILED");
        assert_eq!(failure_of(&DriverError::new("WRONGPASS invalid username-password pair", None), Phase::Auth).0, "AUTH_FAILED");
        assert_eq!(
            failure_of(&DriverError::new("canceling statement due to statement timeout", Some("57014")), Phase::Query),
            ("TIMEOUT".into(), "Timed out".into())
        );
        assert_eq!(
            failure_of(&DriverError::new("relation \"secret\" does not exist", Some("42P01")), Phase::Query),
            ("QUERY_FAILED".into(), "Query failed (42P01)".into())
        );
        assert_eq!(failure_of(&DriverError::new("connect ECONNREFUSED 10.0.0.5:5432", Some("ECONNREFUSED")), Phase::Connect).0, "CONNECT_FAILED");
        assert_eq!(scrub("bad pw secret here", Some("secret")), "bad pw *** here");
    }
}
