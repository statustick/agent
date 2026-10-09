//! The heartbeat relay: jobs inside the network ping the agent, and the agent forwards the pings to
//! StatusTick over its own outbound connection. Off unless STATUSTICK_RELAY_PORT is set.
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::Response;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::buffer::{LineBuffer, Log, write_atomically};

pub const MAX_PING_HASHES: usize = 20000;
pub const MAX_RELAY_BODY_BYTES: usize = 10 * 1024;
pub const RELAY_PINGS_PER_MINUTE: u32 = 600;
const MAX_SOURCES: usize = 10000;
const MAX_VERSION_CHARS: usize = 128;
const PINGS_FILE: &str = "pings.jsonl";
const LIST_FILE: &str = "relay.json";
const INVALID_RUN: &str = "Invalid run parameter: use 1 to 64 letters, digits, - or _";

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RelayAnswer {
    Accepted,
    Unknown,
    NotReady,
}

pub fn ping_hash(ping_id: &str) -> String {
    hex::encode(Sha256::digest(ping_id.as_bytes()))
}

fn token_chars(text: &str, max: usize) -> bool {
    (1..=max).contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

pub fn valid_run(run: &str) -> bool {
    token_chars(run, 64)
}

fn is_relayed_ping(value: &Value) -> bool {
    let kind = value.get("kind").and_then(Value::as_str);
    value.get("pingId").is_some_and(Value::is_string)
        && matches!(kind, Some("ping" | "start" | "fail"))
        && value.get("at").is_some_and(Value::is_string)
        && value.get("run").is_none_or(|run| run.as_str().is_some_and(valid_run))
}

/// Pings waiting for StatusTick, with the time each arrived; `pings.jsonl` in STATUSTICK_BUFFER_DIR.
pub fn ping_buffer(size: usize, dir: Option<&str>, log: Log) -> LineBuffer {
    LineBuffer::new(
        size,
        dir.map(|dir| Path::new(dir).join(PINGS_FILE)),
        log,
        is_relayed_ping,
        |entry| entry["at"].as_str().unwrap_or("").to_string(),
        "heartbeat pings",
    )
}

/// The ping tokens StatusTick allows, as SHA-256 hashes, so neither memory nor `relay.json` holds a token. Until the
/// first list arrives (from StatusTick, or from disk after a restart) the relay answers 503.
pub struct PingAllowList {
    pub version: Option<String>,
    hashes: HashSet<String>,
    order: Vec<String>,
    file: Option<PathBuf>,
    log: Log,
}

impl PingAllowList {
    pub fn new(dir: Option<&str>, log: Log) -> Self {
        let mut list = PingAllowList { version: None, hashes: HashSet::new(), order: Vec::new(), file: dir.map(|dir| Path::new(dir).join(LIST_FILE)), log };
        list.load();
        list
    }

    pub fn received(&self) -> bool {
        self.version.is_some()
    }

    pub fn allows(&self, ping_id: &str) -> bool {
        self.hashes.contains(&ping_hash(ping_id))
    }

    /// Takes a list from a connect or lease answer; anything not shaped as a ping list is ignored.
    pub fn update(&mut self, list: Option<&Value>) {
        let Some(list) = list.and_then(Value::as_object) else { return };
        let (Some(version), Some(hashes)) = (list.get("version").and_then(Value::as_str), list.get("pingHashes").and_then(Value::as_array)) else { return };
        if version.encode_utf16().count() > MAX_VERSION_CHARS || self.version.as_deref() == Some(version) {
            return;
        }
        if hashes.len() > MAX_PING_HASHES {
            (self.log)(&format!("Heartbeat relay: StatusTick sent {} ping URLs; only the first {MAX_PING_HASHES} are accepted.", hashes.len()));
        }
        let mut set = HashSet::new();
        let mut order = Vec::new();
        for hash in hashes.iter().take(MAX_PING_HASHES).filter_map(Value::as_str) {
            if hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) && set.insert(hash.to_string()) {
                order.push(hash.to_string());
            }
        }
        if !self.received() || set.len() != self.hashes.len() {
            (self.log)(&format!("Heartbeat relay: accepting pings for {} heartbeat monitors.", set.len()));
        }
        self.version = Some(version.to_string());
        self.hashes = set;
        self.order = order;
        self.save();
    }

    fn load(&mut self) {
        let Some(file) = self.file.clone() else { return };
        let saved = match std::fs::read_to_string(&file) {
            Ok(text) => serde_json::from_str::<Value>(&text),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => return (self.log)(&format!("Ignoring {}: {error}", file.display())),
        };
        match saved {
            Ok(saved) => {
                self.file = None;
                self.update(Some(&saved));
                self.file = Some(file);
            }
            Err(error) => (self.log)(&format!("Ignoring {}: {error}", file.display())),
        }
    }

    fn save(&mut self) {
        let Some(file) = self.file.clone() else { return };
        let data = json!({ "version": self.version, "pingHashes": self.order }).to_string();
        if let Err(error) = write_atomically(&file, &data) {
            (self.log)(&format!("Relay file {} cannot be written ({error}); keeping the ping list in memory only.", file.display()));
            self.file = None;
        }
    }
}

/// A fixed window per source address; a full table refuses new sources until the window ends.
pub struct SourceLimit {
    limit: u32,
    window_ms: i64,
    window_start: i64,
    counts: HashMap<String, u32>,
}

impl SourceLimit {
    pub fn new(limit: u32, window_ms: i64) -> Self {
        SourceLimit { limit, window_ms, window_start: 0, counts: HashMap::new() }
    }

    pub fn allow(&mut self, source: &str, now: i64) -> bool {
        if now - self.window_start >= self.window_ms {
            self.window_start = now;
            self.counts.clear();
        }
        let count = self.counts.get(source).copied().unwrap_or(0);
        if count >= self.limit || (count == 0 && self.counts.len() >= MAX_SOURCES) {
            return false;
        }
        self.counts.insert(source.to_string(), count + 1);
        true
    }
}

/// `(token, kind)` of `/ping/<token>`, `/ping/<token>/start` and `/ping/<token>/fail`, also with the public `/v1` prefix.
pub fn parse_ping_path(path: &str) -> Option<(String, &'static str)> {
    let rest = path.strip_prefix("/v1/ping/").or_else(|| path.strip_prefix("/ping/"))?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let mut parts = rest.split('/');
    let token = parts.next()?;
    let kind = match parts.next() {
        None => "ping",
        Some("start") => "start",
        Some("fail") => "fail",
        Some(_) => return None,
    };
    (parts.next().is_none() && token_chars(token, 128)).then(|| (token.to_string(), kind))
}

fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let decode = |text: &str| percent_encoding::percent_decode_str(&text.replace('+', " ")).decode_utf8_lossy().into_owned();
        (decode(key) == name).then(|| decode(value))
    })
}

pub type Relay = Arc<dyn Fn(&str, &str, Option<&str>) -> RelayAnswer + Send + Sync>;

struct RelayState {
    relay: Relay,
    limit: Mutex<SourceLimit>,
}

fn text(status: u16, body: &str, headers: &[(&'static str, &'static str)]) -> Response {
    let mut response = Response::new(Body::from(format!("{body}\n")));
    *response.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    for (name, value) in headers {
        response.headers_mut().insert(*name, HeaderValue::from_static(value));
    }
    response
}

async fn answer(State(state): State<Arc<RelayState>>, ConnectInfo(source): ConnectInfo<SocketAddr>, request: Request) -> Response {
    if !state.limit.lock().expect("relay limit").allow(&source.ip().to_string(), chrono::Utc::now().timestamp_millis()) {
        return text(429, "Too many pings", &[("retry-after", "60")]);
    }
    let Some((ping_id, kind)) = parse_ping_path(request.uri().path()) else { return text(404, "Unknown ping URL", &[]) };
    if ![Method::GET, Method::POST, Method::HEAD].contains(request.method()) {
        return text(405, "Method not allowed", &[("allow", "GET, POST, HEAD")]);
    }
    let run = query_param(request.uri().query().unwrap_or(""), "run");
    if run.as_deref().is_some_and(|run| !valid_run(run)) {
        return text(400, INVALID_RUN, &[]);
    }
    let declared =
        request.headers().get(header::CONTENT_LENGTH).and_then(|value| value.to_str().ok()).and_then(|value| value.parse::<usize>().ok()).unwrap_or(0);
    if declared > MAX_RELAY_BODY_BYTES || axum::body::to_bytes(request.into_body(), MAX_RELAY_BODY_BYTES).await.is_err() {
        return text(413, "Body too large", &[]);
    }
    match (state.relay)(&ping_id, kind, run.as_deref()) {
        RelayAnswer::Accepted => text(200, "OK", &[]),
        RelayAnswer::NotReady => text(503, "Ping list not received from StatusTick yet", &[("retry-after", "30")]),
        RelayAnswer::Unknown => text(404, "Unknown ping URL", &[]),
    }
}

/// The relay port: answers in plain text like the public ping URL.
pub fn relay_router(relay: Relay) -> axum::Router {
    let state = Arc::new(RelayState { relay, limit: Mutex::new(SourceLimit::new(RELAY_PINGS_PER_MINUTE, 60 * 1000)) });
    axum::Router::new().fallback(answer).with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_public_ping_paths() {
        assert_eq!(parse_ping_path("/ping/abc_1"), Some(("abc_1".into(), "ping")));
        assert_eq!(parse_ping_path("/v1/ping/abc/start/"), Some(("abc".into(), "start")));
        assert_eq!(parse_ping_path("/ping/abc/fail"), Some(("abc".into(), "fail")));
        assert_eq!(parse_ping_path("/ping/abc/other"), None);
        assert_eq!(parse_ping_path("/ping/"), None);
        assert_eq!(parse_ping_path("/other/abc"), None);
        assert_eq!(query_param("a=1&run=job%2D7", "run").as_deref(), Some("job-7"));
    }

    #[test]
    fn keeps_only_well_formed_hashes_and_reads_them_back() {
        let dir = std::env::temp_dir().join(format!("agent-relay-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log: Log = Arc::new(|_: &str| {});
        let mut list = PingAllowList::new(dir.to_str(), log.clone());
        assert!(!list.received());
        list.update(Some(&json!({ "version": "v1", "pingHashes": [ping_hash("tok"), "not-a-hash", 7] })));
        assert!(list.allows("tok") && !list.allows("other"));
        let text = std::fs::read_to_string(dir.join(LIST_FILE)).unwrap();
        assert!(!text.contains("\"tok\""));
        let again = PingAllowList::new(dir.to_str(), log);
        assert_eq!(again.version.as_deref(), Some("v1"));
        assert!(again.allows("tok"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn limits_pings_per_source_in_a_window() {
        let mut limit = SourceLimit::new(2, 60000);
        assert!(limit.allow("a", 1) && limit.allow("a", 2));
        assert!(!limit.allow("a", 3));
        assert!(limit.allow("b", 3));
        assert!(limit.allow("a", 60001));
    }
}
