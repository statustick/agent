//! The harness of the agent's integration tests: a fake StatusTick that records every call, the agent as a process
//! and small local servers.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use serde_json::{Value, json};

use tokio::net::TcpListener;
use tokio::time::{Instant, sleep};

pub const TOKEN: &str = "sta_live_a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";

#[derive(Clone, Debug)]
pub struct Call {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub headers: HashMap<String, String>,
    pub body: Value,
    pub size: usize,
}

pub enum Answer {
    Hang,
    Reply(u16, Option<Value>, Vec<(&'static str, String)>),
}

pub fn reply(status: u16, body: Value) -> Answer {
    Answer::Reply(status, Some(body), vec![])
}

pub type Handler = Box<dyn Fn(&Call, usize) -> Answer + Send + Sync>;

/// A fake StatusTick: handlers by path, then the `*` handler; anything without one hangs like a long-poll with no jobs.
pub struct Platform {
    pub url: String,
    pub port: u16,
    pub calls: Arc<Mutex<Vec<Call>>>,
}

impl Platform {
    pub async fn start(handlers: Vec<(&'static str, Handler)>) -> Platform {
        let mut handlers: HashMap<&'static str, Handler> = handlers.into_iter().collect();
        let defaults: [(&'static str, Handler); 4] = [
            ("/v1/goodbye", Box::new(|_, _| Answer::Reply(204, None, vec![]))),
            ("/v1/heartbeat", Box::new(|_, _| Answer::Reply(204, None, vec![]))),
            ("/v1/results", Box::new(|call, _| reply(200, json!({ "accepted": lease_ids(&call.body), "rejected": [] })))),
            ("/health", Box::new(|_, _| Answer::Reply(200, Some(json!("ok")), vec![]))),
        ];
        for (path, handler) in defaults {
            handlers.entry(path).or_insert(handler);
        }
        let handlers = Arc::new(handlers);
        let calls = Arc::new(Mutex::new(Vec::<Call>::new()));
        let recorded = calls.clone();
        let app = Router::new().fallback(move |request: Request| {
            let handlers = handlers.clone();
            let calls = recorded.clone();
            async move {
                let (parts, body) = request.into_parts();
                let bytes = to_bytes(body, usize::MAX).await.unwrap_or_default();
                let text = String::from_utf8_lossy(&bytes).to_string();
                let body = if text.is_empty() { Value::Null } else { serde_json::from_str(&text).unwrap_or(Value::String(text)) };
                let query = parts
                    .uri
                    .query()
                    .map(|query| url::form_urlencoded::parse(query.as_bytes()).map(|(key, value)| (key.to_string(), value.to_string())).collect())
                    .unwrap_or_default();
                let headers = parts.headers.iter().map(|(name, value)| (name.to_string(), value.to_str().unwrap_or_default().to_string())).collect();
                let call = Call { method: parts.method.to_string(), path: parts.uri.path().to_string(), query, headers, body, size: bytes.len() };
                let count = {
                    let mut calls = calls.lock().unwrap();
                    calls.push(call.clone());
                    calls.iter().filter(|other| other.path == call.path).count()
                };
                match handlers.get(call.path.as_str()).or_else(|| handlers.get("*")).map(|handler| handler(&call, count)).unwrap_or(Answer::Hang) {
                    Answer::Hang => std::future::pending::<Response>().await,
                    Answer::Reply(status, body, headers) => {
                        let (content_type, payload) = match body {
                            Some(Value::String(text)) => ("text/plain", text),
                            Some(value) if status != 204 => ("application/json", value.to_string()),
                            _ => ("", String::new()),
                        };
                        let mut response = Response::new(Body::from(payload));
                        *response.status_mut() = StatusCode::from_u16(status).unwrap();
                        if !content_type.is_empty() {
                            response.headers_mut().insert("content-type", HeaderValue::from_static(content_type));
                        }
                        for (name, value) in headers {
                            response.headers_mut().insert(name, HeaderValue::from_str(&value).unwrap());
                        }
                        response
                    }
                }
            }
        });
        let listener = TcpListener::bind("[::]:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Platform { url: format!("http://localhost:{port}"), port, calls }
    }

    pub fn calls(&self, path: &str) -> Vec<Call> {
        self.calls.lock().unwrap().iter().filter(|call| call.path == path).cloned().collect()
    }

    pub fn all(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    /// Every result posted to /v1/results, by lease id.
    pub fn results(&self) -> Vec<Value> {
        let mut results: Vec<Value> = self.calls("/v1/results").iter().flat_map(|call| call.body["results"].as_array().cloned().unwrap_or_default()).collect();
        results.sort_by_key(|result| result["leaseId"].as_str().unwrap_or_default().to_string());
        results
    }
}

pub fn lease_ids(body: &Value) -> Value {
    body["results"].as_array().map(|results| results.iter().map(|result| result["leaseId"].clone()).collect()).unwrap_or_default()
}

pub fn in_one_minute() -> String {
    (chrono::Utc::now() + chrono::Duration::minutes(1)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub fn connected(extra: Value) -> Answer {
    let mut body = json!({
        "agentId": "agt_1",
        "sessionId": "ses_1",
        "location": { "id": "loc_1", "name": "Office" },
        "config": { "maxJobs": 20, "pollWaitSeconds": 1, "heartbeatSeconds": 30 }
    });
    if let Value::Object(extra) = extra {
        body.as_object_mut().unwrap().extend(extra);
    }
    reply(200, body)
}

pub fn jobs(jobs: Value) -> Answer {
    reply(200, json!({ "jobs": jobs }))
}

/// The agent as a process, with its stdout and stderr lines.
pub struct Agent {
    pub child: Child,
    pub lines: Arc<Mutex<Vec<String>>>,
    pub errors: Arc<Mutex<Vec<String>>>,
}

impl Agent {
    pub fn start(env: &[(&str, &str)], args: &[&str]) -> Agent {
        let home = std::env::temp_dir();
        let mut child = Command::new(env!("CARGO_BIN_EXE_statustick-agent"))
            .args(args)
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", home)
            .env("STATUSTICK_TOKEN", TOKEN)
            .env("STATUSTICK_HOSTNAME", "contract-host")
            .env("STATUSTICK_INSTALL", "other")
            .envs(env.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let collect = |stream: Box<dyn Read + Send>| {
            let into = Arc::new(Mutex::new(Vec::new()));
            let lines = into.clone();
            std::thread::spawn(move || BufReader::new(stream).lines().map_while(Result::ok).for_each(|line| lines.lock().unwrap().push(line)));
            into
        };
        let lines = collect(Box::new(child.stdout.take().unwrap()));
        let errors = collect(Box::new(child.stderr.take().unwrap()));
        Agent { child, lines, errors }
    }

    pub fn lines(&self) -> Vec<String> {
        self.lines.lock().unwrap().clone()
    }

    pub fn errors(&self) -> Vec<String> {
        self.errors.lock().unwrap().clone()
    }

    pub async fn exited(&mut self) -> Option<i32> {
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                // The reader threads finish at EOF; give them a moment to take the last lines.
                sleep(Duration::from_millis(100)).await;
                return status.code();
            }
            sleep(Duration::from_millis(50)).await;
        }
    }

    /// SIGTERM, then SIGKILL after 15 s; the exit code.
    pub async fn stop(&mut self) -> Option<i32> {
        if self.child.try_wait().unwrap().is_none() {
            unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) };
        }
        match tokio::time::timeout(Duration::from_secs(15), self.exited()).await {
            Ok(code) => code,
            Err(_) => {
                self.child.kill().ok();
                self.exited().await
            }
        }
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        self.child.kill().ok();
    }
}

pub async fn until(what: &str, ms: u64, predicate: impl Fn() -> bool) {
    let end = Instant::now() + Duration::from_millis(ms);
    while !predicate() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        sleep(Duration::from_millis(50)).await;
    }
}

pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A local HTTP target for checks: JSON on /json, text elsewhere.
pub async fn target() -> u16 {
    let app = Router::new().fallback(|request: Request| async move {
        let mut response = if request.uri().path() == "/json" {
            let mut response = Response::new(Body::from(r#"{"status":"ok","count":3}"#));
            response.headers_mut().insert("content-type", HeaderValue::from_static("application/json"));
            response.headers_mut().insert("x-version", HeaderValue::from_static("2"));
            response
        } else {
            Response::new(Body::from("hello contract"))
        };
        response.headers_mut().entry("content-type").or_insert(HeaderValue::from_static("text/plain"));
        response
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    port
}

/// One plain HTTP/1.1 request to a local port: the status and the body.
pub async fn request(port: u16, method: &str, path: &str) -> (u16, String) {
    let (method, path) = (method.to_string(), path.to_string());
    tokio::task::spawn_blocking(move || {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(stream, "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer).unwrap();
        let answer = String::from_utf8_lossy(&answer).to_string();
        let status = answer.split(' ').nth(1).and_then(|code| code.parse().ok()).unwrap_or(0);
        let (head, body) = answer.split_once("\r\n\r\n").unwrap_or((&answer, ""));
        let body = if head.to_ascii_lowercase().contains("transfer-encoding: chunked") { unchunk(body) } else { body.to_string() };
        (status, body)
    })
    .await
    .unwrap()
}

pub fn unchunk(mut body: &str) -> String {
    let mut out = String::new();
    while let Some((size, rest)) = body.split_once("\r\n") {
        let size = usize::from_str_radix(size.trim(), 16).unwrap_or(0);
        if size == 0 {
            break;
        }
        out.push_str(&rest[..size]);
        body = rest[size..].trim_start_matches("\r\n");
    }
    out
}

pub const TIMES: [&str; 9] = ["responseTime", "checkedAt", "at", "startedAt", "bufferedSince", "since", "connectTime", "authTime", "queryTime"];

/// Leaves out times and the machine values that differ between any two runs.
pub fn normalize(value: &Value) -> Value {
    fn walk(value: &Value, top: bool) -> Value {
        match value {
            Value::Array(items) => Value::Array(items.iter().map(|item| walk(item, false)).collect()),
            Value::Object(map) => Value::Object(
                map.iter()
                    .filter(|(name, _)| !TIMES.contains(&name.as_str()))
                    .filter(|(name, _)| !(top && ["memoryLimitBytes", "memoryLimited", "shmBytes", "cpuCount", "os", "arch"].contains(&name.as_str())))
                    .map(|(name, item)| (name.clone(), walk(item, false)))
                    .collect(),
            ),
            other => other.clone(),
        }
    }
    walk(value, true)
}

pub fn tempdir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("agent-contract-{}-{}", std::process::id(), rand_suffix()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

pub fn rand_suffix() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
}

pub fn httpdate(time: std::time::SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(time).format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}
