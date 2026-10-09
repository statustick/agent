//! The agent's side of protocol v1: every call goes out to one host, nothing calls the agent.
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use serde_json::{Value, json};
use statustick_checks::util::Failure;

use crate::VERSION;

const CALL_TIMEOUT: Duration = Duration::from_secs(15);
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(60);
/// The characters `encodeURIComponent` escapes.
const COMPONENT: &percent_encoding::AsciiSet =
    &percent_encoding::NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'!').remove(b'~').remove(b'*').remove(b'\'').remove(b'(').remove(b')');
pub const REPLACED: &str = "agent.replaced";

#[derive(Debug, Clone)]
pub enum CallError {
    /// StatusTick answered with an error status: `{ "error": "<code>" }`.
    Api { status: u16, code: Option<String>, body: Value, retry_after_seconds: Option<f64> },
    /// No answer: the connection, DNS, TLS or a timeout failed; `proxy_status` when a proxy refused the call.
    Network { description: String, proxy_status: Option<u16> },
}

impl CallError {
    pub fn status(&self) -> Option<u16> {
        match self {
            CallError::Api { status, .. } => Some(*status),
            CallError::Network { .. } => None,
        }
    }

    pub fn code(&self) -> Option<&str> {
        match self {
            CallError::Api { code, .. } => code.as_deref(),
            CallError::Network { .. } => None,
        }
    }

    pub fn body_text(&self, name: &str) -> Option<String> {
        match self {
            CallError::Api { body, .. } => body.get(name).and_then(Value::as_str).map(str::to_string),
            CallError::Network { .. } => None,
        }
    }

    pub fn retry_after_ms(&self) -> Option<u64> {
        match self {
            CallError::Api { retry_after_seconds: Some(seconds), .. } => Some((seconds * 1000.0) as u64),
            _ => None,
        }
    }

    /// As the agent logs it: `401 token.unauthorized`, `HTTP 502`, or the socket code.
    pub fn describe(&self) -> String {
        match self {
            CallError::Api { status, code: Some(code), .. } => format!("{status} {code}"),
            CallError::Api { status, .. } => format!("HTTP {status}"),
            CallError::Network { description, .. } => description.clone(),
        }
    }

    /// Any answer but a 5xx means StatusTick is reachable.
    pub fn is_outage(&self) -> bool {
        self.status().is_none_or(|status| status >= 500)
    }

    pub fn is_retryable(&self) -> bool {
        self.status().is_none_or(|status| status == 401 || status == 429 || status >= 500)
    }
}

/// Resolves StatusTick's host with the same lookup as the checks, so a failure names its code (`ENOTFOUND`).
struct Lookup;

impl Resolve for Lookup {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let addresses = statustick_checks::targets::lookup(name.as_str(), 0).await?;
            let addrs: Addrs = Box::new(addresses.into_iter().map(|address| SocketAddr::new(address, 0)).collect::<Vec<_>>().into_iter());
            Ok(addrs)
        })
    }
}

pub struct Client {
    pub base_url: String,
    token: String,
    http: reqwest::Client,
    ids: Mutex<(Option<String>, Option<String>)>,
    replaced: AtomicBool,
    last_call_ms: AtomicI64,
}

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn network_error(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        return "The operation was aborted due to timeout".to_string();
    }
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    let mut deepest = error.to_string();
    while let Some(inner) = current {
        if let Some(failure) = inner.downcast_ref::<Failure>() {
            return failure.code.clone().unwrap_or_else(|| failure.message.clone());
        }
        if let Some(io) = inner.downcast_ref::<std::io::Error>() {
            let code = statustick_checks::util::io_code(io);
            if code != "EIO" && !code.is_empty() {
                return code;
            }
        }
        if let Some(node) = statustick_checks::tls::node_error(inner) {
            return node.code;
        }
        deepest = inner.to_string();
        current = inner.source();
    }
    deepest
}

impl Client {
    pub fn new(base_url: &str, token: &str, proxy: Option<&url::Url>) -> Self {
        let mut builder = reqwest::Client::builder()
            .use_preconfigured_tls((*statustick_checks::tls::client_config(true, &["h2", "http/1.1"])).clone())
            .dns_resolver(Arc::new(Lookup))
            .no_proxy();
        if let Some(proxy) = proxy.and_then(|proxy| reqwest::Proxy::all(proxy.as_str()).ok()) {
            builder = builder.proxy(proxy);
        }
        Client {
            base_url: base_url.to_string(),
            token: token.to_string(),
            http: builder.build().expect("HTTP client"),
            ids: Mutex::new((None, None)),
            replaced: AtomicBool::new(false),
            last_call_ms: AtomicI64::new(0),
        }
    }

    pub fn agent_id(&self) -> Option<String> {
        self.ids.lock().expect("ids").0.clone()
    }

    pub fn forget_agent(&self) {
        self.ids.lock().expect("ids").0 = None;
    }

    pub fn replaced(&self) -> bool {
        self.replaced.load(Ordering::Relaxed)
    }

    pub fn last_call_ms(&self) -> i64 {
        self.last_call_ms.load(Ordering::Relaxed)
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let (agent_id, session_id) = self.ids.lock().expect("ids").clone();
        let mut request = self
            .http
            .request(method, format!("{}{path}", self.base_url))
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Agent-Version", VERSION)
            .header("User-Agent", format!("StatusTick-Agent/{VERSION}"));
        if let Some(id) = agent_id {
            request = request.header("Agent-Id", id);
        }
        if let Some(session) = session_id {
            request = request.header("Agent-Session", session);
        }
        request
    }

    async fn send(&self, request: reqwest::RequestBuilder, url: &str) -> Result<reqwest::Response, CallError> {
        if self.replaced() {
            return Err(CallError::Api { status: 409, code: Some(REPLACED.into()), body: json!({ "error": REPLACED }), retry_after_seconds: None });
        }
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => {
                let target = url::Url::parse(url).ok();
                let refused = match &target {
                    Some(target) => statustick_checks::proxy::refused(&error, target).await,
                    None => None,
                };
                let proxy_status = refused.as_deref().and_then(|text| text.rsplit(' ').next()).and_then(|status| status.parse().ok());
                return Err(CallError::Network { description: network_error(&error), proxy_status });
            }
        };
        if response.status().is_success() {
            self.last_call_ms.store(now_ms(), Ordering::Relaxed);
            return Ok(response);
        }
        let status = response.status().as_u16();
        let retry_after_seconds = response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<f64>().ok())
            .filter(|seconds| *seconds > 0.0);
        let body = response.json::<Value>().await.ok().filter(Value::is_object).unwrap_or_else(|| json!({}));
        let code = body.get("error").and_then(Value::as_str).map(str::to_string);
        if status == 409 && code.as_deref() == Some(REPLACED) {
            self.replaced.store(true, Ordering::Relaxed);
        }
        Err(CallError::Api { status, code, body, retry_after_seconds })
    }

    pub async fn call(&self, method: reqwest::Method, path: &str, body: Option<&Value>, timeout: Duration) -> Result<Value, CallError> {
        let mut request = self.request(method, path).timeout(timeout);
        if let Some(body) = body {
            request = request.header("Content-Type", "application/json").body(body.to_string());
        }
        let response = self.send(request, &format!("{}{path}", self.base_url)).await?;
        if response.status().as_u16() == 204 {
            return Ok(Value::Null);
        }
        let text = response.text().await.map_err(|error| CallError::Network { description: network_error(&error), proxy_status: None })?;
        serde_json::from_str(&text).map_err(|error| CallError::Network { description: error.to_string(), proxy_status: None })
    }

    pub async fn connect(&self, request: &Value) -> Result<Value, CallError> {
        *self.ids.lock().expect("ids") = (None, None);
        let answer = self.call(reqwest::Method::POST, "/v1/connect", Some(request), CALL_TIMEOUT).await?;
        let agent_id = answer.get("agentId").and_then(Value::as_str).map(str::to_string);
        let session = answer.get("sessionId").and_then(Value::as_str).filter(|session| !session.is_empty()).map(str::to_string);
        *self.ids.lock().expect("ids") = (agent_id, session);
        Ok(answer)
    }

    /// `relay` is the version of the agent's ping list, empty before it has one; None while the relay is off.
    pub async fn lease_jobs(&self, max: usize, wait: u64, relay: Option<&str>) -> Result<Value, CallError> {
        let list = relay.map(|version| format!("&relay={}", percent_encoding::utf8_percent_encode(version, COMPONENT))).unwrap_or_default();
        self.call(reqwest::Method::GET, &format!("/v1/jobs?wait={wait}&max={max}{list}"), None, Duration::from_secs(wait + 15)).await
    }

    pub async fn post_results(&self, results: &[Value]) -> Result<Value, CallError> {
        self.call(reqwest::Method::POST, "/v1/results", Some(&json!({ "results": results })), CALL_TIMEOUT).await
    }

    pub async fn post_late_results(&self, request: &Value) -> Result<Value, CallError> {
        self.call(reqwest::Method::POST, "/v1/results/late", Some(request), CALL_TIMEOUT).await
    }

    pub async fn post_relayed_pings(&self, request: &Value) -> Result<Value, CallError> {
        self.call(reqwest::Method::POST, "/v1/heartbeats/relay", Some(request), CALL_TIMEOUT).await
    }

    pub async fn put_discovery(&self, request: &Value) -> Result<Value, CallError> {
        self.call(reqwest::Method::PUT, "/v1/discovery/kubernetes", Some(request), CALL_TIMEOUT).await
    }

    pub async fn post_metrics(&self, text: String) -> Result<(), CallError> {
        let request =
            self.request(reqwest::Method::POST, "/v1/agent/metrics").header("Content-Type", "text/plain; version=0.0.4").timeout(CALL_TIMEOUT).body(text);
        self.send(request, &format!("{}/v1/agent/metrics", self.base_url)).await.map(|_| ())
    }

    pub async fn goodbye(&self, timeout: Duration) -> Result<Value, CallError> {
        self.call(reqwest::Method::POST, "/v1/goodbye", Some(&json!({ "reason": "stopping" })), timeout).await
    }

    pub async fn heartbeat(&self, body: Option<&Value>) -> Result<Value, CallError> {
        self.call(reqwest::Method::POST, "/v1/heartbeat", body, CALL_TIMEOUT).await
    }

    /// A browser run's screenshot or trace, sent before the lease's result.
    pub async fn upload_artifact(&self, lease_id: &str, name: &str, data: Vec<u8>) -> Result<(), CallError> {
        let lease = percent_encoding::utf8_percent_encode(lease_id, COMPONENT).to_string();
        let path = format!("/v1/leases/{lease}/artifacts/{name}");
        let content_type = match name {
            "screenshot.png" => "image/png",
            "trace.zip" => "application/zip",
            _ => "application/octet-stream",
        };
        let request = self.request(reqwest::Method::PUT, &path).header("Content-Type", content_type).timeout(UPLOAD_TIMEOUT).body(data);
        self.send(request, &format!("{}{path}", self.base_url)).await.map(|_| ())
    }
}
