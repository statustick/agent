//! Kubernetes service discovery: Services with a `statustick.com/monitor` annotation become
//! monitors of the agent's location. Plain HTTPS to the API server with the pod's service account token and CA.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt;
use serde_json::{Value, json};

use crate::buffer::Log;

pub const MONITOR_ANNOTATION: &str = "statustick.com/monitor";
pub const NAME_ANNOTATION: &str = "statustick.com/name";
pub const INTERVAL_ANNOTATION: &str = "statustick.com/interval";
const DEFAULT_INTERVAL_SECONDS: i64 = 60;
const MIN_INTERVAL_SECONDS: i64 = 30;
const MAX_INTERVAL_SECONDS: i64 = 86400;
const MAX_NAME_CHARS: usize = 100;
const MAX_PATH_CHARS: usize = 1000;
const SERVICE_ACCOUNT: &str = "/var/run/secrets/kubernetes.io/serviceaccount";
const PAGE_SIZE: usize = 250;
const LIST_TIMEOUT: Duration = Duration::from_secs(30);
const WATCH_SECONDS: u64 = 300;
const MAX_EVENT_BYTES: usize = 1024 * 1024;
const BACKOFF_BASE_MS: f64 = 1000.0;
const BACKOFF_MAX_MS: f64 = 60000.0;

/// A monitor, or the error of a wrong annotation.
#[derive(Clone, Debug, PartialEq)]
pub enum Discovered {
    Monitor(Value),
    Error(String),
}

fn interval_of(value: Option<&str>) -> Option<i64> {
    let Some(value) = value else { return Some(DEFAULT_INTERVAL_SECONDS) };
    let value = value.trim();
    let (digits, unit) = match value.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((at, _)) => value.split_at(at),
        None => (value, "s"),
    };
    if digits.is_empty() || digits.len() > 6 {
        return None;
    }
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        _ => return None,
    };
    let seconds = digits.parse::<i64>().ok()? * multiplier;
    (MIN_INTERVAL_SECONDS..=MAX_INTERVAL_SECONDS).contains(&seconds).then_some(seconds)
}

fn port_name(text: &str) -> bool {
    let bytes = text.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes[0].is_ascii_lowercase()
        && bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        && bytes[bytes.len() - 1] != b'-'
}

/// `<type>[:<port number or name>][/<path>]`: the type, the port part and the path.
fn parse_monitor(value: &str) -> Option<(&str, Option<&str>, Option<&str>)> {
    let (kind, rest) = match value.strip_prefix("http") {
        Some(rest) => ("http", rest),
        None => ("tcp", value.strip_prefix("tcp")?),
    };
    let (port_part, path) = match rest.find('/') {
        Some(at) => (&rest[..at], Some(&rest[at..])),
        None => (rest, None),
    };
    if path.is_some_and(|path| path.chars().any(char::is_whitespace)) {
        return None;
    }
    let port = match port_part.strip_prefix(':') {
        None if port_part.is_empty() => None,
        None => return None,
        Some("") => None,
        Some(port) if port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit()) => Some(port),
        Some(port) if port_name(port) => Some(port),
        Some(_) => return None,
    };
    Some((kind, port, path))
}

/// The monitor a Service asks for, an error for a wrong annotation, or None without the monitor annotation.
pub fn monitor_of(service: &Value) -> Option<Discovered> {
    let metadata = service.get("metadata")?;
    let name = metadata.get("name").and_then(Value::as_str).filter(|name| !name.is_empty())?;
    let namespace = metadata.get("namespace").and_then(Value::as_str).filter(|namespace| !namespace.is_empty())?;
    let annotations = metadata.get("annotations").filter(|annotations| annotations.is_object());
    let annotation = |key: &str| annotations.and_then(|annotations| annotations.get(key)).and_then(Value::as_str);
    let value = annotation(MONITOR_ANNOTATION)?;
    let key = format!("{namespace}/{name}");
    let Some((kind, port_value, path)) = parse_monitor(value.trim()) else {
        let shown: String = value.encode_utf16().take(100).collect::<Vec<_>>().pipe(|units| String::from_utf16_lossy(&units));
        return Some(Discovered::Error(format!(
            "{MONITOR_ANNOTATION} must look like \"http:/healthz\", \"http:8080/healthz\" or \"tcp:5432\", not \"{shown}\""
        )));
    };
    if kind == "tcp" && path.is_some() {
        return Some(Discovered::Error(format!("{MONITOR_ANNOTATION}: a tcp monitor has no path")));
    }
    if path.is_some_and(|path| path.encode_utf16().count() > MAX_PATH_CHARS) {
        return Some(Discovered::Error(format!("{MONITOR_ANNOTATION}: the path is longer than {MAX_PATH_CHARS} characters")));
    }
    let ports: Vec<Value> = service.pointer("/spec/ports").and_then(Value::as_array).cloned().unwrap_or_default();
    let port = match port_value {
        Some(number) if number.bytes().all(|b| b.is_ascii_digit()) => number.parse::<f64>().ok(),
        Some(port_name) => {
            ports.iter().find(|port| port.get("name").and_then(Value::as_str) == Some(port_name)).and_then(|port| port.get("port")).and_then(Value::as_f64)
        }
        None => ports.first().and_then(|port| port.get("port")).and_then(Value::as_f64),
    };
    let Some(port) = port.filter(|port| port.fract() == 0.0 && (1.0..=65535.0).contains(port)).map(|port| port as u16) else {
        return Some(Discovered::Error(match port_value {
            Some(port_value) => format!("{MONITOR_ANNOTATION}: the Service has no port \"{port_value}\""),
            None => "the Service has no port".to_string(),
        }));
    };
    let Some(interval) = interval_of(annotation(INTERVAL_ANNOTATION)) else {
        return Some(Discovered::Error(format!(
            "{INTERVAL_ANNOTATION} must be seconds from {MIN_INTERVAL_SECONDS} to {MAX_INTERVAL_SECONDS}, for example \"60\", \"5m\" or \"1h\""
        )));
    };
    let host = format!("{name}.{namespace}.svc");
    let target = if kind == "http" { format!("http://{host}:{port}{}", path.unwrap_or("/")) } else { format!("{host}:{port}") };
    let label: String =
        annotation(NAME_ANNOTATION).unwrap_or("").trim().encode_utf16().take(MAX_NAME_CHARS).collect::<Vec<_>>().pipe(|units| String::from_utf16_lossy(&units));
    let label = if label.is_empty() { key.clone() } else { label };
    Some(Discovered::Monitor(json!({ "key": key, "type": kind, "target": target, "name": label, "intervalSeconds": interval })))
}

trait Pipe: Sized {
    fn pipe<T>(self, f: impl FnOnce(Self) -> T) -> T {
        f(self)
    }
}

impl<T> Pipe for T {}

/// The API server as seen from inside the pod: the service account's token (read on every call, it rotates) and CA.
pub struct KubernetesApi {
    base_url: String,
    token_file: String,
    http: reqwest::Client,
}

impl KubernetesApi {
    /// Fails with a message for the operator outside a pod or without a mounted service account token.
    pub fn in_cluster(host: Option<&str>, port: Option<&str>) -> Result<Self, String> {
        let host = host.unwrap_or("").trim();
        let port = Some(port.unwrap_or("443").trim()).filter(|port| !port.is_empty()).unwrap_or("443");
        if host.is_empty() {
            return Err("STATUSTICK_DISCOVERY=kubernetes works only inside a Kubernetes pod (KUBERNETES_SERVICE_HOST is not set)".into());
        }
        let token_file = format!("{SERVICE_ACCOUNT}/token");
        let missing =
            || format!("STATUSTICK_DISCOVERY=kubernetes needs the pod's service account token in {SERVICE_ACCOUNT} (automountServiceAccountToken: true)");
        std::fs::File::open(&token_file).map_err(|_| missing())?;
        let ca = std::fs::read(format!("{SERVICE_ACCOUNT}/ca.crt")).map_err(|_| missing())?;
        use rustls::pki_types::pem::PemObject;
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(rustls::pki_types::CertificateDer::pem_slice_iter(&ca).filter_map(Result::ok));
        let tls = rustls::ClientConfig::builder_with_provider(statustick_checks::tls::provider())
            .with_safe_default_protocol_versions()
            .map_err(|error| error.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        // Never through HTTPS_PROXY: the API server is inside the cluster.
        let http = reqwest::Client::builder().use_preconfigured_tls(tls).no_proxy().build().map_err(|error| error.to_string())?;
        let authority = if host.contains(':') { format!("[{host}]") } else { host.to_string() };
        Ok(KubernetesApi { base_url: format!("https://{authority}:{port}"), token_file, http })
    }

    async fn get(&self, path: &str, timeout: Duration) -> Result<reqwest::Response, String> {
        let token = std::fs::read_to_string(&self.token_file).map_err(|error| error.to_string())?;
        self.http
            .get(format!("{}{path}", self.base_url))
            .bearer_auth(token.trim())
            .header("Accept", "application/json")
            .timeout(timeout)
            .send()
            .await
            .map_err(|error| error.to_string())
    }
}

enum Failure {
    Status(u16, String),
    Other(String),
}

fn backoff(attempt: u32) -> Duration {
    let ceiling = BACKOFF_MAX_MS.min(BACKOFF_BASE_MS * 2f64.powi(attempt.min(30) as i32));
    Duration::from_millis((ceiling / 2.0 + rand::random::<f64>() * ceiling / 2.0).round() as u64)
}

type Services = BTreeMap<String, Discovered>;
/// The Services of each scope, the scopes listed once, and the last error logged.
type DiscoveryState = (BTreeMap<Option<String>, Services>, Vec<Option<String>>, Option<String>);

/// Lists the Services of every namespace (or of each listed one), then watches them. `desired` is None until every
/// namespace was listed once, so a failing list never looks like "no Services".
pub struct KubernetesDiscovery {
    api: KubernetesApi,
    scopes: Vec<Option<String>>,
    changed: Arc<dyn Fn() + Send + Sync>,
    log: Log,
    state: Mutex<DiscoveryState>,
}

impl KubernetesDiscovery {
    pub fn new(api: KubernetesApi, namespaces: Option<Vec<String>>, changed: Arc<dyn Fn() + Send + Sync>, log: Log) -> Arc<Self> {
        let scopes: Vec<Option<String>> = match namespaces {
            Some(names) => names.into_iter().map(Some).collect(),
            None => vec![None],
        };
        let services = scopes.iter().map(|scope| (scope.clone(), Services::new())).collect();
        Arc::new(KubernetesDiscovery { api, scopes, changed, log, state: Mutex::new((services, Vec::new(), None)) })
    }

    /// The monitors to send, sorted by key; None while a namespace was never listed.
    pub fn desired(&self) -> Option<Vec<Value>> {
        let state = self.state.lock().expect("discovery");
        if state.1.len() < self.scopes.len() {
            return None;
        }
        let mut monitors: Vec<Value> = state
            .0
            .values()
            .flat_map(|services| services.values())
            .filter_map(|entry| if let Discovered::Monitor(monitor) = entry { Some(monitor.clone()) } else { None })
            .collect();
        monitors.sort_by(|a, b| a["key"].as_str().unwrap_or("").cmp(b["key"].as_str().unwrap_or("")));
        Some(monitors)
    }

    pub fn start(self: &Arc<Self>) {
        let place = if self.scopes[0].is_none() {
            "every namespace".to_string()
        } else {
            format!("namespaces {}", self.scopes.iter().flatten().cloned().collect::<Vec<_>>().join(", "))
        };
        (self.log)(&format!("Kubernetes discovery: watching Services in {place} for the {MONITOR_ANNOTATION} annotation."));
        for scope in self.scopes.clone() {
            let discovery = self.clone();
            tokio::spawn(async move { discovery.run(scope).await });
        }
    }

    async fn run(&self, scope: Option<String>) {
        let mut failures = 0;
        loop {
            let outcome = async {
                let mut version = Some(self.list(&scope).await?);
                while let Some(current) = version {
                    version = self.watch(&scope, &current).await?;
                    failures = 0;
                }
                Ok::<_, Failure>(())
            }
            .await;
            match outcome {
                Ok(()) => tokio::time::sleep(Duration::from_millis(BACKOFF_BASE_MS as u64)).await,
                Err(error) => {
                    self.report(error);
                    tokio::time::sleep(backoff(failures)).await;
                    failures += 1;
                }
            }
        }
    }

    fn report(&self, error: Failure) {
        let message = match error {
            Failure::Status(status @ (401 | 403), _) => format!(
                "Kubernetes refused to list Services (HTTP {status}): give the agent's service account get, list and watch on services (the Helm chart's discovery.enabled does)."
            ),
            Failure::Status(_, message) | Failure::Other(message) => format!("Kubernetes discovery: {message}. Retrying with backoff."),
        };
        let mut state = self.state.lock().expect("discovery");
        if state.2.as_deref() == Some(message.as_str()) {
            return;
        }
        state.2 = Some(message.clone());
        drop(state);
        (self.log)(&message);
    }

    fn path(scope: &Option<String>) -> String {
        match scope {
            None => "/api/v1/services".to_string(),
            Some(namespace) => format!("/api/v1/namespaces/{}/services", percent_encoding::utf8_percent_encode(namespace, percent_encoding::NON_ALPHANUMERIC)),
        }
    }

    fn keep(services: &mut Services, service: &Value) {
        let metadata = service.get("metadata");
        let name = metadata.and_then(|m| m.get("name")).and_then(Value::as_str).filter(|name| !name.is_empty());
        let namespace = metadata.and_then(|m| m.get("namespace")).and_then(Value::as_str).filter(|namespace| !namespace.is_empty());
        let (Some(name), Some(namespace)) = (name, namespace) else { return };
        let key = format!("{namespace}/{name}");
        match monitor_of(service) {
            Some(discovered) => {
                services.insert(key, discovered);
            }
            None => {
                services.remove(&key);
            }
        }
    }

    fn log_error(&self, key: &str, entry: Option<&Discovered>, before: Option<&Discovered>) {
        let Some(Discovered::Error(error)) = entry else { return };
        if let Some(Discovered::Error(previous)) = before
            && previous == error
        {
            return;
        }
        (self.log)(&format!("Kubernetes discovery: Service {key} is skipped: {error}."));
    }

    /// One full list, in pages; replaces the namespace's Services and returns the list's resource version.
    async fn list(&self, scope: &Option<String>) -> Result<String, Failure> {
        let mut services = Services::new();
        let mut next = String::new();
        let mut version = String::new();
        loop {
            let query = if next.is_empty() {
                format!("?limit={PAGE_SIZE}")
            } else {
                format!("?limit={PAGE_SIZE}&continue={}", percent_encoding::utf8_percent_encode(&next, percent_encoding::NON_ALPHANUMERIC))
            };
            let response = self.api.get(&format!("{}{query}", Self::path(scope)), LIST_TIMEOUT).await.map_err(Failure::Other)?;
            let status = response.status().as_u16();
            if !response.status().is_success() {
                return Err(Failure::Status(status, format!("listing Services answered HTTP {status}")));
            }
            let page: Value = response.json().await.map_err(|error| Failure::Other(error.to_string()))?;
            for service in page.get("items").and_then(Value::as_array).cloned().unwrap_or_default() {
                Self::keep(&mut services, &service);
            }
            if version.is_empty() {
                version = page.pointer("/metadata/resourceVersion").and_then(Value::as_str).unwrap_or("").to_string();
            }
            next = page.pointer("/metadata/continue").and_then(Value::as_str).unwrap_or("").to_string();
            if next.is_empty() {
                break;
            }
        }
        let previous = self.state.lock().expect("discovery").0.get(scope).cloned().unwrap_or_default();
        for (key, entry) in &services {
            self.log_error(key, Some(entry), previous.get(key));
        }
        {
            let mut state = self.state.lock().expect("discovery");
            state.0.insert(scope.clone(), services);
            if !state.1.contains(scope) {
                state.1.push(scope.clone());
            }
            state.2 = None;
        }
        (self.changed)();
        Ok(version)
    }

    /// Follows changes from `version` until the API server ends the watch; None asks for a new list (410 Gone).
    async fn watch(&self, scope: &Option<String>, version: &str) -> Result<Option<String>, Failure> {
        let query = format!(
            "?watch=1&allowWatchBookmarks=true&resourceVersion={}&timeoutSeconds={WATCH_SECONDS}",
            percent_encoding::utf8_percent_encode(version, percent_encoding::NON_ALPHANUMERIC)
        );
        let response = self.api.get(&format!("{}{query}", Self::path(scope)), Duration::from_secs(WATCH_SECONDS + 30)).await.map_err(Failure::Other)?;
        let status = response.status().as_u16();
        if status == 410 {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(Failure::Status(status, format!("watching Services answered HTTP {status}")));
        }
        let mut latest = version.to_string();
        let mut pending: Vec<u8> = Vec::new();
        let mut body = response.bytes_stream();
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(|error| Failure::Other(error.to_string()))?;
            pending.extend_from_slice(&chunk);
            while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
                let line: Vec<u8> = pending.drain(..=end).collect();
                let text = String::from_utf8_lossy(&line);
                let text = text.trim();
                if text.is_empty() {
                    continue;
                }
                let event: Value = serde_json::from_str(text).map_err(|error| Failure::Other(error.to_string()))?;
                let kind = event.get("type").and_then(Value::as_str).unwrap_or("");
                let object = event.get("object");
                if kind == "ERROR" {
                    let code = object.and_then(|object| object.get("code"));
                    if code.and_then(Value::as_f64) == Some(410.0) {
                        return Ok(None);
                    }
                    return Err(Failure::Other(format!("watch error {}", code.map(|code| code.to_string()).unwrap_or_default()).trim().to_string()));
                }
                if let Some(next) =
                    object.and_then(|object| object.pointer("/metadata/resourceVersion")).and_then(Value::as_str).filter(|next| !next.is_empty())
                {
                    latest = next.to_string();
                }
                let Some(object) = object.filter(|object| !object.is_null()) else { continue };
                if kind == "BOOKMARK" {
                    continue;
                }
                if self.apply(scope, kind, object) {
                    (self.changed)();
                }
            }
            if pending.len() > MAX_EVENT_BYTES {
                return Err(Failure::Other("a watch event is larger than 1 MB".into()));
            }
        }
        Ok(Some(latest))
    }

    /// True when the event changed a monitor or an error.
    fn apply(&self, scope: &Option<String>, kind: &str, service: &Value) -> bool {
        let metadata = service.get("metadata");
        let name = metadata.and_then(|m| m.get("name")).and_then(Value::as_str).filter(|name| !name.is_empty());
        let namespace = metadata.and_then(|m| m.get("namespace")).and_then(Value::as_str).filter(|namespace| !namespace.is_empty());
        let (Some(name), Some(namespace)) = (name, namespace) else { return false };
        let key = format!("{namespace}/{name}");
        let (before, after) = {
            let mut state = self.state.lock().expect("discovery");
            let services = state.0.entry(scope.clone()).or_default();
            let before = services.get(&key).cloned();
            if kind == "DELETED" {
                services.remove(&key);
                return before.is_some();
            }
            Self::keep(services, service);
            (before, services.get(&key).cloned())
        };
        self.log_error(&key, after.as_ref(), before.as_ref());
        before != after
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(annotations: Value, ports: Value) -> Value {
        json!({ "metadata": { "name": "shop", "namespace": "web", "annotations": annotations }, "spec": { "ports": ports } })
    }

    #[test]
    fn makes_monitors_from_annotations() {
        let ports = json!([{ "name": "http", "port": 8080 }, { "name": "admin", "port": 9000 }]);
        let monitor = |value: &str| monitor_of(&service(json!({ MONITOR_ANNOTATION: value }), ports.clone()));
        assert_eq!(
            monitor("http:/healthz"),
            Some(Discovered::Monitor(
                json!({ "key": "web/shop", "type": "http", "target": "http://shop.web.svc:8080/healthz", "name": "web/shop", "intervalSeconds": 60 })
            ))
        );
        assert_eq!(
            monitor("tcp:admin").unwrap(),
            Discovered::Monitor(json!({ "key": "web/shop", "type": "tcp", "target": "shop.web.svc:9000", "name": "web/shop", "intervalSeconds": 60 }))
        );
        assert_eq!(
            monitor("http:5000").unwrap(),
            Discovered::Monitor(json!({ "key": "web/shop", "type": "http", "target": "http://shop.web.svc:5000/", "name": "web/shop", "intervalSeconds": 60 }))
        );
        assert_eq!(monitor("tcp:5432/x"), Some(Discovered::Error(format!("{MONITOR_ANNOTATION}: a tcp monitor has no path"))));
        assert_eq!(monitor("http:nope"), Some(Discovered::Error(format!("{MONITOR_ANNOTATION}: the Service has no port \"nope\""))));
        assert!(matches!(monitor("ftp:21"), Some(Discovered::Error(_))));
        let named = monitor_of(&service(json!({ MONITOR_ANNOTATION: "http", NAME_ANNOTATION: " Shop ", INTERVAL_ANNOTATION: "5m" }), ports.clone())).unwrap();
        assert_eq!(
            named,
            Discovered::Monitor(json!({ "key": "web/shop", "type": "http", "target": "http://shop.web.svc:8080/", "name": "Shop", "intervalSeconds": 300 }))
        );
        assert!(matches!(monitor_of(&service(json!({ MONITOR_ANNOTATION: "http", INTERVAL_ANNOTATION: "10s" }), ports.clone())), Some(Discovered::Error(_))));
        assert_eq!(monitor_of(&service(json!({}), ports)), None);
    }
}
