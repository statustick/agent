//! MCP server checks: initialize, then every page of tools/list over the Streamable HTTP transport, with the
//! target rules on every request. Tool descriptions and schemas stay here;
//! only a hash of the names and input schemas leaves.
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use url::Url;

use crate::blocking::with_user_agent;
use crate::http::{MAX_RESPONSE_BYTES, client_for};
use crate::proxy::{forward_refused, refusal, refused};
use crate::targets::resolve_allowed;
use crate::util::{Failure, elapsed_ms, js_number, now_iso, string_field, timeout_field, utf16_cmp, utf16_prefix};

pub const MAX_TOOL_PAGES: usize = 20;
const MAX_NAME_LENGTH: usize = 100;
const LATEST_PROTOCOL_VERSION: &str = "2025-11-25";
const SUPPORTED_PROTOCOL_VERSIONS: [&str; 5] = [LATEST_PROTOCOL_VERSION, "2025-06-18", "2025-03-26", "2024-11-05", "2024-10-07"];
const REQUEST_TIMEOUT: i64 = -32001;
const RESERVED_HEADERS: [&str; 7] = ["accept", "content-type", "content-length", "host", "mcp-session-id", "mcp-protocol-version", "last-event-id"];

static HEADER_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$").expect("valid pattern"));
static TLS_CODE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(CERT_|ERR_TLS_|ERR_SSL_|UNABLE_TO_|DEPTH_ZERO_|SELF_SIGNED_)").expect("valid pattern"));

#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Initialize,
    ToolsList,
}

impl Phase {
    fn name(self) -> &'static str {
        match self {
            Phase::Initialize => "initialize",
            Phase::ToolsList => "tools/list",
        }
    }

    fn code(self) -> &'static str {
        match self {
            Phase::Initialize => "MCP_INITIALIZE_FAILED",
            Phase::ToolsList => "MCP_TOOLS_LIST_FAILED",
        }
    }
}

/// Why a check of the MCP server failed, before it is put into the platform's words.
enum Problem {
    /// The check's own words and code.
    Own(String, String),
    /// The server answered with this HTTP status (-1 for an unexpected content type).
    Status(i64),
    /// The server answered with a JSON-RPC error.
    Rpc(i64),
    /// The answer is not what the protocol allows.
    Invalid,
    UnsupportedVersion,
    /// The request did not get through.
    Fetch(Failure),
}

fn failure_of(problem: Problem, phase: Phase) -> (String, String) {
    let name = phase.name();
    match problem {
        Problem::Own(message, code) => (message, code),
        Problem::Status(status @ (401 | 403)) => (format!("The MCP server refused the request: HTTP {status}"), "AUTH_FAILED".into()),
        Problem::Status(status) if (300..400).contains(&status) => {
            (format!("The MCP server answered {name} with a redirect (HTTP {status}); check the URL it redirects to"), phase.code().into())
        }
        Problem::Status(status) => (format!("The MCP server answered {name} with HTTP {status}"), phase.code().into()),
        Problem::Rpc(REQUEST_TIMEOUT) => ("Timed out".into(), "TIMEOUT".into()),
        Problem::Rpc(code) => (format!("The MCP server answered {name} with JSON-RPC error {code}"), phase.code().into()),
        Problem::Invalid => (format!("The MCP server's {name} answer is not valid"), phase.code().into()),
        Problem::UnsupportedVersion => ("The MCP server's protocol version is not supported".into(), phase.code().into()),
        Problem::Fetch(failure) => {
            let code = failure.code.clone().unwrap_or_default();
            if failure.is("TARGET_NOT_ALLOWED") {
                (failure.message, "TARGET_NOT_ALLOWED".into())
            } else if failure.message.starts_with("The proxy refused the request") {
                (failure.message, "CONNECT_FAILED".into())
            } else if ["ETIMEDOUT", "UND_ERR_CONNECT_TIMEOUT", "UND_ERR_HEADERS_TIMEOUT", "UND_ERR_BODY_TIMEOUT"].contains(&code.as_str()) {
                ("Timed out".into(), "TIMEOUT".into())
            } else if TLS_CODE.is_match(&code) {
                (failure.message, "TLS_FAILED".into())
            } else {
                (failure.message, "CONNECT_FAILED".into())
            }
        }
    }
}

/// Why [request] cannot be checked; never quotes the auth header value.
fn request_problem(request: &Map<String, Value>) -> Option<(String, String)> {
    let invalid = |message: &str, code: &str| Some((message.to_string(), code.to_string()));
    let Some(Ok(url)) = request.get("url").and_then(Value::as_str).map(Url::parse) else {
        return invalid("url is not a valid URL", "INVALID_URL");
    };
    if url.scheme() != "https" && url.scheme() != "http" {
        return invalid("url must be an http or https URL", "INVALID_URL");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return invalid("url must not contain a user name or password; use authHeaderName and authHeaderValue", "INVALID_URL");
    }
    let name = string_field(request, "authHeaderName").filter(|name| !name.is_empty());
    let value = string_field(request, "authHeaderValue").filter(|value| !value.is_empty());
    if name.is_some() != value.is_some() {
        return invalid("authHeaderName and authHeaderValue must be set together", "INVALID_HEADER");
    }
    if let Some(name) = &name
        && (!HEADER_NAME.is_match(name) || RESERVED_HEADERS.contains(&name.to_lowercase().as_str()))
    {
        return invalid("authHeaderName is not a header name the check can send", "INVALID_HEADER");
    }
    if value.is_some_and(|value| value.contains(['\r', '\n', '\0'])) {
        return invalid("authHeaderValue is not a valid header value", "INVALID_HEADER");
    }
    None
}

/// `JSON.stringify` of one value with object keys sorted and no white space; arrays keep their order.
pub fn canonical_json(value: &Value) -> String {
    match value {
        Value::Array(items) => format!("[{}]", items.iter().map(canonical_json).collect::<Vec<_>>().join(",")),
        Value::Object(fields) => {
            let mut entries: Vec<(&String, &Value)> = fields.iter().collect();
            entries.sort_by(|(a, _), (b, _)| utf16_cmp(a, b));
            let parts: Vec<String> =
                entries.iter().map(|(key, item)| format!("{}:{}", serde_json::to_string(key).unwrap_or_default(), canonical_json(item))).collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Number(number) => match number.as_f64() {
            Some(float) if float.is_finite() => {
                if float == 0.0 {
                    "0".to_string()
                } else {
                    js_number(float)
                }
            }
            _ => "null".to_string(),
        },
        other => other.to_string(),
    }
}

/// sha256 (hex) of the canonical JSON of `[{inputSchema, name}, …]`, sorted by name, then by the canonical schema.
pub fn tools_hash(tools: &[(String, Value)]) -> String {
    let mut entries: Vec<(&String, String)> =
        tools.iter().map(|(name, schema)| (name, canonical_json(&json!({ "inputSchema": schema, "name": name })))).collect();
    entries.sort_by(|(a_name, a_json), (b_name, b_json)| utf16_cmp(a_name, b_name).then_with(|| utf16_cmp(a_json, b_json)));
    let text = format!("[{}]", entries.iter().map(|(_, json)| json.as_str()).collect::<Vec<_>>().join(","));
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn is_message(value: &Value) -> bool {
    let Some(fields) = value.as_object() else { return false };
    if fields.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return false;
    }
    if fields.get("method").is_some_and(Value::is_string) {
        return true;
    }
    let id_ok = fields.get("id").is_some_and(|id| id.is_string() || id.is_number());
    let result_ok = fields.get("result").is_some_and(Value::is_object);
    let error_ok = fields
        .get("error")
        .and_then(Value::as_object)
        .is_some_and(|error| error.get("code").is_some_and(|code| code.as_i64().is_some()) && error.get("message").is_some_and(Value::is_string));
    id_ok && (result_ok || error_ok)
}

fn valid_initialize(result: &Value) -> bool {
    result.get("protocolVersion").is_some_and(Value::is_string)
        && result.get("capabilities").is_some_and(Value::is_object)
        && result.get("serverInfo").is_some_and(|info| info.get("name").is_some_and(Value::is_string) && info.get("version").is_some_and(Value::is_string))
}

fn valid_tool(tool: &Value) -> bool {
    let optional_string = |name: &str| tool.get(name).is_none_or(Value::is_string);
    let Some(schema) = tool.get("inputSchema").and_then(Value::as_object) else { return false };
    tool.get("name").is_some_and(Value::is_string)
        && optional_string("description")
        && optional_string("title")
        && schema.get("type").and_then(Value::as_str) == Some("object")
        && schema.get("properties").is_none_or(|properties| properties.as_object().is_some_and(|fields| fields.values().all(Value::is_object)))
        && schema.get("required").is_none_or(|required| required.as_array().is_some_and(|items| items.iter().all(Value::is_string)))
}

fn valid_tools_list(result: &Value) -> bool {
    result.get("tools").and_then(Value::as_array).is_some_and(|tools| tools.iter().all(valid_tool)) && result.get("nextCursor").is_none_or(Value::is_string)
}

/// A fetch failure with the connection's own error, as the root cause of Node.js's `fetch failed` reads.
fn fetch_failure(error: &reqwest::Error, address: std::net::IpAddr, port: u16) -> Failure {
    if let Some(node) = crate::tls::node_error(error) {
        return Failure::coded(node.message, &node.code);
    }
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(inner) = current {
        if let Some(failure) = inner.downcast_ref::<Failure>() {
            return failure.clone();
        }
        if let Some(io) = inner.downcast_ref::<std::io::Error>() {
            if let Some(tls) = io.get_ref().filter(|source| source.is::<rustls::Error>()).map(|_| crate::connection::tls_failure(io)) {
                return tls;
            }
            return crate::util::connect_failure(io, address, port);
        }
        current = inner.source();
    }
    Failure::plain("fetch failed")
}

struct Session {
    url: Url,
    headers: Vec<(String, String)>,
    session_id: Option<String>,
    protocol_version: Option<String>,
    next_id: i64,
}

impl Session {
    async fn post(&mut self, message: &Value) -> Result<reqwest::Response, Problem> {
        let addresses = resolve_allowed(self.url.host_str().unwrap_or(""), 0).await.map_err(Problem::Fetch)?;
        let mut builder = client_for(0).post(self.url.clone());
        for (name, value) in &self.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        if let Some(session) = &self.session_id {
            builder = builder.header("mcp-session-id", session.as_str());
        }
        if let Some(version) = &self.protocol_version {
            builder = builder.header("mcp-protocol-version", version.as_str());
        }
        let encodings = if self.url.scheme() == "https" { "br, gzip, deflate, zstd" } else { "gzip, deflate" };
        let request = builder
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("accept-language", "*")
            .header("sec-fetch-mode", "cors")
            .header("accept-encoding", encodings)
            .body(message.to_string());
        let port = self.url.port_or_known_default().unwrap_or(443);
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => {
                let failure = match refused(&error, &self.url).await {
                    Some(message) => Failure::plain(message),
                    None => fetch_failure(&error, addresses[0], port),
                };
                return Err(Problem::Fetch(failure));
            }
        };
        if forward_refused(&self.url, response.status().as_u16()) {
            return Err(Problem::Fetch(Failure::plain(refusal(407))));
        }
        if let Some(session) = response.headers().get("mcp-session-id").and_then(|value| value.to_str().ok()).filter(|value| !value.is_empty()) {
            self.session_id = Some(session.to_string());
        }
        Ok(response)
    }

    /// Reads a body of at most MAX_RESPONSE_BYTES; a larger one fails the phase.
    async fn body(response: reqwest::Response, phase: Phase) -> Result<Vec<u8>, Problem> {
        let mut stream = response.bytes_stream();
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| Problem::Invalid)?;
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(too_large(phase));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    /// Sends a request and waits for the response with its id, in a JSON body or an event stream.
    async fn request(&mut self, method: &str, params: Value, phase: Phase) -> Result<Value, Problem> {
        let id = self.next_id;
        self.next_id += 1;
        let message = json!({ "method": method, "params": params, "jsonrpc": "2.0", "id": id });
        let response = self.post(&message).await?;
        let status = response.status().as_u16();
        if !response.status().is_success() {
            let _ = Self::body(response, phase).await;
            return Err(Problem::Status(i64::from(status)));
        }
        if status == 202 {
            return std::future::pending().await;
        }
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.split(';').next().unwrap_or("").trim().to_lowercase())
            .unwrap_or_default();
        let encoding = response.headers().get("content-encoding").and_then(|value| value.to_str().ok()).map(str::to_string);
        let answer = |candidate: &Value| candidate.get("id").and_then(Value::as_i64) == Some(id) && candidate.get("method").is_none();
        let messages: Vec<Value> = match content_type.as_str() {
            "application/json" => {
                let body = decode(Self::body(response, phase).await?, encoding.as_deref());
                let data: Value = serde_json::from_slice(&body).map_err(|_| Problem::Invalid)?;
                let items = match data {
                    Value::Array(items) => items,
                    single => vec![single],
                };
                if !items.iter().all(is_message) {
                    return Err(Problem::Invalid);
                }
                items
            }
            "text/event-stream" if encoding.is_some() => {
                let body = decode(Self::body(response, phase).await?, encoding.as_deref());
                let mut parser = EventParser::default();
                let mut found = parser.feed(&body);
                found.extend(parser.finish());
                found.into_iter().filter(is_message).collect()
            }
            "text/event-stream" => {
                let mut parser = EventParser::default();
                let mut stream = response.bytes_stream();
                let mut size = 0;
                while let Some(chunk) = stream.next().await {
                    let Ok(chunk) = chunk else { break };
                    size += chunk.len();
                    if size > MAX_RESPONSE_BYTES {
                        return Err(too_large(phase));
                    }
                    if let Some(found) = parser.feed(&chunk).into_iter().find(|message| is_message(message) && answer(message)) {
                        return rpc_result(found);
                    }
                }
                Vec::new()
            }
            _ => return Err(Problem::Status(-1)),
        };
        match messages.into_iter().find(answer) {
            Some(found) => rpc_result(found),
            None => std::future::pending().await,
        }
    }

    async fn notify(&mut self, method: &str, phase: Phase) -> Result<(), Problem> {
        let message = json!({ "method": method, "jsonrpc": "2.0" });
        let response = self.post(&message).await?;
        let status = response.status();
        let _ = Self::body(response, phase).await;
        if !status.is_success() {
            return Err(Problem::Status(i64::from(status.as_u16())));
        }
        Ok(())
    }
}

fn decode(body: Vec<u8>, encoding: Option<&str>) -> Vec<u8> {
    crate::http::decode_body(body, encoding)
}

fn too_large(phase: Phase) -> Problem {
    Problem::Own(format!("The MCP server's {} answer is larger than {} MB", phase.name(), MAX_RESPONSE_BYTES / 1024 / 1024), phase.code().to_string())
}

fn rpc_result(message: Value) -> Result<Value, Problem> {
    if let Some(error) = message.get("error") {
        return Err(Problem::Rpc(error.get("code").and_then(Value::as_i64).unwrap_or(0)));
    }
    Ok(message.get("result").cloned().unwrap_or(Value::Null))
}

/// Server-sent events: the JSON messages in `message` events (or events without a type).
#[derive(Default)]
struct EventParser {
    pending: Vec<u8>,
    data: Vec<String>,
    event: Option<String>,
}

impl EventParser {
    fn feed(&mut self, chunk: &[u8]) -> Vec<Value> {
        self.pending.extend_from_slice(chunk);
        let mut messages = Vec::new();
        while let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
            let mut line: Vec<u8> = self.pending.drain(..=end).collect();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            let line = String::from_utf8_lossy(&line).into_owned();
            if line.is_empty() {
                messages.extend(self.dispatch());
                continue;
            }
            let (field, value) = match line.split_once(':') {
                Some((field, value)) => (field.to_string(), value.strip_prefix(' ').unwrap_or(value).to_string()),
                None => (line.clone(), String::new()),
            };
            match field.as_str() {
                "data" => self.data.push(value),
                "event" => self.event = Some(value),
                _ => {}
            }
        }
        messages
    }

    fn finish(&mut self) -> Vec<Value> {
        self.dispatch().into_iter().collect()
    }

    fn dispatch(&mut self) -> Option<Value> {
        let data = std::mem::take(&mut self.data).join("\n");
        let event = self.event.take();
        if data.is_empty() || event.as_deref().is_some_and(|event| event != "message") {
            return None;
        }
        serde_json::from_str(&data).ok()
    }
}

fn cut(text: Option<&Value>) -> Option<Value> {
    text.and_then(Value::as_str).map(|text| Value::from(utf16_prefix(text, MAX_NAME_LENGTH)))
}

/// `/check/mcp` and the agent's `mcp` job. Never fails.
pub async fn mcp_check(request: &Map<String, Value>) -> Value {
    let start = Instant::now();
    let url = request.get("url").cloned().unwrap_or(Value::Null);
    let timeout = timeout_field(request, "timeout", 10000.0);
    let answer = |status: &str, details: Option<&Map<String, Value>>, failure: Option<(String, String)>, response_time: Option<i64>| {
        let mut result = Map::new();
        result.insert("url".into(), url.clone());
        result.insert("status".into(), Value::from(status));
        result.insert("responseTime".into(), Value::from(response_time.unwrap_or_else(|| elapsed_ms(start))));
        result.insert("timestamp".into(), Value::from(now_iso()));
        if let Some((error, code)) = failure {
            result.insert("error".into(), Value::from(error));
            result.insert("errorCode".into(), Value::from(code));
        }
        if let Some(details) = details {
            result.insert("details".into(), Value::Object(details.clone()));
        }
        Value::Object(result)
    };
    if let Some(problem) = request_problem(request) {
        return answer("error", None, Some(problem), Some(0));
    }
    let auth = string_field(request, "authHeaderName").filter(|name| !name.is_empty()).zip(string_field(request, "authHeaderValue"));
    let mut session = Session {
        url: Url::parse(url.as_str().unwrap_or("")).expect("checked URL"),
        headers: with_user_agent(auth.into_iter().collect()),
        session_id: None,
        protocol_version: None,
        next_id: 0,
    };
    let mut phase = Phase::Initialize;
    let mut details: Option<Map<String, Value>> = None;
    let deadline = tokio::time::Instant::now() + timeout;
    let outcome: Result<(), Problem> = async {
        let work = async {
            let initialize_start = Instant::now();
            let params = json!({ "protocolVersion": LATEST_PROTOCOL_VERSION, "capabilities": {}, "clientInfo": { "name": "StatusTick", "version": "2.0.0" } });
            let result = session.request("initialize", params, Phase::Initialize).await?;
            if !valid_initialize(&result) {
                return Err(Problem::Invalid);
            }
            let version = result["protocolVersion"].as_str().unwrap_or("").to_string();
            if !SUPPORTED_PROTOCOL_VERSIONS.contains(&version.as_str()) {
                return Err(Problem::UnsupportedVersion);
            }
            session.protocol_version = Some(version.clone());
            session.notify("notifications/initialized", Phase::Initialize).await?;
            let mut found = Map::new();
            found.insert("protocolVersion".into(), Value::from(version));
            if let Some(name) = cut(result["serverInfo"].get("name")) {
                found.insert("serverName".into(), name);
            }
            if let Some(server_version) = cut(result["serverInfo"].get("version")) {
                found.insert("serverVersion".into(), server_version);
            }
            found.insert("initializeTime".into(), Value::from(elapsed_ms(initialize_start)));
            details = Some(found);

            phase = Phase::ToolsList;
            let list_start = Instant::now();
            let mut tools: Vec<(String, Value)> = Vec::new();
            let mut cursor: Option<String> = None;
            for page in 1.. {
                let params = match &cursor {
                    None => json!({}),
                    Some(cursor) => json!({ "cursor": cursor }),
                };
                let result = session.request("tools/list", params, Phase::ToolsList).await?;
                if !valid_tools_list(&result) {
                    return Err(Problem::Invalid);
                }
                for tool in result["tools"].as_array().into_iter().flatten() {
                    tools.push((tool["name"].as_str().unwrap_or("").to_string(), tool["inputSchema"].clone()));
                }
                let next = result.get("nextCursor").and_then(Value::as_str).filter(|next| !next.is_empty()).map(str::to_string);
                let Some(next) = next else { break };
                if Some(&next) == cursor.as_ref() {
                    return Err(Problem::Own("tools/list repeats the same cursor".into(), Phase::ToolsList.code().into()));
                }
                if page == MAX_TOOL_PAGES {
                    return Err(Problem::Own(format!("tools/list has more than {MAX_TOOL_PAGES} pages"), Phase::ToolsList.code().into()));
                }
                cursor = Some(next);
            }
            if let Some(found) = details.as_mut() {
                found.insert("toolCount".into(), Value::from(tools.len()));
                found.insert("toolsHash".into(), Value::from(tools_hash(&tools)));
                found.insert("toolsListTime".into(), Value::from(elapsed_ms(list_start)));
            }
            if tools.is_empty() {
                return Err(Problem::Own("The MCP server lists no tools".into(), "MCP_NO_TOOLS".into()));
            }
            Ok(())
        };
        match tokio::time::timeout_at(deadline, work).await {
            Ok(result) => result,
            Err(_) => Err(Problem::Own(format!("Timed out after {} ms", timeout.as_millis()), "TIMEOUT".into())),
        }
    }
    .await;
    if let Some(session_id) = session.session_id.clone() {
        let url = session.url.clone();
        let headers = session.headers.clone();
        let version = session.protocol_version.clone();
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now()).max(Duration::from_millis(1));
        tokio::spawn(async move {
            if resolve_allowed(url.host_str().unwrap_or(""), 0).await.is_err() {
                return;
            }
            let mut builder = client_for(0).delete(url).header("mcp-session-id", session_id);
            for (name, value) in headers {
                builder = builder.header(name, value);
            }
            if let Some(version) = version {
                builder = builder.header("mcp-protocol-version", version);
            }
            let _ = tokio::time::timeout(remaining, builder.send()).await;
        });
    }
    match outcome {
        Ok(()) => answer("up", details.as_ref(), None, None),
        Err(problem) => answer("down", details.as_ref(), Some(failure_of(problem, phase)), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_tools_whatever_their_order() {
        let a =
            vec![("b".to_string(), json!({"type": "object", "properties": {"y": {}, "x": {"type": "number"}}})), ("a".to_string(), json!({"type": "object"}))];
        let b =
            vec![("a".to_string(), json!({"type": "object"})), ("b".to_string(), json!({"properties": {"x": {"type": "number"}, "y": {}}, "type": "object"}))];
        assert_eq!(tools_hash(&a), tools_hash(&b));
        assert_eq!(
            canonical_json(&json!({"b": 1.0, "a": [true, null, "x\u{1}"], "c": -0.0, "d": 1e21})),
            r#"{"a":[true,null,"x\u0001"],"b":1,"c":0,"d":1e+21}"#
        );
    }

    #[test]
    fn checks_the_request_without_quoting_the_auth_value() {
        let request = |value: Value| value.as_object().unwrap().clone();
        assert_eq!(request_problem(&request(json!({"url": "ftp://x"}))).unwrap().0, "url must be an http or https URL");
        assert_eq!(request_problem(&request(json!({"url": "https://u:p@x"}))).unwrap().1, "INVALID_URL");
        assert_eq!(
            request_problem(&request(json!({"url": "https://x", "authHeaderName": "Host", "authHeaderValue": "v"}))).unwrap().0,
            "authHeaderName is not a header name the check can send"
        );
        assert_eq!(
            request_problem(&request(json!({"url": "https://x", "authHeaderName": "X-Key", "authHeaderValue": "a\nb"}))).unwrap().0,
            "authHeaderValue is not a valid header value"
        );
        assert_eq!(request_problem(&request(json!({"url": "https://x", "authHeaderName": "X-Key"}))).unwrap().1, "INVALID_HEADER");
        assert!(request_problem(&request(json!({"url": "https://x/mcp", "authHeaderName": "Authorization", "authHeaderValue": "Bearer t"}))).is_none());
    }

    #[test]
    fn parses_event_streams() {
        let mut parser = EventParser::default();
        let mut messages = parser.feed(b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":0,\n");
        assert!(messages.is_empty());
        messages.extend(parser.feed(b"data: \"result\":{}}\n\nevent: other\ndata: {}\n\n"));
        assert_eq!(messages, vec![json!({"jsonrpc": "2.0", "id": 0, "result": {}})]);
    }
}
