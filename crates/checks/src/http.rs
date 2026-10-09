//! HTTP checks: one request, redirects followed by hand so every hop passes the target
//! rules, a capped body read for the text, JSON and block checks, and the page's assets when asked.
use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use serde::Serialize;
use serde_json::{Map, Value};
use url::Url;

use crate::assets::{MAX_ASSETS, check_assets, extract_assets};
use crate::blocking::{detect_block, with_user_agent};
use crate::json::check_json;
use crate::proxy::{env_settings, forward_refused, proxy_for, refusal, refused};
use crate::targets::{Family, check_target, family_of, lookup, resolve_allowed};
use crate::util::{Failure, bool_field, elapsed_ms, now_iso, number_field, string_field, timeout_field, truthy};

const MAX_REDIRECTS: usize = 5;
pub const MAX_BODY_BYTES: usize = 64 * 1024;
/// Only this much of a response is read for text and asset checks; a larger page is cut, never buffered whole.
pub const MAX_RESPONSE_BYTES: usize = 5 * 1024 * 1024;
const ASSET_TIMEOUT: Duration = Duration::from_millis(5000);
const NULL_BODY_STATUSES: &[u16] = &[101, 103, 204, 205, 304];

/// Resolves through the target rules, as the guarded lookup; proxies are exempt.
struct GuardedResolver {
    family: Family,
}

impl Resolve for GuardedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let family = self.family;
        Box::pin(async move {
            let host = name.as_str().to_string();
            let addresses = lookup(&host, family).await?;
            let addresses: Vec<IpAddr> = addresses.into_iter().filter(|address| family == 0 || (family == 4) == address.is_ipv4()).collect();
            if !proxy_hosts().contains(&host.to_lowercase()) {
                check_target(&host, &addresses)?;
            }
            let addrs: Addrs = Box::new(addresses.into_iter().map(|address| SocketAddr::new(address, 0)).collect::<Vec<_>>().into_iter());
            Ok(addrs)
        })
    }
}

fn proxy_hosts() -> &'static HashSet<String> {
    static HOSTS: LazyLock<HashSet<String>> = LazyLock::new(|| {
        let settings = env_settings();
        [&settings.http, &settings.https].into_iter().flatten().filter_map(|url| url.host_str().map(str::to_lowercase)).collect()
    });
    &HOSTS
}

fn build_client(family: Family) -> reqwest::Client {
    reqwest::Client::builder()
        .use_preconfigured_tls((*crate::tls::client_config(true, &["h2", "http/1.1"])).clone())
        .dns_resolver(Arc::new(GuardedResolver { family }))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .proxy(reqwest::Proxy::custom(|url| proxy_for(url, env_settings())))
        .pool_idle_timeout(Duration::from_secs(4))
        .build()
        .expect("HTTP client")
}

/// One client per IP version, shared by every check so connections are reused.
pub fn client_for(family: Family) -> &'static reqwest::Client {
    static CLIENTS: LazyLock<[reqwest::Client; 3]> = LazyLock::new(|| [build_client(0), build_client(4), build_client(6)]);
    &CLIENTS[match family {
        4 => 1,
        6 => 2,
        _ => 0,
    }]
}

#[derive(Clone, Debug)]
pub struct HttpOptions {
    pub method: String,
    pub timeout: Duration,
    pub headers: Vec<(String, String)>,
    pub expected_status: Option<Value>,
    pub expected_text: Option<String>,
    pub not_contains: bool,
    pub case_sensitive: bool,
    pub body: Option<String>,
    pub body_type: String,
    pub follow_redirects: bool,
    pub family: Family,
    pub ignore_hosts: Option<Vec<String>>,
    pub json: Option<Vec<Value>>,
}

impl HttpOptions {
    pub fn from_request(request: &Map<String, Value>) -> Self {
        let headers = match request.get("headers") {
            Some(Value::Object(fields)) => fields
                .iter()
                .filter(|(_, value)| !value.is_null())
                .map(|(name, value)| {
                    (
                        name.clone(),
                        match value {
                            Value::String(text) => text.clone(),
                            other => other.to_string(),
                        },
                    )
                })
                .collect(),
            _ => Vec::new(),
        };
        let ignore_hosts = match request.get("assets") {
            Some(assets) if truthy(Some(assets)) => Some(
                assets
                    .get("ignoreHosts")
                    .and_then(Value::as_array)
                    .map(|hosts| hosts.iter().filter_map(|host| host.as_str().map(str::to_string)).collect())
                    .unwrap_or_default(),
            ),
            _ => None,
        };
        HttpOptions {
            method: string_field(request, "method").unwrap_or_else(|| "GET".to_string()),
            timeout: timeout_field(request, "timeout", 10000.0),
            headers,
            expected_status: request.get("expectedStatus").filter(|value| truthy(Some(value))).cloned(),
            expected_text: string_field(request, "expectedText").filter(|text| !text.is_empty()),
            not_contains: request.get("textMode").and_then(Value::as_str) == Some("not_contains"),
            case_sensitive: bool_field(request, "caseSensitive").unwrap_or(true),
            body: string_field(request, "body").filter(|body| !body.is_empty()),
            body_type: string_field(request, "bodyType").unwrap_or_else(|| "RAW".to_string()),
            follow_redirects: bool_field(request, "followRedirects").unwrap_or(true),
            family: family_of(request.get("ipVersion")),
            ignore_hosts,
            json: request.get("json").and_then(Value::as_array).cloned(),
        }
    }

    fn plain(method: &str, timeout: Duration, family: Family) -> Self {
        HttpOptions {
            method: method.to_string(),
            timeout,
            headers: Vec::new(),
            expected_status: None,
            expected_text: None,
            not_contains: false,
            case_sensitive: true,
            body: None,
            body_type: "RAW".to_string(),
            follow_redirects: true,
            family,
            ignore_hosts: None,
            json: None,
        }
    }
}

#[derive(Debug)]
pub struct HttpRequestResult {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub is_up: bool,
    pub text_match: bool,
    pub json_failure: Option<String>,
    pub block_reason: Option<&'static str>,
    pub asset_check: Option<Value>,
    pub page_time_ms: i64,
    /// Set when the final answer came over TLS older than 1.2 or without an AEAD cipher: the negotiated version.
    pub legacy_tls: Option<crate::tls::LegacyTls>,
}

fn type_error(message: impl Into<String>) -> Failure {
    Failure::new(message, None, "TypeError")
}

fn aborted() -> Failure {
    Failure::new("This operation was aborted", None, "AbortError")
}

fn body_content_type(body_type: &str) -> &'static str {
    match body_type {
        "JSON" => "application/json",
        "FORM_PARAMS" => "application/x-www-form-urlencoded",
        _ => "text/plain",
    }
}

/// A fetch failure: the target rules' refusal when they refused, else `fetch failed`.
fn fetch_failure(error: &reqwest::Error) -> Failure {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(error) = current {
        if let Some(failure) = error.downcast_ref::<Failure>()
            && (failure.is("TARGET_NOT_ALLOWED") || failure.is("NO_ADDRESS"))
        {
            return failure.clone();
        }
        current = error.source();
    }
    type_error("fetch failed")
}

fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| *byte as char).collect()
}

fn response_headers(headers: &reqwest::header::HeaderMap) -> BTreeMap<String, String> {
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    for (name, value) in headers {
        let text = latin1(value.as_bytes());
        map.entry(name.as_str().to_string())
            .and_modify(|existing| {
                existing.push_str(", ");
                existing.push_str(&text);
            })
            .or_insert(text);
    }
    map
}

fn is_zlib(raw: &[u8]) -> bool {
    raw.len() >= 2 && raw[0] & 0x0f == 8 && (u16::from(raw[0]) << 8 | u16::from(raw[1])) % 31 == 0
}

/// Undoes the response's content codings, as fetch does, keeping at most MAX_RESPONSE_BYTES.
pub fn decode_body(raw: Vec<u8>, encoding: Option<&str>) -> Vec<u8> {
    let codings: Vec<String> = encoding.map(|value| value.to_lowercase().split(',').map(|coding| coding.trim().to_string()).collect()).unwrap_or_default();
    if codings.len() > 5 {
        return Vec::new();
    }
    let mut data = raw;
    for coding in codings.iter().rev() {
        let limit = MAX_RESPONSE_BYTES as u64;
        let mut out = Vec::new();
        let result = match coding.as_str() {
            "gzip" | "x-gzip" => flate2::read::MultiGzDecoder::new(&data[..]).take(limit).read_to_end(&mut out),
            "deflate" if is_zlib(&data) => flate2::read::ZlibDecoder::new(&data[..]).take(limit).read_to_end(&mut out),
            "deflate" => flate2::read::DeflateDecoder::new(&data[..]).take(limit).read_to_end(&mut out),
            "br" => brotli_decompressor::Decompressor::new(&data[..], 4096).take(limit).read_to_end(&mut out),
            "zstd" => match ruzstd::decoding::StreamingDecoder::new(&data[..]) {
                Ok(decoder) => decoder.take(limit).read_to_end(&mut out),
                Err(_) => Err(std::io::Error::other("zstd")),
            },
            _ => return data,
        };
        if result.is_err() && out.is_empty() {
            return Vec::new();
        }
        data = out;
    }
    data
}

async fn read_capped(response: reqwest::Response, skip_body: bool) -> Result<String, reqwest::Error> {
    if skip_body {
        return Ok(String::new());
    }
    let encoding = response.headers().get("content-encoding").map(|value| latin1(value.as_bytes()));
    let mut stream = response.bytes_stream();
    let mut raw: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        let room = MAX_RESPONSE_BYTES - raw.len();
        raw.extend_from_slice(&chunk[..chunk.len().min(room)]);
        if raw.len() >= MAX_RESPONSE_BYTES {
            break;
        }
    }
    let decoded = decode_body(raw, encoding.as_deref());
    let text = String::from_utf8_lossy(&decoded);
    Ok(text.strip_prefix('\u{feff}').unwrap_or(&text).to_string())
}

fn matches_keyword(body: &str, keyword: &str, not_contains: bool, case_sensitive: bool) -> bool {
    let found = if case_sensitive { body.contains(keyword) } else { body.to_lowercase().contains(&keyword.to_lowercase()) };
    found != not_contains
}

/// Sends the request once more over OpenSSL when rustls found no TLS version or cipher in common with the server.
#[cfg(feature = "legacy-tls")]
async fn retry_legacy(
    error: &reqwest::Error,
    url: &Url,
    method: reqwest::Method,
    headers: reqwest::header::HeaderMap,
    body: Option<String>,
    family: Family,
) -> Option<Result<reqwest::Response, Failure>> {
    if !crate::legacy_tls::retries(error, url) {
        return None;
    }
    Some(crate::legacy_tls::send(method, url, headers, body, family).await)
}

#[cfg(not(feature = "legacy-tls"))]
async fn retry_legacy(
    _error: &reqwest::Error,
    _url: &Url,
    _method: reqwest::Method,
    _headers: reqwest::header::HeaderMap,
    _body: Option<String>,
    _family: Family,
) -> Option<Result<reqwest::Response, Failure>> {
    None
}

#[cfg(feature = "legacy-tls")]
fn legacy_version(response: &reqwest::Response) -> Option<crate::tls::LegacyTls> {
    response.extensions().get::<crate::tls::LegacyTls>().cloned()
}

#[cfg(not(feature = "legacy-tls"))]
fn legacy_version(_response: &reqwest::Response) -> Option<crate::tls::LegacyTls> {
    None
}

struct Page {
    response: reqwest::Response,
    url: String,
}

async fn fetch_page(url: &str, options: &HttpOptions) -> Result<Page, Failure> {
    let mut current_url = url.to_string();
    let mut current_method = options.method.to_uppercase();
    let mut current_body = options.body.clone().filter(|_| !["GET", "HEAD"].contains(&current_method.as_str()));
    let mut headers = with_user_agent(options.headers.clone());
    let has_content_type = headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("content-type"));
    if current_body.is_some() && !has_content_type {
        headers.push(("Content-Type".to_string(), body_content_type(&options.body_type).to_string()));
    }
    let mut header_map = reqwest::header::HeaderMap::new();
    for (name, value) in &headers {
        let header_name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| type_error(format!("Headers.append: \"{name}\" is an invalid header name.")))?;
        let header_value = reqwest::header::HeaderValue::from_str(value.trim_matches(|c| matches!(c, ' ' | '\t' | '\n' | '\r')))
            .map_err(|_| type_error(format!("Headers.append: \"{value}\" is an invalid header value.")))?;
        header_map.append(header_name, header_value);
    }
    for (name, value) in [("accept", "*/*"), ("accept-language", "*"), ("sec-fetch-mode", "cors")] {
        if !header_map.contains_key(name) {
            header_map.insert(name, reqwest::header::HeaderValue::from_static(value));
        }
    }
    let client = client_for(options.family);
    let mut hop = 0;
    loop {
        let parsed = Url::parse(&current_url).map_err(|_| type_error("Invalid URL"))?;
        resolve_allowed(parsed.host_str().unwrap_or(""), options.family).await?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(type_error(format!("Request cannot be constructed from a URL that includes credentials: {current_url}")));
        }
        if !["http", "https"].contains(&parsed.scheme()) {
            return Err(type_error("fetch failed"));
        }
        let method =
            reqwest::Method::from_bytes(current_method.as_bytes()).map_err(|_| type_error(format!("'{current_method}' is not a valid HTTP method.")))?;
        let mut request_headers = header_map.clone();
        if !request_headers.contains_key("accept-encoding") {
            let encodings = if parsed.scheme() == "https" { "br, gzip, deflate, zstd" } else { "gzip, deflate" };
            request_headers.insert("accept-encoding", reqwest::header::HeaderValue::from_static(encodings));
        }
        let mut builder = client.request(method.clone(), parsed.clone()).headers(request_headers.clone());
        if let Some(body) = &current_body {
            builder = builder.body(body.clone());
        }
        let response = match builder.send().await {
            Ok(response) => response,
            Err(error) => {
                if let Some(message) = refused(&error, &parsed).await {
                    return Err(Failure::plain(message));
                }
                match retry_legacy(&error, &parsed, method, request_headers, current_body.clone(), options.family).await {
                    Some(answer) => answer?,
                    None => return Err(fetch_failure(&error)),
                }
            }
        };
        let status = response.status().as_u16();
        if forward_refused(&parsed, status) {
            return Err(Failure::plain(refusal(status)));
        }
        let location = response.headers().get("location").map(|value| latin1(value.as_bytes()));
        let Some(location) = location.filter(|_| options.follow_redirects && (300..400).contains(&status) && hop < MAX_REDIRECTS) else {
            return Ok(Page { response, url: current_url });
        };
        drop(response);
        if status == 303 {
            current_method = "GET".to_string();
            current_body = None;
        }
        current_url = parsed.join(&location).map_err(|_| type_error("fetch failed"))?.to_string();
        hop += 1;
    }
}

/// Requests [url] and judges the answer; fails with the error StatusTick expects.
pub async fn make_http_request(url: &str, options: &HttpOptions) -> Result<HttpRequestResult, Failure> {
    let start = Instant::now();
    let fetched = tokio::time::timeout(options.timeout, async {
        let page = fetch_page(url, options).await?;
        let status = page.response.status().as_u16();
        let legacy = legacy_version(&page.response);
        let headers = response_headers(page.response.headers());
        let skip_body = options.method.eq_ignore_ascii_case("HEAD") || NULL_BODY_STATUSES.contains(&status);
        let text = read_capped(page.response, skip_body).await.map_err(|error| fetch_failure(&error))?;
        Ok::<_, Failure>((status, headers, text, page.url, legacy))
    })
    .await
    .map_err(|_| aborted())??;
    let (status, headers, text, final_url, legacy_tls) = fetched;
    let page_time_ms = elapsed_ms(start);
    let is_up = match &options.expected_status {
        Some(expected) => expected.as_f64() == Some(f64::from(status)),
        None => status < 400,
    };
    let text_match = options.expected_text.as_ref().is_none_or(|keyword| matches_keyword(&text, keyword, options.not_contains, options.case_sensitive));
    let json_failure = match &options.json {
        Some(assertions) if is_up && !assertions.is_empty() => check_json(&text, assertions),
        _ => None,
    };
    let block_reason = if is_up { None } else { detect_block(status, &headers, &text) };
    let is_html = headers.get("content-type").is_some_and(|value| value.contains("text/html"));
    let asset_check = match &options.ignore_hosts {
        Some(ignore_hosts) if is_up && is_html => {
            let family = options.family;
            Some(
                check_assets(extract_assets(&text, &final_url, ignore_hosts, MAX_ASSETS), |asset_url, method| async move {
                    make_http_request_boxed(asset_url, HttpOptions::plain(method, ASSET_TIMEOUT, family)).await.map(|result| result.status)
                })
                .await,
            )
        }
        _ => None,
    };
    let mut kept = headers;
    kept.remove("set-cookie");
    kept.remove("set-cookie2");
    Ok(HttpRequestResult {
        status,
        headers: kept,
        is_up: is_up && text_match && json_failure.is_none(),
        text_match,
        json_failure,
        block_reason,
        asset_check,
        page_time_ms,
        legacy_tls,
    })
}

fn make_http_request_boxed(
    url: String,
    options: HttpOptions,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<HttpRequestResult, Failure>> + Send>> {
    Box::pin(async move { make_http_request(&url, &options).await })
}

pub fn check_status(result: &HttpRequestResult) -> &'static str {
    if result.is_up {
        "up"
    } else if result.block_reason.is_some() {
        "blocked"
    } else {
        "down"
    }
}

/// The answer of one HTTP check.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpCheckResult {
    pub url: Value,
    pub method: Value,
    pub status: &'static str,
    pub response_time: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<HttpDetails>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpDetails {
    /// Echoed as sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_status: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_text: Option<Value>,
    pub text_match: bool,
    pub headers: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assets: Option<Value>,
    #[serde(rename = "legacyTLS", skip_serializing_if = "Option::is_none")]
    pub legacy_tls: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weak_key: Option<bool>,
}

/// `/check/http` and the agent's `http` job.
pub async fn http_check(request: &Map<String, Value>) -> Value {
    let start = Instant::now();
    let url = request.get("url").cloned().unwrap_or(Value::Null);
    let method = request.get("method").cloned().unwrap_or_else(|| Value::from("GET"));
    let options = HttpOptions::from_request(request);
    let result = match make_http_request(url.as_str().unwrap_or(""), &options).await {
        Ok(result) => {
            let error = result
                .block_reason
                .map(|reason| (format!("Blocked by the site's firewall: {reason}"), "BLOCKED"))
                .or_else(|| result.json_failure.clone().map(|failure| (failure, "JSON_ASSERTION")));
            let legacy = result.legacy_tls.as_ref();
            HttpCheckResult {
                status: check_status(&result),
                response_time: result.page_time_ms,
                http_status: Some(result.status),
                timestamp: now_iso(),
                error_type: error.as_ref().map(|(_, kind)| kind.to_string()),
                error: error.map(|(message, _)| message),
                details: Some(HttpDetails {
                    expected_status: request.get("expectedStatus").cloned(),
                    expected_text: request.get("expectedText").cloned(),
                    text_match: result.text_match,
                    headers: result.headers,
                    assets: result.asset_check,
                    legacy_tls: legacy.map(|_| true),
                    tls_version: legacy.map(|legacy| legacy.version.clone()),
                    weak_key: legacy.filter(|legacy| legacy.weak_key).map(|_| true),
                }),
                url,
                method,
            }
        }
        Err(failure) => HttpCheckResult {
            url,
            method,
            status: "down",
            response_time: elapsed_ms(start),
            http_status: None,
            timestamp: now_iso(),
            error: Some(failure.message),
            error_type: Some(failure.name),
            details: None,
        },
    };
    serde_json::to_value(result).expect("serializable result")
}

/// The parts of [request] a multi check's HTTP item passes on: no body, assets, JSON assertions or IP version.
pub fn multi_options(request: &Map<String, Value>) -> HttpOptions {
    let mut options = HttpOptions::from_request(request);
    options.body = None;
    options.ignore_hosts = None;
    options.json = None;
    options.family = 0;
    options.follow_redirects = true;
    options
}

pub fn number_or(request: &Map<String, Value>, name: &str, default: f64) -> f64 {
    number_field(request, name).unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_content_codings() {
        use std::io::Write;
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(b"hello").unwrap();
        assert_eq!(decode_body(gzip.finish().unwrap(), Some("gzip")), b"hello");
        let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        zlib.write_all(b"hi").unwrap();
        assert_eq!(decode_body(zlib.finish().unwrap(), Some("deflate")), b"hi");
        let mut raw = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        raw.write_all(b"raw").unwrap();
        assert_eq!(decode_body(raw.finish().unwrap(), Some("deflate")), b"raw");
        assert_eq!(decode_body(b"plain".to_vec(), Some("unknown")), b"plain");
    }

    #[test]
    fn matches_keywords_by_mode_and_case() {
        assert!(matches_keyword("Hello World", "World", false, true));
        assert!(!matches_keyword("Hello World", "world", false, true));
        assert!(matches_keyword("Hello World", "world", false, false));
        assert!(!matches_keyword("Hello World", "World", true, true));
        assert!(matches_keyword("Hello", "Bye", true, true));
    }

    #[test]
    fn joins_repeated_headers() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.append("vary", "accept".parse().unwrap());
        headers.append("vary", "origin".parse().unwrap());
        headers.append("a-first", "1".parse().unwrap());
        let map = response_headers(&headers);
        assert_eq!(map.get("vary").unwrap(), "accept, origin");
        assert_eq!(map.keys().next().unwrap(), "a-first");
    }
}
