//! HTTPS_PROXY, HTTP_PROXY and NO_PROXY for the HTTP and MCP checks (lower case wins, like curl).
use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::Duration;

use base64::Engine;
use ipnet::IpNet;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;

#[derive(Debug, Clone, PartialEq)]
pub enum NoProxyEntry {
    Any,
    Range(IpNet),
    Host { host: String, port: Option<String> },
}

#[derive(Debug, Clone, Default)]
pub struct ProxySettings {
    pub http: Option<Url>,
    pub https: Option<Url>,
    pub no_proxy: Vec<NoProxyEntry>,
}

fn parse_proxy(name: &str, value: Option<&str>) -> Result<Option<Url>, String> {
    let raw = value.unwrap_or("").trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let has_scheme = regex::Regex::new(r"(?i)^[a-z][a-z0-9+.-]*://").expect("valid pattern").is_match(raw);
    let url = Url::parse(&if has_scheme { raw.to_string() } else { format!("http://{raw}") }).map_err(|_| format!("{name} is not a valid proxy URL"))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(format!("{name} must be an http:// or https:// proxy URL"));
    }
    Ok(Some(url))
}

fn parse_no_proxy(value: Option<&str>) -> Vec<NoProxyEntry> {
    value
        .unwrap_or("")
        .split(|c: char| c.is_whitespace() || c == ',')
        .map(|entry| entry.trim().to_lowercase())
        .filter(|entry| !entry.is_empty())
        .filter_map(|entry| {
            if entry == "*" {
                return Some(NoProxyEntry::Any);
            }
            if let Some((address, prefix)) = entry.split_once('/') {
                let ip: IpAddr = address.parse().ok()?;
                let bits: u8 = prefix.parse().ok()?;
                return IpNet::new(ip, bits).ok().map(|net| NoProxyEntry::Range(net.trunc()));
            }
            if let Some(rest) = entry.strip_prefix('[') {
                let (host, after) = rest.split_once(']')?;
                let port = after.strip_prefix(':').filter(|port| !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()));
                if !after.is_empty() && port.is_none() {
                    return None;
                }
                return Some(NoProxyEntry::Host { host: host.to_string(), port: port.map(str::to_string) });
            }
            let parts: Vec<&str> = entry.split(':').collect();
            if parts.len() > 2 {
                return Some(NoProxyEntry::Host { host: entry.clone(), port: None });
            }
            let host = parts[0].strip_prefix("*.").or_else(|| parts[0].strip_prefix('.')).unwrap_or(parts[0]);
            Some(NoProxyEntry::Host { host: host.to_string(), port: parts.get(1).map(|port| port.to_string()) })
        })
        .collect()
}

/// Reads the proxy variables from [env]; an https target falls back to the HTTP proxy.
pub fn read_proxy_settings(env: impl Fn(&str) -> Option<String>) -> Result<ProxySettings, String> {
    let pick = |lower: &str, upper: &str| env(lower).filter(|value| !value.is_empty()).or_else(|| env(upper));
    let http = parse_proxy("HTTP_PROXY", pick("http_proxy", "HTTP_PROXY").as_deref())?;
    let https = parse_proxy("HTTPS_PROXY", pick("https_proxy", "HTTPS_PROXY").as_deref())?.or_else(|| http.clone());
    Ok(ProxySettings { http, https, no_proxy: parse_no_proxy(pick("no_proxy", "NO_PROXY").as_deref()) })
}

static ENV_SETTINGS: LazyLock<ProxySettings> = LazyLock::new(|| read_proxy_settings(|name| std::env::var(name).ok()).unwrap_or_default());

pub fn env_settings() -> &'static ProxySettings {
    &ENV_SETTINGS
}

fn bypasses(target: &Url, no_proxy: &[NoProxyEntry]) -> bool {
    let host = target.host_str().unwrap_or("").trim_start_matches('[').trim_end_matches(']').to_lowercase();
    let port = target.port_or_known_default().map(|port| port.to_string()).unwrap_or_default();
    let ip = host.parse::<IpAddr>().ok();
    no_proxy.iter().any(|entry| match entry {
        NoProxyEntry::Any => true,
        NoProxyEntry::Range(net) => ip.is_some_and(|ip| net.contains(&ip)),
        NoProxyEntry::Host { host: entry, port: entry_port } => {
            if entry_port.as_ref().is_some_and(|entry_port| *entry_port != port) {
                return false;
            }
            host == *entry || host.ends_with(&format!(".{entry}"))
        }
    })
}

/// The proxy to use for a request to [target], or None to connect directly.
pub fn proxy_for(target: &Url, settings: &ProxySettings) -> Option<Url> {
    let proxy = match target.scheme() {
        "https" => settings.https.clone(),
        "http" => settings.http.clone(),
        _ => None,
    }?;
    if bypasses(target, &settings.no_proxy) { None } else { Some(proxy) }
}

/// The proxy address for logs, without the user name and password.
pub fn proxy_label(proxy: &Url) -> String {
    let host = proxy.host_str().unwrap_or("");
    match proxy.port() {
        Some(port) => format!("{}://{host}:{port}", proxy.scheme()),
        None => format!("{}://{host}", proxy.scheme()),
    }
}

/// The error of a request a proxy refused, worded as StatusTick expects it.
pub fn refusal(status: u16) -> String {
    format!("The proxy refused the request: HTTP {status}")
}

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

fn connect_request(target: &Url, proxy: &Url) -> Option<String> {
    let authority = format!("{}:{}", target.host_str()?, target.port_or_known_default()?);
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if !proxy.username().is_empty() {
        let decode = |text: &str| percent_encoding::percent_decode_str(text).decode_utf8_lossy().into_owned();
        let credentials = format!("{}:{}", decode(proxy.username()), decode(proxy.password().unwrap_or("")));
        request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", base64::engine::general_purpose::STANDARD.encode(credentials)));
    }
    request.push_str("\r\n");
    Some(request)
}

async fn status_line<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, request: &str) -> Option<u16> {
    stream.write_all(request.as_bytes()).await.ok()?;
    let mut answer = Vec::new();
    let mut buffer = [0u8; 1024];
    while !answer.windows(2).any(|pair| pair == b"\r\n") && answer.len() < 8192 {
        let read = stream.read(&mut buffer).await.ok()?;
        if read == 0 {
            return None;
        }
        answer.extend_from_slice(&buffer[..read]);
    }
    let line = String::from_utf8_lossy(&answer);
    line.split_whitespace().nth(1)?.parse().ok()
}

/// The status [proxy] refuses a tunnel to [target] with. The HTTP client drops it when a tunnel fails, so the proxy is
/// asked once more on a connection of its own; None when that answer is 200 or does not come.
pub async fn tunnel_refusal(target: &Url, proxy: &Url) -> Option<u16> {
    let request = connect_request(target, proxy)?;
    let host = proxy.host_str()?.trim_start_matches('[').trim_end_matches(']').to_string();
    let port = proxy.port_or_known_default()?;
    let probe = async {
        let stream = TcpStream::connect((host.as_str(), port)).await.ok()?;
        if proxy.scheme() == "https" {
            let name = rustls::pki_types::ServerName::try_from(host.clone()).ok()?;
            let tls = tokio_rustls::TlsConnector::from(crate::tls::client_config(true, &[])).connect(name, stream).await.ok()?;
            status_line(tls, &request).await
        } else {
            status_line(stream, &request).await
        }
    };
    tokio::time::timeout(PROBE_TIMEOUT, probe).await.ok().flatten().filter(|status| *status != 200)
}

/// The error for a request [error] says the proxy refused, or None when no proxy refused it.
pub async fn refused(error: &reqwest::Error, target: &Url) -> Option<String> {
    let mut tunnel = false;
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(error) = current {
        let text = error.to_string();
        if text.contains("proxy authorization required") {
            return Some(refusal(407));
        }
        tunnel |= text.contains("tunnel error: unsuccessful");
        current = error.source();
    }
    if !tunnel {
        return None;
    }
    let proxy = proxy_for(target, env_settings())?;
    Some(match tunnel_refusal(target, &proxy).await {
        Some(status) => refusal(status),
        None => "The proxy refused the request".to_string(),
    })
}

/// Whether a plain-HTTP answer with [status] is [target]'s proxy refusing it: a forwarding proxy asks for credentials
/// with 407, and the request fails then.
pub fn forward_refused(target: &Url, status: u16) -> bool {
    status == 407 && target.scheme() == "http" && proxy_for(target, env_settings()).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn settings(pairs: &[(&str, &str)]) -> Result<ProxySettings, String> {
        let env: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        read_proxy_settings(|name| env.get(name).cloned())
    }

    fn via(url: &str, settings: &ProxySettings) -> Option<String> {
        proxy_for(&Url::parse(url).unwrap(), settings).map(|proxy| proxy.to_string())
    }

    #[test]
    fn picks_the_proxy_per_scheme() {
        let none = settings(&[]).unwrap();
        assert_eq!(via("https://example.com", &none), None);
        let both = settings(&[("HTTPS_PROXY", "http://secure:3128"), ("HTTP_PROXY", "http://plain:3128")]).unwrap();
        assert_eq!(via("https://example.com", &both).as_deref(), Some("http://secure:3128/"));
        assert_eq!(via("http://example.com", &both).as_deref(), Some("http://plain:3128/"));
        let http_only = settings(&[("HTTP_PROXY", "proxy.corp:8080")]).unwrap();
        assert_eq!(via("https://example.com", &http_only).as_deref(), Some("http://proxy.corp:8080/"));
        let lower = settings(&[("https_proxy", "http://lower:1"), ("HTTPS_PROXY", "http://upper:1")]).unwrap();
        assert_eq!(via("https://example.com", &lower).as_deref(), Some("http://lower:1/"));
        assert_eq!(settings(&[("HTTPS_PROXY", "socks5://proxy:1080")]).unwrap_err(), "HTTPS_PROXY must be an http:// or https:// proxy URL");
    }

    #[test]
    fn skips_the_proxy_for_no_proxy_entries() {
        let proxy = settings(&[
            ("HTTPS_PROXY", "http://p:1"),
            ("HTTP_PROXY", "http://p:1"),
            ("NO_PROXY", "corp.example, .internal, 10.0.0.0/8, 192.168.1.5, other.example:8443"),
        ])
        .unwrap();
        assert_eq!(via("https://api.corp.example", &proxy), None);
        assert_eq!(via("https://corp.example", &proxy), None);
        assert_eq!(via("https://db.internal", &proxy), None);
        assert_eq!(via("https://10.2.3.4", &proxy), None);
        assert_eq!(via("http://192.168.1.5", &proxy), None);
        assert_eq!(via("https://other.example:8443", &proxy), None);
        assert!(via("https://other.example", &proxy).is_some());
        assert!(via("https://example.com", &proxy).is_some());
        let all = settings(&[("HTTPS_PROXY", "http://p:1"), ("NO_PROXY", "*")]).unwrap();
        assert_eq!(via("https://example.com", &all), None);
    }

    #[test]
    fn labels_without_credentials() {
        assert_eq!(proxy_label(&Url::parse("http://user:secret@proxy.corp:3128").unwrap()), "http://proxy.corp:3128");
    }

    #[test]
    fn asks_for_a_tunnel_with_the_proxy_credentials() {
        let target = Url::parse("https://example.com/path").unwrap();
        let request = connect_request(&target, &Url::parse("http://us%40er:p%3Ass@proxy:3128").unwrap()).unwrap();
        assert_eq!(request, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic dXNAZXI6cDpzcw==\r\n\r\n");
        assert_eq!(
            connect_request(&target, &Url::parse("http://proxy:3128").unwrap()).unwrap(),
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn reads_the_status_a_proxy_refuses_a_tunnel_with() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            for answer in ["HTTP/1.1 403 Forbidden\r\n\r\n", "HTTP/1.1 200 Connection established\r\n\r\n"] {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buffer = [0u8; 1024];
                let _ = socket.read(&mut buffer).await;
                socket.write_all(answer.as_bytes()).await.unwrap();
            }
        });
        let proxy = Url::parse(&format!("http://127.0.0.1:{port}")).unwrap();
        let target = Url::parse("https://example.com").unwrap();
        assert_eq!(tunnel_refusal(&target, &proxy).await, Some(403));
        assert_eq!(tunnel_refusal(&target, &proxy).await, None);
    }
}
