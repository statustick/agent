//! The egress proxy of one browser run: the browser and the script's own fetch and http(s) reach only what the agent's
//! target policy allows (STATUSTICK_ALLOW, never cloud metadata), on ports 80, 443 and 1024 to 65535, as the package's
//! `proxy.mts` with the agent's resolver. One request per plain-HTTP connection, so every request passes the policy.
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use statustick_checks::targets::resolve_allowed;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

const MAX_HEAD_BYTES: usize = 16 * 1024;
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// A refused request's reason, or a failure to reach the target.
enum Refusal {
    Denied(String),
    Failed,
}

/// The proxy of one run; stops when dropped. [refused] is the first refusal of the agent's policy.
pub struct RunProxy {
    pub url: String,
    refused: Arc<Mutex<Option<String>>>,
    task: JoinHandle<()>,
}

impl Drop for RunProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl RunProxy {
    pub async fn start() -> std::io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let url = format!("http://127.0.0.1:{}", listener.local_addr()?.port());
        let refused = Arc::new(Mutex::new(None));
        let noted = refused.clone();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            while let Ok((client, _)) = listener.accept().await {
                let noted = noted.clone();
                connections.spawn(async move { serve(client, noted).await });
            }
        });
        Ok(RunProxy { url, refused, task })
    }

    /// The first refusal of the agent's policy, when there was one.
    pub fn refused(&self) -> Option<String> {
        self.refused.lock().expect("refusal").clone()
    }
}

pub fn port_allowed(port: u16) -> bool {
    port == 80 || port == 443 || port >= 1024
}

/// The address for [host] when the agent's policy allows it.
async fn target(host: &str, port: u16, refused: &Mutex<Option<String>>) -> Result<IpAddr, Refusal> {
    if !port_allowed(port) {
        return Err(Refusal::Denied(format!("port {port} is not allowed")));
    }
    match resolve_allowed(host.trim_start_matches('[').trim_end_matches(']'), 0).await {
        Ok(addresses) => Ok(addresses[0]),
        Err(failure) if failure.is("TARGET_NOT_ALLOWED") => {
            refused.lock().expect("refusal").get_or_insert_with(|| failure.message.clone());
            Err(Refusal::Denied(failure.message))
        }
        Err(_) => Err(Refusal::Failed),
    }
}

async fn read_head(client: &mut TcpStream) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let rest = buffer.split_off(end + 4);
            return Some((buffer, rest));
        }
        if buffer.len() > MAX_HEAD_BYTES {
            return None;
        }
        let read = client.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

fn split_authority(authority: &str) -> Option<(String, u16)> {
    let (host, port) = authority.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    (!host.is_empty() && (host.starts_with('[') == host.ends_with(']'))).then(|| (host.to_string(), port))
}

async fn serve(mut client: TcpStream, refused: Arc<Mutex<Option<String>>>) {
    let Ok(Some((head, rest))) = tokio::time::timeout(HEAD_TIMEOUT, read_head(&mut client)).await else { return };
    let text = String::from_utf8_lossy(&head).to_string();
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split(' ');
    let (method, target_text) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));

    if method.eq_ignore_ascii_case("CONNECT") {
        let Some((host, port)) = split_authority(target_text) else {
            let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
            return;
        };
        let address = match target(&host, port, &refused).await {
            Ok(address) => address,
            Err(Refusal::Denied(_)) => return drop(client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await),
            Err(Refusal::Failed) => return drop(client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await),
        };
        let Ok(Ok(mut upstream)) = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((address, port))).await else {
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            return;
        };
        if client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await.is_err() || upstream.write_all(&rest).await.is_err() {
            return;
        }
        let _ = copy_bidirectional(&mut client, &mut upstream).await;
        return;
    }

    let blocked = |reason: &str| format!("HTTP/1.1 403 Forbidden\r\ncontent-type: text/plain\r\nconnection: close\r\n\r\nBlocked by StatusTick: {reason}\n");
    let Some(url) = url::Url::parse(target_text).ok().filter(|url| url.scheme() == "http") else {
        let _ = client.write_all(blocked("only http:// URLs can go through without CONNECT").as_bytes()).await;
        return;
    };
    let host = url.host_str().unwrap_or("").to_string();
    let port = url.port_or_known_default().unwrap_or(80);
    let address = match target(&host, port, &refused).await {
        Ok(address) => address,
        Err(Refusal::Denied(reason)) => return drop(client.write_all(blocked(&reason).as_bytes()).await),
        Err(Refusal::Failed) => return drop(client.write_all(blocked("upstream failed").replace("403 Forbidden", "502 Bad Gateway").as_bytes()).await),
    };
    let Ok(Ok(mut upstream)) = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((address, port))).await else {
        let _ = client.write_all(blocked("upstream failed").replace("403 Forbidden", "502 Bad Gateway").as_bytes()).await;
        return;
    };
    let path = &url[url::Position::BeforePath..url::Position::AfterQuery];
    let version = parts.next().unwrap_or("HTTP/1.1");
    let mut forwarded = format!("{method} {path} {version}\r\n");
    for line in lines.filter(|line| !line.is_empty()) {
        let name = line.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
        if !["host", "proxy-connection", "proxy-authorization", "connection", "keep-alive"].contains(&name.as_str()) {
            forwarded.push_str(line);
            forwarded.push_str("\r\n");
        }
    }
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    forwarded.push_str(&format!("host: {authority}\r\nconnection: close\r\n\r\n"));
    if upstream.write_all(forwarded.as_bytes()).await.is_err() || upstream.write_all(&rest).await.is_err() {
        return;
    }
    let _ = copy_bidirectional(&mut client, &mut upstream).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use statustick_checks::targets::{TargetPolicy, parse_allow_list, set_target_policy};

    async fn ask(proxy: &str, request: &str) -> String {
        let address = proxy.trim_start_matches("http://");
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut answer = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut answer)).await;
        String::from_utf8_lossy(&answer).to_string()
    }

    #[tokio::test]
    async fn applies_the_agent_policy_to_tunnels_and_plain_requests() {
        let origin = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = origin.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = origin.accept().await {
                tokio::spawn(async move {
                    let mut buffer = [0u8; 4096];
                    let read = socket.read(&mut buffer).await.unwrap_or(0);
                    let head = String::from_utf8_lossy(&buffer[..read]).to_string();
                    let first = head.lines().next().unwrap_or("").to_string();
                    let _ = socket.write_all(format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{first}", first.len()).as_bytes()).await;
                });
            }
        });

        set_target_policy(TargetPolicy { internal: true, allow: None });
        let proxy = RunProxy::start().await.unwrap();
        let plain = ask(&proxy.url, &format!("GET http://127.0.0.1:{port}/page?a=1 HTTP/1.1\r\nHost: x\r\nProxy-Connection: keep-alive\r\n\r\n")).await;
        assert!(plain.ends_with("GET /page?a=1 HTTP/1.1"), "{plain}");
        let tunnel = ask(&proxy.url, &format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n")).await;
        assert!(tunnel.starts_with("HTTP/1.1 200 Connection Established"), "{tunnel}");
        let metadata = ask(&proxy.url, "CONNECT 169.254.169.254:443 HTTP/1.1\r\n\r\n").await;
        assert!(metadata.starts_with("HTTP/1.1 403"), "{metadata}");
        assert_eq!(proxy.refused().as_deref(), Some("target not allowed"));
        let smtp = ask(&proxy.url, "GET http://127.0.0.1:25/ HTTP/1.1\r\n\r\n").await;
        assert!(smtp.contains("Blocked by StatusTick: port 25 is not allowed"), "{smtp}");

        set_target_policy(TargetPolicy { internal: true, allow: parse_allow_list("10.0.0.0/8", "STATUSTICK_ALLOW").unwrap() });
        let listed = RunProxy::start().await.unwrap();
        let outside = ask(&listed.url, &format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\n\r\n")).await;
        assert!(outside.contains("Blocked by StatusTick: target not allowed by agent policy"), "{outside}");
        assert_eq!(listed.refused().as_deref(), Some("target not allowed by agent policy"));
        set_target_policy(TargetPolicy::default());
    }
}
