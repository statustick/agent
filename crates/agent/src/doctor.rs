//! `statustick-agent doctor`: checks the token, DNS, TCP and TLS to StatusTick (or through the
//! proxy's tunnel), the proxy settings, StatusTick's answer, the token and the clock, with one fix per failed step.
use std::net::IpAddr;
use std::time::{Duration, Instant};

use rustls::pki_types::CertificateDer;
use serde_json::Value;
use statustick_checks::connection::{Stream, Target, connect_tls};
use statustick_checks::proxy::{ProxySettings, proxy_for, proxy_label, read_proxy_settings};
use statustick_checks::targets::{lookup, resolve_allowed};
use statustick_checks::tls::{check_server_identity, common_names, organizations, verify_chain, version_name};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::VERSION;
use crate::settings::{DEFAULT_URL, Env, env_value, read_ca_file, read_relay_port, read_token, read_url};

const TOKEN_PREFIX: &str = "sta_live_";
const TOKEN_LENGTH: usize = 53;
const SHOWN_TOKEN_CHARACTERS: usize = 6;
const STEP_TIMEOUT: Duration = Duration::from_secs(10);
const CALL_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_CLOCK_DRIFT_MS: f64 = 10000.0;
const MAX_PROXY_ANSWER_BYTES: usize = 16384;
const MIN_REDACTED_TOKEN_LENGTH: usize = 8;
pub const USAGE: &str = "Usage: doctor [--target <http(s) URL>] [--report [--include-hosts]]";

#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    Ok(String, String),
    Fail(String, String, String),
    Skip(String, String),
}

fn ok(name: &str, detail: impl Into<String>) -> Step {
    Step::Ok(name.into(), detail.into())
}

fn fail(name: &str, detail: impl Into<String>, fix: impl Into<String>) -> Step {
    Step::Fail(name.into(), detail.into(), fix.into())
}

fn skip(name: &str, detail: impl Into<String>) -> Step {
    Step::Skip(name.into(), detail.into())
}

#[derive(Default, Debug)]
pub struct Options {
    pub target: Option<url::Url>,
    pub report: bool,
    pub include_hosts: bool,
}

pub fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut options = Options::default();
    let mut target: Option<String> = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--report" {
            options.report = true;
        } else if arg == "--include-hosts" {
            options.include_hosts = true;
        } else if arg == "--target" && index + 1 < args.len() && !args[index + 1].is_empty() {
            index += 1;
            target = Some(args[index].clone());
        } else if let Some(value) = arg.strip_prefix("--target=") {
            target = Some(value.to_string());
        } else {
            return Err(format!("Unknown option: {arg}"));
        }
        index += 1;
    }
    if let Some(target) = target.filter(|target| !target.is_empty()) {
        let url = url::Url::parse(&target).ok().filter(|url| url.scheme() == "http" || url.scheme() == "https");
        options.target = Some(url.ok_or("--target must be an http:// or https:// URL")?);
    }
    Ok(options)
}

/// The start of the token as the dashboard shows it; the rest is never printed.
fn token_prefix(token: &str) -> String {
    format!("{}…", token.chars().take(TOKEN_PREFIX.len() + SHOWN_TOKEN_CHARACTERS).collect::<String>())
}

pub fn token_step(token: &str) -> Step {
    let name = "Token format";
    if token.is_empty() {
        return fail(name, "STATUSTICK_TOKEN is not set", "Set STATUSTICK_TOKEN to the token shown when you created the private location.");
    }
    let well_formed = token.strip_prefix(TOKEN_PREFIX).is_some_and(|rest| rest.len() == 44 && rest.bytes().all(|b| b.is_ascii_alphanumeric()));
    if well_formed {
        return ok(name, format!("{} ({TOKEN_LENGTH} characters)", token_prefix(token)));
    }
    let fix = "Copy the whole token again from the private location in StatusTick, without quotes or spaces.";
    if !token.starts_with(TOKEN_PREFIX) {
        return fail(name, format!("the token does not start with {TOKEN_PREFIX}"), fix);
    }
    let length = token.encode_utf16().count();
    if length != TOKEN_LENGTH {
        return fail(name, format!("{} has {length} characters instead of {TOKEN_LENGTH}", token_prefix(token)), fix);
    }
    fail(name, format!("{} has characters other than letters and digits", token_prefix(token)), fix)
}

fn bare(host: &str) -> String {
    host.trim_start_matches('[').trim_end_matches(']').to_string()
}

fn authority(host: &str, port: u16) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() { format!("[{host}]:{port}") } else { format!("{host}:{port}") }
}

fn default_port(url: &url::Url) -> u16 {
    url.port_or_known_default().unwrap_or(443)
}

fn since(started: Instant) -> u128 {
    started.elapsed().as_millis()
}

fn io_reason(error: &std::io::Error) -> String {
    statustick_checks::util::io_code(error)
}

async fn open_socket(address: IpAddr, port: u16) -> Result<TcpStream, String> {
    match tokio::time::timeout(STEP_TIMEOUT, TcpStream::connect((address, port))).await {
        Err(_) => Err("ETIMEDOUT".into()),
        Ok(Err(error)) => Err(io_reason(&error)),
        Ok(Ok(socket)) => Ok(socket),
    }
}

/// Asks the proxy for a tunnel with CONNECT and returns the status code of its answer.
async fn tunnel(socket: &mut Box<dyn Stream>, target: &str, proxy: &url::Url) -> Result<u16, String> {
    let credentials = if proxy.username().is_empty() {
        String::new()
    } else {
        use base64::Engine;
        let decode = |text: &str| percent_encoding::percent_decode_str(text).decode_utf8_lossy().into_owned();
        let pair = format!("{}:{}", decode(proxy.username()), decode(proxy.password().unwrap_or("")));
        format!("Proxy-Authorization: Basic {}\r\n", base64::engine::general_purpose::STANDARD.encode(pair))
    };
    let work = async {
        socket.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{credentials}\r\n").as_bytes()).await.map_err(|error| io_reason(&error))?;
        let mut head: Vec<u8> = Vec::new();
        let mut byte = [0u8; 1];
        // One byte at a time, so no byte of the TLS handshake that follows is taken from the socket.
        while !head.ends_with(b"\r\n\r\n") && head.len() < MAX_PROXY_ANSWER_BYTES {
            match socket.read(&mut byte).await {
                Ok(0) => return Err("the proxy closed the connection".to_string()),
                Ok(_) => head.push(byte[0]),
                Err(error) => return Err(io_reason(&error)),
            }
        }
        let text = String::from_utf8_lossy(&head);
        let status = text
            .strip_prefix("HTTP/1.")
            .and_then(|rest| rest.get(2..5))
            .filter(|_| matches!(text.as_bytes().get(7), Some(b'0' | b'1')))
            .and_then(|code| code.parse().ok());
        match status {
            Some(status) if head.ends_with(b"\r\n\r\n") => Ok(status),
            _ => Err("the proxy sent an answer that is not HTTP".to_string()),
        }
    };
    tokio::time::timeout(STEP_TIMEOUT, work).await.unwrap_or_else(|_| Err("the proxy did not answer".into()))
}

fn proxy_fix(status: u16, target: &str) -> String {
    if status == 407 {
        return "Put the proxy user name and password in the proxy URL: http://user:password@host:port.".into();
    }
    format!("Ask your network team to allow {target} on the proxy.")
}

fn issuer_of(chain: &[CertificateDer<'static>]) -> String {
    let Some((_, leaf)) = chain.first().and_then(|der| X509Certificate::from_der(der).ok()) else { return "an unnamed issuer".into() };
    let parts: Vec<String> = [common_names(leaf.issuer()).into_iter().next(), organizations(leaf.issuer()).into_iter().next()]
        .into_iter()
        .flatten()
        .filter(|part| !part.is_empty())
        .collect();
    if parts.is_empty() { "an unnamed issuer".into() } else { parts.join(", ") }
}

/// The chain and the reason Node.js would not trust it, or None when it would.
fn authorization(chain: &[CertificateDer<'static>], host: &str) -> Option<String> {
    if let Err(code) = verify_chain(chain) {
        return Some(code);
    }
    let (_, leaf) = X509Certificate::from_der(chain.first()?).ok()?;
    check_server_identity(host, &leaf).map(|_| "ERR_TLS_CERT_ALTNAME_INVALID".to_string())
}

struct Secure {
    chain: Vec<CertificateDer<'static>>,
    protocol: String,
}

async fn handshake(stream: Box<dyn Stream>, host: &str, address: IpAddr, port: u16) -> Result<(Secure, Box<dyn Stream>), String> {
    let target = Target { host: host.to_string(), address, port };
    let work = connect_tls(&target, false, &[], stream);
    let tls = match tokio::time::timeout(STEP_TIMEOUT, work).await {
        Err(_) => return Err("ETIMEDOUT".into()),
        Ok(Err(failure)) => return Err(failure.code.unwrap_or(failure.message)),
        Ok(Ok(tls)) => tls,
    };
    let (_, connection) = tls.get_ref();
    let chain = connection.peer_certificates().map(|chain| chain.iter().map(|der| der.clone().into_owned()).collect()).unwrap_or_default();
    let protocol = connection.protocol_version().and_then(version_name).unwrap_or_default();
    Ok((Secure { chain, protocol }, Box::new(tls)))
}

struct Fixes {
    untrusted: &'static str,
    failed: String,
}

/// TLS over an open socket, through a CONNECT tunnel when a proxy is used.
async fn tls_step(name: &str, socket: TcpStream, host: &str, address: IpAddr, port: u16, proxy: Option<&url::Url>, fixes: Fixes) -> Step {
    let started = Instant::now();
    let target = authority(host, port);
    let mut carrier: Box<dyn Stream> = Box::new(socket);
    if let Some(proxy) = proxy {
        if proxy.scheme() == "https" {
            let proxy_host = bare(proxy.host_str().unwrap_or(""));
            let (secure, stream) = match handshake(carrier, &proxy_host, address, default_port(proxy)).await {
                Ok(done) => done,
                Err(reason) => return fail(name, reason, fixes.failed),
            };
            if let Some(reason) = authorization(&secure.chain, &proxy_host) {
                return fail(
                    name,
                    format!("the certificate of proxy {} is not trusted ({reason})", proxy_label(proxy)),
                    "Put the CA certificate of the proxy in a PEM file and set NODE_EXTRA_CA_CERTS to it.",
                );
            }
            carrier = stream;
        }
        match tunnel(&mut carrier, &target, proxy).await {
            Ok(200) => {}
            Ok(status) => return fail(name, format!("proxy {} answered HTTP {status} to CONNECT {target}", proxy_label(proxy)), proxy_fix(status, &target)),
            Err(reason) => return fail(name, reason, fixes.failed),
        }
    }
    let identity = host.parse::<IpAddr>().unwrap_or(address);
    match handshake(carrier, host, identity, port).await {
        Err(reason) => fail(name, reason, fixes.failed),
        Ok((secure, _)) => {
            let ms = since(started);
            let issuer = issuer_of(&secure.chain);
            match authorization(&secure.chain, host) {
                Some(reason) => fail(name, format!("the certificate issued by {issuer} is not trusted ({reason})"), fixes.untrusted),
                None => ok(name, format!("{}, certificate issued by {issuer}, {ms} ms", secure.protocol)),
            }
        }
    }
}

type Hidden = Vec<(String, String)>;

/// Steps 2 to 4: DNS, TCP and TLS to StatusTick, or to the proxy and through its tunnel.
async fn reach_status_tick(base: &url::Url, proxy: Option<&url::Url>, hidden: &mut Hidden) -> (Vec<Step>, bool) {
    let host = bare(base.host_str().unwrap_or(""));
    let port = default_port(base);
    let (via_host, via_port) = match proxy {
        Some(proxy) => (bare(proxy.host_str().unwrap_or("")), default_port(proxy)),
        None => (host.clone(), port),
    };
    let dns_name = match proxy {
        Some(_) => format!("DNS for {host} (resolved by proxy {via_host})"),
        None => format!("DNS for {host}"),
    };
    let tcp_name = match proxy {
        Some(_) => format!("TCP to proxy {}", authority(&via_host, via_port)),
        None => format!("TCP {port}"),
    };
    let tls_name = format!("TLS to {host}");

    let dns_started = Instant::now();
    let addresses = match via_host.parse::<IpAddr>() {
        Ok(address) => Ok(vec![address]),
        Err(_) => lookup(&via_host, 0).await.map_err(|failure| failure.code.unwrap_or(failure.message)),
    };
    let addresses = match addresses {
        Ok(addresses) if !addresses.is_empty() => addresses,
        Ok(_) | Err(_) => {
            let reason = addresses.err().unwrap_or_else(|| "ENOTFOUND".into());
            let fix = if proxy.is_some() {
                "Check the host name in HTTPS_PROXY and that this host's DNS server can resolve it.".to_string()
            } else {
                format!("Make sure this host's DNS server can resolve {host}, or start the container with --dns set to one that can.")
            };
            return (vec![fail(&dns_name, reason, fix), skip(&tcp_name, "needs DNS"), skip(&tls_name, "needs TCP")], false);
        }
    };
    let default_host = url::Url::parse(DEFAULT_URL).ok().and_then(|url| url.host_str().map(str::to_string)).unwrap_or_default();
    let label = if proxy.is_some() {
        Some("<proxy-address>")
    } else if host == default_host {
        None
    } else {
        Some("<statustick-address>")
    };
    if let Some(label) = label {
        hidden.extend(addresses.iter().map(|address| (address.to_string(), label.to_string())));
    }
    let listed = addresses.iter().map(IpAddr::to_string).collect::<Vec<_>>().join(", ");
    let dns_step = ok(&dns_name, format!("{via_host} is {listed}, {} ms", since(dns_started)));

    let tcp_started = Instant::now();
    let socket = match open_socket(addresses[0], via_port).await {
        Ok(socket) => socket,
        Err(reason) => {
            let fix = if proxy.is_some() {
                "Check the proxy address and port in HTTPS_PROXY and that this host may connect to it.".to_string()
            } else {
                format!("Allow outbound TCP from this host to {host} on port {port} in your firewall.")
            };
            return (vec![dns_step, fail(&tcp_name, reason, fix), skip(&tls_name, "needs TCP")], false);
        }
    };
    let tcp_step = ok(&tcp_name, format!("connected to {}, {} ms", addresses[0], since(tcp_started)));
    if base.scheme() == "http" {
        return (vec![dns_step, tcp_step, skip(&tls_name, "STATUSTICK_URL uses plain http (local development)")], true);
    }
    let fixes = Fixes {
        untrusted: "A proxy or firewall on the way probably inspects TLS: put its CA certificate in a PEM file and set NODE_EXTRA_CA_CERTS to it.",
        failed: format!("Allow TLS connections to {host} in your firewall, or set HTTPS_PROXY if outbound traffic must use a proxy."),
    };
    let tls = tls_step(&tls_name, socket, &host, addresses[0], port, proxy, fixes).await;
    let reachable = matches!(tls, Step::Ok(..));
    (vec![dns_step, tcp_step, tls], reachable)
}

fn settings_step(
    settings_error: Option<&str>,
    ca_error: Option<&str>,
    settings: Option<&ProxySettings>,
    proxy: Option<&url::Url>,
    ca_file: Option<&str>,
    host: &str,
) -> Step {
    let name = "Proxy settings";
    if let Some(error) = settings_error {
        return fail(name, error, "Write the proxy as http://host:port, or http://user:password@host:port with a password.");
    }
    if let Some(error) = ca_error {
        return fail(name, error, "Mount the PEM file with your CA certificates into the container and set NODE_EXTRA_CA_CERTS to its path there.");
    }
    let mut detail = match (proxy, settings.and_then(|settings| settings.https.as_ref())) {
        (Some(proxy), _) => format!("connects through proxy {}", proxy_label(proxy)),
        (None, Some(_)) => format!("NO_PROXY matches {host}, connects directly"),
        _ => "no proxy set, connects directly".to_string(),
    };
    if let Some(file) = ca_file {
        detail.push_str(&format!("; extra CA certificates from {file}"));
    }
    ok(name, detail)
}

fn http_client(proxy: Option<&url::Url>) -> reqwest::Client {
    let mut builder = reqwest::Client::builder().use_preconfigured_tls((*statustick_checks::tls::client_config(true, &["http/1.1"])).clone()).no_proxy();
    if let Some(proxy) = proxy.and_then(|proxy| reqwest::Proxy::all(proxy.as_str()).ok()) {
        builder = builder.proxy(proxy);
    }
    builder.build().expect("HTTP client")
}

async fn call_failure(error: &reqwest::Error, url: &str, proxy: Option<&url::Url>) -> (String, Option<u16>) {
    let refused = match (proxy, url::Url::parse(url)) {
        (Some(_), Ok(target)) => statustick_checks::proxy::refused(error, &target).await,
        _ => None,
    };
    let status = refused.as_deref().and_then(|text| text.rsplit(' ').next()).and_then(|status| status.parse().ok());
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    let mut reason = error.to_string();
    while let Some(inner) = current {
        if let Some(io) = inner.downcast_ref::<std::io::Error>() {
            reason = io_reason(io);
            break;
        }
        if let Some(node) = statustick_checks::tls::node_error(inner) {
            reason = node.code;
            break;
        }
        reason = inner.to_string();
        current = inner.source();
    }
    if error.is_timeout() {
        reason = "The operation was aborted due to timeout".into();
    }
    (reason, status)
}

/// `GET /health` needs no token, so a proxy or firewall answering instead of StatusTick is told apart from a token problem.
async fn reachable_step(base_url: &str, proxy: Option<&url::Url>) -> Step {
    let name = "StatusTick answers";
    let url = format!("{base_url}/health");
    let host = url::Url::parse(base_url)
        .ok()
        .and_then(|url| {
            url.host_str().map(|host| match url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            })
        })
        .unwrap_or_default();
    let response = match http_client(proxy).get(&url).header("User-Agent", format!("StatusTick-Agent/{VERSION}")).timeout(CALL_TIMEOUT).send().await {
        Ok(response) => response,
        Err(error) => {
            let (reason, refused) = call_failure(&error, &url, proxy).await;
            if let (Some(proxy), Some(status)) = (proxy, refused) {
                return fail(name, format!("proxy {} refused the call: HTTP {status}", proxy_label(proxy)), proxy_fix(status, &host));
            }
            return fail(name, reason, "Fix the failed steps above, then run doctor again.");
        }
    };
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if status.is_success() && body.trim() == "ok" {
        return ok(name, format!("GET {url} answered ok"));
    }
    fail(
        name,
        format!("GET {url} answered HTTP {} without \"ok\"", status.as_u16()),
        format!(
            "Something other than StatusTick answered: allow {host} in your proxy or firewall, and leave STATUSTICK_URL unset so the agent uses {DEFAULT_URL}."
        ),
    )
}

pub struct Clock {
    sent_at: i64,
    received_at: i64,
    server_date: Option<String>,
}

/// Sends a heartbeat without an agent id: a good token gets agent.unauthorized and nothing is recorded for this host.
async fn token_accepted_step(token: &str, base_url: &str, proxy: Option<&url::Url>) -> (Step, Option<Clock>) {
    let name = "Token accepted";
    let host = url::Url::parse(base_url)
        .ok()
        .and_then(|url| {
            url.host_str().map(|host| match url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            })
        })
        .unwrap_or_default();
    let sent_at = chrono::Utc::now().timestamp_millis();
    let url = format!("{base_url}/v1/heartbeat");
    let request = http_client(proxy)
        .post(&url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Agent-Version", VERSION)
        .header("User-Agent", format!("StatusTick-Agent/{VERSION}"))
        .timeout(CALL_TIMEOUT);
    let response = match request.send().await {
        Ok(response) => response,
        Err(error) => {
            let (reason, refused) = call_failure(&error, &url, proxy).await;
            if let (Some(proxy), Some(status)) = (proxy, refused) {
                return (fail(name, format!("proxy {} refused the call: HTTP {status}", proxy_label(proxy)), proxy_fix(status, &host)), None);
            }
            return (fail(name, reason, "Fix the failed steps above, then run doctor again."), None);
        }
    };
    let clock = Clock {
        sent_at,
        received_at: chrono::Utc::now().timestamp_millis(),
        server_date: response.headers().get("date").and_then(|date| date.to_str().ok()).map(str::to_string),
    };
    let status = response.status();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    let code = body.get("error").and_then(Value::as_str);
    let message = |fallback: &str| body.get("message").and_then(Value::as_str).filter(|message| !message.is_empty()).unwrap_or(fallback).to_string();
    let step = if status.is_success() || code == Some("agent.unauthorized") {
        ok(name, "StatusTick accepts the token")
    } else if code == Some("token.unauthorized") {
        fail(name, "StatusTick rejected the token", "Copy the current token from the agent's page in StatusTick: this one is wrong, or its agent was removed.")
    } else if code == Some("token.rotated") {
        fail(
            name,
            message("Token rotated; set the new STATUSTICK_TOKEN"),
            "Set STATUSTICK_TOKEN to the token shown when this agent's token was rotated and restart the agent; rotate again on the agent's page if it was not saved.",
        )
    } else if code == Some("token.revoked") {
        fail(
            name,
            message("Token revoked; set a new STATUSTICK_TOKEN"),
            "Rotate the token on the agent's page in StatusTick, set the new STATUSTICK_TOKEN and restart the agent.",
        )
    } else if status.as_u16() == 426 {
        fail(name, message(&format!("agent {VERSION} is too old")), "Pull the newest agent image and start the agent again.")
    } else if status.as_u16() == 429 {
        fail(name, "too many calls (HTTP 429)", "Wait a minute and run doctor again; StatusTick limits calls per token and per IP address.")
    } else if status.as_u16() >= 500 {
        fail(name, format!("StatusTick answered HTTP {}", status.as_u16()), "Run doctor again in a few minutes.")
    } else {
        let code = code.map(|code| format!(" {code}")).unwrap_or_default();
        fail(name, format!("unexpected answer HTTP {}{code}", status.as_u16()), format!("Leave STATUSTICK_URL unset so the agent uses {DEFAULT_URL}."))
    };
    (step, Some(clock))
}

/// The browser runs set for this agent in StatusTick, read without connecting so the running agent keeps its session.
async fn dashboard_browser_runs(token: &str, base_url: &str, proxy: Option<&url::Url>) -> Option<u64> {
    let response = http_client(proxy)
        .get(format!("{base_url}/v1/settings"))
        .header("Authorization", format!("Bearer {token}"))
        .header("Agent-Version", VERSION)
        .header("User-Agent", format!("StatusTick-Agent/{VERSION}"))
        .timeout(CALL_TIMEOUT)
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.json::<Value>().await.ok()?.pointer("/settings/browserRuns")?.as_u64()
}

/// Where the browser runs the memory warnings count with came from, when the machine does not set them.
fn browser_runs_note(set_on_machine: bool, read: Option<u64>) -> Option<String> {
    match (set_on_machine, read) {
        (true, _) => None,
        (false, Some(runs)) => Some(format!("      Counted with {runs} browser {} at once, as set in StatusTick.", if runs == 1 { "run" } else { "runs" })),
        (false, None) => Some(
            "      Counted with the default of 1 browser run at once; doctor could not read the value set in StatusTick. Set BROWSER_CONCURRENCY to check another value."
                .into(),
        ),
    }
}

pub fn clock_step(clock: Option<&Clock>) -> Step {
    let name = "Clock drift";
    let server = clock
        .and_then(|clock| clock.server_date.as_deref())
        .and_then(|date| chrono::DateTime::parse_from_rfc2822(date).ok())
        .map(|date| date.timestamp_millis());
    let (Some(clock), Some(server)) = (clock, server) else { return skip(name, "needs an answer from StatusTick") };
    // The Date header has whole seconds, so the middle of that second is the best guess.
    let drift = (clock.sent_at + clock.received_at) as f64 / 2.0 - (server as f64 + 500.0);
    let detail = format!("{:.1} s {} StatusTick", drift.abs() / 1000.0, if drift >= 0.0 { "ahead of" } else { "behind" });
    if drift.abs() > MAX_CLOCK_DRIFT_MS {
        return fail(name, detail, "Sync this host's clock with NTP; the container uses the clock of the host.");
    }
    ok(name, detail)
}

/// Only with STATUSTICK_RELAY_PORT set: the port and the ping URLs jobs call.
pub fn relay_step(env: &Env) -> Option<Step> {
    let name = "Heartbeat relay";
    match read_relay_port(env) {
        Err(message) => Some(fail(name, message, "Set STATUSTICK_RELAY_PORT to a free port from 1 to 65535, or unset it to turn the relay off.")),
        Ok(None) => None,
        Ok(Some(port)) => Some(ok(
            name,
            format!(
                "port {port}; jobs call http://<agent address>:{port}/ping/<token>/start?run=<id> and then /ping/<token>?run=<id> (or /fail?run=<id>); the same run id ties a start to its finish"
            ),
        )),
    }
}

/// --target: DNS through the target rules (never around them), then connect and TLS like an HTTP check.
async fn target_steps(target: &url::Url, settings: Option<&ProxySettings>, hidden: &mut Hidden) -> Vec<Step> {
    let host = bare(target.host_str().unwrap_or(""));
    let port = default_port(target);
    let proxy = settings.and_then(|settings| proxy_for(target, settings));
    let dns_name = format!("Target DNS for {host}");
    let connect_name = format!("Target connect to {}", authority(&host, port));
    let tls_name = format!("Target TLS for {host}");
    hidden.push((host.clone(), "<target>".into()));

    let dns_started = Instant::now();
    let addresses = match resolve_allowed(&host, 0).await {
        Ok(addresses) => addresses,
        Err(failure) if failure.message == "target not allowed by agent policy" => {
            return vec![fail(
                &dns_name,
                "it is not in STATUSTICK_ALLOW",
                "Add the host or its address range to STATUSTICK_ALLOW; checks to this target fail with \"target not allowed by agent policy\".",
            )];
        }
        Err(failure) if failure.is("TARGET_NOT_ALLOWED") => {
            return vec![fail(
                &dns_name,
                "it resolves to an address the agent refuses, such as cloud metadata",
                "List the address in STATUSTICK_ALLOW only if checking it is really intended.",
            )];
        }
        Err(failure) => {
            return vec![fail(
                &dns_name,
                failure.code.unwrap_or(failure.message),
                "Make sure this host's DNS server can resolve the target, or start the container with --dns set to your internal DNS server.",
            )];
        }
    };
    hidden.extend(addresses.iter().map(|address| (address.to_string(), "<target-address>".to_string())));
    let mut steps = vec![ok(&dns_name, format!("{}, {} ms", addresses.iter().map(IpAddr::to_string).collect::<Vec<_>>().join(", "), since(dns_started)))];

    let connect_started = Instant::now();
    let mut via = addresses[0];
    let mut via_port = port;
    let opened = async {
        if let Some(proxy) = &proxy {
            let proxy_host = bare(proxy.host_str().unwrap_or(""));
            via = match proxy_host.parse::<IpAddr>() {
                Ok(address) => address,
                Err(_) => *lookup(&proxy_host, 0).await.map_err(|failure| failure.code.unwrap_or(failure.message))?.first().ok_or("ENOTFOUND")?,
            };
            via_port = default_port(proxy);
        }
        open_socket(via, via_port).await
    }
    .await;
    if proxy.is_some() {
        hidden.push((via.to_string(), "<proxy-address>".into()));
    }
    let socket = match opened {
        Ok(socket) => socket,
        Err(reason) => {
            let fix = match &proxy {
                Some(_) => format!(
                    "Check the proxy in {}, or add the target to NO_PROXY if it must be reached directly.",
                    if target.scheme() == "https" { "HTTPS_PROXY" } else { "HTTP_PROXY" }
                ),
                None => format!("Allow this host to connect to the target on port {port} in your firewall."),
            };
            steps.push(fail(&connect_name, reason, fix));
            return steps;
        }
    };
    let detail = match &proxy {
        Some(proxy) => format!("through proxy {}, {} ms", proxy_label(proxy), since(connect_started)),
        None => format!("connected to {via}, {} ms", since(connect_started)),
    };
    steps.push(ok(&connect_name, detail));
    if target.scheme() == "http" {
        steps.push(skip(&tls_name, "the target uses plain http"));
        return steps;
    }
    let fixes = Fixes {
        untrusted: "Put the CA that signed this certificate, for example your internal CA, in a PEM file and set NODE_EXTRA_CA_CERTS to it.",
        failed: "Check that the target serves HTTPS on this port.".into(),
    };
    steps.push(tls_step(&tls_name, socket, &host, addresses[0], port, proxy.as_ref(), fixes).await);
    steps
}

fn boundary(byte: Option<u8>, dot: bool) -> bool {
    byte.is_none_or(|byte| !(byte.is_ascii_alphanumeric() || byte == b'-' || (dot && byte == b'.')))
}

/// Replaces the token with its prefix, and each hidden host name or address with its label.
pub fn redact(text: &str, token: &str, hidden: &Hidden) -> String {
    let shown = if token.starts_with(TOKEN_PREFIX) { token_prefix(token) } else { "<token>".to_string() };
    let mut result = if token.len() >= MIN_REDACTED_TOKEN_LENGTH { text.replace(token, &shown) } else { text.to_string() };
    let mut sorted: Hidden = hidden.iter().filter(|(value, _)| !value.is_empty()).cloned().collect();
    sorted.sort_by_key(|(value, _)| std::cmp::Reverse(value.len()));
    for (value, label) in sorted {
        let lower = result.to_lowercase();
        let needle = value.to_lowercase();
        let mut out = String::new();
        let mut at = 0;
        while let Some(found) = lower[at..].find(&needle) {
            let start = at + found;
            let end = start + needle.len();
            let before = start.checked_sub(1).map(|index| lower.as_bytes()[index]);
            let after = lower.as_bytes().get(end).copied();
            out.push_str(&result[at..start]);
            if boundary(before, true) && boundary(after, false) {
                out.push_str(&label);
            } else {
                out.push_str(&result[start..end]);
            }
            at = end;
        }
        out.push_str(&result[at..]);
        result = out;
    }
    result
}

fn format_step(step: &Step) -> String {
    match step {
        Step::Ok(name, detail) => format!("OK    {name}: {detail}"),
        Step::Skip(name, detail) => format!("SKIP  {name}: {detail}"),
        Step::Fail(name, detail, fix) => format!("FAIL  {name}: {detail}\n      Fix: {fix}"),
    }
}

fn node_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        other => other,
    }
}

/// Runs every check in order; the text to print and whether every step passed.
const MB: i64 = 1024 * 1024;
const GB: i64 = 1024 * MB;
const AGENT_MEMORY_BYTES: i64 = 256 * MB;
const BROWSER_RUN_MEMORY_BYTES: i64 = 500 * MB;
const MIN_HEADROOM_BYTES: i64 = 512 * MB;
const MIN_SHM_BYTES: u64 = 512 * MB as u64;

/// "310 MB", "1.2 GB".
fn format_bytes(bytes: i64) -> String {
    if bytes >= GB {
        let tenths = (bytes as f64 / GB as f64 * 10.0).round() / 10.0;
        return format!("{tenths} GB");
    }
    format!("{} MB", (bytes as f64 / MB as f64).round())
}

/// The warnings the agent's page shows for too little memory or /dev/shm for its browser runs, with the same texts.
pub fn memory_warnings(memory_bytes: u64, shm_bytes: Option<u64>, browser_runs: u64) -> Vec<String> {
    if browser_runs == 0 {
        return Vec::new();
    }
    let mut warnings = Vec::new();
    let memory = memory_bytes as i64;
    let headroom = memory - AGENT_MEMORY_BYTES - BROWSER_RUN_MEMORY_BYTES * browser_runs as i64;
    if headroom < MIN_HEADROOM_BYTES {
        let fits = ((memory - AGENT_MEMORY_BYTES - MIN_HEADROOM_BYTES) as f64 / BROWSER_RUN_MEMORY_BYTES as f64).floor().max(0.0) as i64;
        let amount = if headroom < 0 { format!("about {} short", format_bytes(-headroom)) } else { format!("{} free", format_bytes(headroom)) };
        let advice =
            if fits > 0 { format!("Lower browser runs at once to {fits}.") } else { "Turn browser runs off or give the agent more memory.".to_string() };
        warnings.push(format!("Low memory: {amount}. Browser checks may fail. {advice}"));
    }
    if let Some(shm) = shm_bytes.filter(|shm| *shm < MIN_SHM_BYTES) {
        warnings.push(format!("Small /dev/shm: {}. Browser checks may crash. Give the agent 512 MB (--shm-size 512m).", format_bytes(shm as i64)));
    }
    warnings
}

pub async fn run_doctor(options: &Options, env: &Env) -> (bool, String) {
    let token = read_token(env_value(env, "STATUSTICK_TOKEN"), "STATUSTICK_TOKEN").unwrap_or_default();
    let mut hidden: Hidden = Vec::new();
    let mut steps = vec![token_step(&token)];
    let base_url = read_url(env_value(env, "STATUSTICK_URL"), "STATUSTICK_URL");
    let settings = read_proxy_settings(|name| env_value(env, name).map(str::to_string));
    let ca = read_ca_file(env_value(env, "NODE_EXTRA_CA_CERTS"), "NODE_EXTRA_CA_CERTS");
    let base = base_url.as_ref().ok().and_then(|url| url::Url::parse(url).ok());
    let proxy = match (&base, &settings) {
        (Some(base), Ok(settings)) => proxy_for(base, settings),
        _ => None,
    };
    if let Ok(settings) = &settings {
        for setting in [&settings.https, &settings.http].into_iter().flatten() {
            hidden.push((bare(setting.host_str().unwrap_or("")), "<proxy>".into()));
        }
    }
    let default_host = url::Url::parse(DEFAULT_URL).ok().and_then(|url| url.host_str().map(str::to_string)).unwrap_or_default();
    if let Some(base) = &base
        && base.host_str() != Some(default_host.as_str())
    {
        hidden.push((bare(base.host_str().unwrap_or("")), "<statustick-host>".into()));
    }
    let mut reachable = false;
    match (&base, &base_url) {
        (Some(base), _) => {
            let (reached, ok) = reach_status_tick(base, proxy.as_ref(), &mut hidden).await;
            steps.extend(reached);
            reachable = ok;
        }
        (None, Err(message)) => steps.extend([
            fail("DNS for StatusTick", message.clone(), format!("Leave STATUSTICK_URL unset so the agent uses {DEFAULT_URL}.")),
            skip("TCP 443", "needs DNS"),
            skip("TLS", "needs TCP"),
        ]),
        (None, Ok(_)) => {}
    }
    steps.push(settings_step(
        settings.as_ref().err().map(String::as_str),
        ca.as_ref().err().map(String::as_str),
        settings.as_ref().ok(),
        proxy.as_ref(),
        ca.as_ref().ok().and_then(|file| file.as_deref()),
        base.as_ref().and_then(|base| base.host_str()).unwrap_or(""),
    ));
    let base_text = base_url.clone().unwrap_or_default();
    let answers = if reachable { reachable_step(&base_text, proxy.as_ref()).await } else { skip("StatusTick answers", "needs the connection steps above") };
    let answered = matches!(answers, Step::Ok(..));
    steps.push(answers);
    let (mut accepted, clock) = if answered {
        token_accepted_step(&token, &base_text, proxy.as_ref()).await
    } else {
        (skip("Token accepted", "needs an answer from StatusTick"), None)
    };
    // The call still answers with the StatusTick time, so the clock is checked even with a malformed token.
    if !matches!(steps[0], Step::Ok(..)) {
        accepted = skip("Token accepted", "needs a token in the right format");
    }
    let token_works = matches!(accepted, Step::Ok(..));
    steps.push(accepted);
    steps.push(clock_step(clock.as_ref()));
    if let Some(relay) = relay_step(env) {
        steps.push(relay);
    }
    if let Some(target) = &options.target {
        steps.extend(target_steps(target, settings.as_ref().ok(), &mut hidden).await);
    }

    let failed = steps.iter().filter(|step| matches!(step, Step::Fail(..))).count();
    let mut lines = vec![format!("StatusTick agent {VERSION} doctor")];
    if options.report {
        let os = match std::env::consts::OS {
            "macos" => "darwin",
            other => other,
        };
        lines.push(format!("Agent {VERSION}, binary, {os}/{}, {}", node_arch(), statustick_checks::util::now_iso()));
        if !options.include_hosts {
            lines.push("Internal host names and addresses are hidden; add --include-hosts to show them.".into());
        }
    }
    lines.push(String::new());
    lines.extend(steps.iter().map(format_step));
    let machine = crate::machine::read_machine(
        None,
        env,
        &crate::machine::Probe { root: "/".into(), total_memory: crate::machine::total_memory(), parallelism: 1, started_at: String::new() },
    );
    let support = crate::browser::browser_support(env, std::path::Path::new(crate::browser::RUNNER_DIR)).ok().flatten();
    let set_on_machine = crate::settings::machine_settings(env).contains(&"BROWSER_CONCURRENCY");
    let read = if support.is_some() && !set_on_machine && token_works { dashboard_browser_runs(&token, &base_text, proxy.as_ref()).await } else { None };
    let browser_runs = support.map_or(0, |support| read.unwrap_or(support.concurrency as u64));
    let warnings = memory_warnings(machine["memoryLimitBytes"].as_u64().unwrap_or(0), machine["shmBytes"].as_u64(), browser_runs);
    lines.extend(warnings.iter().map(|warning| format!("WARN  {warning}")));
    if !warnings.is_empty() {
        lines.extend(browser_runs_note(set_on_machine, read));
    }
    lines.push(String::new());
    lines.push(if failed == 0 { "All checks passed.".into() } else { format!("{failed} {} failed.", if failed == 1 { "check" } else { "checks" }) });
    let shown = if options.report && !options.include_hosts { hidden } else { Vec::new() };
    (failed == 0, redact(&lines.join("\n"), &token, &shown))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_the_token_format_without_printing_the_token() {
        let good = format!("sta_live_{}", "a".repeat(44));
        assert_eq!(token_step(&good), ok("Token format", "sta_live_aaaaaa… (53 characters)"));
        assert!(matches!(token_step("sta_live_short"), Step::Fail(_, detail, _) if detail == "sta_live_short… has 14 characters instead of 53"));
        assert!(matches!(token_step("abc"), Step::Fail(_, detail, _) if detail == "the token does not start with sta_live_"));
        assert!(matches!(token_step(""), Step::Fail(_, detail, _) if detail == "STATUSTICK_TOKEN is not set"));
    }

    #[test]
    fn hides_tokens_hosts_and_addresses() {
        let token = format!("sta_live_{}", "b".repeat(44));
        let text = format!("token {token} proxy.corp:3128 sub.proxy.corp 10.0.0.5 10.0.0.50");
        let hidden = vec![("proxy.corp".to_string(), "<proxy>".to_string()), ("10.0.0.5".to_string(), "<proxy-address>".to_string())];
        assert_eq!(redact(&text, &token, &hidden), "token sta_live_bbbbbb… <proxy>:3128 sub.proxy.corp <proxy-address> 10.0.0.50");
    }

    #[test]
    fn warns_about_memory_and_shm_for_browser_runs() {
        const MB: u64 = 1024 * 1024;
        let enough = (256 + 2 * 500 + 512) * MB;
        assert!(memory_warnings(enough, Some(512 * MB), 2).is_empty());
        assert_eq!(memory_warnings(enough - MB, Some(512 * MB), 2), ["Low memory: 511 MB free. Browser checks may fail. Lower browser runs at once to 1."]);
        assert_eq!(
            memory_warnings(1024 * MB, Some(512 * MB), 4),
            ["Low memory: about 1.2 GB short. Browser checks may fail. Turn browser runs off or give the agent more memory."]
        );
        assert_eq!(memory_warnings(2048 * MB, None, 4), ["Low memory: about 208 MB short. Browser checks may fail. Lower browser runs at once to 2."]);
        assert_eq!(memory_warnings(enough, Some(64 * MB), 2), ["Small /dev/shm: 64 MB. Browser checks may crash. Give the agent 512 MB (--shm-size 512m)."]);
        assert!(memory_warnings(512 * MB, Some(64 * MB), 0).is_empty());
    }

    #[test]
    fn says_where_the_counted_browser_runs_came_from() {
        assert_eq!(browser_runs_note(true, None), None);
        assert_eq!(browser_runs_note(true, Some(4)), None);
        assert_eq!(browser_runs_note(false, Some(4)).unwrap(), "      Counted with 4 browser runs at once, as set in StatusTick.");
        assert_eq!(browser_runs_note(false, Some(1)).unwrap(), "      Counted with 1 browser run at once, as set in StatusTick.");
        assert!(browser_runs_note(false, None).unwrap().starts_with("      Counted with the default of 1 browser run at once;"));
    }

    /// One HTTP answer from a local listener, with the request it got.
    async fn answer_once(status: &str, body: &str) -> (String, tokio::task::JoinHandle<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let reply = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        let served = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let read = socket.read(&mut request).await.unwrap();
            socket.write_all(reply.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&request[..read]).into_owned()
        });
        (base, served)
    }

    #[tokio::test]
    async fn reads_the_browser_runs_set_in_statustick_with_the_token_only() {
        let (base, served) =
            answer_once("200 OK", r#"{"agentId":"agt_1","settings":{"browserRuns":4,"maxChecks":5,"paused":false,"shareHealth":false}}"#).await;

        assert_eq!(dashboard_browser_runs("sta_live_token", &base, None).await, Some(4));

        let request = served.await.unwrap().to_lowercase();
        assert!(request.starts_with("get /v1/settings "));
        assert!(request.contains("authorization: bearer sta_live_token"));
        assert!(request.contains(&format!("agent-version: {VERSION}")));
        assert!(!request.contains("agent-id"));
        assert!(!request.contains("agent-session"));
    }

    #[tokio::test]
    async fn reads_nothing_when_statustick_refuses() {
        let (base, _served) = answer_once("401 Unauthorized", r#"{"error":"token.revoked"}"#).await;

        assert_eq!(dashboard_browser_runs("sta_live_token", &base, None).await, None);
    }

    #[test]
    fn reads_the_options() {
        let args = |list: &[&str]| list.iter().map(|arg| arg.to_string()).collect::<Vec<_>>();
        let options = parse_args(&args(&["--target", "https://intranet.example/health", "--report"])).unwrap();
        assert_eq!(options.target.unwrap().as_str(), "https://intranet.example/health");
        assert!(options.report);
        assert_eq!(parse_args(&args(&["--target=ftp://x"])).unwrap_err(), "--target must be an http:// or https:// URL");
        assert_eq!(parse_args(&args(&["--nope"])).unwrap_err(), "Unknown option: --nope");
    }

    #[test]
    fn measures_clock_drift_from_the_date_header() {
        let clock = Clock { sent_at: 1_700_000_000_000, received_at: 1_700_000_000_200, server_date: Some("Tue, 14 Nov 2023 22:13:20 GMT".into()) };
        assert_eq!(clock_step(Some(&clock)), ok("Clock drift", "0.4 s behind StatusTick"));
        assert!(matches!(clock_step(None), Step::Skip(..)));
    }
}
