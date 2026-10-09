//! Local servers the engine tests check: HTTP and HTTPS (also with CBC ciphers only, TLS 1.0 or 1.1 only and a weak
//! key), plain TCP, TLS with good and bad certificates, gRPC health over h2c and TLS, SMTP and IMAP with STARTTLS, MCP
//! over Streamable HTTP, and a proxy that refuses. All listen on `::` with IPv4 mapped, so `localhost` answers on ::1
//! and 127.0.0.1. The certificates' CA is trusted through `NODE_EXTRA_CA_CERTS`.
#![allow(dead_code)]

use std::collections::HashMap;
use std::convert::Infallible;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::ssl::{AlpnError, Ssl, SslAcceptor, SslMethod, SslOptions, SslVersion};
use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName, SubjectKeyIdentifier};
use openssl::x509::{X509, X509NameBuilder};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub struct Ports {
    pub http: u16,
    pub https: u16,
    pub https_cbc: u16,
    pub https_tls10: u16,
    pub https_tls11: u16,
    pub https_weak_key: u16,
    pub https_weak_key_tls10: u16,
    pub closed: u16,
    pub tls: HashMap<&'static str, u16>,
    pub grpc: u16,
    pub grpc_tls: u16,
    pub smtp: u16,
    pub smtp_no_tls: u16,
    pub smtp_554: u16,
    pub smtp_inject: u16,
    pub smtps: u16,
    pub imap: u16,
    pub imap_no_caps: u16,
    pub imap_bye: u16,
    pub mcp: u16,
    pub proxy: u16,
}

pub struct Fixtures {
    pub ports: Ports,
    pub dir: PathBuf,
}

static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("runtime"));
static HTTP_PORT: OnceLock<u16> = OnceLock::new();

/// Starts every fixture once per test binary; [proxy] also points the engine at the refusing proxy.
pub fn fixtures(proxy: bool) -> &'static Fixtures {
    static FIXTURES: OnceLock<Fixtures> = OnceLock::new();
    FIXTURES.get_or_init(|| start(proxy))
}

/// Runs one check (or `multi`, `{"checks": [...]}`) on the shared runtime.
pub fn check(kind: &str, request: Value) -> Value {
    let request = request.as_object().cloned().unwrap_or_default();
    RUNTIME.block_on(async move {
        if kind == "multi" {
            let checks = request.get("checks").and_then(Value::as_array).cloned().unwrap_or_default();
            let (results, _) = statustick_checks::multi::multi_check(&checks, true).await;
            json!({ "results": results })
        } else {
            statustick_checks::run_check(kind, &request).await.expect("known check type")
        }
    })
}

/// The value at [path], such as `details.tlsVersion` or `results[4].status`; Null when missing.
pub fn at(value: &Value, path: &str) -> Value {
    path.split(['.', '[', ']']).filter(|key| !key.is_empty()).fold(value.clone(), |current, key| match key.parse::<usize>() {
        Ok(index) if current.is_array() => current.get(index).cloned().unwrap_or(Value::Null),
        _ => current.get(key).cloned().unwrap_or(Value::Null),
    })
}

/// One check: its name, type, request and the values expected at paths of its result.
pub type Case<'a> = (&'a str, &'a str, Value, Vec<(&'a str, Value)>);

/// Checks each case and fails once with every mismatch. `ENGINE_DUMP=1` prints each result.
pub fn expect_all(cases: Vec<Case>) {
    let mut failures = Vec::new();
    for (name, kind, request, expected) in cases {
        let result = check(kind, request);
        if std::env::var_os("ENGINE_DUMP").is_some() {
            println!("{name}: {result}");
        }
        for (path, value) in expected {
            let found = at(&result, path);
            if found != value {
                failures.push(format!("{name}: {path} is {found}, expected {value}"));
            }
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

fn start(proxy: bool) -> Fixtures {
    let dir = std::env::temp_dir().join(format!("checks-engine-{}-{}", std::process::id(), rand::random::<u32>()));
    std::fs::create_dir_all(&dir).expect("certificate dir");
    let certificates = make_certificates();
    std::fs::write(dir.join("ca.pem"), certificates["ca"].cert.to_pem().expect("pem")).expect("ca.pem");
    // SAFETY: set once, before any check reads the environment.
    unsafe {
        std::env::set_var("NODE_EXTRA_CA_CERTS", dir.join("ca.pem"));
    }
    let (hosts, _) = statustick_checks::targets::parse_allowed_internal_hosts("localhost");
    statustick_checks::targets::set_allowed_internal_hosts(hosts);

    let _guard = RUNTIME.enter();
    let pair = |name: &str| &certificates[name];
    let http = listen(|stream, _| serve_http(Box::new(stream)));
    HTTP_PORT.set(http).expect("http port");
    let https = |profile: Profile, name: &str| {
        let acceptor = acceptor(pair(name), profile, false);
        listen(move |stream, _| {
            let acceptor = acceptor.clone();
            async move {
                if let Some(stream) = accept(&acceptor, Box::new(stream)).await {
                    serve_http(Box::new(stream)).await;
                }
            }
        })
    };
    let mut tls = HashMap::new();
    for name in ["localhost", "expired", "other-host", "unknown-ca", "self-signed"] {
        let acceptor = acceptor(pair(name), Profile::Modern, false);
        tls.insert(
            name,
            listen(move |stream, _| {
                let acceptor = acceptor.clone();
                async move {
                    if let Some(mut stream) = accept(&acceptor, Box::new(stream)).await {
                        let _ = stream.shutdown().await;
                    }
                }
            }),
        );
    }
    tls.insert(
        "plain",
        listen(|mut stream, _| async move {
            let _ = stream.write_all(b"SSH-2.0-OpenSSH_9.0\r\n").await;
            let _ = stream.shutdown().await;
        }),
    );
    let grpc_acceptor = acceptor(pair("localhost"), Profile::Modern, true);
    let mail_acceptor = acceptor(pair("localhost"), Profile::Modern, false);
    let mail = |script: Mail, implicit: bool| {
        let acceptor = mail_acceptor.clone();
        listen(move |stream, _| {
            let acceptor = acceptor.clone();
            async move {
                let stream: Box<dyn Io> = Box::new(stream);
                let stream: Box<dyn Io> = if implicit {
                    match accept(&acceptor, stream).await {
                        Some(secure) => Box::new(secure),
                        None => return,
                    }
                } else {
                    stream
                };
                serve_mail(stream, script, acceptor).await;
            }
        })
    };
    let ports = Ports {
        http,
        https: https(Profile::Modern, "localhost"),
        https_cbc: https(Profile::Cbc, "localhost"),
        https_tls10: https(Profile::Tls10, "localhost"),
        https_tls11: https(Profile::Tls11, "localhost"),
        https_weak_key: https(Profile::Weak, "weak-key"),
        https_weak_key_tls10: https(Profile::Tls10, "weak-key"),
        closed: {
            let listener = std::net::TcpListener::bind("[::]:0").expect("bind");
            listener.local_addr().expect("address").port()
        },
        tls,
        grpc: listen(|stream, _| serve_grpc(Box::new(stream))),
        grpc_tls: listen(move |stream, _| {
            let acceptor = grpc_acceptor.clone();
            async move {
                if let Some(stream) = accept(&acceptor, Box::new(stream)).await {
                    serve_grpc(Box::new(stream)).await;
                }
            }
        }),
        smtp: mail(Mail { greeting: "220 parity ESMTP\r\n", starttls: true, inject: false, imap: false }, false),
        smtp_no_tls: mail(Mail { greeting: "220 parity ESMTP\r\n", starttls: false, inject: false, imap: false }, false),
        smtp_554: mail(Mail { greeting: "554 go away secret-text\r\n", starttls: false, inject: false, imap: false }, false),
        smtp_inject: mail(Mail { greeting: "220 parity ESMTP\r\n", starttls: true, inject: true, imap: false }, false),
        smtps: mail(Mail { greeting: "220 parity ESMTP\r\n", starttls: false, inject: false, imap: false }, true),
        imap: mail(Mail { greeting: "* OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN] ready\r\n", starttls: true, inject: false, imap: true }, false),
        imap_no_caps: mail(Mail { greeting: "* OK ready\r\n", starttls: true, inject: false, imap: true }, false),
        imap_bye: mail(Mail { greeting: "* BYE overloaded\r\n", starttls: false, inject: false, imap: true }, false),
        mcp: listen(|stream, _| serve_mcp(Box::new(stream))),
        proxy: listen(|stream, _| serve_refusing_proxy(stream)),
    };
    if proxy {
        let url = format!("http://127.0.0.1:{}", ports.proxy);
        // SAFETY: set once, before any check reads the environment.
        unsafe {
            for name in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
                std::env::set_var(name, &url);
            }
            std::env::set_var("NO_PROXY", "");
            std::env::set_var("no_proxy", "");
        }
    }
    Fixtures { ports, dir }
}

/// A dual-stack listener on `::` that hands every connection to [serve].
fn listen<F, Fut>(serve: F) -> u16
where
    F: Fn(TcpStream, u16) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, None).expect("socket");
    socket.set_only_v6(false).expect("dual stack");
    socket.set_reuse_address(true).expect("reuse");
    socket.bind(&"[::]:0".parse::<std::net::SocketAddr>().expect("address").into()).expect("bind");
    socket.listen(128).expect("listen");
    socket.set_nonblocking(true).expect("nonblocking");
    let listener = TcpListener::from_std(socket.into()).expect("listener");
    let port = listener.local_addr().expect("address").port();
    let serve = Arc::new(serve);
    RUNTIME.spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(serve(stream, port));
        }
    });
    port
}

// Certificates.

pub struct Pair {
    pub cert: X509,
    pub key: PKey<Private>,
    pub chain: Vec<X509>,
}

struct Leaf {
    name: &'static str,
    issuer: Option<&'static str>,
    hosts: &'static [&'static str],
    validity: Option<(&'static str, &'static str)>,
    bits: u32,
}

const LEAVES: [Leaf; 6] = [
    Leaf {
        name: "localhost",
        issuer: Some("ca"),
        hosts: &["DNS:localhost", "IP:127.0.0.1", "IP:::1"],
        validity: Some(("20250101000000Z", "20991231000000Z")),
        bits: 2048,
    },
    Leaf {
        name: "weak-key",
        issuer: Some("ca"),
        hosts: &["DNS:localhost", "IP:127.0.0.1", "IP:::1"],
        validity: Some(("20250101000000Z", "20991231000000Z")),
        bits: 1024,
    },
    Leaf { name: "expired", issuer: Some("ca"), hosts: &["DNS:localhost"], validity: Some(("20200101000000Z", "20200201000000Z")), bits: 2048 },
    Leaf {
        name: "other-host",
        issuer: Some("ca"),
        hosts: &["DNS:other.test", "DNS:*.other.test"],
        validity: Some(("20250101000000Z", "20991231000000Z")),
        bits: 2048,
    },
    Leaf { name: "unknown-ca", issuer: Some("unknown"), hosts: &["DNS:localhost"], validity: Some(("20250101000000Z", "20991231000000Z")), bits: 2048 },
    Leaf { name: "self-signed", issuer: None, hosts: &["DNS:localhost"], validity: None, bits: 2048 },
];

fn rsa_key(bits: u32) -> PKey<Private> {
    PKey::from_rsa(Rsa::generate(bits).expect("rsa")).expect("key")
}

fn certificate(subject: &[(&str, &str)], key: &PKey<Private>, issuer: Option<&Pair>, validity: Option<(&str, &str)>, ca: bool, hosts: &[&str]) -> X509 {
    static SERIAL: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1000);
    let mut name = X509NameBuilder::new().expect("name");
    for (field, value) in subject {
        name.append_entry_by_text(field, value).expect("name entry");
    }
    let name = name.build();
    let mut builder = X509::builder().expect("builder");
    builder.set_version(2).expect("version");
    let serial = BigNum::from_u32(SERIAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed)).expect("serial");
    builder.set_serial_number(&Asn1Integer::from_bn(&serial).expect("serial")).expect("serial");
    builder.set_subject_name(&name).expect("subject");
    builder.set_issuer_name(issuer.map(|issuer| issuer.cert.subject_name()).unwrap_or(&name)).expect("issuer");
    builder.set_pubkey(key).expect("public key");
    let (start, end) = match validity {
        Some((start, end)) => (Asn1Time::from_str(start).expect("start"), Asn1Time::from_str(end).expect("end")),
        None => (Asn1Time::days_from_now(0).expect("start"), Asn1Time::days_from_now(3650).expect("end")),
    };
    builder.set_not_before(&start).expect("not before");
    builder.set_not_after(&end).expect("not after");
    if ca {
        builder.append_extension(BasicConstraints::new().critical().ca().build().expect("constraints")).expect("extension");
        builder.append_extension(KeyUsage::new().critical().key_cert_sign().crl_sign().build().expect("usage")).expect("extension");
        let identifier = SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None)).expect("identifier");
        builder.append_extension(identifier).expect("extension");
    } else {
        builder.append_extension(BasicConstraints::new().critical().build().expect("constraints")).expect("extension");
        builder.append_extension(KeyUsage::new().critical().digital_signature().key_encipherment().build().expect("usage")).expect("extension");
        builder.append_extension(ExtendedKeyUsage::new().server_auth().build().expect("extended usage")).expect("extension");
        let mut names = SubjectAlternativeName::new();
        for host in hosts {
            match host.split_once(':') {
                Some(("DNS", value)) => names.dns(value),
                Some(("IP", value)) => names.ip(value),
                _ => unreachable!("host kind"),
            };
        }
        let names = names.build(&builder.x509v3_context(issuer.map(|issuer| issuer.cert.as_ref()), None)).expect("names");
        builder.append_extension(names).expect("extension");
    }
    builder.sign(issuer.map(|issuer| &issuer.key).unwrap_or(key), MessageDigest::sha256()).expect("sign");
    builder.build()
}

/// A trusted CA, leaves it signed for localhost (valid, expired, for another host, with a weak 1024-bit key), a
/// self-signed leaf and a leaf of a CA nobody trusts, sent with that CA.
fn make_certificates() -> HashMap<&'static str, Pair> {
    let mut pairs = HashMap::new();
    for (name, subject) in [("ca", [("CN", "Parity Test CA"), ("O", "StatusTick Parity")]), ("unknown", [("CN", "Unknown Test CA"), ("O", "Nobody")])] {
        let key = rsa_key(2048);
        let cert = certificate(&subject, &key, None, None, true, &[]);
        pairs.insert(name, Pair { cert, key, chain: Vec::new() });
    }
    for leaf in LEAVES {
        let key = rsa_key(leaf.bits);
        let common_name = leaf.hosts[0].trim_start_matches("DNS:");
        let issuer = leaf.issuer.map(|issuer| &pairs[issuer]);
        let cert = certificate(&[("CN", common_name)], &key, issuer, leaf.validity, false, leaf.hosts);
        let chain = if leaf.issuer == Some("unknown") { vec![pairs["unknown"].cert.clone()] } else { Vec::new() };
        pairs.insert(leaf.name, Pair { cert, key, chain });
    }
    pairs
}

// TLS.

#[derive(Clone, Copy)]
enum Profile {
    Modern,
    Cbc,
    Tls10,
    Tls11,
    Weak,
}

fn acceptor(pair: &Pair, profile: Profile, h2: bool) -> Arc<SslAcceptor> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).expect("acceptor");
    builder.set_security_level(0);
    match profile {
        Profile::Modern => {}
        Profile::Cbc => {
            builder.set_min_proto_version(Some(SslVersion::TLS1_2)).expect("min");
            builder.set_max_proto_version(Some(SslVersion::TLS1_2)).expect("max");
            builder.set_cipher_list("ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES128-SHA").expect("ciphers");
        }
        Profile::Tls10 | Profile::Tls11 => {
            let version = if matches!(profile, Profile::Tls10) { SslVersion::TLS1 } else { SslVersion::TLS1_1 };
            builder.clear_options(SslOptions::NO_TLSV1 | SslOptions::NO_TLSV1_1);
            builder.set_min_proto_version(Some(version)).expect("min");
            builder.set_max_proto_version(Some(version)).expect("max");
            builder.set_cipher_list("DEFAULT@SECLEVEL=0").expect("ciphers");
        }
        Profile::Weak => builder.set_cipher_list("DEFAULT@SECLEVEL=0").expect("ciphers"),
    }
    builder.set_private_key(&pair.key).expect("key");
    builder.set_certificate(&pair.cert).expect("certificate");
    for extra in &pair.chain {
        builder.add_extra_chain_cert(extra.clone()).expect("chain");
    }
    if h2 {
        builder.set_alpn_select_callback(|_, offered| openssl::ssl::select_next_proto(b"\x02h2", offered).ok_or(AlpnError::NOACK));
    }
    Arc::new(builder.build())
}

async fn accept(acceptor: &SslAcceptor, stream: Box<dyn Io>) -> Option<tokio_openssl::SslStream<Box<dyn Io>>> {
    let ssl = Ssl::new(acceptor.context()).ok()?;
    let mut stream = tokio_openssl::SslStream::new(ssl, stream).ok()?;
    Pin::new(&mut stream).accept().await.ok()?;
    Some(stream)
}

// HTTP.

const SEEN: [&str; 7] = ["content-type", "user-agent", "accept", "accept-encoding", "accept-language", "sec-fetch-mode", "x-custom"];
const BROTLI_HELLO: [u8; 16] = [139, 5, 128, 98, 114, 111, 116, 108, 105, 32, 104, 101, 108, 108, 111, 3];

async fn serve_http(stream: Box<dyn Io>) {
    let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), service_fn(http_answer)).await;
}

async fn http_answer(request: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let port = *HTTP_PORT.get().expect("http port");
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let mut seen: Vec<(String, String)> = Vec::new();
    for name in SEEN {
        let value = request.headers().get_all(name).iter().filter_map(|value| value.to_str().ok()).collect::<Vec<_>>().join(", ");
        seen.push((format!("x-seen-{name}"), value));
    }
    let body = request.into_body().collect().await.map(|body| body.to_bytes()).unwrap_or_default();
    seen.push(("x-seen-method".into(), method.clone()));
    seen.push(("x-seen-body-length".into(), body.len().to_string()));
    let send = |status: u16, body: Vec<u8>, headers: &[(&str, &str)]| {
        let mut response = Response::builder().status(StatusCode::from_u16(status).expect("status"));
        if !headers.iter().any(|(name, _)| *name == "content-type") {
            response = response.header("content-type", "text/plain");
        }
        for (name, value) in &seen {
            response = response.header(name.as_str(), value.as_str());
        }
        for (name, value) in headers {
            response = response.header(*name, *value);
        }
        Ok(response.body(Full::new(Bytes::from(if method == "HEAD" { Vec::new() } else { body }))).expect("response"))
    };
    if let Some(code) = path.strip_prefix("/status/").and_then(|code| code.parse::<u16>().ok()) {
        let location: &[(&str, &str)] = if (300..400).contains(&code) { &[("location", "/ok")] } else { &[] };
        return send(code, b"status".to_vec(), location);
    }
    let internal = format!("http://127.0.0.1:{port}/ok");
    match path.as_str() {
        "/ok" => send(200, b"hello world".to_vec(), &[("set-cookie", "session=secret"), ("set-cookie", "other=1"), ("vary", "accept"), ("vary", "origin")]),
        "/json" => send(200, br#"{"status":"ok","count":1,"items":[{"id":7,"done":true,"note":null}]}"#.to_vec(), &[("content-type", "application/json")]),
        "/blocked" => send(403, b"<html><script>window._cf_chl_opt={}</script></html>".to_vec(), &[("content-type", "text/html")]),
        "/forbidden" => send(403, b"Forbidden".to_vec(), &[]),
        "/redirect" => send(302, Vec::new(), &[("location", "/ok")]),
        "/redirect303" => send(303, Vec::new(), &[("location", "/ok")]),
        "/redirect-internal" => send(302, Vec::new(), &[("location", internal.as_str())]),
        "/redirect-loop" => send(302, Vec::new(), &[("location", "/redirect-loop")]),
        "/gzip" => {
            use std::io::Write;
            let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(b"compressed hello").expect("gzip");
            send(200, encoder.finish().expect("gzip"), &[("content-encoding", "gzip")])
        }
        "/brotli" => send(200, BROTLI_HELLO.to_vec(), &[("content-encoding", "br")]),
        "/slow" => {
            tokio::time::sleep(Duration::from_secs(2)).await;
            send(200, b"late".to_vec(), &[])
        }
        "/nocontent" => send(204, Vec::new(), &[]),
        "/utf8" => send(200, "\u{feff}naïve café".as_bytes().to_vec(), &[("content-type", "text/plain; charset=utf-8")]),
        "/big" => {
            let mut body = vec![b'a'; 6 * 1024 * 1024];
            body.extend_from_slice(b"needle");
            send(200, body, &[])
        }
        "/html" => {
            let html = format!(
                r#"<html><head><link rel="stylesheet" href="/head405.css"><script src="/missing.js"></script></head><body><img src="/ok"><img src="http://127.0.0.1:{port}/x.png"></body></html>"#
            );
            send(200, html.into_bytes(), &[("content-type", "text/html; charset=utf-8")])
        }
        "/missing.js" => send(404, b"missing".to_vec(), &[]),
        "/head405.css" if method == "HEAD" => send(405, Vec::new(), &[]),
        "/head405.css" => send(200, b"body{}".to_vec(), &[("content-type", "text/css")]),
        _ => send(404, b"not found".to_vec(), &[]),
    }
}

// gRPC health.

fn health_answer(status: u8) -> Bytes {
    let message: Vec<u8> = if status == 0 { Vec::new() } else { vec![0x08, status] };
    let mut frame = vec![0u8, 0, 0, 0, message.len() as u8];
    frame.extend(message);
    Bytes::from(frame)
}

fn service_of(body: &[u8]) -> String {
    if body.len() <= 5 || body[5] != 0x0a {
        return String::new();
    }
    let length = body[6] as usize;
    String::from_utf8_lossy(&body[7..(7 + length).min(body.len())]).to_string()
}

async fn serve_grpc(stream: Box<dyn Io>) {
    let Ok(mut connection) = h2::server::handshake(stream).await else { return };
    while let Some(Ok((request, mut respond))) = connection.accept().await {
        tokio::spawn(async move {
            let path = request.uri().path().to_string();
            let mut body = request.into_body();
            let mut data = Vec::new();
            while let Some(Ok(chunk)) = body.data().await {
                let _ = body.flow_control().release_capacity(chunk.len());
                data.extend_from_slice(&chunk);
            }
            if path != "/grpc.health.v1.Health/Check" {
                let _ = respond.send_response(http::Response::builder().status(404).body(()).expect("response"), true);
                return;
            }
            let grpc = |status: &str, message: Option<&str>| {
                let mut response = http::Response::builder().status(200).header("content-type", "application/grpc").header("grpc-status", status);
                if let Some(message) = message {
                    response = response.header("grpc-message", message);
                }
                response.body(()).expect("response")
            };
            match service_of(&data).as_str() {
                "unknown" => {
                    let _ = respond.send_response(grpc("5", Some("unknown service secret-text")), true);
                }
                "unimplemented" => {
                    let _ = respond.send_response(grpc("12", None), true);
                }
                service => {
                    let response = http::Response::builder().status(200).header("content-type", "application/grpc").body(()).expect("response");
                    let Ok(mut send) = respond.send_response(response, false) else { return };
                    let _ = send.send_data(health_answer(if service == "down" { 2 } else { 1 }), false);
                    let mut trailers = http::HeaderMap::new();
                    trailers.insert("grpc-status", "0".parse().expect("header"));
                    let _ = send.send_trailers(trailers);
                }
            }
        });
    }
}

// SMTP and IMAP.

#[derive(Clone, Copy)]
struct Mail {
    greeting: &'static str,
    starttls: bool,
    inject: bool,
    imap: bool,
}

enum Step {
    Write(String),
    Upgrade(String),
    Close(String),
}

fn mail_answer(script: Mail, line: &str) -> Step {
    if script.imap {
        let mut parts = line.split(' ');
        let tag = parts.next().unwrap_or("");
        let command = parts.next().unwrap_or("").to_ascii_uppercase();
        return match command.as_str() {
            "CAPABILITY" => Step::Write(format!("* CAPABILITY IMAP4rev1{}\r\n{tag} OK done\r\n", if script.starttls { " STARTTLS" } else { "" })),
            "STARTTLS" => Step::Upgrade(format!("{tag} OK Begin TLS\r\n")),
            "LOGOUT" => Step::Close(format!("* BYE\r\n{tag} OK LOGOUT\r\n")),
            _ => Step::Write(format!("{tag} BAD unknown\r\n")),
        };
    }
    let upper = line.to_ascii_uppercase();
    if upper.starts_with("EHLO ") {
        return Step::Write(format!("250-parity\r\n250-PIPELINING\r\n{}250 8BITMIME\r\n", if script.starttls { "250-STARTTLS\r\n" } else { "" }));
    }
    match upper.as_str() {
        "STARTTLS" => Step::Upgrade(if script.inject { "220 Ready\r\n250 injected\r\n" } else { "220 Ready\r\n" }.to_string()),
        "QUIT" => Step::Close("221 bye\r\n".to_string()),
        _ => Step::Write("500 unknown\r\n".to_string()),
    }
}

async fn serve_mail(mut stream: Box<dyn Io>, script: Mail, acceptor: Arc<SslAcceptor>) {
    if stream.write_all(script.greeting.as_bytes()).await.is_err() {
        return;
    }
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let Ok(read) = stream.read(&mut chunk).await else { return };
        if read == 0 {
            return;
        }
        buffer.extend_from_slice(&chunk[..read]);
        while let Some(end) = buffer.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = buffer.drain(..=end).collect();
            let line = String::from_utf8_lossy(&line).trim_end_matches(['\r', '\n']).to_string();
            match mail_answer(script, &line) {
                Step::Write(text) => {
                    if stream.write_all(text.as_bytes()).await.is_err() {
                        return;
                    }
                }
                Step::Close(text) => {
                    let _ = stream.write_all(text.as_bytes()).await;
                    let _ = stream.shutdown().await;
                    return;
                }
                Step::Upgrade(text) => {
                    if stream.write_all(text.as_bytes()).await.is_err() || stream.flush().await.is_err() {
                        return;
                    }
                    buffer.clear();
                    match accept(&acceptor, stream).await {
                        Some(secure) => stream = Box::new(secure),
                        None => return,
                    }
                }
            }
        }
    }
}

// MCP.

fn tools() -> Value {
    json!([
        { "name": "search", "description": "secret description", "inputSchema": { "type": "object", "properties": { "query": { "type": "string" }, "limit": { "type": "number", "default": 10 } }, "required": ["query"] } },
        { "name": "fetch", "inputSchema": { "type": "object" } },
        { "name": "ünïcode", "inputSchema": { "type": "object", "properties": { "b": { "type": "boolean" }, "a": { "type": "array", "items": { "type": "integer" } } } } }
    ])
}

async fn serve_mcp(stream: Box<dyn Io>) {
    let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), service_fn(mcp_answer)).await;
}

fn plain(status: u16, body: &str) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::builder().status(status).body(Full::new(Bytes::from(body.to_string()))).expect("response"))
}

/// The path picks the behaviour, e.g. `/mcp`, `/mcp-sse`, `/mcp-401`.
async fn mcp_answer(request: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let kind = request.uri().path().trim_start_matches('/').to_string();
    let method = request.method().clone();
    let key = request.headers().get("x-key").and_then(|value| value.to_str().ok()).map(str::to_string);
    let body = request.into_body().collect().await.map(|body| body.to_bytes()).unwrap_or_default();
    if method == hyper::Method::DELETE {
        return plain(200, "");
    }
    if method != hyper::Method::POST {
        return plain(405, "");
    }
    if kind == "mcp-401" || (kind == "mcp-auth" && key.as_deref() != Some("secret")) {
        return plain(401, "no secret-text");
    }
    if kind == "mcp-redirect" {
        return Ok(Response::builder().status(302).header("location", "/mcp").body(Full::new(Bytes::new())).expect("response"));
    }
    let message: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let Some(id) = message.get("id").cloned() else { return plain(202, "") };
    let rpc = message.get("method").and_then(Value::as_str).unwrap_or("");
    let reply = |result: Option<Value>| {
        let body = match result {
            Some(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            None => json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32603, "message": "secret-text" } }),
        }
        .to_string();
        let mut response = Response::builder().status(200);
        if rpc == "initialize" {
            response = response.header("mcp-session-id", "session-1");
        }
        let (content_type, body) =
            if kind == "mcp-sse" { ("text/event-stream", format!("event: message\ndata: {body}\n\n")) } else { ("application/json", body) };
        Ok(response.header("content-type", content_type).body(Full::new(Bytes::from(body))).expect("response"))
    };
    match rpc {
        "initialize" => match kind.as_str() {
            "mcp-500" => plain(500, "secret-text"),
            "mcp-rpc-error" => reply(None),
            "mcp-invalid" => reply(Some(json!({ "protocolVersion": "2025-06-18", "capabilities": {} }))),
            "mcp-old-version" => reply(Some(json!({ "protocolVersion": "1999-01-01", "capabilities": {}, "serverInfo": { "name": "old", "version": "0" } }))),
            _ => reply(Some(
                json!({ "protocolVersion": "2025-06-18", "capabilities": { "tools": {} }, "serverInfo": { "name": format!("parity-server-{}", "x".repeat(120)), "version": "1.2.3" } }),
            )),
        },
        "tools/list" => {
            let tools = tools();
            let list = tools.as_array().expect("tools");
            match kind.as_str() {
                "mcp-tools-fail" => plain(500, "secret-text"),
                "mcp-empty" => reply(Some(json!({ "tools": [] }))),
                "mcp-loop" => reply(Some(json!({ "tools": [list[0]], "nextCursor": "same" }))),
                _ if message.pointer("/params/cursor").and_then(Value::as_str) == Some("page-2") => reply(Some(json!({ "tools": [list[2]] }))),
                _ => reply(Some(json!({ "tools": [list[0], list[1]], "nextCursor": "page-2" }))),
            }
        }
        _ => reply(None),
    }
}

// A proxy that refuses every request with the status in the target's port: 1403 is 403, 1407 asks for credentials.

fn reason(status: u16) -> &'static str {
    match status {
        403 => "Forbidden",
        407 => "Proxy Authentication Required",
        502 => "Bad Gateway",
        _ => "Refused",
    }
}

async fn serve_refusing_proxy(mut stream: TcpStream) {
    let mut head = Vec::new();
    let mut chunk = [0u8; 4096];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => head.extend_from_slice(&chunk[..read]),
        }
    }
    let text = String::from_utf8_lossy(&head);
    let mut parts = text.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let port = if method == "CONNECT" {
        target.rsplit(':').next().unwrap_or("")
    } else {
        target.split("://").nth(1).and_then(|rest| rest.split('/').next()).and_then(|host| host.rsplit(':').next()).unwrap_or("")
    };
    let status = port.parse::<u16>().unwrap_or(1502).saturating_sub(1000);
    let answer = if method == "CONNECT" {
        format!("HTTP/1.1 {status} {}\r\n\r\n", reason(status))
    } else {
        let body = "refused by the proxy";
        format!("HTTP/1.1 {status} {}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", reason(status), body.len())
    };
    let _ = stream.write_all(answer.as_bytes()).await;
    let _ = stream.shutdown().await;
}
