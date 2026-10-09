//! Sockets of the TLS certificate, gRPC, SMTP and IMAP checks: plain or TLS connections to an allowed address, a line
//! reader for the mail protocols, a deadline over the whole check, and error codes that never quote the server.
use std::collections::VecDeque;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;
use serde_json::{Map, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::tls::{client_config, node_error, server_name, version_name};
use crate::util::{Failure, connect_failure, iso};

const MAX_LINE_BYTES: usize = 4096;
const MAX_LINES: usize = 200;
const DAY_MS: f64 = 24.0 * 60.0 * 60.0 * 1000.0;

/// The target as the job names it and the address the target rules chose for it.
#[derive(Clone, Debug)]
pub struct Target {
    pub host: String,
    pub address: IpAddr,
    pub port: u16,
}

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

pub fn problem(message: impl Into<String>, code: &str) -> Failure {
    Failure::new(message, Some(code), "ProtocolProblem")
}

static TLS_CODE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(CERT_|ERR_TLS_|ERR_SSL_|UNABLE_TO_|DEPTH_ZERO_|SELF_SIGNED_|HOSTNAME_)").expect("valid pattern"));

/// The `{error, errorCode}` of a failed gRPC, SMTP or IMAP check.
pub fn failure_of(failure: &Failure) -> (String, String) {
    let code = failure.code.clone().unwrap_or_default();
    if failure.name == "ProtocolProblem" || failure.name == "TargetNotAllowed" || failure.name == "NoAddress" {
        return (failure.message.clone(), code);
    }
    if TLS_CODE.is_match(&code) {
        return (format!("TLS failed: {}", failure.message), "TLS_FAILED".to_string());
    }
    if code == "ETIMEDOUT" {
        return ("Timed out".to_string(), "TIMEOUT".to_string());
    }
    (failure.message.clone(), "CONNECT_FAILED".to_string())
}

/// Runs [work]; after [timeout] the check fails with TIMEOUT and every socket it opened is dropped.
pub async fn with_deadline<T>(timeout: Duration, work: impl Future<Output = Result<T, Failure>>) -> Result<T, Failure> {
    match tokio::time::timeout(timeout, work).await {
        Ok(result) => result,
        Err(_) => Err(problem(format!("Timed out after {} ms", timeout.as_millis()), "TIMEOUT")),
    }
}

pub async fn connect_plain(target: &Target) -> Result<TcpStream, Failure> {
    let stream = TcpStream::connect((target.address, target.port)).await.map_err(|error| connect_failure(&error, target.address, target.port))?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// A TLS handshake failure as Node.js reports it: a verification code, a closed socket, or an OpenSSL-style code.
pub fn tls_failure(error: &std::io::Error) -> Failure {
    if let Some(node) = error.get_ref().and_then(|inner| node_error(inner)) {
        return Failure::coded(node.message, &node.code);
    }
    if matches!(error.kind(), std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe) {
        return Failure::coded("Client network socket disconnected before secure TLS connection was established", "ECONNRESET");
    }
    let rustls_error = error.get_ref().and_then(|inner| inner.downcast_ref::<rustls::Error>());
    let code = match rustls_error {
        Some(rustls::Error::AlertReceived(rustls::AlertDescription::HandshakeFailure)) => "ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE",
        Some(rustls::Error::AlertReceived(rustls::AlertDescription::ProtocolVersion)) => "ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION",
        Some(rustls::Error::AlertReceived(rustls::AlertDescription::InternalError)) => "ERR_SSL_TLSV1_ALERT_INTERNAL_ERROR",
        Some(rustls::Error::AlertReceived(rustls::AlertDescription::UnrecognisedName)) => "ERR_SSL_TLSV1_UNRECOGNIZED_NAME",
        Some(rustls::Error::AlertReceived(_)) => "ERR_SSL_TLSV1_ALERT",
        Some(rustls::Error::InvalidMessage(_)) => "ERR_SSL_WRONG_VERSION_NUMBER",
        Some(rustls::Error::PeerIncompatible(_)) => "ERR_SSL_UNSUPPORTED_PROTOCOL",
        Some(_) => "ERR_SSL_PROTOCOL_ERROR",
        None => return Failure::coded(error.to_string(), &crate::util::io_code(error)),
    };
    Failure::coded(error.to_string(), code)
}

/// TLS over [stream] (a fresh connection, or the socket after STARTTLS). With [verify] the chain must lead to a
/// trusted root and the certificate must name [Target::host].
pub async fn connect_tls<S: AsyncRead + AsyncWrite + Unpin>(target: &Target, verify: bool, alpn: &[&str], stream: S) -> Result<TlsStream<S>, Failure> {
    connect_tls_io(target, verify, alpn, stream).await.map_err(|error| tls_failure(&error))
}

/// [connect_tls] with the handshake's own error.
pub async fn connect_tls_io<S: AsyncRead + AsyncWrite + Unpin>(target: &Target, verify: bool, alpn: &[&str], stream: S) -> std::io::Result<TlsStream<S>> {
    TlsConnector::from(client_config(verify, alpn)).connect(server_name(&target.host, target.address), stream).await
}

/// The TLS version and the leaf certificate's expiry of an open connection.
pub fn tls_details<S>(stream: &TlsStream<S>, details: &mut Map<String, Value>) {
    let (_, connection) = stream.get_ref();
    if let Some(version) = connection.protocol_version().and_then(version_name) {
        details.insert("tlsVersion".into(), Value::from(version));
    }
    let leaf = connection.peer_certificates().and_then(|chain| chain.first());
    if let Some(Ok((_, certificate))) = leaf.map(|der| X509Certificate::from_der(der)) {
        let valid_to = certificate.validity().not_after.timestamp();
        if let Some(time) = chrono::DateTime::from_timestamp(valid_to, 0) {
            details.insert("certificateExpiresAt".into(), Value::from(iso(time)));
            let days = ((time.timestamp_millis() - chrono::Utc::now().timestamp_millis()) as f64 / DAY_MS).floor();
            details.insert("certificateDaysLeft".into(), Value::from(days as i64));
        }
    }
}

/// CRLF lines of a text protocol, at most MAX_LINE_BYTES each and MAX_LINES per connection.
pub struct LineReader {
    stream: Pin<Box<dyn Stream>>,
    buffer: Vec<u8>,
    lines: VecDeque<String>,
    read: usize,
    failure: Option<Failure>,
}

impl LineReader {
    pub fn new(stream: Pin<Box<dyn Stream>>) -> Self {
        LineReader { stream, buffer: Vec::new(), lines: VecDeque::new(), read: 0, failure: None }
    }

    /// Something arrived after the last line read; after a STARTTLS answer it would be taken as sent over TLS.
    pub fn pending(&self) -> bool {
        !self.buffer.is_empty() || !self.lines.is_empty()
    }

    pub async fn write_line(&mut self, line: &str) -> Result<(), Failure> {
        let bytes = format!("{line}\r\n");
        self.stream
            .write_all(bytes.as_bytes())
            .await
            .map_err(|error| Failure::coded(format!("write {}", crate::util::io_code(&error)), &crate::util::io_code(&error)))
    }

    pub async fn next(&mut self) -> Result<String, Failure> {
        loop {
            if let Some(line) = self.lines.pop_front() {
                return Ok(line);
            }
            if let Some(failure) = &self.failure {
                return Err(failure.clone());
            }
            let mut chunk = [0u8; 4096];
            match self.stream.read(&mut chunk).await {
                Ok(0) => self.failure = Some(problem("The server closed the connection", "CONNECT_FAILED")),
                Ok(length) => self.take(&chunk[..length]),
                Err(error) => {
                    let code = crate::util::io_code(&error);
                    self.failure = Some(Failure::coded(format!("read {code}"), &code));
                }
            }
        }
    }

    fn take(&mut self, chunk: &[u8]) {
        self.buffer.extend_from_slice(chunk);
        while let Some(end) = self.buffer.iter().position(|byte| *byte == b'\n') {
            let mut line: Vec<u8> = self.buffer.drain(..=end).collect();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            self.read += 1;
            if self.read > MAX_LINES {
                self.failure = Some(problem(format!("The server sent more than {MAX_LINES} lines"), "INVALID_ANSWER"));
                self.buffer.clear();
                return;
            }
            self.lines.push_back(line.iter().map(|byte| *byte as char).collect());
        }
        if self.buffer.len() > MAX_LINE_BYTES {
            self.failure = Some(problem(format!("The server sent a line longer than {MAX_LINE_BYTES} bytes"), "INVALID_ANSWER"));
        }
    }

    /// Gives the socket back so TLS can take it over.
    pub fn into_inner(self) -> Pin<Box<dyn Stream>> {
        self.stream
    }
}
