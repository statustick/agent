//! A second TLS attempt over OpenSSL, after rustls found no TLS version or cipher in common with a server: servers
//! that offer only TLS 1.0 or 1.1, or only CBC ciphers. It offers Node.js's default
//! ciphers at security level 0, from TLS 1.0 up. A weak certificate key (RSA or DSA under 2048 bits) passes only on a
//! legacy connection, flagged; a modern connection with one fails.
use std::net::IpAddr;

use hyper_util::rt::TokioIo;
use openssl::pkey::Id;
use openssl::ssl::{Ssl, SslConnector, SslMethod, SslRef, SslVerifyMode, SslVersion};
use rustls::AlertDescription;
use rustls::pki_types::CertificateDer;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;
use url::Url;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::connection::Target;
use crate::proxy::{env_settings, proxy_for};
use crate::targets::{Family, resolve_allowed};
use crate::tls::{LegacyTls, check_server_identity, verify_chain};
use crate::util::Failure;

/// Node.js's `tls.DEFAULT_CIPHERS` at OpenSSL security level 0.
const NODE_CIPHERS: &str = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:\
DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:\
!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA:@SECLEVEL=0";

const MIN_KEY_BITS: u32 = 2048;

/// The rustls error inside [error], which may sit inside further I/O errors.
fn rustls_error(error: &std::io::Error) -> Option<&rustls::Error> {
    match error.get_ref() {
        Some(inner) if inner.is::<std::io::Error>() => inner.downcast_ref::<std::io::Error>().and_then(rustls_error),
        Some(inner) => inner.downcast_ref::<rustls::Error>(),
        None => None,
    }
}

/// Whether rustls failed because the server offers no TLS version or cipher rustls supports.
pub fn mismatch(error: &std::io::Error) -> bool {
    matches!(
        rustls_error(error),
        Some(
            rustls::Error::AlertReceived(AlertDescription::HandshakeFailure | AlertDescription::ProtocolVersion | AlertDescription::InsufficientSecurity)
                | rustls::Error::PeerIncompatible(_)
        )
    )
}

/// Whether rustls could not verify the server's handshake signature, as for an RSA key under 2048 bits.
pub fn bad_signature(error: &std::io::Error) -> bool {
    matches!(rustls_error(error), Some(rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature)))
}

/// The leaf certificate's key type and size when it is RSA or DSA under 2048 bits.
fn weak_key(ssl: &SslRef) -> Option<String> {
    let key = ssl.peer_certificate()?.public_key().ok()?;
    let kind = match key.id() {
        Id::RSA | Id::RSA_PSS => "RSA",
        Id::DSA => "DSA",
        _ => return None,
    };
    (key.bits() < MIN_KEY_BITS).then(|| format!("{kind} {} bits", key.bits()))
}

/// What the connection negotiated, when it is legacy; a weak key on a modern connection fails.
fn judge(ssl: &SslRef) -> Result<Option<LegacyTls>, Failure> {
    let weak = weak_key(ssl);
    match (legacy_version(ssl), weak) {
        (None, Some(weak)) => Err(Failure::coded(format!("certificate key too weak: {weak}"), "ERR_SSL_EE_KEY_TOO_SMALL")),
        (version, weak) => Ok(version.map(|version| LegacyTls { version, weak_key: weak.is_some() })),
    }
}

/// Whether a failed HTTP request to [url] is tried once more over OpenSSL: an https target reached without a proxy
/// whose handshake failed for want of a common version or cipher.
pub fn retries(error: &reqwest::Error, url: &Url) -> bool {
    if url.scheme() != "https" || proxy_for(url, env_settings()).is_some() {
        return false;
    }
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(inner) = current {
        if inner.downcast_ref::<std::io::Error>().is_some_and(mismatch) {
            return true;
        }
        current = inner.source();
    }
    false
}

/// Whether a connection with [version] and [cipher] (OpenSSL names) is one the SSL check warns about: older than
/// TLS 1.2, or without an AEAD cipher.
pub fn is_legacy(version: &str, cipher: &str) -> bool {
    matches!(version, "TLSv1" | "TLSv1.1") || !["GCM", "CHACHA20", "CCM"].iter().any(|aead| cipher.contains(aead))
}

/// The negotiated version, when the connection is legacy.
fn legacy_version(ssl: &SslRef) -> Option<String> {
    is_legacy(ssl.version_str(), ssl.current_cipher().map(|cipher| cipher.name()).unwrap_or("")).then(|| ssl.version_str().to_string())
}

/// An OpenSSL handshake that trusts nothing yet: the caller judges the chain.
async fn handshake(host: &str, address: IpAddr, port: u16, alpn: bool) -> Option<SslStream<TcpStream>> {
    let tcp = TcpStream::connect((address, port)).await.ok()?;
    let mut builder = SslConnector::builder(SslMethod::tls_client()).ok()?;
    builder.set_min_proto_version(Some(SslVersion::TLS1)).ok()?;
    builder.set_cipher_list(NODE_CIPHERS).ok()?;
    builder.set_verify(SslVerifyMode::NONE);
    if alpn {
        builder.set_alpn_protos(b"\x08http/1.1").ok()?;
    }
    let mut configuration = builder.build().configure().ok()?;
    configuration.set_verify_hostname(false);
    let ssl: Ssl = configuration.into_ssl(host.trim_start_matches('[').trim_end_matches(']')).ok()?;
    let mut stream = SslStream::new(ssl, tcp).ok()?;
    std::pin::Pin::new(&mut stream).connect().await.ok()?;
    Some(stream)
}

fn peer_chain(ssl: &SslRef) -> Vec<CertificateDer<'static>> {
    ssl.peer_cert_chain().map(|chain| chain.iter().filter_map(|certificate| certificate.to_der().ok()).map(CertificateDer::from).collect()).unwrap_or_default()
}

/// The certificates [target] presents over OpenSSL and what a legacy connection negotiated, or the failure of a weak
/// key on a modern connection; None when the handshake fails.
pub async fn read_chain(target: &Target) -> Option<Result<(Vec<CertificateDer<'static>>, Option<LegacyTls>), Failure>> {
    let stream = handshake(&target.host, target.address, target.port, false).await?;
    Some(judge(stream.ssl()).map(|legacy| (peer_chain(stream.ssl()), legacy)))
}

/// Sends one HTTP/1.1 request to [url] over OpenSSL, verifying the server as the rustls client does.
pub async fn send(
    method: reqwest::Method,
    url: &Url,
    headers: reqwest::header::HeaderMap,
    body: Option<String>,
    family: Family,
) -> Result<reqwest::Response, Failure> {
    let failed = || Failure::new("fetch failed", None, "TypeError");
    let authority = url.host_str().unwrap_or("").to_string();
    let host = authority.trim_start_matches('[').trim_end_matches(']').to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let address = *resolve_allowed(&host, family).await?.first().ok_or_else(failed)?;
    let stream = handshake(&host, address, port, true).await.ok_or_else(failed)?;
    let chain = peer_chain(stream.ssl());
    let legacy = judge(stream.ssl()).map_err(|_| failed())?;
    let leaf = chain.first().and_then(|der| X509Certificate::from_der(der).ok().map(|(_, leaf)| leaf));
    if verify_chain(&chain).is_err() || leaf.is_none_or(|leaf| check_server_identity(&host, &leaf).is_some()) {
        return Err(failed());
    }
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.map_err(|_| failed())?;
    tokio::spawn(connection);
    let host_header = match url.port() {
        Some(port) => format!("{authority}:{port}"),
        None => authority,
    };
    let mut request = http::Request::builder()
        .method(method)
        .uri(&url[url::Position::BeforePath..url::Position::AfterQuery])
        .body(reqwest::Body::from(body.unwrap_or_default()))
        .map_err(|_| failed())?;
    *request.headers_mut() = headers;
    request.headers_mut().insert(http::header::HOST, http::HeaderValue::from_str(&host_header).map_err(|_| failed())?);
    let response = sender.send_request(request).await.map_err(|_| failed())?;
    let mut response = response.map(reqwest::Body::wrap);
    if let Some(legacy) = legacy {
        response.extensions_mut().insert(legacy);
    }
    Ok(reqwest::Response::from(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calls_old_versions_and_cbc_ciphers_legacy() {
        assert!(!is_legacy("TLSv1.3", "TLS_AES_128_GCM_SHA256"));
        assert!(!is_legacy("TLSv1.2", "ECDHE-RSA-CHACHA20-POLY1305"));
        assert!(is_legacy("TLSv1.2", "ECDHE-RSA-AES128-SHA256"));
        assert!(is_legacy("TLSv1", "ECDHE-RSA-AES128-GCM-SHA256"));
    }
}
