//! TLS certificate checks: read the chain without trusting it, then judge it (expiry,
//! host name, trust), and optionally probe which TLS versions the server accepts.
use std::net::IpAddr;
use std::time::{Duration, Instant};

use rustls::pki_types::CertificateDer;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::connection::{Target, connect_tls_io, tls_failure};
use crate::targets::resolve_allowed;
use crate::tls::{check_server_identity, common_names, name_attribute, organizations, peer_chain, verify_chain};
use crate::util::{Failure, connect_failure, elapsed_ms, iso, now_iso, number_field, timeout_field, truthy};

const DAY_MS: f64 = 24.0 * 60.0 * 60.0 * 1000.0;
const MAX_CHAIN: usize = 10;
/// The TLS versions a client can ask for, oldest first.
pub const TLS_VERSIONS: [(&str, u16); 4] = [("TLSv1", 0x0301), ("TLSv1.1", 0x0302), ("TLSv1.2", 0x0303), ("TLSv1.3", 0x0304)];

/// The certificates a server presented, whether the chain is trusted, and why not.
pub struct PeerCertificates {
    pub chain: Vec<CertificateDer<'static>>,
    pub authorization_error: Option<String>,
    /// Set when read over TLS older than 1.2 or without an AEAD cipher: the negotiated version.
    pub legacy_tls: Option<crate::tls::LegacyTls>,
}

fn issuer_name(name: &x509_parser::x509::X509Name<'_>) -> Value {
    name_attribute(organizations(name)).or_else(|| name_attribute(common_names(name))).unwrap_or(Value::Null)
}

fn time_of(time: x509_parser::time::ASN1Time) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(time.timestamp(), 0).unwrap_or_default()
}

/// The fields the platform stores for a certificate, with the first problem found.
pub fn describe_certificate(peer: &PeerCertificates, host: &str, now: chrono::DateTime<chrono::Utc>) -> Result<Value, Failure> {
    let leaf_der = peer.chain.first().ok_or_else(|| Failure::plain("The server sent no certificate"))?;
    let (_, leaf) = X509Certificate::from_der(leaf_der).map_err(|_| Failure::plain("The server sent no certificate"))?;
    let valid_from = time_of(leaf.validity().not_before);
    let valid_to = time_of(leaf.validity().not_after);
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let hostname_error = if bare.parse::<IpAddr>().is_ok() { None } else { check_server_identity(bare, &leaf) };
    let error = if valid_to <= now {
        Some("Certificate has expired".to_string())
    } else if let Some(reason) = &hostname_error {
        Some(format!("Hostname mismatch: Hostname/IP does not match certificate's altnames: {reason}"))
    } else {
        peer.authorization_error.as_ref().map(|code| format!("Certificate is not trusted: {code}"))
    };
    let chain: Vec<Value> = peer_chain(&peer.chain)
        .iter()
        .take(MAX_CHAIN)
        .filter_map(|der| X509Certificate::from_der(der).ok().map(|(_, certificate)| certificate))
        .map(|certificate| {
            let subject =
                name_attribute(common_names(certificate.subject())).or_else(|| name_attribute(organizations(certificate.subject()))).unwrap_or(Value::Null);
            json!({ "subject": subject, "issuer": issuer_name(certificate.issuer()), "validTo": iso(time_of(certificate.validity().not_after)) })
        })
        .collect();
    let millis = |from: chrono::DateTime<chrono::Utc>, to: chrono::DateTime<chrono::Utc>| (to.timestamp_millis() - from.timestamp_millis()) as f64;
    Ok(json!({
        "valid": error.is_none(),
        "error": error,
        "validFrom": iso(valid_from),
        "validTo": iso(valid_to),
        "daysLeft": (millis(now, valid_to) / DAY_MS).floor() as i64,
        "lifetimeDays": (millis(valid_from, valid_to) / DAY_MS).round() as i64,
        "issuer": issuer_name(leaf.issuer()),
        "subject": name_attribute(common_names(leaf.subject())).unwrap_or(Value::Null),
        "hostnameMatch": hostname_error.is_none(),
        "chain": chain,
    }))
}

/// Opens a TLS connection to an already allowed address and reads the certificates without trusting them.
pub async fn read_certificate(target: &Target, timeout: Duration) -> Result<PeerCertificates, Failure> {
    let work = async {
        let stream = TcpStream::connect((target.address, target.port)).await.map_err(|error| connect_failure(&error, target.address, target.port))?;
        match connect_tls_io(target, false, &[], stream).await {
            Ok(tls) => {
                let chain: Vec<CertificateDer<'static>> =
                    tls.get_ref().1.peer_certificates().map(|chain| chain.iter().map(|der| der.clone().into_owned()).collect()).unwrap_or_default();
                Ok::<_, Failure>((chain, None))
            }
            #[cfg(feature = "legacy-tls")]
            Err(error) if crate::legacy_tls::mismatch(&error) => crate::legacy_tls::read_chain(target).await.unwrap_or_else(|| Err(tls_failure(&error))),
            // rustls refuses RSA keys under 2048 bits; name that failure as OpenSSL does.
            #[cfg(feature = "legacy-tls")]
            Err(error) if crate::legacy_tls::bad_signature(&error) => match crate::legacy_tls::read_chain(target).await {
                Some(Err(weak)) => Err(weak),
                _ => Err(tls_failure(&error)),
            },
            Err(error) => Err(tls_failure(&error)),
        }
    };
    let (chain, legacy_tls) = tokio::time::timeout(timeout, work).await.map_err(|_| Failure::plain("TLS handshake timeout"))??;
    if chain.is_empty() {
        return Err(Failure::plain("The server sent no certificate"));
    }
    let identity_host = match target.host.trim_start_matches('[').trim_end_matches(']') {
        host if host.parse::<IpAddr>().is_ok() => target.address.to_string(),
        host => host.to_string(),
    };
    let authorization_error = match verify_chain(&chain) {
        Err(code) => Some(code),
        Ok(()) => X509Certificate::from_der(&chain[0])
            .ok()
            .and_then(|(_, leaf)| check_server_identity(&identity_host, &leaf))
            .map(|_| "ERR_TLS_CERT_ALTNAME_INVALID".to_string()),
    };
    Ok(PeerCertificates { chain, authorization_error, legacy_tls })
}

fn client_hello(version: u16, host: &str) -> Vec<u8> {
    let tls13 = version == 0x0304;
    let mut extensions: Vec<u8> = Vec::new();
    let mut extension = |kind: u16, data: Vec<u8>| {
        extensions.extend_from_slice(&kind.to_be_bytes());
        extensions.extend_from_slice(&(data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&data);
    };
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare.parse::<IpAddr>().is_err() && !bare.is_empty() {
        let name = bare.as_bytes();
        let mut data = ((name.len() + 3) as u16).to_be_bytes().to_vec();
        data.push(0);
        data.extend_from_slice(&(name.len() as u16).to_be_bytes());
        data.extend_from_slice(name);
        extension(0x0000, data);
    }
    let groups: [u16; 4] = [0x001d, 0x0017, 0x0018, 0x0019];
    let mut data = ((groups.len() * 2) as u16).to_be_bytes().to_vec();
    groups.iter().for_each(|group| data.extend_from_slice(&group.to_be_bytes()));
    extension(0x000a, data);
    extension(0x000b, vec![1, 0]);
    if version >= 0x0303 {
        let schemes: [u16; 11] = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201];
        let mut data = ((schemes.len() * 2) as u16).to_be_bytes().to_vec();
        schemes.iter().for_each(|scheme| data.extend_from_slice(&scheme.to_be_bytes()));
        extension(0x000d, data);
    }
    if tls13 {
        extension(0x002b, vec![2, 0x03, 0x04]);
        let key: [u8; 32] = rand::random();
        let mut data = 36u16.to_be_bytes().to_vec();
        data.extend_from_slice(&0x001du16.to_be_bytes());
        data.extend_from_slice(&32u16.to_be_bytes());
        data.extend_from_slice(&key);
        extension(0x0033, data);
    }
    extension(0xff01, vec![0]);
    let suites: Vec<u16> = if tls13 {
        vec![0x1301, 0x1302, 0x1303]
    } else {
        vec![
            0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0x009e, 0x009f, 0xc009, 0xc013, 0xc00a, 0xc014, 0xc023, 0xc027, 0xc024, 0xc028, 0x009c, 0x009d,
            0x003c, 0x003d, 0x002f, 0x0035, 0x0033, 0x0039, 0xc012, 0x000a, 0x0016, 0x0005, 0x0004,
        ]
    };
    let mut body = (if tls13 { 0x0303u16 } else { version }).to_be_bytes().to_vec();
    body.extend_from_slice(&rand::random::<[u8; 32]>());
    if tls13 {
        body.push(32);
        body.extend_from_slice(&rand::random::<[u8; 32]>());
    } else {
        body.push(0);
    }
    body.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
    suites.iter().for_each(|suite| body.extend_from_slice(&suite.to_be_bytes()));
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    let mut handshake = vec![1];
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);
    let mut record = vec![22, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// Whether a ServerHello agrees to [version]; for TLS 1.3 its supported_versions extension must name it.
fn server_hello_version(hello: &[u8], version: u16) -> bool {
    if hello.len() < 38 || hello[0] != 2 {
        return false;
    }
    let body = &hello[4..];
    let legacy = u16::from_be_bytes([body[0], body[1]]);
    let mut at = 2 + 32;
    let Some(session) = body.get(at) else { return false };
    at += 1 + usize::from(*session) + 2 + 1;
    let mut selected = legacy;
    if let Some(length) = body.get(at..at + 2).map(|bytes| usize::from(u16::from_be_bytes([bytes[0], bytes[1]]))) {
        let mut cursor = at + 2;
        let end = (cursor + length).min(body.len());
        while cursor + 4 <= end {
            let kind = u16::from_be_bytes([body[cursor], body[cursor + 1]]);
            let size = usize::from(u16::from_be_bytes([body[cursor + 2], body[cursor + 3]]));
            if kind == 0x002b && size == 2 && cursor + 6 <= end {
                selected = u16::from_be_bytes([body[cursor + 4], body[cursor + 5]]);
            }
            cursor += 4 + size;
        }
    }
    selected == version
}

/// Whether the server accepts a handshake with only [version] offered.
pub async fn offers_version(target: &Target, timeout: Duration, version: u16) -> bool {
    let work = async {
        let mut stream = TcpStream::connect((target.address, target.port)).await.ok()?;
        stream.write_all(&client_hello(version, &target.host)).await.ok()?;
        let mut header = [0u8; 5];
        stream.read_exact(&mut header).await.ok()?;
        if header[0] != 22 {
            return Some(false);
        }
        let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let mut record = vec![0u8; length.min(16 * 1024)];
        stream.read_exact(&mut record).await.ok()?;
        Some(server_hello_version(&record, version))
    };
    tokio::time::timeout(timeout, work).await.ok().flatten().unwrap_or(false)
}

/// The TLS versions the server at an already allowed address accepts, oldest first.
pub async fn offered_protocols(target: &Target, timeout: Duration) -> Vec<String> {
    let answers = futures_util::future::join_all(TLS_VERSIONS.iter().map(|(_, version)| offers_version(target, timeout, *version))).await;
    TLS_VERSIONS.iter().zip(answers).filter(|(_, offered)| *offered).map(|((name, _), _)| name.to_string()).collect()
}

/// `/check/ssl` and the agent's `ssl` job. Never fails.
pub async fn ssl_check(request: &Map<String, Value>) -> Value {
    let start = Instant::now();
    let host = request.get("host").cloned().unwrap_or(Value::Null);
    let port_value = match request.get("port") {
        None => Value::from(443),
        Some(port) => port.clone(),
    };
    let port = number_field(request, "port").map(|port| port as u16).unwrap_or(443);
    let timeout = timeout_field(request, "timeout", 10000.0);
    let protocols = truthy(request.get("protocols"));
    let host_text = host.as_str().unwrap_or("").to_string();
    let outcome = async {
        let address = resolve_allowed(&host_text, 0).await?[0];
        let target = Target { host: host_text.clone(), address, port };
        let (peer, offered) =
            tokio::join!(read_certificate(&target, timeout), async { if protocols { Some(offered_protocols(&target, timeout).await) } else { None } });
        let peer = peer?;
        let certificate = describe_certificate(&peer, &host_text, chrono::Utc::now())?;
        Ok::<_, Failure>((certificate, offered, peer.legacy_tls))
    }
    .await;
    let mut result = Map::new();
    result.insert("host".into(), host);
    result.insert("port".into(), port_value);
    match outcome {
        Ok((certificate, offered, legacy_tls)) => {
            if let Some(offered) = offered {
                result.insert("protocols".into(), Value::from(offered));
            }
            if let Some(legacy) = legacy_tls {
                result.insert("legacyTLS".into(), Value::Bool(true));
                result.insert("tlsVersion".into(), Value::from(legacy.version));
                if legacy.weak_key {
                    result.insert("weakKey".into(), Value::Bool(true));
                }
            }
            let valid = certificate["valid"].as_bool().unwrap_or(false);
            result.insert("status".into(), Value::from(if valid { "up" } else { "down" }));
            result.insert("responseTime".into(), Value::from(elapsed_ms(start)));
            result.insert("timestamp".into(), Value::from(now_iso()));
            let error = certificate["error"].clone();
            result.insert("certificate".into(), certificate);
            if !error.is_null() {
                result.insert("error".into(), error);
            }
        }
        Err(failure) => {
            result.insert("status".into(), Value::from("error"));
            result.insert("responseTime".into(), Value::from(elapsed_ms(start)));
            result.insert("timestamp".into(), Value::from(now_iso()));
            result.insert("error".into(), Value::from(failure.message));
            if let Some(code) = failure.code {
                result.insert("errorCode".into(), Value::from(code));
            }
        }
    }
    Value::Object(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_version_a_server_hello_agrees_to() {
        let mut hello = vec![2, 0, 0, 0, 0x03, 0x03];
        hello.extend_from_slice(&[0; 32]);
        hello.extend_from_slice(&[0, 0x13, 0x01, 0]);
        assert!(server_hello_version(&hello, 0x0303));
        let mut tls13 = hello.clone();
        tls13.extend_from_slice(&[0, 6, 0, 0x2b, 0, 2, 0x03, 0x04]);
        assert!(server_hello_version(&tls13, 0x0304));
        assert!(!server_hello_version(&tls13, 0x0303));
        assert!(!server_hello_version(&[21, 3, 3], 0x0303));
    }

    #[test]
    fn builds_a_client_hello_record() {
        let record = client_hello(0x0301, "example.com");
        assert_eq!(&record[..3], &[22, 3, 1]);
        assert_eq!(usize::from(u16::from_be_bytes([record[3], record[4]])), record.len() - 5);
        assert_eq!(record[5], 1);
    }
}
