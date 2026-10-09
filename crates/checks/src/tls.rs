//! TLS for every check: the trust store (Mozilla's roots plus `NODE_EXTRA_CA_CERTS`), chain verification with the
//! OpenSSL error codes StatusTick expects, Node.js's host name rules, and certificate descriptions.
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

/// A verification failure as Node.js reports it: an OpenSSL code such as `DEPTH_ZERO_SELF_SIGNED_CERT` and its text,
/// or `ERR_TLS_CERT_ALTNAME_INVALID` for a host name mismatch.
#[derive(Debug, Clone)]
pub struct NodeTLSError {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for NodeTLSError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for NodeTLSError {}

pub fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: LazyLock<Arc<CryptoProvider>> = LazyLock::new(|| Arc::new(rustls::crypto::ring::default_provider()));
    PROVIDER.clone()
}

fn algorithms() -> WebPkiSupportedAlgorithms {
    provider().signature_verification_algorithms
}

pub struct TrustStore {
    pub certificates: Vec<CertificateDer<'static>>,
    anchors: Vec<TrustAnchor<'static>>,
    by_subject: HashMap<Vec<u8>, Vec<usize>>,
}

fn pem_certificates(text: &str) -> Vec<CertificateDer<'static>> {
    use rustls::pki_types::pem::PemObject;
    CertificateDer::pem_slice_iter(text.as_bytes()).filter_map(Result::ok).collect()
}

/// Mozilla's roots and the PEM file in `NODE_EXTRA_CA_CERTS`, as Node.js trusts them.
pub fn trust_store() -> &'static TrustStore {
    static STORE: LazyLock<TrustStore> = LazyLock::new(|| {
        let mut certificates: Vec<CertificateDer<'static>> = webpki_root_certs::TLS_SERVER_ROOT_CERTS.to_vec();
        if let Some(path) = std::env::var_os("NODE_EXTRA_CA_CERTS").filter(|path| !path.is_empty()) {
            match std::fs::read_to_string(&path) {
                Ok(text) => certificates.extend(pem_certificates(&text)),
                Err(error) => eprintln!("Warning: Ignoring extra certs from `{}`, load failed: {error}", path.to_string_lossy()),
            }
        }
        let mut anchors = Vec::new();
        let mut by_subject: HashMap<Vec<u8>, Vec<usize>> = HashMap::new();
        let mut kept = Vec::new();
        for certificate in certificates {
            let Ok(anchor) = webpki::anchor_from_trusted_cert(&certificate) else { continue };
            if let Ok((_, parsed)) = X509Certificate::from_der(&certificate) {
                by_subject.entry(parsed.subject().as_raw().to_vec()).or_default().push(kept.len());
            }
            anchors.push(anchor.to_owned());
            kept.push(certificate);
        }
        TrustStore { certificates: kept, anchors, by_subject }
    });
    &STORE
}

impl TrustStore {
    fn issuer_of(&self, certificate: &X509Certificate<'_>) -> Option<&CertificateDer<'static>> {
        self.by_subject
            .get(certificate.issuer().as_raw())?
            .iter()
            .map(|index| &self.certificates[*index])
            .find(|candidate| X509Certificate::from_der(candidate).is_ok_and(|(_, issuer)| certificate.verify_signature(Some(issuer.public_key())).is_ok()))
    }

    fn contains(&self, certificate: &CertificateDer<'_>) -> bool {
        self.certificates.iter().any(|trusted| trusted.as_ref() == certificate.as_ref())
    }
}

fn self_issued(certificate: &X509Certificate<'_>) -> bool {
    certificate.subject().as_raw() == certificate.issuer().as_raw()
}

fn issued_by(certificate: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> bool {
    certificate.issuer().as_raw() == issuer.subject().as_raw() && certificate.verify_signature(Some(issuer.public_key())).is_ok()
}

/// The certificates from the leaf up, as Node.js's `getPeerCertificate(true)` follows `issuerCertificate`: issuers the
/// server sent, then one from the trust store.
pub fn peer_chain(presented: &[CertificateDer<'static>]) -> Vec<CertificateDer<'static>> {
    let parsed: Vec<Option<X509Certificate<'_>>> = presented.iter().map(|der| X509Certificate::from_der(der).ok().map(|(_, cert)| cert)).collect();
    let mut chain: Vec<CertificateDer<'static>> = Vec::new();
    let Some(Some(mut current)) = parsed.first().cloned() else {
        return presented.iter().take(1).cloned().collect();
    };
    chain.push(presented[0].clone());
    let mut used = vec![0usize];
    loop {
        if self_issued(&current) || chain.len() >= 10 {
            break;
        }
        let next = (0..presented.len()).find(|index| !used.contains(index) && parsed[*index].as_ref().is_some_and(|issuer| issued_by(&current, issuer)));
        match next {
            Some(index) => {
                used.push(index);
                chain.push(presented[index].clone());
                current = parsed[index].clone().expect("parsed issuer");
            }
            None => {
                if let Some(root) = trust_store().issuer_of(&current)
                    && !chain.iter().any(|certificate| certificate.as_ref() == root.as_ref())
                {
                    chain.push(root.clone());
                }
                break;
            }
        }
    }
    chain
}

pub fn openssl_message(code: &str) -> &'static str {
    match code {
        "DEPTH_ZERO_SELF_SIGNED_CERT" => "self-signed certificate",
        "SELF_SIGNED_CERT_IN_CHAIN" => "self-signed certificate in certificate chain",
        "UNABLE_TO_VERIFY_LEAF_SIGNATURE" => "unable to verify the first certificate",
        "UNABLE_TO_GET_ISSUER_CERT_LOCALLY" => "unable to get local issuer certificate",
        "CERT_HAS_EXPIRED" => "certificate has expired",
        "CERT_NOT_YET_VALID" => "certificate is not yet valid",
        "CERT_SIGNATURE_FAILURE" => "certificate signature failure",
        "INVALID_PURPOSE" => "unsupported certificate purpose",
        _ => "certificate rejected",
    }
}

/// Verifies [presented] (leaf first) against the trust store; the error is the OpenSSL code Node.js reports.
pub fn verify_chain(presented: &[CertificateDer<'static>]) -> Result<(), String> {
    let store = trust_store();
    let Some(leaf) = presented.first() else {
        return Err("UNABLE_TO_VERIFY_LEAF_SIGNATURE".to_string());
    };
    if store.contains(leaf) {
        return Ok(());
    }
    let parsed_leaf = X509Certificate::from_der(leaf).map(|(_, cert)| cert).map_err(|_| "CERT_REJECTED".to_string())?;
    let end_entity = webpki::EndEntityCert::try_from(leaf).map_err(|_| "CERT_REJECTED".to_string())?;
    let intermediates = &presented[1..];
    let unknown_issuer = || {
        let chain = peer_chain(presented);
        let last = chain.last().and_then(|der| X509Certificate::from_der(der).ok().map(|(_, cert)| cert));
        if presented.len() == 1 && self_issued(&parsed_leaf) {
            "DEPTH_ZERO_SELF_SIGNED_CERT"
        } else if chain.len() > 1 && last.is_some_and(|last| self_issued(&last)) {
            "SELF_SIGNED_CERT_IN_CHAIN"
        } else if chain.len() == 1 {
            "UNABLE_TO_VERIFY_LEAF_SIGNATURE"
        } else {
            "UNABLE_TO_GET_ISSUER_CERT_LOCALLY"
        }
    };
    let result = end_entity.verify_for_usage(algorithms().all, &store.anchors, intermediates, UnixTime::now(), webpki::KeyUsage::server_auth(), None, None);
    match result {
        Ok(_) => Ok(()),
        Err(webpki::Error::CertExpired { .. }) => Err("CERT_HAS_EXPIRED".to_string()),
        Err(webpki::Error::CertNotValidYet { .. }) => Err("CERT_NOT_YET_VALID".to_string()),
        Err(webpki::Error::UnknownIssuer) => Err(unknown_issuer().to_string()),
        Err(webpki::Error::CaUsedAsEndEntity) if self_issued(&parsed_leaf) => Err(unknown_issuer().to_string()),
        Err(webpki::Error::RequiredEkuNotFoundContext(_)) => Err("INVALID_PURPOSE".to_string()),
        Err(webpki::Error::InvalidSignatureForPublicKey) => Err("CERT_SIGNATURE_FAILURE".to_string()),
        Err(_) => Err(unknown_issuer().to_string()),
    }
}

/// OpenSSL's `subjectaltname` text: `DNS:a, IP Address:1.2.3.4`.
pub fn subject_alt_name(certificate: &X509Certificate<'_>) -> Option<String> {
    let extension = certificate.subject_alternative_name().ok().flatten()?;
    let names: Vec<String> = extension
        .value
        .general_names
        .iter()
        .map(|name| match name {
            GeneralName::DNSName(dns) => format!("DNS:{dns}"),
            GeneralName::RFC822Name(email) => format!("email:{email}"),
            GeneralName::URI(uri) => format!("URI:{uri}"),
            GeneralName::IPAddress(bytes) => format!("IP Address:{}", openssl_ip(bytes)),
            _ => "othername:<unsupported>".to_string(),
        })
        .collect();
    Some(names.join(", "))
}

fn openssl_ip(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]),
        16 => bytes.chunks(2).map(|pair| format!("{:X}", u16::from_be_bytes([pair[0], pair[1]]))).collect::<Vec<_>>().join(":"),
        _ => "<invalid>".to_string(),
    }
}

/// The values of one attribute of a name: a string, an array when there are several, or None.
pub fn name_attribute(values: Vec<String>) -> Option<serde_json::Value> {
    match values.len() {
        0 => None,
        1 => Some(serde_json::Value::String(values.into_iter().next().expect("one value"))),
        _ => Some(serde_json::Value::from(values)),
    }
}

pub fn common_names(name: &x509_parser::x509::X509Name<'_>) -> Vec<String> {
    name.iter_common_name().map(|attribute| attribute_text(attribute.attr_value())).collect()
}

pub fn organizations(name: &x509_parser::x509::X509Name<'_>) -> Vec<String> {
    name.iter_organization().map(|attribute| attribute_text(attribute.attr_value())).collect()
}

fn attribute_text(value: &x509_parser::der_parser::asn1_rs::Any<'_>) -> String {
    use x509_parser::der_parser::asn1_rs::Tag;
    if value.tag() == Tag::BmpString {
        let units: Vec<u16> = value.data.chunks(2).filter(|pair| pair.len() == 2).map(|pair| u16::from_be_bytes([pair[0], pair[1]])).collect();
        return String::from_utf16_lossy(&units);
    }
    String::from_utf8_lossy(value.data).into_owned()
}

fn split_host(host: &str) -> Vec<String> {
    host.to_lowercase().trim_end_matches('.').split('.').map(str::to_string).collect()
}

/// Node.js's `check` in `tls.checkServerIdentity`.
fn name_matches(host_parts: &[String], pattern: &str, wildcards: bool) -> bool {
    if pattern.is_empty() {
        return false;
    }
    let pattern_parts = split_host(pattern);
    if host_parts.len() != pattern_parts.len() || pattern_parts.iter().any(String::is_empty) {
        return false;
    }
    if pattern_parts.iter().any(|part| part.chars().any(|c| !('\u{21}'..='\u{7f}').contains(&c))) {
        return false;
    }
    for index in (1..host_parts.len()).rev() {
        if host_parts[index] != pattern_parts[index] {
            return false;
        }
    }
    let host_subdomain = &host_parts[0];
    let pattern_subdomain = &pattern_parts[0];
    let pieces: Vec<&str> = pattern_subdomain.splitn(3, '*').collect();
    if pieces.len() == 1 || pattern_subdomain.contains("xn--") {
        return host_subdomain == pattern_subdomain;
    }
    if !wildcards || pieces.len() > 2 || pattern_parts.len() <= 2 {
        return false;
    }
    let (prefix, suffix) = (pieces[0], pieces[1]);
    prefix.len() + suffix.len() <= host_subdomain.len() && host_subdomain.starts_with(prefix) && host_subdomain.ends_with(suffix)
}

fn canonical_ip(text: &str) -> Option<IpAddr> {
    text.parse().ok()
}

/// `tls.checkServerIdentity(host, cert)`: None when [host] matches, else Node.js's reason after
/// "Hostname/IP does not match certificate's altnames: ".
pub fn check_server_identity(host: &str, certificate: &X509Certificate<'_>) -> Option<String> {
    let alt_names = subject_alt_name(certificate);
    let mut dns_names = Vec::new();
    let mut ips = Vec::new();
    if let Some(alt_names) = &alt_names {
        for name in alt_names.split(", ") {
            if let Some(dns) = name.strip_prefix("DNS:") {
                dns_names.push(dns.to_string());
            } else if let Some(ip) = name.strip_prefix("IP Address:") {
                ips.push(ip.to_string());
            }
        }
    }
    let hostname = host.strip_suffix('.').unwrap_or(host);
    if let Some(address) = canonical_ip(hostname) {
        if ips.iter().any(|ip| canonical_ip(ip) == Some(address)) {
            return None;
        }
        return Some(format!("IP: {hostname} is not in the cert's list: {}", ips.join(", ")));
    }
    let common = common_names(certificate.subject());
    if !dns_names.is_empty() || !common.is_empty() {
        let host_parts = split_host(hostname);
        if !dns_names.is_empty() {
            if dns_names.iter().any(|name| name_matches(&host_parts, name, true)) {
                return None;
            }
            return Some(format!("Host: {hostname}. is not in the cert's altnames: {}", alt_names.unwrap_or_default()));
        }
        if common.iter().any(|name| name_matches(&host_parts, name, true)) {
            return None;
        }
        return Some(format!("Host: {hostname}. is not cert's CN: {}", common.join(",")));
    }
    Some("Cert does not contain a DNS name".to_string())
}

/// Accepts what Node.js accepts: with [verify] the chain must lead to a trusted root and the certificate must name the
/// host; without it any certificate. Handshake signatures are always checked.
#[derive(Debug)]
pub struct NodeVerifier {
    verify: bool,
}

impl ServerCertVerifier for NodeVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if !self.verify {
            return Ok(ServerCertVerified::assertion());
        }
        let mut presented = vec![end_entity.clone().into_owned()];
        presented.extend(intermediates.iter().map(|certificate| certificate.clone().into_owned()));
        let refuse = |code: String, message: String| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(Arc::new(NodeTLSError { code, message }))))
        };
        if let Err(code) = verify_chain(&presented) {
            let message = openssl_message(&code).to_string();
            return Err(refuse(code, message));
        }
        let host = match server_name {
            ServerName::DnsName(name) => name.as_ref().to_string(),
            ServerName::IpAddress(address) => IpAddr::from(*address).to_string(),
            _ => String::new(),
        };
        let (_, parsed) = X509Certificate::from_der(end_entity).map_err(|_| refuse("CERT_REJECTED".into(), "certificate rejected".into()))?;
        match check_server_identity(&host, &parsed) {
            None => Ok(ServerCertVerified::assertion()),
            Some(reason) => Err(refuse("ERR_TLS_CERT_ALTNAME_INVALID".into(), format!("Hostname/IP does not match certificate's altnames: {reason}"))),
        }
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &algorithms())
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &algorithms())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        algorithms().supported_schemes()
    }
}

/// A client configuration; [alpn] are the protocols offered, e.g. `h2`.
pub fn client_config(verify: bool, alpn: &[&str]) -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NodeVerifier { verify }))
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.as_bytes().to_vec()).collect();
    Arc::new(config)
}

/// The SNI name for [host]; an IP literal sends none, as Node.js leaves `servername` out for it.
pub fn server_name(host: &str, address: IpAddr) -> ServerName<'static> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    match bare.parse::<IpAddr>() {
        Ok(ip) => ServerName::IpAddress(ip.into()),
        Err(_) => ServerName::try_from(bare.to_string()).unwrap_or_else(|_| ServerName::IpAddress(address.into())),
    }
}

pub fn version_name(version: rustls::ProtocolVersion) -> Option<String> {
    match version {
        rustls::ProtocolVersion::TLSv1_3 => Some("TLSv1.3".to_string()),
        rustls::ProtocolVersion::TLSv1_2 => Some("TLSv1.2".to_string()),
        rustls::ProtocolVersion::TLSv1_1 => Some("TLSv1.1".to_string()),
        rustls::ProtocolVersion::TLSv1_0 => Some("TLSv1".to_string()),
        _ => None,
    }
}

/// The Node.js failure for a TLS error: a verification code with its text, or the error itself.
pub fn node_error(error: &(dyn std::error::Error + 'static)) -> Option<NodeTLSError> {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(error) = current {
        if let Some(node) = error.downcast_ref::<NodeTLSError>() {
            return Some(node.clone());
        }
        if let Some(rustls::Error::InvalidCertificate(rustls::CertificateError::Other(other))) = error.downcast_ref::<rustls::Error>()
            && let Some(node) = other.0.downcast_ref::<NodeTLSError>()
        {
            return Some(node.clone());
        }
        current = error.source();
    }
    None
}

/// A connection over TLS older than 1.2 or without an AEAD cipher: the negotiated version, such as `TLSv1`, and
/// whether the certificate's key is RSA or DSA under 2048 bits, which only such a connection accepts.
#[derive(Clone, Debug)]
pub struct LegacyTls {
    pub version: String,
    pub weak_key: bool,
}
