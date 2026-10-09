//! The agent's settings from the environment: names, defaults and messages.
use std::net::IpAddr;

use statustick_checks::targets::{AllowRule, parse_allow_list};

pub const DEFAULT_URL: &str = "https://agent.statustick.com";
pub const DEFAULT_CONCURRENCY: usize = 5;
pub const MAX_CONCURRENCY: usize = 50;
pub const DEFAULT_METRICS_HOST: &str = "0.0.0.0";
pub const DEFAULT_RELAY_HOST: &str = "0.0.0.0";
pub const DEFAULT_BUFFER_SIZE: usize = 10000;
pub const MAX_BUFFER_SIZE: usize = 100000;

/// The settings the dashboard also sets; one set on the machine wins and shows as locked.
pub const MACHINE_SETTINGS: [&str; 3] = ["BROWSER_CONCURRENCY", "STATUSTICK_CONCURRENCY", "STATUSTICK_SHARE_METRICS"];

pub type Env = Vec<(String, String)>;

pub fn env_value<'a>(env: &'a Env, name: &str) -> Option<&'a str> {
    env.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
}

/// The process environment, in its own order.
pub fn process_env() -> Env {
    std::env::vars_os().filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?))).collect()
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub token: String,
    pub url: String,
    pub concurrency: usize,
    pub allow: Option<Vec<AllowRule>>,
    pub host_name: String,
    pub install: Option<String>,
    pub ca_file: Option<String>,
    pub buffer_size: usize,
    pub buffer_dir: Option<String>,
    pub health_port: Option<u16>,
    pub relay_port: Option<u16>,
    pub relay_host: String,
    pub discovery: bool,
    pub discovery_namespaces: Vec<String>,
    pub metrics_port: Option<u16>,
    pub metrics_host: String,
    pub share_metrics: Option<bool>,
    /// STATUSTICK_BROWSER_ISOLATION: `user`, `off`, or empty for "when the container allows it".
    pub browser_isolation: String,
}

fn trimmed(value: Option<&str>) -> &str {
    value.unwrap_or("").trim()
}

fn whole_number(value: Option<&str>, name: &str, fallback: usize, min: usize, max: usize) -> Result<usize, String> {
    let message = || format!("{name} must be a whole number from {min} to {max}");
    let number = match value {
        None | Some("") => fallback as f64,
        Some(text) => js_number(text).ok_or_else(message)?,
    };
    if number.fract() != 0.0 || number < min as f64 || number > max as f64 {
        return Err(message());
    }
    Ok(number as usize)
}

/// `Number(text)` for the forms a setting can take: blank is 0, decimal, hex with 0x, exponents.
fn js_number(text: &str) -> Option<f64> {
    let text = text.trim();
    if text.is_empty() {
        return Some(0.0);
    }
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok().map(|value| value as f64);
    }
    if text.chars().any(|c| c.is_ascii_alphabetic() && !matches!(c, 'e' | 'E')) {
        return None;
    }
    text.parse::<f64>().ok().filter(|value| value.is_finite())
}

pub fn port(value: Option<&str>, name: &str) -> Result<Option<u16>, String> {
    let text = trimmed(value);
    if text.is_empty() {
        return Ok(None);
    }
    match js_number(text) {
        Some(number) if number.fract() == 0.0 && (1.0..=65535.0).contains(&number) => Ok(Some(number as u16)),
        _ => Err(format!("{name} must be a port number from 1 to 65535")),
    }
}

fn is_local_host(host: &str) -> bool {
    host == "localhost" || host.ends_with(".localhost") || host == "127.0.0.1" || host == "[::1]"
}

pub fn read_url(value: Option<&str>, name: &str) -> Result<String, String> {
    let raw = value.filter(|value| !value.is_empty()).unwrap_or(DEFAULT_URL);
    let url = url::Url::parse(raw).map_err(|_| format!("{name} is not a valid URL"))?;
    let host = url.host_str().unwrap_or("");
    if url.scheme() != "https" && !(url.scheme() == "http" && is_local_host(host)) {
        return Err(format!("{name} must use https"));
    }
    Ok(format!("{}{}", url.origin().ascii_serialization(), url.path().trim_end_matches('/')))
}

pub fn read_token(value: Option<&str>, name: &str) -> Result<String, String> {
    let token = trimmed(value);
    if token.is_empty() { Err(format!("{name} is not set")) } else { Ok(token.to_string()) }
}

pub fn read_ca_file(value: Option<&str>, name: &str) -> Result<Option<String>, String> {
    let file = trimmed(value);
    if file.is_empty() {
        return Ok(None);
    }
    let pem = std::fs::read_to_string(file).map_err(|_| format!("{name} file cannot be read: {file}"))?;
    if !pem.contains("-----BEGIN CERTIFICATE-----") {
        return Err(format!("{name} file has no PEM certificate: {file}"));
    }
    Ok(Some(file.to_string()))
}

fn writable(dir: &str) -> bool {
    let Ok(path) = std::ffi::CString::new(dir) else { return false };
    // SAFETY: access only reads the path it is given.
    unsafe { libc::access(path.as_ptr(), libc::W_OK) == 0 }
}

pub fn host_name() -> String {
    let mut buffer = [0u8; 256];
    // SAFETY: gethostname writes at most the length it is given.
    if unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) } != 0 {
        return String::new();
    }
    let end = buffer.iter().position(|byte| *byte == 0).unwrap_or(buffer.len());
    String::from_utf8_lossy(&buffer[..end]).into_owned()
}

fn choice(value: Option<&str>, name: &str) -> Result<Option<bool>, String> {
    match trimmed(value).to_lowercase().as_str() {
        "" => Ok(None),
        "true" => Ok(Some(true)),
        "false" => Ok(Some(false)),
        _ => Err(format!("{name} must be true, false or empty")),
    }
}

pub fn read_relay_port(env: &Env) -> Result<Option<u16>, String> {
    port(env_value(env, "STATUSTICK_RELAY_PORT"), "STATUSTICK_RELAY_PORT")
}

fn namespace_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes.iter().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && bytes[0] != b'-'
        && bytes[bytes.len() - 1] != b'-'
}

fn secret_hosts_name(name: &str) -> bool {
    name.strip_prefix("STATUSTICK_SECRET_")
        .and_then(|rest| rest.strip_suffix("_HOSTS"))
        .is_some_and(|middle| !middle.is_empty() && middle.bytes().all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'))
}

/// The agent's settings except those for browser checks; the error is the first problem's message.
pub fn read_settings(env: &Env) -> Result<Settings, String> {
    let get = |name: &str| env_value(env, name);
    let token = read_token(get("STATUSTICK_TOKEN"), "STATUSTICK_TOKEN")?;
    let url = read_url(get("STATUSTICK_URL"), "STATUSTICK_URL")?;
    let concurrency = whole_number(get("STATUSTICK_CONCURRENCY"), "STATUSTICK_CONCURRENCY", DEFAULT_CONCURRENCY, 1, MAX_CONCURRENCY)?;
    let allow = parse_allow_list(get("STATUSTICK_ALLOW").unwrap_or(""), "STATUSTICK_ALLOW")?;
    let host = trimmed(get("STATUSTICK_HOSTNAME"));
    let host_name = if host.is_empty() { host_name() } else { host.to_string() };
    let install = match trimmed(get("STATUSTICK_INSTALL")).to_lowercase().as_str() {
        "" => None,
        kind @ ("docker" | "compose" | "helm" | "other") => Some(kind.to_string()),
        _ => return Err("STATUSTICK_INSTALL must be docker, compose, helm or other".to_string()),
    };
    let ca_file = read_ca_file(get("NODE_EXTRA_CA_CERTS"), "NODE_EXTRA_CA_CERTS")?;
    let buffer_size = whole_number(get("STATUSTICK_BUFFER_SIZE"), "STATUSTICK_BUFFER_SIZE", DEFAULT_BUFFER_SIZE, 1, MAX_BUFFER_SIZE)?;
    let dir = trimmed(get("STATUSTICK_BUFFER_DIR"));
    if !dir.is_empty() && !writable(dir) {
        return Err(format!("STATUSTICK_BUFFER_DIR is not a writable folder: {dir}"));
    }
    let buffer_dir = (!dir.is_empty()).then(|| dir.to_string());
    let health_port = port(get("STATUSTICK_HEALTH_PORT"), "STATUSTICK_HEALTH_PORT")?;
    let relay_port = read_relay_port(env)?;
    let relay_host = Some(trimmed(get("STATUSTICK_RELAY_HOST"))).filter(|host| !host.is_empty()).unwrap_or(DEFAULT_RELAY_HOST).to_string();
    let discovery = match trimmed(get("STATUSTICK_DISCOVERY")) {
        "" => false,
        "kubernetes" => true,
        _ => return Err("STATUSTICK_DISCOVERY must be \"kubernetes\" or empty".to_string()),
    };
    let mut discovery_namespaces: Vec<String> = Vec::new();
    for name in trimmed(get("STATUSTICK_DISCOVERY_NAMESPACES")).split(',').map(str::trim).filter(|name| !name.is_empty()) {
        if !discovery_namespaces.iter().any(|seen| seen == name) {
            discovery_namespaces.push(name.to_string());
        }
    }
    let metrics_port = port(get("METRICS_PORT"), "METRICS_PORT")?;
    let metrics_host = Some(trimmed(get("METRICS_HOST"))).filter(|host| !host.is_empty()).unwrap_or(DEFAULT_METRICS_HOST).to_string();
    let share_metrics = choice(get("STATUSTICK_SHARE_METRICS"), "STATUSTICK_SHARE_METRICS")?;
    let browser_isolation = trimmed(get("STATUSTICK_BROWSER_ISOLATION")).to_lowercase();
    if !["", "user", "off"].contains(&browser_isolation.as_str()) {
        return Err("STATUSTICK_BROWSER_ISOLATION must be user, off or empty".to_string());
    }

    for (name, value) in env {
        if secret_hosts_name(name) {
            parse_allow_list(value, name)?;
        }
    }
    if let Some(relay) = relay_port {
        if Some(relay) == health_port {
            return Err("STATUSTICK_RELAY_PORT must not be the same port as STATUSTICK_HEALTH_PORT".to_string());
        }
        if relay_host.parse::<IpAddr>().is_err() {
            return Err("STATUSTICK_RELAY_HOST must be an IP address of this host, for example 0.0.0.0 or 10.0.0.5".to_string());
        }
    }
    if discovery && let Some(wrong) = discovery_namespaces.iter().find(|name| !namespace_name(name)) {
        return Err(format!("STATUSTICK_DISCOVERY_NAMESPACES has a name that is not a namespace: {wrong}"));
    }
    if let Some(metrics) = metrics_port {
        if Some(metrics) == health_port || Some(metrics) == relay_port {
            return Err("METRICS_PORT must not be the same port as STATUSTICK_HEALTH_PORT or STATUSTICK_RELAY_PORT".to_string());
        }
        if metrics_host.parse::<IpAddr>().is_err() {
            return Err("METRICS_HOST must be an IP address of this host, for example 0.0.0.0 or 127.0.0.1".to_string());
        }
    }
    Ok(Settings {
        token,
        url,
        concurrency,
        allow,
        host_name,
        install,
        ca_file,
        buffer_size,
        buffer_dir,
        health_port,
        relay_port,
        relay_host,
        discovery,
        discovery_namespaces,
        metrics_port,
        metrics_host,
        share_metrics,
        browser_isolation,
    })
}

/// The names of the dashboard settings set on this machine; their values are never sent.
pub fn machine_settings(env: &Env) -> Vec<&'static str> {
    MACHINE_SETTINGS.iter().copied().filter(|name| !trimmed(env_value(env, name)).is_empty()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Env {
        pairs.iter().map(|(name, value)| (name.to_string(), value.to_string())).collect()
    }

    fn error(pairs: &[(&str, &str)]) -> String {
        let mut all = vec![("STATUSTICK_TOKEN", "sta_live_x")];
        all.extend_from_slice(pairs);
        read_settings(&env(&all)).unwrap_err()
    }

    #[test]
    fn reads_the_defaults() {
        let settings = read_settings(&env(&[("STATUSTICK_TOKEN", " sta_live_x ")])).unwrap();
        assert_eq!(settings.token, "sta_live_x");
        assert_eq!(settings.url, DEFAULT_URL);
        assert_eq!(settings.concurrency, 5);
        assert_eq!(settings.buffer_size, 10000);
        assert_eq!(settings.relay_host, "0.0.0.0");
        assert!(settings.allow.is_none());
        assert_eq!(read_settings(&env(&[])).unwrap_err(), "STATUSTICK_TOKEN is not set");
    }

    #[test]
    fn refuses_wrong_values_with_the_operator_messages() {
        assert_eq!(error(&[("STATUSTICK_URL", "http://agent.example.com")]), "STATUSTICK_URL must use https");
        assert_eq!(error(&[("STATUSTICK_URL", "nope")]), "STATUSTICK_URL is not a valid URL");
        assert_eq!(error(&[("STATUSTICK_CONCURRENCY", "0")]), "STATUSTICK_CONCURRENCY must be a whole number from 1 to 50");
        assert_eq!(error(&[("STATUSTICK_CONCURRENCY", "2.5")]), "STATUSTICK_CONCURRENCY must be a whole number from 1 to 50");
        assert_eq!(error(&[("STATUSTICK_HEALTH_PORT", "70000")]), "STATUSTICK_HEALTH_PORT must be a port number from 1 to 65535");
        assert_eq!(
            error(&[("STATUSTICK_HEALTH_PORT", "8080"), ("STATUSTICK_RELAY_PORT", "8080")]),
            "STATUSTICK_RELAY_PORT must not be the same port as STATUSTICK_HEALTH_PORT"
        );
        assert_eq!(
            error(&[("METRICS_PORT", "9100"), ("METRICS_HOST", "localhost")]),
            "METRICS_HOST must be an IP address of this host, for example 0.0.0.0 or 127.0.0.1"
        );
        assert_eq!(
            error(&[("STATUSTICK_DISCOVERY", "kubernetes"), ("STATUSTICK_DISCOVERY_NAMESPACES", "shop,Bad")]),
            "STATUSTICK_DISCOVERY_NAMESPACES has a name that is not a namespace: Bad"
        );
        assert_eq!(error(&[("STATUSTICK_SHARE_METRICS", "yes")]), "STATUSTICK_SHARE_METRICS must be true, false or empty");
        assert_eq!(error(&[("STATUSTICK_SECRET_DB_HOSTS", "a/b")]), "STATUSTICK_SECRET_DB_HOSTS has an entry that is not valid: a/b");
    }

    #[test]
    fn keeps_local_http_urls_without_a_trailing_slash() {
        assert_eq!(read_url(Some("http://localhost:8080/base/"), "X").unwrap(), "http://localhost:8080/base");
        assert_eq!(read_url(Some("https://agent.example.com:443/"), "X").unwrap(), "https://agent.example.com");
    }

    #[test]
    fn names_the_dashboard_settings_set_on_the_machine() {
        assert_eq!(machine_settings(&env(&[("STATUSTICK_CONCURRENCY", "3"), ("BROWSER_CONCURRENCY", " ")])), vec!["STATUSTICK_CONCURRENCY"]);
    }
}
