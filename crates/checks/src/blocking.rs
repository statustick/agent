//! Firewall and bot-protection pages, and the User-Agent every check sends.
use std::collections::BTreeMap;

use crate::util::utf16_prefix;

/// What every check sends as, or in, its User-Agent.
pub const USER_AGENT: &str = "StatusTick/2.0 (+https://statustick.com/docs/checks)";

const CHALLENGE_MARKERS: &[(&str, &[&str])] = &[
    ("Cloudflare challenge page", &["cf-chl-", "cf_chl_opt", "/cdn-cgi/challenge-platform/", "Just a moment..."]),
    ("Cloudflare firewall block", &["Attention Required! | Cloudflare", "Sorry, you have been blocked"]),
    ("Imperva (Incapsula) firewall block", &["Incapsula incident ID", "_Incapsula_Resource"]),
    ("Sucuri firewall block", &["Sucuri WebSite Firewall - Access Denied"]),
    ("AWS WAF block", &["<title>ERROR: The request could not be satisfied</title>"]),
    ("DataDome bot protection", &["captcha-delivery.com", "geo.captcha-delivery.com"]),
    ("Akamai firewall block", &["errors.edgesuite.net"]),
];

const BLOCK_STATUSES: &[u16] = &[401, 403, 405, 406, 429, 503];

fn header(headers: &BTreeMap<String, String>, name: &str) -> String {
    headers.get(name).map(|value| value.to_lowercase()).unwrap_or_default()
}

/// Why the response looks like a firewall or bot-protection block, or None. Only typical block statuses count, so a
/// plain 403 from the application stays a normal failure. [headers] have lower-case names.
pub fn detect_block(status: u16, headers: &BTreeMap<String, String>, body: &str) -> Option<&'static str> {
    if header(headers, "cf-mitigated") == "challenge" {
        return Some("Cloudflare challenge page");
    }
    if !BLOCK_STATUSES.contains(&status) {
        return None;
    }
    if !header(headers, "x-amzn-waf-action").is_empty() {
        return Some("AWS WAF block");
    }
    if !header(headers, "x-sucuri-block").is_empty() || header(headers, "server").contains("sucuri") {
        return Some("Sucuri firewall block");
    }
    if !header(headers, "x-datadome").is_empty() || header(headers, "server") == "datadome" {
        return Some("DataDome bot protection");
    }
    if !header(headers, "x-iinfo").is_empty() {
        return Some("Imperva (Incapsula) firewall block");
    }
    let text = utf16_prefix(body, 64 * 1024);
    CHALLENGE_MARKERS.iter().find(|(_, patterns)| patterns.iter().any(|pattern| text.contains(pattern))).map(|(reason, _)| *reason)
}

/// The check's headers with the default User-Agent first unless one is set in any case.
pub fn with_user_agent(headers: Vec<(String, String)>) -> Vec<(String, String)> {
    if headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("user-agent")) {
        return headers;
    }
    let mut all = vec![("User-Agent".to_string(), USER_AGENT.to_string())];
    all.extend(headers);
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn detects_blocks_only_on_block_statuses() {
        assert_eq!(detect_block(200, &headers(&[("cf-mitigated", "challenge")]), ""), Some("Cloudflare challenge page"));
        assert_eq!(detect_block(403, &headers(&[]), "<script src=\"/cdn-cgi/challenge-platform/x\">"), Some("Cloudflare challenge page"));
        assert_eq!(detect_block(403, &headers(&[("x-amzn-waf-action", "block")]), ""), Some("AWS WAF block"));
        assert_eq!(detect_block(403, &headers(&[("server", "Sucuri/Cloudproxy")]), ""), Some("Sucuri firewall block"));
        assert_eq!(detect_block(403, &headers(&[("x-iinfo", "1")]), ""), Some("Imperva (Incapsula) firewall block"));
        assert_eq!(detect_block(403, &headers(&[]), "Forbidden"), None);
        assert_eq!(detect_block(500, &headers(&[("x-amzn-waf-action", "block")]), "Just a moment..."), None);
    }

    #[test]
    fn keeps_a_custom_user_agent() {
        assert_eq!(with_user_agent(vec![("user-AGENT".into(), "Mine".into())]), vec![("user-AGENT".to_string(), "Mine".to_string())]);
        assert_eq!(with_user_agent(vec![])[0].1, USER_AGENT);
    }
}
