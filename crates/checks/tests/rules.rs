//! Proxy settings, asset lists, JSON paths and firewall pages, without a network.
use std::collections::{BTreeMap, HashMap};

use serde_json::{Value, json};
use statustick_checks::assets::{MAX_ASSETS, extract_assets};
use statustick_checks::blocking::detect_block;
use statustick_checks::json::{check_json, valid_json_path};
use statustick_checks::proxy::{ProxySettings, proxy_for, read_proxy_settings};
use url::Url;

fn settings(pairs: &[(&str, &str)]) -> Result<ProxySettings, String> {
    let env: HashMap<String, String> = pairs.iter().map(|(name, value)| (name.to_string(), value.to_string())).collect();
    read_proxy_settings(|name| env.get(name).cloned())
}

fn via(url: &str, settings: &ProxySettings) -> Option<String> {
    proxy_for(&Url::parse(url).expect("url"), settings).map(|proxy| proxy.to_string())
}

#[test]
fn lower_case_no_proxy_wins_over_upper_case() {
    let settings = settings(&[("HTTPS_PROXY", "http://proxy:1"), ("no_proxy", "example.com"), ("NO_PROXY", "other.com")]).unwrap();
    assert_eq!(via("https://example.com/", &settings), None);
}

#[test]
fn an_invalid_proxy_url_is_refused() {
    assert_eq!(settings(&[("HTTP_PROXY", "http://")]).unwrap_err(), "HTTP_PROXY is not a valid proxy URL");
}

#[test]
fn no_proxy_matches_domains_subdomains_and_wildcards() {
    let settings = settings(&[("HTTPS_PROXY", "http://proxy:3128"), ("NO_PROXY", "intranet.corp, .internal,*.lan")]).unwrap();
    for direct in ["https://intranet.corp/", "https://wiki.intranet.corp/", "https://db.internal/", "https://nas.lan/"] {
        assert_eq!(via(direct, &settings), None, "{direct}");
    }
    for proxied in ["https://notintranet.corp/", "https://example.com/"] {
        assert_eq!(via(proxied, &settings).as_deref(), Some("http://proxy:3128/"), "{proxied}");
    }
}

#[test]
fn no_proxy_matches_ports_addresses_and_ranges() {
    let port = settings(&[("HTTPS_PROXY", "http://proxy:3128"), ("NO_PROXY", "app.corp:8443")]).unwrap();
    assert_eq!(via("https://app.corp:8443/", &port), None);
    assert_eq!(via("https://app.corp/", &port).as_deref(), Some("http://proxy:3128/"));

    let addresses = settings(&[("HTTP_PROXY", "http://proxy:3128"), ("NO_PROXY", "10.0.0.0/8,192.168.1.5,::1,[fd00::1]")]).unwrap();
    for direct in ["http://10.20.30.40/", "http://192.168.1.5:8080/", "http://[::1]/", "http://[fd00::1]/"] {
        assert_eq!(via(direct, &addresses), None, "{direct}");
    }
    assert_eq!(via("http://192.168.1.6/", &addresses).as_deref(), Some("http://proxy:3128/"));
}

#[test]
fn assets_are_listed_in_page_order_without_data_urls_or_ignored_hosts() {
    let page = r#"<!doctype html><html><head>
  <link rel="stylesheet" href="/css/site.css"><link rel="icon" href="/favicon.ico">
  <script src="https://cdn.example.net/app.js"></script>
</head><body>
  <img src="img/logo.png"><img src="data:image/png;base64,AAAA"><img src='https://res.cloudinary.com/demo/hero.jpg?w=1&amp;h=2'>
  <script src="https://www.googletagmanager.com/gtm.js"></script>
</body></html>"#;
    assert_eq!(
        extract_assets(page, "https://93.184.215.14/shop/", &[], MAX_ASSETS),
        [
            "https://93.184.215.14/css/site.css",
            "https://cdn.example.net/app.js",
            "https://93.184.215.14/shop/img/logo.png",
            "https://res.cloudinary.com/demo/hero.jpg?w=1&h=2",
            "https://www.googletagmanager.com/gtm.js",
        ]
    );
    let ignored = extract_assets(page, "https://93.184.215.14/", &["googletagmanager.com".to_string(), "cdn.example.net".to_string()], MAX_ASSETS);
    assert!(!ignored.iter().any(|url| url.contains("googletagmanager") || url.contains("cdn.example.net")), "{ignored:?}");
    assert_eq!(ignored.len(), 3);
}

#[test]
fn json_assertions_accept_simple_paths_and_name_the_failing_one() {
    for path in ["$", "$.a", "$.a.b[0]", "$[2].x_y-z"] {
        assert!(valid_json_path(path), "{path}");
    }
    for path in ["a.b", "$.", "$..a", "$.a[x]", "$['a']", "$.a b", "$.1a"] {
        assert!(!valid_json_path(path), "{path}");
    }
    let body = json!({ "status": "ok", "data": { "items": [{ "id": 7, "healthy": true, "note": null }] } }).to_string();
    let check = |assertions: Value| check_json(&body, assertions.as_array().expect("assertions"));
    assert_eq!(check(json!([{ "path": "$.data.items[0].healthy", "equals": true }, { "path": "$.data.items", "exists": true }])), None);
    assert_eq!(
        check(json!([{ "path": "$.status", "equals": "ok" }, { "path": "$.data.items[0].id", "equals": "7" }])).as_deref(),
        Some("JSON path $.data.items[0].id is not the expected value")
    );
    assert_eq!(check(json!([{ "path": "$.data.items[3]", "exists": true }])).as_deref(), Some("JSON path $.data.items[3] is missing in the response"));
}

#[test]
fn a_firewall_challenge_is_recognised_by_its_page_or_header() {
    let headers = |pairs: &[(&str, &str)]| pairs.iter().map(|(name, value)| (name.to_string(), value.to_string())).collect::<BTreeMap<_, _>>();
    let challenge = r#"<html><title>Just a moment...</title><script src="/cdn-cgi/challenge-platform/h/b/orchestrate"></script>"#;
    assert_eq!(detect_block(503, &headers(&[("server", "cloudflare")]), challenge), Some("Cloudflare challenge page"));
    assert_eq!(detect_block(403, &headers(&[("cf-mitigated", "challenge")]), ""), Some("Cloudflare challenge page"));
    assert_eq!(detect_block(403, &headers(&[("server", "nginx")]), "<h1>Forbidden</h1>"), None);
    assert_eq!(detect_block(500, &headers(&[("server", "cloudflare")]), "Just a moment..."), None);
}
