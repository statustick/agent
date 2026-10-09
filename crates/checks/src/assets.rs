//! Images, scripts and stylesheets of a page, checked after the page is up.
use std::future::Future;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Value, json};
use url::Url;

use crate::util::Failure;

pub const MAX_ASSETS: usize = 30;
const PARALLEL: usize = 6;

static IMG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)<img(?-u:\b)[^>]*?(?-u:\b)src\s*=\s*["']([^"']+)["']"#).expect("valid pattern"));
static SCRIPT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)<script(?-u:\b)[^>]*?(?-u:\b)src\s*=\s*["']([^"']+)["']"#).expect("valid pattern"));
static LINK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)<link(?-u:\b)").expect("valid pattern"));
static STYLESHEET: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)(?-u:\b)rel\s*=\s*["']?stylesheet"#).expect("valid pattern"));
static HREF: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)^[^>]*?(?-u:\b)href\s*=\s*["']([^"']+)["']"#).expect("valid pattern"));

fn is_ignored(hostname: &str, ignore_hosts: &[String]) -> bool {
    let host = hostname.to_lowercase();
    ignore_hosts.iter().any(|ignored| {
        let lower = ignored.to_lowercase();
        let entry = lower.strip_prefix("*.").unwrap_or(&lower);
        host == entry || host.ends_with(&format!(".{entry}"))
    })
}

/// Stylesheet links: `<link` with `rel=stylesheet` before its `>`, then the first `href` after the tag name.
fn stylesheet_links(html: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(tag) = LINK.find_at(html, from) {
        let rest = &html[tag.end()..];
        let attributes = &rest[..rest.find('>').unwrap_or(rest.len())];
        match STYLESHEET.is_match(attributes).then(|| HREF.captures(rest)).flatten() {
            Some(capture) => {
                found.push((tag.start(), capture[1].trim().to_string()));
                from = tag.end() + capture.get(0).map_or(0, |whole| whole.end());
            }
            None => from = tag.end(),
        }
    }
    found
}

/// Image, script and stylesheet URLs of a page, absolute, http(s) only, the first [max] in page order.
pub fn extract_assets(html: &str, page_url: &str, ignore_hosts: &[String], max: usize) -> Vec<String> {
    let mut found: Vec<(usize, String)> = Vec::new();
    for pattern in [&*IMG, &*SCRIPT] {
        found.extend(pattern.captures_iter(html).map(|capture| (capture.get(0).map_or(0, |whole| whole.start()), capture[1].trim().to_string())));
    }
    found.extend(stylesheet_links(html));
    found.sort_by_key(|(index, _)| *index);
    let Ok(base) = Url::parse(page_url) else {
        return Vec::new();
    };
    let mut urls: Vec<String> = Vec::new();
    for (_, value) in found {
        if value.starts_with("data:") {
            continue;
        }
        let Ok(url) = base.join(&value.replace("&amp;", "&")) else {
            continue;
        };
        if !["http", "https"].contains(&url.scheme()) || is_ignored(url.host_str().unwrap_or(""), ignore_hosts) {
            continue;
        }
        let href = url.to_string();
        if !urls.contains(&href) {
            urls.push(href);
        }
        if urls.len() == max {
            break;
        }
    }
    urls
}

/// Checks each asset with [request] (HEAD, then GET when HEAD is refused); returns `{checked, failed}`.
pub async fn check_assets<F, Fut>(urls: Vec<String>, request: F) -> Value
where
    F: Fn(String, &'static str) -> Fut,
    Fut: Future<Output = Result<u16, Failure>>,
{
    let mut failed = Vec::new();
    for batch in urls.chunks(PARALLEL) {
        let results = futures_util::future::join_all(batch.iter().map(|url| {
            let request = &request;
            async move {
                let mut result = request(url.clone(), "HEAD").await;
                if matches!(result, Ok(405 | 501)) {
                    result = request(url.clone(), "GET").await;
                }
                match result {
                    Ok(status) if status < 400 => None,
                    Ok(status) => Some(json!({ "url": url, "status": status })),
                    Err(error) => Some(json!({ "url": url, "error": error.message })),
                }
            }
        }))
        .await;
        failed.extend(results.into_iter().flatten());
    }
    json!({ "checked": urls.len(), "failed": failed })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_assets_in_page_order() {
        let html = r#"<html><head><link rel="stylesheet" href="/a.css"><script src="https://cdn.example/app.js?x=1&amp;y=2"></script>
            <link rel=icon href="/favicon.ico"><LINK HREF='/b.css' REL='stylesheet'></head>
            <body><img alt="x" src="logo.png"><img src="data:image/png;base64,AAA"><img src="/a.css"><img src="ftp://x/y"></body></html>"#;
        assert_eq!(
            extract_assets(html, "https://example.com/dir/page", &[], MAX_ASSETS),
            vec!["https://example.com/a.css", "https://cdn.example/app.js?x=1&y=2", "https://example.com/b.css", "https://example.com/dir/logo.png"]
        );
        assert_eq!(
            extract_assets(html, "https://example.com/", &["*.example".to_string()], MAX_ASSETS),
            vec!["https://example.com/a.css", "https://example.com/b.css", "https://example.com/logo.png"]
        );
        let many: String = (0..40).map(|i| format!("<img src=\"/{i}.png\">")).collect();
        assert_eq!(extract_assets(&many, "https://example.com/", &[], MAX_ASSETS).len(), 30);
    }

    #[tokio::test]
    async fn retries_with_get_when_head_is_refused() {
        let urls = vec!["https://a/1".to_string(), "https://a/2".to_string(), "https://a/3".to_string()];
        let result = check_assets(urls, |url, method| async move {
            match (url.as_str(), method) {
                ("https://a/1", "HEAD") => Ok(405),
                ("https://a/1", _) => Ok(200),
                ("https://a/2", _) => Ok(404),
                _ => Err(Failure::plain("fetch failed")),
            }
        })
        .await;
        assert_eq!(result, json!({"checked": 3, "failed": [{"url": "https://a/2", "status": 404}, {"url": "https://a/3", "error": "fetch failed"}]}));
    }
}
