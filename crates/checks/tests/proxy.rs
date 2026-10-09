//! Checks through HTTP_PROXY and HTTPS_PROXY, pointing at a proxy that refuses with the status in the target's port.
mod common;

use common::{expect_all, fixtures};
use serde_json::{Value, json};

fn refused_by_the_proxy(status: u16) -> Vec<(&'static str, Value)> {
    vec![("status", json!("down")), ("error", json!(format!("The proxy refused the request: HTTP {status}")))]
}

#[test]
fn http_check_names_the_proxy_when_it_refuses() {
    fixtures(true);
    expect_all(vec![
        ("tunnel, 403", "http", json!({ "url": "https://localhost:1403/" }), refused_by_the_proxy(403)),
        ("tunnel, credentials asked", "http", json!({ "url": "https://localhost:1407/" }), refused_by_the_proxy(407)),
        ("tunnel, 502", "http", json!({ "url": "https://localhost:1502/" }), refused_by_the_proxy(502)),
        ("forwarded, credentials asked", "http", json!({ "url": "http://localhost:1407/" }), refused_by_the_proxy(407)),
    ]);
}

#[test]
fn a_forwarded_403_is_the_target_answering() {
    fixtures(true);
    expect_all(vec![
        ("http", "http", json!({ "url": "http://localhost:1403/" }), vec![("status", json!("down")), ("httpStatus", json!(403)), ("error", Value::Null)]),
        (
            "mcp",
            "mcp",
            json!({ "url": "http://localhost:1403/mcp" }),
            vec![("status", json!("down")), ("error", json!("The MCP server refused the request: HTTP 403")), ("errorCode", json!("AUTH_FAILED"))],
        ),
    ]);
}

#[test]
fn mcp_check_names_the_proxy_when_it_refuses() {
    fixtures(true);
    let refused = |status: u16| {
        let mut expected = refused_by_the_proxy(status);
        expected.push(("errorCode", json!("CONNECT_FAILED")));
        expected
    };
    expect_all(vec![
        ("tunnel, 403", "mcp", json!({ "url": "https://localhost:1403/mcp" }), refused(403)),
        ("forwarded, credentials asked", "mcp", json!({ "url": "http://localhost:1407/mcp" }), refused(407)),
    ]);
}
