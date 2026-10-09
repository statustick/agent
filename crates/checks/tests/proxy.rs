//! Checks through HTTP_PROXY and HTTPS_PROXY, pointing at a proxy that refuses with the status in the target's port.
mod common;

use common::{expect_all, fixtures};
use serde_json::{Value, json};

#[test]
fn refusing_proxy() {
    fixtures(true);
    expect_all(vec![
        (
            "proxy refuses a tunnel with 403",
            "http",
            json!({ "url": "https://localhost:1403/" }),
            vec![("status", json!("down")), ("error", json!("The proxy refused the request: HTTP 403")), ("errorType", json!("Error"))],
        ),
        (
            "proxy asks for credentials for a tunnel",
            "http",
            json!({ "url": "https://localhost:1407/" }),
            vec![("status", json!("down")), ("error", json!("The proxy refused the request: HTTP 407"))],
        ),
        (
            "proxy fails a tunnel with 502",
            "http",
            json!({ "url": "https://localhost:1502/" }),
            vec![("status", json!("down")), ("error", json!("The proxy refused the request: HTTP 502"))],
        ),
        (
            "forwarding proxy asks for credentials",
            "http",
            json!({ "url": "http://localhost:1407/" }),
            vec![("status", json!("down")), ("error", json!("The proxy refused the request: HTTP 407"))],
        ),
        (
            "forwarding proxy answers 403",
            "http",
            json!({ "url": "http://localhost:1403/" }),
            vec![("status", json!("down")), ("httpStatus", json!(403)), ("error", Value::Null)],
        ),
        (
            "mcp proxy refuses a tunnel with 403",
            "mcp",
            json!({ "url": "https://localhost:1403/mcp" }),
            vec![("status", json!("down")), ("error", json!("The proxy refused the request: HTTP 403")), ("errorCode", json!("CONNECT_FAILED"))],
        ),
        (
            "mcp forwarding proxy asks for credentials",
            "mcp",
            json!({ "url": "http://localhost:1407/mcp" }),
            vec![("status", json!("down")), ("error", json!("The proxy refused the request: HTTP 407")), ("errorCode", json!("CONNECT_FAILED"))],
        ),
        (
            "mcp forwarding proxy answers 403",
            "mcp",
            json!({ "url": "http://localhost:1403/mcp" }),
            vec![("status", json!("down")), ("error", json!("The MCP server refused the request: HTTP 403")), ("errorCode", json!("AUTH_FAILED"))],
        ),
    ]);
}
