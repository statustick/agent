//! StatusTick's check engine: HTTP, TCP, ping, DNS, TLS certificate, gRPC health, SMTP, IMAP and MCP checks with the
//! target rules. Results keep the field names and error codes StatusTick expects.
pub mod assets;
pub mod blocking;
pub mod certificate;
pub mod connection;
pub mod dns;
pub mod grpc;
pub mod http;
pub mod json;
#[cfg(feature = "legacy-tls")]
pub mod legacy_tls;
pub mod mail;
pub mod mcp;
pub mod multi;
pub mod ping;
pub mod proxy;
pub mod targets;
pub mod tcp;
pub mod tls;
pub mod util;

use serde_json::{Map, Value};

/// The check types [run_check] knows.
pub const CHECK_TYPES: [&str; 9] = ["http", "tcp", "ping", "dns", "ssl", "grpc", "smtp", "imap", "mcp"];

/// Runs one check of [kind] with the fields of [request]; None for a kind it does not know.
pub async fn run_check(kind: &str, request: &Map<String, Value>) -> Option<Value> {
    Some(match kind {
        "http" => http::http_check(request).await,
        "tcp" => tcp::tcp_check(request).await,
        "ping" => ping::ping_check(request).await,
        "dns" => dns::dns_check(request).await,
        "ssl" => certificate::ssl_check(request).await,
        "grpc" => grpc::grpc_check(request).await,
        "smtp" => mail::smtp_check(request).await,
        "imap" => mail::imap_check(request).await,
        "mcp" => mcp::mcp_check(request).await,
        _ => return None,
    })
}
