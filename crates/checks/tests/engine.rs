mod common;

use common::{expect_all, fixtures};
use serde_json::{Value, json};

fn parse(text: &str) -> Value {
    serde_json::from_str(text).expect("expected JSON")
}

#[test]
fn http() {
    let p = &fixtures(false).ports;
    let http = p.http;
    let web = format!("http://localhost:{http}");
    expect_all(vec![
        (
            "http up with keyword",
            "http",
            json!({ "url": format!("{web}/ok"), "expectedText": "world" }),
            vec![
                ("status", json!("up")),
                ("httpStatus", json!(200)),
                ("details.textMatch", json!(true)),
                ("details.headers.x-seen-user-agent", json!("StatusTick/2.0 (+https://statustick.com/docs/checks)")),
                ("details.headers.x-seen-method", json!("GET")),
            ],
        ),
        (
            "http keyword must not be there",
            "http",
            json!({ "url": format!("{web}/ok"), "expectedText": "world", "textMode": "not_contains" }),
            vec![("status", json!("down")), ("details.textMatch", json!(false))],
        ),
        (
            "http keyword any case",
            "http",
            json!({ "url": format!("{web}/ok"), "expectedText": "WORLD", "caseSensitive": false }),
            vec![("status", json!("up")), ("details.textMatch", json!(true))],
        ),
        (
            "http keyword case-sensitive miss",
            "http",
            json!({ "url": format!("{web}/ok"), "expectedText": "WORLD" }),
            vec![("status", json!("down")), ("details.textMatch", json!(false))],
        ),
        (
            "http expected status differs",
            "http",
            json!({ "url": format!("{web}/ok"), "expectedStatus": 201 }),
            vec![("status", json!("down")), ("httpStatus", json!(200)), ("details.expectedStatus", json!(201))],
        ),
        ("http 404", "http", json!({ "url": format!("{web}/nope") }), vec![("status", json!("down")), ("httpStatus", json!(404))]),
        ("http 500", "http", json!({ "url": format!("{web}/status/500") }), vec![("status", json!("down")), ("httpStatus", json!(500))]),
        (
            "http firewall challenge",
            "http",
            json!({ "url": format!("{web}/blocked") }),
            vec![
                ("status", json!("blocked")),
                ("httpStatus", json!(403)),
                ("error", json!("Blocked by the site's firewall: Cloudflare challenge page")),
                ("errorType", json!("BLOCKED")),
            ],
        ),
        (
            "http plain 403",
            "http",
            json!({ "url": format!("{web}/forbidden") }),
            vec![("status", json!("down")), ("httpStatus", json!(403)), ("errorType", Value::Null)],
        ),
        (
            "http 403 expected",
            "http",
            json!({ "url": format!("{web}/blocked"), "expectedStatus": 403 }),
            vec![("status", json!("up")), ("httpStatus", json!(403))],
        ),
        ("http redirect followed", "http", json!({ "url": format!("{web}/redirect") }), vec![("status", json!("up")), ("httpStatus", json!(200))]),
        (
            "http redirect not followed",
            "http",
            json!({ "url": format!("{web}/redirect"), "followRedirects": false }),
            vec![("status", json!("up")), ("httpStatus", json!(302)), ("details.headers.location", json!("/ok"))],
        ),
        (
            "http 303 turns POST into GET",
            "http",
            json!({ "url": format!("{web}/redirect303"), "method": "POST", "body": "x=1", "bodyType": "FORM_PARAMS" }),
            vec![
                ("status", json!("up")),
                ("httpStatus", json!(200)),
                ("method", json!("POST")),
                ("details.headers.x-seen-method", json!("GET")),
                ("details.headers.x-seen-body-length", json!("0")),
            ],
        ),
        (
            "http redirect loop stops after 5 hops",
            "http",
            json!({ "url": format!("{web}/redirect-loop") }),
            vec![("status", json!("up")), ("httpStatus", json!(302)), ("details.headers.location", json!("/redirect-loop"))],
        ),
        (
            "http redirect to an internal address",
            "http",
            json!({ "url": format!("{web}/redirect-internal") }),
            vec![("status", json!("down")), ("error", json!("target not allowed")), ("errorType", json!("TargetNotAllowed"))],
        ),
        (
            "http JSON assertions pass",
            "http",
            json!({ "url": format!("{web}/json"), "json": [{ "path": "$.status", "equals": "ok" }, { "path": "$.items[0].id", "equals": 7 }, { "path": "$.error", "exists": false }] }),
            vec![("status", json!("up")), ("error", Value::Null)],
        ),
        (
            "http JSON assertion fails",
            "http",
            json!({ "url": format!("{web}/json"), "json": [{ "path": "$.count", "equals": "1" }] }),
            vec![("status", json!("down")), ("error", json!("JSON path $.count is not the expected value")), ("errorType", json!("JSON_ASSERTION"))],
        ),
        (
            "http JSON on a text body",
            "http",
            json!({ "url": format!("{web}/ok"), "json": [{ "path": "$.a", "exists": true }] }),
            vec![("status", json!("down")), ("error", json!("The response is not JSON, so $.a cannot be checked")), ("errorType", json!("JSON_ASSERTION"))],
        ),
        (
            "http POST JSON body",
            "http",
            json!({ "url": format!("{web}/ok"), "method": "post", "body": "{\"a\":1}", "bodyType": "JSON" }),
            vec![
                ("status", json!("up")),
                ("details.headers.x-seen-method", json!("POST")),
                ("details.headers.x-seen-content-type", json!("application/json")),
                ("details.headers.x-seen-body-length", json!("7")),
            ],
        ),
        (
            "http content type from headers kept",
            "http",
            json!({ "url": format!("{web}/ok"), "method": "PUT", "body": "x", "headers": { "Content-Type": "text/csv" } }),
            vec![
                ("status", json!("up")),
                ("details.headers.x-seen-method", json!("PUT")),
                ("details.headers.x-seen-content-type", json!("text/csv")),
                ("details.headers.x-seen-body-length", json!("1")),
            ],
        ),
        (
            "http no body with GET",
            "http",
            json!({ "url": format!("{web}/ok"), "body": "ignored" }),
            vec![("status", json!("up")), ("details.headers.x-seen-body-length", json!("0"))],
        ),
        (
            "http custom User-Agent and header",
            "http",
            json!({ "url": format!("{web}/ok"), "headers": { "user-agent": "Probe/1.0", "X-Custom": "yes" } }),
            vec![("status", json!("up")), ("details.headers.x-seen-user-agent", json!("Probe/1.0")), ("details.headers.x-seen-x-custom", json!("yes"))],
        ),
        (
            "http gzip body",
            "http",
            json!({ "url": format!("{web}/gzip"), "expectedText": "compressed hello" }),
            vec![("status", json!("up")), ("details.textMatch", json!(true))],
        ),
        (
            "http brotli body",
            "http",
            json!({ "url": format!("{web}/brotli"), "expectedText": "brotli hello" }),
            vec![("status", json!("up")), ("details.textMatch", json!(true))],
        ),
        (
            "http HEAD",
            "http",
            json!({ "url": format!("{web}/ok"), "method": "HEAD" }),
            vec![("status", json!("up")), ("httpStatus", json!(200)), ("details.headers.x-seen-method", json!("HEAD"))],
        ),
        ("http 204", "http", json!({ "url": format!("{web}/nocontent") }), vec![("status", json!("up")), ("httpStatus", json!(204))]),
        (
            "http UTF-8 with BOM",
            "http",
            json!({ "url": format!("{web}/utf8"), "expectedText": "naïve café" }),
            vec![("status", json!("up")), ("details.textMatch", json!(true))],
        ),
        (
            "http body cut at 5 MB",
            "http",
            json!({ "url": format!("{web}/big"), "expectedText": "needle" }),
            vec![("status", json!("down")), ("httpStatus", json!(200)), ("details.textMatch", json!(false))],
        ),
        (
            "http assets",
            "http",
            json!({ "url": format!("{web}/html"), "assets": { "ignoreHosts": [] } }),
            vec![
                ("status", json!("up")),
                ("details.assets.checked", json!(4)),
                (
                    "details.assets.failed",
                    parse(&format!(
                        r#"[{{"url": "{web}/missing.js", "status": 404}}, {{"url": "http://127.0.0.1:{http}/x.png", "error": "target not allowed"}}]"#
                    )),
                ),
            ],
        ),
        (
            "http assets with ignored host",
            "http",
            json!({ "url": format!("{web}/html"), "assets": { "ignoreHosts": ["127.0.0.1"] } }),
            vec![
                ("status", json!("up")),
                ("details.assets.checked", json!(3)),
                ("details.assets.failed", parse(&format!(r#"[{{"url": "{web}/missing.js", "status": 404}}]"#))),
            ],
        ),
        (
            "http timeout",
            "http",
            json!({ "url": format!("{web}/slow"), "timeout": 500 }),
            vec![("status", json!("down")), ("error", json!("This operation was aborted")), ("errorType", json!("AbortError"))],
        ),
        (
            "http connection refused",
            "http",
            json!({ "url": format!("http://localhost:{}/", p.closed) }),
            vec![("status", json!("down")), ("error", json!("fetch failed")), ("errorType", json!("TypeError"))],
        ),
        (
            "http invalid URL",
            "http",
            json!({ "url": "not a url" }),
            vec![("status", json!("down")), ("error", json!("Invalid URL")), ("errorType", json!("TypeError"))],
        ),
        (
            "http unknown host",
            "http",
            json!({ "url": "http://parity-unknown-host.invalid/" }),
            vec![("status", json!("down")), ("error", json!("getaddrinfo ENOTFOUND parity-unknown-host.invalid")), ("errorType", json!("Error"))],
        ),
        (
            "http internal address refused",
            "http",
            json!({ "url": format!("http://127.0.0.1:{}/ok", p.http) }),
            vec![("status", json!("down")), ("error", json!("target not allowed")), ("errorType", json!("TargetNotAllowed"))],
        ),
        ("http over IPv6 only", "http", json!({ "url": format!("{web}/ok"), "ipVersion": "6" }), vec![("status", json!("up")), ("httpStatus", json!(200))]),
        ("http over IPv4 only", "http", json!({ "url": format!("{web}/ok"), "ipVersion": 4 }), vec![("status", json!("up")), ("httpStatus", json!(200))]),
        (
            "http no IPv6 address for an IPv4 literal",
            "http",
            json!({ "url": format!("http://127.0.0.1:{}/", p.http), "ipVersion": "6" }),
            vec![("status", json!("down")), ("error", json!("No IPv6 address (AAAA record) for 127.0.0.1")), ("errorType", json!("NoAddress"))],
        ),
        (
            "https trusted certificate",
            "http",
            json!({ "url": format!("https://localhost:{}/ok", p.https) }),
            vec![("status", json!("up")), ("httpStatus", json!(200)), ("details.legacyTLS", Value::Null)],
        ),
        (
            "https CBC ciphers only",
            "http",
            json!({ "url": format!("https://localhost:{}/ok", p.https_cbc), "expectedText": "world" }),
            vec![("status", json!("up")), ("details.textMatch", json!(true)), ("details.legacyTLS", json!(true)), ("details.tlsVersion", json!("TLSv1.2"))],
        ),
        (
            "https TLS 1.0 only",
            "http",
            json!({ "url": format!("https://localhost:{}/ok", p.https_tls10), "expectedText": "world" }),
            vec![("status", json!("up")), ("details.textMatch", json!(true)), ("details.legacyTLS", json!(true)), ("details.tlsVersion", json!("TLSv1"))],
        ),
        (
            "https TLS 1.1 only",
            "http",
            json!({ "url": format!("https://localhost:{}/ok", p.https_tls11), "expectedText": "world" }),
            vec![("status", json!("up")), ("details.textMatch", json!(true)), ("details.legacyTLS", json!(true)), ("details.tlsVersion", json!("TLSv1.1"))],
        ),
        (
            "https weak key over TLS 1.2+",
            "http",
            json!({ "url": format!("https://localhost:{}/ok", p.https_weak_key) }),
            vec![("status", json!("down")), ("error", json!("fetch failed"))],
        ),
        (
            "https weak key over TLS 1.0",
            "http",
            json!({ "url": format!("https://localhost:{}/ok", p.https_weak_key_tls10), "expectedText": "world" }),
            vec![("status", json!("up")), ("details.legacyTLS", json!(true)), ("details.tlsVersion", json!("TLSv1")), ("details.weakKey", json!(true))],
        ),
        (
            "https untrusted certificate",
            "http",
            json!({ "url": format!("https://localhost:{}/", p.tls["self-signed"]) }),
            vec![("status", json!("down")), ("error", json!("fetch failed")), ("errorType", json!("TypeError"))],
        ),
        (
            "https URL with credentials",
            "http",
            json!({ "url": format!("http://user:pass@localhost:{}/ok", p.http) }),
            vec![
                ("status", json!("down")),
                ("error", json!(format!("Request cannot be constructed from a URL that includes credentials: http://user:pass@localhost:{http}/ok"))),
                ("errorType", json!("TypeError")),
            ],
        ),
        (
            "http unsupported scheme",
            "http",
            json!({ "url": format!("ftp://localhost:{}/", p.http) }),
            vec![("status", json!("down")), ("error", json!("fetch failed")), ("errorType", json!("TypeError"))],
        ),
    ]);
}

#[test]
fn tcp_ping_dns() {
    let p = &fixtures(false).ports;
    let closed = p.closed;
    expect_all(vec![
        ("tcp open", "tcp", json!({ "host": "localhost", "port": p.http }), vec![("status", json!("up")), ("error", Value::Null)]),
        ("tcp closed", "tcp", json!({ "host": "localhost", "port": p.closed }), vec![("status", json!("down")), ("errorCode", json!("ECONNREFUSED"))]),
        (
            "tcp IPv4 only closed",
            "tcp",
            json!({ "host": "localhost", "port": p.closed, "ipVersion": "4" }),
            vec![("status", json!("down")), ("error", json!(format!("connect ECONNREFUSED 127.0.0.1:{closed}"))), ("errorCode", json!("ECONNREFUSED"))],
        ),
        (
            "tcp internal refused",
            "tcp",
            json!({ "host": "10.1.2.3", "port": 22 }),
            vec![("status", json!("down")), ("error", json!("target not allowed")), ("errorCode", json!("TARGET_NOT_ALLOWED"))],
        ),
        (
            "tcp no IPv4 address",
            "tcp",
            json!({ "host": "::1", "port": 22, "ipVersion": "4" }),
            vec![("status", json!("down")), ("error", json!("No IPv4 address (A record) for ::1")), ("errorCode", json!("NO_ADDRESS"))],
        ),
        (
            "tcp unknown host",
            "tcp",
            json!({ "host": "parity-unknown-host.invalid", "port": 80 }),
            vec![("status", json!("down")), ("error", json!("getaddrinfo ENOTFOUND parity-unknown-host.invalid")), ("errorCode", json!("ENOTFOUND"))],
        ),
        ("tcp timeout", "tcp", json!({ "host": "192.0.2.1", "port": 80, "timeout": 500 }), vec![("status", json!("down"))]),
        (
            "ping localhost",
            "ping",
            json!({ "host": "localhost", "count": 2, "timeout": 3000, "ipVersion": "4" }),
            vec![("status", json!("up")), ("packetLoss", json!("0.000")), ("details.alive", json!(true))],
        ),
        ("ping localhost over IPv6", "ping", json!({ "host": "localhost", "timeout": 3000, "ipVersion": "6" }), vec![("host", json!("localhost"))]),
        ("ping metadata refused", "ping", json!({ "host": "169.254.169.254" }), vec![("status", json!("down")), ("error", json!("target not allowed"))]),
        (
            "ping unknown host",
            "ping",
            json!({ "host": "parity-unknown-host.invalid" }),
            vec![("status", json!("down")), ("error", json!("getaddrinfo ENOTFOUND parity-unknown-host.invalid"))],
        ),
        (
            "dns unknown type",
            "dns",
            json!({ "hostname": "example.com", "recordType": "PTR" }),
            vec![("status", json!("down")), ("error", json!("Unsupported record type: PTR"))],
        ),
        (
            "dns unknown host",
            "dns",
            json!({ "hostname": "parity-unknown-host.invalid" }),
            vec![
                ("status", json!("down")),
                ("recordType", json!("A")),
                ("error", json!("queryA ENOTFOUND parity-unknown-host.invalid")),
                ("errorCode", json!("ENOTFOUND")),
            ],
        ),
    ]);
}

#[test]
fn ssl() {
    let p = &fixtures(false).ports;
    expect_all(vec![
        (
            "ssl trusted",
            "ssl",
            json!({ "host": "localhost", "port": p.tls["localhost"], "protocols": true }),
            vec![
                ("status", json!("up")),
                ("protocols", json!(["TLSv1.2", "TLSv1.3"])),
                ("certificate.valid", json!(true)),
                ("certificate.error", Value::Null),
                ("certificate.validFrom", json!("2025-01-01T00:00:00.000Z")),
                ("certificate.validTo", json!("2099-12-31T00:00:00.000Z")),
                ("certificate.lifetimeDays", json!(27392)),
                ("certificate.issuer", json!("StatusTick Parity")),
                ("certificate.subject", json!("localhost")),
                ("certificate.hostnameMatch", json!(true)),
                ("certificate.chain[1].subject", json!("Parity Test CA")),
            ],
        ),
        (
            "ssl expired",
            "ssl",
            json!({ "host": "localhost", "port": p.tls["expired"] }),
            vec![
                ("status", json!("down")),
                ("error", json!("Certificate has expired")),
                ("certificate.valid", json!(false)),
                ("certificate.lifetimeDays", json!(31)),
            ],
        ),
        (
            "ssl other host",
            "ssl",
            json!({ "host": "localhost", "port": p.tls["other-host"] }),
            vec![
                ("status", json!("down")),
                (
                    "error",
                    json!(
                        "Hostname mismatch: Hostname/IP does not match certificate's altnames: Host: localhost. is not in the cert's altnames: DNS:other.test, DNS:*.other.test"
                    ),
                ),
                ("certificate.subject", json!("other.test")),
                ("certificate.hostnameMatch", json!(false)),
            ],
        ),
        (
            "ssl unknown CA in chain",
            "ssl",
            json!({ "host": "localhost", "port": p.tls["unknown-ca"] }),
            vec![
                ("status", json!("down")),
                ("error", json!("Certificate is not trusted: SELF_SIGNED_CERT_IN_CHAIN")),
                ("certificate.issuer", json!("Nobody")),
                ("certificate.chain[1].subject", json!("Unknown Test CA")),
            ],
        ),
        (
            "ssl self-signed",
            "ssl",
            json!({ "host": "localhost", "port": p.tls["self-signed"] }),
            vec![
                ("status", json!("down")),
                ("error", json!("Certificate is not trusted: DEPTH_ZERO_SELF_SIGNED_CERT")),
                ("certificate.issuer", json!("localhost")),
                ("certificate.hostnameMatch", json!(true)),
            ],
        ),
        (
            "ssl no TLS on the port",
            "ssl",
            json!({ "host": "localhost", "port": p.tls["plain"] }),
            vec![("status", json!("error")), ("errorCode", json!("ERR_SSL_WRONG_VERSION_NUMBER"))],
        ),
        ("ssl closed port", "ssl", json!({ "host": "localhost", "port": p.closed }), vec![("status", json!("error")), ("errorCode", json!("ECONNREFUSED"))]),
        (
            "ssl CBC ciphers only",
            "ssl",
            json!({ "host": "localhost", "port": p.https_cbc, "protocols": true }),
            vec![
                ("status", json!("up")),
                ("protocols", json!(["TLSv1.2"])),
                ("legacyTLS", json!(true)),
                ("tlsVersion", json!("TLSv1.2")),
                ("certificate.valid", json!(true)),
            ],
        ),
        (
            "ssl TLS 1.0 only",
            "ssl",
            json!({ "host": "localhost", "port": p.https_tls10, "protocols": true }),
            vec![("status", json!("up")), ("protocols", json!(["TLSv1"])), ("legacyTLS", json!(true)), ("tlsVersion", json!("TLSv1"))],
        ),
        (
            "ssl TLS 1.1 only",
            "ssl",
            json!({ "host": "localhost", "port": p.https_tls11, "protocols": true }),
            vec![("status", json!("up")), ("protocols", json!(["TLSv1.1"])), ("legacyTLS", json!(true)), ("tlsVersion", json!("TLSv1.1"))],
        ),
        (
            "ssl weak key over TLS 1.2+",
            "ssl",
            json!({ "host": "localhost", "port": p.https_weak_key, "protocols": true }),
            vec![("status", json!("error")), ("error", json!("certificate key too weak: RSA 1024 bits")), ("errorCode", json!("ERR_SSL_EE_KEY_TOO_SMALL"))],
        ),
        (
            "ssl weak key over TLS 1.0",
            "ssl",
            json!({ "host": "localhost", "port": p.https_weak_key_tls10, "protocols": true }),
            vec![("status", json!("up")), ("legacyTLS", json!(true)), ("tlsVersion", json!("TLSv1")), ("weakKey", json!(true))],
        ),
        (
            "ssl internal refused",
            "ssl",
            json!({ "host": "127.0.0.1", "port": p.tls["localhost"] }),
            vec![("status", json!("error")), ("error", json!("target not allowed")), ("errorCode", json!("TARGET_NOT_ALLOWED"))],
        ),
    ]);
}

#[test]
fn grpc() {
    let p = &fixtures(false).ports;
    expect_all(vec![
        (
            "grpc serving",
            "grpc",
            json!({ "host": "localhost", "port": p.grpc }),
            vec![("status", json!("up")), ("details.grpcStatus", json!(0)), ("details.servingStatus", json!("SERVING"))],
        ),
        (
            "grpc service serving",
            "grpc",
            json!({ "host": "localhost", "port": p.grpc, "service": "api" }),
            vec![("status", json!("up")), ("details.servingStatus", json!("SERVING"))],
        ),
        (
            "grpc not serving",
            "grpc",
            json!({ "host": "localhost", "port": p.grpc, "service": "down" }),
            vec![
                ("status", json!("down")),
                ("error", json!("Health status NOT_SERVING")),
                ("errorCode", json!("GRPC_NOT_SERVING")),
                ("details.servingStatus", json!("NOT_SERVING")),
            ],
        ),
        (
            "grpc unknown service",
            "grpc",
            json!({ "host": "localhost", "port": p.grpc, "service": "unknown" }),
            vec![
                ("status", json!("down")),
                ("error", json!("gRPC status 5 NOT_FOUND: the server does not know the service \"unknown\"")),
                ("errorCode", json!("GRPC_STATUS")),
                ("details.grpcStatus", json!(5)),
            ],
        ),
        (
            "grpc no health service",
            "grpc",
            json!({ "host": "localhost", "port": p.grpc, "service": "unimplemented" }),
            vec![
                ("status", json!("down")),
                ("error", json!("gRPC status 12 UNIMPLEMENTED: the server has no grpc.health.v1.Health service")),
                ("errorCode", json!("GRPC_STATUS")),
                ("details.grpcStatus", json!(12)),
            ],
        ),
        (
            "grpc over TLS",
            "grpc",
            json!({ "host": "localhost", "port": p.grpc_tls, "tlsMode": "TLS" }),
            vec![
                ("status", json!("up")),
                ("details.tlsVersion", json!("TLSv1.3")),
                ("details.certificateExpiresAt", json!("2099-12-31T00:00:00.000Z")),
                ("details.servingStatus", json!("SERVING")),
            ],
        ),
        (
            "grpc TLS to an untrusted server",
            "grpc",
            json!({ "host": "localhost", "port": p.tls["self-signed"], "tlsMode": "TLS" }),
            vec![("status", json!("down")), ("errorCode", json!("TLS_FAILED"))],
        ),
        (
            "grpc TLS without verification, no h2",
            "grpc",
            json!({ "host": "localhost", "port": p.tls["self-signed"], "tlsMode": "TLS", "tlsVerify": false }),
            vec![
                ("status", json!("down")),
                ("error", json!("The server does not speak HTTP/2 over TLS (no ALPN h2)")),
                ("errorCode", json!("GRPC_INVALID_ANSWER")),
            ],
        ),
        (
            "grpc bad TLS mode",
            "grpc",
            json!({ "host": "localhost", "port": p.grpc, "tlsMode": "STARTTLS" }),
            vec![("status", json!("error")), ("error", json!("tlsMode must be NONE or TLS for gRPC")), ("errorCode", json!("INVALID_REQUEST"))],
        ),
        ("grpc closed port", "grpc", json!({ "host": "localhost", "port": p.closed }), vec![("status", json!("down")), ("errorCode", json!("CONNECT_FAILED"))]),
        (
            "grpc internal refused",
            "grpc",
            json!({ "host": "10.0.0.1", "port": 50051 }),
            vec![("status", json!("down")), ("error", json!("target not allowed")), ("errorCode", json!("TARGET_NOT_ALLOWED"))],
        ),
    ]);
}

#[test]
fn mail() {
    let p = &fixtures(false).ports;
    expect_all(vec![
        (
            "smtp with STARTTLS offered",
            "smtp",
            json!({ "host": "localhost", "port": p.smtp }),
            vec![
                ("status", json!("up")),
                ("details.greetingCode", json!("220")),
                ("details.startTLSOffered", json!(true)),
                ("details.tlsVersion", Value::Null),
            ],
        ),
        (
            "smtp STARTTLS",
            "smtp",
            json!({ "host": "localhost", "port": p.smtp, "tlsMode": "STARTTLS" }),
            vec![
                ("status", json!("up")),
                ("details.startTLSOffered", json!(true)),
                ("details.tlsVersion", json!("TLSv1.3")),
                ("details.certificateExpiresAt", json!("2099-12-31T00:00:00.000Z")),
            ],
        ),
        (
            "smtp STARTTLS required, not offered",
            "smtp",
            json!({ "host": "localhost", "port": p.smtp_no_tls, "requireStartTLS": true }),
            vec![
                ("status", json!("down")),
                ("error", json!("The SMTP server does not offer STARTTLS")),
                ("errorCode", json!("STARTTLS_NOT_OFFERED")),
                ("details.startTLSOffered", json!(false)),
            ],
        ),
        (
            "smtp STARTTLS mode, not offered",
            "smtp",
            json!({ "host": "localhost", "port": p.smtp_no_tls, "tlsMode": "STARTTLS" }),
            vec![("status", json!("down")), ("errorCode", json!("STARTTLS_NOT_OFFERED"))],
        ),
        (
            "smtp greeting 554",
            "smtp",
            json!({ "host": "localhost", "port": p.smtp_554 }),
            vec![
                ("status", json!("down")),
                ("error", json!("The SMTP greeting is 554, not 220")),
                ("errorCode", json!("SMTP_GREETING")),
                ("details.greetingCode", json!("554")),
            ],
        ),
        (
            "smtp bytes after STARTTLS answer",
            "smtp",
            json!({ "host": "localhost", "port": p.smtp_inject, "tlsMode": "STARTTLS" }),
            vec![("status", json!("down")), ("error", json!("The server sent more after its STARTTLS answer")), ("errorCode", json!("STARTTLS_FAILED"))],
        ),
        (
            "smtps",
            "smtp",
            json!({ "host": "localhost", "port": p.smtps, "tlsMode": "TLS" }),
            vec![
                ("status", json!("up")),
                ("details.tlsVersion", json!("TLSv1.3")),
                ("details.greetingCode", json!("220")),
                ("details.startTLSOffered", json!(false)),
            ],
        ),
        (
            "smtp requireStartTLS with TLS",
            "smtp",
            json!({ "host": "localhost", "port": p.smtps, "tlsMode": "TLS", "requireStartTLS": true }),
            vec![("status", json!("error")), ("error", json!("requireStartTLS needs tlsMode NONE or STARTTLS")), ("errorCode", json!("INVALID_REQUEST"))],
        ),
        (
            "smtp timeout without greeting",
            "smtp",
            json!({ "host": "localhost", "port": p.tls["localhost"], "timeout": 500 }),
            vec![("status", json!("down")), ("error", json!("Timed out after 500 ms")), ("errorCode", json!("TIMEOUT"))],
        ),
        (
            "imap capabilities in greeting",
            "imap",
            json!({ "host": "localhost", "port": p.imap }),
            vec![("status", json!("up")), ("details.greetingCode", json!("OK")), ("details.startTLSOffered", json!(true))],
        ),
        (
            "imap STARTTLS",
            "imap",
            json!({ "host": "localhost", "port": p.imap, "tlsMode": "STARTTLS" }),
            vec![("status", json!("up")), ("details.tlsVersion", json!("TLSv1.3"))],
        ),
        (
            "imap asks for capabilities",
            "imap",
            json!({ "host": "localhost", "port": p.imap_no_caps }),
            vec![("status", json!("up")), ("details.startTLSOffered", json!(true))],
        ),
        (
            "imap BYE",
            "imap",
            json!({ "host": "localhost", "port": p.imap_bye }),
            vec![
                ("status", json!("down")),
                ("error", json!("The IMAP greeting is BYE: the server refuses connections")),
                ("errorCode", json!("IMAP_GREETING")),
                ("details.greetingCode", json!("BYE")),
            ],
        ),
        (
            "imap internal refused",
            "imap",
            json!({ "host": "192.168.1.1", "port": 143 }),
            vec![("status", json!("down")), ("error", json!("target not allowed")), ("errorCode", json!("TARGET_NOT_ALLOWED"))],
        ),
    ]);
}

#[test]
fn mcp() {
    let p = &fixtures(false).ports;
    let mcp = format!("http://localhost:{}", p.mcp);
    expect_all(vec![
        (
            "mcp JSON answers, two pages",
            "mcp",
            json!({ "url": format!("{mcp}/mcp") }),
            vec![
                ("status", json!("up")),
                ("details.protocolVersion", json!("2025-06-18")),
                ("details.serverName", json!("parity-server-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")),
                ("details.serverVersion", json!("1.2.3")),
                ("details.toolCount", json!(3)),
                ("details.toolsHash", json!("36ee5b48b3347cb08ce36de0fc67d49704bc2a23cab387b6d628a1493597b5ce")),
            ],
        ),
        (
            "mcp event stream answers",
            "mcp",
            json!({ "url": format!("{mcp}/mcp-sse") }),
            vec![
                ("status", json!("up")),
                ("details.toolCount", json!(3)),
                ("details.toolsHash", json!("36ee5b48b3347cb08ce36de0fc67d49704bc2a23cab387b6d628a1493597b5ce")),
            ],
        ),
        (
            "mcp auth header",
            "mcp",
            json!({ "url": format!("{mcp}/mcp-auth"), "authHeaderName": "X-Key", "authHeaderValue": "secret" }),
            vec![("status", json!("up")), ("details.toolCount", json!(3))],
        ),
        (
            "mcp refused credentials",
            "mcp",
            json!({ "url": format!("{mcp}/mcp-401") }),
            vec![("status", json!("down")), ("error", json!("The MCP server refused the request: HTTP 401")), ("errorCode", json!("AUTH_FAILED"))],
        ),
        (
            "mcp redirect",
            "mcp",
            json!({ "url": format!("{mcp}/mcp-redirect") }),
            vec![
                ("status", json!("down")),
                ("error", json!("The MCP server answered initialize with a redirect (HTTP 302); check the URL it redirects to")),
                ("errorCode", json!("MCP_INITIALIZE_FAILED")),
            ],
        ),
        (
            "mcp no tools",
            "mcp",
            json!({ "url": format!("{mcp}/mcp-empty") }),
            vec![
                ("status", json!("down")),
                ("error", json!("The MCP server lists no tools")),
                ("errorCode", json!("MCP_NO_TOOLS")),
                ("details.toolCount", json!(0)),
            ],
        ),
        (
            "mcp initialize 500",
            "mcp",
            json!({ "url": format!("{mcp}/mcp-500") }),
            vec![
                ("status", json!("down")),
                ("error", json!("The MCP server answered initialize with HTTP 500")),
                ("errorCode", json!("MCP_INITIALIZE_FAILED")),
            ],
        ),
        (
            "mcp JSON-RPC error",
            "mcp",
            json!({ "url": format!("{mcp}/mcp-rpc-error") }),
            vec![
                ("status", json!("down")),
                ("error", json!("The MCP server answered initialize with JSON-RPC error -32603")),
                ("errorCode", json!("MCP_INITIALIZE_FAILED")),
            ],
        ),
        (
            "mcp invalid initialize answer",
            "mcp",
            json!({ "url": format!("{mcp}/mcp-invalid") }),
            vec![("status", json!("down")), ("error", json!("The MCP server's initialize answer is not valid")), ("errorCode", json!("MCP_INITIALIZE_FAILED"))],
        ),
        (
            "mcp old protocol version",
            "mcp",
            json!({ "url": format!("{mcp}/mcp-old-version") }),
            vec![
                ("status", json!("down")),
                ("error", json!("The MCP server's protocol version is not supported")),
                ("errorCode", json!("MCP_INITIALIZE_FAILED")),
            ],
        ),
        (
            "mcp tools/list fails",
            "mcp",
            json!({ "url": format!("{mcp}/mcp-tools-fail") }),
            vec![
                ("status", json!("down")),
                ("error", json!("The MCP server answered tools/list with HTTP 500")),
                ("errorCode", json!("MCP_TOOLS_LIST_FAILED")),
            ],
        ),
        (
            "mcp repeated cursor",
            "mcp",
            json!({ "url": format!("{mcp}/mcp-loop") }),
            vec![("status", json!("down")), ("error", json!("tools/list repeats the same cursor")), ("errorCode", json!("MCP_TOOLS_LIST_FAILED"))],
        ),
        (
            "mcp closed port",
            "mcp",
            json!({ "url": format!("http://localhost:{}/mcp", p.closed) }),
            vec![("status", json!("down")), ("errorCode", json!("CONNECT_FAILED"))],
        ),
        (
            "mcp internal refused",
            "mcp",
            json!({ "url": format!("http://127.0.0.1:{}/mcp", p.mcp) }),
            vec![("status", json!("down")), ("error", json!("target not allowed")), ("errorCode", json!("TARGET_NOT_ALLOWED"))],
        ),
        (
            "mcp bad header name",
            "mcp",
            json!({ "url": format!("{mcp}/mcp"), "authHeaderName": "Host", "authHeaderValue": "x" }),
            vec![
                ("status", json!("error")),
                ("error", json!("authHeaderName is not a header name the check can send")),
                ("errorCode", json!("INVALID_HEADER")),
            ],
        ),
        (
            "mcp not http",
            "mcp",
            json!({ "url": "ws://localhost/mcp" }),
            vec![("status", json!("error")), ("error", json!("url must be an http or https URL")), ("errorCode", json!("INVALID_URL"))],
        ),
    ]);
}

/// The multi items run the drone's per-item logic; ping depends on the host's ICMP permissions.
#[test]
fn multi() {
    let p = &fixtures(false).ports;
    let web = format!("http://localhost:{}", p.http);
    let request = json!({ "checks": [
        { "type": "http", "url": format!("{web}/ok"), "expectedText": "hello" },
        { "type": "tcp", "host": "localhost", "port": p.http },
        { "type": "tcp", "host": "10.0.0.1", "port": 80 },
        { "type": "dns", "hostname": "parity-unknown-host.invalid" },
        { "type": "ping", "host": "localhost", "timeout": 2000 },
        { "type": "bogus" }
    ] });
    expect_all(vec![(
        "multi",
        "multi",
        request,
        vec![
            ("results[0].status", json!("up")),
            ("results[0].httpStatus", json!(200)),
            ("results[0].expectedText", json!("hello")),
            ("results[1].status", json!("up")),
            ("results[2].status", json!("error")),
            ("results[2].error", json!("target not allowed")),
            ("results[3].status", json!("error")),
            ("results[3].error", json!("queryA ENOTFOUND parity-unknown-host.invalid")),
            ("results[4].type", json!("ping")),
            ("results[5].status", json!("error")),
            ("results[5].error", json!("Unknown check type")),
        ],
    )]);
}

#[test]
#[ignore = "needs the internet"]
fn public_targets() {
    fixtures(false);
    let up = || vec![("status", json!("up"))];
    let down = || vec![("status", json!("down"))];
    expect_all(vec![
        ("public dns A", "dns", json!({ "hostname": "one.one.one.one", "recordType": "A" }), up()),
        ("public dns AAAA", "dns", json!({ "hostname": "one.one.one.one", "recordType": "AAAA" }), up()),
        ("public dns MX", "dns", json!({ "hostname": "gmail.com", "recordType": "MX" }), up()),
        ("public dns NS", "dns", json!({ "hostname": "github.com", "recordType": "NS" }), up()),
        ("public dns CAA", "dns", json!({ "hostname": "google.com", "recordType": "CAA" }), up()),
        ("public dns CNAME", "dns", json!({ "hostname": "www.github.com", "recordType": "CNAME" }), up()),
        ("public dns no CNAME", "dns", json!({ "hostname": "github.com", "recordType": "CNAME" }), down()),
        ("public dns expected IP", "dns", json!({ "hostname": "one.one.one.one", "expectedIP": "1.1.1.1" }), up()),
        ("public dns NXDOMAIN", "dns", json!({ "hostname": "does-not-exist.statustick.com" }), down()),
        ("public ssl", "ssl", json!({ "host": "github.com", "protocols": true }), up()),
        ("public ssl wrong host", "ssl", json!({ "host": "wrong.host.badssl.com" }), down()),
        ("public ssl expired", "ssl", json!({ "host": "expired.badssl.com" }), down()),
        ("public ssl self-signed", "ssl", json!({ "host": "self-signed.badssl.com" }), down()),
        ("public ssl untrusted root", "ssl", json!({ "host": "untrusted-root.badssl.com" }), down()),
        ("public http", "http", json!({ "url": "https://example.com/", "expectedText": "Example Domain" }), up()),
        ("public ping", "ping", json!({ "host": "1.1.1.1", "count": 2 }), up()),
    ]);
}

#[test]
#[ignore = "needs the internet"]
fn public_txt_value() {
    fixtures(false);
    expect_all(vec![(
        "public dns TXT",
        "dns",
        json!({ "hostname": "google.com", "recordType": "TXT", "expectedValue": "v=spf1" }),
        vec![("status", json!("up"))],
    )]);
}

#[test]
#[ignore = "engine bug: an SOA answer is one object, so it is never up"]
fn public_soa() {
    fixtures(false);
    expect_all(vec![("public dns SOA", "dns", json!({ "hostname": "github.com", "recordType": "SOA" }), vec![("status", json!("up"))])]);
}
