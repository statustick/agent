//! Every check type against the local servers in `common`.
mod common;

use common::{at, check, expect_all, fixtures};
use serde_json::{Value, json};

const UNKNOWN_HOST: &str = "unknown-host.invalid";

fn web() -> String {
    format!("http://localhost:{}", fixtures(false).ports.http)
}

#[test]
fn http_check_matches_the_expected_text() {
    let web = web();
    expect_all(vec![
        ("found", "http", json!({ "url": format!("{web}/ok"), "expectedText": "world" }), vec![("status", json!("up")), ("details.textMatch", json!(true))]),
        (
            "must not be there",
            "http",
            json!({ "url": format!("{web}/ok"), "expectedText": "world", "textMode": "not_contains" }),
            vec![("status", json!("down")), ("details.textMatch", json!(false))],
        ),
        (
            "case-insensitive",
            "http",
            json!({ "url": format!("{web}/ok"), "expectedText": "WORLD", "caseSensitive": false }),
            vec![("status", json!("up")), ("details.textMatch", json!(true))],
        ),
        (
            "case-sensitive by default",
            "http",
            json!({ "url": format!("{web}/ok"), "expectedText": "WORLD" }),
            vec![("status", json!("down")), ("details.textMatch", json!(false))],
        ),
    ]);
}

#[test]
fn http_check_reads_compressed_and_utf8_bodies_up_to_5_mb() {
    let web = web();
    expect_all(vec![
        ("gzip", "http", json!({ "url": format!("{web}/gzip"), "expectedText": "compressed hello" }), vec![("details.textMatch", json!(true))]),
        ("brotli", "http", json!({ "url": format!("{web}/brotli"), "expectedText": "brotli hello" }), vec![("details.textMatch", json!(true))]),
        ("UTF-8 with a BOM", "http", json!({ "url": format!("{web}/utf8"), "expectedText": "naïve café" }), vec![("details.textMatch", json!(true))]),
        (
            "text after the first 5 MB is not read",
            "http",
            json!({ "url": format!("{web}/big"), "expectedText": "needle" }),
            vec![("status", json!("down")), ("httpStatus", json!(200)), ("details.textMatch", json!(false))],
        ),
    ]);
}

#[test]
fn http_check_is_up_only_for_the_expected_status() {
    let web = web();
    let answered = |status: &str, code: u16| vec![("status", json!(status)), ("httpStatus", json!(code))];
    expect_all(vec![
        ("404", "http", json!({ "url": format!("{web}/nope") }), answered("down", 404)),
        ("500", "http", json!({ "url": format!("{web}/status/500") }), answered("down", 500)),
        ("a plain 403 is down, not blocked", "http", json!({ "url": format!("{web}/forbidden") }), answered("down", 403)),
        ("201 expected, 200 answered", "http", json!({ "url": format!("{web}/ok"), "expectedStatus": 201 }), answered("down", 200)),
        ("403 expected", "http", json!({ "url": format!("{web}/blocked"), "expectedStatus": 403 }), answered("up", 403)),
        ("204 with no body", "http", json!({ "url": format!("{web}/nocontent") }), answered("up", 204)),
        ("HEAD", "http", json!({ "url": format!("{web}/ok"), "method": "HEAD" }), answered("up", 200)),
    ]);
}

#[test]
fn http_check_reports_a_firewall_challenge_as_blocked() {
    expect_all(vec![(
        "Cloudflare challenge",
        "http",
        json!({ "url": format!("{}/blocked", web()) }),
        vec![("status", json!("blocked")), ("error", json!("Blocked by the site's firewall: Cloudflare challenge page")), ("errorType", json!("BLOCKED"))],
    )]);
}

#[test]
fn http_check_follows_up_to_five_redirects() {
    let web = web();
    expect_all(vec![
        ("followed", "http", json!({ "url": format!("{web}/redirect") }), vec![("status", json!("up")), ("httpStatus", json!(200))]),
        (
            "not followed when turned off",
            "http",
            json!({ "url": format!("{web}/redirect"), "followRedirects": false }),
            vec![("httpStatus", json!(302)), ("details.headers.location", json!("/ok"))],
        ),
        (
            "303 turns POST into a GET without a body",
            "http",
            json!({ "url": format!("{web}/redirect303"), "method": "POST", "body": "x=1", "bodyType": "FORM_PARAMS" }),
            vec![("httpStatus", json!(200)), ("details.headers.x-seen-method", json!("GET")), ("details.headers.x-seen-body-length", json!("0"))],
        ),
        (
            "a loop stops at the last hop's answer",
            "http",
            json!({ "url": format!("{web}/redirect-loop") }),
            vec![("httpStatus", json!(302)), ("details.headers.location", json!("/redirect-loop"))],
        ),
    ]);
}

#[test]
fn http_check_refuses_internal_targets_also_after_a_redirect() {
    let web = web();
    let refused = || vec![("status", json!("down")), ("error", json!("target not allowed")), ("errorType", json!("TargetNotAllowed"))];
    expect_all(vec![
        ("redirect to 127.0.0.1", "http", json!({ "url": format!("{web}/redirect-internal") }), refused()),
        ("127.0.0.1", "http", json!({ "url": format!("http://127.0.0.1:{}/ok", fixtures(false).ports.http) }), refused()),
    ]);
}

#[test]
fn http_check_runs_json_assertions_without_quoting_the_body() {
    let web = web();
    expect_all(vec![
        (
            "all pass",
            "http",
            json!({ "url": format!("{web}/json"), "json": [{ "path": "$.status", "equals": "ok" }, { "path": "$.items[0].id", "equals": 7 }, { "path": "$.error", "exists": false }] }),
            vec![("status", json!("up")), ("error", Value::Null)],
        ),
        (
            "a wrong value",
            "http",
            json!({ "url": format!("{web}/json"), "json": [{ "path": "$.count", "equals": "1" }] }),
            vec![("status", json!("down")), ("error", json!("JSON path $.count is not the expected value")), ("errorType", json!("JSON_ASSERTION"))],
        ),
        (
            "a body that is not JSON",
            "http",
            json!({ "url": format!("{web}/ok"), "json": [{ "path": "$.a", "exists": true }] }),
            vec![("status", json!("down")), ("error", json!("The response is not JSON, so $.a cannot be checked")), ("errorType", json!("JSON_ASSERTION"))],
        ),
    ]);
}

#[test]
fn http_check_sends_the_method_body_and_headers_it_was_given() {
    let web = web();
    expect_all(vec![
        (
            "StatusTick's User-Agent by default",
            "http",
            json!({ "url": format!("{web}/ok") }),
            vec![
                ("details.headers.x-seen-user-agent", json!("StatusTick/2.0 (+https://statustick.com/docs/checks)")),
                ("details.headers.x-seen-method", json!("GET")),
            ],
        ),
        (
            "JSON body",
            "http",
            json!({ "url": format!("{web}/ok"), "method": "post", "body": "{\"a\":1}", "bodyType": "JSON" }),
            vec![
                ("details.headers.x-seen-method", json!("POST")),
                ("details.headers.x-seen-content-type", json!("application/json")),
                ("details.headers.x-seen-body-length", json!("7")),
            ],
        ),
        (
            "a Content-Type header wins",
            "http",
            json!({ "url": format!("{web}/ok"), "method": "PUT", "body": "x", "headers": { "Content-Type": "text/csv" } }),
            vec![("details.headers.x-seen-content-type", json!("text/csv")), ("details.headers.x-seen-body-length", json!("1"))],
        ),
        ("no body with GET", "http", json!({ "url": format!("{web}/ok"), "body": "ignored" }), vec![("details.headers.x-seen-body-length", json!("0"))]),
        (
            "own User-Agent and headers",
            "http",
            json!({ "url": format!("{web}/ok"), "headers": { "user-agent": "Probe/1.0", "X-Custom": "yes" } }),
            vec![("details.headers.x-seen-user-agent", json!("Probe/1.0")), ("details.headers.x-seen-x-custom", json!("yes"))],
        ),
    ]);
}

#[test]
fn http_check_reports_page_assets_that_fail_or_are_refused() {
    let web = web();
    let http = fixtures(false).ports.http;
    let missing = json!({ "url": format!("{web}/missing.js"), "status": 404 });
    expect_all(vec![
        (
            "all hosts",
            "http",
            json!({ "url": format!("{web}/html"), "assets": { "ignoreHosts": [] } }),
            vec![
                ("status", json!("up")),
                ("details.assets.checked", json!(4)),
                ("details.assets.failed", json!([missing, { "url": format!("http://127.0.0.1:{http}/x.png"), "error": "target not allowed" }])),
            ],
        ),
        (
            "an ignored host",
            "http",
            json!({ "url": format!("{web}/html"), "assets": { "ignoreHosts": ["127.0.0.1"] } }),
            vec![("details.assets.checked", json!(3)), ("details.assets.failed", json!([missing]))],
        ),
    ]);
}

#[test]
fn http_check_reports_why_a_request_failed() {
    let p = &fixtures(false).ports;
    let web = web();
    let failed = |error: &str, kind: &str| vec![("status", json!("down")), ("error", json!(error)), ("errorType", json!(kind))];
    expect_all(vec![
        ("timeout", "http", json!({ "url": format!("{web}/slow"), "timeout": 500 }), failed("This operation was aborted", "AbortError")),
        ("connection refused", "http", json!({ "url": format!("http://localhost:{}/", p.closed) }), failed("fetch failed", "TypeError")),
        ("invalid URL", "http", json!({ "url": "not a url" }), failed("Invalid URL", "TypeError")),
        ("unknown host", "http", json!({ "url": format!("http://{UNKNOWN_HOST}/") }), failed(&format!("getaddrinfo ENOTFOUND {UNKNOWN_HOST}"), "Error")),
        (
            "credentials in the URL",
            "http",
            json!({ "url": format!("http://user:pass@localhost:{}/ok", p.http) }),
            failed(&format!("Request cannot be constructed from a URL that includes credentials: http://user:pass@localhost:{}/ok", p.http), "TypeError"),
        ),
        ("not http", "http", json!({ "url": format!("ftp://localhost:{}/", p.http) }), failed("fetch failed", "TypeError")),
    ]);
}

#[test]
fn http_check_can_use_one_ip_version() {
    let p = &fixtures(false).ports;
    let web = web();
    expect_all(vec![
        ("IPv6", "http", json!({ "url": format!("{web}/ok"), "ipVersion": "6" }), vec![("status", json!("up"))]),
        ("IPv4", "http", json!({ "url": format!("{web}/ok"), "ipVersion": 4 }), vec![("status", json!("up"))]),
        (
            "no IPv6 address",
            "http",
            json!({ "url": format!("http://127.0.0.1:{}/", p.http), "ipVersion": "6" }),
            vec![("status", json!("down")), ("error", json!("No IPv6 address (AAAA record) for 127.0.0.1")), ("errorType", json!("NoAddress"))],
        ),
    ]);
}

#[test]
fn https_check_falls_back_to_legacy_tls_and_flags_it() {
    let p = &fixtures(false).ports;
    let legacy = |version: &str| {
        vec![("status", json!("up")), ("details.textMatch", json!(true)), ("details.legacyTLS", json!(true)), ("details.tlsVersion", json!(version))]
    };
    let request = |port: u16| json!({ "url": format!("https://localhost:{port}/ok"), "expectedText": "world" });
    expect_all(vec![
        ("modern TLS is not flagged", "http", request(p.https), vec![("status", json!("up")), ("details.legacyTLS", Value::Null)]),
        ("CBC ciphers only", "http", request(p.https_cbc), legacy("TLSv1.2")),
        ("TLS 1.0 only", "http", request(p.https_tls10), legacy("TLSv1")),
        ("TLS 1.1 only", "http", request(p.https_tls11), legacy("TLSv1.1")),
        ("a weak key over TLS 1.2 fails", "http", request(p.https_weak_key), vec![("status", json!("down")), ("error", json!("fetch failed"))]),
        ("a weak key over TLS 1.0 is flagged", "http", request(p.https_weak_key_tls10), vec![("status", json!("up")), ("details.weakKey", json!(true))]),
        (
            "an untrusted certificate fails",
            "http",
            json!({ "url": format!("https://localhost:{}/", p.tls["self-signed"]) }),
            vec![("status", json!("down")), ("error", json!("fetch failed")), ("errorType", json!("TypeError"))],
        ),
    ]);
}

#[test]
fn tcp_check_is_up_when_the_port_accepts_a_connection() {
    let p = &fixtures(false).ports;
    let closed = p.closed;
    expect_all(vec![
        ("open", "tcp", json!({ "host": "localhost", "port": p.http }), vec![("status", json!("up")), ("error", Value::Null)]),
        ("closed", "tcp", json!({ "host": "localhost", "port": closed }), vec![("status", json!("down")), ("errorCode", json!("ECONNREFUSED"))]),
        (
            "closed, IPv4 only",
            "tcp",
            json!({ "host": "localhost", "port": closed, "ipVersion": "4" }),
            vec![("error", json!(format!("connect ECONNREFUSED 127.0.0.1:{closed}"))), ("errorCode", json!("ECONNREFUSED"))],
        ),
        ("no answer", "tcp", json!({ "host": "192.0.2.1", "port": 80, "timeout": 500 }), vec![("status", json!("down"))]),
    ]);
}

#[test]
fn tcp_check_reports_refused_and_missing_targets() {
    expect_all(vec![
        (
            "internal address",
            "tcp",
            json!({ "host": "10.1.2.3", "port": 22 }),
            vec![("status", json!("down")), ("error", json!("target not allowed")), ("errorCode", json!("TARGET_NOT_ALLOWED"))],
        ),
        (
            "no IPv4 address",
            "tcp",
            json!({ "host": "::1", "port": 22, "ipVersion": "4" }),
            vec![("error", json!("No IPv4 address (A record) for ::1")), ("errorCode", json!("NO_ADDRESS"))],
        ),
        (
            "unknown host",
            "tcp",
            json!({ "host": UNKNOWN_HOST, "port": 80 }),
            vec![("error", json!(format!("getaddrinfo ENOTFOUND {UNKNOWN_HOST}"))), ("errorCode", json!("ENOTFOUND"))],
        ),
    ]);
}

/// Whether ICMP works depends on the machine, so the IPv6 case only asks for an answer.
#[test]
fn ping_check_answers_for_reachable_refused_and_unknown_hosts() {
    fixtures(false);
    expect_all(vec![
        (
            "localhost",
            "ping",
            json!({ "host": "localhost", "count": 2, "timeout": 3000, "ipVersion": "4" }),
            vec![("status", json!("up")), ("packetLoss", json!("0.000")), ("details.alive", json!(true))],
        ),
        ("localhost over IPv6", "ping", json!({ "host": "localhost", "timeout": 3000, "ipVersion": "6" }), vec![("host", json!("localhost"))]),
        ("cloud metadata", "ping", json!({ "host": "169.254.169.254" }), vec![("status", json!("down")), ("error", json!("target not allowed"))]),
        (
            "unknown host",
            "ping",
            json!({ "host": UNKNOWN_HOST }),
            vec![("status", json!("down")), ("error", json!(format!("getaddrinfo ENOTFOUND {UNKNOWN_HOST}")))],
        ),
    ]);
}

#[test]
fn dns_check_reports_unsupported_types_and_unknown_hosts() {
    fixtures(false);
    expect_all(vec![
        (
            "PTR",
            "dns",
            json!({ "hostname": "example.com", "recordType": "PTR" }),
            vec![("status", json!("down")), ("error", json!("Unsupported record type: PTR"))],
        ),
        (
            "unknown host, A by default",
            "dns",
            json!({ "hostname": UNKNOWN_HOST }),
            vec![
                ("status", json!("down")),
                ("recordType", json!("A")),
                ("error", json!(format!("queryA ENOTFOUND {UNKNOWN_HOST}"))),
                ("errorCode", json!("ENOTFOUND")),
            ],
        ),
    ]);
}

#[test]
fn certificate_check_describes_a_trusted_certificate() {
    let p = &fixtures(false).ports;
    expect_all(vec![(
        "trusted",
        "ssl",
        json!({ "host": "localhost", "port": p.tls["localhost"], "protocols": true }),
        vec![
            ("status", json!("up")),
            ("protocols", json!(["TLSv1.2", "TLSv1.3"])),
            ("certificate.valid", json!(true)),
            ("certificate.validFrom", json!("2025-01-01T00:00:00.000Z")),
            ("certificate.validTo", json!("2099-12-31T00:00:00.000Z")),
            ("certificate.issuer", json!("StatusTick Tests")),
            ("certificate.subject", json!("localhost")),
            ("certificate.hostnameMatch", json!(true)),
            ("certificate.chain[1].subject", json!("Test CA")),
        ],
    )]);
}

#[test]
fn certificate_check_names_why_a_certificate_is_not_valid() {
    let p = &fixtures(false).ports;
    let request = |name: &str| json!({ "host": "localhost", "port": p.tls[name] });
    expect_all(vec![
        (
            "expired",
            "ssl",
            request("expired"),
            vec![
                ("status", json!("down")),
                ("error", json!("Certificate has expired")),
                ("certificate.valid", json!(false)),
                ("certificate.lifetimeDays", json!(31)),
            ],
        ),
        (
            "for another host",
            "ssl",
            request("other-host"),
            vec![
                ("status", json!("down")),
                (
                    "error",
                    json!(
                        "Hostname mismatch: Hostname/IP does not match certificate's altnames: Host: localhost. is not in the cert's altnames: DNS:other.test, DNS:*.other.test"
                    ),
                ),
                ("certificate.hostnameMatch", json!(false)),
            ],
        ),
        (
            "from a CA nobody trusts",
            "ssl",
            request("unknown-ca"),
            vec![
                ("status", json!("down")),
                ("error", json!("Certificate is not trusted: SELF_SIGNED_CERT_IN_CHAIN")),
                ("certificate.chain[1].subject", json!("Unknown Test CA")),
            ],
        ),
        (
            "self-signed",
            "ssl",
            request("self-signed"),
            vec![
                ("status", json!("down")),
                ("error", json!("Certificate is not trusted: DEPTH_ZERO_SELF_SIGNED_CERT")),
                ("certificate.hostnameMatch", json!(true)),
            ],
        ),
    ]);
}

#[test]
fn certificate_check_is_an_error_when_there_is_no_tls_to_read() {
    let p = &fixtures(false).ports;
    expect_all(vec![
        (
            "not TLS",
            "ssl",
            json!({ "host": "localhost", "port": p.tls["plain"] }),
            vec![("status", json!("error")), ("errorCode", json!("ERR_SSL_WRONG_VERSION_NUMBER"))],
        ),
        ("closed port", "ssl", json!({ "host": "localhost", "port": p.closed }), vec![("status", json!("error")), ("errorCode", json!("ECONNREFUSED"))]),
        (
            "internal address",
            "ssl",
            json!({ "host": "127.0.0.1", "port": p.tls["localhost"] }),
            vec![("status", json!("error")), ("error", json!("target not allowed")), ("errorCode", json!("TARGET_NOT_ALLOWED"))],
        ),
    ]);
}

#[test]
fn certificate_check_reports_legacy_tls_and_weak_keys() {
    let p = &fixtures(false).ports;
    let request = |port: u16| json!({ "host": "localhost", "port": port, "protocols": true });
    let legacy = |version: &str| vec![("status", json!("up")), ("protocols", json!([version])), ("legacyTLS", json!(true)), ("tlsVersion", json!(version))];
    expect_all(vec![
        ("CBC ciphers only", "ssl", request(p.https_cbc), legacy("TLSv1.2")),
        ("TLS 1.0 only", "ssl", request(p.https_tls10), legacy("TLSv1")),
        ("TLS 1.1 only", "ssl", request(p.https_tls11), legacy("TLSv1.1")),
        (
            "a weak key over TLS 1.2 is an error",
            "ssl",
            request(p.https_weak_key),
            vec![("status", json!("error")), ("error", json!("certificate key too weak: RSA 1024 bits")), ("errorCode", json!("ERR_SSL_EE_KEY_TOO_SMALL"))],
        ),
        (
            "a weak key over TLS 1.0 is flagged",
            "ssl",
            request(p.https_weak_key_tls10),
            vec![("status", json!("up")), ("tlsVersion", json!("TLSv1")), ("weakKey", json!(true))],
        ),
    ]);
}

#[test]
fn grpc_check_reports_the_health_status_of_a_service() {
    let p = &fixtures(false).ports;
    let request = |service: &str| json!({ "host": "localhost", "port": p.grpc, "service": service });
    expect_all(vec![
        (
            "the whole server",
            "grpc",
            json!({ "host": "localhost", "port": p.grpc }),
            vec![("status", json!("up")), ("details.grpcStatus", json!(0)), ("details.servingStatus", json!("SERVING"))],
        ),
        ("one service", "grpc", request("api"), vec![("status", json!("up")), ("details.servingStatus", json!("SERVING"))]),
        (
            "not serving",
            "grpc",
            request("down"),
            vec![("status", json!("down")), ("error", json!("Health status NOT_SERVING")), ("errorCode", json!("GRPC_NOT_SERVING"))],
        ),
        (
            "unknown service",
            "grpc",
            request("unknown"),
            vec![
                ("status", json!("down")),
                ("error", json!("gRPC status 5 NOT_FOUND: the server does not know the service \"unknown\"")),
                ("errorCode", json!("GRPC_STATUS")),
            ],
        ),
        (
            "no health service",
            "grpc",
            request("unimplemented"),
            vec![
                ("status", json!("down")),
                ("error", json!("gRPC status 12 UNIMPLEMENTED: the server has no grpc.health.v1.Health service")),
                ("errorCode", json!("GRPC_STATUS")),
            ],
        ),
    ]);
}

#[test]
fn grpc_check_over_tls_verifies_the_server() {
    let p = &fixtures(false).ports;
    expect_all(vec![
        (
            "trusted",
            "grpc",
            json!({ "host": "localhost", "port": p.grpc_tls, "tlsMode": "TLS" }),
            vec![("status", json!("up")), ("details.tlsVersion", json!("TLSv1.3")), ("details.certificateExpiresAt", json!("2099-12-31T00:00:00.000Z"))],
        ),
        (
            "untrusted",
            "grpc",
            json!({ "host": "localhost", "port": p.tls["self-signed"], "tlsMode": "TLS" }),
            vec![("status", json!("down")), ("errorCode", json!("TLS_FAILED"))],
        ),
        (
            "unverified, but no HTTP/2",
            "grpc",
            json!({ "host": "localhost", "port": p.tls["self-signed"], "tlsMode": "TLS", "tlsVerify": false }),
            vec![("error", json!("The server does not speak HTTP/2 over TLS (no ALPN h2)")), ("errorCode", json!("GRPC_INVALID_ANSWER"))],
        ),
    ]);
}

#[test]
fn grpc_check_refuses_bad_settings_and_unreachable_targets() {
    let p = &fixtures(false).ports;
    expect_all(vec![
        (
            "STARTTLS",
            "grpc",
            json!({ "host": "localhost", "port": p.grpc, "tlsMode": "STARTTLS" }),
            vec![("status", json!("error")), ("error", json!("tlsMode must be NONE or TLS for gRPC")), ("errorCode", json!("INVALID_REQUEST"))],
        ),
        ("closed port", "grpc", json!({ "host": "localhost", "port": p.closed }), vec![("status", json!("down")), ("errorCode", json!("CONNECT_FAILED"))]),
        (
            "internal address",
            "grpc",
            json!({ "host": "10.0.0.1", "port": 50051 }),
            vec![("status", json!("down")), ("error", json!("target not allowed")), ("errorCode", json!("TARGET_NOT_ALLOWED"))],
        ),
    ]);
}

#[test]
fn smtp_check_reads_the_greeting_and_starttls() {
    let p = &fixtures(false).ports;
    expect_all(vec![
        (
            "plain, STARTTLS offered",
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
            "STARTTLS",
            "smtp",
            json!({ "host": "localhost", "port": p.smtp, "tlsMode": "STARTTLS" }),
            vec![("status", json!("up")), ("details.tlsVersion", json!("TLSv1.3")), ("details.certificateExpiresAt", json!("2099-12-31T00:00:00.000Z"))],
        ),
        (
            "implicit TLS",
            "smtp",
            json!({ "host": "localhost", "port": p.smtps, "tlsMode": "TLS" }),
            vec![("status", json!("up")), ("details.tlsVersion", json!("TLSv1.3")), ("details.greetingCode", json!("220"))],
        ),
    ]);
}

#[test]
fn smtp_check_fails_without_starttls_or_a_220_greeting() {
    let p = &fixtures(false).ports;
    let not_offered =
        || vec![("status", json!("down")), ("error", json!("The SMTP server does not offer STARTTLS")), ("errorCode", json!("STARTTLS_NOT_OFFERED"))];
    expect_all(vec![
        ("STARTTLS required", "smtp", json!({ "host": "localhost", "port": p.smtp_no_tls, "requireStartTLS": true }), not_offered()),
        ("STARTTLS mode", "smtp", json!({ "host": "localhost", "port": p.smtp_no_tls, "tlsMode": "STARTTLS" }), not_offered()),
        (
            "greeting 554",
            "smtp",
            json!({ "host": "localhost", "port": p.smtp_554 }),
            vec![("status", json!("down")), ("error", json!("The SMTP greeting is 554, not 220")), ("errorCode", json!("SMTP_GREETING"))],
        ),
        (
            "bytes after the STARTTLS answer",
            "smtp",
            json!({ "host": "localhost", "port": p.smtp_inject, "tlsMode": "STARTTLS" }),
            vec![("status", json!("down")), ("error", json!("The server sent more after its STARTTLS answer")), ("errorCode", json!("STARTTLS_FAILED"))],
        ),
        (
            "no greeting",
            "smtp",
            json!({ "host": "localhost", "port": p.tls["localhost"], "timeout": 500 }),
            vec![("status", json!("down")), ("error", json!("Timed out after 500 ms")), ("errorCode", json!("TIMEOUT"))],
        ),
        (
            "requireStartTLS with implicit TLS",
            "smtp",
            json!({ "host": "localhost", "port": p.smtps, "tlsMode": "TLS", "requireStartTLS": true }),
            vec![("status", json!("error")), ("error", json!("requireStartTLS needs tlsMode NONE or STARTTLS")), ("errorCode", json!("INVALID_REQUEST"))],
        ),
    ]);
}

#[test]
fn imap_check_reads_the_greeting_and_capabilities() {
    let p = &fixtures(false).ports;
    expect_all(vec![
        (
            "capabilities in the greeting",
            "imap",
            json!({ "host": "localhost", "port": p.imap }),
            vec![("status", json!("up")), ("details.greetingCode", json!("OK")), ("details.startTLSOffered", json!(true))],
        ),
        (
            "STARTTLS",
            "imap",
            json!({ "host": "localhost", "port": p.imap, "tlsMode": "STARTTLS" }),
            vec![("status", json!("up")), ("details.tlsVersion", json!("TLSv1.3"))],
        ),
        (
            "capabilities asked for",
            "imap",
            json!({ "host": "localhost", "port": p.imap_no_caps }),
            vec![("status", json!("up")), ("details.startTLSOffered", json!(true))],
        ),
        (
            "BYE",
            "imap",
            json!({ "host": "localhost", "port": p.imap_bye }),
            vec![
                ("status", json!("down")),
                ("error", json!("The IMAP greeting is BYE: the server refuses connections")),
                ("errorCode", json!("IMAP_GREETING")),
            ],
        ),
        (
            "internal address",
            "imap",
            json!({ "host": "192.168.1.1", "port": 143 }),
            vec![("status", json!("down")), ("error", json!("target not allowed")), ("errorCode", json!("TARGET_NOT_ALLOWED"))],
        ),
    ]);
}

#[test]
fn mcp_check_lists_every_tool_page_and_hashes_the_tools() {
    let mcp = format!("http://localhost:{}", fixtures(false).ports.mcp);
    let json_answers = check("mcp", json!({ "url": format!("{mcp}/mcp") }));
    let event_stream = check("mcp", json!({ "url": format!("{mcp}/mcp-sse") }));
    for result in [&json_answers, &event_stream] {
        assert_eq!(at(result, "status"), "up", "{result}");
        assert_eq!(at(result, "details.toolCount"), 3, "{result}");
    }
    assert_eq!(at(&json_answers, "details.protocolVersion"), "2025-06-18");
    assert_eq!(at(&json_answers, "details.serverVersion"), "1.2.3");
    let name = at(&json_answers, "details.serverName");
    assert!(name.as_str().is_some_and(|name| name.starts_with("test-server-") && name.chars().count() == 100), "server name cut to 100: {name}");
    let hash = at(&json_answers, "details.toolsHash");
    assert_eq!(hash, "36ee5b48b3347cb08ce36de0fc67d49704bc2a23cab387b6d628a1493597b5ce", "the hash StatusTick compares across agents and regions");
    assert_eq!(at(&event_stream, "details.toolsHash"), hash);
    let authenticated = check("mcp", json!({ "url": format!("{mcp}/mcp-auth"), "authHeaderName": "X-Key", "authHeaderValue": "secret" }));
    assert_eq!(at(&authenticated, "status"), "up");
}

#[test]
fn mcp_check_names_the_phase_that_failed() {
    let mcp = format!("http://localhost:{}", fixtures(false).ports.mcp);
    let request = |path: &str| json!({ "url": format!("{mcp}/{path}") });
    let failed = |error: &str, code: &str| vec![("status", json!("down")), ("error", json!(error)), ("errorCode", json!(code))];
    expect_all(vec![
        ("refused credentials", "mcp", request("mcp-401"), failed("The MCP server refused the request: HTTP 401", "AUTH_FAILED")),
        (
            "redirect",
            "mcp",
            request("mcp-redirect"),
            failed("The MCP server answered initialize with a redirect (HTTP 302); check the URL it redirects to", "MCP_INITIALIZE_FAILED"),
        ),
        ("HTTP 500 at initialize", "mcp", request("mcp-500"), failed("The MCP server answered initialize with HTTP 500", "MCP_INITIALIZE_FAILED")),
        ("JSON-RPC error", "mcp", request("mcp-rpc-error"), failed("The MCP server answered initialize with JSON-RPC error -32603", "MCP_INITIALIZE_FAILED")),
        ("invalid initialize answer", "mcp", request("mcp-invalid"), failed("The MCP server's initialize answer is not valid", "MCP_INITIALIZE_FAILED")),
        ("old protocol version", "mcp", request("mcp-old-version"), failed("The MCP server's protocol version is not supported", "MCP_INITIALIZE_FAILED")),
        ("no tools", "mcp", request("mcp-empty"), failed("The MCP server lists no tools", "MCP_NO_TOOLS")),
        ("HTTP 500 at tools/list", "mcp", request("mcp-tools-fail"), failed("The MCP server answered tools/list with HTTP 500", "MCP_TOOLS_LIST_FAILED")),
        ("repeated cursor", "mcp", request("mcp-loop"), failed("tools/list repeats the same cursor", "MCP_TOOLS_LIST_FAILED")),
    ]);
}

#[test]
fn mcp_check_refuses_bad_settings_and_unreachable_targets() {
    let p = &fixtures(false).ports;
    let mcp = format!("http://localhost:{}", p.mcp);
    expect_all(vec![
        (
            "closed port",
            "mcp",
            json!({ "url": format!("http://localhost:{}/mcp", p.closed) }),
            vec![("status", json!("down")), ("errorCode", json!("CONNECT_FAILED"))],
        ),
        (
            "internal address",
            "mcp",
            json!({ "url": format!("http://127.0.0.1:{}/mcp", p.mcp) }),
            vec![("status", json!("down")), ("error", json!("target not allowed")), ("errorCode", json!("TARGET_NOT_ALLOWED"))],
        ),
        (
            "Host as the auth header",
            "mcp",
            json!({ "url": format!("{mcp}/mcp"), "authHeaderName": "Host", "authHeaderValue": "x" }),
            vec![
                ("status", json!("error")),
                ("error", json!("authHeaderName is not a header name the check can send")),
                ("errorCode", json!("INVALID_HEADER")),
            ],
        ),
        (
            "not http",
            "mcp",
            json!({ "url": "ws://localhost/mcp" }),
            vec![("status", json!("error")), ("error", json!("url must be an http or https URL")), ("errorCode", json!("INVALID_URL"))],
        ),
    ]);
}

/// Server text (greetings, gRPC messages, JSON-RPC errors, tool descriptions) never reaches a result.
#[test]
fn checks_never_quote_what_the_server_said() {
    let p = &fixtures(false).ports;
    let mcp = format!("http://localhost:{}", p.mcp);
    for (kind, request) in [
        ("smtp", json!({ "host": "localhost", "port": p.smtp_554 })),
        ("grpc", json!({ "host": "localhost", "port": p.grpc, "service": "unknown" })),
        ("mcp", json!({ "url": format!("{mcp}/mcp") })),
        ("mcp", json!({ "url": format!("{mcp}/mcp-401") })),
        ("mcp", json!({ "url": format!("{mcp}/mcp-500") })),
        ("mcp", json!({ "url": format!("{mcp}/mcp-rpc-error") })),
        ("mcp", json!({ "url": format!("{mcp}/mcp-tools-fail") })),
    ] {
        let result = check(kind, request.clone()).to_string();
        assert!(!result.contains("secret"), "{kind} {request}: {result}");
    }
}

#[test]
fn multi_check_runs_each_item_on_its_own() {
    let p = &fixtures(false).ports;
    let request = json!({ "checks": [
        { "type": "http", "url": format!("{}/ok", web()), "expectedText": "hello" },
        { "type": "tcp", "host": "localhost", "port": p.http },
        { "type": "tcp", "host": "10.0.0.1", "port": 80 },
        { "type": "dns", "hostname": UNKNOWN_HOST },
        { "type": "ping", "host": "localhost", "timeout": 2000 },
        { "type": "bogus" }
    ] });
    expect_all(vec![(
        "six items",
        "multi",
        request,
        vec![
            ("results[0].status", json!("up")),
            ("results[0].expectedText", json!("hello")),
            ("results[1].status", json!("up")),
            ("results[2].status", json!("error")),
            ("results[2].error", json!("target not allowed")),
            ("results[3].status", json!("error")),
            ("results[3].error", json!(format!("queryA ENOTFOUND {UNKNOWN_HOST}"))),
            ("results[4].type", json!("ping")),
            ("results[5].status", json!("error")),
            ("results[5].error", json!("Unknown check type")),
        ],
    )]);
}

#[test]
#[ignore = "needs the internet"]
fn public_dns_records() {
    fixtures(false);
    let up = || vec![("status", json!("up"))];
    let down = || vec![("status", json!("down"))];
    expect_all(vec![
        ("A", "dns", json!({ "hostname": "one.one.one.one", "recordType": "A" }), up()),
        ("AAAA", "dns", json!({ "hostname": "one.one.one.one", "recordType": "AAAA" }), up()),
        ("MX", "dns", json!({ "hostname": "gmail.com", "recordType": "MX" }), up()),
        ("NS", "dns", json!({ "hostname": "github.com", "recordType": "NS" }), up()),
        ("CAA", "dns", json!({ "hostname": "google.com", "recordType": "CAA" }), up()),
        ("CNAME", "dns", json!({ "hostname": "www.github.com", "recordType": "CNAME" }), up()),
        ("TXT with an expected value", "dns", json!({ "hostname": "google.com", "recordType": "TXT", "expectedValue": "v=spf1" }), up()),
        ("SOA", "dns", json!({ "hostname": "github.com", "recordType": "SOA" }), up()),
        ("expected IP", "dns", json!({ "hostname": "one.one.one.one", "expectedIP": "1.1.1.1" }), up()),
        ("no CNAME", "dns", json!({ "hostname": "github.com", "recordType": "CNAME" }), down()),
        ("NXDOMAIN", "dns", json!({ "hostname": "does-not-exist.statustick.com" }), down()),
    ]);
}

#[test]
#[ignore = "needs the internet"]
fn public_certificates_http_and_ping() {
    fixtures(false);
    let up = || vec![("status", json!("up"))];
    let down = || vec![("status", json!("down"))];
    expect_all(vec![
        ("valid certificate", "ssl", json!({ "host": "github.com", "protocols": true }), up()),
        ("wrong host", "ssl", json!({ "host": "wrong.host.badssl.com" }), down()),
        ("expired", "ssl", json!({ "host": "expired.badssl.com" }), down()),
        ("self-signed", "ssl", json!({ "host": "self-signed.badssl.com" }), down()),
        ("untrusted root", "ssl", json!({ "host": "untrusted-root.badssl.com" }), down()),
        ("http", "http", json!({ "url": "https://example.com/", "expectedText": "Example Domain" }), up()),
        ("ping", "ping", json!({ "host": "1.1.1.1", "count": 2 }), up()),
    ]);
}
