//! The agent's contract: the binary against a fake StatusTick that records every call. Each case checks what StatusTick
//! and the agent's ports saw.
//!   CONTRACT_DATABASES=postgres=127.0.0.1:5432,redis=127.0.0.1:6379,mongodb=127.0.0.1:27017 adds the database checks
//!   against real servers whose user is `statustick` with the password `contract` (Redis: only the password).
mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use common::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::time::sleep;

#[tokio::test(flavor = "multi_thread")]
async fn connects_with_its_token_and_reports_its_setup() {
    let fake = Platform::start(vec![("/v1/connect", Box::new(|_, _| connected(json!({})))), ("/v1/jobs", Box::new(|_, _| jobs(json!([]))))]).await;
    let mut agent = Agent::start(&[("STATUSTICK_URL", &fake.url), ("STATUSTICK_CONCURRENCY", "10")], &[]);
    until("a lease", 20000, || !fake.calls("/v1/jobs").is_empty()).await;
    let connect = fake.calls("/v1/connect").remove(0);
    let lease = fake.calls("/v1/jobs").remove(0);
    let lines = agent.lines();
    agent.stop().await;
    assert_eq!(connect.headers["authorization"], format!("Bearer {TOKEN}"));
    assert!(regex::Regex::new(r"^StatusTick-Agent/\d+\.\d+\.\d+").unwrap().is_match(&connect.headers["user-agent"]));
    assert_eq!(
        normalize(&connect.body),
        json!({
            "hostName": "contract-host",
            "capabilities": { "browser": null },
            "installType": "other",
            "chromium": "off",
            "envSettings": ["STATUSTICK_CONCURRENCY"],
            "applied": { "browserConcurrency": 0, "concurrency": 10, "shareMetrics": false }
        })
    );
    assert_eq!(lease.query, HashMap::from([("max".to_string(), "10".to_string()), ("wait".to_string(), "1".to_string())]));
    assert_eq!((lease.headers["agent-id"].as_str(), lease.headers["agent-session"].as_str()), ("agt_1", "ses_1"));
    assert!(lines.contains(&format!("Connected to {} as agt_1 (location \"Office\").", fake.url)), "{lines:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn runs_leased_jobs_and_posts_only_the_documented_result_fields() {
    let port = target().await;
    let closed = free_port();
    let lease = |id: &str, kind: &str, check: Value| json!({ "leaseId": id, "expiresAt": in_one_minute(), "type": kind, "check": check });
    let list = json!([
        lease("l-tcp", "tcp", json!({ "host": "127.0.0.1", "port": port })),
        lease("l-closed", "tcp", json!({ "host": "127.0.0.1", "port": closed, "timeout": 2000 })),
        lease(
            "l-http",
            "http",
            json!({ "url": format!("http://127.0.0.1:{port}/json"), "expectedText": "ok", "expectedHeaders": { "X-Version": "3" }, "json": [{ "path": "$.count", "equals": 3 }], "timeout": null })
        ),
        lease("l-metadata", "http", json!({ "url": "http://169.254.169.254/latest" })),
        lease("l-missing", "tcp", json!({ "host": "", "port": 1 })),
        lease("l-invalid", "dns", json!({ "hostname": "example.com", "recordType": "PTR" })),
        lease("l-browser", "browser", json!({ "script": "x" })),
        lease("l-secret", "postgres", json!({ "host": "db.internal", "port": 5432, "passwordEnv": "HOME" }))
    ]);
    let count = list.as_array().unwrap().len();
    let fake = Platform::start(vec![
        ("/v1/connect", Box::new(|_, _| connected(json!({})))),
        ("/v1/jobs", Box::new(move |_, n| if n == 1 { jobs(list.clone()) } else { Answer::Hang })),
    ])
    .await;
    let mut agent = Agent::start(&[("STATUSTICK_URL", &fake.url), ("STATUSTICK_CONCURRENCY", "10")], &[]);
    until("all results", 20000, || fake.results().len() == count).await;
    let results: HashMap<String, Value> =
        fake.results().into_iter().map(|result| (result["leaseId"].as_str().unwrap().to_string(), normalize(&result["result"]))).collect();
    agent.stop().await;
    let expected = [
        ("l-tcp", "an open port is up", json!({ "status": "up" })),
        (
            "l-closed",
            "a closed port names the refusal",
            json!({ "status": "down", "error": format!("connect ECONNREFUSED 127.0.0.1:{closed}"), "errorCode": "ECONNREFUSED" }),
        ),
        (
            "l-http",
            "a header mismatch is down; headers and body stay in the network",
            json!({ "status": "down", "httpStatus": 200, "details": { "textMatch": true, "headerMismatch": { "name": "X-Version", "reason": "different" } } }),
        ),
        ("l-metadata", "cloud metadata is refused", json!({ "status": "down", "error": "target not allowed", "errorType": "TargetNotAllowed" })),
        ("l-missing", "a job without a host is an error", json!({ "status": "error", "error": "Missing host" })),
        ("l-invalid", "a record type outside the schema is an error", json!({ "status": "error", "error": "Invalid recordType" })),
        ("l-browser", "browser jobs need the image", json!({ "status": "error", "error": "Unsupported check type: browser" })),
        (
            "l-secret",
            "a password is read only from STATUSTICK_SECRET_* variables",
            json!({
                "status": "error",
                "error": "passwordEnv HOME is not allowed: the agent only reads variables that start with STATUSTICK_SECRET_",
                "errorCode": "SECRET_NOT_ALLOWED"
            }),
        ),
    ];
    for (lease, why, result) in expected {
        assert_eq!(results[lease], result, "{lease}: {why}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn logs_a_rejected_token_once_keeps_retrying_and_never_says_goodbye() {
    let fake = Platform::start(vec![("/v1/connect", Box::new(|_, _| reply(401, json!({ "error": "token.unauthorized" }))))]).await;
    let mut agent = Agent::start(&[("STATUSTICK_URL", &fake.url)], &[]);
    until("three connects", 20000, || fake.calls("/v1/connect").len() >= 3).await;
    let code = agent.stop().await;
    let lines: Vec<String> = agent.lines().into_iter().filter(|line| line.starts_with("Token rejected")).collect();
    assert_eq!(code, Some(0));
    assert_eq!(
        lines,
        ["Token rejected: check STATUSTICK_TOKEN, or rotate this agent's token on its page in StatusTick and restart with the new one. Retrying with backoff."]
    );
    assert!(fake.calls("/v1/goodbye").is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn stops_polling_when_an_update_is_required() {
    let fake = Platform::start(vec![(
        "/v1/connect",
        Box::new(|_, _| {
            reply(426, json!({ "error": "agent.update_required", "message": "Agent 1.0.0 is too old; install 9.0.0 or later.", "minimumVersion": "9.0.0" }))
        }),
    )])
    .await;
    let mut agent = Agent::start(&[("STATUSTICK_URL", &fake.url)], &[]);
    until("the update line", 20000, || agent.lines().iter().any(|line| line.starts_with("Update required"))).await;
    sleep(Duration::from_millis(1500)).await;
    let lines: Vec<String> = agent.lines().into_iter().filter(|line| line.starts_with("Update required")).collect();
    assert_eq!(lines, ["Update required: Agent 1.0.0 is too old; install 9.0.0 or later. Polling stopped."]);
    assert_eq!(fake.calls("/v1/connect").len(), 1);
    agent.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn logs_one_line_when_gone_and_one_when_back_then_connects_again() {
    let down = Arc::new(AtomicBool::new(false));
    let gone = down.clone();
    let fake = Platform::start(vec![
        ("/v1/connect", Box::new(move |_, _| if gone.load(Ordering::SeqCst) { reply(503, json!({ "error": "unavailable" })) } else { connected(json!({})) })),
        ("/v1/jobs", Box::new(|_, n| if n == 1 { reply(502, json!({})) } else { jobs(json!([])) })),
    ])
    .await;
    let mut agent = Agent::start(&[("STATUSTICK_URL", &fake.url)], &[]);
    let lines = || -> Vec<String> { agent.lines().into_iter().filter(|line| line.starts_with("Disconnected") || line.starts_with("Connected")).collect() };
    until("the line after the disconnect", 20000, || lines().len() >= 3).await;
    down.store(true, Ordering::SeqCst);
    let seen: Vec<String> = lines().into_iter().take(3).map(|line| line.replace(&fake.url, "<url>")).collect();
    assert_eq!(
        seen,
        [
            "Connected to <url> as agt_1 (location \"Office\").",
            "Disconnected: HTTP 502. Retrying with backoff.",
            "Connected to <url> as agt_1 (location \"Office\")."
        ]
    );
    agent.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn says_goodbye_once_after_the_running_checks_and_posts_their_results() {
    let fake = Platform::start(vec![
        ("/v1/connect", Box::new(|_, _| connected(json!({})))),
        (
            "/v1/jobs",
            Box::new(|_, n| {
                if n == 1 {
                    jobs(json!([{ "leaseId": "l-slow", "expiresAt": in_one_minute(), "type": "tcp", "check": { "host": "10.255.255.1", "port": 9, "timeout": 1500 } }]))
                } else {
                    Answer::Hang
                }
            }),
        ),
    ])
    .await;
    let mut agent = Agent::start(&[("STATUSTICK_URL", &fake.url)], &[]);
    until("the second lease", 20000, || fake.calls("/v1/jobs").len() >= 2).await;
    let code = agent.stop().await;
    let order: Vec<String> = fake.all().into_iter().map(|call| call.path).filter(|path| path == "/v1/results" || path == "/v1/goodbye").collect();
    let goodbye: Vec<Value> = fake.calls("/v1/goodbye").into_iter().map(|call| call.body).collect();
    assert_eq!(code, Some(0));
    assert_eq!(order, ["/v1/results", "/v1/goodbye"]);
    assert_eq!(goodbye, [json!({ "reason": "stopping" })]);
}

#[tokio::test(flavor = "multi_thread")]
async fn applies_max_checks_and_pause_from_a_lease_answer_and_reports_them_at_the_next_connect() {
    let port = target().await;
    let fake = Platform::start(vec![
        ("/v1/connect", Box::new(|_, _| connected(json!({})))),
        (
            "/v1/jobs",
            Box::new(move |_, n| match n {
                1 => reply(200, json!({ "jobs": [], "settings": { "maxChecks": 2, "paused": true, "shareHealth": false } })),
                2 => reply(
                    200,
                    json!({ "jobs": [{ "leaseId": "l-paused", "expiresAt": in_one_minute(), "type": "tcp", "check": { "host": "127.0.0.1", "port": port } }], "settings": { "maxChecks": 2, "paused": true } }),
                ),
                3 => reply(401, json!({ "error": "agent.unauthorized" })),
                _ => Answer::Hang,
            }),
        ),
    ])
    .await;
    let mut agent = Agent::start(&[("STATUSTICK_URL", &fake.url)], &[]);
    until("the second connect", 20000, || fake.calls("/v1/connect").len() >= 2).await;
    sleep(Duration::from_millis(300)).await;
    let lines: Vec<String> =
        agent.lines().into_iter().filter(|line| ["Checks at once", "Paused", "Resumed"].iter().any(|start| line.starts_with(start))).collect();
    assert_eq!(lines, ["Checks at once: 5 → 2, from the dashboard", "Paused from the dashboard"]);
    assert!(fake.calls("/v1/results").is_empty());
    assert_eq!(fake.calls("/v1/connect")[1].body["applied"], json!({ "browserConcurrency": 0, "concurrency": 2, "shareMetrics": false }));
    agent.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn buffers_a_remembered_check_offline_on_disk_and_uploads_it_once_statustick_answers() {
    let port = target().await;
    let dir = tempdir();
    let down = Arc::new(AtomicBool::new(false));
    let (connect_down, jobs_down) = (down.clone(), down.clone());
    let fake = Platform::start(vec![
        ("/v1/connect", Box::new(move |_, _| if connect_down.load(Ordering::SeqCst) { Answer::Reply(503, None, vec![]) } else { connected(json!({})) })),
        (
            "/v1/jobs",
            Box::new(move |_, n| {
                if jobs_down.load(Ordering::SeqCst) {
                    Answer::Reply(503, None, vec![])
                } else if n == 1 {
                    jobs(json!([{ "leaseId": "l-1", "expiresAt": in_one_minute(), "type": "tcp", "check": { "host": "127.0.0.1", "port": port }, "schedule": { "monitorId": "mnt_office", "intervalSeconds": 10 } }]))
                } else {
                    jobs(json!([]))
                }
            }),
        ),
        ("/v1/results/late", Box::new(|call, _| reply(200, json!({ "accepted": (0..call.body["results"].as_array().map_or(0, Vec::len)).collect::<Vec<_>>(), "rejected": [] })))),
    ])
    .await;
    let dir_text = dir.to_string_lossy().to_string();
    let mut agent = Agent::start(&[("STATUSTICK_URL", &fake.url), ("STATUSTICK_BUFFER_DIR", &dir_text)], &[]);
    until("the leased result", 20000, || !fake.calls("/v1/results").is_empty()).await;
    down.store(true, Ordering::SeqCst);
    until("the offline line", 30000, || agent.lines().iter().any(|line| line.starts_with("Offline:"))).await;
    let buffered = dir.join("results.jsonl");
    until("a buffered result", 30000, || std::fs::read_to_string(&buffered).is_ok_and(|text| text.contains("mnt_office"))).await;
    let jobs_file: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("jobs.json")).unwrap()).unwrap();
    down.store(false, Ordering::SeqCst);
    until("the late upload", 30000, || !fake.calls("/v1/results/late").is_empty()).await;
    until("the upload line", 20000, || agent.lines().iter().any(|line| line == "All buffered results are uploaded.")).await;
    let late = fake.calls("/v1/results/late").remove(0).body;
    let number = regex::Regex::new(r"\d+ (seconds|minutes)").unwrap();
    let uploading = regex::Regex::new(r"Uploading \d+").unwrap();
    let lines: Vec<String> = agent
        .lines()
        .into_iter()
        .filter(|line| ["Offline", "Uploading", "All buffered", "StatusTick answers again"].iter().any(|start| line.starts_with(start)))
        .map(|line| uploading.replace(&number.replace(&line, "N $1"), "Uploading N").to_string())
        .collect();
    assert_eq!(
        normalize(&jobs_file),
        json!({ "jobs": [{ "type": "tcp", "check": { "host": "127.0.0.1", "port": port }, "schedule": { "monitorId": "mnt_office", "intervalSeconds": 10 }, "passwordRemoved": false }] })
    );
    assert_eq!(late["dropped"], 0);
    assert_eq!(normalize(&late["results"][0]), json!({ "monitorId": "mnt_office", "result": { "status": "up" } }));
    assert_eq!(
        lines,
        [
            "Offline: no answer from StatusTick for N seconds. Checking 1 monitors on their own schedule for up to an hour and buffering the results.",
            "StatusTick answers again after N minutes offline.",
            "Uploading N results checked while offline.",
            "All buffered results are uploaded."
        ]
    );
    agent.stop().await;
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn answers_health_relays_listed_pings_and_serves_only_its_own_metric_names() {
    let (health, relay, metrics) = (free_port(), free_port(), free_port());
    let hash = hex::encode(Sha256::digest(b"tok_contract"));
    let fake = Platform::start(vec![
        ("/v1/connect", Box::new(move |_, _| connected(json!({ "relay": { "version": "v1", "pingHashes": [hash] } })))),
        ("/v1/jobs", Box::new(|_, n| if n == 1 { jobs(json!([])) } else { Answer::Hang })),
        (
            "/v1/heartbeats/relay",
            Box::new(|call, _| reply(200, json!({ "accepted": (0..call.body["pings"].as_array().map_or(0, Vec::len)).collect::<Vec<_>>(), "rejected": [] }))),
        ),
    ])
    .await;
    let (health_text, relay_text, metrics_text) = (health.to_string(), relay.to_string(), metrics.to_string());
    let mut agent = Agent::start(
        &[
            ("STATUSTICK_URL", &fake.url),
            ("STATUSTICK_HEALTH_PORT", &health_text),
            ("STATUSTICK_RELAY_PORT", &relay_text),
            ("STATUSTICK_RELAY_HOST", "127.0.0.1"),
            ("METRICS_PORT", &metrics_text),
            ("METRICS_HOST", "127.0.0.1"),
        ],
        &[],
    );
    until("a lease", 20000, || !fake.calls("/v1/jobs").is_empty()).await;
    let answers = vec![
        ("healthz", request(health, "GET", "/healthz").await),
        ("readyz", request(health, "GET", "/readyz").await),
        ("other", request(health, "GET", "/other").await),
        ("ping", request(relay, "GET", "/ping/tok_contract/start?run=job-1").await),
        ("v1", request(relay, "POST", "/v1/ping/tok_contract").await),
        ("unknown", request(relay, "GET", "/ping/tok_other").await),
        ("badRun", request(relay, "GET", "/ping/tok_contract?run=bad%20run").await),
        ("wrongPath", request(relay, "GET", "/nope").await),
        ("put", request(relay, "PUT", "/ping/tok_contract").await),
    ];
    let pings =
        || -> Vec<Value> { fake.calls("/v1/heartbeats/relay").iter().flat_map(|call| call.body["pings"].as_array().cloned().unwrap_or_default()).collect() };
    until("the relayed pings", 20000, || pings().len() >= 2).await;
    let text = request(metrics, "GET", "/metrics").await.1;
    let mut names: Vec<&str> = text.lines().filter(|line| line.starts_with("# TYPE st_")).filter_map(|line| line.split(' ').nth(2)).collect();
    names.sort();
    names.dedup();
    let expected = [
        ("healthz", 200, "ok\n"),
        ("readyz", 200, "ok\n"),
        ("other", 404, "not found\n"),
        ("ping", 200, "OK\n"),
        ("v1", 200, "OK\n"),
        ("unknown", 404, "Unknown ping URL\n"),
        ("badRun", 400, "Invalid run parameter: use 1 to 64 letters, digits, - or _\n"),
        ("wrongPath", 404, "Unknown ping URL\n"),
        ("put", 405, "Method not allowed\n"),
    ];
    for ((name, (status, body)), (expected_name, expected_status, expected_body)) in answers.iter().zip(expected) {
        assert_eq!((*name, *status, body.as_str()), (expected_name, expected_status, expected_body));
    }
    assert_eq!(
        normalize(&Value::Array(pings())),
        json!([{ "pingId": "tok_contract", "kind": "start", "run": "job-1" }, { "pingId": "tok_contract", "kind": "ping" }])
    );
    assert_eq!(
        names,
        [
            "st_buffer_dropped_total",
            "st_buffer_results",
            "st_build_info",
            "st_check_duration_seconds",
            "st_checks_total",
            "st_connected",
            "st_jobs",
            "st_last_contact_timestamp_seconds",
            "st_reconnects_total",
            "st_relay_pings_total",
            "st_uploads_total"
        ]
    );
    assert_eq!(request(metrics, "GET", "/other").await.0, 404);
    agent.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn refuses_to_start_with_a_wrong_setting_and_says_which() {
    let mut agent = Agent::start(&[("STATUSTICK_CONCURRENCY", "0")], &[]);
    let code = agent.exited().await;
    assert_eq!(code, Some(1));
    assert_eq!(agent.errors(), ["StatusTick agent cannot start: STATUSTICK_CONCURRENCY must be a whole number from 1 to 50"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn doctor_checks_the_connection_the_token_and_the_clock() {
    let fake = Platform::start(vec![(
        "/v1/heartbeat",
        Box::new(|_, _| Answer::Reply(401, Some(json!({ "error": "agent.unauthorized" })), vec![("date", httpdate(std::time::SystemTime::now()))])),
    )])
    .await;
    let mut agent = Agent::start(&[("STATUSTICK_URL", &fake.url), ("STATUSTICK_RELAY_PORT", "8099")], &["doctor"]);
    let code = agent.exited().await;
    let mut text = agent.lines().join("\n").replace(&fake.port.to_string(), "<port>");
    for (pattern, with) in [
        (r"\d+ ms", "N ms"),
        (r"\d+\.\d s (ahead of|behind)", "N s near"),
        (r"localhost is .+, N ms", "localhost is <addresses>, N ms"),
        (r"connected to [^,]+,", "connected to <address>,"),
        (r"StatusTick agent \S+ doctor", "StatusTick agent <version> doctor"),
    ] {
        text = regex::Regex::new(pattern).unwrap().replace_all(&text, with).to_string();
    }
    assert_eq!(code, Some(0));
    assert_eq!(
        text.lines().collect::<Vec<_>>(),
        [
            "StatusTick agent <version> doctor",
            "",
            "OK    Token format: sta_live_a1a1a1… (53 characters)",
            "OK    DNS for localhost: localhost is <addresses>, N ms",
            "OK    TCP <port>: connected to <address>, N ms",
            "SKIP  TLS to localhost: STATUSTICK_URL uses plain http (local development)",
            "OK    Proxy settings: no proxy set, connects directly",
            "OK    StatusTick answers: GET http://localhost:<port>/health answered ok",
            "OK    Token accepted: StatusTick accepts the token",
            "OK    Clock drift: N s near StatusTick",
            "OK    Heartbeat relay: port 8099; jobs call http://<agent address>:8099/ping/<token>/start?run=<id> and then /ping/<token>?run=<id> (or /fail?run=<id>); the same run id ties a start to its finish",
            "",
            "All checks passed."
        ]
    );
}

/// CONTRACT_DATABASES as type → (host, port).
fn databases() -> HashMap<String, (String, u16)> {
    std::env::var("CONTRACT_DATABASES")
        .unwrap_or_default()
        .split(',')
        .filter(|entry| !entry.is_empty())
        .filter_map(|entry| {
            let (kind, address) = entry.split_once('=')?;
            let (host, port) = address.rsplit_once(':')?;
            Some((kind.to_string(), (host.to_string(), port.parse().ok()?)))
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn databases_log_in_run_the_read_only_query_and_report_failures_with_their_codes() {
    let servers = databases();
    if servers.is_empty() {
        eprintln!("skipped: set CONTRACT_DATABASES to run the database checks");
        return;
    }
    let job = |lease: &str, kind: &str, check: Value| {
        let (host, port) = &servers[kind];
        let mut check = check;
        check.as_object_mut().unwrap().extend([("host".to_string(), json!(host)), ("port".to_string(), json!(port))]);
        json!({ "leaseId": lease, "expiresAt": in_one_minute(), "type": kind, "check": check })
    };
    let secret = json!("STATUSTICK_SECRET_DB");
    let mut list = Vec::new();
    if servers.contains_key("postgres") {
        list.extend([
            job("pg-up", "postgres", json!({ "user": "statustick", "passwordEnv": secret, "query": "SELECT 41 + 1", "expectedValue": "42" })),
            job(
                "pg-types",
                "postgres",
                json!({ "user": "statustick", "passwordEnv": secret, "query": "SELECT '{\"a\":1}'::jsonb", "expectedValue": "{\"a\":1}" }),
            ),
            job("pg-wrong-password", "postgres", json!({ "user": "statustick", "password": "wrong" })),
            job("pg-missing-table", "postgres", json!({ "user": "statustick", "passwordEnv": secret, "query": "SELECT * FROM missing_table" })),
            job("pg-two-statements", "postgres", json!({ "user": "statustick", "passwordEnv": secret, "query": "SELECT 1; SELECT 2" })),
            job("pg-no-user", "postgres", json!({})),
        ]);
    }
    if servers.contains_key("redis") {
        list.extend([
            job("redis-up", "redis", json!({ "passwordEnv": secret, "expectedValue": "PONG" })),
            job("redis-wrong-password", "redis", json!({ "password": "wrong" })),
            job("redis-database", "redis", json!({ "passwordEnv": secret, "database": "3" })),
        ]);
    }
    if servers.contains_key("mongodb") {
        list.extend([
            job("mongo-up", "mongodb", json!({ "user": "statustick", "passwordEnv": secret, "expectedValue": "1" })),
            job("mongo-wrong-password", "mongodb", json!({ "user": "statustick", "password": "wrong" })),
        ]);
    }
    let count = list.len();
    let list = Value::Array(list);
    let fake = Platform::start(vec![
        ("/v1/connect", Box::new(|_, _| connected(json!({})))),
        ("/v1/jobs", Box::new(move |_, n| if n == 1 { jobs(list.clone()) } else { Answer::Hang })),
    ])
    .await;
    let mut agent = Agent::start(&[("STATUSTICK_URL", &fake.url), ("STATUSTICK_CONCURRENCY", "20"), ("STATUSTICK_SECRET_DB", "contract")], &[]);
    until("all results", 40000, || fake.results().len() == count).await;
    let results: HashMap<String, Value> =
        fake.results().into_iter().map(|result| (result["leaseId"].as_str().unwrap().to_string(), normalize(&result["result"]))).collect();
    agent.stop().await;
    let expected = json!({
        "pg-up": { "status": "up", "details": { "value": "42" } },
        "pg-types": { "status": "up", "details": { "value": "{\"a\":1}" } },
        "pg-wrong-password": { "status": "down", "error": "password authentication failed for user \"statustick\"", "errorCode": "AUTH_FAILED" },
        "pg-missing-table": { "status": "down", "error": "Query failed (42P01)", "errorCode": "QUERY_FAILED" },
        "pg-two-statements": { "status": "down", "error": "Query failed (42601)", "errorCode": "QUERY_FAILED" },
        "pg-no-user": { "status": "down", "error": "A PostgreSQL check needs a user", "errorCode": "AUTH_FAILED" },
        "redis-up": { "status": "up", "details": { "value": "PONG" } },
        "redis-wrong-password": { "status": "down", "error": "WRONGPASS invalid username-password pair or user is disabled.", "errorCode": "AUTH_FAILED" },
        "redis-database": { "status": "up", "details": {} },
        "mongo-up": { "status": "up", "details": { "value": "1" } },
        "mongo-wrong-password": { "status": "down", "error": "Authentication failed.", "errorCode": "AUTH_FAILED" }
    });
    for (lease, result) in &results {
        assert_eq!(result, &expected[lease.as_str()], "{lease}");
    }
}
