//! Browser checks in the agent image against a fake StatusTick on this machine. They need the image with Chromium:
//!   docker build -t statustick-agent:dev . && CONTRACT_IMAGE=statustick-agent:dev cargo test -p statustick-agent --test browser -- --ignored
mod common;

use std::process::{Command, Stdio};

use axum::Router;
use axum::body::Body;
use axum::http::HeaderValue;
use axum::response::Response;
use common::*;
use serde_json::{Value, json};
use tokio::net::TcpListener;

const TOKEN: &str = "sta_live_b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";
const RUN_UIDS: std::ops::RangeInclusive<u64> = 10101..=10108;

fn image() -> String {
    std::env::var("CONTRACT_IMAGE").expect("set CONTRACT_IMAGE to the agent image")
}

/// A page titled "Contract", reached from the container as `site.internal`.
async fn site() -> String {
    let app = Router::new().fallback(|| async {
        let mut response = Response::new(Body::from("<title>Contract</title><p>ok</p>"));
        response.headers_mut().insert("content-type", HeaderValue::from_static("text/html"));
        response
    });
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://site.internal:{port}/")
}

fn job(lease: &str, body: &str) -> Value {
    let expires = (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    json!({
        "leaseId": lease,
        "expiresAt": expires,
        "type": "browser",
        "check": { "script": format!("import {{ test, expect }} from '@playwright/test';\n{body}"), "language": "typescript", "variables": null }
    })
}

/// One agent container with the install command's capabilities; removed on drop.
struct Container(String);

impl Container {
    fn start(port: u16, env: &[(&str, &str)]) -> Container {
        let name = format!("agent-browser-contract-{}-{}", std::process::id(), rand_suffix());
        let mut command = Command::new("docker");
        command.args(["run", "-d", "--name", &name, "--shm-size", "512m", "--cap-drop", "ALL", "--cap-add", "SETUID", "--cap-add", "SETGID"]);
        command.args(["--add-host", "statustick.localhost:host-gateway", "--add-host", "site.internal:host-gateway"]);
        let url = format!("http://statustick.localhost:{port}");
        let base = [
            ("STATUSTICK_TOKEN", TOKEN),
            ("STATUSTICK_URL", &url),
            ("STATUSTICK_HOSTNAME", "contract-host"),
            ("STATUSTICK_INSTALL", "docker"),
            ("STATUSTICK_SECRET_DB", "agent-only-secret"),
        ];
        for (key, value) in base.iter().chain(env) {
            command.args(["-e", &format!("{key}={value}")]);
        }
        let status = command.arg(image()).stdout(Stdio::null()).status().unwrap();
        assert!(status.success(), "docker run failed");
        Container(name)
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        Command::new("docker").args(["rm", "-f", &self.0]).stdout(Stdio::null()).stderr(Stdio::null()).status().ok();
    }
}

struct Seen {
    connect: Value,
    results: Vec<Value>,
    uploads: Vec<String>,
}

/// Runs [list] with [env] and [settings] and returns what StatusTick saw.
async fn run(list: Vec<Value>, env: &[(&str, &str)], settings: Value) -> Seen {
    let count = list.len();
    let (connect_settings, lease_settings) = (settings.clone(), settings);
    let fake = Platform::start(vec![
        ("/v1/connect", Box::new(move |_, _| connected(json!({ "settings": connect_settings })))),
        ("/v1/jobs", Box::new(move |_, n| if n == 1 { reply(200, json!({ "jobs": list, "settings": lease_settings })) } else { Answer::Hang })),
        ("*", Box::new(|_, _| Answer::Reply(204, None, vec![]))),
    ])
    .await;
    let _container = Container::start(fake.port, env);
    until("all results", 120000, || fake.results().len() == count).await;
    let mut uploads: Vec<String> = fake
        .all()
        .into_iter()
        .filter(|call| call.path.contains("/artifacts/"))
        .map(|call| format!("{} {} {}", call.method, call.path, if call.size > 0 { "data" } else { "empty" }))
        .collect();
    uploads.sort();
    Seen { connect: fake.calls("/v1/connect").remove(0).body, results: fake.results(), uploads }
}

fn status(seen: &Seen, lease: &str) -> String {
    let result = seen.results.iter().find(|result| result["leaseId"] == lease).unwrap_or_else(|| panic!("no result for {lease}"));
    result["result"]["status"].as_str().unwrap_or_default().to_string()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs CONTRACT_IMAGE, an agent image with Chromium"]
async fn reports_browser_support_runs_passing_and_failing_scripts_and_uploads_their_artifacts() {
    let site = site().await;
    let seen = run(
        vec![
            job("l-pass", &format!("test('home', async ({{ page }}) => {{ await page.goto('{site}'); await expect(page).toHaveTitle('Contract'); }});")),
            job(
                "l-fail",
                &format!("test('title', async ({{ page }}) => {{ await page.goto('{site}'); await expect(page).toHaveTitle('Other', {{ timeout: 500 }}); }});"),
            ),
            job("l-error", "import missing from './missing.ts';\ntest('x', async () => { missing(); });"),
        ],
        &[],
        json!({}),
    )
    .await;
    assert!(seen.connect["capabilities"]["browser"].is_object(), "no browser support: {}", seen.connect["capabilities"]);
    assert_eq!((status(&seen, "l-pass"), status(&seen, "l-fail"), status(&seen, "l-error")), ("up".into(), "down".into(), "error".into()));
    assert!(seen.uploads.iter().all(|upload| upload.ends_with(" data")), "{:?}", seen.uploads);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs CONTRACT_IMAGE, an agent image with Chromium"]
async fn runs_as_a_run_user_without_the_agent_environment() {
    let seen = run(
        vec![job(
            "l-env",
            "test('env', async () => { throw new Error('ENV' + JSON.stringify({ uid: process.getuid(), token: 'STATUSTICK_TOKEN' in process.env, secret: Object.values(process.env).includes('agent-only-secret') })); });",
        )],
        &[],
        json!({}),
    )
    .await;
    let error = seen.results[0]["result"]["error"].as_str().unwrap_or_default().to_string();
    let start = error.find("ENV").expect("the script's error") + 3;
    let end = error[start..].find('}').unwrap() + start + 1;
    let env: Value = serde_json::from_str(&error[start..end]).unwrap();
    assert!(RUN_UIDS.contains(&env["uid"].as_u64().unwrap()), "run uid {}", env["uid"]);
    assert_eq!((&env["token"], &env["secret"]), (&json!(false), &json!(false)));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs CONTRACT_IMAGE, an agent image with Chromium"]
async fn refuses_cloud_metadata_and_targets_outside_statustick_allow() {
    let site = site().await;
    let metadata =
        run(vec![job("l-metadata", "test('meta', async ({ page }) => { await page.goto('http://169.254.169.254/latest/'); });")], &[], json!({})).await;
    assert_ne!(status(&metadata, "l-metadata"), "up");
    let listed = run(
        vec![job("l-listed", &format!("test('listed', async ({{ page }}) => {{ await page.goto('{site}'); }});"))],
        &[("STATUSTICK_ALLOW", "10.0.0.0/8")],
        json!({}),
    )
    .await;
    assert_ne!(status(&listed, "l-listed"), "up");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs CONTRACT_IMAGE, an agent image with Chromium"]
async fn answers_browser_jobs_without_running_them_when_browser_runs_are_off() {
    let seen = run(vec![job("l-off", "test('x', async () => {});")], &[], json!({ "browserRuns": 0 })).await;
    assert_ne!(status(&seen, "l-off"), "up");
    assert!(seen.uploads.is_empty(), "{:?}", seen.uploads);
}
