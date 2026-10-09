//! The process sandbox: each run is its own `node run.mts` from `sandbox/`, as one of the run users
//! when the image allows it, with the job on stdin and its outcome on stdout. Its only way out is the proxy the caller
//! gives it, and its guard refuses every other connection.
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

pub const WALL_LIMIT: Duration = Duration::from_secs(120);
pub const MAX_ARTIFACT_BYTES: usize = 20 * 1024 * 1024;
const FIRST_RUN_UID: u32 = 10101;
const PROXY_START: Duration = Duration::from_secs(10);
// run.mts exits with this when the guard refused one of the script's connections.
const REFUSED_EXIT: i32 = 3;
const REFUSED_MARKER: &str = "egress-refused";

/// What a run gave: Playwright's report, the base64 files by sandbox path, and whether its guard refused a connection.
#[derive(Debug, Clone)]
pub struct RunOutput {
    pub report: Value,
    pub files: Map<String, Value>,
    pub refused: bool,
}

/// The package's proxy for one run: the run's allowed hosts, public addresses only. Stopped when dropped.
pub struct PackageProxy {
    _child: Child,
    pub url: String,
}

/// Starts the package's proxy for one run on a free loopback port and prints the port.
const PROXY: &str = "const { createProxy, parseAllowedHosts } = await import(process.argv[1]);\n\
const server = createProxy({ allowed: parseAllowedHosts(process.env.ST_ALLOWED_HOSTS) });\n\
server.listen(0, '127.0.0.1', () => process.stdout.write(`${server.address().port}\\n`));\n";

// Runs as the run's user and does nothing as any other user: kill(-1) would stop every process of the caller's user.
const END_USER: &str = "\nconst fs = require('node:fs');\nconst path = require('node:path');\nconst [uid, work, ...roots] = process.argv.slice(1);\n\
if (process.getuid() !== Number(uid) || Number(uid) === 0) process.exit(1);\ntry { process.kill(-1, 'SIGKILL'); } catch {}\n\
fs.rmSync(work, { recursive: true, force: true });\nfor (const root of roots) {\n  let names = [];\n  try { names = fs.readdirSync(root); } catch {}\n\
  for (const name of names) {\n    const file = path.join(root, name);\n    try { if (fs.lstatSync(file).uid === process.getuid()) fs.rmSync(file, { recursive: true, force: true }); } catch {}\n  }\n}\n";

/// A run that went over a limit or gave no result; the message is shown to the customer.
#[derive(Debug, Clone, PartialEq)]
pub enum RunError {
    Limit(String),
    Sandbox(String),
    /// The run could not start at all, as when no run user is free or `node` cannot be started.
    Start(String),
}

impl RunError {
    pub fn message(&self) -> &str {
        match self {
            RunError::Limit(message) | RunError::Sandbox(message) | RunError::Start(message) => message,
        }
    }

    pub fn time() -> Self {
        RunError::Limit(format!("Run stopped: it went over the {} second time limit.", WALL_LIMIT.as_secs()))
    }

    pub fn artifacts() -> Self {
        RunError::Limit(format!("Run failed: the screenshot and trace are larger than the {} MB limit.", MAX_ARTIFACT_BYTES / 1024 / 1024))
    }

    pub fn no_result() -> Self {
        RunError::Sandbox("The browser run ended without a result.".into())
    }
}

/// Report and base64 artifacts, with room for the JSON around them.
pub fn max_output_bytes() -> usize {
    (MAX_ARTIFACT_BYTES * 4).div_ceil(3) + 4 * 1024 * 1024
}

/// What `run.mts` printed: the Playwright report and the base64 files by sandbox path.
pub fn read_output(stdout: &[u8]) -> Result<(Value, Map<String, Value>), RunError> {
    let output: Value = serde_json::from_slice(stdout).map_err(|_| RunError::no_result())?;
    let Some(fields) = output.as_object() else { return Err(RunError::no_result()) };
    if fields.get("artifactsTooLarge") == Some(&Value::Bool(true)) {
        return Err(RunError::artifacts());
    }
    let report = fields.get("report").filter(|report| statustick_checks::util::truthy(Some(report))).cloned().ok_or_else(RunError::no_result)?;
    Ok((report, fields.get("files").and_then(Value::as_object).cloned().unwrap_or_default()))
}

/// A random version 4 UUID, as `crypto.randomUUID()`.
pub fn random_uuid() -> String {
    let mut bytes: [u8; 16] = rand::random();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode(bytes);
    format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
}

pub struct Sandbox {
    pub runner_dir: PathBuf,
    pub work_root: PathBuf,
    pub browsers: String,
    /// setpriv with the setuid and setgid file capabilities; None runs checks as the caller's user.
    pub run_as: Option<String>,
    users: Mutex<Vec<u32>>,
}

fn run_as_args(uid: u32, command: &[&str]) -> Vec<String> {
    let mut args = vec![format!("--reuid={uid}"), format!("--regid={uid}"), "--clear-groups".into(), "--no-new-privs".into()];
    args.extend(command.iter().map(|part| part.to_string()));
    args
}

impl Sandbox {
    pub fn new(runner_dir: PathBuf, work_root: PathBuf, browsers: String, run_as: Option<String>, users: usize) -> Self {
        let free = (0..users as u32).map(|index| FIRST_RUN_UID + index).collect();
        Sandbox { runner_dir, work_root, browsers, run_as, users: Mutex::new(free) }
    }

    /// Stops every process of [uid] and removes [work] and what the user left in the work root and /dev/shm. False when
    /// the user could not be switched to.
    pub async fn end_user(&self, uid: u32, work: &Path) -> bool {
        let Some(run_as) = &self.run_as else { return false };
        let work = work.to_string_lossy().to_string();
        let root = self.work_root.to_string_lossy().to_string();
        let args = run_as_args(uid, &["node", "-e", END_USER, &uid.to_string(), &work, &root, "/dev/shm"]);
        let status = Command::new(run_as)
            .args(&args)
            .current_dir("/")
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
        status.is_ok_and(|status| status.success())
    }

    /// Whether the container lets the caller switch to a run's user: SETUID and SETGID, and no `no-new-privileges`.
    pub async fn isolation_available(&self) -> bool {
        let first = self.users.lock().expect("run users").first().copied();
        match first {
            Some(uid) => self.end_user(uid, &self.work_root.join(format!("st-run-{}", random_uuid()))).await,
            None => false,
        }
    }

    /// Starts the package's `proxy.mts` with [allowed_hosts], for runs that may reach public hosts only.
    pub async fn package_proxy(&self, allowed_hosts: &[String]) -> Result<PackageProxy, RunError> {
        let mut child = Command::new("node")
            .args(["--input-type=module", "-e", PROXY, &self.runner_dir.join("proxy.mts").to_string_lossy()])
            .current_dir(&self.runner_dir)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("ST_ALLOWED_HOSTS", allowed_hosts.join(","))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| RunError::no_result())?;
        let stdout = child.stdout.take().ok_or_else(RunError::no_result)?;
        let mut line = String::new();
        let read = tokio::time::timeout(PROXY_START, BufReader::new(stdout).read_line(&mut line)).await;
        match (read, line.trim().parse::<u16>()) {
            (Ok(Ok(_)), Ok(port)) => Ok(PackageProxy { _child: child, url: format!("http://127.0.0.1:{port}") }),
            _ => Err(RunError::no_result()),
        }
    }

    fn take_user(&self) -> Option<u32> {
        self.run_as.as_ref()?;
        let mut users = self.users.lock().expect("run users");
        (!users.is_empty()).then(|| users.remove(0))
    }

    fn give_back(&self, uid: Option<u32>) {
        if let Some(uid) = uid {
            self.users.lock().expect("run users").push(uid);
        }
    }

    /// Runs [job] (the run's script, file name, variables and snapshot mode) with [proxy] as its only way out.
    pub async fn run(&self, job: &Map<String, Value>, proxy: &str) -> Result<RunOutput, RunError> {
        let uid = self.take_user();
        if self.run_as.is_some() && uid.is_none() {
            return Err(RunError::Start("No free user for a browser run.".into()));
        }
        // The run's user makes its own folder (run.mts): the caller's user cannot hand one over.
        let work = self.work_root.join(format!("st-run-{}", random_uuid()));
        if uid.is_none() {
            let _ = std::fs::create_dir_all(&work);
        }
        let outcome = self.run_child(job, proxy, uid, &work).await;
        match uid {
            Some(uid) => {
                self.end_user(uid, &work).await;
            }
            None => {
                let _ = std::fs::remove_dir_all(&work);
            }
        }
        self.give_back(uid);
        outcome
    }

    async fn run_child(&self, job: &Map<String, Value>, proxy: &str, uid: Option<u32>, work: &Path) -> Result<RunOutput, RunError> {
        let runner = self.runner_dir.join("run.mts").to_string_lossy().to_string();
        let program = match (&self.run_as, uid) {
            (Some(run_as), Some(_)) => run_as.clone(),
            _ => "node".to_string(),
        };
        let mut command = match (&self.run_as, uid) {
            (Some(run_as), Some(uid)) => {
                let mut command = Command::new(run_as);
                command.args(run_as_args(uid, &["node", &runner]));
                command
            }
            _ => {
                let mut command = Command::new("node");
                command.arg(&runner);
                command
            }
        };
        let mut child = command
            .current_dir(&self.runner_dir)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("ST_WORK_DIR", work)
            .env("PLAYWRIGHT_BROWSERS_PATH", &self.browsers)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| RunError::Start(format!("spawn {program} {}", statustick_checks::util::io_code(&error))))?;
        let mut input = job.clone();
        input.insert("proxy".into(), Value::from(proxy));
        input.insert("guard".into(), Value::Bool(true));
        input.insert("maxArtifactBytes".into(), json!(MAX_ARTIFACT_BYTES));
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(Value::Object(input).to_string().as_bytes()).await;
        }
        let mut stdout = child.stdout.take().ok_or_else(RunError::no_result)?;
        let reading = async {
            let mut output = Vec::new();
            let mut chunk = vec![0u8; 64 * 1024];
            loop {
                let read = stdout.read(&mut chunk).await.unwrap_or(0);
                if read == 0 {
                    return Some(output);
                }
                if output.len() + read > max_output_bytes() {
                    return None;
                }
                output.extend_from_slice(&chunk[..read]);
            }
        };
        let outcome = tokio::time::timeout(WALL_LIMIT, reading).await;
        let stop = |child: &mut Child| {
            let _ = child.start_kill();
        };
        let output = match outcome {
            Err(_) => {
                stop(&mut child);
                return Err(RunError::time());
            }
            Ok(None) => {
                stop(&mut child);
                return Err(RunError::artifacts());
            }
            Ok(Some(output)) => output,
        };
        let status = tokio::time::timeout(Duration::from_secs(10), child.wait()).await.ok().and_then(Result::ok);
        let refused = status.and_then(|status| status.code()) == Some(REFUSED_EXIT) || work.join(REFUSED_MARKER).exists();
        read_output(&output).map(|(report, files)| RunOutput { report, files, refused })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_run_output() {
        let (report, files) = read_output(br#"{"exitCode":0,"report":{"suites":[]},"files":{"/w/out/a.png":"aGk="}}"#).unwrap();
        assert_eq!(report, json!({ "suites": [] }));
        assert_eq!(files["/w/out/a.png"], "aGk=");
        assert_eq!(read_output(b"not json").unwrap_err(), RunError::no_result());
        assert_eq!(read_output(br#"{"report":null}"#).unwrap_err(), RunError::no_result());
        assert_eq!(
            read_output(br#"{"report":{},"artifactsTooLarge":true}"#).unwrap_err().message(),
            "Run failed: the screenshot and trace are larger than the 20 MB limit."
        );
        assert_eq!(RunError::time().message(), "Run stopped: it went over the 120 second time limit.");
    }

    #[test]
    fn makes_version_4_uuids() {
        let id = random_uuid();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
        assert!(matches!(&id[19..20], "8" | "9" | "a" | "b"));
    }

    const STUB_RUN: &str = r#"import net from 'node:net';
let data = '';
for await (const chunk of process.stdin) data += chunk;
const job = JSON.parse(data);
if (job.script === 'big') {
  process.stdout.write('x'.repeat(31 * 1024 * 1024));
} else {
const port = Number(new URL(job.proxy).port);
const proxyAnswer = await new Promise((resolve) => {
  const socket = net.connect(port, '127.0.0.1', () => socket.write('CONNECT blocked.example:443 HTTP/1.1\r\nHost: blocked.example:443\r\n\r\n'));
  socket.on('data', (chunk) => { resolve(chunk.toString().split('\r\n')[0]); socket.destroy(); });
  socket.on('error', (error) => resolve(error.message));
});
const report = { seen: { proxyAnswer, env: Object.keys(process.env).filter((name) => !name.startsWith('__CF_')).sort(), guard: job.guard, fileName: job.fileName, variables: job.variables }, suites: [], errors: [], stats: { duration: 12 } };
process.stdout.write(JSON.stringify({ exitCode: 0, report, files: { '/w/out/s.png': Buffer.from('png').toString('base64') } }));
}
"#;

    fn runner_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("browser-sandbox-{}", random_uuid()));
        std::fs::create_dir_all(&dir).unwrap();
        let proxy = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sandbox/proxy.mts");
        std::fs::copy(proxy, dir.join("proxy.mts")).unwrap();
        std::fs::write(dir.join("run.mts"), STUB_RUN).unwrap();
        dir
    }

    #[tokio::test]
    async fn runs_a_job_with_its_own_proxy_and_only_its_environment() {
        let dir = runner_dir();
        let sandbox = Sandbox::new(dir.clone(), std::env::temp_dir(), "/ms-playwright".into(), None, 1);
        let job = json!({ "script": "x", "fileName": "check.spec.ts", "variables": { "LOGIN": "a" } }).as_object().cloned().unwrap();
        let proxy = sandbox.package_proxy(&["shop.example.com".to_string()]).await.unwrap();
        let RunOutput { report, files, refused } = sandbox.run(&job, &proxy.url).await.unwrap();
        assert!(!refused);
        assert_eq!(report["seen"]["proxyAnswer"], "HTTP/1.1 403 Forbidden");
        assert_eq!(report["seen"]["env"], json!(["PATH", "PLAYWRIGHT_BROWSERS_PATH", "ST_WORK_DIR"]));
        assert_eq!(report["seen"]["guard"], true);
        assert_eq!(report["seen"]["variables"], json!({ "LOGIN": "a" }));
        assert_eq!(files["/w/out/s.png"], "cG5n");
        let big = json!({ "script": "big", "fileName": "check.spec.ts", "variables": {} }).as_object().cloned().unwrap();
        assert_eq!(sandbox.run(&big, &proxy.url).await.unwrap_err(), RunError::artifacts());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
