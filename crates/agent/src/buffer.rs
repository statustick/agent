//! The offline buffer: results checked while StatusTick is unreachable, and the jobs the agent repeats
//! meanwhile. With STATUSTICK_BUFFER_DIR both are also kept on disk, so they
//! survive a restart; database passwords and MCP auth header values never are.
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

use crate::schema::{is_check_type, valid_schedule};

const RESULTS_FILE: &str = "results.jsonl";
const JOBS_FILE: &str = "jobs.json";
const FILE_MODE: u32 = 0o600;
const FORGET_AFTER_MS: i64 = 24 * 60 * 60 * 1000;
const OFFLINE_LEASE: &str = "offline";
const SECRET_FIELDS: [&str; 2] = ["password", "authHeaderValue"];

pub type Log = std::sync::Arc<dyn Fn(&str) + Send + Sync>;

pub fn write_atomically(file: &Path, data: &str) -> std::io::Result<()> {
    let temporary = PathBuf::from(format!("{}.tmp", file.display()));
    let mut out = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(FILE_MODE).open(&temporary)?;
    out.write_all(data.as_bytes())?;
    drop(out);
    std::fs::rename(&temporary, file)
}

fn error_text(error: &std::io::Error) -> String {
    let code = statustick_checks::util::io_code(error);
    format!("{code}: {}", error.kind().to_string().to_lowercase())
}

/// At most `size` entries, oldest first; when full, the oldest is dropped and counted. On disk an append-only JSON
/// lines file: a `{"dropped": n}` line, then one entry per line, rewritten when entries are uploaded or the file holds
/// twice the bound.
pub struct LineBuffer {
    pub size: usize,
    pub file: Option<PathBuf>,
    entries: Vec<(u64, Value)>,
    next_id: u64,
    pub dropped: u64,
    /// Entries dropped since the agent started; unlike [dropped] it never starts again.
    pub dropped_total: u64,
    appended: usize,
    log: Log,
    valid: fn(&Value) -> bool,
    time_of: fn(&Value) -> String,
    noun: &'static str,
}

impl LineBuffer {
    pub fn new(size: usize, file: Option<PathBuf>, log: Log, valid: fn(&Value) -> bool, time_of: fn(&Value) -> String, noun: &'static str) -> Self {
        let mut buffer = LineBuffer { size, file, entries: Vec::new(), next_id: 0, dropped: 0, dropped_total: 0, appended: 0, log, valid, time_of, noun };
        buffer.load();
        buffer
    }

    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// The time of the oldest entry.
    pub fn since(&self) -> Option<String> {
        self.entries.first().map(|(_, entry)| (self.time_of)(entry))
    }

    pub fn buffering(&self) -> Option<Value> {
        (self.count() > 0).then(|| json!({ "count": self.count(), "since": self.since() }))
    }

    fn push(&mut self, entry: Value) {
        self.next_id += 1;
        self.entries.push((self.next_id, entry));
    }

    pub fn add(&mut self, entry: Value) {
        self.push(entry.clone());
        let over = self.entries.len().saturating_sub(self.size);
        if over > 0 {
            self.entries.drain(..over);
            self.dropped += over as u64;
            self.dropped_total += over as u64;
        }
        self.append(&entry);
    }

    /// The oldest entries with their ids, at most `max` and, but for a single one, at most `max_bytes` of JSON.
    pub fn batch(&self, max: usize, max_bytes: usize) -> Vec<(u64, Value)> {
        let mut batch = Vec::new();
        let mut bytes = 0;
        for (id, entry) in &self.entries {
            let size = entry.to_string().len() + 1;
            if batch.len() >= max || (!batch.is_empty() && bytes + size > max_bytes) {
                break;
            }
            batch.push((*id, entry.clone()));
            bytes += size;
        }
        batch
    }

    /// Forgets entries StatusTick answered; the dropped count starts again once the buffer is empty.
    pub fn remove(&mut self, done: &[u64]) {
        if done.is_empty() {
            return;
        }
        self.entries.retain(|(id, _)| !done.contains(id));
        if self.entries.is_empty() {
            self.dropped = 0;
        }
        self.rewrite();
    }

    fn load(&mut self) {
        let Some(file) = self.file.clone() else { return };
        let text = match std::fs::read_to_string(&file) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => return self.fail(&error_text(&error)),
        };
        let mut dropped = 0u64;
        let mut entries = Vec::new();
        for line in text.split('\n').filter(|line| !line.is_empty()) {
            // A line cut short when the agent stopped mid-write is skipped.
            let Ok(value) = serde_json::from_str::<Value>(line) else { continue };
            if (self.valid)(&value) {
                entries.push(value);
            } else if let Some(count) =
                value.as_object().filter(|object| !object.contains_key("monitorId")).and_then(|object| object.get("dropped")).and_then(Value::as_u64)
            {
                dropped = count;
            }
        }
        let over = entries.len().saturating_sub(self.size);
        for entry in entries.into_iter().skip(over) {
            self.push(entry);
        }
        self.dropped = dropped + over as u64;
        self.rewrite();
        if self.count() > 0 {
            (self.log)(&format!("Loaded {} buffered {} from {}.", self.count(), self.noun, file.display()));
        }
    }

    fn append(&mut self, entry: &Value) {
        let Some(file) = self.file.clone() else { return };
        let written = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(FILE_MODE)
            .open(&file)
            .and_then(|mut out| out.write_all(format!("{entry}\n").as_bytes()));
        if let Err(error) = written {
            return self.fail(&error_text(&error));
        }
        self.appended += 1;
        if self.appended > self.size {
            self.rewrite();
        }
    }

    fn rewrite(&mut self) {
        let Some(file) = self.file.clone() else { return };
        let mut data = format!("{}\n", json!({ "dropped": self.dropped }));
        for (_, entry) in &self.entries {
            data.push_str(&format!("{entry}\n"));
        }
        match write_atomically(&file, &data) {
            Ok(()) => self.appended = 0,
            Err(error) => self.fail(&error_text(&error)),
        }
    }

    fn fail(&mut self, reason: &str) {
        if let Some(file) = &self.file {
            (self.log)(&format!("Buffer file {} cannot be used ({reason}); buffering in memory only.", file.display()));
        }
        self.file = None;
    }
}

fn is_late_result(value: &Value) -> bool {
    value.get("monitorId").is_some_and(Value::is_string)
        && value.get("checkedAt").is_some_and(Value::is_string)
        && value.get("result").is_some_and(Value::is_object)
}

pub fn result_buffer(size: usize, dir: Option<&str>, log: Log) -> LineBuffer {
    LineBuffer::new(
        size,
        dir.map(|dir| Path::new(dir).join(RESULTS_FILE)),
        log,
        is_late_result,
        |entry| entry["checkedAt"].as_str().unwrap_or("").to_string(),
        "results",
    )
}

pub struct Remembered {
    pub job: Value,
    pub monitor_id: String,
    pub interval_seconds: i64,
    leased_at: i64,
    pub next_at: i64,
    pub running: bool,
    /// Restored from disk without its database password or MCP auth header value: skipped until a fresh lease brings it.
    pub password_missing: bool,
    stored: String,
}

/// The job as written to disk: no lease, no database password and no MCP auth header value.
fn stored_form(kind: &str, check: &Map<String, Value>, monitor_id: &str, interval: i64, password_removed: Option<bool>) -> String {
    let mut kept = check.clone();
    let removed = SECRET_FIELDS.iter().any(|field| kept.get(*field).and_then(Value::as_str).is_some_and(|value| !value.is_empty()));
    for field in SECRET_FIELDS {
        kept.remove(field);
    }
    json!({
        "type": kind,
        "check": kept,
        "schedule": { "monitorId": monitor_id, "intervalSeconds": interval },
        "passwordRemoved": password_removed.unwrap_or(removed),
    })
    .to_string()
}

/// The last leased job of each monitor, to repeat on its interval while StatusTick is unreachable. Browser and
/// certificate jobs are not kept. A monitor not leased for a day is forgotten.
pub struct JobMemory {
    file: Option<PathBuf>,
    pub jobs: Vec<Remembered>,
    log: Log,
}

impl JobMemory {
    pub fn new(dir: Option<&str>, log: Log, now: i64) -> Self {
        let mut memory = JobMemory { file: dir.map(|dir| Path::new(dir).join(JOBS_FILE)), jobs: Vec::new(), log };
        memory.load(now);
        memory
    }

    pub fn size(&self) -> usize {
        self.jobs.len()
    }

    pub fn remember(&mut self, job: &Value, now: i64) {
        let kind = job.get("type").and_then(Value::as_str).unwrap_or("");
        if kind == "browser" || kind == "ssl" {
            return;
        }
        let Some((monitor_id, interval)) = valid_schedule(job.get("schedule")) else { return };
        let check = job.get("check").and_then(Value::as_object).cloned().unwrap_or_default();
        let stored = stored_form(kind, &check, &monitor_id, interval, None);
        let entry = Remembered {
            job: job.clone(),
            monitor_id: monitor_id.clone(),
            interval_seconds: interval,
            leased_at: now,
            next_at: now + interval * 1000,
            running: false,
            password_missing: false,
            stored: stored.clone(),
        };
        let mut changed = true;
        match self.jobs.iter_mut().find(|remembered| remembered.monitor_id == monitor_id) {
            Some(previous) => {
                changed = previous.stored != stored;
                *previous = entry;
            }
            None => self.jobs.push(entry),
        }
        let before = self.jobs.len();
        self.jobs.retain(|remembered| now - remembered.leased_at <= FORGET_AFTER_MS);
        changed |= self.jobs.len() != before;
        if changed {
            self.save();
        }
    }

    /// The monitors whose next check is due and that can run.
    pub fn due(&self, now: i64) -> Vec<String> {
        self.jobs.iter().filter(|job| !job.running && !job.password_missing && job.next_at <= now).map(|job| job.monitor_id.clone()).collect()
    }

    pub fn get_mut(&mut self, monitor_id: &str) -> Option<&mut Remembered> {
        self.jobs.iter_mut().find(|job| job.monitor_id == monitor_id)
    }

    fn load(&mut self, now: i64) {
        let Some(file) = self.file.clone() else { return };
        let text = match std::fs::read_to_string(&file) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => return (self.log)(&format!("Ignoring {}: {}", file.display(), error_text(&error))),
        };
        let saved: Value = match serde_json::from_str(&text) {
            Ok(saved) => saved,
            Err(error) => return (self.log)(&format!("Ignoring {}: {error}", file.display())),
        };
        for item in saved.get("jobs").and_then(Value::as_array).cloned().unwrap_or_default() {
            let Some(kind) = item.get("type").and_then(Value::as_str).filter(|kind| is_check_type(kind)) else { continue };
            let Some(check) = item.get("check").and_then(Value::as_object) else { continue };
            let Some((monitor_id, interval)) = valid_schedule(item.get("schedule")) else { continue };
            let password_missing = item.get("passwordRemoved") == Some(&Value::Bool(true));
            let schedule = json!({ "monitorId": monitor_id, "intervalSeconds": interval });
            let job = json!({ "leaseId": OFFLINE_LEASE, "expiresAt": "", "type": kind, "check": check, "schedule": schedule });
            let stored = stored_form(kind, check, &monitor_id, interval, Some(password_missing));
            let entry = Remembered {
                job,
                monitor_id: monitor_id.clone(),
                interval_seconds: interval,
                leased_at: now,
                next_at: now,
                running: false,
                password_missing,
                stored,
            };
            match self.jobs.iter_mut().find(|remembered| remembered.monitor_id == monitor_id) {
                Some(previous) => *previous = entry,
                None => self.jobs.push(entry),
            }
        }
    }

    fn save(&mut self) {
        let Some(file) = self.file.clone() else { return };
        let data = format!("{{\"jobs\":[{}]}}", self.jobs.iter().map(|job| job.stored.as_str()).collect::<Vec<_>>().join(","));
        if let Err(error) = write_atomically(&file, &data) {
            (self.log)(&format!("Job file {} cannot be written ({}); remembering jobs in memory only.", file.display(), error_text(&error)));
            self.file = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn folder(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("agent-buffer-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn quiet() -> Log {
        Arc::new(|_: &str| {})
    }

    fn late(monitor: &str, at: &str) -> Value {
        json!({ "monitorId": monitor, "checkedAt": at, "result": { "status": "up", "responseTime": 1 } })
    }

    #[test]
    fn keeps_at_most_the_bound_and_counts_what_it_drops() {
        let mut buffer = result_buffer(2, None, quiet());
        for index in 0..3 {
            buffer.add(late("mnt_1", &format!("2026-10-03T08:00:0{index}.000Z")));
        }
        assert_eq!(buffer.count(), 2);
        assert_eq!(buffer.dropped, 1);
        assert_eq!(buffer.since().as_deref(), Some("2026-10-03T08:00:01.000Z"));
        let batch = buffer.batch(1, 1000);
        buffer.remove(&[batch[0].0]);
        assert_eq!(buffer.count(), 1);
        buffer.remove(&[buffer.batch(5, 1000)[0].0]);
        assert_eq!(buffer.dropped, 0);
    }

    #[test]
    fn reads_the_buffer_back_from_disk_with_the_dropped_count() {
        let dir = folder("results");
        let lines: Arc<Mutex<Vec<String>>> = Arc::default();
        let seen = lines.clone();
        let log: Log = Arc::new(move |line: &str| seen.lock().unwrap().push(line.to_string()));
        {
            let mut buffer = result_buffer(3, dir.to_str(), log.clone());
            for index in 0..5 {
                buffer.add(late("mnt_1", &format!("t{index}")));
            }
        }
        let buffer = result_buffer(3, dir.to_str(), log);
        assert_eq!(buffer.count(), 3);
        assert_eq!(buffer.dropped, 2);
        assert!(lines.lock().unwrap().iter().any(|line| line.starts_with("Loaded 3 buffered results from ")));
        let text = std::fs::read_to_string(dir.join(RESULTS_FILE)).unwrap();
        assert!(text.starts_with("{\"dropped\":2}\n"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn never_writes_a_password_or_auth_header_value_to_disk() {
        let dir = folder("jobs");
        let job = json!({ "leaseId": "l1", "expiresAt": "x", "type": "postgres", "check": { "host": "db", "port": 5432, "password": "s3cret" }, "schedule": { "monitorId": "mnt_db", "intervalSeconds": 60 } });
        let mcp = json!({ "leaseId": "l2", "expiresAt": "x", "type": "mcp", "check": { "url": "https://m", "authHeaderValue": "tok" }, "schedule": { "monitorId": "mnt_mcp", "intervalSeconds": 60 } });
        let ssl = json!({ "leaseId": "l3", "type": "ssl", "check": { "host": "db" }, "schedule": { "monitorId": "mnt_db", "intervalSeconds": 60 } });
        let mut memory = JobMemory::new(dir.to_str(), quiet(), 0);
        memory.remember(&job, 0);
        memory.remember(&mcp, 0);
        memory.remember(&ssl, 0);
        let text = std::fs::read_to_string(dir.join(JOBS_FILE)).unwrap();
        assert!(!text.contains("s3cret") && !text.contains("tok"));
        assert!(text.contains("\"passwordRemoved\":true"));
        assert_eq!(memory.due(60000), vec!["mnt_db", "mnt_mcp"]);
        let restored = JobMemory::new(dir.to_str(), quiet(), 0);
        assert_eq!(restored.size(), 2);
        assert!(restored.due(0).is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
