//! Prometheus metrics of one agent, with fixed names and help texts. Labels come from fixed
//! sets only; never a target, host, monitor, location or token.
use std::collections::BTreeMap;
use std::sync::Mutex;

const CHECK_DURATION_BUCKETS: [f64; 8] = [0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0];

/// The names an agent pushes when it shares its health; StatusTick drops any other name.
pub const SHARED_METRICS: [&str; 17] = [
    "st_build_info",
    "st_connected",
    "st_last_contact_timestamp_seconds",
    "st_reconnects_total",
    "st_jobs",
    "st_checks_total",
    "st_check_duration_seconds",
    "st_buffer_results",
    "st_buffer_dropped_total",
    "st_uploads_total",
    "st_browser_runs_active",
    "st_browser_concurrency",
    "st_relay_pings_total",
    "process_cpu_user_seconds_total",
    "process_cpu_system_seconds_total",
    "process_cpu_seconds_total",
    "process_resident_memory_bytes",
];

/// What the gauges read from the agent when they are collected.
pub struct Snapshot {
    pub connected: bool,
    /// Unix milliseconds of the last call StatusTick answered; 0 before the first.
    pub last_contact_ms: i64,
    pub jobs: usize,
    pub buffer_results: usize,
    pub buffer_dropped_total: u64,
    pub browser_runs_active: usize,
    pub browser_concurrency: usize,
}

#[derive(Default)]
struct Histogram {
    buckets: [u64; 8],
    sum: f64,
    count: u64,
}

#[derive(Default)]
struct Counts {
    checks: BTreeMap<(String, String), u64>,
    durations: BTreeMap<String, Histogram>,
    reconnects: u64,
    uploads: BTreeMap<String, u64>,
    relay: BTreeMap<String, u64>,
}

pub struct AgentMetrics {
    version: String,
    relay: bool,
    browser: bool,
    counts: Mutex<Counts>,
}

fn number(value: f64) -> String {
    statustick_checks::util::number_text(value)
}

fn cpu_seconds() -> (f64, f64) {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: getrusage fills the struct it is given.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return (0.0, 0.0);
    }
    let seconds = |time: libc::timeval| time.tv_sec as f64 + time.tv_usec as f64 / 1e6;
    (seconds(usage.ru_utime), seconds(usage.ru_stime))
}

fn resident_bytes() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    // SAFETY: sysconf has no preconditions.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    Some(pages * page_size.max(0) as u64)
}

fn check_types_help() -> String {
    let mut types: Vec<&str> = crate::schema::CHECK_TYPES.to_vec();
    types.push("browser");
    format!("Checks run, by check type ({}) and result (up, down, blocked or error).", types.join(", "))
}

impl AgentMetrics {
    pub fn new(version: &str, relay: bool, browser: bool) -> Self {
        AgentMetrics { version: version.to_string(), relay, browser, counts: Mutex::new(Counts::default()) }
    }

    pub fn check(&self, kind: &str, result: &str, response_time_ms: f64) {
        let mut counts = self.counts.lock().expect("metrics");
        *counts.checks.entry((kind.to_string(), result.to_string())).or_default() += 1;
        if response_time_ms.is_finite() && response_time_ms >= 0.0 {
            let seconds = response_time_ms / 1000.0;
            let histogram = counts.durations.entry(kind.to_string()).or_default();
            for (index, bound) in CHECK_DURATION_BUCKETS.iter().enumerate() {
                if seconds <= *bound {
                    histogram.buckets[index] += 1;
                }
            }
            histogram.sum += seconds;
            histogram.count += 1;
        }
    }

    pub fn reconnected(&self) {
        self.counts.lock().expect("metrics").reconnects += 1;
    }

    /// `ok`, `failed` (retried) or `rejected`.
    pub fn upload(&self, result: &str) {
        *self.counts.lock().expect("metrics").uploads.entry(result.to_string()).or_default() += 1;
    }

    /// `accepted`, `rejected` or `failed`.
    pub fn relayed(&self, result: &str, count: usize) {
        if self.relay && count > 0 {
            *self.counts.lock().expect("metrics").relay.entry(result.to_string()).or_default() += count as u64;
        }
    }

    fn names(&self) -> Vec<&'static str> {
        let mut names = vec![
            "process_cpu_user_seconds_total",
            "process_cpu_system_seconds_total",
            "process_cpu_seconds_total",
            "process_resident_memory_bytes",
            "st_build_info",
            "st_connected",
            "st_last_contact_timestamp_seconds",
            "st_reconnects_total",
            "st_jobs",
            "st_checks_total",
            "st_check_duration_seconds",
            "st_buffer_results",
            "st_buffer_dropped_total",
            "st_uploads_total",
        ];
        if self.browser {
            names.extend(["st_browser_runs_active", "st_browser_concurrency"]);
        }
        if self.relay {
            names.push("st_relay_pings_total");
        }
        names
    }

    fn metric(&self, name: &str, snapshot: &Snapshot) -> Option<String> {
        let (help, kind): (String, &str) = match name {
            "process_cpu_user_seconds_total" => ("Total user CPU time spent in seconds.".into(), "counter"),
            "process_cpu_system_seconds_total" => ("Total system CPU time spent in seconds.".into(), "counter"),
            "process_cpu_seconds_total" => ("Total user and system CPU time spent in seconds.".into(), "counter"),
            "process_resident_memory_bytes" => ("Resident memory size in bytes.".into(), "gauge"),
            "st_build_info" => ("Always 1; the agent version and whether it runs browser checks (BROWSER_CONCURRENCY above 0).".into(), "gauge"),
            "st_connected" => ("1 while connected to StatusTick, 0 otherwise.".into(), "gauge"),
            "st_last_contact_timestamp_seconds" => ("Unix time of the last call StatusTick answered.".into(), "gauge"),
            "st_reconnects_total" => ("Connects after the first one.".into(), "counter"),
            "st_jobs" => ("Checks running now.".into(), "gauge"),
            "st_checks_total" => (check_types_help(), "counter"),
            "st_check_duration_seconds" => ("Check response time, by check type; buckets 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30 s.".into(), "histogram"),
            "st_buffer_results" => ("Results kept while StatusTick is unreachable.".into(), "gauge"),
            "st_buffer_dropped_total" => ("Results dropped because the buffer was full.".into(), "counter"),
            "st_uploads_total" => ("Result uploads to StatusTick, by result: ok, failed (retried) or rejected.".into(), "counter"),
            "st_browser_runs_active" if self.browser => ("Browser checks on only: browser checks running now.".into(), "gauge"),
            "st_browser_concurrency" if self.browser => {
                ("Browser checks on only: browser checks that may run at once (the \"Browser runs\" setting, or BROWSER_CONCURRENCY).".into(), "gauge")
            }
            "st_relay_pings_total" if self.relay => ("Heartbeat relay on: relayed pings, by result: accepted, rejected or failed.".into(), "counter"),
            _ => return None,
        };
        let mut out = format!("# HELP {name} {help}\n# TYPE {name} {kind}\n");
        let counts = self.counts.lock().expect("metrics");
        let (user, system) = cpu_seconds();
        match name {
            "process_cpu_user_seconds_total" => out.push_str(&format!("{name} {}\n", number(user))),
            "process_cpu_system_seconds_total" => out.push_str(&format!("{name} {}\n", number(system))),
            "process_cpu_seconds_total" => out.push_str(&format!("{name} {}\n", number(user + system))),
            "process_resident_memory_bytes" => out.push_str(&format!("{name} {}\n", resident_bytes()?)),
            "st_build_info" => out.push_str(&format!("{name}{{version=\"{}\",browser=\"{}\"}} 1\n", self.version, self.browser)),
            "st_browser_runs_active" => out.push_str(&format!("{name} {}\n", snapshot.browser_runs_active)),
            "st_browser_concurrency" => out.push_str(&format!("{name} {}\n", snapshot.browser_concurrency)),
            "st_connected" => out.push_str(&format!("{name} {}\n", u8::from(snapshot.connected))),
            "st_last_contact_timestamp_seconds" => out.push_str(&format!("{name} {}\n", number(snapshot.last_contact_ms as f64 / 1000.0))),
            "st_reconnects_total" => out.push_str(&format!("{name} {}\n", counts.reconnects)),
            "st_jobs" => out.push_str(&format!("{name} {}\n", snapshot.jobs)),
            "st_checks_total" => {
                for ((kind, result), value) in &counts.checks {
                    out.push_str(&format!("{name}{{type=\"{kind}\",result=\"{result}\"}} {value}\n"));
                }
            }
            "st_check_duration_seconds" => {
                for (kind, histogram) in &counts.durations {
                    for (bound, count) in CHECK_DURATION_BUCKETS.iter().zip(histogram.buckets) {
                        out.push_str(&format!("{name}_bucket{{le=\"{}\",type=\"{kind}\"}} {count}\n", number(*bound)));
                    }
                    out.push_str(&format!("{name}_bucket{{le=\"+Inf\",type=\"{kind}\"}} {}\n", histogram.count));
                    out.push_str(&format!("{name}_sum{{type=\"{kind}\"}} {}\n", number(histogram.sum)));
                    out.push_str(&format!("{name}_count{{type=\"{kind}\"}} {}\n", histogram.count));
                }
            }
            "st_buffer_results" => out.push_str(&format!("{name} {}\n", snapshot.buffer_results)),
            "st_buffer_dropped_total" => out.push_str(&format!("{name} {}\n", snapshot.buffer_dropped_total)),
            "st_uploads_total" => {
                for (result, value) in &counts.uploads {
                    out.push_str(&format!("{name}{{result=\"{result}\"}} {value}\n"));
                }
            }
            "st_relay_pings_total" => {
                for (result, value) in &counts.relay {
                    out.push_str(&format!("{name}{{result=\"{result}\"}} {value}\n"));
                }
            }
            _ => return None,
        }
        Some(out)
    }

    /// Every metric in the Prometheus text format, for the local endpoint.
    pub fn text(&self, snapshot: &Snapshot) -> String {
        let parts: Vec<String> = self.names().iter().filter_map(|name| self.metric(name, snapshot)).collect();
        format!("{}\n", parts.join("\n"))
    }

    /// Only [SHARED_METRICS], for the push to StatusTick.
    pub fn shared(&self, snapshot: &Snapshot) -> String {
        let parts: Vec<String> = SHARED_METRICS.iter().filter_map(|name| self.metric(name, snapshot)).collect();
        format!("{}\n", parts.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_checks_uploads_and_relayed_pings_with_fixed_labels() {
        let metrics = AgentMetrics::new("1.0.0", true, false);
        metrics.check("http", "up", 120.0);
        metrics.check("tcp", "down", 3.0);
        metrics.upload("ok");
        metrics.relayed("accepted", 2);
        metrics.reconnected();
        let snapshot = Snapshot {
            connected: true,
            last_contact_ms: 1_700_000_000_000,
            jobs: 1,
            buffer_results: 4,
            buffer_dropped_total: 2,
            browser_runs_active: 1,
            browser_concurrency: 2,
        };
        let text = metrics.text(&snapshot);
        for line in [
            "st_build_info{version=\"1.0.0\",browser=\"false\"} 1",
            "st_connected 1",
            "st_last_contact_timestamp_seconds 1700000000",
            "st_reconnects_total 1",
            "st_jobs 1",
            "st_checks_total{type=\"http\",result=\"up\"} 1",
            "st_check_duration_seconds_bucket{le=\"0.25\",type=\"http\"} 1",
            "st_buffer_results 4",
            "st_buffer_dropped_total 2",
            "st_uploads_total{result=\"ok\"} 1",
            "st_relay_pings_total{result=\"accepted\"} 2",
        ] {
            assert!(text.contains(line), "{line}");
        }
        let shared = metrics.shared(&snapshot);
        assert!(shared.contains("st_connected 1"));
        assert!(!AgentMetrics::new("1.0.0", false, false).text(&snapshot).contains("st_relay_pings_total"));
        let browser = AgentMetrics::new("1.0.0", false, true).text(&snapshot);
        assert!(browser.contains("st_build_info{version=\"1.0.0\",browser=\"true\"} 1"));
        assert!(browser.contains("st_browser_runs_active 1") && browser.contains("st_browser_concurrency 2"));
    }
}
