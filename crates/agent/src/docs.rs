//! The generated tables in `docs/agent.md` (settings, metrics) and the chart README (values): the tests fail while a
//! table is out of date, and `UPDATE_DOCS=1 cargo test -p statustick-agent docs` rewrites them.
use std::path::{Path, PathBuf};

use crate::metrics::{AgentMetrics, SHARED_METRICS, Snapshot};
use crate::settings::{DEFAULT_BUFFER_SIZE, DEFAULT_CONCURRENCY, DEFAULT_METRICS_HOST, DEFAULT_RELAY_HOST, DEFAULT_URL, MAX_BUFFER_SIZE, MAX_CONCURRENCY};

const AGENT_DOC: &str = "docs/agent.md";
const CHART_README: &str = "charts/statustick-agent/README.md";
const CHART_VALUES: &str = "charts/statustick-agent/values.yaml";
const CHART: &str = "charts/statustick-agent/Chart.yaml";
const SETTINGS_MARKERS: (&str, &str) = ("<!-- settings:start -->", "<!-- settings:end -->");
const METRICS_MARKERS: (&str, &str) = ("<!-- metrics:start -->", "<!-- metrics:end -->");

struct Setting {
    name: &'static str,
    kind: &'static str,
    default: &'static str,
    values: &'static str,
    description: &'static str,
    browser_only: bool,
}

const fn setting(name: &'static str, kind: &'static str, default: &'static str, values: &'static str, description: &'static str) -> Setting {
    Setting { name, kind, default, values, description, browser_only: false }
}

/// Every variable the agent reads, in the order of the table. Markdown, one line each.
const SETTINGS: &[Setting] = &[
    setting(
        "STATUSTICK_TOKEN",
        "text",
        "none (required)",
        "any",
        "The agent's token, from its page in StatusTick. The agent sends it as `Authorization: Bearer` on every call.",
    ),
    setting(
        "STATUSTICK_URL",
        "URL",
        "`https://agent.statustick.com`",
        "`https`; `http` for `localhost`, `*.localhost` and `127.0.0.1`",
        "Where the agent connects. Plain `http` is accepted only for local development.",
    ),
    setting(
        "STATUSTICK_CONCURRENCY",
        "whole number",
        "`5`",
        "1 to 50",
        "How many checks run at the same time. Set on the machine, it wins over the agent's \"Max checks\" setting in the dashboard. Higher values use more memory.",
    ),
    setting(
        "STATUSTICK_ALLOW",
        "list",
        "none",
        "address ranges, single addresses, host names and `*.` subdomain wildcards, for example `10.0.0.0/8,192.168.1.20,*.corp.example`",
        "Optional allowlist. When set, the agent checks only matching targets; any other check fails with \"target not allowed by agent policy\" and is never attempted. See \"Target rules\" below.",
    ),
    setting(
        "STATUSTICK_HOSTNAME",
        "text",
        "the container's host name",
        "any",
        "The name the agent reports, shown as Host on its page. The token picks the agent, so a recreated container stays the same agent whatever its host name.",
    ),
    setting(
        "STATUSTICK_INSTALL",
        "choice",
        "set by the install command or the chart",
        "`docker`, `compose`, `helm` or `other`",
        "How the agent was installed, shown on its page in the dashboard. Unset: `helm` inside Kubernetes, `docker` inside a Docker container, else `other`.",
    ),
    setting(
        "HTTPS_PROXY",
        "URL",
        "none",
        "`http://host:port` or `https://host:port`, with `user:password@` for basic authentication",
        "Proxy for `https` traffic: the connection to StatusTick and HTTPS checks. Falls back to `HTTP_PROXY`.",
    ),
    setting("HTTP_PROXY", "URL", "none", "as `HTTPS_PROXY`", "Proxy for plain `http` checks."),
    setting(
        "NO_PROXY",
        "list",
        "none",
        "`db.internal`, `.corp` (the domain and its subdomains), `host:8443` (that port only), IP addresses, CIDR ranges such as `10.0.0.0/8`, or `*` for all",
        "Hosts that skip the proxy.",
    ),
    setting(
        "NODE_EXTRA_CA_CERTS",
        "path",
        "none",
        "a PEM file",
        "Extra CA certificates, for example your TLS-inspecting proxy's CA or your internal CA. Trusted for the connection to StatusTick and for HTTPS checks, next to the usual public CAs.",
    ),
    setting(
        "STATUSTICK_BUFFER_SIZE",
        "whole number",
        "`10000`",
        "1 to 100000",
        "How many results the agent keeps while StatusTick is unreachable. When full, the oldest are dropped and counted. See \"Offline buffer\" below.",
    ),
    setting(
        "STATUSTICK_BUFFER_DIR",
        "path",
        "none (memory only)",
        "a writable folder",
        "Keeps the buffer and the checks to repeat across restarts, usually on a mounted volume. The agent does not start when the folder cannot be written.",
    ),
    setting(
        "STATUSTICK_HEALTH_PORT",
        "port",
        "none (no port)",
        "1 to 65535",
        "Opens `GET /healthz` (`200 ok` while the process runs) and `GET /readyz` (`200 ok` while StatusTick answered in the last two minutes, `503` otherwise) on this port, for Kubernetes probes. Nothing else is served. The Helm chart sets it to `8080`.",
    ),
    setting(
        "STATUSTICK_RELAY_PORT",
        "port",
        "none (no port)",
        "1 to 65535, not the health port",
        "Opens the heartbeat relay on this port: jobs inside your network ping the agent instead of `webhook.statustick.com`. Internal only, never expose it to the internet. See \"Heartbeat relay\" below.",
    ),
    setting(
        "STATUSTICK_RELAY_HOST",
        "IP address",
        "`0.0.0.0`",
        "an address of this host",
        "The address the heartbeat relay listens on. Inside a container `0.0.0.0` is needed for a published port; on a host with several networks set the internal address.",
    ),
    setting(
        "STATUSTICK_DISCOVERY",
        "choice",
        "none (off)",
        "`kubernetes`",
        "Turns on Kubernetes service discovery: annotated Services get monitors in the agent's location. Only inside a pod with a service account token. See \"Kubernetes service discovery\" below.",
    ),
    setting(
        "STATUSTICK_DISCOVERY_NAMESPACES",
        "list",
        "none (every namespace)",
        "namespaces, for example `shop,payments`",
        "The namespaces to watch instead of all of them.",
    ),
    setting(
        "METRICS_PORT",
        "port",
        "none (no port)",
        "1 to 65535, not the health or relay port",
        "Opens `GET /metrics` (Prometheus text format) on this port. Nothing else is served there. See \"Metrics\" below.",
    ),
    setting(
        "METRICS_HOST",
        "IP address",
        "`0.0.0.0`",
        "an address of this host",
        "The address the metrics port listens on. Set `127.0.0.1` to keep it on the host.",
    ),
    setting(
        "STATUSTICK_SHARE_METRICS",
        "choice",
        "none (follows the dashboard)",
        "`true` or `false`",
        "`true` sends the agent's health to StatusTick every minute; `false` never does, whatever the dashboard says. Unset follows the agent's \"Share health\" setting in the dashboard (off by default). See \"Metrics\" below.",
    ),
    Setting {
        name: "BROWSER_CONCURRENCY",
        kind: "whole number",
        default: "`1`",
        values: "0 to 8",
        description: "How many browser checks run at the same time; `0` turns them off. Set on the machine, it wins over the agent's \"Browser runs\" setting in the dashboard. Each run needs up to 2 GB of memory (see below).",
        browser_only: true,
    },
    setting(
        "STATUSTICK_BROWSER_ISOLATION",
        "choice",
        "none (isolated when the container allows it)",
        "`user` or `off`",
        "Browser checks: each run runs as its own user, so a script cannot read the agent's token or files. `user` refuses to start when the container does not allow it; `off` runs browser checks as the agent's user. See \"Browser checks\" below.",
    ),
    setting("STATUSTICK_REQUIRE_SECRET_HOSTS", "choice", "none", "`true`", "`true` refuses every `STATUSTICK_SECRET_` variable that has no `_HOSTS` list."),
    setting(
        "STATUSTICK_SECRET_<NAME>_HOSTS",
        "list",
        "none",
        "as `STATUSTICK_ALLOW`",
        "The hosts the secret `STATUSTICK_SECRET_<NAME>` may be sent to. A database check that uses the secret for any other host fails with `SECRET_NOT_ALLOWED`. See \"Database checks\" below.",
    ),
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(file: &str) -> String {
    std::fs::read_to_string(root().join(file)).unwrap_or_else(|_| panic!("{file}"))
}

fn cell(text: &str) -> String {
    text.replace('|', "\\|")
}

fn settings_table() -> Result<String, String> {
    let mut rows = vec!["| Variable | Type | Default | Values | What it does |".to_string(), "| -- | -- | -- | -- | -- |".to_string()];
    for setting in SETTINGS {
        if setting.description.trim().is_empty() || setting.description.contains('\n') {
            return Err(format!("{} has no one-line description", setting.name));
        }
        let description = if setting.browser_only { format!("Browser checks only. {}", setting.description) } else { setting.description.to_string() };
        rows.push(format!("| `{}` | {} | {} | {} | {} |", setting.name, setting.kind, cell(setting.default), cell(setting.values), cell(&description)));
    }
    Ok(rows.join("\n"))
}

fn metrics_table(metrics: &AgentMetrics) -> Result<String, String> {
    let snapshot =
        Snapshot { connected: true, last_contact_ms: 0, jobs: 0, buffer_results: 0, buffer_dropped_total: 0, browser_runs_active: 0, browser_concurrency: 1 };
    let mut rows = vec!["| Metric | Type | Labels | Meaning |".to_string(), "| -- | -- | -- | -- |".to_string()];
    for block in metrics.text(&snapshot).split("# HELP ").skip(1) {
        let (name, rest) = block.split_once(' ').unwrap_or((block, ""));
        if !name.starts_with("st_") {
            continue;
        }
        let help = rest.lines().next().unwrap_or("").trim();
        if help.is_empty() {
            return Err(format!("{name} has no help text"));
        }
        let kind = rest.lines().find_map(|line| line.strip_prefix(&format!("# TYPE {name} "))).unwrap_or("");
        let labels: Vec<String> = rest
            .lines()
            .filter(|line| !line.starts_with('#'))
            .find_map(|line| line.split_once('{').map(|(_, labels)| labels))
            .map(|labels| {
                labels
                    .split_once('}')
                    .map(|(inner, _)| inner)
                    .unwrap_or("")
                    .split(',')
                    .filter_map(|pair| pair.split_once('=').map(|(key, _)| key))
                    .filter(|key| *key != "le")
                    .map(|key| format!("`{key}`"))
                    .collect()
            })
            .unwrap_or_default();
        rows.push(format!("| `{name}` | {kind} | {} | {} |", labels.join(", "), cell(help)));
    }
    Ok(rows.join("\n"))
}

/// Every metric an agent can have: browser checks and the heartbeat relay on, one sample per labelled metric.
fn all_metrics() -> AgentMetrics {
    let metrics = AgentMetrics::new("0.0.0", true, true);
    metrics.check("http", "up", 1.0);
    metrics.upload("ok");
    metrics.relayed("accepted", 1);
    metrics
}

/// One `key: value` line of values.yaml: its indent, key and the value after the colon.
fn entry(line: &str) -> Option<(usize, &str, &str)> {
    let indent = line.len() - line.trim_start().len();
    let (key, value) = line.trim_start().split_once(':')?;
    (!key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')).then_some((indent, key, value.trim()))
}

struct Value {
    path: String,
    /// The value as written on its line; empty for a map with children.
    raw: String,
}

/// Every key of values.yaml with its dotted path, in file order (block maps and one-line values only).
fn values(yaml: &str) -> Vec<Value> {
    let mut parents: Vec<(usize, String)> = Vec::new();
    let mut out = Vec::new();
    for line in yaml.lines().filter(|line| !line.trim_start().starts_with('#')) {
        let Some((indent, key, raw)) = entry(line) else { continue };
        while parents.last().is_some_and(|(parent, _)| *parent >= indent) {
            parents.pop();
        }
        let path = parents.iter().map(|(_, key)| key.as_str()).chain([key]).collect::<Vec<_>>().join(".");
        parents.push((indent, key.to_string()));
        out.push(Value { path, raw: raw.split(" #").next().unwrap_or("").trim().to_string() });
    }
    out
}

struct Documented {
    path: String,
    description: String,
    default: Option<String>,
}

/// The values with a `# -- ` comment, in file order, and their `# @default -- ` text.
fn documented_values(yaml: &str) -> Vec<Documented> {
    let mut parents: Vec<(usize, String)> = Vec::new();
    let (mut description, mut default): (Option<String>, Option<String>) = (None, None);
    let mut out = Vec::new();
    for line in yaml.lines() {
        if let Some(text) = line.trim_start().strip_prefix('#') {
            let text = text.strip_prefix(' ').unwrap_or(text);
            if let Some(rest) = text.strip_prefix("-- ") {
                description = Some(rest.trim().to_string());
            } else if let Some(rest) = text.strip_prefix("@default -- ") {
                default = Some(rest.trim().to_string());
            }
            continue;
        }
        if let Some((indent, key, _)) = entry(line) {
            while parents.last().is_some_and(|(parent, _)| *parent >= indent) {
                parents.pop();
            }
            let path = parents.iter().map(|(_, key)| key.as_str()).chain([key]).collect::<Vec<_>>().join(".");
            parents.push((indent, key.to_string()));
            if let Some(description) = description.take() {
                out.push(Documented { path, description, default: default.take() });
            }
        }
        description = None;
        default = None;
    }
    out
}

fn default_text(raw: &str, path: &str) -> Result<String, String> {
    Ok(match raw {
        "" => return Err(format!("{path} needs a \"# @default -- \" comment")),
        "null" | "~" => "unset".to_string(),
        "\"\"" | "''" | "{}" => "none".to_string(),
        "[]" => "`[]`".to_string(),
        _ => format!("`{}`", raw.trim_matches('"')),
    })
}

fn chart_table(yaml: &str) -> Result<String, String> {
    let all = values(yaml);
    let mut rows = vec!["| Value | Default | What it does |".to_string(), "| -- | -- | -- |".to_string()];
    for value in documented_values(yaml) {
        let default = match value.default {
            Some(text) => text,
            None => default_text(all.iter().find(|entry| entry.path == value.path).map(|entry| entry.raw.as_str()).unwrap_or(""), &value.path)?,
        };
        rows.push(format!("| `{}` | {} | {} |", value.path, cell(&default), cell(&value.description)));
    }
    Ok(rows.join("\n"))
}

/// The leaf values whose path and parents have no `# -- ` comment.
fn undocumented_values(yaml: &str) -> Vec<String> {
    let documented: Vec<String> = documented_values(yaml).into_iter().map(|value| value.path).collect();
    let covered = |path: &str| documented.iter().any(|doc| path == doc || path.starts_with(&format!("{doc}.")));
    values(yaml).into_iter().filter(|value| !value.raw.is_empty() && !covered(&value.path)).map(|value| value.path).collect()
}

fn table_in<'a>(text: &'a str, (start, end): (&str, &str)) -> Option<&'a str> {
    let from = text.find(start)?;
    let to = text.find(end).filter(|to| *to > from)?;
    Some(text[from + start.len()..to].trim())
}

fn with_table(text: &str, table: &str, (start, end): (&str, &str), file: &str) -> Result<String, String> {
    let from = text.find(start).ok_or_else(|| format!("{file} has no {start} … {end} block"))?;
    let to = text.find(end).filter(|to| *to > from).ok_or_else(|| format!("{file} has no {start} … {end} block"))?;
    Ok(format!("{}{start}\n{table}\n{}", &text[..from], &text[to..]))
}

/// Compares the table in [file] with [table], or rewrites it with UPDATE_DOCS=1.
fn check_table(file: &str, markers: (&str, &str), table: &str) {
    let text = read(file);
    if std::env::var("UPDATE_DOCS").is_ok_and(|value| value == "1") {
        std::fs::write(root().join(file), with_table(&text, table, markers, file).unwrap()).unwrap();
        return;
    }
    assert_eq!(table_in(&text, markers), Some(table), "{file} is out of date: run `UPDATE_DOCS=1 cargo test -p statustick-agent docs`");
}

#[test]
fn settings_table_is_up_to_date() {
    check_table(AGENT_DOC, SETTINGS_MARKERS, &settings_table().unwrap());
}

#[test]
fn metrics_table_is_up_to_date() {
    check_table(AGENT_DOC, METRICS_MARKERS, &metrics_table(&all_metrics()).unwrap());
}

#[test]
fn chart_values_table_is_up_to_date() {
    check_table(CHART_README, SETTINGS_MARKERS, &chart_table(&read(CHART_VALUES)).unwrap());
}

#[test]
fn settings_defaults_and_ranges_are_the_agent_ones() {
    let find = |name: &str| SETTINGS.iter().find(|setting| setting.name == name).unwrap();
    assert_eq!(find("STATUSTICK_URL").default, format!("`{DEFAULT_URL}`"));
    assert_eq!(find("STATUSTICK_CONCURRENCY").default, format!("`{DEFAULT_CONCURRENCY}`"));
    assert_eq!(find("STATUSTICK_CONCURRENCY").values, format!("1 to {MAX_CONCURRENCY}"));
    assert_eq!(find("STATUSTICK_BUFFER_SIZE").default, format!("`{DEFAULT_BUFFER_SIZE}`"));
    assert_eq!(find("STATUSTICK_BUFFER_SIZE").values, format!("1 to {MAX_BUFFER_SIZE}"));
    assert_eq!(find("STATUSTICK_RELAY_HOST").default, format!("`{DEFAULT_RELAY_HOST}`"));
    assert_eq!(find("METRICS_HOST").default, format!("`{DEFAULT_METRICS_HOST}`"));
    assert_eq!(find("BROWSER_CONCURRENCY").values, format!("0 to {}", crate::browser::MAX_BROWSER_CONCURRENCY));
}

/// The agent's sources (this file aside), one file at a time.
fn sources() -> Vec<(PathBuf, String)> {
    let mut files = Vec::new();
    let mut dirs = vec![root().join("crates/agent/src")];
    while let Some(dir) = dirs.pop() {
        for path in std::fs::read_dir(dir).unwrap().flatten().map(|entry| entry.path()) {
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") && !path.ends_with("docs.rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                files.push((path, text));
            }
        }
    }
    files
}

/// The `STATUSTICK_*` names in [text].
fn variable_names(text: &str) -> Vec<String> {
    text.match_indices("STATUSTICK_")
        .map(|(index, _)| text[index..].chars().take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_').collect::<String>())
        .map(|name| name.trim_end_matches('_').to_string())
        .collect()
}

#[test]
fn every_variable_the_agent_reads_is_in_the_settings_table_and_back() {
    let sources = sources();
    for (file, text) in &sources {
        for name in variable_names(text).into_iter().filter(|name| !name.starts_with("STATUSTICK_SECRET")) {
            assert!(SETTINGS.iter().any(|setting| setting.name == name), "{} names {name}, which is not in the settings table", file.display());
        }
    }
    let read: Vec<String> = sources.iter().flat_map(|(_, text)| variable_names(text)).collect();
    for setting in SETTINGS.iter().filter(|setting| setting.name.starts_with("STATUSTICK_") && !setting.name.contains('<')) {
        assert!(read.contains(&setting.name.to_string()), "{} is in the settings table but the agent never reads it", setting.name);
    }
}

#[test]
fn every_shared_metric_is_in_the_metrics_table() {
    let table = metrics_table(&all_metrics()).unwrap();
    for name in SHARED_METRICS.iter().filter(|name| name.starts_with("st_")) {
        assert!(table.contains(&format!("| `{name}` |")), "{name} is not in the table");
    }
}

#[test]
fn every_chart_value_is_documented_itself_or_through_a_parent() {
    assert_eq!(undocumented_values(&read(CHART_VALUES)), Vec::<String>::new());
    assert_eq!(undocumented_values("a:\n  # -- Documented.\n  b: 1\n  c: 2\n"), vec!["a.c"]);
}

#[test]
fn reads_descriptions_and_defaults_from_the_values_comments() {
    let yaml = "# Not a description.\n\n# -- The parent.\n# @default -- see below\nparent:\n  child: 1\nother:\n  # -- A child.\n  child: \"\"\n";
    let documented = documented_values(yaml);
    assert_eq!(
        documented.iter().map(|value| (value.path.as_str(), value.default.as_deref())).collect::<Vec<_>>(),
        [("parent", Some("see below")), ("other.child", None)]
    );
    assert_eq!(chart_table(yaml).unwrap().lines().last(), Some("| `other.child` | none | A child. |"));
    assert_eq!(chart_table("# -- No default.\nmap:\n  key: 1\n").unwrap_err(), "map needs a \"# @default -- \" comment");
}

#[test]
fn replaces_only_the_block_between_the_markers() {
    let text = "before\n<!-- settings:start -->\nold\n<!-- settings:end -->\nafter\n";
    assert_eq!(with_table(text, "new", SETTINGS_MARKERS, "file.md").unwrap(), "before\n<!-- settings:start -->\nnew\n<!-- settings:end -->\nafter\n");
    assert!(with_table("no markers", "new", SETTINGS_MARKERS, "file.md").unwrap_err().starts_with("file.md has no"));
}

#[test]
fn chart_app_version_is_the_agent_version() {
    let chart = read(CHART);
    let app_version = chart.lines().find_map(|line| line.strip_prefix("appVersion:")).map(|value| value.split('#').next().unwrap().trim().trim_matches('"'));
    assert_eq!(app_version, Some(crate::VERSION), "Chart.yaml appVersion is not the agent version in version.txt");
}
