//! What a browser run may be: the script, its variables and the hosts it may reach, with the messages StatusTick shows.
use std::sync::LazyLock;

use fancy_regex::Regex;
use serde_json::{Map, Value};

pub const MAX_SCRIPT_BYTES: usize = 128 * 1024;
const PLAYWRIGHT_MODULE: &str = "@playwright/test";
const MAX_VARIABLES: usize = 50;
const MAX_VALUE_BYTES: usize = 4096;
const MAX_HOSTS: usize = 20;
const MAX_URL_CHARS: usize = 2048;
pub const MAX_STEP_CHARS: usize = 1000;

/// Node.js's `builtinModules`.
const BUILTINS: &[&str] = &[
    "_http_agent",
    "_http_client",
    "_http_common",
    "_http_incoming",
    "_http_outgoing",
    "_http_server",
    "_tls_common",
    "_tls_wrap",
    "assert",
    "assert/strict",
    "async_hooks",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "constants",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "dns/promises",
    "domain",
    "events",
    "fs",
    "fs/promises",
    "http",
    "http2",
    "https",
    "inspector",
    "inspector/promises",
    "module",
    "net",
    "os",
    "path",
    "path/posix",
    "path/win32",
    "perf_hooks",
    "process",
    "punycode",
    "querystring",
    "readline",
    "readline/promises",
    "repl",
    "stream",
    "stream/consumers",
    "stream/promises",
    "stream/web",
    "string_decoder",
    "sys",
    "timers",
    "timers/promises",
    "tls",
    "trace_events",
    "tty",
    "url",
    "util",
    "util/types",
    "v8",
    "vm",
    "wasi",
    "worker_threads",
    "zlib",
];

/// A request the runner refuses with 400 and this message.
#[derive(Debug, Clone, PartialEq)]
pub struct ScriptError(pub String);

fn refuse<T>(message: impl Into<String>) -> Result<T, ScriptError> {
    Err(ScriptError(message.into()))
}

static STATIC_IMPORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?<![.A-Za-z0-9_$])(?:import|export)\s+(?:[^'"`;]*?\s+from\s+)?(['"])([^'"\n]+)\1"#).expect("valid pattern"));
static CALL_IMPORT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?<![.A-Za-z0-9_$])(import|require)\s*\(\s*([^)]*?)\s*\)").expect("valid pattern"));
static STRING_LITERAL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"^(['"`])([^'"`\n]+)\1$"#).expect("valid pattern"));

fn check_specifier(specifier: &str) -> Result<(), ScriptError> {
    let local = specifier.starts_with('.') || specifier.starts_with('/') || specifier.starts_with("file:") || specifier.contains('\\');
    if local {
        return refuse(format!("Local files cannot be imported ('{specifier}'). Put the whole check in one file."));
    }
    let builtin = specifier.starts_with("node:") || BUILTINS.contains(&specifier);
    if specifier != PLAYWRIGHT_MODULE && !builtin {
        return refuse(format!("Only {PLAYWRIGHT_MODULE} and Node.js built-in modules can be imported ('{specifier}')."));
    }
    Ok(())
}

fn imports_of(source: &str) -> Result<Vec<String>, ScriptError> {
    let mut found = Vec::new();
    for captures in STATIC_IMPORT.captures_iter(source).flatten() {
        found.push(captures[2].to_string());
    }
    for captures in CALL_IMPORT.captures_iter(source).flatten() {
        match STRING_LITERAL.captures(&captures[2]).ok().flatten() {
            Some(literal) => found.push(literal[2].to_string()),
            None => return refuse(format!("{}() needs a fixed module name in quotes.", &captures[1])),
        }
    }
    Ok(found)
}

/// Checks one @playwright/test file: the script and its file name.
pub fn validate_script(script: Option<&Value>, language: Option<&Value>) -> Result<(String, String), ScriptError> {
    let Some(script) = script.and_then(Value::as_str).filter(|script| !script.trim().is_empty()) else { return refuse("The script is empty.") };
    if script.len() > MAX_SCRIPT_BYTES {
        return refuse(format!("The script is larger than {} KB.", MAX_SCRIPT_BYTES / 1024));
    }
    let extension = match language {
        None => "ts",
        Some(Value::String(language)) if language == "typescript" => "ts",
        Some(Value::String(language)) if language == "javascript" => "js",
        Some(_) => return refuse("language must be \"typescript\" or \"javascript\"."),
    };
    let imports = imports_of(script)?;
    for specifier in &imports {
        check_specifier(specifier)?;
    }
    if !imports.iter().any(|specifier| specifier == PLAYWRIGHT_MODULE) {
        return refuse(format!("The script must import test from '{PLAYWRIGHT_MODULE}'."));
    }
    Ok((script.to_string(), format!("check.spec.{extension}")))
}

fn reserved(name: &str) -> bool {
    let upper = name.to_uppercase();
    ["PATH", "HOME", "TMPDIR", "PWD", "SHELL", "USER", "DEBUG", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"].contains(&upper.as_str())
        || ["NODE_", "NPM_", "PLAYWRIGHT_", "PW_", "LD_", "ST_", "FLY_"].iter().any(|prefix| upper.starts_with(prefix))
}

fn variable_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=64).contains(&bytes.len()) && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_') && bytes.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

/// The check's own variables, the only environment the script gets besides PATH, HOME and TMPDIR.
pub fn validate_variables(variables: Option<&Value>) -> Result<Map<String, Value>, ScriptError> {
    let entries = match variables {
        None | Some(Value::Null) => return Ok(Map::new()),
        Some(Value::Object(entries)) => entries,
        Some(_) => return refuse("variables must be an object of names to text values."),
    };
    if entries.len() > MAX_VARIABLES {
        return refuse(format!("A check can have at most {MAX_VARIABLES} variables."));
    }
    let mut checked = Map::new();
    for (name, value) in entries {
        if !variable_name(name) {
            return refuse(format!("Variable name '{name}' may use only letters, digits and _, and must not start with a digit."));
        }
        if reserved(name) {
            return refuse(format!("Variable name '{name}' is reserved."));
        }
        let Some(text) = value.as_str() else { return refuse(format!("Variable '{name}' must be text.")) };
        if text.len() > MAX_VALUE_BYTES {
            return refuse(format!("Variable '{name}' is longer than {MAX_VALUE_BYTES} bytes."));
        }
        checked.insert(name.clone(), value.clone());
    }
    Ok(checked)
}

/// `String(value)` in JavaScript, for messages that quote what was sent.
pub fn js_string(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => "null".into(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => number.as_f64().map(statustick_checks::util::js_number).unwrap_or_else(|| number.to_string()),
        Value::Array(items) => items.iter().map(|item| if item.is_null() { String::new() } else { js_string(item) }).collect::<Vec<_>>().join(","),
        Value::Object(_) => "[object Object]".into(),
    }
}

fn host_name(host: &str) -> bool {
    static HOSTNAME: LazyLock<Regex> = LazyLock::new(|| {
        let label = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
        Regex::new(&format!(r"^(?:\*\.)?(?:{label}\.)+{label}$")).expect("valid pattern")
    });
    HOSTNAME.is_match(host).unwrap_or(false)
}

/// Hosts the run may reach through the egress proxy: `example.com`, `*.example.com` or `*`; none means no network.
pub fn validate_allowed_hosts(hosts: Option<&Value>) -> Result<Vec<String>, ScriptError> {
    let message = || ScriptError(format!("allowedHosts must be a list of at most {MAX_HOSTS} hosts."));
    let list = match hosts {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(list)) if list.len() <= MAX_HOSTS => list,
        Some(_) => return Err(message()),
    };
    list.iter()
        .map(|entry| {
            let host = entry
                .as_str()
                .map(|text| text.trim().to_lowercase())
                .map(|text| text.strip_suffix('.').map(str::to_string).unwrap_or(text))
                .unwrap_or_default();
            if host == "*" || host_name(&host) || host.parse::<std::net::IpAddr>().is_ok() {
                Ok(host)
            } else {
                refuse(format!("'{}' is not a host name. Use example.com, *.example.com or *.", js_string(entry)))
            }
        })
        .collect()
}

/// A region code such as `fra`; kept for the request shape, a process sandbox runs where its caller runs.
pub fn validate_region(region: Option<&Value>) -> Result<Option<String>, ScriptError> {
    match region {
        None => Ok(None),
        Some(Value::String(code)) if code.len() == 3 && code.bytes().all(|b| b.is_ascii_lowercase()) => Ok(Some(code.clone())),
        Some(_) => refuse("region must be a region code such as \"fra\"."),
    }
}

/// The page to snapshot: an absolute http(s) URL without credentials.
pub fn validate_snapshot_url(value: Option<&Value>) -> Result<url::Url, ScriptError> {
    let message = "url must be an absolute http or https URL.";
    let text = value.and_then(Value::as_str).map(str::trim).unwrap_or("");
    let url = url::Url::parse(text).map_err(|_| ScriptError(message.into()))?;
    if (url.scheme() != "http" && url.scheme() != "https") || url.as_str().encode_utf16().count() > MAX_URL_CHARS {
        return refuse(message);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return refuse("url must not contain a user name or password.");
    }
    Ok(url)
}

/// The step the stored run failed at, for `/failure-snapshot`.
pub fn validate_failed_step(value: Option<&Value>) -> Result<Option<String>, ScriptError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(step)) if step.encode_utf16().count() <= MAX_STEP_CHARS => Ok(Some(step.clone())),
        Some(_) => refuse(format!("failedStep must be a step title of at most {MAX_STEP_CHARS} characters.")),
    }
}

/// The script a `/snapshot` run executes: open the page, give it a moment to render, and let the fixture attach the snapshot.
pub fn snapshot_script(url: &url::Url) -> String {
    [
        "import { test } from '@playwright/test';".to_string(),
        String::new(),
        "test('page snapshot', async ({ page }) => {".to_string(),
        format!("  await page.goto({}, {{ waitUntil: 'load' }});", Value::from(url.as_str())),
        "  await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});".to_string(),
        "});".to_string(),
        String::new(),
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const VALID: &str = "import { test, expect } from '@playwright/test';\n\ntest('home page', async ({ page }) => {\n  await test.step('open', async () => {\n    await page.goto('https://example.com');\n  });\n  await expect(page).toHaveTitle(/Example/);\n});\n";

    fn script(text: &str, language: Option<&str>) -> Result<(String, String), ScriptError> {
        validate_script(Some(&Value::from(text)), language.map(Value::from).as_ref())
    }

    fn message(result: Result<(String, String), ScriptError>) -> String {
        result.unwrap_err().0
    }

    #[test]
    fn accepts_playwright_files_and_builtins() {
        assert_eq!(script(VALID, None).unwrap().1, "check.spec.ts");
        let required = "const { test } = require('@playwright/test');\nconst crypto = require('node:crypto');\ntest('x', async () => {});";
        assert_eq!(script(required, Some("javascript")).unwrap().1, "check.spec.js");
    }

    #[test]
    fn refuses_local_files_other_packages_and_dynamic_names() {
        assert_eq!(
            message(script(&format!("{VALID}\nimport {{ login }} from './helpers';"), None)),
            "Local files cannot be imported ('./helpers'). Put the whole check in one file."
        );
        assert!(message(script(&format!("{VALID}\nconst data = require('../data.json');"), None)).starts_with("Local files cannot be imported"));
        assert!(message(script(&format!("{VALID}\nimport '/etc/passwd';"), None)).starts_with("Local files cannot be imported"));
        assert_eq!(message(script(&format!("{VALID}\nconst name = './x';\nawait import(name);"), None)), "import() needs a fixed module name in quotes.");
        assert_eq!(
            message(script(&format!("{VALID}\nimport _ from 'lodash';"), None)),
            "Only @playwright/test and Node.js built-in modules can be imported ('lodash')."
        );
        assert_eq!(message(script("test('x', async () => {});", None)), "The script must import test from '@playwright/test'.");
        assert_eq!(message(script("   ", None)), "The script is empty.");
        assert_eq!(message(script(VALID, Some("python"))), "language must be \"typescript\" or \"javascript\".");
        assert_eq!(message(script(&format!("{VALID}//{}", "x".repeat(130 * 1024)), None)), "The script is larger than 128 KB.");
        assert!(script("const s = page.import('x');\nimport { test } from '@playwright/test';", None).is_ok());
    }

    #[test]
    fn checks_variables() {
        assert_eq!(Value::Object(validate_variables(Some(&json!({ "LOGIN": "a" }))).unwrap()), json!({ "LOGIN": "a" }));
        assert!(validate_variables(None).unwrap().is_empty());
        for name in ["PATH", "NODE_OPTIONS", "https_proxy", "ST_RUN", "fly_api_token"] {
            assert_eq!(validate_variables(Some(&json!({ name: "x" }))).unwrap_err().0, format!("Variable name '{name}' is reserved."));
        }
        assert!(validate_variables(Some(&json!({ "1A": "x" }))).unwrap_err().0.contains("may use only letters"));
        assert_eq!(validate_variables(Some(&json!({ "A": 1 }))).unwrap_err().0, "Variable 'A' must be text.");
        assert_eq!(validate_variables(Some(&json!([]))).unwrap_err().0, "variables must be an object of names to text values.");
        assert!(validate_variables(Some(&json!({ "A": "x".repeat(4097) }))).unwrap_err().0.contains("longer than 4096 bytes"));
    }

    #[test]
    fn checks_hosts_regions_urls_and_steps() {
        assert_eq!(
            validate_allowed_hosts(Some(&json!([" Shop.Example.com. ", "*.cdn.example.com", "*", "203.0.113.5"]))).unwrap(),
            vec!["shop.example.com", "*.cdn.example.com", "*", "203.0.113.5"]
        );
        assert_eq!(validate_allowed_hosts(Some(&json!(["bad host"]))).unwrap_err().0, "'bad host' is not a host name. Use example.com, *.example.com or *.");
        assert_eq!(validate_allowed_hosts(Some(&json!("x"))).unwrap_err().0, "allowedHosts must be a list of at most 20 hosts.");
        assert_eq!(validate_region(Some(&json!("FRA"))).unwrap_err().0, "region must be a region code such as \"fra\".");
        assert_eq!(validate_region(Some(&json!("fra"))).unwrap().as_deref(), Some("fra"));
        assert_eq!(validate_snapshot_url(Some(&json!("ftp://x"))).unwrap_err().0, "url must be an absolute http or https URL.");
        assert_eq!(validate_snapshot_url(Some(&json!("https://u:p@x.example"))).unwrap_err().0, "url must not contain a user name or password.");
        assert_eq!(validate_failed_step(Some(&json!(5))).unwrap_err().0, "failedStep must be a step title of at most 1000 characters.");
        let url = validate_snapshot_url(Some(&json!("https://shop.example.com/pricing"))).unwrap();
        assert!(snapshot_script(&url).contains("await page.goto(\"https://shop.example.com/pricing\", { waitUntil: 'load' });"));
    }
}
