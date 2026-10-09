//! What a browser run accepts, and the versions it reports.
use serde_json::{Map, Value, json};
use statustick_browser::result::build_result;
use statustick_browser::validate::{validate_script, validate_variables};
use statustick_browser::{CHROMIUM_VERSION, PLAYWRIGHT_VERSION};

fn refused(variables: Value) -> String {
    validate_variables(Some(&variables)).unwrap_err().0
}

#[test]
fn passes_variables_through_and_refuses_reserved_or_bad_ones() {
    let variables = json!({ "LOGIN_EMAIL": "a@example.com", "password": "x" });
    assert_eq!(Value::Object(validate_variables(Some(&variables)).unwrap()), variables);
    for name in ["PATH", "HOME", "NODE_OPTIONS", "LD_PRELOAD", "PLAYWRIGHT_BROWSERS_PATH", "ST_PROXY", "HTTPS_PROXY", "no_proxy", "FLY_API_TOKEN"] {
        assert_eq!(refused(json!({ name: "x" })), format!("Variable name '{name}' is reserved."));
    }
    for name in ["1ABC", "A-B"] {
        assert!(refused(json!({ name: "x" })).contains("may use only letters"), "{name}");
    }
    let many: Map<String, Value> = (0..51).map(|index| (format!("V{index}"), Value::from("x"))).collect();
    assert!(refused(Value::Object(many)).contains("at most 50"));
    assert!(refused(json!(["A"])).contains("must be an object"));
}

#[test]
fn keeps_the_script_as_written() {
    let script = "import { test } from '@playwright/test';\ntest('x', async () => {});\n";
    assert_eq!(validate_script(Some(&Value::from(script)), None).unwrap(), (script.to_string(), "check.spec.ts".to_string()));
}

#[test]
fn a_script_that_does_not_load_has_no_screenshot_or_trace() {
    let (result, screenshot, trace) =
        build_result(&json!({ "suites": [], "errors": [{ "message": "SyntaxError: Unexpected token (3:5)" }], "stats": { "duration": 10 } }));
    assert_eq!(result["status"], "failed");
    assert_eq!(result["error"], "SyntaxError: Unexpected token (3:5)");
    assert_eq!((screenshot, trace), (None, None));
}

#[test]
fn reports_the_pinned_playwright_and_chromium() {
    for version in [PLAYWRIGHT_VERSION, CHROMIUM_VERSION] {
        assert!(version.split('.').count() >= 3 && version.split('.').all(|part| part.parse::<u32>().is_ok()), "{version}");
    }
}
