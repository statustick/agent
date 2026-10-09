//! The target rules as the checks apply them. The policy is global, so one test walks through the cases in order.
use std::collections::HashSet;

use serde_json::{Value, json};
use statustick_checks::targets::{
    TargetPolicy, parse_allow_list, parse_allowed_internal_hosts, refused_answer, resolve_allowed, set_allowed_internal_hosts, set_target_policy,
};

async fn check(kind: &str, request: Value) -> Value {
    statustick_checks::run_check(kind, request.as_object().expect("request")).await.expect("known check type")
}

fn reset() {
    set_target_policy(TargetPolicy::default());
    set_allowed_internal_hosts(HashSet::new());
}

fn allow(list: &str) {
    set_target_policy(TargetPolicy { internal: true, allow: parse_allow_list(list, "STATUSTICK_ALLOW").expect("valid list") });
}

#[tokio::test]
async fn checks_follow_the_target_policy_and_ip_version() {
    reset();
    for host in ["10.1.2.3", "192.168.1.10", "169.254.169.254", "fd00:ec2::254"] {
        assert_eq!(resolve_allowed(host, 0).await.unwrap_err().message, "target not allowed", "{host}");
    }
    let tcp = check("tcp", json!({ "host": "127.0.0.1", "port": 9, "timeout": 500 })).await;
    assert_eq!((tcp["status"].as_str(), tcp["error"].as_str()), (Some("down"), Some("target not allowed")));
    let tcp = check("tcp", json!({ "host": "10.0.0.5", "port": 5432, "timeout": 500 })).await;
    assert_eq!(tcp["errorCode"], "TARGET_NOT_ALLOWED");
    let ping = check("ping", json!({ "host": "169.254.169.254", "timeout": 500 })).await;
    assert_eq!((ping["status"].as_str(), ping["error"].as_str()), (Some("down"), Some("target not allowed")));
    let http = check("http", json!({ "url": "http://[::1]:9/" })).await;
    assert_eq!((http["error"].as_str(), http["errorType"].as_str()), (Some("target not allowed"), Some("TargetNotAllowed")));

    set_target_policy(TargetPolicy { internal: true, allow: None });
    assert_eq!(resolve_allowed("10.1.2.3", 0).await.unwrap(), ["10.1.2.3".parse::<std::net::IpAddr>().unwrap()]);
    assert!(resolve_allowed("192.168.1.10", 0).await.is_ok());
    for host in ["169.254.169.254", "fd00:ec2::254"] {
        assert_eq!(resolve_allowed(host, 0).await.unwrap_err().message, "target not allowed", "{host}");
    }
    assert!(!refused_answer("db.internal", &["10.0.0.5".to_string()]));

    allow("10.0.0.0/8, 192.168.1.20, *.corp.example");
    assert!(resolve_allowed("10.9.9.9", 0).await.is_ok());
    assert!(resolve_allowed("192.168.1.20", 0).await.is_ok());
    for host in ["192.168.1.21", "169.254.169.254"] {
        assert_eq!(resolve_allowed(host, 0).await.unwrap_err().message, "target not allowed by agent policy", "{host}");
    }
    allow("*.corp.example");
    assert!(!refused_answer("db.corp.example", &["10.0.0.5".to_string()]));
    assert!(refused_answer("db.internal", &["10.0.0.5".to_string()]));

    allow("169.254.169.254");
    assert!(resolve_allowed("169.254.169.254", 0).await.is_ok());

    reset();
    assert!(refused_answer("db.internal", &["10.0.0.5".to_string()]));
    set_allowed_internal_hosts(parse_allowed_internal_hosts(" e2e-harness , Webhook_Receiver. ").0);
    for host in ["e2e-harness", "E2E-Harness.", "webhook_receiver"] {
        assert!(!refused_answer(host, &["172.18.0.5".to_string()]), "{host}");
    }
    for host in ["e2e-harness.evil.com", "xe2e-harness", "evil.e2e-harness", "e2e-harness-x", "db"] {
        assert!(refused_answer(host, &["172.18.0.5".to_string()]), "{host}");
    }
    set_allowed_internal_hosts(parse_allowed_internal_hosts("localhost").0);
    assert!(resolve_allowed("LOCALHOST.", 0).await.is_ok());
    assert_eq!(resolve_allowed("127.0.0.1", 0).await.unwrap_err().message, "target not allowed");
    reset();

    assert_eq!(resolve_allowed("2606:2800:21f:cb07:6820:80da:af6b:8b2c", 4).await.unwrap_err().code.as_deref(), Some("NO_ADDRESS"));
    let http = check("http", json!({ "url": "https://93.184.215.14/", "ipVersion": "6" })).await;
    assert_eq!(http["status"], "down");
    assert_eq!(http["errorType"], "NoAddress");
    assert_eq!(http["error"], "No IPv6 address (AAAA record) for 93.184.215.14");
    let tcp = check("tcp", json!({ "host": "93.184.215.14", "port": 443, "ipVersion": "6" })).await;
    assert_eq!(tcp["errorCode"], "NO_ADDRESS");
}
