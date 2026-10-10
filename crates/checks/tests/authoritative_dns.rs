//! DNS checks against the zone's own name servers.
mod common;

use common::{check, expect_all};
use serde_json::json;
use statustick_checks::dns::set_authoritative_dns;

#[test]
#[ignore = "needs the internet"]
fn public_dns_records_from_the_zone_name_servers() {
    set_authoritative_dns(true);
    let up = || vec![("status", json!("up"))];
    let down = || vec![("status", json!("down"))];
    expect_all(vec![
        ("A", "dns", json!({ "hostname": "one.one.one.one", "recordType": "A" }), up()),
        ("AAAA", "dns", json!({ "hostname": "one.one.one.one", "recordType": "AAAA" }), up()),
        ("MX", "dns", json!({ "hostname": "gmail.com", "recordType": "MX" }), up()),
        ("NS", "dns", json!({ "hostname": "github.com", "recordType": "NS" }), up()),
        ("CAA", "dns", json!({ "hostname": "google.com", "recordType": "CAA" }), up()),
        ("CNAME", "dns", json!({ "hostname": "www.github.com", "recordType": "CNAME" }), up()),
        ("A through a CNAME into another zone", "dns", json!({ "hostname": "www.wikipedia.org", "recordType": "A" }), up()),
        ("TXT with an expected value", "dns", json!({ "hostname": "google.com", "recordType": "TXT", "expectedValue": "v=spf1" }), up()),
        ("SOA", "dns", json!({ "hostname": "github.com", "recordType": "SOA" }), up()),
        ("expected IP", "dns", json!({ "hostname": "one.one.one.one", "expectedIP": "1.1.1.1" }), up()),
        ("no CNAME", "dns", json!({ "hostname": "github.com", "recordType": "CNAME" }), down()),
        ("NXDOMAIN", "dns", json!({ "hostname": "does-not-exist.statustick.com" }), vec![("status", json!("down")), ("errorCode", json!("ENOTFOUND"))]),
    ]);
    let answer = check("dns", json!({ "hostname": "www.wikipedia.org", "recordType": "A" }));
    assert!(answer["responseTime"].as_i64().is_some_and(|time| time > 1), "{answer}");
}
