//! DNS checks: one query to the system's name servers, no cache and no search list, answered in the shapes Node.js's
//! `dns.resolve*` gives.
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use hickory_resolver::config::ResolveHosts;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::Name;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::{Resolver, TokioResolver};
use serde_json::{Map, Value, json};

use crate::targets::{refused_answer, target_not_allowed};
use crate::util::{Failure, elapsed_ms, now_iso, string_field, timeout_field, truthy};

fn resolver() -> &'static TokioResolver {
    static RESOLVER: LazyLock<TokioResolver> = LazyLock::new(|| {
        let mut builder = Resolver::builder_tokio().expect("system DNS configuration");
        let options = builder.options_mut();
        options.cache_size = 0;
        options.use_hosts_file = ResolveHosts::Never;
        options.ndots = 0;
        builder.build().expect("DNS resolver")
    });
    &RESOLVER
}

fn query_name(record_type: &str) -> &'static str {
    match record_type {
        "A" => "queryA",
        "AAAA" => "queryAaaa",
        "CNAME" => "queryCname",
        "MX" => "queryMx",
        "TXT" => "queryTxt",
        "NS" => "queryNs",
        "SOA" => "querySoa",
        _ => "queryCaa",
    }
}

fn name_text(name: &Name) -> String {
    let text = name.to_utf8();
    text.strip_suffix('.').map(str::to_string).unwrap_or(text)
}

fn failure_of(error: &NetError, record_type: &str, hostname: &str) -> Failure {
    let code = match error {
        NetError::Dns(DnsError::NoRecordsFound(no_records)) if no_records.response_code == ResponseCode::NXDomain => "ENOTFOUND",
        NetError::Dns(DnsError::NoRecordsFound(_)) => "ENODATA",
        NetError::Dns(DnsError::ResponseCode(ResponseCode::Refused)) => "EREFUSED",
        NetError::Dns(DnsError::ResponseCode(ResponseCode::ServFail)) => "ESERVFAIL",
        NetError::Dns(DnsError::ResponseCode(ResponseCode::NotImp)) => "ENOTIMP",
        NetError::Dns(DnsError::ResponseCode(ResponseCode::FormErr)) => "EFORMERR",
        NetError::Timeout => "ETIMEOUT",
        NetError::Io(io) if io.kind() == std::io::ErrorKind::ConnectionRefused => "ECONNREFUSED",
        _ => "ESERVFAIL",
    };
    Failure::coded(format!("{} {code} {hostname}", query_name(record_type)), code)
}

/// The records for [hostname] as Node.js shapes them: strings for A, AAAA, CNAME and NS, `{exchange, priority}` for MX,
/// arrays of strings for TXT, one SOA object, `{critical, <tag>: value}` for CAA.
pub async fn resolve_dns(hostname: &str, record_type: &str, timeout: Duration) -> Result<Value, Failure> {
    let upper = record_type.to_uppercase();
    let kind = match upper.as_str() {
        "A" => RecordType::A,
        "AAAA" => RecordType::AAAA,
        "CNAME" => RecordType::CNAME,
        "MX" => RecordType::MX,
        "TXT" => RecordType::TXT,
        "NS" => RecordType::NS,
        "SOA" => RecordType::SOA,
        "CAA" => RecordType::CAA,
        _ => return Err(Failure::plain(format!("Unsupported record type: {record_type}"))),
    };
    let fqdn = if hostname.ends_with('.') { hostname.to_string() } else { format!("{hostname}.") };
    let name = Name::from_utf8(&fqdn).map_err(|_| Failure::coded(format!("{} EBADNAME {hostname}", query_name(&upper)), "EBADNAME"))?;
    let lookup = match tokio::time::timeout(timeout, resolver().lookup(name, kind)).await {
        Err(_) => return Err(Failure::plain("DNS timeout")),
        Ok(Err(error)) => return Err(failure_of(&error, &upper, hostname)),
        Ok(Ok(lookup)) => lookup,
    };
    let data: Vec<&RData> = lookup.answers().iter().filter(|record| record.record_type() == kind).map(|record| &record.data).collect();
    let records: Value = match kind {
        RecordType::SOA => match data.first() {
            Some(RData::SOA(soa)) => json!({
                "nsname": name_text(&soa.mname),
                "hostmaster": name_text(&soa.rname),
                "serial": soa.serial,
                "refresh": soa.refresh,
                "retry": soa.retry,
                "expire": soa.expire,
                "minttl": soa.minimum,
            }),
            _ => return Err(Failure::coded(format!("querySoa ENODATA {hostname}"), "ENODATA")),
        },
        _ => Value::from(
            data.iter()
                .filter_map(|rdata| match rdata {
                    RData::A(a) => Some(Value::from(a.0.to_string())),
                    RData::AAAA(aaaa) => Some(Value::from(aaaa.0.to_string())),
                    RData::CNAME(cname) => Some(Value::from(name_text(&cname.0))),
                    RData::NS(ns) => Some(Value::from(name_text(&ns.0))),
                    RData::MX(mx) => Some(json!({ "exchange": name_text(&mx.exchange), "priority": mx.preference, "type": "MX" })),
                    RData::TXT(txt) => {
                        Some(Value::from(txt.txt_data.iter().map(|chunk| Value::from(String::from_utf8_lossy(chunk).into_owned())).collect::<Vec<_>>()))
                    }
                    RData::CAA(caa) => {
                        let mut record = Map::new();
                        record.insert("critical".into(), Value::from(caa.flags()));
                        record.insert("type".into(), Value::from("CAA"));
                        record.insert(caa.tag.clone(), Value::from(String::from_utf8_lossy(&caa.value).into_owned()));
                        Some(Value::Object(record))
                    }
                    _ => None,
                })
                .collect::<Vec<_>>(),
        ),
    };
    if let Value::Array(items) = &records {
        if items.is_empty() {
            return Err(Failure::coded(format!("{} ENODATA {hostname}", query_name(&upper)), "ENODATA"));
        }
        let strings: Vec<String> = items.iter().filter_map(|item| item.as_str().map(str::to_string)).collect();
        if refused_answer(hostname, &strings) {
            return Err(target_not_allowed());
        }
    }
    Ok(records)
}

/// The text of one record for `expectedValue`: the record itself, or a TXT record's strings joined as one value.
fn record_text(record: &Value) -> Option<String> {
    match record {
        Value::String(text) => Some(text.clone()),
        Value::Array(chunks) => Some(chunks.iter().filter_map(Value::as_str).collect()),
        _ => None,
    }
}

/// A DNS answer is up when it has records; an SOA answer is one object.
pub fn has_records(records: &Value) -> bool {
    match records {
        Value::Array(items) => !items.is_empty(),
        Value::Object(_) => true,
        _ => false,
    }
}

/// `/check/dns` and the agent's `dns` job.
pub async fn dns_check(request: &Map<String, Value>) -> Value {
    let start = Instant::now();
    let hostname = request.get("hostname").cloned().unwrap_or(Value::Null);
    let record_type = request.get("recordType").cloned().unwrap_or_else(|| Value::from("A"));
    let timeout = timeout_field(request, "timeout", 10000.0);
    let expected_ip = request.get("expectedIP").cloned();
    let expected_value = request.get("expectedValue").cloned();
    match resolve_dns(hostname.as_str().unwrap_or(""), record_type.as_str().unwrap_or("A"), timeout).await {
        Ok(records) => {
            let mut has_expected = true;
            if let (true, Some(items)) = (truthy(expected_ip.as_ref()), records.as_array()) {
                has_expected = items.iter().any(|item| Some(item) == expected_ip.as_ref());
            }
            if let (true, Some(items), Some(wanted)) = (truthy(expected_value.as_ref()), records.as_array(), string_field(request, "expectedValue")) {
                has_expected = items.iter().any(|item| record_text(item).is_some_and(|text| text.contains(&wanted)));
            }
            let mut result = Map::new();
            result.insert("hostname".into(), hostname);
            result.insert("recordType".into(), record_type);
            result.insert("status".into(), Value::from(if has_records(&records) && has_expected { "up" } else { "down" }));
            result.insert("responseTime".into(), Value::from(elapsed_ms(start)));
            result.insert("timestamp".into(), Value::from(now_iso()));
            let (list, count) = match records {
                Value::Array(items) => {
                    let count = items.len();
                    (Value::Array(items), count)
                }
                single => (Value::Array(vec![single]), 1),
            };
            result.insert("records".into(), list);
            result.insert("recordCount".into(), Value::from(count));
            if let Some(expected) = expected_ip {
                result.insert("expectedIP".into(), expected);
            }
            if let Some(expected) = expected_value {
                result.insert("expectedValue".into(), expected);
            }
            Value::Object(result)
        }
        Err(failure) => {
            let mut result = Map::new();
            result.insert("hostname".into(), hostname);
            result.insert("recordType".into(), record_type);
            result.insert("status".into(), Value::from("down"));
            result.insert("responseTime".into(), Value::from(elapsed_ms(start)));
            result.insert("timestamp".into(), Value::from(now_iso()));
            result.insert("error".into(), Value::from(failure.message));
            if let Some(code) = failure.code {
                result.insert("errorCode".into(), Value::from(code));
            }
            Value::Object(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_the_strings_of_a_txt_record() {
        assert_eq!(record_text(&json!(["v=spf1 include:_spf.example.com", " ~all"])).as_deref(), Some("v=spf1 include:_spf.example.com ~all"));
        assert_eq!(record_text(&json!("192.0.2.1")).as_deref(), Some("192.0.2.1"));
        assert_eq!(record_text(&json!({ "exchange": "mx.example.com", "priority": 10 })), None);
    }

    #[test]
    fn counts_an_soa_answer_as_records() {
        assert!(has_records(&json!({ "nsname": "ns1.example.com", "serial": 1 })));
        assert!(has_records(&json!(["192.0.2.1"])));
        assert!(!has_records(&json!([])));
    }
}
