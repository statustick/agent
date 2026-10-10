//! DNS checks: one query to the system's name servers, no cache and no search list, or to the zone's own name servers.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use hickory_resolver::config::ResolveHosts;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::op::{Edns, Message, Query, ResponseCode};
use hickory_resolver::proto::rr::Name;
use hickory_resolver::proto::rr::{RData, Record, RecordType};
use hickory_resolver::{Resolver, TokioResolver};
use serde::Serialize;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::targets::{is_blocked_address, refused_answer, target_not_allowed};
use crate::util::{Failure, elapsed_ms, now_iso, string_field, timeout_field, truthy};

static AUTHORITATIVE: AtomicBool = AtomicBool::new(false);

/// Drones only: private agents need the system resolver for internal names.
pub fn set_authoritative_dns(on: bool) {
    AUTHORITATIVE.store(on, Ordering::Relaxed);
}

fn system_resolver(cache_size: u64) -> TokioResolver {
    let mut builder = Resolver::builder_tokio().expect("system DNS configuration");
    let options = builder.options_mut();
    options.cache_size = cache_size;
    options.use_hosts_file = ResolveHosts::Never;
    options.ndots = 0;
    builder.build().expect("DNS resolver")
}

fn resolver() -> &'static TokioResolver {
    static RESOLVER: LazyLock<TokioResolver> = LazyLock::new(|| system_resolver(0));
    &RESOLVER
}

/// Finds zones and name servers; cached, and not part of the response time.
fn discovery() -> &'static TokioResolver {
    static RESOLVER: LazyLock<TokioResolver> = LazyLock::new(|| system_resolver(1024));
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

/// The closest zone at or above [name] with NS records, never a top-level domain.
async fn zone_servers(name: &Name) -> Result<Vec<Name>, &'static str> {
    let mut zone = name.clone();
    while zone.num_labels() >= 2 {
        let hosts: Vec<Name> = match discovery().lookup(zone.clone(), RecordType::NS).await {
            Ok(lookup) => lookup
                .answers()
                .iter()
                .filter(|record| record.name == zone)
                .filter_map(|record| match &record.data {
                    RData::NS(ns) => Some(ns.0.clone()),
                    _ => None,
                })
                .collect(),
            Err(NetError::Dns(DnsError::NoRecordsFound(_))) => Vec::new(),
            Err(_) => return Err("ESERVFAIL"),
        };
        if !hosts.is_empty() {
            return Ok(hosts);
        }
        zone = zone.base_name();
    }
    Err("ENOTFOUND")
}

async fn exchange(server: SocketAddr, query: &[u8], id: u16) -> std::io::Result<Message> {
    let local: IpAddr = if server.is_ipv4() { Ipv4Addr::UNSPECIFIED.into() } else { Ipv6Addr::UNSPECIFIED.into() };
    let socket = UdpSocket::bind((local, 0)).await?;
    socket.connect(server).await?;
    socket.send(query).await?;
    let mut buffer = vec![0; 4096];
    let response = loop {
        let size = socket.recv(&mut buffer).await?;
        if let Ok(message) = Message::from_vec(&buffer[..size])
            && message.metadata.id == id
        {
            break message;
        }
    };
    if !response.metadata.truncation {
        return Ok(response);
    }
    let mut stream = TcpStream::connect(server).await?;
    stream.write_all(&(query.len() as u16).to_be_bytes()).await?;
    stream.write_all(query).await?;
    let mut body = vec![0; usize::from(stream.read_u16().await?)];
    stream.read_exact(&mut body).await?;
    Message::from_vec(&body).map_err(std::io::Error::other)
}

/// Asks the zone's name servers in turn, without recursion, and follows a CNAME into another zone. The time is only the
/// time the name servers took.
async fn authoritative_answers(mut name: Name, kind: RecordType) -> Result<(Vec<Record>, Duration), &'static str> {
    let mut answers = Vec::new();
    let mut took = Duration::ZERO;
    for _ in 0..8 {
        let mut query = Message::query();
        query.add_query(Query::query(name.clone(), kind));
        query.metadata.recursion_desired = false;
        query.edns = Some(Edns::new());
        let bytes = query.to_vec().map_err(|_| "EBADNAME")?;
        let mut response = None;
        'servers: for host in zone_servers(&name).await? {
            let Ok(addresses) = discovery().lookup_ip(host).await else { continue };
            let mut addresses: Vec<IpAddr> = addresses.iter().filter(|address| !is_blocked_address(*address)).collect();
            addresses.sort_by_key(IpAddr::is_ipv6);
            for address in addresses {
                let start = Instant::now();
                let answer = tokio::time::timeout(Duration::from_secs(2), exchange(SocketAddr::new(address, 53), &bytes, query.metadata.id)).await;
                took += start.elapsed();
                if let Ok(Ok(answer)) = answer {
                    response = Some(answer);
                    break 'servers;
                }
            }
        }
        let response = response.ok_or("ETIMEOUT")?;
        match response.metadata.response_code {
            ResponseCode::NoError => {}
            ResponseCode::NXDomain => return Err("ENOTFOUND"),
            ResponseCode::Refused => return Err("EREFUSED"),
            _ => return Err("ESERVFAIL"),
        }
        let found = response.answers.iter().any(|record| record.record_type() == kind);
        let alias = response.answers.iter().rev().find_map(|record| match &record.data {
            RData::CNAME(cname) => Some(cname.0.clone()),
            _ => None,
        });
        answers.extend(response.answers);
        match alias {
            Some(target) if !found && kind != RecordType::CNAME => name = target,
            _ => return Ok((answers, took)),
        }
    }
    Err("ESERVFAIL")
}

/// The records for [hostname] in the shapes StatusTick reads: strings for A, AAAA, CNAME and NS, `{exchange, priority}` for MX,
/// arrays of strings for TXT, one SOA object, `{critical, <tag>: value}` for CAA.
/// With the time of the zone's name servers when they were asked directly.
pub async fn resolve_dns(hostname: &str, record_type: &str, timeout: Duration) -> Result<(Value, Option<Duration>), Failure> {
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
    let (answers, took) = if AUTHORITATIVE.load(Ordering::Relaxed) {
        match tokio::time::timeout(timeout, authoritative_answers(name, kind)).await {
            Err(_) => return Err(Failure::plain("DNS timeout")),
            Ok(Err(code)) => return Err(Failure::coded(format!("{} {code} {hostname}", query_name(&upper)), code)),
            Ok(Ok((answers, took))) => (answers, Some(took)),
        }
    } else {
        match tokio::time::timeout(timeout, resolver().lookup(name, kind)).await {
            Err(_) => return Err(Failure::plain("DNS timeout")),
            Ok(Err(error)) => return Err(failure_of(&error, &upper, hostname)),
            Ok(Ok(lookup)) => (lookup.answers().to_vec(), None),
        }
    };
    let data: Vec<&RData> = answers.iter().filter(|record| record.record_type() == kind).map(|record| &record.data).collect();
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
    Ok((records, took))
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

/// The answer of one DNS check. [hostname] and [record_type] are echoed as sent.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsCheckResult {
    pub hostname: Value,
    pub record_type: Value,
    pub status: &'static str,
    pub response_time: i64,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub records: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_count: Option<usize>,
    #[serde(rename = "expectedIP", skip_serializing_if = "Option::is_none")]
    pub expected_ip: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_value: Option<Value>,
}

/// `/check/dns` and the agent's `dns` job.
pub async fn dns_check(request: &Map<String, Value>) -> Value {
    let start = Instant::now();
    let hostname = request.get("hostname").cloned().unwrap_or(Value::Null);
    let record_type = request.get("recordType").cloned().unwrap_or_else(|| Value::from("A"));
    let timeout = timeout_field(request, "timeout", 10000.0);
    let expected_ip = request.get("expectedIP").cloned();
    let expected_value = request.get("expectedValue").cloned();
    let mut result = DnsCheckResult {
        status: "down",
        response_time: 0,
        timestamp: String::new(),
        error: None,
        error_code: None,
        records: None,
        record_count: None,
        expected_ip: None,
        expected_value: None,
        hostname,
        record_type,
    };
    let mut took = None;
    match resolve_dns(result.hostname.as_str().unwrap_or(""), result.record_type.as_str().unwrap_or("A"), timeout).await {
        Ok((records, time)) => {
            took = time;
            let mut has_expected = true;
            if let (true, Some(items)) = (truthy(expected_ip.as_ref()), records.as_array()) {
                has_expected = items.iter().any(|item| Some(item) == expected_ip.as_ref());
            }
            if let (true, Some(items), Some(wanted)) = (truthy(expected_value.as_ref()), records.as_array(), string_field(request, "expectedValue")) {
                has_expected = items.iter().any(|item| record_text(item).is_some_and(|text| text.contains(&wanted)));
            }
            if has_records(&records) && has_expected {
                result.status = "up";
            }
            let list = match records {
                Value::Array(items) => items,
                single => vec![single],
            };
            result.record_count = Some(list.len());
            result.records = Some(list);
            result.expected_ip = expected_ip;
            result.expected_value = expected_value;
        }
        Err(failure) => {
            result.error = Some(failure.message);
            result.error_code = failure.code;
        }
    }
    result.response_time = took.map_or_else(|| elapsed_ms(start), |time| time.as_millis() as i64);
    result.timestamp = now_iso();
    serde_json::to_value(result).expect("serializable result")
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
