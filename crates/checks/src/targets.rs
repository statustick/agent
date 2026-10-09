//! The target rules: push-mode drones refuse internal and metadata addresses, a private agent may reach internal
//! addresses but never cloud metadata, and with an allowlist only the listed targets. Every check resolves a host once
//! with [resolve_allowed] and connects to the addresses it returned, so a later lookup cannot swap in another one.
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{LazyLock, RwLock};

use ipnet::IpNet;
use serde_json::Value;

use crate::util::Failure;

/// 0 takes any IP version, 4 or 6 only that one.
pub type Family = u8;

#[derive(Debug, Clone)]
pub enum AllowRule {
    Range(IpNet),
    Host(String),
}

#[derive(Debug, Clone, Default)]
pub struct TargetPolicy {
    pub internal: bool,
    pub allow: Option<Vec<AllowRule>>,
}

struct State {
    policy: TargetPolicy,
    allowed_internal_hosts: HashSet<String>,
}

static STATE: LazyLock<RwLock<State>> = LazyLock::new(|| RwLock::new(State { policy: TargetPolicy::default(), allowed_internal_hosts: HashSet::new() }));

static BLOCKED: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    ]
    .iter()
    .map(|range| range.parse().expect("valid range"))
    .collect()
});

static METADATA: LazyLock<[IpAddr; 2]> = LazyLock::new(|| [IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)), "fd00:ec2::254".parse().expect("valid address")]);

pub fn set_target_policy(policy: TargetPolicy) {
    STATE.write().expect("target state").policy = policy;
}

pub fn set_allowed_internal_hosts(hosts: HashSet<String>) {
    STATE.write().expect("target state").allowed_internal_hosts = hosts;
}

pub fn target_not_allowed() -> Failure {
    Failure::new("target not allowed", Some("TARGET_NOT_ALLOWED"), "TargetNotAllowed")
}

fn agent_policy_refusal() -> Failure {
    Failure::new("target not allowed by agent policy", Some("TARGET_NOT_ALLOWED"), "TargetNotAllowed")
}

pub fn no_address(host: &str, family: Family) -> Failure {
    let record = if family == 6 { "AAAA" } else { "A" };
    Failure::new(format!("No IPv{family} address ({record} record) for {host}"), Some("NO_ADDRESS"), "NoAddress")
}

/// STATUSTICK_ALLOW, e.g. `10.0.0.0/8,192.168.1.20,*.corp.example`; the error names the entry that is not valid.
pub fn parse_allow_list(value: &str, setting: &str) -> Result<Option<Vec<AllowRule>>, String> {
    let entries: Vec<String> = value.split(',').map(|entry| entry.trim().to_lowercase()).filter(|entry| !entry.is_empty()).collect();
    if entries.is_empty() {
        return Ok(None);
    }
    let host = regex::Regex::new(r"^(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)*$").expect("valid pattern");
    entries
        .into_iter()
        .map(|entry| {
            let (address, prefix) = match entry.split_once('/') {
                Some((address, prefix)) => (address.to_string(), Some(prefix.to_string())),
                None => (entry.clone(), None),
            };
            if let Ok(ip) = address.parse::<IpAddr>() {
                let max = if ip.is_ipv4() { 32 } else { 128 };
                let bits = match &prefix {
                    None => max,
                    Some(prefix) => {
                        prefix.parse::<u8>().ok().filter(|bits| *bits <= max).ok_or_else(|| format!("{setting} has a range that is not valid: {entry}"))?
                    }
                };
                return IpNet::new(ip, bits).map(|net| AllowRule::Range(net.trunc())).map_err(|_| format!("{setting} has a range that is not valid: {entry}"));
            }
            if prefix.is_some() || !host.is_match(&entry) {
                return Err(format!("{setting} has an entry that is not valid: {entry}"));
            }
            Ok(AllowRule::Host(entry))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

fn host_name(host: &str) -> String {
    let lower = host.to_lowercase();
    lower.strip_suffix('.').map(str::to_string).unwrap_or(lower)
}

/// ALLOWED_INTERNAL_HOSTS: exact host names a push-mode drone may reach on internal addresses, for local test stacks
/// only. Entries that are not plain host names (IP literals, wildcards, URLs) are returned as ignored.
pub fn parse_allowed_internal_hosts(value: &str) -> (HashSet<String>, Vec<String>) {
    let name = regex::Regex::new(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)*$").expect("valid pattern");
    let numeric_last = regex::Regex::new(r"(^|\.)(\d+|0x[0-9a-f]*)$").expect("valid pattern");
    let mut hosts = HashSet::new();
    let mut ignored = Vec::new();
    for entry in value.split(',').map(str::trim).filter(|entry| !entry.is_empty()) {
        let host = host_name(entry);
        if name.is_match(&host) && !numeric_last.is_match(&host) {
            hosts.insert(host);
        } else {
            ignored.push(entry.to_string());
        }
    }
    (hosts, ignored)
}

/// IPv4-mapped IPv6 addresses count as their IPv4 address.
fn canonical(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(address),
        v4 => v4,
    }
}

fn in_range(net: &IpNet, address: IpAddr) -> bool {
    net.contains(&canonical(address))
}

fn host_listed(host: &str, rules: &[AllowRule]) -> bool {
    let name = host_name(host);
    rules.iter().any(|rule| match rule {
        AllowRule::Host(pattern) => *pattern == name || (pattern.starts_with("*.") && name.ends_with(&pattern[1..])),
        AllowRule::Range(_) => false,
    })
}

/// True when [rules] list [host] by name, or [address], the one a check connects to, is in a listed range.
pub fn bound_to(rules: &[AllowRule], host: &str, address: Option<IpAddr>) -> bool {
    host_listed(host.trim_start_matches('[').trim_end_matches(']'), rules)
        || address.is_some_and(|address| rules.iter().any(|rule| matches!(rule, AllowRule::Range(net) if in_range(net, address))))
}

pub fn is_blocked_address(address: IpAddr) -> bool {
    let address = canonical(address);
    BLOCKED.iter().any(|net| net.contains(&address))
}

/// Fails when [host], resolved to [addresses], is not a target this drone or agent may reach.
pub fn check_target(host: &str, addresses: &[IpAddr]) -> Result<(), Failure> {
    let state = STATE.read().expect("target state");
    if let Some(allow) = &state.policy.allow {
        let listed = host_listed(host, allow)
            || addresses.iter().all(|address| allow.iter().any(|rule| matches!(rule, AllowRule::Range(net) if in_range(net, *address))));
        return if listed { Ok(()) } else { Err(agent_policy_refusal()) };
    }
    if state.policy.internal {
        return if addresses.iter().any(|address| METADATA.contains(&canonical(*address))) { Err(target_not_allowed()) } else { Ok(()) };
    }
    if state.allowed_internal_hosts.contains(&host_name(host)) {
        return Ok(());
    }
    if addresses.iter().any(|address| is_blocked_address(*address)) {
        return Err(target_not_allowed());
    }
    Ok(())
}

/// True when a DNS check's answer for [hostname] has an address this drone or agent may not report.
pub fn refused_answer(hostname: &str, records: &[String]) -> bool {
    let addresses: Vec<IpAddr> = records.iter().filter_map(|record| record.parse().ok()).collect();
    !addresses.is_empty() && check_target(hostname, &addresses).is_err()
}

/// Maps the platform's ipVersion ("4", "6", 4, 6 or missing) to a family.
pub fn family_of(ip_version: Option<&Value>) -> Family {
    match ip_version {
        Some(Value::String(text)) if text == "4" => 4,
        Some(Value::String(text)) if text == "6" => 6,
        Some(Value::Number(number)) if number.as_f64() == Some(4.0) => 4,
        Some(Value::Number(number)) if number.as_f64() == Some(6.0) => 6,
        _ => 0,
    }
}

fn gai_code(error: &dns_lookup::LookupError) -> &'static str {
    use dns_lookup::LookupErrorKind::*;
    match error.kind() {
        NoName | NoData => "ENOTFOUND",
        Again => "EAI_AGAIN",
        Fail => "EAI_FAIL",
        Family => "EAI_FAMILY",
        Memory => "EAI_MEMORY",
        Service => "EAI_SERVICE",
        Socktype => "EAI_SOCKTYPE",
        Badflags => "EAI_BADFLAGS",
        _ => "EAI_FAIL",
    }
}

/// `dns.lookup(host, { all: true, family })`: the system resolver, in the order it answers.
pub async fn lookup(host: &str, family: Family) -> Result<Vec<IpAddr>, Failure> {
    if host.is_empty() {
        return Ok(Vec::new());
    }
    let name = host.to_string();
    let answer = tokio::task::spawn_blocking(move || {
        let hints = dns_lookup::AddrInfoHints {
            socktype: libc::SOCK_STREAM,
            address: match family {
                4 => libc::AF_INET,
                6 => libc::AF_INET6,
                _ => libc::AF_UNSPEC,
            },
            ..Default::default()
        };
        dns_lookup::getaddrinfo(Some(&name), None, Some(hints))
            .map(|entries| entries.filter_map(Result::ok).map(|entry| entry.sockaddr.ip()).collect::<Vec<_>>())
    })
    .await
    .map_err(|_| Failure::coded(format!("getaddrinfo EAI_FAIL {host}"), "EAI_FAIL"))?;
    match answer {
        Ok(mut addresses) => {
            let mut seen = HashSet::new();
            addresses.retain(|address| seen.insert(*address));
            Ok(addresses)
        }
        Err(error) => {
            let code = gai_code(&error);
            Err(Failure::coded(format!("getaddrinfo {code} {host}"), code))
        }
    }
}

/// Resolves once and returns the addresses to connect to, after the target rules allowed them.
pub async fn resolve_allowed(host: &str, family: Family) -> Result<Vec<IpAddr>, Failure> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let mut addresses = match bare.parse::<IpAddr>() {
        Ok(address) => vec![address],
        Err(_) => match lookup(bare, family).await {
            Ok(addresses) => addresses,
            Err(error) if family != 0 && error.code.as_deref().is_some_and(|code| ["ENOTFOUND", "ENODATA", "EAI_NODATA", "EAI_NONAME"].contains(&code)) => {
                return Err(no_address(bare, family));
            }
            Err(error) => return Err(error),
        },
    };
    if family != 0 {
        addresses.retain(|address| (family == 4) == address.is_ipv4());
        if addresses.is_empty() {
            return Err(no_address(bare, family));
        }
    }
    if addresses.is_empty() {
        return Err(target_not_allowed());
    }
    check_target(bare, &addresses)?;
    Ok(addresses)
}

/// Whether [address] is an IPv6 literal, as `net.isIPv6`.
pub fn is_ipv6_literal(host: &str) -> bool {
    host.parse::<Ipv6Addr>().is_ok()
}

pub fn is_ip_literal(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reset() {
        set_target_policy(TargetPolicy::default());
        set_allowed_internal_hosts(HashSet::new());
    }

    #[test]
    fn blocks_internal_and_mapped_addresses() {
        for address in ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1", "fd00::1", "::ffff:127.0.0.1", "0.0.0.0"] {
            assert!(is_blocked_address(address.parse().unwrap()), "{address}");
        }
        for address in ["1.1.1.1", "2606:4700:4700::1111", "172.32.0.1"] {
            assert!(!is_blocked_address(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn parses_allow_lists_and_names_the_bad_entry() {
        let rules = parse_allow_list("10.0.0.0/8, 192.168.1.20,*.corp.example", "STATUSTICK_ALLOW").unwrap().unwrap();
        assert_eq!(rules.len(), 3);
        assert!(bound_to(&rules, "db.corp.example", None));
        assert!(bound_to(&rules, "x", Some("10.9.9.9".parse().unwrap())));
        assert!(!bound_to(&rules, "corp.example", Some("192.168.1.21".parse().unwrap())));
        assert_eq!(parse_allow_list("10.0.0.0/33", "STATUSTICK_ALLOW").unwrap_err(), "STATUSTICK_ALLOW has a range that is not valid: 10.0.0.0/33");
        assert_eq!(parse_allow_list("https://x", "STATUSTICK_ALLOW").unwrap_err(), "STATUSTICK_ALLOW has an entry that is not valid: https://x");
        assert!(parse_allow_list(" , ", "STATUSTICK_ALLOW").unwrap().is_none());
    }

    #[test]
    fn allowed_internal_hosts_ignore_literals_and_wildcards() {
        let (hosts, ignored) = parse_allowed_internal_hosts("mock.test, Target.Local., 127.0.0.1, *.x.test, 127.1, http://a");
        assert_eq!(hosts, HashSet::from(["mock.test".to_string(), "target.local".to_string()]));
        assert_eq!(ignored, vec!["127.0.0.1", "*.x.test", "127.1", "http://a"]);
    }

    #[tokio::test]
    async fn policies_decide_what_a_check_may_reach() {
        reset();
        assert_eq!(resolve_allowed("127.0.0.1", 0).await.unwrap_err(), target_not_allowed());
        assert_eq!(resolve_allowed("[::1]", 0).await.unwrap_err(), target_not_allowed());
        set_target_policy(TargetPolicy { internal: true, allow: None });
        assert!(resolve_allowed("127.0.0.1", 0).await.is_ok());
        assert_eq!(resolve_allowed("169.254.169.254", 0).await.unwrap_err(), target_not_allowed());
        set_target_policy(TargetPolicy { internal: true, allow: parse_allow_list("10.0.0.0/8", "X").unwrap() });
        assert_eq!(resolve_allowed("127.0.0.1", 0).await.unwrap_err().message, "target not allowed by agent policy");
        assert!(resolve_allowed("10.1.1.1", 0).await.is_ok());
        assert!(refused_answer("x.example", &["127.0.0.1".to_string()]));
        reset();
        assert_eq!(resolve_allowed("::1", 4).await.unwrap_err().message, "No IPv4 address (A record) for ::1");
        assert!(refused_answer("x.example", &["10.0.0.1".to_string(), "text".to_string()]));
        assert!(!refused_answer("x.example", &["mail.example".to_string()]));
    }

    #[test]
    fn maps_ip_versions() {
        assert_eq!(family_of(Some(&Value::from("6"))), 6);
        assert_eq!(family_of(Some(&Value::from(4))), 4);
        assert_eq!(family_of(Some(&Value::from("x"))), 0);
        assert_eq!(family_of(None), 0);
    }
}
