//! Ping checks: ICMP echo over an unprivileged ICMP socket (or a raw one), and a TCP connection to port 443 where
//! neither may be opened.
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};
use socket2::{Domain, Protocol, Socket, Type};

use crate::targets::{family_of, resolve_allowed};
use crate::tcp::tcp_probe;
use crate::util::{elapsed_ms, now_iso, number_field, timeout_field};

const TCP_PING_PORT: u16 = 443;
pub const TCP_PING_NOTE: &str = "ICMP ping is not available here (no NET_RAW capability or ping program), so a TCP connection to port 443 was checked instead";
const INTERVAL: Duration = Duration::from_secs(1);
const PAYLOAD: usize = 56;
static TCP_PING_LOGGED: AtomicBool = AtomicBool::new(false);

/// What the echo requests got back; `sent` counts the requests that left before the deadline.
#[derive(Debug, Clone)]
pub struct PingAnswer {
    pub sent: usize,
    pub times: Vec<f64>,
}

impl PingAnswer {
    pub fn alive(&self) -> bool {
        !self.times.is_empty()
    }

    fn stat(&self, pick: impl Fn(&[f64]) -> f64) -> String {
        if self.times.is_empty() { "unknown".to_string() } else { format!("{:.3}", pick(&self.times)) }
    }

    pub fn min(&self) -> String {
        self.stat(|times| times.iter().copied().fold(f64::INFINITY, f64::min))
    }

    pub fn max(&self) -> String {
        self.stat(|times| times.iter().copied().fold(0.0, f64::max))
    }

    pub fn avg(&self) -> String {
        self.stat(|times| times.iter().sum::<f64>() / times.len() as f64)
    }

    pub fn stddev(&self) -> String {
        self.stat(|times| {
            let mean = times.iter().sum::<f64>() / times.len() as f64;
            (times.iter().map(|time| time * time).sum::<f64>() / times.len() as f64 - mean * mean).max(0.0).sqrt()
        })
    }

    pub fn packet_loss(&self) -> String {
        let sent = self.sent.max(1) as f64;
        format!("{:.3}", (sent - self.times.len() as f64) / sent * 100.0)
    }

    /// The first reply's time with the 3 decimals ping prints.
    pub fn first_time(&self) -> Option<f64> {
        self.times.first().map(|time| (time * 1000.0).round() / 1000.0)
    }
}

/// ICMP sockets may not be opened here.
#[derive(Debug)]
pub struct IcmpUnavailable;

fn open_socket(address: IpAddr) -> Result<Socket, IcmpUnavailable> {
    let (domain, protocol) = if address.is_ipv4() { (Domain::IPV4, Protocol::ICMPV4) } else { (Domain::IPV6, Protocol::ICMPV6) };
    Socket::new(domain, Type::DGRAM, Some(protocol)).or_else(|_| Socket::new(domain, Type::RAW, Some(protocol))).map_err(|_| IcmpUnavailable)
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data.chunks(2).map(|pair| u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]))).sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn echo_request(v4: bool, identifier: u16, sequence: u16, token: &[u8; 8]) -> Vec<u8> {
    let mut packet = vec![if v4 { 8 } else { 128 }, 0, 0, 0];
    packet.extend_from_slice(&identifier.to_be_bytes());
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(token);
    packet.resize(8 + PAYLOAD, 0);
    if v4 {
        let sum = checksum(&packet);
        packet[2..4].copy_from_slice(&sum.to_be_bytes());
    }
    packet
}

/// The sequence number of an echo reply carrying [token]; IPv4 sockets may hand over the IP header first.
fn reply_sequence(v4: bool, data: &[u8], token: &[u8; 8]) -> Option<u16> {
    let icmp = if v4 && data.len() >= 20 && data[0] >> 4 == 4 { &data[usize::from(data[0] & 0x0f) * 4..] } else { data };
    if icmp.len() < 16 || icmp[0] != if v4 { 0 } else { 129 } || &icmp[8..16] != token {
        return None;
    }
    Some(u16::from_be_bytes([icmp[6], icmp[7]]))
}

/// Sends [count] echo requests a second apart and collects the replies until all came back or [timeout] passed.
pub async fn icmp_probe(address: IpAddr, count: usize, timeout: Duration) -> Result<PingAnswer, IcmpUnavailable> {
    let socket = open_socket(address)?;
    socket.set_nonblocking(true).map_err(|_| IcmpUnavailable)?;
    let socket = tokio::net::UdpSocket::from_std(std::net::UdpSocket::from(socket)).map_err(|_| IcmpUnavailable)?;
    let v4 = address.is_ipv4();
    let token: [u8; 8] = rand::random();
    let identifier: u16 = rand::random();
    let target = SocketAddr::new(address, 0);
    let deadline = tokio::time::Instant::now() + timeout;
    let mut sent_at: HashMap<u16, Instant> = HashMap::new();
    let mut times = Vec::new();
    let mut next_send = tokio::time::Instant::now();
    let mut sequence: u16 = 0;
    let mut buffer = [0u8; 2048];
    loop {
        let all_sent = usize::from(sequence) >= count;
        if all_sent && sent_at.is_empty() {
            break;
        }
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => break,
            _ = tokio::time::sleep_until(next_send), if !all_sent => {
                let packet = echo_request(v4, identifier, sequence, &token);
                let _ = socket.send_to(&packet, target).await;
                sent_at.insert(sequence, Instant::now());
                sequence += 1;
                next_send += INTERVAL;
            }
            received = socket.recv(&mut buffer) => {
                let Ok(length) = received else { continue };
                if let Some(when) = reply_sequence(v4, &buffer[..length], &token).and_then(|sequence| sent_at.remove(&sequence)) {
                    times.push(when.elapsed().as_secs_f64() * 1000.0);
                }
            }
        }
    }
    Ok(PingAnswer { sent: usize::from(sequence), times })
}

fn count_of(request: &Map<String, Value>) -> usize {
    number_field(request, "count").filter(|count| *count >= 1.0).map(|count| count as usize).unwrap_or(1).min(100)
}

async fn tcp_ping(host: Value, address: IpAddr, timeout: Duration, start: Instant) -> Value {
    if !TCP_PING_LOGGED.swap(true, Ordering::Relaxed) {
        eprintln!("Ping: {TCP_PING_NOTE}. Ping checks use TCP until the agent can send ICMP.");
    }
    let (connected, time, failure) = tcp_probe(address, TCP_PING_PORT, timeout).await;
    let up = connected || failure.as_ref().is_some_and(|failure| failure.is("ECONNREFUSED"));
    let ms = time.to_string();
    let mut result = Map::new();
    result.insert("host".into(), host);
    result.insert("status".into(), Value::from(if up { "up" } else { "down" }));
    result.insert("responseTime".into(), Value::from(if up { time } else { elapsed_ms(start) }));
    result.insert("packetLoss".into(), Value::from(if up { "0%" } else { "100%" }));
    result.insert("timestamp".into(), Value::from(now_iso()));
    if !up {
        let error = failure.map(|failure| failure.message).filter(|message| !message.is_empty()).unwrap_or_else(|| "No answer".to_string());
        result.insert("error".into(), Value::from(format!("{error}. {TCP_PING_NOTE}")));
    }
    result.insert("details".into(), json!({ "alive": up, "min": ms, "max": ms, "avg": ms, "stddev": "0", "method": "tcp", "note": TCP_PING_NOTE }));
    Value::Object(result)
}

/// `/check/ping` and the agent's `ping` job.
pub async fn ping_check(request: &Map<String, Value>) -> Value {
    let start = Instant::now();
    let host = request.get("host").cloned().unwrap_or(Value::Null);
    let timeout = timeout_field(request, "timeout", 10000.0);
    let address = match resolve_allowed(host.as_str().unwrap_or(""), family_of(request.get("ipVersion"))).await {
        Ok(addresses) => addresses[0],
        Err(failure) => {
            return json!({ "host": host, "status": "down", "responseTime": elapsed_ms(start), "timestamp": now_iso(), "error": failure.message });
        }
    };
    let answer = match icmp_probe(address, count_of(request), timeout).await {
        Ok(answer) => answer,
        Err(IcmpUnavailable) => return tcp_ping(host, address, timeout, start).await,
    };
    let response_time = answer.first_time().map(Value::from).unwrap_or_else(|| Value::from(elapsed_ms(start)));
    json!({
        "host": host,
        "status": if answer.alive() { "up" } else { "down" },
        "responseTime": response_time,
        "packetLoss": answer.packet_loss(),
        "timestamp": now_iso(),
        "details": {
            "alive": answer.alive(),
            "min": answer.min(),
            "max": answer.max(),
            "avg": answer.avg(),
            "stddev": answer.stddev(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_statistics_like_ping() {
        let answer = PingAnswer { sent: 2, times: vec![0.083, 0.147] };
        assert_eq!(
            (answer.min(), answer.avg(), answer.max(), answer.stddev(), answer.packet_loss()),
            ("0.083".into(), "0.115".into(), "0.147".into(), "0.032".into(), "0.000".into())
        );
        let lost = PingAnswer { sent: 1, times: vec![] };
        assert_eq!((lost.min(), lost.packet_loss(), lost.alive()), ("unknown".into(), "100.000".into(), false));
    }

    #[test]
    fn matches_replies_by_token_with_or_without_the_ip_header() {
        let token = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut reply = echo_request(true, 9, 3, &token);
        reply[0] = 0;
        assert_eq!(reply_sequence(true, &reply, &token), Some(3));
        let mut with_header = vec![0x45; 20];
        with_header.extend_from_slice(&reply);
        assert_eq!(reply_sequence(true, &with_header, &token), Some(3));
        assert_eq!(reply_sequence(true, &reply, &[0; 8]), None);
        assert_eq!(checksum(&echo_request(true, 9, 3, &token)), 0);
    }

    #[tokio::test]
    async fn pings_the_loopback_address() {
        match icmp_probe("127.0.0.1".parse().unwrap(), 2, Duration::from_secs(3)).await {
            Ok(answer) => assert_eq!((answer.sent, answer.times.len()), (2, 2)),
            Err(IcmpUnavailable) => eprintln!("ICMP sockets are not available here"),
        }
    }
}
