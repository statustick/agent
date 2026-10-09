//! TCP port checks: connect to the first allowed address, nothing sent.
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use serde_json::{Map, Value};
use tokio::net::TcpStream;

use crate::targets::{family_of, resolve_allowed};
use crate::util::{Failure, connect_failure, elapsed_ms, now_iso, number_field, object, timeout_field};

/// Connects to [address]; the failure carries the errno code, or is `Connection timeout` after [timeout].
pub async fn connect(address: IpAddr, port: u16, timeout: Duration) -> Result<TcpStream, Failure> {
    match tokio::time::timeout(timeout, TcpStream::connect(SocketAddr::new(address, port))).await {
        Ok(Ok(stream)) => {
            let _ = stream.set_nodelay(true);
            Ok(stream)
        }
        Ok(Err(error)) => Err(connect_failure(&error, address, port)),
        Err(_) => Err(Failure::plain("Connection timeout")),
    }
}

pub fn port_of(request: &Map<String, Value>) -> u16 {
    number_field(request, "port").filter(|port| (0.0..=65535.0).contains(port)).map(|port| port as u16).unwrap_or(0)
}

/// `/check/tcp` and the agent's `tcp` job.
pub async fn tcp_check(request: &Map<String, Value>) -> Value {
    let start = Instant::now();
    let host = request.get("host").cloned().unwrap_or(Value::Null);
    let port_value = request.get("port").cloned().unwrap_or(Value::Null);
    let timeout = timeout_field(request, "timeout", 10000.0);
    let answer = |status: &str, failure: Option<Failure>| {
        object(vec![
            ("host", Some(host.clone())),
            ("port", Some(port_value.clone())),
            ("status", Some(Value::from(status))),
            ("responseTime", Some(Value::from(elapsed_ms(start)))),
            ("timestamp", Some(Value::from(now_iso()))),
            ("error", failure.as_ref().map(|failure| Value::from(failure.message.clone()))),
            ("errorCode", failure.and_then(|failure| failure.code).map(Value::from)),
        ])
    };
    let addresses = match resolve_allowed(host.as_str().unwrap_or(""), family_of(request.get("ipVersion"))).await {
        Ok(addresses) => addresses,
        Err(failure) => return answer("down", Some(failure)),
    };
    match connect(addresses[0], port_of(request), timeout).await {
        Ok(_) => answer("up", None),
        Err(failure) => answer("down", Some(failure)),
    }
}

/// The result of a TCP connection standing in for another check, as `tcp_check` answers it.
pub async fn tcp_probe(address: IpAddr, port: u16, timeout: Duration) -> (bool, i64, Option<Failure>) {
    let start = Instant::now();
    let outcome = connect(address, port, timeout).await;
    let time = elapsed_ms(start);
    match outcome {
        Ok(_) => (true, time, None),
        Err(failure) => (false, time, Some(failure)),
    }
}
