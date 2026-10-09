//! gRPC health checks: one unary call of the standard grpc.health.v1.Health/Check over HTTP/2. Request and answer are
//! one-field protobuf messages, encoded here by hand.
use std::time::Instant;

use bytes::Bytes;
use serde_json::{Map, Value};

use crate::blocking::USER_AGENT;
use crate::connection::{Stream, Target, connect_plain, connect_tls, failure_of, problem, tls_details, with_deadline};
use crate::targets::{family_of, is_ipv6_literal, resolve_allowed};
use crate::tcp::port_of;
use crate::util::{Failure, elapsed_ms, now_iso, number_field, string_field, timeout_field};

const HEALTH_PATH: &str = "/grpc.health.v1.Health/Check";
const MAX_SERVICE_LENGTH: usize = 1000;
const MAX_ANSWER_BYTES: usize = 1024;
pub const SERVING_STATUSES: [&str; 4] = ["UNKNOWN", "SERVING", "NOT_SERVING", "SERVICE_UNKNOWN"];
pub const GRPC_CODES: [&str; 17] = [
    "OK",
    "CANCELLED",
    "UNKNOWN",
    "INVALID_ARGUMENT",
    "DEADLINE_EXCEEDED",
    "NOT_FOUND",
    "ALREADY_EXISTS",
    "PERMISSION_DENIED",
    "RESOURCE_EXHAUSTED",
    "FAILED_PRECONDITION",
    "ABORTED",
    "OUT_OF_RANGE",
    "UNIMPLEMENTED",
    "INTERNAL",
    "UNAVAILABLE",
    "DATA_LOSS",
    "UNAUTHENTICATED",
];

fn varint(mut value: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    while value > 0x7f {
        bytes.push((value & 0x7f) as u8 | 0x80);
        value >>= 7;
    }
    bytes.push(value as u8);
    bytes
}

/// A length-prefixed gRPC message holding `HealthCheckRequest { string service = 1; }`.
pub fn health_request(service: &str) -> Vec<u8> {
    let name = service.as_bytes();
    let mut message = Vec::new();
    if !name.is_empty() {
        message.push(0x0a);
        message.extend(varint(name.len()));
        message.extend_from_slice(name);
    }
    let mut frame = vec![0];
    frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
    frame.extend(message);
    frame
}

fn invalid_answer() -> Failure {
    problem("The health answer is not a valid protobuf message", "GRPC_INVALID_ANSWER")
}

fn read_varint(bytes: &[u8], at: usize) -> Result<(u64, usize), Failure> {
    let mut value: u64 = 0;
    let mut shift = 0;
    let mut offset = at;
    while offset < bytes.len() && shift < 35 {
        let byte = bytes[offset];
        value += u64::from(byte & 0x7f) << shift;
        if byte < 0x80 {
            return Ok((value, offset + 1));
        }
        shift += 7;
        offset += 1;
    }
    Err(invalid_answer())
}

/// The `status` of a length-prefixed `HealthCheckResponse { ServingStatus status = 1; }`; 0 (UNKNOWN) when absent.
pub fn serving_status_of(frame: &[u8]) -> Result<u64, Failure> {
    if frame.len() < 5 {
        return Err(problem("The server sent no health answer", "GRPC_INVALID_ANSWER"));
    }
    if frame[0] != 0 {
        return Err(problem("The health answer is compressed", "GRPC_INVALID_ANSWER"));
    }
    let length = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
    if frame.len() < 5 + length {
        return Err(problem("The health answer is cut short", "GRPC_INVALID_ANSWER"));
    }
    let message = &frame[5..5 + length];
    let mut status = 0;
    let mut at = 0;
    while at < message.len() {
        let (tag, next) = read_varint(message, at)?;
        match tag & 7 {
            0 => {
                let (value, after) = read_varint(message, next)?;
                if tag >> 3 == 1 {
                    status = value;
                }
                at = after;
            }
            1 => at = next + 8,
            5 => at = next + 4,
            2 => {
                let (size, after) = read_varint(message, next)?;
                at = after + size as usize;
            }
            _ => return Err(invalid_answer()),
        }
    }
    Ok(status)
}

fn status_error(code: u64, service: &str) -> String {
    let name = GRPC_CODES.get(code as usize).copied().unwrap_or("UNKNOWN");
    match code {
        12 => format!("gRPC status {code} {name}: the server has no grpc.health.v1.Health service"),
        5 => {
            let quoted = if service.is_empty() { "\"\"".to_string() } else { format!("\"{}\"", crate::util::utf16_prefix(service, 100)) };
            format!("gRPC status {code} {name}: the server does not know the service {quoted}")
        }
        _ => format!("gRPC status {code} {name}"),
    }
}

fn h2_failure(error: h2::Error) -> Failure {
    if error.is_io()
        && let Some(io) = error.get_io()
    {
        let code = crate::util::io_code(io);
        return Failure::coded(format!("read {code}"), &code);
    }
    Failure::coded(error.to_string(), "ERR_HTTP2_ERROR")
}

struct Answer {
    http_status: u16,
    grpc_status: Option<String>,
    frame: Vec<u8>,
}

async fn call(io: std::pin::Pin<Box<dyn Stream>>, target: &Target, tls: bool, service: &str, timeout_ms: u128) -> Result<Answer, Failure> {
    let (client, connection) = h2::client::handshake(io).await.map_err(h2_failure)?;
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let host = if is_ipv6_literal(&target.host) { format!("[{}]", target.host) } else { target.host.clone() };
    let uri = format!("{}://{host}:{}{HEALTH_PATH}", if tls { "https" } else { "http" }, target.port);
    let request = http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("grpc-timeout", format!("{timeout_ms}m"))
        .header("user-agent", USER_AGENT)
        .body(())
        .map_err(|error| Failure::plain(error.to_string()))?;
    let result = async {
        let mut client = client.ready().await.map_err(h2_failure)?;
        let (response, mut send) = client.send_request(request, false).map_err(h2_failure)?;
        send.send_data(Bytes::from(health_request(service)), true).map_err(h2_failure)?;
        let response = response.await.map_err(|error| {
            if error.reason().is_some() || error.is_go_away() {
                problem("The server closed the call without an answer", "GRPC_INVALID_ANSWER")
            } else {
                h2_failure(error)
            }
        })?;
        let http_status = response.status().as_u16();
        let header_status = response.headers().get("grpc-status").and_then(|value| value.to_str().ok()).map(str::to_string);
        let mut body = response.into_body();
        let mut frame = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.map_err(h2_failure)?;
            let _ = body.flow_control().release_capacity(chunk.len());
            if frame.len() + chunk.len() > MAX_ANSWER_BYTES {
                return Err(problem(format!("The health answer is larger than {MAX_ANSWER_BYTES} bytes"), "GRPC_INVALID_ANSWER"));
            }
            frame.extend_from_slice(&chunk);
        }
        let trailers = body.trailers().await.map_err(h2_failure)?;
        let trailer_status = trailers.and_then(|trailers| trailers.get("grpc-status").and_then(|value| value.to_str().ok()).map(str::to_string));
        Ok(Answer { http_status, grpc_status: trailer_status.or(header_status), frame })
    }
    .await;
    driver.abort();
    result
}

/// `/check/grpc` and the agent's `grpc` job. Never fails.
pub async fn grpc_check(request: &Map<String, Value>) -> Value {
    let start = Instant::now();
    let host = request.get("host").cloned().unwrap_or(Value::Null);
    let port_value = request.get("port").cloned().unwrap_or(Value::Null);
    let service = string_field(request, "service").unwrap_or_default();
    let tls_mode = string_field(request, "tlsMode").unwrap_or_else(|| "NONE".to_string());
    let tls_verify = crate::util::bool_field(request, "tlsVerify").unwrap_or(true);
    let timeout = timeout_field(request, "timeout", 10000.0);
    let mut details = Map::new();
    let answer = |status: &str, failure: Option<(String, String)>, details: &Map<String, Value>, response_time: Option<i64>| {
        let mut result = Map::new();
        result.insert("host".into(), host.clone());
        result.insert("port".into(), port_value.clone());
        result.insert("status".into(), Value::from(status));
        result.insert("responseTime".into(), Value::from(response_time.unwrap_or_else(|| elapsed_ms(start))));
        result.insert("timestamp".into(), Value::from(now_iso()));
        if let Some((error, code)) = failure {
            result.insert("error".into(), Value::from(error));
            result.insert("errorCode".into(), Value::from(code));
        }
        if !details.is_empty() {
            result.insert("details".into(), Value::Object(details.clone()));
        }
        Value::Object(result)
    };
    if tls_mode != "NONE" && tls_mode != "TLS" {
        return answer("error", Some(("tlsMode must be NONE or TLS for gRPC".into(), "INVALID_REQUEST".into())), &details, Some(0));
    }
    if service.encode_utf16().count() > MAX_SERVICE_LENGTH {
        return answer("error", Some((format!("service is longer than {MAX_SERVICE_LENGTH} characters"), "INVALID_REQUEST".into())), &details, Some(0));
    }
    let timeout_ms = number_field(request, "timeout").map(|value| value as u128).unwrap_or(timeout.as_millis());
    let host_text = host.as_str().unwrap_or("").to_string();
    let outcome = with_deadline(timeout, async {
        let address = resolve_allowed(&host_text, family_of(request.get("ipVersion"))).await?[0];
        let target = Target { host: host_text.clone(), address, port: port_of(request) };
        let plain = connect_plain(&target).await?;
        let io: std::pin::Pin<Box<dyn Stream>> = if tls_mode == "TLS" {
            let stream = connect_tls(&target, tls_verify, &["h2"], plain).await?;
            if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
                return Err(problem("The server does not speak HTTP/2 over TLS (no ALPN h2)", "GRPC_INVALID_ANSWER"));
            }
            tls_details(&stream, &mut details);
            Box::pin(stream)
        } else {
            Box::pin(plain)
        };
        let answer = call(io, &target, tls_mode == "TLS", &service, timeout_ms).await?;
        Ok(answer)
    })
    .await;
    let reply = match outcome {
        Ok(reply) => reply,
        Err(failure) => return answer("down", Some(failure_of(&failure)), &details, None),
    };
    if reply.http_status != 200 {
        return answer("down", Some((format!("The server answered HTTP {}, not gRPC", reply.http_status), "GRPC_INVALID_ANSWER".into())), &details, None);
    }
    let Some(grpc_status) = reply.grpc_status.and_then(|status| status.trim().parse::<u64>().ok()) else {
        return answer("down", Some(("The server sent no gRPC status".into(), "GRPC_INVALID_ANSWER".into())), &details, None);
    };
    details.insert("grpcStatus".into(), Value::from(grpc_status));
    if grpc_status != 0 {
        return answer("down", Some((status_error(grpc_status, &service), "GRPC_STATUS".into())), &details, None);
    }
    let serving = match serving_status_of(&reply.frame) {
        Ok(status) => SERVING_STATUSES.get(status as usize).copied().unwrap_or("UNKNOWN"),
        Err(failure) => return answer("down", Some(failure_of(&failure)), &details, None),
    };
    details.insert("servingStatus".into(), Value::from(serving));
    if serving != "SERVING" {
        return answer("down", Some((format!("Health status {serving}"), "GRPC_NOT_SERVING".into())), &details, None);
    }
    answer("up", None, &details, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_the_service_as_field_one() {
        assert_eq!(health_request(""), vec![0, 0, 0, 0, 0]);
        assert_eq!(health_request("api"), vec![0, 0, 0, 0, 5, 0x0a, 3, b'a', b'p', b'i']);
    }

    #[test]
    fn reads_the_serving_status_and_skips_unknown_fields() {
        assert_eq!(serving_status_of(&[0, 0, 0, 0, 2, 0x08, 1]).unwrap(), 1);
        assert_eq!(serving_status_of(&[0, 0, 0, 0, 0]).unwrap(), 0);
        assert_eq!(
            serving_status_of(&[0, 0, 0, 0, 7, 0x12, 2, b'h', b'i', 0x08, 2, 0x18]).unwrap_err().message,
            "The health answer is not a valid protobuf message"
        );
        assert_eq!(serving_status_of(&[0, 0, 0, 0, 6, 0x12, 2, b'h', b'i', 0x08, 2]).unwrap(), 2);
        assert_eq!(serving_status_of(&[1, 0, 0, 0, 0]).unwrap_err().message, "The health answer is compressed");
        assert_eq!(serving_status_of(&[0, 0, 0, 0, 9, 1]).unwrap_err().message, "The health answer is cut short");
    }
}
