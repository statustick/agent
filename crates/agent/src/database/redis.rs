//! Redis: AUTH and SELECT when the job asks for them, then PING, in RESP over a plain or TLS stream.
use std::time::Instant;

use serde_json::Value;
use statustick_checks::connection::Stream;

use super::{DriverError, Target, open_stream, read_exact, write_all};

const MAX_LINE_BYTES: usize = 64 * 1024;

pub struct Session {
    stream: Box<dyn Stream>,
}

fn command(parts: &[&str]) -> Vec<u8> {
    let mut bytes = format!("*{}\r\n", parts.len()).into_bytes();
    for part in parts {
        bytes.extend_from_slice(format!("${}\r\n", part.len()).as_bytes());
        bytes.extend_from_slice(part.as_bytes());
        bytes.extend_from_slice(b"\r\n");
    }
    bytes
}

async fn line(stream: &mut Box<dyn Stream>) -> Result<String, DriverError> {
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    while !bytes.ends_with(b"\r\n") {
        if bytes.len() > MAX_LINE_BYTES {
            return Err(DriverError::new("The Redis answer is too long", None));
        }
        read_exact(stream, &mut byte).await?;
        bytes.push(byte[0]);
    }
    bytes.truncate(bytes.len() - 2);
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// One reply: a simple string or the text of a bulk string; an error reply fails with its text.
async fn reply(stream: &mut Box<dyn Stream>) -> Result<String, DriverError> {
    let first = line(stream).await?;
    let (kind, rest) = first.split_at(first.chars().next().map(char::len_utf8).unwrap_or(0));
    match kind {
        "+" | ":" => Ok(rest.to_string()),
        "-" => Err(DriverError::new(rest, None)),
        "$" => {
            let length: i64 = rest.parse().map_err(|_| DriverError::new("The Redis answer is not valid", None))?;
            if length < 0 {
                return Ok(String::new());
            }
            let mut body = vec![0u8; length as usize + 2];
            read_exact(stream, &mut body).await?;
            body.truncate(length as usize);
            Ok(String::from_utf8_lossy(&body).into_owned())
        }
        _ => Err(DriverError::new("The Redis answer is not valid", None)),
    }
}

async fn call(stream: &mut Box<dyn Stream>, parts: &[&str]) -> Result<String, DriverError> {
    write_all(stream, &command(parts)).await?;
    reply(stream).await
}

pub async fn open(target: &Target, connected: &mut Option<Instant>) -> Result<Session, DriverError> {
    let mut stream = open_stream(target).await?;
    *connected = Some(Instant::now());
    if let Some(password) = &target.password {
        match target.user.as_ref().filter(|user| !user.is_empty()) {
            Some(user) => call(&mut stream, &["AUTH", user, password]).await?,
            None => call(&mut stream, &["AUTH", password]).await?,
        };
    }
    if let Some(database) = &target.database {
        call(&mut stream, &["SELECT", database]).await?;
    }
    Ok(Session { stream })
}

impl Session {
    pub async fn run(&mut self) -> Result<Value, DriverError> {
        call(&mut self.stream, &["PING"]).await.map(Value::from)
    }

    pub async fn close(mut self) {
        let _ = call(&mut self.stream, &["QUIT"]).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_commands_as_resp_arrays() {
        assert_eq!(command(&["AUTH", "pw"]), b"*2\r\n$4\r\nAUTH\r\n$2\r\npw\r\n".to_vec());
    }
}
