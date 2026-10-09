//! PostgreSQL: our own TCP connection, TLS with Node.js's verification, and the read-only query in a transaction that
//! is rolled back. Values come back as the JavaScript driver gives them: int8 and numeric as text, json as objects.
use std::time::Instant;

use serde_json::Value;
use statustick_checks::tls::client_config;
use tokio_postgres::types::{FromSql, Type};
use tokio_postgres::{Client, Config, NoTls, SimpleQueryMessage};

use super::{DriverError, Target, connect_tcp};

pub struct Session {
    client: Client,
}

fn driver_error(error: tokio_postgres::Error) -> DriverError {
    if let Some(db) = error.as_db_error() {
        return DriverError::new(db.message(), Some(db.code().code()));
    }
    let mut source: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(&error);
    while let Some(inner) = source {
        if let Some(io) = inner.downcast_ref::<std::io::Error>() {
            return DriverError::new(error.to_string(), Some(&statustick_checks::util::io_code(io)));
        }
        source = inner.source();
    }
    DriverError::new(error.to_string(), None)
}

pub async fn open(target: &Target, connected: &mut Option<Instant>) -> Result<Session, DriverError> {
    let user = target.user.clone().filter(|user| !user.is_empty()).ok_or_else(|| DriverError::problem("A PostgreSQL check needs a user", "AUTH_FAILED"))?;
    let tcp = connect_tcp(target).await?;
    *connected = Some(Instant::now());
    let mut config = Config::new();
    config
        .user(&user)
        .dbname(target.database.clone().filter(|name| !name.is_empty()).unwrap_or_else(|| user.clone()))
        .password(target.password.clone().unwrap_or_default())
        .ssl_mode(if target.tls { tokio_postgres::config::SslMode::Require } else { tokio_postgres::config::SslMode::Disable });
    let client = if target.tls {
        use tokio_postgres::tls::MakeTlsConnect;
        let mut maker = tokio_postgres_rustls::MakeRustlsConnect::new((*client_config(target.tls_verify, &[])).clone());
        let host = target.host.trim_start_matches('[').trim_end_matches(']');
        let tls = MakeTlsConnect::<tokio::net::TcpStream>::make_tls_connect(&mut maker, host).map_err(|error| DriverError::new(error.to_string(), None))?;
        let (client, connection) = config.connect_raw(tcp, tls).await.map_err(driver_error)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        client
    } else {
        let (client, connection) = config.connect_raw(tcp, NoTls).await.map_err(driver_error)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        client
    };
    Ok(Session { client })
}

impl Session {
    pub async fn run(&mut self, query: Option<&str>, timeout_ms: u64) -> Result<Value, DriverError> {
        let Some(query) = query else {
            let messages = self.client.simple_query("SELECT 1").await.map_err(driver_error)?;
            let first = messages.iter().find_map(|message| match message {
                SimpleQueryMessage::Row(row) => row.get(0).map(str::to_string),
                _ => None,
            });
            return Ok(first.and_then(|text| text.parse::<i64>().ok()).map(Value::from).unwrap_or(Value::Null));
        };
        self.client.batch_execute("BEGIN READ ONLY").await.map_err(driver_error)?;
        self.client.batch_execute(&format!("SET LOCAL statement_timeout = {timeout_ms}")).await.map_err(driver_error)?;
        // The extended protocol refuses a second statement such as "COMMIT; DELETE …".
        let rows = self.client.query(query, &[]).await.map_err(driver_error)?;
        self.client.batch_execute("ROLLBACK").await.map_err(driver_error)?;
        let Some(row) = rows.first() else { return Ok(Value::Null) };
        if row.is_empty() {
            return Ok(Value::Null);
        }
        let raw: Raw = row.try_get(0).map_err(driver_error)?;
        Ok(raw.value())
    }

    pub async fn close(self) {
        drop(self.client);
    }
}

/// Any column as its wire bytes and type, decoded by [Raw::value].
struct Raw {
    bytes: Option<Vec<u8>>,
    kind: Type,
}

impl<'a> FromSql<'a> for Raw {
    fn from_sql(kind: &Type, raw: &'a [u8]) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        Ok(Raw { bytes: Some(raw.to_vec()), kind: kind.clone() })
    }

    fn from_sql_null(kind: &Type) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        Ok(Raw { bytes: None, kind: kind.clone() })
    }

    fn accepts(_: &Type) -> bool {
        true
    }
}

const POSTGRES_EPOCH_DAYS: i64 = 10957;

fn iso_from_micros(micros: i64) -> String {
    let unix = micros + POSTGRES_EPOCH_DAYS * 86_400_000_000;
    chrono::DateTime::from_timestamp_micros(unix).map(statustick_checks::util::iso).unwrap_or_default()
}

/// The binary `numeric` as the text PostgreSQL prints.
fn numeric_text(bytes: &[u8]) -> String {
    let word = |at: usize| u16::from_be_bytes([bytes[at], bytes[at + 1]]);
    if bytes.len() < 8 {
        return String::new();
    }
    let (count, weight, sign, scale) = (word(0) as usize, word(2) as i16 as i32, word(4), word(6) as usize);
    if sign == 0xC000 {
        return "NaN".into();
    }
    let digits: Vec<u16> = (0..count).filter(|index| 8 + index * 2 + 1 < bytes.len()).map(|index| word(8 + index * 2)).collect();
    let mut integer = String::new();
    for position in 0..=weight.max(-1) {
        let digit = digits.get(position as usize).copied().unwrap_or(0);
        if integer.is_empty() { integer.push_str(&digit.to_string()) } else { integer.push_str(&format!("{digit:04}")) }
    }
    if integer.is_empty() {
        integer.push('0');
    }
    let mut fraction = String::new();
    let mut position = weight + 1;
    while fraction.len() < scale {
        let digit = if position < 0 { 0 } else { digits.get(position as usize).copied().unwrap_or(0) };
        fraction.push_str(&format!("{digit:04}"));
        position += 1;
    }
    fraction.truncate(scale);
    let sign = if sign == 0x4000 { "-" } else { "" };
    if scale > 0 { format!("{sign}{integer}.{fraction}") } else { format!("{sign}{integer}") }
}

impl Raw {
    fn value(&self) -> Value {
        let Some(bytes) = &self.bytes else { return Value::Null };
        let int = |size: usize| -> Option<i64> {
            (bytes.len() == size).then(|| match size {
                2 => i16::from_be_bytes([bytes[0], bytes[1]]) as i64,
                4 => i32::from_be_bytes(bytes[..4].try_into().unwrap_or_default()) as i64,
                _ => i64::from_be_bytes(bytes[..8].try_into().unwrap_or_default()),
            })
        };
        let text = || Value::from(String::from_utf8_lossy(bytes).into_owned());
        match self.kind {
            Type::BOOL => Value::Bool(bytes.first() == Some(&1)),
            Type::INT2 => int(2).map(Value::from).unwrap_or(Value::Null),
            Type::INT4 => int(4).map(Value::from).unwrap_or(Value::Null),
            Type::OID if bytes.len() == 4 => Value::from(u32::from_be_bytes(bytes[..4].try_into().unwrap_or_default())),
            Type::INT8 => int(8).map(|value| Value::from(value.to_string())).unwrap_or(Value::Null),
            Type::FLOAT4 if bytes.len() == 4 => Value::from(f32::from_be_bytes(bytes[..4].try_into().unwrap_or_default()) as f64),
            Type::FLOAT8 if bytes.len() == 8 => Value::from(f64::from_be_bytes(bytes[..8].try_into().unwrap_or_default())),
            Type::OID | Type::FLOAT4 | Type::FLOAT8 => Value::Null,
            Type::NUMERIC => Value::from(numeric_text(bytes)),
            Type::JSON => serde_json::from_slice(bytes).unwrap_or_else(|_| text()),
            Type::JSONB => serde_json::from_slice(bytes.get(1..).unwrap_or_default()).unwrap_or(Value::Null),
            Type::TIMESTAMP | Type::TIMESTAMPTZ => int(8).map(|micros| Value::from(iso_from_micros(micros))).unwrap_or(Value::Null),
            Type::DATE => int(4).map(|days| Value::from(iso_from_micros(days * 86_400_000_000))).unwrap_or(Value::Null),
            Type::UUID if bytes.len() == 16 => {
                let hex = hex::encode(bytes);
                Value::from(format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..]))
            }
            _ => text(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn numeric(count: u16, weight: i16, sign: u16, scale: u16, digits: &[u16]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for word in [count, weight as u16, sign, scale].iter().chain(digits) {
            bytes.extend_from_slice(&word.to_be_bytes());
        }
        bytes
    }

    #[test]
    fn prints_numeric_values_as_postgres_does() {
        assert_eq!(numeric_text(&numeric(2, 0, 0, 2, &[12, 3400])), "12.34");
        assert_eq!(numeric_text(&numeric(2, 1, 0x4000, 0, &[1, 2345])), "-12345");
        assert_eq!(numeric_text(&numeric(1, -1, 0, 4, &[5])), "0.0005");
        assert_eq!(numeric_text(&numeric(0, 0, 0, 1, &[])), "0.0");
    }

    #[test]
    fn decodes_values_as_the_javascript_driver_gives_them() {
        let raw = |kind: Type, bytes: &[u8]| Raw { bytes: Some(bytes.to_vec()), kind }.value();
        assert_eq!(raw(Type::INT4, &7i32.to_be_bytes()), Value::from(7));
        assert_eq!(raw(Type::INT8, &7i64.to_be_bytes()), Value::from("7"));
        assert_eq!(raw(Type::TEXT, b"ok"), Value::from("ok"));
        assert_eq!(raw(Type::TIMESTAMPTZ, &0i64.to_be_bytes()), Value::from("2000-01-01T00:00:00.000Z"));
        assert_eq!(raw(Type::JSONB, b"\x01{\"a\":1}"), serde_json::json!({ "a": 1 }));
    }
}
