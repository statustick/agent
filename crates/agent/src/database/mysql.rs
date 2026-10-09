//! MySQL and MariaDB: the read-only query as a prepared statement, which refuses a second statement, inside a read-only
//! transaction that is rolled back. Error codes carry the names the JavaScript driver uses.
use std::time::Instant;

use mysql_async::prelude::Queryable;
use mysql_async::{Conn, OptsBuilder, SslOpts};
use serde_json::Value;

use super::{DriverError, Target, connect_tcp};

pub struct Session {
    conn: Conn,
}

fn code_name(code: u16) -> String {
    match code {
        1044 => "ER_DBACCESS_DENIED_ERROR",
        1045 => "ER_ACCESS_DENIED_ERROR",
        1049 => "ER_BAD_DB_ERROR",
        1054 => "ER_BAD_FIELD_ERROR",
        1064 => "ER_PARSE_ERROR",
        1142 => "ER_TABLEACCESS_DENIED_ERROR",
        1146 => "ER_NO_SUCH_TABLE",
        1193 => "ER_UNKNOWN_SYSTEM_VARIABLE",
        1227 => "ER_SPECIFIC_ACCESS_DENIED_ERROR",
        1295 => "ER_UNSUPPORTED_PS",
        1305 => "ER_SP_DOES_NOT_EXIST",
        1698 => "ER_ACCESS_DENIED_NO_PASSWORD_ERROR",
        1792 => "ER_CANT_EXECUTE_IN_READ_ONLY_TRANSACTION",
        1969 => "ER_STATEMENT_TIMEOUT",
        3024 => "ER_QUERY_TIMEOUT",
        other => return other.to_string(),
    }
    .to_string()
}

fn driver_error(error: mysql_async::Error) -> DriverError {
    match error {
        mysql_async::Error::Server(server) => DriverError::new(server.message, Some(&code_name(server.code))),
        mysql_async::Error::Io(mysql_async::IoError::Io(io)) => DriverError::new(io.to_string(), Some(&statustick_checks::util::io_code(&io))),
        other => DriverError::new(other.to_string(), None),
    }
}

pub async fn open(target: &Target, connected: &mut Option<Instant>) -> Result<Session, DriverError> {
    // The driver opens its own socket, so the connect time comes from one TCP connection of ours.
    drop(connect_tcp(target).await?);
    *connected = Some(Instant::now());
    let mut options = OptsBuilder::default()
        .ip_or_hostname(target.address.to_string())
        .tcp_port(target.port)
        .db_name(target.database.clone())
        .user(target.user.clone())
        .pass(target.password.clone())
        .prefer_socket(false)
        .stmt_cache_size(0);
    if target.tls {
        let mut tls = SslOpts::default()
            .with_danger_tls_hostname_override(Some(target.host.trim_start_matches('[').trim_end_matches(']').to_string()))
            .with_danger_accept_invalid_certs(!target.tls_verify)
            .with_danger_skip_domain_validation(!target.tls_verify);
        if let Ok(file) = std::env::var("NODE_EXTRA_CA_CERTS")
            && !file.trim().is_empty()
        {
            tls = tls.with_root_certs(vec![std::path::PathBuf::from(file.trim()).into()]);
        }
        options = options.ssl_opts(tls);
    }
    let conn = Conn::new(options).await.map_err(driver_error)?;
    Ok(Session { conn })
}

fn number(value: f64) -> Value {
    serde_json::Number::from_f64(value).map(Value::Number).unwrap_or(Value::Null)
}

fn json_of(value: mysql_async::Value) -> Value {
    use mysql_async::Value as V;
    match value {
        V::NULL => Value::Null,
        V::Bytes(bytes) => Value::from(String::from_utf8_lossy(&bytes).into_owned()),
        V::Int(value) => number(value as f64),
        V::UInt(value) => number(value as f64),
        V::Float(value) => number(value as f64),
        V::Double(value) => number(value),
        V::Date(year, month, day, hour, minute, second, micros) => {
            Value::from(format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{:03}Z", micros / 1000))
        }
        V::Time(negative, days, hours, minutes, seconds, _) => {
            Value::from(format!("{}{:02}:{minutes:02}:{seconds:02}", if negative { "-" } else { "" }, days * 24 + hours as u32))
        }
    }
}

impl Session {
    pub async fn run(&mut self, query: Option<&str>, timeout_ms: u64) -> Result<Value, DriverError> {
        let Some(query) = query else {
            let row: Option<mysql_async::Row> = self.conn.query_first("SELECT 1").await.map_err(driver_error)?;
            return Ok(row.and_then(|mut row| row.take::<mysql_async::Value, _>(0)).map(json_of).unwrap_or(Value::Null));
        };
        if let Err(error) = self.conn.query_drop(format!("SET SESSION MAX_EXECUTION_TIME = {timeout_ms}")).await {
            let error = driver_error(error);
            if error.code.as_deref() != Some("ER_UNKNOWN_SYSTEM_VARIABLE") {
                return Err(error);
            }
            // MariaDB has max_statement_time, in seconds, instead.
            let seconds = statustick_checks::util::js_number(timeout_ms as f64 / 1000.0);
            self.conn.query_drop(format!("SET SESSION max_statement_time = {seconds}")).await.map_err(driver_error)?;
        }
        self.conn.query_drop("START TRANSACTION READ ONLY").await.map_err(driver_error)?;
        let row: Option<mysql_async::Row> = self.conn.exec_first(query, ()).await.map_err(driver_error)?;
        self.conn.query_drop("ROLLBACK").await.map_err(driver_error)?;
        Ok(row.and_then(|mut row| row.take::<mysql_async::Value, _>(0)).map(json_of).unwrap_or(Value::Null))
    }

    pub async fn close(self) {
        let _ = self.conn.disconnect().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_error_codes_and_values_as_the_javascript_driver() {
        assert_eq!(code_name(1045), "ER_ACCESS_DENIED_ERROR");
        assert_eq!(code_name(9999), "9999");
        assert_eq!(json_of(mysql_async::Value::Int(1)), Value::from(1.0));
        assert_eq!(json_of(mysql_async::Value::Bytes(b"12.50".to_vec())), Value::from("12.50"));
        assert_eq!(json_of(mysql_async::Value::Date(2026, 10, 7, 9, 5, 1, 250000)), Value::from("2026-10-07T09:05:01.250Z"));
    }
}
