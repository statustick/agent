//! SMTP and IMAP checks: read the greeting, ask what the server offers (EHLO, CAPABILITY), optionally switch to TLS with
//! STARTTLS, and say goodbye (QUIT, LOGOUT). Never logs in, and never returns the server's texts.
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::LazyLock;
use std::time::Instant;

use regex::Regex;
use serde_json::{Map, Value};

use crate::connection::{LineReader, Stream, Target, connect_plain, connect_tls, failure_of, problem, tls_details, with_deadline};
use crate::targets::{family_of, resolve_allowed};
use crate::tcp::port_of;
use crate::util::{Failure, bool_field, elapsed_ms, now_iso, string_field, timeout_field};

const MAX_REPLY_LINES: usize = 100;

#[derive(Clone, Copy, PartialEq)]
enum Mail {
    Smtp,
    Imap,
}

impl Mail {
    fn name(self) -> &'static str {
        match self {
            Mail::Smtp => "SMTP",
            Mail::Imap => "IMAP",
        }
    }
}

static SMTP_LINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^([0-9]{3})([ -]?)(.*)$").expect("valid pattern"));
static SMTP_STARTTLS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^STARTTLS(?-u:\b)").expect("valid pattern"));
static IMAP_GREETING: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^\*\s+(OK|PREAUTH|BYE)(?-u:\b)").expect("valid pattern"));
static IMAP_CAPABILITY_IN_GREETING: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\[CAPABILITY\s").expect("valid pattern"));
static IMAP_CAPABILITY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^\*\s+(OK\s+\[)?CAPABILITY\s").expect("valid pattern"));
static IMAP_STARTTLS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\sSTARTTLS(\s|\]|$)").expect("valid pattern"));

/// `EHLO` names the client by its address literal (RFC 5321 4.1.3), so no host name of the machine leaves.
fn address_literal(local: Option<IpAddr>) -> String {
    let address = match local {
        Some(IpAddr::V6(v6)) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        Some(v4) => v4,
        None => IpAddr::from([127, 0, 0, 1]),
    };
    match address {
        IpAddr::V6(v6) => format!("[IPv6:{v6}]"),
        IpAddr::V4(v4) => format!("[{v4}]"),
    }
}

async fn smtp_reply(reader: &mut LineReader) -> Result<(u16, Vec<String>), Failure> {
    let mut lines = Vec::new();
    loop {
        let line = reader.next().await?;
        let Some(capture) = SMTP_LINE.captures(&line) else {
            return Err(problem("The server does not answer in SMTP", "SMTP_INVALID_ANSWER"));
        };
        lines.push(capture[3].to_string());
        if &capture[2] != "-" {
            return Ok((capture[1].parse().unwrap_or(0), lines));
        }
        if lines.len() > MAX_REPLY_LINES {
            return Err(problem(format!("An SMTP reply has more than {MAX_REPLY_LINES} lines"), "SMTP_INVALID_ANSWER"));
        }
    }
}

async fn imap_answer(reader: &mut LineReader, tag: &str) -> Result<(String, Vec<String>), Failure> {
    let mut untagged = Vec::new();
    loop {
        let line = reader.next().await?;
        if let Some(rest) = line.strip_prefix(&format!("{tag} ")) {
            return Ok((rest.split(' ').next().unwrap_or("").to_uppercase(), untagged));
        }
        untagged.push(line);
        if untagged.len() > MAX_REPLY_LINES {
            return Err(problem(format!("An IMAP answer has more than {MAX_REPLY_LINES} lines"), "IMAP_INVALID_ANSWER"));
        }
    }
}

fn offers_starttls(line: &str) -> bool {
    IMAP_CAPABILITY.is_match(line) && IMAP_STARTTLS.is_match(line)
}

struct Dialogue {
    mail: Mail,
    tags: usize,
    greeting_offers: Option<bool>,
    local: Option<IpAddr>,
}

impl Dialogue {
    fn tag(&mut self) -> String {
        self.tags += 1;
        format!("st{}", self.tags)
    }

    async fn greet(&mut self, reader: &mut LineReader, details: &mut Map<String, Value>) -> Result<(), Failure> {
        match self.mail {
            Mail::Smtp => {
                let (code, _) = smtp_reply(reader).await?;
                details.insert("greetingCode".into(), Value::from(code.to_string()));
                if code != 220 {
                    return Err(problem(format!("The SMTP greeting is {code}, not 220"), "SMTP_GREETING"));
                }
            }
            Mail::Imap => {
                let line = reader.next().await?;
                let Some(capture) = IMAP_GREETING.captures(&line) else {
                    return Err(problem("The server does not answer in IMAP", "IMAP_INVALID_ANSWER"));
                };
                let code = capture[1].to_uppercase();
                details.insert("greetingCode".into(), Value::from(code.clone()));
                if code == "BYE" {
                    return Err(problem("The IMAP greeting is BYE: the server refuses connections", "IMAP_GREETING"));
                }
                if IMAP_CAPABILITY_IN_GREETING.is_match(&line) {
                    self.greeting_offers = Some(offers_starttls(&line));
                }
            }
        }
        Ok(())
    }

    async fn capabilities(&mut self, reader: &mut LineReader) -> Result<bool, Failure> {
        match self.mail {
            Mail::Smtp => {
                reader.write_line(&format!("EHLO {}", address_literal(self.local))).await?;
                let (code, lines) = smtp_reply(reader).await?;
                Ok(code == 250 && lines.iter().skip(1).any(|line| SMTP_STARTTLS.is_match(line)))
            }
            Mail::Imap => {
                if let Some(offered) = self.greeting_offers {
                    return Ok(offered);
                }
                let tag = self.tag();
                reader.write_line(&format!("{tag} CAPABILITY")).await?;
                let (status, untagged) = imap_answer(reader, &tag).await?;
                if status != "OK" {
                    return Err(problem(format!("The server answered CAPABILITY with {status}"), "IMAP_INVALID_ANSWER"));
                }
                Ok(untagged.iter().any(|line| offers_starttls(line)))
            }
        }
    }

    async fn start_tls(&mut self, reader: &mut LineReader) -> Result<(), Failure> {
        match self.mail {
            Mail::Smtp => {
                reader.write_line("STARTTLS").await?;
                let (code, _) = smtp_reply(reader).await?;
                if code != 220 {
                    return Err(problem(format!("The server refused STARTTLS with {code}"), "STARTTLS_FAILED"));
                }
            }
            Mail::Imap => {
                let tag = self.tag();
                reader.write_line(&format!("{tag} STARTTLS")).await?;
                let (status, _) = imap_answer(reader, &tag).await?;
                if status != "OK" {
                    return Err(problem(format!("The server refused STARTTLS with {status}"), "STARTTLS_FAILED"));
                }
            }
        }
        Ok(())
    }

    async fn goodbye(&mut self, reader: &mut LineReader) -> Result<(), Failure> {
        match self.mail {
            Mail::Smtp => {
                reader.write_line("QUIT").await?;
                smtp_reply(reader).await.map(|_| ())
            }
            Mail::Imap => {
                let tag = self.tag();
                reader.write_line(&format!("{tag} LOGOUT")).await?;
                imap_answer(reader, &tag).await.map(|_| ())
            }
        }
    }
}

struct Options {
    tls_mode: String,
    tls_verify: bool,
    require_starttls: bool,
}

async fn converse(mail: Mail, target: &Target, options: &Options, details: &mut Map<String, Value>) -> Result<(), Failure> {
    let plain = connect_plain(target).await?;
    let local = plain.local_addr().ok().map(|address| address.ip());
    let stream: Pin<Box<dyn Stream>> = if options.tls_mode == "TLS" {
        let tls = connect_tls(target, options.tls_verify, &[], plain).await?;
        tls_details(&tls, details);
        Box::pin(tls)
    } else {
        Box::pin(plain)
    };
    let mut reader = LineReader::new(stream);
    let mut dialogue = Dialogue { mail, tags: 0, greeting_offers: None, local };
    dialogue.greet(&mut reader, details).await?;
    let offered = dialogue.capabilities(&mut reader).await?;
    details.insert("startTLSOffered".into(), Value::Bool(offered));
    if options.tls_mode == "STARTTLS" {
        if !offered {
            return Err(problem(format!("The {} server does not offer STARTTLS", mail.name()), "STARTTLS_NOT_OFFERED"));
        }
        dialogue.start_tls(&mut reader).await?;
        // Bytes that came with the STARTTLS answer would be read as if they came over TLS (CVE-2011-0411).
        if reader.pending() {
            return Err(problem("The server sent more after its STARTTLS answer", "STARTTLS_FAILED"));
        }
        let secure = connect_tls(target, options.tls_verify, &[], reader.into_inner()).await?;
        tls_details(&secure, details);
        reader = LineReader::new(Box::pin(secure));
    }
    // A server that does not answer QUIT or LOGOUT politely has still passed the check.
    let _ = dialogue.goodbye(&mut reader).await;
    if options.tls_mode == "NONE" && options.require_starttls && !offered {
        return Err(problem(format!("The {} server does not offer STARTTLS", mail.name()), "STARTTLS_NOT_OFFERED"));
    }
    Ok(())
}

async fn mail_check(mail: Mail, request: &Map<String, Value>) -> Value {
    let start = Instant::now();
    let host = request.get("host").cloned().unwrap_or(Value::Null);
    let port_value = request.get("port").cloned().unwrap_or(Value::Null);
    let options = Options {
        tls_mode: string_field(request, "tlsMode").unwrap_or_else(|| "NONE".to_string()),
        tls_verify: bool_field(request, "tlsVerify").unwrap_or(true),
        require_starttls: bool_field(request, "requireStartTLS").unwrap_or(false),
    };
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
    if !["NONE", "STARTTLS", "TLS"].contains(&options.tls_mode.as_str()) {
        return answer("error", Some(("tlsMode must be NONE, STARTTLS or TLS".into(), "INVALID_REQUEST".into())), &details, Some(0));
    }
    if options.require_starttls && options.tls_mode == "TLS" {
        return answer("error", Some(("requireStartTLS needs tlsMode NONE or STARTTLS".into(), "INVALID_REQUEST".into())), &details, Some(0));
    }
    let host_text = host.as_str().unwrap_or("").to_string();
    let outcome = with_deadline(timeout, async {
        let address = resolve_allowed(&host_text, family_of(request.get("ipVersion"))).await?[0];
        let target = Target { host: host_text.clone(), address, port: port_of(request) };
        converse(mail, &target, &options, &mut details).await
    })
    .await;
    match outcome {
        Ok(()) => answer("up", None, &details, None),
        Err(failure) => answer("down", Some(failure_of(&failure)), &details, None),
    }
}

/// `/check/smtp` and the agent's `smtp` job. Never fails.
pub async fn smtp_check(request: &Map<String, Value>) -> Value {
    mail_check(Mail::Smtp, request).await
}

/// `/check/imap` and the agent's `imap` job. Never fails.
pub async fn imap_check(request: &Map<String, Value>) -> Value {
    mail_check(Mail::Imap, request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_the_client_by_its_address() {
        assert_eq!(address_literal(Some("::ffff:10.0.0.5".parse().unwrap())), "[10.0.0.5]");
        assert_eq!(address_literal(Some("2001:db8::1".parse().unwrap())), "[IPv6:2001:db8::1]");
        assert_eq!(address_literal(None), "[127.0.0.1]");
    }

    #[test]
    fn reads_starttls_from_imap_capabilities() {
        assert!(offers_starttls("* OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN] ready"));
        assert!(offers_starttls("* CAPABILITY IMAP4rev1 STARTTLS"));
        assert!(!offers_starttls("* CAPABILITY IMAP4rev1 LOGINDISABLED"));
    }
}
