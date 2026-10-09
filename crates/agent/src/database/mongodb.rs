//! MongoDB: OP_MSG over our own plain or TLS stream, SCRAM-SHA-256 or SCRAM-SHA-1 when the job has a user, then
//! `ping` on `admin`. Only the few BSON types these commands use are read and written.
use std::time::Instant;

use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::Digest;
use statustick_checks::connection::Stream;

use super::{DriverError, Target, open_stream, read_exact, write_all};

const OP_MSG: i32 = 2013;
const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

pub struct Session {
    stream: Box<dyn Stream>,
    request_id: i32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Bson {
    Double(f64),
    Text(String),
    Document(Vec<(String, Bson)>),
    Array(Vec<Bson>),
    Binary(Vec<u8>),
    Bool(bool),
    Null,
    Int32(i32),
    Int64(i64),
    Other,
}

impl Bson {
    fn get(&self, name: &str) -> Option<&Bson> {
        match self {
            Bson::Document(fields) => fields.iter().find(|(key, _)| key == name).map(|(_, value)| value),
            _ => None,
        }
    }

    fn number(&self) -> Option<f64> {
        match self {
            Bson::Double(value) => Some(*value),
            Bson::Int32(value) => Some(*value as f64),
            Bson::Int64(value) => Some(*value as f64),
            Bson::Bool(flag) => Some(f64::from(u8::from(*flag))),
            _ => None,
        }
    }

    fn text(&self) -> Option<&str> {
        match self {
            Bson::Text(text) => Some(text),
            _ => None,
        }
    }
}

fn write_cstring(out: &mut Vec<u8>, text: &str) {
    out.extend_from_slice(text.as_bytes());
    out.push(0);
}

fn encode_fields(fields: &[(String, Bson)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (key, value) in fields {
        let (kind, bytes): (u8, Vec<u8>) = match value {
            Bson::Double(number) => (0x01, number.to_le_bytes().to_vec()),
            Bson::Text(text) => {
                let mut bytes = ((text.len() + 1) as i32).to_le_bytes().to_vec();
                write_cstring(&mut bytes, text);
                (0x02, bytes)
            }
            Bson::Document(inner) => (0x03, encode_fields(inner)),
            Bson::Array(items) => (0x04, encode_fields(&items.iter().enumerate().map(|(index, item)| (index.to_string(), item.clone())).collect::<Vec<_>>())),
            Bson::Binary(data) => {
                let mut bytes = (data.len() as i32).to_le_bytes().to_vec();
                bytes.push(0);
                bytes.extend_from_slice(data);
                (0x05, bytes)
            }
            Bson::Bool(flag) => (0x08, vec![u8::from(*flag)]),
            Bson::Null | Bson::Other => (0x0A, Vec::new()),
            Bson::Int32(number) => (0x10, number.to_le_bytes().to_vec()),
            Bson::Int64(number) => (0x12, number.to_le_bytes().to_vec()),
        };
        body.push(kind);
        write_cstring(&mut body, key);
        body.extend_from_slice(&bytes);
    }
    let mut document = ((body.len() + 5) as i32).to_le_bytes().to_vec();
    document.extend_from_slice(&body);
    document.push(0);
    document
}

pub fn encode(document: &Bson) -> Vec<u8> {
    match document {
        Bson::Document(fields) => encode_fields(fields),
        _ => encode_fields(&[]),
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn take(&mut self, count: usize) -> Option<&[u8]> {
        let slice = self.bytes.get(self.at..self.at + count)?;
        self.at += count;
        Some(slice)
    }

    fn i32(&mut self) -> Option<i32> {
        Some(i32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn cstring(&mut self) -> Option<String> {
        let end = self.bytes.get(self.at..)?.iter().position(|byte| *byte == 0)?;
        let text = String::from_utf8_lossy(&self.bytes[self.at..self.at + end]).into_owned();
        self.at += end + 1;
        Some(text)
    }

    fn document(&mut self) -> Option<Vec<(String, Bson)>> {
        let length = self.i32()? as usize;
        let end = self.at + length.checked_sub(4)?;
        let mut fields = Vec::new();
        while self.at < end - 1 {
            let kind = *self.take(1)?.first()?;
            let key = self.cstring()?;
            let value = match kind {
                0x01 => Bson::Double(f64::from_le_bytes(self.take(8)?.try_into().ok()?)),
                0x02 | 0x0D | 0x0E => {
                    let size = self.i32()? as usize;
                    let bytes = self.take(size)?;
                    Bson::Text(String::from_utf8_lossy(&bytes[..size.saturating_sub(1)]).into_owned())
                }
                0x03 => Bson::Document(self.document()?),
                0x04 => Bson::Array(self.document()?.into_iter().map(|(_, value)| value).collect()),
                0x05 => {
                    let size = self.i32()? as usize;
                    self.take(1)?;
                    Bson::Binary(self.take(size)?.to_vec())
                }
                0x07 => {
                    self.take(12)?;
                    Bson::Other
                }
                0x08 => Bson::Bool(*self.take(1)?.first()? != 0),
                0x09 | 0x11 => {
                    self.take(8)?;
                    Bson::Other
                }
                0x0A | 0x06 | 0xFF | 0x7F => Bson::Null,
                0x10 => Bson::Int32(self.i32()?),
                0x12 => Bson::Int64(i64::from_le_bytes(self.take(8)?.try_into().ok()?)),
                0x13 => {
                    self.take(16)?;
                    Bson::Other
                }
                _ => return None,
            };
            fields.push((key, value));
        }
        self.take(1)?;
        Some(fields)
    }
}

pub fn decode(bytes: &[u8]) -> Option<Bson> {
    Reader { bytes, at: 0 }.document().map(Bson::Document)
}

fn invalid() -> DriverError {
    DriverError::new("The MongoDB answer is not valid", None)
}

fn doc(fields: Vec<(&str, Bson)>) -> Bson {
    Bson::Document(fields.into_iter().map(|(key, value)| (key.to_string(), value)).collect())
}

impl Session {
    /// Sends one command and returns its answer; `ok: 0` fails with the server's message and code.
    async fn command(&mut self, command: Bson) -> Result<Bson, DriverError> {
        self.request_id += 1;
        let body = encode(&command);
        let mut message = Vec::with_capacity(body.len() + 21);
        message.extend_from_slice(&((body.len() + 21) as i32).to_le_bytes());
        message.extend_from_slice(&self.request_id.to_le_bytes());
        message.extend_from_slice(&0i32.to_le_bytes());
        message.extend_from_slice(&OP_MSG.to_le_bytes());
        message.extend_from_slice(&0u32.to_le_bytes());
        message.push(0);
        message.extend_from_slice(&body);
        write_all(&mut self.stream, &message).await?;

        let mut header = [0u8; 16];
        read_exact(&mut self.stream, &mut header).await?;
        let length = i32::from_le_bytes(header[..4].try_into().map_err(|_| invalid())?) as usize;
        let opcode = i32::from_le_bytes(header[12..16].try_into().map_err(|_| invalid())?);
        if !(21..=MAX_MESSAGE_BYTES).contains(&length) || opcode != OP_MSG {
            return Err(invalid());
        }
        let mut rest = vec![0u8; length - 16];
        read_exact(&mut self.stream, &mut rest).await?;
        if rest.get(4) != Some(&0) {
            return Err(invalid());
        }
        let answer = decode(&rest[5..]).ok_or_else(invalid)?;
        if answer.get("ok").and_then(Bson::number) != Some(1.0) {
            let message = answer.get("errmsg").and_then(Bson::text).unwrap_or("MongoDB refused the command").to_string();
            let code = answer.get("code").and_then(Bson::number).map(|code| (code as i64).to_string());
            return Err(DriverError::new(message, code.as_deref()));
        }
        Ok(answer)
    }

    pub async fn run(&mut self) -> Result<Value, DriverError> {
        let answer = self.command(doc(vec![("ping", Bson::Int32(1)), ("$db", Bson::Text("admin".into()))])).await?;
        Ok(answer.get("ok").and_then(Bson::number).map(Value::from).unwrap_or(Value::Null))
    }
}

/// SASLprep is left out: user names and passwords with only printable ASCII pass through it unchanged.
fn sasl_name(user: &str) -> String {
    user.replace('=', "=3D").replace(',', "=2C")
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(key).expect("any key size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<sha1::Sha1> as KeyInit>::new_from_slice(key).expect("any key size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

enum Mechanism {
    Sha256,
    Sha1,
}

fn salted_password(mechanism: &Mechanism, password: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    match mechanism {
        Mechanism::Sha256 => {
            let mut out = [0u8; 32];
            pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, iterations, &mut out);
            out.to_vec()
        }
        Mechanism::Sha1 => {
            let mut out = [0u8; 20];
            pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, salt, iterations, &mut out);
            out.to_vec()
        }
    }
}

fn mac(mechanism: &Mechanism, key: &[u8], data: &[u8]) -> Vec<u8> {
    match mechanism {
        Mechanism::Sha256 => hmac_sha256(key, data),
        Mechanism::Sha1 => hmac_sha1(key, data),
    }
}

fn hash(mechanism: &Mechanism, data: &[u8]) -> Vec<u8> {
    match mechanism {
        Mechanism::Sha256 => sha2::Sha256::digest(data).to_vec(),
        Mechanism::Sha1 => sha1::Sha1::digest(data).to_vec(),
    }
}

fn attribute(message: &str, name: char) -> Option<&str> {
    message.split(',').find_map(|part| part.strip_prefix(name).and_then(|rest| rest.strip_prefix('=')))
}

async fn authenticate(session: &mut Session, user: &str, password: &str, source: &str) -> Result<(), DriverError> {
    let hello = session
        .command(doc(vec![("hello", Bson::Int32(1)), ("saslSupportedMechs", Bson::Text(format!("{source}.{user}"))), ("$db", Bson::Text("admin".into()))]))
        .await?;
    let offers_sha256 = match hello.get("saslSupportedMechs") {
        Some(Bson::Array(mechanisms)) => mechanisms.iter().any(|mechanism| mechanism.text() == Some("SCRAM-SHA-256")),
        _ => true,
    };
    let (mechanism, name, secret) = if offers_sha256 {
        (Mechanism::Sha256, "SCRAM-SHA-256", password.to_string())
    } else {
        (Mechanism::Sha1, "SCRAM-SHA-1", hex::encode(md5::Md5::digest(format!("{user}:mongo:{password}").as_bytes())))
    };
    let nonce = base64::engine::general_purpose::STANDARD.encode(rand::random::<[u8; 24]>());
    let first_bare = format!("n={},r={nonce}", sasl_name(user));
    let start = session
        .command(doc(vec![
            ("saslStart", Bson::Int32(1)),
            ("mechanism", Bson::Text(name.into())),
            ("payload", Bson::Binary(format!("n,,{first_bare}").into_bytes())),
            ("autoAuthorize", Bson::Int32(1)),
            ("options", doc(vec![("skipEmptyExchange", Bson::Bool(true))])),
            ("$db", Bson::Text(source.into())),
        ]))
        .await?;
    let conversation = start.get("conversationId").cloned().unwrap_or(Bson::Int32(1));
    let Some(Bson::Binary(server_first)) = start.get("payload") else { return Err(invalid()) };
    let server_first = String::from_utf8_lossy(server_first).into_owned();
    let combined = attribute(&server_first, 'r').filter(|combined| combined.starts_with(&nonce)).ok_or_else(invalid)?;
    let salt = attribute(&server_first, 's').and_then(|salt| base64::engine::general_purpose::STANDARD.decode(salt).ok()).ok_or_else(invalid)?;
    let iterations: u32 = attribute(&server_first, 'i').and_then(|count| count.parse().ok()).filter(|count| *count >= 4096).ok_or_else(invalid)?;

    let salted = salted_password(&mechanism, secret.as_bytes(), &salt, iterations);
    let client_key = mac(&mechanism, &salted, b"Client Key");
    let stored_key = hash(&mechanism, &client_key);
    let without_proof = format!("c=biws,r={combined}");
    let auth_message = format!("{first_bare},{server_first},{without_proof}");
    let signature = mac(&mechanism, &stored_key, auth_message.as_bytes());
    let proof: Vec<u8> = client_key.iter().zip(&signature).map(|(a, b)| a ^ b).collect();
    let client_final = format!("{without_proof},p={}", base64::engine::general_purpose::STANDARD.encode(proof));
    let mut answer = session
        .command(doc(vec![
            ("saslContinue", Bson::Int32(1)),
            ("conversationId", conversation.clone()),
            ("payload", Bson::Binary(client_final.into_bytes())),
            ("$db", Bson::Text(source.into())),
        ]))
        .await?;
    let server_key = mac(&mechanism, &salted, b"Server Key");
    let expected = base64::engine::general_purpose::STANDARD.encode(mac(&mechanism, &server_key, auth_message.as_bytes()));
    let Some(Bson::Binary(server_final)) = answer.get("payload") else { return Err(invalid()) };
    if attribute(&String::from_utf8_lossy(server_final), 'v') != Some(expected.as_str()) {
        return Err(DriverError::new("The MongoDB server's signature is not valid", None));
    }
    while answer.get("done") != Some(&Bson::Bool(true)) {
        answer = session
            .command(doc(vec![
                ("saslContinue", Bson::Int32(1)),
                ("conversationId", conversation.clone()),
                ("payload", Bson::Binary(Vec::new())),
                ("$db", Bson::Text(source.into())),
            ]))
            .await?;
    }
    Ok(())
}

pub async fn open(target: &Target, connected: &mut Option<Instant>) -> Result<Session, DriverError> {
    let stream = open_stream(target).await?;
    *connected = Some(Instant::now());
    let mut session = Session { stream, request_id: 0 };
    if let Some(user) = &target.user {
        let source = target.database.clone().unwrap_or_else(|| "admin".to_string());
        authenticate(&mut session, user, target.password.as_deref().unwrap_or(""), &source).await?;
    }
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_and_reads_bson_documents() {
        let document = doc(vec![
            ("ping", Bson::Int32(1)),
            ("$db", Bson::Text("admin".into())),
            ("payload", Bson::Binary(vec![1, 2])),
            ("options", doc(vec![("skip", Bson::Bool(true))])),
            ("list", Bson::Array(vec![Bson::Double(1.5)])),
        ]);
        assert_eq!(decode(&encode(&document)), Some(document));
        assert_eq!(&encode(&doc(vec![("a", Bson::Int32(1))]))[..], &[12, 0, 0, 0, 0x10, b'a', 0, 1, 0, 0, 0, 0]);
    }

    #[test]
    fn computes_the_scram_sha_256_proof_of_rfc_7677() {
        let salt = base64::engine::general_purpose::STANDARD.decode("W22ZaJ0SNY7soEsUEjb6gQ==").unwrap();
        let salted = salted_password(&Mechanism::Sha256, b"pencil", &salt, 4096);
        let client_key = mac(&Mechanism::Sha256, &salted, b"Client Key");
        let stored = hash(&Mechanism::Sha256, &client_key);
        let auth = "n=user,r=rOprNGfwEbeRWgbNEkqO,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
        let signature = mac(&Mechanism::Sha256, &stored, auth.as_bytes());
        let proof: Vec<u8> = client_key.iter().zip(&signature).map(|(a, b)| a ^ b).collect();
        assert_eq!(base64::engine::general_purpose::STANDARD.encode(proof), "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=");
    }
}
