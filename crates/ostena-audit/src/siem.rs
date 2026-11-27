//! Export of the chain to a SIEM (ADR-0012, « Export syslog TLS en OCSF »):
//! each record becomes an OCSF event (JSON), carried in an RFC 5424 syslog
//! message, framed by octet counting as RFC 5425 (syslog over TLS) says.
//!
//! - [`ocsf`] — the OCSF event of a record (Base Event class, every field
//!   of the record kept under `unmapped`);
//! - [`message`] — the RFC 5424 message: facility 13 (log audit), severity
//!   from the outcome, the time of the record, `MSGID` `audit`, the JSON
//!   as `MSG`. The JSON is plain ASCII (every other character escaped), so
//!   the message needs no byte order mark;
//! - [`frame`] and [`FrameDecoder`] — the octet-counting framing, written
//!   and read back strictly;
//! - [`parse_message`] — a strict reader of RFC 5424 headers, for the tests
//!   and for whoever checks what a collector received.
//!
//! The transport (TLS 1.3 through `ostena-crypto`) is the core's.

use std::fmt::Write as _;

use crate::record::{ActorKind, Outcome, Record, Value};

/// The OCSF schema version written in `metadata.version`.
pub const OCSF_VERSION: &str = "1.3.0";

/// Facility `log audit` (RFC 5424, section 6.2.1).
pub const FACILITY: u8 = 13;

/// The largest message read back by [`FrameDecoder`], and the largest
/// [`message`] can write: a record of 8 KiB whose binary fields are written
/// in hexadecimal stays below.
pub const MAX_MESSAGE: usize = 64 * 1024;

/// The longest `HOSTNAME` (RFC 5424, section 6.2.4).
const MAX_HOSTNAME: usize = 255;

/// Why a frame or a message is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SiemError {
    /// The octet count is malformed or too large.
    #[error("[AUD-E022] trame syslog invalide : {0}")]
    Frame(&'static str),
    /// The RFC 5424 header is malformed.
    #[error("[AUD-E022] message syslog invalide : {0}")]
    Message(&'static str),
}

/// The OCSF severity, syslog severity and status of an outcome.
const fn levels(outcome: Outcome) -> (u8, u8, &'static str) {
    match outcome {
        // Informational / informational.
        Outcome::Success => (1, 6, "Success"),
        // Medium / notice.
        Outcome::Refused => (3, 5, "Failure"),
        // High / warning.
        Outcome::Failure => (4, 4, "Failure"),
    }
}

/// The OCSF `type_id` and name of an actor kind (`actor.user.type_id`).
const fn user_type(kind: ActorKind) -> (u8, &'static str) {
    match kind {
        ActorKind::User => (1, "User"),
        ActorKind::Admin => (2, "Admin"),
        ActorKind::Core => (3, "System"),
        ActorKind::Agent => (99, "Agent"),
        ActorKind::Peer => (99, "Peer"),
    }
}

const fn outcome_name(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Success => "success",
        Outcome::Refused => "refused",
        Outcome::Failure => "failure",
    }
}

/// `text` as a JSON string, ASCII only.
fn json_string(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ' '..='~' => out.push(c),
            _ => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out.push('"');
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn uuid_text(bytes: &[u8; 16]) -> String {
    let mut s = String::with_capacity(36);
    for (i, b) in bytes.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The OCSF event of `record` (JSON, one line, ASCII), written by the
/// product at `version`.
///
/// Class Base Event (`class_uid` 0, category 0), activity Other (99). The
/// event name is `metadata.event_code` and `message`; `metadata.uid` is
/// `<chain>:<seq>`, unique, so that a collector can drop a record sent
/// twice; every field of the record is kept under `unmapped`, binary
/// values in hexadecimal.
pub fn ocsf(record: &Record, version: &str) -> String {
    let (severity_id, _, status) = levels(record.outcome);
    let (user_type_id, user_type) = user_type(record.actor_kind);
    let mut out = String::with_capacity(512 + record.fields.len() * 64);
    out.push_str("{\"activity_id\":99,\"activity_name\":\"Other\",\"category_name\":\"Uncategorized\",\"category_uid\":0,\"class_name\":\"Base Event\",\"class_uid\":0");
    out.push_str(",\"message\":");
    json_string(&mut out, &record.event);
    out.push_str(",\"metadata\":{\"correlation_uid\":");
    json_string(&mut out, &record.chain_id.to_string());
    out.push_str(",\"event_code\":");
    json_string(&mut out, &record.event);
    out.push_str(",\"log_name\":\"audit\",\"product\":{\"name\":\"Ostena\",\"vendor_name\":\"Ostena\",\"version\":");
    json_string(&mut out, version);
    let _ = write!(
        out,
        "}},\"sequence\":{},\"uid\":\"{}:{}\",\"version\":\"{OCSF_VERSION}\"}}",
        record.seq, record.chain_id, record.seq
    );
    let _ = write!(
        out,
        ",\"severity_id\":{severity_id},\"status\":\"{status}\",\"status_detail\":\"{}\",\"status_id\":{}",
        outcome_name(record.outcome),
        if record.outcome == Outcome::Success {
            1
        } else {
            2
        }
    );
    let _ = write!(
        out,
        ",\"time\":{},\"type_name\":\"Base Event: Other\",\"type_uid\":99",
        record.time_ms
    );
    out.push_str(",\"actor\":{\"user\":{\"name\":");
    json_string(&mut out, &record.actor);
    let _ = write!(
        out,
        ",\"type\":\"{user_type}\",\"type_id\":{user_type_id}}}}}"
    );
    out.push_str(",\"unmapped\":{");
    for (i, field) in record.fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        json_string(&mut out, &field.name);
        out.push(':');
        match &field.value {
            Value::Text(t) => json_string(&mut out, t),
            Value::U64(n) => {
                let _ = write!(out, "{n}");
            }
            Value::Bytes(b) => {
                let _ = write!(out, "\"{}\"", hex(b));
            }
            Value::Uuid(u) => {
                let _ = write!(out, "\"{}\"", uuid_text(u));
            }
            Value::Bool(b) => {
                let _ = write!(out, "{b}");
            }
        }
    }
    out.push_str("}}");
    out
}

/// RFC 3339 time of Unix milliseconds, UTC, three decimals.
pub fn rfc3339_ms(ms: u64) -> String {
    let secs = ms / 1000;
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        ms % 1000
    )
}

/// Days since 1970-01-01 to a civil date (proleptic Gregorian).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    (y, m, d)
}

/// `name` as an RFC 5424 `HOSTNAME`: printable ASCII without space, at most
/// 255 characters; the nil value `-` if nothing is left.
pub fn hostname(name: &str) -> String {
    let clean: String = name
        .chars()
        .filter(char::is_ascii_graphic)
        .take(MAX_HOSTNAME)
        .collect();
    if clean.is_empty() { "-".into() } else { clean }
}

/// The RFC 5424 message of `record`, from `host` (see [`hostname`]):
/// `<PRI>1 TIMESTAMP HOSTNAME ostena - audit - JSON`.
pub fn message(record: &Record, host: &str, version: &str) -> Vec<u8> {
    let (_, severity, _) = levels(record.outcome);
    let pri = u16::from(FACILITY) * 8 + u16::from(severity);
    format!(
        "<{pri}>1 {} {} ostena - audit - {}",
        rfc3339_ms(record.time_ms),
        hostname(host),
        ocsf(record, version)
    )
    .into_bytes()
}

/// `message` framed by octet counting (RFC 5425, section 4.3):
/// `MSG-LEN SP SYSLOG-MSG`.
pub fn frame(message: &[u8]) -> Vec<u8> {
    let mut out = format!("{} ", message.len()).into_bytes();
    out.extend_from_slice(message);
    out
}

/// Reads octet-counted frames from a byte stream, strictly: a length of
/// one to five digits without leading zero, at most [`MAX_MESSAGE`], one
/// space, then the message.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buffer: Vec<u8>,
}

impl FrameDecoder {
    /// An empty decoder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds bytes read from the stream.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Bytes received and not yet returned as a frame.
    pub fn pending(&self) -> usize {
        self.buffer.len()
    }

    /// The next whole message, `None` if more bytes are needed.
    ///
    /// # Errors
    ///
    /// [`SiemError::Frame`]: the stream cannot be resynchronised after it.
    pub fn next_message(&mut self) -> Result<Option<Vec<u8>>, SiemError> {
        let digits = self
            .buffer
            .iter()
            .take(6)
            .take_while(|b| b.is_ascii_digit())
            .count();
        match self.buffer.get(digits) {
            None if digits < 6 => return Ok(None),
            Some(b' ') if digits > 0 => {}
            _ => return Err(SiemError::Frame("longueur attendue, puis une espace")),
        }
        if self.buffer[0] == b'0' {
            return Err(SiemError::Frame("longueur nulle ou à zéro de tête"));
        }
        let mut length = 0usize;
        for b in &self.buffer[..digits] {
            length = length * 10 + usize::from(b - b'0');
        }
        if length > MAX_MESSAGE {
            return Err(SiemError::Frame("message trop long"));
        }
        let start = digits + 1;
        if self.buffer.len() < start + length {
            return Ok(None);
        }
        let message = self.buffer[start..start + length].to_vec();
        self.buffer.drain(..start + length);
        Ok(Some(message))
    }
}

/// The header of an RFC 5424 message, and its `MSG`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message<'a> {
    /// Facility (0 to 23).
    pub facility: u8,
    /// Severity (0 to 7).
    pub severity: u8,
    /// `TIMESTAMP`, as written (`-` for none).
    pub timestamp: &'a str,
    /// `HOSTNAME`.
    pub hostname: &'a str,
    /// `APP-NAME`.
    pub app_name: &'a str,
    /// `PROCID`.
    pub proc_id: &'a str,
    /// `MSGID`.
    pub msg_id: &'a str,
    /// `STRUCTURED-DATA`, as written (`-` for none).
    pub structured_data: &'a str,
    /// `MSG`, possibly empty.
    pub msg: &'a [u8],
}

/// One header field: printable ASCII up to the next space, at most `max`.
fn token<'a>(rest: &mut &'a [u8], max: usize, what: &'static str) -> Result<&'a str, SiemError> {
    let end = rest
        .iter()
        .position(|&b| b == b' ')
        .ok_or(SiemError::Message(what))?;
    let (field, tail) = rest.split_at(end);
    if field.is_empty() || field.len() > max || !field.iter().all(u8::is_ascii_graphic) {
        return Err(SiemError::Message(what));
    }
    *rest = &tail[1..];
    // Printable ASCII: valid UTF-8.
    std::str::from_utf8(field).map_err(|_| SiemError::Message(what))
}

/// Reads `STRUCTURED-DATA`: `-`, or elements `[id param="value"…]` with
/// `\"`, `\\` and `\]` escapes in values.
fn structured_data<'a>(rest: &mut &'a [u8]) -> Result<&'a str, SiemError> {
    let bad = SiemError::Message("STRUCTURED-DATA");
    let data = *rest;
    let mut i = 0;
    if data.first() == Some(&b'-') {
        i = 1;
    } else {
        while data.get(i) == Some(&b'[') {
            i += 1;
            let mut quoted = false;
            loop {
                let &b = data.get(i).ok_or(bad.clone())?;
                i += 1;
                match (quoted, b) {
                    (true, b'\\') => {
                        if !matches!(data.get(i), Some(b'"' | b'\\' | b']')) {
                            return Err(bad);
                        }
                        i += 1;
                    }
                    (_, b'"') => quoted = !quoted,
                    (false, b']') => break,
                    (false, b'[') => return Err(bad),
                    _ => {}
                }
            }
        }
        if i == 0 {
            return Err(bad);
        }
    }
    let (sd, tail) = data.split_at(i);
    match tail.first() {
        None => *rest = tail,
        Some(b' ') => *rest = &tail[1..],
        Some(_) => return Err(bad),
    }
    std::str::from_utf8(sd).map_err(|_| bad)
}

/// Reads the header of an RFC 5424 message (section 6), version 1.
///
/// # Errors
///
/// [`SiemError::Message`] naming the first part that breaks the grammar.
pub fn parse_message(message: &[u8]) -> Result<Message<'_>, SiemError> {
    let rest = message
        .strip_prefix(b"<")
        .ok_or(SiemError::Message("PRI"))?;
    let close = rest
        .iter()
        .take(4)
        .position(|&b| b == b'>')
        .ok_or(SiemError::Message("PRI"))?;
    let digits = &rest[..close];
    if digits.is_empty()
        || !digits.iter().all(u8::is_ascii_digit)
        || (digits.len() > 1 && digits[0] == b'0')
    {
        return Err(SiemError::Message("PRI"));
    }
    let pri = digits
        .iter()
        .fold(0u16, |n, b| n * 10 + u16::from(b - b'0'));
    if pri > 191 {
        return Err(SiemError::Message("PRI"));
    }
    let mut rest = rest[close + 1..]
        .strip_prefix(b"1 ")
        .ok_or(SiemError::Message("VERSION"))?;
    let timestamp = token(&mut rest, 32, "TIMESTAMP")?;
    let hostname = token(&mut rest, MAX_HOSTNAME, "HOSTNAME")?;
    let app_name = token(&mut rest, 48, "APP-NAME")?;
    let proc_id = token(&mut rest, 128, "PROCID")?;
    let msg_id = token(&mut rest, 32, "MSGID")?;
    let structured_data = structured_data(&mut rest)?;
    // Both bounded above: the casts cannot truncate.
    let facility = u8::try_from(pri / 8).map_err(|_| SiemError::Message("PRI"))?;
    let severity = u8::try_from(pri % 8).map_err(|_| SiemError::Message("PRI"))?;
    Ok(Message {
        facility,
        severity,
        timestamp,
        hostname,
        app_name,
        proc_id,
        msg_id,
        structured_data,
        msg: rest,
    })
}

#[cfg(test)]
mod tests;
