//! The asciicast v2 writer of the core (ADR-0016).
//!
//! The output is deterministic: the same events give the same bytes, hence
//! the same SHA-256, computed as the file is written.
//!
//! - Header, keys in this order: `version` (2), `width`, `height`
//!   (80 × 24 without a terminal), `timestamp` (Unix seconds),
//!   `command` (an `exec` only), `title` (`ostena <session>`), `env`
//!   (`TERM`, with a terminal only).
//! - Events: `[t, "o", text]` for output, `[t, "r", "COLSxROWS"]` for a
//!   window change; `t` in seconds with six decimals.
//! - Output is decoded as UTF-8 across events: an incomplete sequence at
//!   the end of an event waits for the next one; each invalid sequence
//!   becomes U+FFFD and is counted. Nothing is written for an event that
//!   only holds the start of a sequence.
//! - Strings are escaped so that the file holds no control character but
//!   the line feeds between lines: C0, DEL and C1 are written `\uXXXX`
//!   (escape sequences of the session included), and so are the
//!   bidirectional format characters (U+061C, U+200E, U+200F, U+202A to
//!   U+202E, U+2066 to U+2069), which could make the command or the output
//!   read differently from what they are. The file can be shown safely; a
//!   player renders the session. A player that replays it in a real
//!   terminal runs the escape sequences of the session in that terminal,
//!   as the session did: replay untrusted transcripts in an isolated
//!   player.

use std::io::Write;

use ostena_crypto::sha256::Hasher;

use crate::error::RecorderError;
use crate::event::{Event, Frame};

/// Size of a window when the session has no terminal.
pub const DEFAULT_SIZE: (u16, u16) = (80, 24);

/// What seals a finished transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    /// SHA-256 of the file.
    pub sha256: [u8; 32],
    /// Its size, bytes.
    pub size: u64,
    /// Lines written after the header.
    pub events: u64,
    /// Invalid UTF-8 sequences replaced by U+FFFD.
    pub invalid_utf8: u64,
}

/// Writes a transcript as asciicast v2 into `W`, hashing what it writes.
pub struct CastWriter<W: Write> {
    inner: W,
    session: [u8; 16],
    hasher: Hasher,
    events: u64,
    invalid_utf8: u64,
    /// Start of a UTF-8 sequence waiting for its end (at most 3 bytes).
    carry: Vec<u8>,
    started: bool,
    last_at: u64,
    line: String,
}

fn format_uuid(b: &[u8; 16]) -> String {
    let mut s = String::with_capacity(36);
    for (i, byte) in b.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        s.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        s.push(char::from(b"0123456789abcdef"[usize::from(byte & 0xf)]));
    }
    s
}

/// A bidirectional format character: shown as is, it reorders the text
/// around it.
pub(crate) fn is_bidi_format(c: char) -> bool {
    matches!(
        c,
        '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
    )
}

fn push_escaped(out: &mut String, c: char) {
    let v = u32::from(c);
    out.push_str("\\u");
    for shift in [12, 8, 4, 0] {
        out.push(char::from(b"0123456789abcdef"[(v >> shift) as usize & 0xf]));
    }
}

/// Appends `text` as a JSON string.
fn push_json_str(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // C0, DEL and C1, and the bidirectional format characters: all
            // in the basic plane, so four hex digits.
            c if c.is_control() || is_bidi_format(c) => push_escaped(out, c),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn push_time(out: &mut String, at_us: u64) {
    use std::fmt::Write as _;
    let _ = write!(out, "{}.{:06}", at_us / 1_000_000, at_us % 1_000_000);
}

/// Decodes `bytes` as UTF-8 into `out`, U+FFFD for each invalid sequence;
/// returns the number replaced and the incomplete tail, if `keep_tail`.
fn decode_lossy(bytes: &[u8], out: &mut String, keep_tail: bool) -> (u64, Vec<u8>) {
    let mut rest = bytes;
    let mut invalid = 0;
    loop {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                out.push_str(s);
                return (invalid, Vec::new());
            }
            Err(e) => {
                let (valid, after) = rest.split_at(e.valid_up_to());
                // `valid` is valid UTF-8 by construction.
                out.push_str(std::str::from_utf8(valid).unwrap_or_default());
                match e.error_len() {
                    Some(n) => {
                        out.push(char::REPLACEMENT_CHARACTER);
                        invalid += 1;
                        rest = &after[n..];
                    }
                    None if keep_tail => return (invalid, after.to_vec()),
                    None => {
                        out.push(char::REPLACEMENT_CHARACTER);
                        return (invalid + 1, Vec::new());
                    }
                }
            }
        }
    }
}

impl<W: Write> CastWriter<W> {
    /// A writer for session `session`; nothing is written before the start
    /// event.
    pub fn new(inner: W, session: [u8; 16]) -> Self {
        Self {
            inner,
            session,
            hasher: Hasher::new(),
            events: 0,
            invalid_utf8: 0,
            carry: Vec::new(),
            started: false,
            last_at: 0,
            line: String::new(),
        }
    }

    fn emit(&mut self) -> Result<(), RecorderError> {
        self.line.push('\n');
        self.inner
            .write_all(self.line.as_bytes())
            .map_err(|e| RecorderError::Io(e.to_string()))?;
        self.hasher.update(self.line.as_bytes());
        self.line.clear();
        Ok(())
    }

    fn output_line(&mut self, at_us: u64, text: &str) -> Result<(), RecorderError> {
        if text.is_empty() {
            return Ok(());
        }
        self.line.push('[');
        push_time(&mut self.line, at_us);
        self.line.push_str(",\"o\",");
        push_json_str(&mut self.line, text);
        self.line.push(']');
        self.events += 1;
        self.emit()
    }

    /// Writes one event, decoded and checked by [`crate::Decoder`].
    ///
    /// # Errors
    ///
    /// [`RecorderError::Io`]; [`RecorderError::Malformed`] for an event
    /// before the start or a second start.
    pub fn push(&mut self, frame: &Frame) -> Result<(), RecorderError> {
        use std::fmt::Write as _;
        self.last_at = self.last_at.max(frame.at_us);
        match &frame.event {
            Event::Start {
                cols,
                rows,
                started_ms,
                term,
                command,
            } => {
                if self.started {
                    return Err(RecorderError::Malformed("deuxième début"));
                }
                self.started = true;
                let (w, h) = if term.is_empty() {
                    DEFAULT_SIZE
                } else {
                    (*cols, *rows)
                };
                let _ = write!(
                    self.line,
                    "{{\"version\":2,\"width\":{w},\"height\":{h},\"timestamp\":{}",
                    started_ms / 1000
                );
                if let Some(command) = command {
                    let mut text = String::new();
                    let (invalid, _) = decode_lossy(command, &mut text, false);
                    self.invalid_utf8 += invalid;
                    self.line.push_str(",\"command\":");
                    push_json_str(&mut self.line, &text);
                }
                let _ = write!(
                    self.line,
                    ",\"title\":\"ostena {}\"",
                    format_uuid(&self.session)
                );
                if !term.is_empty() {
                    // Printable ASCII, escaped all the same (quote,
                    // backslash).
                    self.line.push_str(",\"env\":{\"TERM\":");
                    push_json_str(&mut self.line, term);
                    self.line.push('}');
                }
                self.line.push('}');
                self.emit()
            }
            _ if !self.started => Err(RecorderError::Malformed("pas de début")),
            Event::Output(data) => {
                let mut bytes = std::mem::take(&mut self.carry);
                bytes.extend_from_slice(data);
                let mut text = String::with_capacity(bytes.len());
                let (invalid, tail) = decode_lossy(&bytes, &mut text, true);
                self.invalid_utf8 += invalid;
                self.carry = tail;
                self.output_line(frame.at_us, &text)
            }
            Event::Resize { cols, rows } => {
                self.line.push('[');
                push_time(&mut self.line, frame.at_us);
                let _ = write!(self.line, ",\"r\",\"{cols}x{rows}\"]");
                self.events += 1;
                self.emit()
            }
            Event::End { .. } => self.flush_carry(frame.at_us),
        }
    }

    fn flush_carry(&mut self, at_us: u64) -> Result<(), RecorderError> {
        if self.carry.is_empty() {
            return Ok(());
        }
        let bytes = std::mem::take(&mut self.carry);
        let mut text = String::new();
        let (invalid, _) = decode_lossy(&bytes, &mut text, false);
        self.invalid_utf8 += invalid;
        self.output_line(at_us, &text)
    }

    /// Bytes written so far and their SHA-256 (a checkpoint).
    pub fn checkpoint(&self) -> (u64, [u8; 32]) {
        (self.hasher.len(), self.hasher.digest())
    }

    /// Flushes the inner writer (before syncing it to disk).
    ///
    /// # Errors
    ///
    /// [`RecorderError::Io`].
    pub fn flush(&mut self) -> Result<(), RecorderError> {
        self.inner
            .flush()
            .map_err(|e| RecorderError::Io(e.to_string()))
    }

    /// Ends the file, complete or not: a sequence still waiting becomes
    /// U+FFFD, at the time of the last event. Returns the seal and the
    /// inner writer.
    ///
    /// # Errors
    ///
    /// [`RecorderError::Io`].
    pub fn finish(mut self) -> Result<(Sealed, W), RecorderError> {
        self.flush_carry(self.last_at)?;
        self.flush()?;
        let sealed = Sealed {
            size: self.hasher.len(),
            sha256: self.hasher.finish(),
            events: self.events,
            invalid_utf8: self.invalid_utf8,
        };
        Ok((sealed, self.inner))
    }
}

#[cfg(test)]
mod tests;
