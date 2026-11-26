//! The agent-to-core transcript stream (ADR-0016).
//!
//! After the 18-byte channel header of the tunnel, the stream is a sequence
//! of frames, integers big-endian:
//!
//! | Size | Field |
//! |---|---|
//! | 1 | type: 1 start, 2 output, 3 resize, 4 end, 5 exit |
//! | 8 | time, microseconds since the start |
//! | 4 | payload length |
//! | n | payload |
//!
//! Payloads: start `cols u16 ‖ rows u16 ‖ started_ms u64 ‖ term_len u8 ‖
//! term ‖ has_command u8 (0 or 1) ‖ command` (the command runs to the end of
//! the payload); output: the bytes; resize `cols u16 ‖ rows u16`; end
//! `reason u8 ‖ output_bytes u64`; exit `1 ‖ status u32` or
//! `2 ‖ core_dumped u8 (0 or 1) ‖ signal name` (to the end of the payload).
//!
//! The decoder is strict: the start comes first, at time 0, and only once;
//! times never decrease; at most one exit, before the end; the end comes
//! last, with the exact count of output bytes; nothing follows it. Anything else is refused, so that
//! `encode(decode(b)) == b`.

use crate::error::RecorderError;
use crate::event::{EndReason, Event, Exit, Frame, MAX_COMMAND, MAX_OUTPUT, MAX_TERM};

/// Length of a frame header.
pub const FRAME_HEADER_LEN: usize = 13;
/// Largest payload: a start with the longest terminal type and command.
pub const MAX_PAYLOAD: usize = 14 + MAX_TERM + MAX_COMMAND;
/// Largest frame.
pub const MAX_FRAME_LEN: usize = FRAME_HEADER_LEN + MAX_PAYLOAD;

const START: u8 = 1;
const OUTPUT: u8 = 2;
const RESIZE: u8 = 3;
const END: u8 = 4;
const EXIT: u8 = 5;
const EXIT_STATUS: u8 = 1;
const EXIT_SIGNAL: u8 = 2;

/// Default largest transcript: 256 MiB of output.
pub const DEFAULT_MAX_OUTPUT_BYTES: u64 = 256 * 1024 * 1024;
/// Default longest transcript: 8 h 10 min, above the longest session (8 h).
pub const DEFAULT_MAX_DURATION_US: u64 = (8 * 3600 + 600) * 1_000_000;

/// The limits a receiver puts on one transcript (`REC-E003`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Most bytes of output.
    pub max_output_bytes: u64,
    /// Latest event time, microseconds.
    pub max_duration_us: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_duration_us: DEFAULT_MAX_DURATION_US,
        }
    }
}

fn len_u32(n: usize) -> Result<u32, RecorderError> {
    u32::try_from(n).map_err(|_| RecorderError::Malformed("charge trop longue"))
}

/// Appends the encoding of `frame` to `out`, after checking the bounds of
/// its event (not its place in the stream).
///
/// # Errors
///
/// [`RecorderError::Malformed`] for an event out of bounds; `out` is then
/// unchanged.
pub fn encode(frame: &Frame, out: &mut Vec<u8>) -> Result<(), RecorderError> {
    frame.event.check()?;
    let (kind, len) = match &frame.event {
        Event::Start { term, command, .. } => (
            START,
            14 + term.len() + command.as_ref().map_or(0, Vec::len),
        ),
        Event::Output(data) => (OUTPUT, data.len()),
        Event::Resize { .. } => (RESIZE, 4),
        Event::End { .. } => (END, 9),
        Event::Exit(Exit::Status(_)) => (EXIT, 5),
        Event::Exit(Exit::Signal { name, .. }) => (EXIT, 2 + name.len()),
    };
    let len32 = len_u32(len)?;
    out.reserve(FRAME_HEADER_LEN + len);
    out.push(kind);
    out.extend_from_slice(&frame.at_us.to_be_bytes());
    out.extend_from_slice(&len32.to_be_bytes());
    match &frame.event {
        Event::Start {
            cols,
            rows,
            started_ms,
            term,
            command,
        } => {
            out.extend_from_slice(&cols.to_be_bytes());
            out.extend_from_slice(&rows.to_be_bytes());
            out.extend_from_slice(&started_ms.to_be_bytes());
            // At most MAX_TERM (64) bytes, checked above.
            out.push(u8::try_from(term.len()).unwrap_or(u8::MAX));
            out.extend_from_slice(term.as_bytes());
            match command {
                Some(c) => {
                    out.push(1);
                    out.extend_from_slice(c);
                }
                None => out.push(0),
            }
        }
        Event::Output(data) => out.extend_from_slice(data),
        Event::Resize { cols, rows } => {
            out.extend_from_slice(&cols.to_be_bytes());
            out.extend_from_slice(&rows.to_be_bytes());
        }
        Event::End {
            reason,
            output_bytes,
        } => {
            out.push(*reason as u8);
            out.extend_from_slice(&output_bytes.to_be_bytes());
        }
        Event::Exit(Exit::Status(status)) => {
            out.push(EXIT_STATUS);
            out.extend_from_slice(&status.to_be_bytes());
        }
        Event::Exit(Exit::Signal { name, core_dumped }) => {
            out.push(EXIT_SIGNAL);
            out.push(u8::from(*core_dumped));
            out.extend_from_slice(name.as_bytes());
        }
    }
    Ok(())
}

/// Appends `data` as output frames of at most [`MAX_OUTPUT`] bytes each, all
/// at `at_us`. Nothing for empty data.
pub fn encode_output(at_us: u64, data: &[u8], out: &mut Vec<u8>) {
    for chunk in data.chunks(MAX_OUTPUT) {
        // Never fails: chunks are 1 to MAX_OUTPUT bytes.
        let _ = encode(
            &Frame {
                at_us,
                event: Event::Output(chunk.to_vec()),
            },
            out,
        );
    }
}

fn be_u16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

fn be_u64(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    u64::from_be_bytes(a)
}

fn decode_payload(kind: u8, p: &[u8]) -> Result<Event, RecorderError> {
    let event = match kind {
        START => {
            if p.len() < 14 {
                return Err(RecorderError::Malformed("début trop court"));
            }
            let term_len = usize::from(p[12]);
            let rest = &p[13..];
            if rest.len() < term_len + 1 {
                return Err(RecorderError::Malformed("début trop court"));
            }
            let term = std::str::from_utf8(&rest[..term_len])
                .map_err(|_| RecorderError::Malformed("type de terminal invalide"))?
                .to_owned();
            let command = match rest[term_len] {
                0 if rest.len() == term_len + 1 => None,
                0 => return Err(RecorderError::Malformed("octets après le début")),
                1 => Some(rest[term_len + 1..].to_vec()),
                _ => return Err(RecorderError::Malformed("indicateur de commande invalide")),
            };
            Event::Start {
                cols: be_u16(p),
                rows: be_u16(&p[2..]),
                started_ms: be_u64(&p[4..]),
                term,
                command,
            }
        }
        OUTPUT => Event::Output(p.to_vec()),
        RESIZE => {
            if p.len() != 4 {
                return Err(RecorderError::Malformed(
                    "changement de taille de longueur fausse",
                ));
            }
            Event::Resize {
                cols: be_u16(p),
                rows: be_u16(&p[2..]),
            }
        }
        END => {
            if p.len() != 9 {
                return Err(RecorderError::Malformed("fin de longueur fausse"));
            }
            Event::End {
                reason: EndReason::from_u8(p[0])
                    .ok_or(RecorderError::Malformed("raison de fin inconnue"))?,
                output_bytes: be_u64(&p[1..]),
            }
        }
        EXIT => Event::Exit(decode_exit(p)?),
        _ => return Err(RecorderError::Malformed("type de trame inconnu")),
    };
    event.check()?;
    Ok(event)
}

fn decode_exit(p: &[u8]) -> Result<Exit, RecorderError> {
    match p {
        [EXIT_STATUS, status @ ..] => <[u8; 4]>::try_from(status)
            .map(|s| Exit::Status(u32::from_be_bytes(s)))
            .map_err(|_| RecorderError::Malformed("fin de commande mal formée")),
        [EXIT_SIGNAL, core @ (0 | 1), name @ ..] => Ok(Exit::Signal {
            name: std::str::from_utf8(name)
                .map_err(|_| RecorderError::Malformed("nom de signal invalide"))?
                .to_owned(),
            core_dumped: *core == 1,
        }),
        _ => Err(RecorderError::Malformed("fin de commande mal formée")),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Fresh,
    Started,
    Ended,
    Failed,
}

/// Streaming decoder of a transcript stream. Feed it what is read, then take
/// frames until [`Decoder::next_frame`] gives `None`, before feeding more:
/// it then holds at most one incomplete frame ([`MAX_FRAME_LEN`]) beside
/// the last read.
#[derive(Debug)]
pub struct Decoder {
    buf: Vec<u8>,
    pos: usize,
    state: State,
    last_at: u64,
    output: u64,
    exited: bool,
    limits: Limits,
}

impl Decoder {
    /// A decoder enforcing `limits`.
    pub fn new(limits: Limits) -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
            state: State::Fresh,
            last_at: 0,
            output: 0,
            exited: false,
            limits,
        }
    }

    /// Adds bytes read from the stream.
    pub fn feed(&mut self, data: &[u8]) {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        self.buf.extend_from_slice(data);
    }

    /// Bytes of output decoded so far.
    pub fn output_bytes(&self) -> u64 {
        self.output
    }

    /// Bytes fed but not decoded yet: the start of a frame still
    /// incomplete.
    pub fn pending(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Whether the end frame was decoded.
    pub fn ended(&self) -> bool {
        self.state == State::Ended
    }

    fn fail(&mut self, e: RecorderError) -> RecorderError {
        self.state = State::Failed;
        e
    }

    /// The next complete frame, or `None` until more bytes are fed.
    ///
    /// # Errors
    ///
    /// [`RecorderError::Malformed`] or [`RecorderError::Limit`]; the decoder
    /// then refuses everything.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, RecorderError> {
        let available = self.buf.len() - self.pos;
        match self.state {
            State::Failed => return Err(RecorderError::Malformed("flux déjà refusé")),
            State::Ended if available > 0 => {
                return Err(self.fail(RecorderError::Malformed("octets après la fin")));
            }
            _ => {}
        }
        if available < FRAME_HEADER_LEN {
            return Ok(None);
        }
        let header = &self.buf[self.pos..self.pos + FRAME_HEADER_LEN];
        let kind = header[0];
        let at_us = be_u64(&header[1..]);
        let len = u32::from_be_bytes([header[9], header[10], header[11], header[12]]);
        let len = usize::try_from(len).unwrap_or(usize::MAX);
        if !(START..=EXIT).contains(&kind) {
            return Err(self.fail(RecorderError::Malformed("type de trame inconnu")));
        }
        if len > MAX_PAYLOAD {
            return Err(self.fail(RecorderError::Malformed("trame trop longue")));
        }
        if available < FRAME_HEADER_LEN + len {
            return Ok(None);
        }
        let start = self.pos + FRAME_HEADER_LEN;
        let event = match decode_payload(kind, &self.buf[start..start + len]) {
            Ok(e) => e,
            Err(e) => return Err(self.fail(e)),
        };
        self.pos += FRAME_HEADER_LEN + len;
        if let Err(e) = self.accept(at_us, &event) {
            return Err(self.fail(e));
        }
        Ok(Some(Frame { at_us, event }))
    }

    fn accept(&mut self, at_us: u64, event: &Event) -> Result<(), RecorderError> {
        match (self.state, event) {
            (State::Fresh, Event::Start { .. }) => {
                if at_us != 0 {
                    return Err(RecorderError::Malformed("début à un temps non nul"));
                }
                self.state = State::Started;
            }
            (State::Fresh, _) => return Err(RecorderError::Malformed("pas de début")),
            (State::Started, Event::Start { .. }) => {
                return Err(RecorderError::Malformed("deuxième début"));
            }
            (State::Started, Event::Output(data)) => {
                self.output = self.output.saturating_add(data.len() as u64);
                if self.output > self.limits.max_output_bytes {
                    return Err(RecorderError::Limit("taille maximale"));
                }
            }
            (State::Started, Event::Resize { .. }) => {}
            (State::Started, Event::Exit(_)) => {
                if self.exited {
                    return Err(RecorderError::Malformed("deuxième fin de commande"));
                }
                self.exited = true;
            }
            (State::Started, Event::End { output_bytes, .. }) => {
                if *output_bytes != self.output {
                    return Err(RecorderError::Malformed(
                        "nombre d'octets de sortie différent de celui reçu",
                    ));
                }
                self.state = State::Ended;
            }
            (State::Ended | State::Failed, _) => {
                return Err(RecorderError::Malformed("trame après la fin"));
            }
        }
        if at_us < self.last_at {
            return Err(RecorderError::Malformed("temps qui recule"));
        }
        if at_us > self.limits.max_duration_us {
            return Err(RecorderError::Limit("durée maximale"));
        }
        self.last_at = at_us;
        Ok(())
    }

    /// Checks the stream ended where it should: after the end frame, on a
    /// frame boundary.
    ///
    /// # Errors
    ///
    /// [`RecorderError::Incomplete`], or the error already met.
    pub fn finish(&self) -> Result<(), RecorderError> {
        match self.state {
            State::Failed => Err(RecorderError::Malformed("flux déjà refusé")),
            State::Ended if self.pos == self.buf.len() => Ok(()),
            State::Ended => Err(RecorderError::Malformed("octets après la fin")),
            _ if self.pos == self.buf.len() => {
                Err(RecorderError::Incomplete("flux terminé sans trame de fin"))
            }
            _ => Err(RecorderError::Incomplete(
                "flux terminé au milieu d'une trame",
            )),
        }
    }
}

#[cfg(test)]
mod tests;
