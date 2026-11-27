//! The frame codec (RFC 6455, § 5): a parser of the frames a client sends,
//! and the encoders of the frames the server sends (never masked).
//!
//! The [`Parser`] reads from a buffer the caller fills, and never blocks:
//! it answers how many bytes it used, and the event they completed. A
//! message is reassembled in the parser, unmasked as it is copied, within
//! its bound.

use std::fmt;

use crate::MAX_MESSAGE;

/// Largest frame header: two bytes, a 64-bit length and the mask key.
pub const MAX_HEADER: usize = 14;
/// Largest payload of a control frame.
pub const MAX_CONTROL: usize = 125;
/// Largest close reason, in bytes: a control payload less the code.
pub const MAX_REASON: usize = MAX_CONTROL - 2;

/// The opcodes of RFC 6455; the others are reserved and refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Opcode {
    /// The next fragment of a message.
    Continuation = 0x0,
    /// A text message: refused by the parser.
    Text = 0x1,
    /// A binary message.
    Binary = 0x2,
    /// Close.
    Close = 0x8,
    /// Ping.
    Ping = 0x9,
    /// Pong.
    Pong = 0xa,
}

impl Opcode {
    /// The opcode of `bits`, if it is not reserved.
    pub const fn from_bits(bits: u8) -> Option<Self> {
        Some(match bits {
            0x0 => Self::Continuation,
            0x1 => Self::Text,
            0x2 => Self::Binary,
            0x8 => Self::Close,
            0x9 => Self::Ping,
            0xa => Self::Pong,
            _ => return None,
        })
    }

    /// Whether it is a control frame (close, ping, pong).
    pub const fn is_control(self) -> bool {
        (self as u8) & 0x8 != 0
    }
}

/// A close status code (RFC 6455, § 7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CloseCode(pub u16);

impl CloseCode {
    /// Normal closure.
    pub const NORMAL: Self = Self(1000);
    /// The endpoint goes away.
    pub const GOING_AWAY: Self = Self(1001);
    /// Protocol error.
    pub const PROTOCOL: Self = Self(1002);
    /// A data type the endpoint does not accept (text).
    pub const UNSUPPORTED: Self = Self(1003);
    /// Data inconsistent with the type of the message (a close reason that
    /// is not UTF-8).
    pub const INVALID_DATA: Self = Self(1007);
    /// The message violates the policy of the endpoint.
    pub const POLICY: Self = Self(1008);
    /// The message is too big.
    pub const TOO_BIG: Self = Self(1009);
    /// An unexpected condition on the server.
    pub const INTERNAL: Self = Self(1011);

    /// Whether a peer may send it in a close frame: the codes of the RFC
    /// that are not reserved, and the registered and private ranges.
    pub const fn is_valid(self) -> bool {
        matches!(self.0, 1000..=1003 | 1007..=1011 | 3000..=4999)
    }
}

/// Why the parser refuses the input. The connection must end with
/// [`WsError::close_code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WsError {
    /// A client frame without a mask.
    Unmasked,
    /// A reserved bit is set: no extension is negotiated.
    Reserved,
    /// A reserved opcode.
    Opcode(u8),
    /// A text message.
    Text,
    /// A control frame of more than 125 bytes.
    ControlLength,
    /// A control frame that is not final.
    ControlFragmented,
    /// A length that does not use its shortest encoding, or with the most
    /// significant bit set.
    Length,
    /// A message larger than the bound.
    TooBig,
    /// A continuation without a started message.
    Continuation,
    /// A new message before the end of the previous one.
    Interrupted,
    /// A close body of one byte, or with an invalid code.
    CloseBody,
    /// A close reason that is not UTF-8.
    CloseReason,
    /// Data after a close frame.
    AfterClose,
}

impl WsError {
    /// The close code the server sends before it ends the connection.
    pub const fn close_code(self) -> CloseCode {
        match self {
            Self::Text => CloseCode::UNSUPPORTED,
            Self::TooBig => CloseCode::TOO_BIG,
            Self::CloseReason => CloseCode::INVALID_DATA,
            _ => CloseCode::PROTOCOL,
        }
    }
}

impl fmt::Display for WsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unmasked => f.write_str("trame du client non masquée"),
            Self::Reserved => f.write_str("bit réservé positionné (aucune extension négociée)"),
            Self::Opcode(op) => write!(f, "opcode réservé {op:#x}"),
            Self::Text => f.write_str("message texte refusé"),
            Self::ControlLength => f.write_str("trame de contrôle de plus de 125 octets"),
            Self::ControlFragmented => f.write_str("trame de contrôle fragmentée"),
            Self::Length => f.write_str("longueur mal encodée"),
            Self::TooBig => write!(f, "message de plus de {MAX_MESSAGE} octets"),
            Self::Continuation => f.write_str("suite sans message commencé"),
            Self::Interrupted => f.write_str("nouveau message avant la fin du précédent"),
            Self::CloseBody => f.write_str("corps de fermeture invalide"),
            Self::CloseReason => f.write_str("raison de fermeture qui n'est pas en UTF-8"),
            Self::AfterClose => f.write_str("données après la trame de fermeture"),
        }
    }
}

impl std::error::Error for WsError {}

/// What a complete frame gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event<'a> {
    /// A whole binary message, unmasked.
    Binary(&'a [u8]),
    /// A ping and its payload, to answer with a pong.
    Ping(&'a [u8]),
    /// A pong.
    Pong(&'a [u8]),
    /// A close frame: its code and reason, if it has a body. Nothing may
    /// follow it.
    Close(Option<(CloseCode, &'a str)>),
}

/// The fixed part of a frame header.
struct Head {
    fin: bool,
    opcode: Opcode,
    len: u64,
    mask: [u8; 4],
    size: usize,
}

/// Reads a client frame header; `None` while it is incomplete. Every check
/// that the bytes received allow is made before waiting for more.
fn head(input: &[u8]) -> Result<Option<Head>, WsError> {
    let (Some(&b0), Some(&b1)) = (input.first(), input.get(1)) else {
        return Ok(None);
    };
    if b0 & 0x70 != 0 {
        return Err(WsError::Reserved);
    }
    let opcode = Opcode::from_bits(b0 & 0x0f).ok_or(WsError::Opcode(b0 & 0x0f))?;
    if b1 & 0x80 == 0 {
        return Err(WsError::Unmasked);
    }
    let fin = b0 & 0x80 != 0;
    let short = b1 & 0x7f;
    if opcode.is_control() {
        if !fin {
            return Err(WsError::ControlFragmented);
        }
        if usize::from(short) > MAX_CONTROL {
            return Err(WsError::ControlLength);
        }
    }
    let (len, at) = match short {
        126 => {
            let Some(bytes) = input.get(2..4) else {
                return Ok(None);
            };
            let len = u16::from_be_bytes([bytes[0], bytes[1]]);
            if len < 126 {
                return Err(WsError::Length);
            }
            (u64::from(len), 4)
        }
        127 => {
            let Some(bytes) = input.get(2..10) else {
                return Ok(None);
            };
            let mut raw = [0u8; 8];
            raw.copy_from_slice(bytes);
            let len = u64::from_be_bytes(raw);
            if len >> 63 != 0 || u16::try_from(len).is_ok() {
                return Err(WsError::Length);
            }
            (len, 10)
        }
        n => (u64::from(n), 2),
    };
    let Some(key) = input.get(at..at + 4) else {
        return Ok(None);
    };
    Ok(Some(Head {
        fin,
        opcode,
        len,
        mask: [key[0], key[1], key[2], key[3]],
        size: at + 4,
    }))
}

/// Appends `payload` unmasked with `mask` to `out`.
fn unmask_into(out: &mut Vec<u8>, payload: &[u8], mask: [u8; 4]) {
    out.extend(payload.iter().zip(mask.iter().cycle()).map(|(b, m)| b ^ m));
}

/// The parser of the frames of one client connection.
#[derive(Debug, Clone)]
pub struct Parser {
    max: usize,
    message: Vec<u8>,
    fragmented: bool,
    control: [u8; MAX_CONTROL],
    closed: bool,
}

impl Default for Parser {
    fn default() -> Self {
        Self::new(MAX_MESSAGE)
    }
}

impl Parser {
    /// A parser that accepts messages of at most `max` bytes (capped at
    /// [`MAX_MESSAGE`]).
    pub fn new(max: usize) -> Self {
        Self {
            max: max.min(MAX_MESSAGE),
            message: Vec::new(),
            fragmented: false,
            control: [0; MAX_CONTROL],
            closed: false,
        }
    }

    /// Whether a close frame was received.
    pub fn closed(&self) -> bool {
        self.closed
    }

    /// Reads one frame from the start of `input`. Returns the bytes used
    /// and the event the frame completed:
    ///
    /// - `(0, None)`: the frame is incomplete, call again with more bytes;
    /// - `(n, None)`: a fragment of a message, `n` bytes used;
    /// - `(n, Some(event))`: an event; a [`Event::Binary`] borrows the
    ///   parser until the next call.
    ///
    /// # Errors
    ///
    /// The first violation, see [`WsError`]: the connection must end.
    pub fn parse(&mut self, input: &[u8]) -> Result<(usize, Option<Event<'_>>), WsError> {
        if self.closed {
            return if input.is_empty() {
                Ok((0, None))
            } else {
                Err(WsError::AfterClose)
            };
        }
        let Some(head) = head(input)? else {
            return Ok((0, None));
        };
        let message_len = match head.opcode {
            Opcode::Text => return Err(WsError::Text),
            Opcode::Binary if self.fragmented => return Err(WsError::Interrupted),
            Opcode::Continuation if !self.fragmented => return Err(WsError::Continuation),
            Opcode::Binary => Some(head.len),
            Opcode::Continuation => Some((self.message.len() as u64).saturating_add(head.len)),
            Opcode::Close | Opcode::Ping | Opcode::Pong => None,
        };
        // Before waiting for the payload: a client cannot make the server
        // buffer more than the bound.
        if message_len.is_some_and(|l| l > self.max as u64) {
            return Err(WsError::TooBig);
        }
        // Bounded by the check above (or by 125 for a control frame).
        let len = usize::try_from(head.len).map_err(|_| WsError::TooBig)?;
        let end = head.size + len;
        let Some(payload) = input.get(head.size..end) else {
            return Ok((0, None));
        };
        if head.opcode.is_control() {
            for (i, (b, m)) in payload.iter().zip(head.mask.iter().cycle()).enumerate() {
                self.control[i] = b ^ m;
            }
            let body = &self.control[..len];
            let event = match head.opcode {
                Opcode::Ping => Event::Ping(body),
                Opcode::Pong => Event::Pong(body),
                _ => {
                    self.closed = true;
                    Event::Close(close_body(body)?)
                }
            };
            return Ok((end, Some(event)));
        }
        if head.opcode == Opcode::Binary {
            self.message.clear();
        }
        unmask_into(&mut self.message, payload, head.mask);
        self.fragmented = !head.fin;
        if head.fin {
            Ok((end, Some(Event::Binary(&self.message))))
        } else {
            Ok((end, None))
        }
    }
}

/// The code and reason of a close body.
fn close_body(body: &[u8]) -> Result<Option<(CloseCode, &str)>, WsError> {
    match body {
        [] => Ok(None),
        [_] => Err(WsError::CloseBody),
        [a, b, reason @ ..] => {
            let code = CloseCode(u16::from_be_bytes([*a, *b]));
            if !code.is_valid() {
                return Err(WsError::CloseBody);
            }
            let reason = std::str::from_utf8(reason).map_err(|_| WsError::CloseReason)?;
            Ok(Some((code, reason)))
        }
    }
}

/// Writes the header of a server frame (final, unmasked) of `len` bytes;
/// returns its length.
pub fn encode_header(opcode: Opcode, len: usize, out: &mut [u8; 10]) -> usize {
    out[0] = 0x80 | opcode as u8;
    if len < 126 {
        // Below 126: fits in the 7 bits.
        out[1] = u8::try_from(len).unwrap_or(0);
        2
    } else if let Ok(short) = u16::try_from(len) {
        out[1] = 126;
        out[2..4].copy_from_slice(&short.to_be_bytes());
        4
    } else {
        out[1] = 127;
        out[2..10].copy_from_slice(&(len as u64).to_be_bytes());
        10
    }
}

/// Appends a server frame (final, unmasked) carrying `payload` to `out`.
pub fn encode(opcode: Opcode, payload: &[u8], out: &mut Vec<u8>) {
    let mut header = [0u8; 10];
    let n = encode_header(opcode, payload.len(), &mut header);
    out.reserve(n + payload.len());
    out.extend_from_slice(&header[..n]);
    out.extend_from_slice(payload);
}

/// Appends a close frame with `code` and `reason` (cut to
/// [`MAX_REASON`] bytes on a character boundary) to `out`.
pub fn encode_close(code: CloseCode, reason: &str, out: &mut Vec<u8>) {
    let mut cut = reason.len().min(MAX_REASON);
    while !reason.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut body = [0u8; MAX_CONTROL];
    body[..2].copy_from_slice(&code.0.to_be_bytes());
    body[2..2 + cut].copy_from_slice(&reason.as_bytes()[..cut]);
    encode(Opcode::Close, &body[..2 + cut], out);
}

#[cfg(test)]
mod tests;
