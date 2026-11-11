//! Frame decoding (zero-copy, allocation-free) and encoding.

use alloc::vec::Vec;

use crate::error::{Code, FrameError};
use crate::header::{Direction, Flags, HEADER_LEN, Header};
use crate::payload::Payload;

/// A decoded frame, borrowing the buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    /// Header.
    pub header: Header,
    /// Typed payload.
    pub payload: Payload<'a>,
}

/// Decodes a buffer holding exactly one frame (one WebSocket message).
///
/// # Errors
///
/// Any header or payload rule broken; a truncated frame is `FRM-E001`, extra
/// bytes `FRM-E002`.
pub fn decode_message(buf: &[u8], direction: Direction) -> Result<Frame<'_>, FrameError> {
    let header = Header::parse(buf, direction)?;
    let end = HEADER_LEN + usize::from(header.length);
    if buf.len() < end {
        return Err(FrameError::new(Code::Truncated, "charge utile incomplète"));
    }
    if buf.len() > end {
        return Err(FrameError::new(
            Code::TrailingBytes,
            "octets après la trame",
        ));
    }
    let payload = Payload::parse(header.frame_type, &buf[HEADER_LEN..end])?;
    Ok(Frame { header, payload })
}

/// Result of [`decode_stream`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decoded<'a> {
    /// A frame and the number of bytes it used.
    Frame(Frame<'a>, usize),
    /// More bytes are needed; the header (if present) was already checked.
    Incomplete {
        /// Total bytes needed for the next frame, when known.
        needed: Option<usize>,
    },
}

/// Decodes the first frame of a byte stream. The header is checked as soon
/// as it is complete, so an oversized or forbidden frame is refused before
/// its payload arrives.
///
/// # Errors
///
/// Any header or payload rule broken.
pub fn decode_stream(buf: &[u8], direction: Direction) -> Result<Decoded<'_>, FrameError> {
    if buf.len() < HEADER_LEN {
        return Ok(Decoded::Incomplete { needed: None });
    }
    let header = Header::parse(buf, direction)?;
    let end = HEADER_LEN + usize::from(header.length);
    if buf.len() < end {
        return Ok(Decoded::Incomplete { needed: Some(end) });
    }
    let payload = Payload::parse(header.frame_type, &buf[HEADER_LEN..end])?;
    Ok(Decoded::Frame(Frame { header, payload }, end))
}

/// Encodes a frame and appends it to `out`. The header is checked with the
/// same rules as the decoder, so only decodable frames are produced.
///
/// # Errors
///
/// Any header rule broken (wrong direction, version, channel or flags for
/// the type), or a payload above the type maximum (`FRM-E006`).
pub fn encode(
    payload: &Payload<'_>,
    direction: Direction,
    version: u8,
    channel: u16,
    flags: Flags,
    sequence: u64,
    out: &mut Vec<u8>,
) -> Result<(), FrameError> {
    let frame_type = payload.frame_type();
    let len = payload.encoded_len();
    if len > frame_type.max_payload() {
        return Err(FrameError::new(
            Code::Length,
            "charge utile au-delà du maximum du type",
        ));
    }
    let header = Header {
        version,
        frame_type,
        flags,
        channel,
        length: u16::try_from(len)
            .map_err(|_| FrameError::new(Code::Length, "charge utile trop longue"))?,
        sequence,
    };
    let mut h = [0u8; HEADER_LEN];
    header.write(&mut h);
    Header::parse(&h, direction)?;
    out.reserve(HEADER_LEN + len);
    out.extend_from_slice(&h);
    payload.write(out);
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
