//! The client side of the codec, for the tests of the gateway and the fuzz
//! targets only (feature `client`): masked frames, any opcode and flags, so
//! that a test can also forge what the server must refuse.

use crate::frame::Opcode;

/// Appends a masked client frame to `out`: `fin`, `opcode` and `payload`
/// as given, the length in its shortest encoding.
pub fn encode(opcode: Opcode, fin: bool, payload: &[u8], mask: [u8; 4], out: &mut Vec<u8>) {
    encode_raw(u8::from(fin) << 7 | opcode as u8, payload, mask, out);
}

/// Appends a masked client frame whose first byte is `first` (flags,
/// reserved bits and opcode, unchecked).
pub fn encode_raw(first: u8, payload: &[u8], mask: [u8; 4], out: &mut Vec<u8>) {
    out.push(first);
    let len = payload.len();
    if len < 126 {
        out.push(0x80 | u8::try_from(len).unwrap_or(0));
    } else if let Ok(short) = u16::try_from(len) {
        out.push(0x80 | 0x7e);
        out.extend_from_slice(&short.to_be_bytes());
    } else {
        out.push(0x80 | 0x7f);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(&mask);
    out.extend(payload.iter().zip(mask.iter().cycle()).map(|(b, m)| b ^ m));
}

/// A frame the server sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerFrame<'a> {
    /// Final fragment.
    pub fin: bool,
    /// Opcode bits.
    pub opcode: u8,
    /// Payload.
    pub payload: &'a [u8],
}

/// Reads one server frame from `input`: `None` while incomplete, or if it
/// is masked (a server never masks).
pub fn decode(input: &[u8]) -> Option<(usize, ServerFrame<'_>)> {
    let (&b0, &b1) = (input.first()?, input.get(1)?);
    if b1 & 0x80 != 0 {
        return None;
    }
    let (len, at): (usize, usize) = match b1 & 0x7f {
        126 => (
            usize::from(u16::from_be_bytes(input.get(2..4)?.try_into().ok()?)),
            4,
        ),
        127 => (
            usize::try_from(u64::from_be_bytes(input.get(2..10)?.try_into().ok()?)).ok()?,
            10,
        ),
        n => (usize::from(n), 2),
    };
    let payload = input.get(at..at.checked_add(len)?)?;
    Some((
        at + len,
        ServerFrame {
            fin: b0 & 0x80 != 0,
            opcode: b0 & 0x0f,
            payload,
        },
    ))
}
