//! The BER subset of `LDAPv3` (RFC 4511 § 5.1, X.690).
//!
//! Only what LDAP uses is accepted:
//!
//! - identifiers on one byte (tag numbers 0 to 30); the high-tag-number form
//!   is refused;
//! - definite lengths only, short form or long form on 1 to 4 bytes (Active
//!   Directory always writes the 4-byte form); the indefinite form is
//!   refused;
//! - integers of 1 to 8 bytes, two's complement;
//! - booleans of exactly one byte.
//!
//! Every length is checked against what remains before anything is sliced:
//! the reader never allocates and never reads past its input. The writer
//! uses the shortest form of every length.

use crate::LdapError;

/// Universal tags used by LDAP.
pub(crate) mod tag {
    pub(crate) const BOOLEAN: u8 = 0x01;
    pub(crate) const INTEGER: u8 = 0x02;
    pub(crate) const OCTET_STRING: u8 = 0x04;
    pub(crate) const ENUMERATED: u8 = 0x0a;
    pub(crate) const SEQUENCE: u8 = 0x30;
    pub(crate) const SET: u8 = 0x31;
}

const fn malformed(what: &'static str) -> LdapError {
    LdapError::Malformed(what)
}

/// The length of an element whose identifier and first length byte are
/// `header` (at least two bytes): `(header length, content length)`, or
/// `None` while more header bytes are needed.
///
/// # Errors
///
/// [`LdapError::Malformed`] for a high tag number, an indefinite length or
/// a length on more than 4 bytes.
pub(crate) fn header_len(header: &[u8]) -> Result<Option<(usize, usize)>, LdapError> {
    let (Some(&id), Some(&first)) = (header.first(), header.get(1)) else {
        return Ok(None);
    };
    if id & 0x1f == 0x1f {
        return Err(malformed("numéro d'étiquette sur plusieurs octets"));
    }
    if first < 0x80 {
        return Ok(Some((2, usize::from(first))));
    }
    let n = usize::from(first & 0x7f);
    if n == 0 {
        return Err(malformed("longueur indéfinie"));
    }
    if n > 4 {
        return Err(malformed("longueur sur plus de 4 octets"));
    }
    let Some(bytes) = header.get(2..2 + n) else {
        return Ok(None);
    };
    let len = bytes
        .iter()
        .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
    Ok(Some((2 + n, len)))
}

/// A reader over the content of a constructed element.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// The identifier of the next element, if any.
    pub(crate) fn peek(&self) -> Option<u8> {
        self.rest.first().copied()
    }

    /// The next element: its identifier and content.
    pub(crate) fn any(&mut self) -> Result<(u8, &'a [u8]), LdapError> {
        let (head, len) = header_len(self.rest)?.ok_or(malformed("en-tête tronqué"))?;
        let end = head
            .checked_add(len)
            .filter(|end| *end <= self.rest.len())
            .ok_or(malformed("longueur au-delà du message"))?;
        let id = self.rest[0];
        let content = &self.rest[head..end];
        self.rest = &self.rest[end..];
        Ok((id, content))
    }

    /// The next element, which must have the identifier `id`.
    pub(crate) fn expect(&mut self, id: u8, what: &'static str) -> Result<&'a [u8], LdapError> {
        match self.any()? {
            (got, content) if got == id => Ok(content),
            _ => Err(malformed(what)),
        }
    }

    /// The next element if it has the identifier `id`.
    pub(crate) fn optional(&mut self, id: u8) -> Result<Option<&'a [u8]>, LdapError> {
        if self.peek() == Some(id) {
            self.any().map(|(_, c)| Some(c))
        } else {
            Ok(None)
        }
    }

    /// A constructed element with identifier `id`, as a reader.
    pub(crate) fn nested(&mut self, id: u8, what: &'static str) -> Result<Self, LdapError> {
        self.expect(id, what).map(Reader::new)
    }

    pub(crate) fn integer(&mut self, id: u8, what: &'static str) -> Result<i64, LdapError> {
        integer(self.expect(id, what)?)
    }

    /// A non-negative integer that fits in `u32` (message ids, result codes,
    /// limits).
    pub(crate) fn unsigned(&mut self, id: u8, what: &'static str) -> Result<u32, LdapError> {
        u32::try_from(self.integer(id, what)?).map_err(|_| malformed(what))
    }

    pub(crate) fn boolean(&mut self, id: u8, what: &'static str) -> Result<bool, LdapError> {
        match self.expect(id, what)? {
            [0] => Ok(false),
            [_] => Ok(true),
            _ => Err(malformed(what)),
        }
    }

    pub(crate) fn utf8(&mut self, id: u8, what: &'static str) -> Result<&'a str, LdapError> {
        std::str::from_utf8(self.expect(id, what)?).map_err(|_| malformed(what))
    }

    /// Fails unless every byte was read.
    pub(crate) fn end(&self, what: &'static str) -> Result<(), LdapError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(malformed(what))
        }
    }
}

/// An integer of 1 to 8 bytes, two's complement.
pub(crate) fn integer(content: &[u8]) -> Result<i64, LdapError> {
    if content.is_empty() || content.len() > 8 {
        return Err(malformed("entier de 1 à 8 octets attendu"));
    }
    let negative = content[0] & 0x80 != 0;
    let start = if negative { -1i64 } else { 0 };
    Ok(content
        .iter()
        .fold(start, |acc, b| (acc << 8) | i64::from(*b)))
}

/// Appends a length in its shortest form.
fn push_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        // Fits on 7 bits.
        out.push(u8::try_from(len).unwrap_or(0));
        return;
    }
    let bytes = len.to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count();
    let n = bytes.len() - skip;
    out.push(0x80 | u8::try_from(n).unwrap_or(0));
    out.extend_from_slice(&bytes[skip..]);
}

/// Appends the identifier and length of an element whose `len` bytes of
/// content the caller writes next.
pub(crate) fn push_header(out: &mut Vec<u8>, id: u8, len: usize) {
    out.push(id);
    push_len(out, len);
}

/// Encoded length of an element with `len` bytes of content.
pub(crate) fn element_len(len: usize) -> usize {
    let length_bytes = if len < 0x80 {
        1
    } else {
        1 + len.bit_width().div_ceil(8) as usize
    };
    1 + length_bytes + len
}

/// Appends an element.
pub(crate) fn push(out: &mut Vec<u8>, id: u8, content: &[u8]) {
    out.push(id);
    push_len(out, content.len());
    out.extend_from_slice(content);
}

/// Appends a constructed element whose content `fill` writes.
pub(crate) fn push_nested(out: &mut Vec<u8>, id: u8, fill: impl FnOnce(&mut Vec<u8>)) {
    let mut content = Vec::new();
    fill(&mut content);
    push(out, id, &content);
}

/// Appends an integer in its shortest two's complement form.
pub(crate) fn push_integer(out: &mut Vec<u8>, id: u8, value: i64) {
    let bytes = value.to_be_bytes();
    let mut start = 0;
    while start < 7 {
        let (b, next) = (bytes[start], bytes[start + 1]);
        if (b == 0 && next & 0x80 == 0) || (b == 0xff && next & 0x80 != 0) {
            start += 1;
        } else {
            break;
        }
    }
    push(out, id, &bytes[start..]);
}

pub(crate) fn push_boolean(out: &mut Vec<u8>, id: u8, value: bool) {
    push(out, id, &[if value { 0xff } else { 0 }]);
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn lengths() {
        assert_eq!(header_len(&[0x30, 0x05]).unwrap(), Some((2, 5)));
        assert_eq!(header_len(&[0x30, 0x81, 0x80]).unwrap(), Some((3, 128)));
        // The four-byte form of Active Directory.
        assert_eq!(
            header_len(&[0x30, 0x84, 0, 0, 0x01, 0x00]).unwrap(),
            Some((6, 256))
        );
        assert_eq!(header_len(&[0x30]).unwrap(), None);
        assert_eq!(header_len(&[0x30, 0x82, 0x01]).unwrap(), None);
        assert!(header_len(&[0x30, 0x80]).is_err(), "indefinite");
        assert!(header_len(&[0x30, 0x85, 0, 0, 0, 0, 1]).is_err());
        assert!(header_len(&[0x3f, 0x01]).is_err(), "high tag number");
    }

    #[test]
    fn reader_bounds() {
        // Content shorter than announced.
        let mut r = Reader::new(&[0x04, 0x05, b'a']);
        assert!(r.any().is_err());
        // Long form announcing more than the input.
        let mut r = Reader::new(&[0x04, 0x84, 0xff, 0xff, 0xff, 0xff]);
        assert!(r.any().is_err());
        let mut r = Reader::new(&[0x01, 0x02, 0, 0]);
        assert!(r.boolean(0x01, "b").is_err());
        let mut r = Reader::new(&[0x02, 0x00]);
        assert!(r.integer(0x02, "i").is_err());
    }

    #[test]
    fn integers() {
        for (value, bytes) in [
            (0i64, &[0u8][..]),
            (127, &[0x7f]),
            (128, &[0x00, 0x80]),
            (-1, &[0xff]),
            (-128, &[0x80]),
            (-129, &[0xff, 0x7f]),
            (2_147_483_647, &[0x7f, 0xff, 0xff, 0xff]),
        ] {
            let mut out = Vec::new();
            push_integer(&mut out, tag::INTEGER, value);
            assert_eq!(&out[2..], bytes, "{value}");
            assert_eq!(integer(bytes).unwrap(), value);
        }
    }

    proptest! {
        #[test]
        fn integer_round_trip(value in any::<i64>()) {
            let mut out = Vec::new();
            push_integer(&mut out, tag::INTEGER, value);
            let mut r = Reader::new(&out);
            prop_assert_eq!(r.integer(tag::INTEGER, "i").unwrap(), value);
            prop_assert!(r.is_empty());
        }

        #[test]
        fn element_round_trip(content in proptest::collection::vec(any::<u8>(), 0..70_000)) {
            let mut out = Vec::new();
            push(&mut out, tag::OCTET_STRING, &content);
            let mut r = Reader::new(&out);
            prop_assert_eq!(r.expect(tag::OCTET_STRING, "s").unwrap(), &content[..]);
            prop_assert!(r.is_empty());
        }

        #[test]
        fn reader_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let mut r = Reader::new(&bytes);
            while r.any().is_ok() && !r.is_empty() {}
        }
    }
}
