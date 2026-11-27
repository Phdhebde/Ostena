//! A minimal, strict DER reader and writer: what RFC 3161 and CMS need,
//! nothing more. The reader refuses every encoding that is not the unique
//! DER one (indefinite or non-minimal lengths, multi-byte tags), so that a
//! value has one encoding and parsing never guesses.

use super::TspError;

/// Universal and context tags used here.
pub(crate) mod tag {
    pub(crate) const BOOLEAN: u8 = 0x01;
    pub(crate) const INTEGER: u8 = 0x02;
    pub(crate) const BIT_STRING: u8 = 0x03;
    pub(crate) const OCTET_STRING: u8 = 0x04;
    pub(crate) const NULL: u8 = 0x05;
    pub(crate) const OID: u8 = 0x06;
    pub(crate) const UTF8_STRING: u8 = 0x0c;
    pub(crate) const GENERALIZED_TIME: u8 = 0x18;
    pub(crate) const SEQUENCE: u8 = 0x30;
    pub(crate) const SET: u8 = 0x31;
    /// `[n]` constructed (explicit, or implicit over a constructed type).
    pub(crate) const fn context(n: u8) -> u8 {
        0xa0 | n
    }
    /// `[n]` primitive (implicit over a primitive type).
    pub(crate) const fn context_primitive(n: u8) -> u8 {
        0x80 | n
    }
}

/// A cursor over DER bytes.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Reader<'a> {
    data: &'a [u8],
}

fn malformed(what: &'static str) -> TspError {
    TspError::Malformed(what)
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// The next tag, without consuming it.
    pub(crate) fn peek(&self) -> Option<u8> {
        self.data.first().copied()
    }

    /// The next element: its tag, its content and its whole encoding.
    pub(crate) fn any(&mut self) -> Result<(u8, &'a [u8], &'a [u8]), TspError> {
        let data = self.data;
        let (&tag, rest) = data.split_first().ok_or(malformed("fin inattendue"))?;
        if tag & 0x1f == 0x1f {
            return Err(malformed("étiquette sur plusieurs octets"));
        }
        let (&first, mut rest) = rest.split_first().ok_or(malformed("longueur absente"))?;
        let len = if first < 0x80 {
            usize::from(first)
        } else {
            let n = usize::from(first & 0x7f);
            if n == 0 || n > 3 {
                return Err(malformed("longueur indéfinie ou trop grande"));
            }
            if rest.len() < n {
                return Err(malformed("longueur tronquée"));
            }
            let (bytes, after) = rest.split_at(n);
            rest = after;
            if bytes[0] == 0 {
                return Err(malformed("longueur non minimale"));
            }
            let len = bytes
                .iter()
                .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
            if len < 0x80 {
                return Err(malformed("longueur non minimale"));
            }
            len
        };
        if rest.len() < len {
            return Err(malformed("contenu tronqué"));
        }
        let header = data.len() - rest.len();
        let (content, after) = rest.split_at(len);
        self.data = after;
        Ok((tag, content, &data[..header + len]))
    }

    /// The next element, which must have tag `expected`; its content.
    pub(crate) fn expect(
        &mut self,
        expected: u8,
        what: &'static str,
    ) -> Result<&'a [u8], TspError> {
        let (tag, content, _) = self.any()?;
        if tag == expected {
            Ok(content)
        } else {
            Err(malformed(what))
        }
    }

    /// The next element with tag `expected`, with its whole encoding.
    pub(crate) fn expect_whole(
        &mut self,
        expected: u8,
        what: &'static str,
    ) -> Result<(&'a [u8], &'a [u8]), TspError> {
        let (tag, content, whole) = self.any()?;
        if tag == expected {
            Ok((content, whole))
        } else {
            Err(malformed(what))
        }
    }

    /// The next element if it has tag `expected`.
    pub(crate) fn optional(&mut self, expected: u8) -> Result<Option<&'a [u8]>, TspError> {
        if self.peek() == Some(expected) {
            Ok(Some(self.any()?.1))
        } else {
            Ok(None)
        }
    }

    /// A nested reader over the content of the next element `expected`.
    pub(crate) fn nested(&mut self, expected: u8, what: &'static str) -> Result<Self, TspError> {
        Ok(Self::new(self.expect(expected, what)?))
    }

    /// An INTEGER, as its minimal two's complement bytes.
    pub(crate) fn integer(&mut self, what: &'static str) -> Result<&'a [u8], TspError> {
        let bytes = self.expect(tag::INTEGER, what)?;
        check_integer(bytes, what)?;
        Ok(bytes)
    }

    /// A small non-negative INTEGER.
    pub(crate) fn small(&mut self, what: &'static str) -> Result<u64, TspError> {
        let bytes = self.integer(what)?;
        if bytes[0] & 0x80 != 0 || bytes.len() > 8 {
            return Err(malformed(what));
        }
        Ok(bytes.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
    }

    /// A BOOLEAN (DER: `0x00` or `0xff`).
    pub(crate) fn boolean(&mut self, what: &'static str) -> Result<bool, TspError> {
        match self.expect(tag::BOOLEAN, what)? {
            [0x00] => Ok(false),
            [0xff] => Ok(true),
            _ => Err(malformed(what)),
        }
    }

    /// Fails if anything is left.
    pub(crate) fn finish(&self, what: &'static str) -> Result<(), TspError> {
        if self.data.is_empty() {
            Ok(())
        } else {
            Err(malformed(what))
        }
    }
}

/// A DER INTEGER content: not empty, minimal.
pub(crate) fn check_integer(bytes: &[u8], what: &'static str) -> Result<(), TspError> {
    match bytes {
        [] => Err(malformed(what)),
        [0x00, next, ..] if next & 0x80 == 0 => Err(malformed(what)),
        [0xff, next, ..] if next & 0x80 != 0 => Err(malformed(what)),
        _ => Ok(()),
    }
}

/// Parses a DER `GeneralizedTime` as RFC 5280 and RFC 3161 restrict it:
/// `YYYYMMDDHHMMSS[.f+]Z`, UTC, no trailing zero in the fraction; returns
/// Unix milliseconds (a finer fraction is truncated).
pub(crate) fn generalized_time(bytes: &[u8]) -> Result<u64, TspError> {
    let bad = || malformed("heure GeneralizedTime");
    let text = std::str::from_utf8(bytes).map_err(|_| bad())?;
    let text = text.strip_suffix('Z').ok_or_else(bad)?;
    let (main, fraction) = match text.split_once('.') {
        Some((main, fraction)) => (main, Some(fraction)),
        None => (text, None),
    };
    if main.len() != 14 || !main.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let num = |range: std::ops::Range<usize>| -> u32 {
        main[range]
            .bytes()
            .fold(0u32, |acc, b| acc * 10 + u32::from(b - b'0'))
    };
    let (year, month, day) = (num(0..4), num(4..6), num(6..8));
    let (hour, minute, second) = (num(8..10), num(10..12), num(12..14));
    let millis = match fraction {
        None => 0,
        Some(f) => {
            if f.is_empty() || f.ends_with('0') || !f.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad());
            }
            let mut digits = f
                .bytes()
                .take(3)
                .map(|b| u64::from(b - b'0'))
                .collect::<Vec<_>>();
            digits.resize(3, 0);
            digits[0] * 100 + digits[1] * 10 + digits[2]
        }
    };
    let month_ok = (1..=12).contains(&month);
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in_month = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if year < 1970
        || !month_ok
        || day == 0
        || day > days_in_month
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(bad());
    }
    let days = days_from_civil(year, month, day);
    let seconds =
        days * 86_400 + u64::from(hour) * 3600 + u64::from(minute) * 60 + u64::from(second);
    Ok(seconds * 1000 + millis)
}

/// Days since 1970-01-01 of a proleptic Gregorian date (year ≥ 1970).
fn days_from_civil(year: u32, month: u32, day: u32) -> u64 {
    let y = u64::from(if month <= 2 { year - 1 } else { year });
    let era = y / 400;
    let yoe = y - era * 400;
    let m = u64::from(month);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + u64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The DER writer: each function returns a complete element.
pub(crate) mod write {
    use super::tag;

    /// An element `tag` around `content`.
    pub(crate) fn element(tag: u8, content: &[u8]) -> Vec<u8> {
        let len = content.len();
        let mut out = Vec::with_capacity(len + 5);
        out.push(tag);
        if len < 0x80 {
            out.push(u8::try_from(len).unwrap_or(0));
        } else {
            let bytes = len.to_be_bytes();
            let skip = bytes.iter().take_while(|&&b| b == 0).count();
            out.push(0x80 | u8::try_from(bytes.len() - skip).unwrap_or(0));
            out.extend_from_slice(&bytes[skip..]);
        }
        out.extend_from_slice(content);
        out
    }

    /// A SEQUENCE of already encoded elements.
    pub(crate) fn sequence(parts: &[&[u8]]) -> Vec<u8> {
        element(tag::SEQUENCE, &parts.concat())
    }

    /// An INTEGER from big-endian unsigned bytes (leading zeros stripped,
    /// a zero byte added if the high bit is set).
    pub(crate) fn unsigned(bytes: &[u8]) -> Vec<u8> {
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        let trimmed = &bytes[skip..];
        let mut content = Vec::with_capacity(trimmed.len() + 1);
        if trimmed.first().is_none_or(|&b| b & 0x80 != 0) {
            content.push(0);
        }
        content.extend_from_slice(trimmed);
        element(tag::INTEGER, &content)
    }

    /// An OBJECT IDENTIFIER from its content bytes.
    pub(crate) fn oid(content: &[u8]) -> Vec<u8> {
        element(tag::OID, content)
    }

    /// An OCTET STRING.
    pub(crate) fn octets(content: &[u8]) -> Vec<u8> {
        element(tag::OCTET_STRING, content)
    }
}
