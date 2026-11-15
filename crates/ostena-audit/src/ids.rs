//! Chain and key identifiers, and the hexadecimal helpers of the text forms.

use std::fmt;

use ostena_crypto::p256::VerifyingKey;

use crate::AuditError;

/// Writes `bytes` in lowercase hexadecimal.
pub(crate) fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    bytes.iter().try_for_each(|b| write!(f, "{b:02x}"))
}

/// Lowercase hexadecimal of `bytes`.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

/// Strict lowercase hexadecimal into `out`: exactly `2 × out.len()` digits,
/// `0-9a-f` only. Returns `false` otherwise.
pub(crate) fn from_hex(text: &str, out: &mut [u8]) -> bool {
    fn digit(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }
    let text = text.as_bytes();
    if text.len() != out.len() * 2 {
        return false;
    }
    for (byte, pair) in out.iter_mut().zip(text.as_chunks::<2>().0) {
        match (digit(pair[0]), digit(pair[1])) {
            (Some(hi), Some(lo)) => *byte = (hi << 4) | lo,
            _ => return false,
        }
    }
    true
}

/// Identifier of an audit chain: 16 random bytes drawn when the chain starts
/// (`audit.chain_started`). Every record and head carries it, so records of
/// another chain (another core, a restored database) cannot be spliced in.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChainId([u8; 16]);

impl ChainId {
    /// A fresh random identifier.
    ///
    /// # Errors
    ///
    /// [`AuditError::Crypto`] if the system generator fails.
    pub fn random() -> Result<Self, AuditError> {
        ostena_crypto::rand::array()
            .map(Self)
            .map_err(AuditError::Crypto)
    }

    /// Wraps 16 bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The 16 bytes.
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Display for ChainId {
    /// UUID text form, `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChainId({self})")
    }
}

/// Key identifier: the first 8 bytes of SHA-256 of the public key in its
/// uncompressed SEC1 form (65 bytes, `0x04 ‖ x ‖ y`). Same definition as the
/// grant kid (ADR-0004).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Kid([u8; 8]);

impl Kid {
    /// The identifier of a public key.
    pub fn of(key: &VerifyingKey) -> Self {
        let digest = ostena_crypto::sha256::digest(&key.to_bytes());
        let mut kid = [0u8; 8];
        kid.copy_from_slice(&digest[..8]);
        Self(kid)
    }

    /// Wraps 8 bytes.
    pub const fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    /// The 8 bytes.
    pub const fn to_bytes(self) -> [u8; 8] {
        self.0
    }
}

impl fmt::Display for Kid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl fmt::Debug for Kid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Kid({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip_is_strict() {
        let mut out = [0u8; 3];
        assert!(from_hex("00ff7a", &mut out));
        assert_eq!(out, [0x00, 0xff, 0x7a]);
        assert_eq!(to_hex(&out), "00ff7a");
        assert!(!from_hex("00FF7A", &mut out), "uppercase refused");
        assert!(!from_hex("00ff7", &mut out), "odd length refused");
        assert!(!from_hex("00ff7a00", &mut out), "too long refused");
        assert!(!from_hex("00fg7a", &mut out), "non-hex refused");
        assert!(!from_hex("+0ff7a", &mut out), "sign refused");
    }

    #[test]
    fn chain_id_text_form() {
        let id = ChainId::from_bytes([
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef,
        ]);
        assert_eq!(id.to_string(), "12345678-9abc-def0-0123-456789abcdef");
        assert_eq!(
            format!("{id:?}"),
            "ChainId(12345678-9abc-def0-0123-456789abcdef)"
        );
        assert_ne!(ChainId::random().unwrap(), ChainId::random().unwrap());
    }

    #[test]
    fn kid_matches_the_grant_definition() {
        let key = ostena_crypto::p256::SigningKey::generate().unwrap().0;
        let public = key.verifying_key();
        assert_eq!(
            Kid::of(&public).to_bytes(),
            ostena_grant::Kid::of(&public).to_bytes()
        );
        assert_eq!(Kid::of(&public).to_string().len(), 16);
    }
}
