//! HMAC-SHA-256 (RFC 2104) under a 256-bit key, the only MAC offered.
//!
//! Used for keyed digests of audited values that must not be recoverable by
//! dictionary (ADR-0016): the key never leaves the core.

use aws_lc_rs::hmac;
use ostena_common::secret::SecretBytes;

use crate::CryptoError;

/// Length of a key, in bytes.
pub const KEY_LEN: usize = 32;
/// Length of a tag, in bytes.
pub const TAG_LEN: usize = 32;

/// An HMAC-SHA-256 key. Implements neither `Debug` nor `Clone`.
pub struct HmacKey(hmac::Key);

impl HmacKey {
    /// A key from exactly [`KEY_LEN`] secret bytes.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`] for any other length, or for a key of
    /// identical bytes (an all-zero or uninitialised buffer).
    pub fn new(bytes: &SecretBytes) -> Result<Self, CryptoError> {
        // SECRET-EXPOSURE: the key bytes are handed to the HMAC key schedule.
        #[expect(clippy::disallowed_methods)]
        let raw = bytes.expose_secret();
        if raw.len() != KEY_LEN || raw.iter().all(|b| *b == raw[0]) {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self(hmac::Key::new(hmac::HMAC_SHA256, raw)))
    }

    /// A fresh key from the operating system random generator.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Random`].
    pub fn generate() -> Result<SecretBytes, CryptoError> {
        let mut out = SecretBytes::from(vec![0u8; KEY_LEN]);
        // SECRET-EXPOSURE: the key buffer is filled in place, never copied.
        #[expect(clippy::disallowed_methods)]
        crate::rand::fill(out.expose_secret_mut())?;
        Ok(out)
    }

    /// The tag of the concatenation of `parts`, without copying them
    /// (domain-separated MACs: a prefix, then the data).
    pub fn tag(&self, parts: &[&[u8]]) -> [u8; TAG_LEN] {
        let mut context = hmac::Context::with_key(&self.0);
        for part in parts {
            context.update(part);
        }
        let tag = context.sign();
        let mut out = [0u8; TAG_LEN];
        out.copy_from_slice(tag.as_ref());
        out
    }

    /// Whether `tag` is the tag of `parts`, compared in constant time.
    pub fn verify(&self, parts: &[&[u8]], tag: &[u8]) -> bool {
        crate::constant_time_eq(&self.tag(parts), tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The RFC 4231 keys do not have our fixed length: a 32-byte key
    /// (bytes 1 to 32), checked against an independent implementation.
    #[test]
    fn known_answer_32_byte_key() {
        let key = HmacKey::new(&SecretBytes::from((1..=32).collect::<Vec<u8>>())).unwrap();
        let expected = hex("4d9d653fcd05f91cd858a20d50c74b604fe38f2cac49d9b0a7099584cf4fb35a");
        let tag = key.tag(&[b"what do ya want for nothing?"]);
        assert_eq!(tag.as_slice(), expected.as_slice());
        assert_eq!(tag, key.tag(&[b"what do ya ", b"", b"want for nothing?"]));
        assert!(key.verify(&[b"what do ya want for nothing?"], &tag));
    }

    #[test]
    fn rfc4231_case_2_through_aws_lc() {
        // The algorithm itself, with the RFC key (bypassing our length rule).
        let key = hmac::Key::new(hmac::HMAC_SHA256, b"Jefe");
        let tag = hmac::sign(&key, b"what do ya want for nothing?");
        assert_eq!(
            tag.as_ref(),
            hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843").as_slice()
        );
    }

    #[test]
    fn keys_of_another_length_or_constant_bytes_are_refused() {
        for bad in [
            vec![7u8; 31],
            vec![7u8; 33],
            vec![],
            vec![0u8; 32],
            vec![9u8; 32],
        ] {
            assert!(matches!(
                HmacKey::new(&SecretBytes::from(bad)),
                Err(CryptoError::InvalidKey)
            ));
        }
    }

    #[test]
    fn a_wrong_tag_or_key_does_not_verify() {
        let a = HmacKey::new(&HmacKey::generate().unwrap()).unwrap();
        let b = HmacKey::new(&HmacKey::generate().unwrap()).unwrap();
        let tag = a.tag(&[b"ls -la"]);
        assert!(!b.verify(&[b"ls -la"], &tag));
        assert!(!a.verify(&[b"ls -l"], &tag));
        assert!(!a.verify(&[b"ls -la"], &tag[..31]));
    }
}
