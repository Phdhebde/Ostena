//! HKDF (RFC 5869) with SHA-256, the only hash offered.

use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Salt};
use ostena_common::secret::SecretBytes;

use crate::CryptoError;

/// Largest output allowed by RFC 5869 for SHA-256 (255 × 32 bytes).
pub const MAX_OUTPUT_LEN: usize = 255 * 32;

struct Len(usize);

impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// Derives `len` bytes from `ikm` with HKDF-SHA-256 (extract then expand).
///
/// # Errors
///
/// [`CryptoError::Derivation`] if `len` is 0 or above [`MAX_OUTPUT_LEN`].
pub fn derive(
    salt: &[u8],
    ikm: &SecretBytes,
    info: &[u8],
    len: usize,
) -> Result<SecretBytes, CryptoError> {
    if len == 0 || len > MAX_OUTPUT_LEN {
        return Err(CryptoError::Derivation);
    }
    // SECRET-EXPOSURE: the input key material is handed to HKDF-Extract.
    #[expect(clippy::disallowed_methods)]
    let prk = Salt::new(HKDF_SHA256, salt).extract(ikm.expose_secret());
    let info = [info];
    let okm = prk
        .expand(&info, Len(len))
        .map_err(|_| CryptoError::Derivation)?;
    let mut out = SecretBytes::from(vec![0u8; len]);
    // SECRET-EXPOSURE: the output buffer is filled in place, never copied.
    #[expect(clippy::disallowed_methods)]
    okm.fill(out.expose_secret_mut())
        .map_err(|_| CryptoError::Derivation)?;
    Ok(out)
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

    #[test]
    fn rfc5869_test_case_1() {
        let ikm = SecretBytes::from(vec![0x0b; 22]);
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let okm = derive(&salt, &ikm, &info, 42).unwrap();
        let expected = hex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        );
        // SECRET-EXPOSURE: test compares against the RFC vector.
        #[expect(clippy::disallowed_methods)]
        let out = okm.expose_secret();
        assert_eq!(out, expected.as_slice());
    }

    #[test]
    fn length_bounds() {
        let ikm = SecretBytes::from(vec![1; 32]);
        assert_eq!(
            derive(b"", &ikm, b"", 0).err(),
            Some(CryptoError::Derivation)
        );
        assert!(derive(b"", &ikm, b"", MAX_OUTPUT_LEN).is_ok());
        assert_eq!(
            derive(b"", &ikm, b"", MAX_OUTPUT_LEN + 1).err(),
            Some(CryptoError::Derivation)
        );
    }
}
