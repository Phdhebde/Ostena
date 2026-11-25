//! AES-256-GCM encryption of small secrets at rest (ADR-0009), such as the
//! TOTP secrets in the core database.
//!
//! Format: version (`0x01`) ‖ nonce (12 random bytes) ‖ ciphertext ‖ tag
//! (16). The version byte is authenticated with the caller's associated
//! data, which binds a ciphertext to its row (for example the user
//! identifier): a ciphertext moved to another row does not open.
//!
//! Random 96-bit nonces: safe well beyond the number of secrets a core
//! stores (the bound is 2^32 encryptions per key).

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ostena_common::secret::SecretBytes;

use crate::CryptoError;

/// Bytes of a key.
pub const KEY_LEN: usize = 32;
const VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// Bytes added to the plaintext.
pub const OVERHEAD: usize = 1 + NONCE_LEN + TAG_LEN;

/// An AES-256-GCM key. No `Debug`.
pub struct AeadKey(LessSafeKey);

impl AeadKey {
    /// Takes a 32-byte key.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`] for another length.
    pub fn from_bytes(key: &SecretBytes) -> Result<Self, CryptoError> {
        // SECRET-EXPOSURE: the key is handed to AES-GCM.
        #[expect(clippy::disallowed_methods)]
        let raw = key.expose_secret();
        if raw.len() != KEY_LEN {
            return Err(CryptoError::InvalidKey);
        }
        let unbound = UnboundKey::new(&AES_256_GCM, raw).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self(LessSafeKey::new(unbound)))
    }

    /// Draws a new key and returns it with its bytes, to be stored.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Random`].
    pub fn generate() -> Result<(Self, SecretBytes), CryptoError> {
        let mut bytes = SecretBytes::from(vec![0u8; KEY_LEN]);
        // SECRET-EXPOSURE: the buffer is filled in place by the system generator.
        #[expect(clippy::disallowed_methods)]
        crate::rand::fill(bytes.expose_secret_mut())?;
        Ok((Self::from_bytes(&bytes)?, bytes))
    }

    /// Encrypts `plaintext`, bound to `aad`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Random`], or [`CryptoError::Decrypt`] if the library
    /// fails.
    pub fn seal(&self, plaintext: &SecretBytes, aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = crate::rand::array::<NONCE_LEN>()?;
        // SECRET-EXPOSURE: the plaintext is encrypted in place.
        #[expect(clippy::disallowed_methods)]
        let mut body = plaintext.expose_secret().to_vec();
        let sealed = self.0.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(associated(aad)),
            &mut body,
        );
        if sealed.is_err() {
            zeroize::Zeroize::zeroize(&mut body);
            return Err(CryptoError::Decrypt);
        }
        let mut out = Vec::with_capacity(OVERHEAD + plaintext_len(&body));
        out.push(VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decrypts what [`AeadKey::seal`] produced with the same `aad`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Decrypt`] for another key, another `aad`, another
    /// version or an altered ciphertext; the reasons are not told apart.
    pub fn open(&self, sealed: &[u8], aad: &[u8]) -> Result<SecretBytes, CryptoError> {
        if sealed.len() < OVERHEAD || sealed[0] != VERSION {
            return Err(CryptoError::Decrypt);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&sealed[1..=NONCE_LEN]);
        let mut body = sealed[1 + NONCE_LEN..].to_vec();
        let opened = self
            .0
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(associated(aad)),
                &mut body,
            )
            .map(|plain| SecretBytes::from(plain.to_vec()));
        zeroize::Zeroize::zeroize(&mut body);
        opened.map_err(|_| CryptoError::Decrypt)
    }
}

fn plaintext_len(body_with_tag: &[u8]) -> usize {
    body_with_tag.len().saturating_sub(TAG_LEN)
}

/// The version byte, then the caller's associated data.
fn associated(aad: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + aad.len());
    out.push(VERSION);
    out.extend_from_slice(aad);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(bytes: &SecretBytes) -> Vec<u8> {
        // SECRET-EXPOSURE: test assertion on a throwaway value.
        #[expect(clippy::disallowed_methods)]
        let v = bytes.expose_secret().to_vec();
        v
    }

    #[test]
    fn round_trip_and_binding() {
        let (key, bytes) = AeadKey::generate().unwrap();
        let secret = SecretBytes::from(b"totp secret bytes!!!".to_vec());
        let sealed = key.seal(&secret, b"user-1").unwrap();
        assert_eq!(sealed.len(), 20 + OVERHEAD);
        assert_eq!(
            plain(&key.open(&sealed, b"user-1").unwrap()),
            b"totp secret bytes!!!"
        );
        // The same key rebuilt from its bytes opens it.
        let again = AeadKey::from_bytes(&bytes).unwrap();
        assert!(again.open(&sealed, b"user-1").is_ok());
        // Another row, another key, a flipped bit, another version: refused.
        assert_eq!(
            key.open(&sealed, b"user-2").err(),
            Some(CryptoError::Decrypt)
        );
        let (other, _) = AeadKey::generate().unwrap();
        assert_eq!(
            other.open(&sealed, b"user-1").err(),
            Some(CryptoError::Decrypt)
        );
        for i in 0..sealed.len() {
            let mut altered = sealed.clone();
            altered[i] ^= 1;
            assert_eq!(
                key.open(&altered, b"user-1").err(),
                Some(CryptoError::Decrypt)
            );
        }
        assert_eq!(
            key.open(&sealed[..OVERHEAD - 1], b"user-1").err(),
            Some(CryptoError::Decrypt)
        );
        // Fresh nonce each time.
        assert_ne!(key.seal(&secret, b"user-1").unwrap(), sealed);
    }

    #[test]
    fn key_length() {
        assert!(AeadKey::from_bytes(&SecretBytes::from(vec![0; 31])).is_err());
        assert!(AeadKey::from_bytes(&SecretBytes::from(vec![0; 16])).is_err());
        assert!(AeadKey::from_bytes(&SecretBytes::from(vec![0; 32])).is_ok());
    }
}
