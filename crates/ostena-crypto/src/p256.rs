//! ECDSA on P-256 with SHA-256 (FIPS 186-5), fixed 64-byte signatures `r ‖ s`.
//!
//! ECDSA signatures are malleable: if `(r, s)` verifies, so does `(r, n − s)`.
//! To keep exactly one accepted signature per message and key, the signer
//! always produces the low form (`s ≤ (n − 1) / 2`) and the verifier refuses:
//!
//! - `r` or `s` equal to zero or not below the group order `n`;
//! - `s` above `(n − 1) / 2` (high-S);
//! - a public key that is not an uncompressed SEC1 point on the curve.
//!
//! These checks run before the library verification.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair,
    ParsedPublicKey,
};
use ostena_common::secret::SecretBytes;

use crate::CryptoError;

/// Length of a public key: SEC1 uncompressed, `0x04 ‖ x ‖ y`.
pub const PUBLIC_KEY_LEN: usize = 65;
/// Length of a signature: `r ‖ s`, 32 bytes each, big-endian.
pub const SIGNATURE_LEN: usize = 64;

/// The group order n, big-endian.
const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// (n − 1) / 2, big-endian: the largest accepted `s`.
const HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

/// `a < b` for 256-bit big-endian integers.
fn less_than(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a < b
}

/// `a − b` for 256-bit big-endian integers, `a ≥ b`.
fn sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = i16::from(a[i]) - i16::from(b[i]) - borrow;
        borrow = 0;
        if d < 0 {
            d += 256;
            borrow = 1;
        }
        out[i] = d.to_be_bytes()[1];
    }
    out
}

/// Non-zero and below n.
fn is_scalar(x: &[u8; 32]) -> bool {
    *x != [0; 32] && less_than(x, &N)
}

/// A private signing key. No `Debug`, no `Clone`.
pub struct SigningKey(EcdsaKeyPair);

impl SigningKey {
    /// Generates a key pair and returns it with its PKCS#8 encoding, to be
    /// stored as a secret.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Random`] if the system generator fails.
    pub fn generate() -> Result<(Self, SecretBytes), CryptoError> {
        let rng = SystemRandom::new();
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| CryptoError::Random)?;
        let pkcs8 = SecretBytes::from(document.as_ref().to_vec());
        let key = Self::from_pkcs8(&pkcs8)?;
        Ok((key, pkcs8))
    }

    /// Loads a key from its PKCS#8 encoding.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`] if the encoding is not a P-256 key.
    pub fn from_pkcs8(pkcs8: &SecretBytes) -> Result<Self, CryptoError> {
        // SECRET-EXPOSURE: the PKCS#8 document is parsed by aws-lc-rs.
        #[expect(clippy::disallowed_methods)]
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.expose_secret())
                .map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self(pair))
    }

    /// The matching public key.
    pub fn verifying_key(&self) -> VerifyingKey {
        let mut bytes = [0u8; PUBLIC_KEY_LEN];
        bytes.copy_from_slice(self.0.public_key().as_ref());
        VerifyingKey(bytes)
    }

    /// Signs `message` (hashed with SHA-256), always in the low-S form.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Signing`] if the library fails to sign.
    pub fn sign(&self, message: &[u8]) -> Result<Signature, CryptoError> {
        let signature = self
            .0
            .sign(&SystemRandom::new(), message)
            .map_err(|_| CryptoError::Signing)?;
        let mut bytes = [0u8; SIGNATURE_LEN];
        bytes.copy_from_slice(signature.as_ref());
        let (r, s) = Signature(bytes).parts();
        if less_than(&HALF_N, &s) {
            bytes[32..].copy_from_slice(&sub(&N, &s));
        }
        debug_assert!(is_scalar(&r));
        Ok(Signature(bytes))
    }
}

/// A public key, accepted only if it is an uncompressed point on the curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VerifyingKey([u8; PUBLIC_KEY_LEN]);

impl VerifyingKey {
    /// Parses an uncompressed SEC1 public key.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`] for another encoding or a point that is not
    /// on the curve.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LEN]) -> Result<Self, CryptoError> {
        if bytes[0] != 0x04 {
            return Err(CryptoError::InvalidKey);
        }
        ParsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, bytes)
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self(*bytes))
    }

    /// The 65-byte uncompressed SEC1 encoding.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0
    }

    /// Strict verification of `signature` over `message`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::BadSignature`] if the signature is invalid or not in its
    /// unique low-S form.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), CryptoError> {
        let (r, s) = signature.parts();
        if !is_scalar(&r) || !is_scalar(&s) || less_than(&HALF_N, &s) {
            return Err(CryptoError::BadSignature);
        }
        ParsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, self.0)
            .map_err(|_| CryptoError::BadSignature)?
            .verify_sig(message, &signature.0)
            .map_err(|_| CryptoError::BadSignature)
    }
}

/// A signature: `r ‖ s`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_LEN]);

impl Signature {
    /// Wraps 64 bytes; validity is only checked by [`VerifyingKey::verify`].
    pub fn from_bytes(bytes: &[u8; SIGNATURE_LEN]) -> Self {
        Self(*bytes)
    }

    /// The 64-byte encoding.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        self.0
    }

    fn parts(&self) -> ([u8; 32], [u8; 32]) {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&self.0[..32]);
        s.copy_from_slice(&self.0[32..]);
        (r, s)
    }
}

#[cfg(test)]
mod tests;
