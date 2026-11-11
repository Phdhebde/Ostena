//! Ed25519 (RFC 8032) signatures with strict verification.
//!
//! On top of `aws-lc-rs`, verification refuses every non-canonical or weak
//! encoding, so that one message has exactly one accepted signature per key:
//!
//! - public key and `R`: the y coordinate must be below p (canonical), and the
//!   point must not have small order (identity, order 2, 4 or 8);
//! - `S` must be below the group order L (no malleability by adding L).
//!
//! These are encoding checks only, run before the library verification.

use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use ostena_common::secret::SecretBytes;

use crate::CryptoError;

/// Length of a public key.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of a signature.
pub const SIGNATURE_LEN: usize = 64;

/// The field prime p = 2^255 − 19, little-endian.
const P: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// The group order L = 2^252 + 27742317777372353535851937790883648493, little-endian.
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// y coordinates (sign bit cleared) of the points of small order:
/// 0 (order 4), 1 (identity), p − 1 (order 2) and the two of order 8.
const SMALL_ORDER_Y: [[u8; 32]; 5] = [
    [0; 32],
    [
        0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ],
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ],
];

/// `a < b` for 256-bit little-endian integers.
fn less_than(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

/// y coordinate of a point encoding, sign bit cleared.
fn y_of(point: &[u8; 32]) -> [u8; 32] {
    let mut y = *point;
    y[31] &= 0x7f;
    y
}

/// Canonical and not of small order.
fn is_strict_point(point: &[u8; 32]) -> bool {
    let y = y_of(point);
    less_than(&y, &P) && !SMALL_ORDER_Y.contains(&y)
}

/// A private signing key. No `Debug`, no `Clone`.
pub struct SigningKey(Ed25519KeyPair);

impl SigningKey {
    /// Generates a key pair and returns it with its PKCS#8 v2 encoding, to be
    /// stored as a secret.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Random`] if the system generator fails.
    pub fn generate() -> Result<(Self, SecretBytes), CryptoError> {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let document = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| CryptoError::Random)?;
        let pkcs8 = SecretBytes::from(document.as_ref().to_vec());
        let key = Self::from_pkcs8(&pkcs8)?;
        Ok((key, pkcs8))
    }

    /// Loads a key from its PKCS#8 encoding.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`] if the encoding is not an Ed25519 key.
    pub fn from_pkcs8(pkcs8: &SecretBytes) -> Result<Self, CryptoError> {
        // SECRET-EXPOSURE: the PKCS#8 document is parsed by aws-lc-rs.
        #[expect(clippy::disallowed_methods)]
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.expose_secret())
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self(pair))
    }

    /// The matching public key.
    pub fn verifying_key(&self) -> VerifyingKey {
        let mut bytes = [0u8; PUBLIC_KEY_LEN];
        bytes.copy_from_slice(self.0.public_key().as_ref());
        VerifyingKey(bytes)
    }

    /// Signs `message`.
    pub fn sign(&self, message: &[u8]) -> Signature {
        let mut bytes = [0u8; SIGNATURE_LEN];
        bytes.copy_from_slice(self.0.sign(message).as_ref());
        Signature(bytes)
    }
}

/// A public key, accepted only if strictly valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VerifyingKey([u8; PUBLIC_KEY_LEN]);

impl VerifyingKey {
    /// Parses a public key.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InvalidKey`] for a non-canonical or small-order point.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LEN]) -> Result<Self, CryptoError> {
        if is_strict_point(bytes) {
            Ok(Self(*bytes))
        } else {
            Err(CryptoError::InvalidKey)
        }
    }

    /// The 32-byte encoding.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0
    }

    /// Strict verification of `signature` over `message`.
    ///
    /// # Errors
    ///
    /// [`CryptoError::BadSignature`] if the signature is invalid or not in its
    /// unique canonical form.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), CryptoError> {
        let (r, s) = signature.parts();
        if !is_strict_point(&r) || !less_than(&s, &L) {
            return Err(CryptoError::BadSignature);
        }
        UnparsedPublicKey::new(&ED25519, &self.0)
            .verify(message, &signature.0)
            .map_err(|_| CryptoError::BadSignature)
    }
}

/// A signature: `R ‖ S`.
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
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn key() -> SigningKey {
        SigningKey::generate().unwrap().0
    }

    /// a + b for 256-bit little-endian integers (no overflow in our uses).
    fn add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut carry = 0u16;
        for i in 0..32 {
            let sum = u16::from(a[i]) + u16::from(b[i]) + carry;
            out[i] = (sum & 0xff) as u8;
            carry = sum >> 8;
        }
        out
    }

    #[test]
    fn sign_and_verify() {
        let k = key();
        let sig = k.sign(b"message");
        assert!(k.verifying_key().verify(b"message", &sig).is_ok());
        assert_eq!(
            k.verifying_key().verify(b"messagf", &sig),
            Err(CryptoError::BadSignature)
        );
        assert_eq!(
            key().verifying_key().verify(b"message", &sig),
            Err(CryptoError::BadSignature)
        );
    }

    #[test]
    fn pkcs8_round_trip() {
        let (k, pkcs8) = SigningKey::generate().unwrap();
        let reloaded = SigningKey::from_pkcs8(&pkcs8).unwrap();
        assert_eq!(k.verifying_key(), reloaded.verifying_key());
        assert!(SigningKey::from_pkcs8(&SecretBytes::from(vec![0; 48])).is_err());
    }

    #[test]
    fn rfc8032_test_1() {
        // RFC 8032 section 7.1, TEST 1 (empty message).
        let pk = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        let sig = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
            0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
            0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
            0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];
        let key = VerifyingKey::from_bytes(&pk).unwrap();
        assert!(key.verify(b"", &Signature::from_bytes(&sig)).is_ok());
    }

    #[test]
    fn malleated_s_is_refused() {
        let k = key();
        let sig = k.sign(b"m").to_bytes();
        let (r, s) = Signature::from_bytes(&sig).parts();
        let mut malleated = [0u8; 64];
        malleated[..32].copy_from_slice(&r);
        malleated[32..].copy_from_slice(&add(&s, &L));
        assert_eq!(
            k.verifying_key()
                .verify(b"m", &Signature::from_bytes(&malleated)),
            Err(CryptoError::BadSignature)
        );
    }

    #[test]
    fn order_8_points_are_opposite() {
        // Sanity check of the constants: the two order-8 y values sum to p.
        assert_eq!(add(&SMALL_ORDER_Y[3], &SMALL_ORDER_Y[4]), P);
        assert_eq!(add(&SMALL_ORDER_Y[2], &SMALL_ORDER_Y[1]), P);
    }

    #[test]
    fn weak_public_keys_are_refused() {
        for y in SMALL_ORDER_Y {
            for sign in [0u8, 0x80] {
                let mut encoding = y;
                encoding[31] |= sign;
                assert_eq!(
                    VerifyingKey::from_bytes(&encoding),
                    Err(CryptoError::InvalidKey)
                );
            }
        }
        // Non-canonical: y = p and y = p + 2 (≥ p).
        let mut p_plus_2 = P;
        p_plus_2[0] = 0xef;
        assert!(VerifyingKey::from_bytes(&P).is_err());
        assert!(VerifyingKey::from_bytes(&p_plus_2).is_err());
    }

    #[test]
    fn small_order_r_is_refused() {
        let k = key();
        let mut sig = k.sign(b"m").to_bytes();
        sig[..32].copy_from_slice(&SMALL_ORDER_Y[1]);
        assert_eq!(
            k.verifying_key().verify(b"m", &Signature::from_bytes(&sig)),
            Err(CryptoError::BadSignature)
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn prop_any_bit_flip_in_signature_is_refused(msg in proptest::collection::vec(any::<u8>(), 0..64), bit in 0usize..512) {
            let k = key();
            let mut sig = k.sign(&msg).to_bytes();
            sig[bit / 8] ^= 1 << (bit % 8);
            prop_assert!(k.verifying_key().verify(&msg, &Signature::from_bytes(&sig)).is_err());
        }
    }
}
