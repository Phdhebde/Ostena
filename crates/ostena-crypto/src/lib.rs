//! The only crate allowed to call cryptographic primitives.
//!
//! A thin facade over `aws-lc-rs`; `deny.toml` refuses `aws-lc-rs` as a direct
//! dependency of any other crate, and refuses `ring` everywhere. Algorithms are
//! fixed and never negotiated:
//!
//! - [`p256`] — ECDSA P-256 / SHA-256 signatures, with strict verification;
//! - [`rand`] — operating system randomness;
//! - [`hkdf`] — HKDF-SHA-256;
//! - [`sha256`] — digests.

#![forbid(unsafe_code)]

pub mod hkdf;
pub mod p256;
pub mod pki;
pub mod rand;
pub mod sha256;
pub mod tls;

/// Errors raised by this crate. Deliberately coarse: callers must not be able
/// to tell apart the reasons of a cryptographic failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// The operating system random generator failed.
    #[error("échec du générateur d'aléa du système")]
    Random,
    /// A key is malformed or not acceptable.
    #[error("clé invalide")]
    InvalidKey,
    /// A signature does not verify.
    #[error("signature invalide")]
    BadSignature,
    /// A key derivation request is out of bounds.
    #[error("paramètres de dérivation de clé invalides")]
    Derivation,
    /// The library failed to produce a signature.
    #[error("échec de la signature")]
    Signing,
}
