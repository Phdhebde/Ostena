//! The only crate allowed to call cryptographic primitives.
//!
//! A thin facade over `aws-lc-rs`; `deny.toml` refuses `aws-lc-rs` as a direct
//! dependency of any other crate, and refuses `ring` everywhere. Algorithms are
//! fixed and never negotiated:
//!
//! - [`ed25519`] — signatures, with strict verification;
//! - [`rand`] — operating system randomness;
//! - [`hkdf`] — HKDF-SHA-256;
//! - [`sha256`] — digests.

#![forbid(unsafe_code)]

pub mod ed25519;
pub mod hkdf;
pub mod rand;
pub mod sha256;

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
}
