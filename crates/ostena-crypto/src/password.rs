//! Password hashing for local identities (ADR-0009, amendment of
//! 2026-11-25): PBKDF2-HMAC-SHA256, 600 000 iterations, a random 16-byte
//! salt, a 32-byte digest.
//!
//! The parameters travel with the digest, so that they can evolve without a
//! migration: a digest with fewer iterations than [`ITERATIONS`] still
//! verifies, and [`PasswordHash::needs_rehash`] tells the caller to store a
//! new one after the next successful login.
//!
//! Encoded form, canonical (only one encoding per digest):
//!
//! ```text
//! $ostena-pbkdf2-sha256$v=1$i=600000$<salt>$<digest>
//! ```
//!
//! where the salt and the digest are standard base64 without padding, and
//! the iterations are written in decimal without a leading zero.
//!
//! A password is taken as the bytes typed, without Unicode normalisation:
//! normalising would need the Unicode tables that `deny.toml` refuses. The
//! administrator and the user type it on the same kind of keyboard.

use std::fmt;
use std::num::NonZeroU32;
use std::ops::RangeInclusive;

use aws_lc_rs::pbkdf2;
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use ostena_common::secret::SecretString;

/// Iterations written by [`hash`].
pub const ITERATIONS: u32 = 600_000;
/// Iterations accepted when parsing: the floor of the policy, and a ceiling
/// so that a value forced into the database cannot stall the core.
pub const ACCEPTED_ITERATIONS: RangeInclusive<u32> = ITERATIONS..=10_000_000;
/// Bytes of the salt.
pub const SALT_LEN: usize = 16;
/// Bytes of the digest.
pub const DIGEST_LEN: usize = 32;
/// Longest password, in bytes.
pub const MAX_PASSWORD_LEN: usize = 1024;

const PREFIX: &str = "$ostena-pbkdf2-sha256$v=1$i=";

/// Password errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PasswordError {
    /// The stored digest is not in the expected format.
    #[error("condensat de mot de passe mal formé")]
    Format,
    /// The password is empty or longer than 1024 bytes.
    #[error("mot de passe vide ou de plus de 1024 octets")]
    Length,
    /// The password does not match.
    #[error("mot de passe incorrect")]
    Mismatch,
    /// The system random generator failed.
    #[error("échec du générateur d'aléa du système")]
    Random,
}

/// A stored password digest with its parameters.
///
/// Not a secret in the sense of `Secret<…>` (it is stored in the database),
/// but it allows an offline guessing attack: its `Debug` form shows only
/// the iterations.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordHash {
    iterations: u32,
    salt: [u8; SALT_LEN],
    digest: [u8; DIGEST_LEN],
}

impl fmt::Debug for PasswordHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordHash")
            .field("iterations", &self.iterations)
            .finish_non_exhaustive()
    }
}

impl PasswordHash {
    /// Parses the encoded form.
    ///
    /// # Errors
    ///
    /// [`PasswordError::Format`] for anything but the canonical encoding,
    /// or iterations outside [`ACCEPTED_ITERATIONS`].
    pub fn parse(text: &str) -> Result<Self, PasswordError> {
        let rest = text.strip_prefix(PREFIX).ok_or(PasswordError::Format)?;
        let mut parts = rest.split('$');
        let (Some(iterations), Some(salt), Some(digest), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(PasswordError::Format);
        };
        if iterations.is_empty()
            || iterations.starts_with('0')
            || !iterations.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(PasswordError::Format);
        }
        let iterations: u32 = iterations.parse().map_err(|_| PasswordError::Format)?;
        if !ACCEPTED_ITERATIONS.contains(&iterations) {
            return Err(PasswordError::Format);
        }
        let salt = decode::<SALT_LEN>(salt)?;
        let digest = decode::<DIGEST_LEN>(digest)?;
        Ok(Self {
            iterations,
            salt,
            digest,
        })
    }

    /// The encoded form, for the database.
    pub fn encode(&self) -> String {
        format!(
            "{PREFIX}{}${}${}",
            self.iterations,
            STANDARD_NO_PAD.encode(self.salt),
            STANDARD_NO_PAD.encode(self.digest)
        )
    }

    /// The iterations of this digest.
    pub fn iterations(&self) -> u32 {
        self.iterations
    }

    /// Whether the digest was made with other parameters than the current
    /// ones: store a new one after the next successful verification.
    pub fn needs_rehash(&self) -> bool {
        self.iterations != ITERATIONS
    }
}

/// Decodes canonical base64 without padding into exactly `N` bytes.
fn decode<const N: usize>(text: &str) -> Result<[u8; N], PasswordError> {
    let bytes = STANDARD_NO_PAD
        .decode(text)
        .map_err(|_| PasswordError::Format)?;
    let out: [u8; N] = bytes.try_into().map_err(|_| PasswordError::Format)?;
    // The decoder refuses trailing bits; re-encoding proves canonicity.
    if STANDARD_NO_PAD.encode(out) != text {
        return Err(PasswordError::Format);
    }
    Ok(out)
}

fn check_length(password: &SecretString) -> Result<(), PasswordError> {
    // SECRET-EXPOSURE: only the length is read.
    #[expect(clippy::disallowed_methods)]
    let len = password.expose_secret().len();
    if len == 0 || len > MAX_PASSWORD_LEN {
        return Err(PasswordError::Length);
    }
    Ok(())
}

fn derive(password: &SecretString, salt: &[u8], iterations: NonZeroU32) -> [u8; DIGEST_LEN] {
    let mut out = [0u8; DIGEST_LEN];
    // SECRET-EXPOSURE: the password is handed to PBKDF2.
    #[expect(clippy::disallowed_methods)]
    let secret = password.expose_secret().as_bytes();
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        secret,
        &mut out,
    );
    out
}

fn iterations(n: u32) -> Result<NonZeroU32, PasswordError> {
    NonZeroU32::new(n).ok_or(PasswordError::Format)
}

/// Hashes `password` with a fresh salt and the current parameters.
///
/// # Errors
///
/// [`PasswordError::Length`] or [`PasswordError::Random`].
pub fn hash(password: &SecretString) -> Result<PasswordHash, PasswordError> {
    check_length(password)?;
    let salt = crate::rand::array::<SALT_LEN>().map_err(|_| PasswordError::Random)?;
    let digest = derive(password, &salt, iterations(ITERATIONS)?);
    Ok(PasswordHash {
        iterations: ITERATIONS,
        salt,
        digest,
    })
}

/// Checks `password` against `stored`, in constant time.
///
/// # Errors
///
/// [`PasswordError::Mismatch`], or [`PasswordError::Length`] for a
/// password that [`hash`] would not have accepted (the time spent is the
/// same: the derivation still runs).
pub fn verify(password: &SecretString, stored: &PasswordHash) -> Result<(), PasswordError> {
    let length = check_length(password);
    // SECRET-EXPOSURE: the password is handed to PBKDF2 verification.
    #[expect(clippy::disallowed_methods)]
    let secret = password.expose_secret().as_bytes();
    let matched = pbkdf2::verify(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations(stored.iterations)?,
        &stored.salt,
        secret,
        &stored.digest,
    );
    length?;
    matched.map_err(|_| PasswordError::Mismatch)
}

/// Spends the time of a verification at the current parameters, for an
/// unknown user, so that response times do not tell which accounts exist.
pub fn dummy_verify(password: &SecretString) {
    let salt = [0u8; SALT_LEN];
    if let Ok(n) = iterations(ITERATIONS) {
        let _ = derive(password, &salt, n);
    }
}

#[cfg(test)]
mod tests;
