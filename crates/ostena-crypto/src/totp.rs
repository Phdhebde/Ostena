//! Time-based one-time passwords (RFC 6238), the second factor of
//! `ostena login` (ADR-0009, amendment of 2026-11-25).
//!
//! - 6 digits, 30-second steps, one step of tolerance on each side;
//! - HMAC-SHA-1 by default, for the authenticator applications; HMAC-SHA-256
//!   as an option. HMAC-SHA-1 is a deviation from ANSSI-PG-083 recorded in
//!   ADR-0009: the HMAC construction does not rest on the collision
//!   resistance of SHA-1, and the code is a second factor bound to a
//!   30-second window, not a signature;
//! - secrets of 160 bits (SHA-1, RFC 4226 § 4) or 256 bits (SHA-256), drawn
//!   from the system generator and kept in a [`SecretBytes`];
//! - **anti-replay**: [`TotpSecret::verify`] refuses any step at or below
//!   the last step accepted for this secret, which the caller stores.

use aws_lc_rs::hmac;
use ostena_common::secret::{SecretBytes, SecretString};

/// Digits of a code.
pub const DIGITS: usize = 6;
/// Length of a step, in seconds.
pub const STEP_SECS: u64 = 30;
/// Steps accepted before and after the current one.
pub const SKEW_STEPS: u64 = 1;
/// Longest issuer or account name in a provisioning URI, in bytes.
pub const MAX_LABEL_LEN: usize = 64;

/// The HMAC of the codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TotpAlgorithm {
    /// HMAC-SHA-1, the default (compatibility with authenticator apps).
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
}

impl TotpAlgorithm {
    /// Name in the configuration and the database: `sha1` or `sha256`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }

    /// Parses [`TotpAlgorithm::as_str`].
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "sha1" => Some(Self::Sha1),
            "sha256" => Some(Self::Sha256),
            _ => None,
        }
    }

    /// Bytes of a secret for this algorithm.
    pub fn secret_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }

    fn uri_name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
        }
    }

    fn hmac(self) -> hmac::Algorithm {
        match self {
            Self::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => hmac::HMAC_SHA256,
        }
    }
}

/// TOTP errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TotpError {
    /// The code is not made of exactly six ASCII digits.
    #[error("code TOTP mal formé : six chiffres attendus")]
    Format,
    /// The code matches no step of the window.
    #[error("code TOTP incorrect")]
    Invalid,
    /// The code matches a step already used.
    #[error("code TOTP déjà utilisé")]
    Replayed,
    /// The secret has the wrong length for its algorithm.
    #[error("secret TOTP de longueur invalide")]
    SecretLength,
    /// An issuer or account name is unfit for a provisioning URI.
    #[error("nom invalide pour l'URI d'enrôlement : {0}")]
    Label(&'static str),
    /// The system random generator failed.
    #[error("échec du générateur d'aléa du système")]
    Random,
}

/// The step that contains `unix_secs`.
pub fn step_at(unix_secs: u64) -> u64 {
    unix_secs / STEP_SECS
}

/// A TOTP secret and its algorithm. No `Debug`.
pub struct TotpSecret {
    algorithm: TotpAlgorithm,
    key: hmac::Key,
    bytes: SecretBytes,
}

impl TotpSecret {
    /// Draws a secret for `algorithm`.
    ///
    /// # Errors
    ///
    /// [`TotpError::Random`].
    pub fn generate(algorithm: TotpAlgorithm) -> Result<Self, TotpError> {
        let mut bytes = SecretBytes::from(vec![0u8; algorithm.secret_len()]);
        // SECRET-EXPOSURE: the buffer is filled in place by the system generator.
        #[expect(clippy::disallowed_methods)]
        crate::rand::fill(bytes.expose_secret_mut()).map_err(|_| TotpError::Random)?;
        Self::from_bytes(algorithm, bytes)
    }

    /// Takes a stored secret.
    ///
    /// # Errors
    ///
    /// [`TotpError::SecretLength`] unless it has exactly
    /// [`TotpAlgorithm::secret_len`] bytes.
    pub fn from_bytes(algorithm: TotpAlgorithm, bytes: SecretBytes) -> Result<Self, TotpError> {
        // SECRET-EXPOSURE: the secret becomes the HMAC key.
        #[expect(clippy::disallowed_methods)]
        let raw = bytes.expose_secret();
        if raw.len() != algorithm.secret_len() {
            return Err(TotpError::SecretLength);
        }
        let key = hmac::Key::new(algorithm.hmac(), raw);
        Ok(Self {
            algorithm,
            key,
            bytes,
        })
    }

    /// The algorithm.
    pub fn algorithm(&self) -> TotpAlgorithm {
        self.algorithm
    }

    /// The raw secret, to be encrypted before it is stored.
    pub fn bytes(&self) -> &SecretBytes {
        &self.bytes
    }

    /// The HOTP value (RFC 4226 § 5.3) of `counter`, modulo 10^`digits`.
    fn hotp(&self, counter: u64, digits: u32) -> u32 {
        let tag = hmac::sign(&self.key, &counter.to_be_bytes());
        let mac = tag.as_ref();
        let offset = usize::from(mac[mac.len() - 1] & 0x0f);
        let binary = u32::from_be_bytes([
            mac[offset] & 0x7f,
            mac[offset + 1],
            mac[offset + 2],
            mac[offset + 3],
        ]);
        binary % 10u32.pow(digits)
    }

    /// The six-digit code of `step`, zero-padded. For tests and for the
    /// confirmation of an enrolment; never logged.
    pub fn code(&self, step: u64) -> SecretString {
        SecretString::from(format!("{:06}", self.hotp(step, 6)))
    }

    /// Checks `code` at `unix_secs`, against the steps from one before to
    /// one after the current one, and returns the step it matches.
    ///
    /// Every candidate is computed and compared in constant time. A step at
    /// or below `last_step` (the last one accepted for this secret, 0 if
    /// none) is refused as a replay: the caller stores the returned step,
    /// atomically with the login.
    ///
    /// # Errors
    ///
    /// [`TotpError::Format`], [`TotpError::Invalid`] or
    /// [`TotpError::Replayed`].
    pub fn verify(
        &self,
        code: &SecretString,
        unix_secs: u64,
        last_step: u64,
    ) -> Result<u64, TotpError> {
        // SECRET-EXPOSURE: the typed code is compared in constant time.
        #[expect(clippy::disallowed_methods)]
        let typed = code.expose_secret().as_bytes();
        if typed.len() != DIGITS || !typed.iter().all(u8::is_ascii_digit) {
            return Err(TotpError::Format);
        }
        let current = step_at(unix_secs);
        let mut matched: Option<u64> = None;
        for step in current.saturating_sub(SKEW_STEPS)..=current.saturating_add(SKEW_STEPS) {
            let expected = format!("{:06}", self.hotp(step, 6));
            let equal = crate::constant_time_eq(expected.as_bytes(), typed);
            let mut expected = expected.into_bytes();
            zeroize::Zeroize::zeroize(&mut expected);
            if equal {
                matched = Some(matched.map_or(step, |m| m.max(step)));
            }
        }
        match matched {
            None => Err(TotpError::Invalid),
            Some(step) if step <= last_step => Err(TotpError::Replayed),
            Some(step) => Ok(step),
        }
    }

    /// The secret in base32 (RFC 4648, no padding), for manual entry.
    pub fn base32(&self) -> SecretString {
        // SECRET-EXPOSURE: encoded into a new secret, shown once at enrolment.
        #[expect(clippy::disallowed_methods)]
        let raw = self.bytes.expose_secret();
        SecretString::from(base32(raw))
    }

    /// The provisioning URI read by authenticator applications:
    /// `otpauth://totp/<issuer>:<account>?secret=…&issuer=…&algorithm=…&digits=6&period=30`.
    /// It contains the secret.
    ///
    /// # Errors
    ///
    /// [`TotpError::Label`] if `issuer` or `account` is empty, longer than
    /// [`MAX_LABEL_LEN`], or holds `:` or a control character.
    pub fn provisioning_uri(&self, issuer: &str, account: &str) -> Result<SecretString, TotpError> {
        check_label(issuer)?;
        check_label(account)?;
        let secret = self.base32();
        let issuer = percent_encode(issuer);
        // SECRET-EXPOSURE: the secret is written into the URI, itself a secret.
        #[expect(clippy::disallowed_methods)]
        let uri = format!(
            "otpauth://totp/{issuer}:{}?secret={}&issuer={issuer}&algorithm={}&digits={DIGITS}&period={STEP_SECS}",
            percent_encode(account),
            secret.expose_secret(),
            self.algorithm.uri_name(),
        );
        Ok(SecretString::from(uri))
    }
}

fn check_label(label: &str) -> Result<(), TotpError> {
    if label.is_empty() || label.len() > MAX_LABEL_LEN {
        return Err(TotpError::Label("de 1 à 64 octets"));
    }
    if label.contains(':') {
        return Err(TotpError::Label("deux-points interdit"));
    }
    if label.chars().any(char::is_control) {
        return Err(TotpError::Label("caractère de contrôle"));
    }
    Ok(())
}

/// Percent-encodes everything but the unreserved characters (RFC 3986).
fn percent_encode(text: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Base32 (RFC 4648 § 6), without padding.
fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut bits = 0u16;
    let mut count = 0;
    for &b in bytes {
        bits = (bits << 8) | u16::from(b);
        count += 8;
        while count >= 5 {
            count -= 5;
            out.push(char::from(ALPHABET[usize::from((bits >> count) & 0x1f)]));
        }
        bits &= (1 << count) - 1;
    }
    if count > 0 {
        out.push(char::from(
            ALPHABET[usize::from((bits << (5 - count)) & 0x1f)],
        ));
    }
    out
}

#[cfg(test)]
mod tests;
