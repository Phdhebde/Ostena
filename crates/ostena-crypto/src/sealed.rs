//! Sealing of the offline root key (ADR-0008, root ceremony).
//!
//! The passphrase is not chosen by a person: it is drawn here, 30 base32
//! characters (150 bits), so that the sealed file cannot be attacked offline
//! by guessing (ANSSI-PG-083 `RègleSecretFaibleEntropie`). It is shown once,
//! in six groups of five, to be written in the ceremony record and split
//! between two custodians.
//!
//! Format: `OSTSEAL1` ‖ iterations (u32, big-endian) ‖ salt (16) ‖ nonce (12)
//! ‖ AES-256-GCM(key, nonce, aad = the 40 header bytes, PKCS#8), where key =
//! PBKDF2-HMAC-SHA256(passphrase, salt, iterations). The derivation only
//! adds margin: the passphrase already has full entropy.

use std::num::NonZeroU32;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::pbkdf2;
use ostena_common::secret::SecretBytes;

const MAGIC: &[u8; 8] = b"OSTSEAL1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = MAGIC.len() + 4 + SALT_LEN + NONCE_LEN;
const TAG_LEN: usize = 16;
/// Iterations written by [`seal`].
pub const ITERATIONS: u32 = 600_000;
/// Iterations accepted by [`open`].
const ACCEPTED_ITERATIONS: std::ops::RangeInclusive<u32> = 600_000..=10_000_000;

/// Crockford base32 alphabet: no I, L, O, U.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Characters of a passphrase.
pub const PASSPHRASE_LEN: usize = 30;

/// Sealing errors, coarse on purpose: a wrong passphrase and a damaged file
/// are not told apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SealError {
    /// Not a sealed file of this format.
    #[error("fichier scellé mal formé")]
    Format,
    /// The passphrase is not 30 base32 characters.
    #[error("phrase secrète mal formée : 30 caractères base32 attendus")]
    Passphrase,
    /// Wrong passphrase or altered file.
    #[error("ouverture impossible : phrase secrète fausse ou fichier altéré")]
    Open,
    /// Random generation failed.
    #[error("échec du générateur d'aléa du système")]
    Random,
}

/// A generated passphrase. No `Debug`.
pub struct Passphrase(SecretBytes);

impl Passphrase {
    /// Draws a passphrase from the system generator.
    ///
    /// # Errors
    ///
    /// [`SealError::Random`].
    pub fn generate() -> Result<Self, SealError> {
        let random = crate::rand::array::<PASSPHRASE_LEN>().map_err(|_| SealError::Random)?;
        let chars: Vec<u8> = random
            .iter()
            .map(|b| ALPHABET[usize::from(b & 0x1f)])
            .collect();
        Ok(Self(SecretBytes::from(chars)))
    }

    /// Parses a passphrase typed back: spaces and dashes are ignored, case
    /// too, and the Crockford substitutions (O→0, I/L→1) are applied.
    ///
    /// # Errors
    ///
    /// [`SealError::Passphrase`].
    pub fn parse(text: &SecretBytes) -> Result<Self, SealError> {
        // SECRET-EXPOSURE: the typed passphrase is normalised into a new secret.
        #[expect(clippy::disallowed_methods)]
        let typed = text.expose_secret();
        let mut chars = Vec::with_capacity(PASSPHRASE_LEN);
        for &b in typed {
            let c = match b.to_ascii_uppercase() {
                b' ' | b'-' | b'\t' | b'\r' | b'\n' => continue,
                b'O' => b'0',
                b'I' | b'L' => b'1',
                c => c,
            };
            if !ALPHABET.contains(&c) {
                return Err(SealError::Passphrase);
            }
            chars.push(c);
        }
        if chars.len() != PASSPHRASE_LEN {
            return Err(SealError::Passphrase);
        }
        Ok(Self(SecretBytes::from(chars)))
    }

    /// Six groups of five characters, for the ceremony record.
    pub fn groups(&self) -> [String; 6] {
        // SECRET-EXPOSURE: shown once to the custodians during the ceremony.
        #[expect(clippy::disallowed_methods)]
        let chars = self.0.expose_secret();
        std::array::from_fn(|i| String::from_utf8_lossy(&chars[i * 5..i * 5 + 5]).into_owned())
    }

    fn key(&self, salt: &[u8], iterations: u32) -> Result<LessSafeKey, SealError> {
        let iterations = NonZeroU32::new(iterations).ok_or(SealError::Format)?;
        let mut key = [0u8; 32];
        // SECRET-EXPOSURE: the passphrase feeds the key derivation.
        #[expect(clippy::disallowed_methods)]
        let secret = self.0.expose_secret();
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            iterations,
            salt,
            secret,
            &mut key,
        );
        let unbound = UnboundKey::new(&AES_256_GCM, &key).map_err(|_| SealError::Open);
        zeroize::Zeroize::zeroize(&mut key);
        Ok(LessSafeKey::new(unbound?))
    }
}

/// Seals `plaintext` under `passphrase`.
///
/// # Errors
///
/// [`SealError::Random`] or [`SealError::Open`] if the library fails.
pub fn seal(plaintext: &SecretBytes, passphrase: &Passphrase) -> Result<Vec<u8>, SealError> {
    let salt = crate::rand::array::<SALT_LEN>().map_err(|_| SealError::Random)?;
    let nonce = crate::rand::array::<NONCE_LEN>().map_err(|_| SealError::Random)?;
    let mut out = Vec::with_capacity(HEADER_LEN + TAG_LEN + 256);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&ITERATIONS.to_be_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    let key = passphrase.key(&salt, ITERATIONS)?;
    // SECRET-EXPOSURE: the key is encrypted in place in the output buffer.
    #[expect(clippy::disallowed_methods)]
    let mut body = plaintext.expose_secret().to_vec();
    let sealed = key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(&out[..HEADER_LEN]),
        &mut body,
    );
    if sealed.is_err() {
        zeroize::Zeroize::zeroize(&mut body);
        return Err(SealError::Open);
    }
    out.extend_from_slice(&body);
    Ok(out)
}

/// Opens a sealed file.
///
/// # Errors
///
/// [`SealError::Format`] for another format or out-of-range iterations,
/// [`SealError::Open`] for a wrong passphrase or an altered file.
pub fn open(sealed: &[u8], passphrase: &Passphrase) -> Result<SecretBytes, SealError> {
    if sealed.len() < HEADER_LEN + TAG_LEN || &sealed[..MAGIC.len()] != MAGIC {
        return Err(SealError::Format);
    }
    let mut iterations = [0u8; 4];
    iterations.copy_from_slice(&sealed[8..12]);
    let iterations = u32::from_be_bytes(iterations);
    if !ACCEPTED_ITERATIONS.contains(&iterations) {
        return Err(SealError::Format);
    }
    let salt = &sealed[12..12 + SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&sealed[12 + SALT_LEN..HEADER_LEN]);
    let key = passphrase.key(salt, iterations)?;
    let mut body = sealed[HEADER_LEN..].to_vec();
    match key.open_in_place(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(&sealed[..HEADER_LEN]),
        &mut body,
    ) {
        Ok(plain) => {
            let plain = SecretBytes::from(plain.to_vec());
            zeroize::Zeroize::zeroize(&mut body);
            Ok(plain)
        }
        Err(_) => Err(SealError::Open),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(text: &str) -> SecretBytes {
        SecretBytes::from(text.as_bytes().to_vec())
    }

    #[test]
    fn round_trip_and_typed_back_passphrase() {
        let p = Passphrase::generate().unwrap();
        let sealed = seal(&secret("pkcs8 bytes"), &p).unwrap();
        let typed = p.groups().join(" - ").to_lowercase();
        let reparsed = Passphrase::parse(&secret(&typed)).unwrap();
        let plain = open(&sealed, &reparsed).unwrap();
        // SECRET-EXPOSURE: test assertion on a throwaway value.
        #[expect(clippy::disallowed_methods)]
        let bytes = plain.expose_secret().to_vec();
        assert_eq!(bytes, b"pkcs8 bytes");
    }

    #[test]
    fn passphrases_are_random_and_well_formed() {
        let a = Passphrase::generate().unwrap().groups();
        let b = Passphrase::generate().unwrap().groups();
        assert_ne!(a, b);
        assert!(
            a.iter()
                .all(|g| g.len() == 5 && g.bytes().all(|c| ALPHABET.contains(&c)))
        );
    }

    #[test]
    fn crockford_substitutions() {
        let a = Passphrase::parse(&secret(&"O".repeat(30))).unwrap();
        let b = Passphrase::parse(&secret(&"0".repeat(30))).unwrap();
        assert_eq!(a.groups(), b.groups());
        for bad in ["", "ABC", &"U".repeat(30), &"A".repeat(31)] {
            assert_eq!(
                Passphrase::parse(&secret(bad)).err(),
                Some(SealError::Passphrase)
            );
        }
    }

    #[test]
    fn wrong_passphrase_and_tampering_are_refused() {
        let p = Passphrase::generate().unwrap();
        let sealed = seal(&secret("key"), &p).unwrap();
        let other = Passphrase::generate().unwrap();
        assert_eq!(open(&sealed, &other).err(), Some(SealError::Open));
        for i in [0, 9, 20, 35, sealed.len() - 1] {
            let mut bad = sealed.clone();
            bad[i] ^= 1;
            assert!(open(&bad, &p).is_err(), "byte {i}");
        }
        assert_eq!(open(&sealed[..30], &p).err(), Some(SealError::Format));
        let mut weak = sealed.clone();
        weak[8..12].copy_from_slice(&1000u32.to_be_bytes());
        assert_eq!(open(&weak, &p).err(), Some(SealError::Format));
    }
}
