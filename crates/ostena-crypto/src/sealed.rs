//! Sealing of the offline root key (ADR-0008, root ceremony).
//!
//! The root key is sealed under a **root secret** of 256 random bits, drawn
//! here rather than chosen by a person, so that the sealed file cannot be
//! attacked offline by guessing (ANSSI-PG-083 `RègleSecretFaibleEntropie`).
//!
//! The root secret is never shown: it is split with Shamir's scheme over
//! GF(256) into **three shares, any two of which rebuild it** (`vsss-rs`,
//! an audited implementation). One share per custodian, in a sealed
//! envelope: a lost envelope does not lose the root, and no custodian alone
//! can open it. A share is written as 56 base32 characters (id, value, and
//! a CRC-16 that catches every mistyped character).
//!
//! Sealed format: `OSTSEAL2` ‖ iterations (u32, big-endian) ‖ salt (16) ‖
//! nonce (12) ‖ AES-256-GCM(key, nonce, aad = the 40 header bytes, PKCS#8),
//! where key = PBKDF2-HMAC-SHA256(root secret, salt, iterations). The
//! derivation only adds margin: the root secret already has full entropy.

use std::convert::Infallible;
use std::num::NonZeroU32;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::pbkdf2;
use ostena_common::secret::SecretBytes;
use vsss_rs::Gf256;

const MAGIC: &[u8; 8] = b"OSTSEAL2";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = MAGIC.len() + 4 + SALT_LEN + NONCE_LEN;
const TAG_LEN: usize = 16;
/// Iterations written by [`seal`].
pub const ITERATIONS: u32 = 600_000;
/// Iterations accepted by [`open`].
const ACCEPTED_ITERATIONS: std::ops::RangeInclusive<u32> = 600_000..=10_000_000;

/// Bytes of the root secret.
pub const SECRET_LEN: usize = 32;
/// Shares made, and shares needed to rebuild the root secret.
pub const SHARES: usize = 3;
/// Shares needed to rebuild the root secret.
pub const THRESHOLD: usize = 2;

/// Crockford base32 alphabet: no I, L, O, U.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Bytes of an encoded share: id, value, checksum.
const SHARE_BYTES: usize = 1 + SECRET_LEN + 2;
/// Characters of a share in base32 (280 bits, no padding).
pub const SHARE_CHARS: usize = (SHARE_BYTES * 8).div_ceil(5);
/// Domain separation of the share checksum.
const SHARE_DOMAIN: &[u8] = b"ostena-root-share-v1";

/// Sealing errors, coarse on purpose: a wrong secret and a damaged file are
/// not told apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SealError {
    /// Not a sealed file of this format.
    #[error("fichier scellé mal formé")]
    Format,
    /// A share is mistyped or damaged (wrong length, character or checksum).
    #[error("part mal recopiée : 56 caractères base32 attendus, somme de contrôle fausse")]
    Share,
    /// Fewer than two distinct shares.
    #[error("au moins deux parts différentes sont nécessaires")]
    NotEnoughShares,
    /// Wrong shares or altered file.
    #[error("ouverture impossible : parts d'une autre racine ou fichier altéré")]
    Open,
    /// Random generation failed.
    #[error("échec du générateur d'aléa du système")]
    Random,
}

/// Serves pre-drawn system randomness to `vsss-rs`: drawing can fail, a
/// `rand_core` generator cannot. If the buffer runs out (it is sized well
/// above what a split uses), the flag is raised and the split is refused.
struct DrawnRandomness {
    bytes: Vec<u8>,
    exhausted: bool,
}

impl rand_core::TryRng for DrawnRandomness {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        if dst.len() > self.bytes.len() {
            self.exhausted = true;
            dst.fill(0);
        } else {
            let rest = self.bytes.split_off(self.bytes.len() - dst.len());
            dst.copy_from_slice(&rest);
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for DrawnRandomness {}

impl Drop for DrawnRandomness {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.bytes);
    }
}

/// CRC-16/CCITT (polynomial 0x1021) over the domain and the share: it
/// detects every error burst of at most 16 bits, so every mistyped
/// character (5 bits). An integrity check against typos, not a MAC: a
/// forged share only yields a secret that does not open the seal.
fn checksum(id_and_value: &[u8]) -> [u8; 2] {
    crc16(SHARE_DOMAIN.iter().chain(id_and_value)).to_be_bytes()
}

fn crc16<'a>(bytes: impl Iterator<Item = &'a u8>) -> u16 {
    let mut crc: u16 = 0xffff;
    for &byte in bytes {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// One share of the root secret. No `Debug`.
pub struct Share(SecretBytes);

impl Share {
    /// The share as 56 base32 characters in groups of five, for the ceremony
    /// record.
    pub fn to_text(&self) -> String {
        // SECRET-EXPOSURE: shown once to its custodian during the ceremony.
        #[expect(clippy::disallowed_methods)]
        let bytes = self.0.expose_secret();
        let mut bits = 0u32;
        let mut count = 0;
        let mut chars = Vec::with_capacity(SHARE_CHARS);
        for &b in bytes {
            bits = (bits << 8) | u32::from(b);
            count += 8;
            while count >= 5 {
                count -= 5;
                chars.push(ALPHABET[((bits >> count) & 0x1f) as usize]);
            }
        }
        if count > 0 {
            chars.push(ALPHABET[((bits << (5 - count)) & 0x1f) as usize]);
        }
        chars
            .chunks(5)
            .map(|g| String::from_utf8_lossy(g).into_owned())
            .collect::<Vec<_>>()
            .join("-")
    }

    /// Parses a share typed back: spaces and dashes are ignored, case too,
    /// and the Crockford substitutions (O→0, I/L→1) are applied. The
    /// checksum must match.
    ///
    /// # Errors
    ///
    /// [`SealError::Share`].
    pub fn parse(text: &SecretBytes) -> Result<Self, SealError> {
        // SECRET-EXPOSURE: the typed share is decoded into a new secret.
        #[expect(clippy::disallowed_methods)]
        let typed = text.expose_secret();
        let mut bits = 0u32;
        let mut count = 0;
        let mut chars = 0;
        let mut bytes = Vec::with_capacity(SHARE_BYTES + 1);
        for &b in typed {
            let c = match b.to_ascii_uppercase() {
                b' ' | b'-' | b'\t' | b'\r' | b'\n' => continue,
                b'O' => b'0',
                b'I' | b'L' => b'1',
                c => c,
            };
            let v = ALPHABET
                .iter()
                .position(|&a| a == c)
                .and_then(|v| u32::try_from(v).ok())
                .ok_or(SealError::Share)?;
            chars += 1;
            bits = (bits << 5) | v;
            count += 5;
            if count >= 8 {
                count -= 8;
                bytes.push((bits >> count).to_be_bytes()[3]);
            }
        }
        let padding_is_zero = bits & ((1 << count) - 1) == 0;
        if chars != SHARE_CHARS || bytes.len() != SHARE_BYTES || !padding_is_zero {
            zeroize::Zeroize::zeroize(&mut bytes);
            return Err(SealError::Share);
        }
        let (body, sum) = bytes.split_at(SHARE_BYTES - 2);
        if checksum(body) != sum || body[0] == 0 {
            zeroize::Zeroize::zeroize(&mut bytes);
            return Err(SealError::Share);
        }
        Ok(Self(SecretBytes::from(bytes)))
    }

    /// The identifier (1 to 3).
    pub fn id(&self) -> u8 {
        // SECRET-EXPOSURE: the identifier is not secret.
        #[expect(clippy::disallowed_methods)]
        let id = self.0.expose_secret()[0];
        id
    }
}

/// The root secret: 256 random bits (PG-083 `RecoPQTailleCléSym`: at least
/// 192 bits for post-quantum security; the root lives beyond 2030). No `Debug`, never shown.
pub struct RootSecret(SecretBytes);

impl RootSecret {
    /// Draws a root secret and splits it into [`SHARES`] shares, any
    /// [`THRESHOLD`] of which rebuild it.
    ///
    /// # Errors
    ///
    /// [`SealError::Random`].
    pub fn generate() -> Result<(Self, [Share; SHARES]), SealError> {
        let secret = crate::rand::array::<SECRET_LEN>().map_err(|_| SealError::Random)?;
        let mut rng = DrawnRandomness {
            bytes: vec![0u8; 4096],
            exhausted: false,
        };
        crate::rand::fill(&mut rng.bytes).map_err(|_| SealError::Random)?;
        let split = Gf256::split_bytes(THRESHOLD, SHARES, secret, &mut rng);
        let secret = SecretBytes::from(secret.to_vec());
        let mut raw = match split {
            Ok(raw) if !rng.exhausted && raw.len() == SHARES => raw,
            _ => return Err(SealError::Random),
        };
        let mut shares = Vec::with_capacity(SHARES);
        for share in &mut raw {
            let mut bytes = share.clone();
            bytes.extend_from_slice(&checksum(share));
            shares.push(Share(SecretBytes::from(bytes)));
            zeroize::Zeroize::zeroize(share);
        }
        let shares: [Share; SHARES] = shares.try_into().map_err(|_| SealError::Random)?;
        Ok((Self(secret), shares))
    }

    /// Rebuilds the root secret from at least [`THRESHOLD`] distinct shares.
    /// Shares of another root give another secret, refused by [`open`].
    ///
    /// # Errors
    ///
    /// [`SealError::NotEnoughShares`].
    pub fn combine(shares: &[Share]) -> Result<Self, SealError> {
        let mut ids: Vec<u8> = shares.iter().map(Share::id).collect();
        ids.sort_unstable();
        ids.dedup();
        if ids.len() < THRESHOLD || ids.len() != shares.len() {
            return Err(SealError::NotEnoughShares);
        }
        let mut raw: Vec<Vec<u8>> = shares
            .iter()
            .map(|s| {
                // SECRET-EXPOSURE: the shares are combined by vsss-rs.
                #[expect(clippy::disallowed_methods)]
                let bytes = s.0.expose_secret();
                bytes[..SHARE_BYTES - 2].to_vec()
            })
            .collect();
        let combined = Gf256::combine_bytes(&raw);
        for share in &mut raw {
            zeroize::Zeroize::zeroize(share);
        }
        match combined {
            Ok(secret) if secret.len() == SECRET_LEN => Ok(Self(SecretBytes::from(secret))),
            _ => Err(SealError::NotEnoughShares),
        }
    }

    fn key(&self, salt: &[u8], iterations: u32) -> Result<LessSafeKey, SealError> {
        let iterations = NonZeroU32::new(iterations).ok_or(SealError::Format)?;
        let mut key = [0u8; 32];
        // SECRET-EXPOSURE: the root secret feeds the key derivation.
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

/// Seals `plaintext` under `secret`.
///
/// # Errors
///
/// [`SealError::Random`] or [`SealError::Open`] if the library fails.
pub fn seal(plaintext: &SecretBytes, secret: &RootSecret) -> Result<Vec<u8>, SealError> {
    let salt = crate::rand::array::<SALT_LEN>().map_err(|_| SealError::Random)?;
    let nonce = crate::rand::array::<NONCE_LEN>().map_err(|_| SealError::Random)?;
    let mut out = Vec::with_capacity(HEADER_LEN + TAG_LEN + 256);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&ITERATIONS.to_be_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    let key = secret.key(&salt, ITERATIONS)?;
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
/// [`SealError::Open`] for another secret or an altered file.
pub fn open(sealed: &[u8], secret: &RootSecret) -> Result<SecretBytes, SealError> {
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
    let key = secret.key(salt, iterations)?;
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
mod tests;
