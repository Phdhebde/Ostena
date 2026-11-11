//! Key set indexed by kid, and the grant issuer.
//!
//! Rotation (ADR-0004): publish the new public key to every gateway, make it
//! active on the core once propagated, then set a retirement date on the old
//! one, no earlier than the maximum TTL plus the clock tolerance. Revocation
//! is immediate and wins over everything else.

use std::collections::HashMap;

use ostena_crypto::CryptoError;
use ostena_crypto::p256::{SigningKey, VerifyingKey};

use crate::error::GrantError;
use crate::format::{self, Claims, Grant, SignedGrant};
use crate::ids::{Jti, Kid};

/// Default grant lifetime, in seconds.
pub const DEFAULT_TTL_SECS: u32 = 60;

#[derive(Debug, Clone, Copy)]
struct Entry {
    key: VerifyingKey,
    retire_at: Option<u64>,
    revoked: bool,
}

/// Public keys accepted to verify grants.
#[derive(Debug, Clone, Default)]
pub struct KeySet {
    keys: HashMap<Kid, Entry>,
}

impl KeySet {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a key (or keeps the existing entry) and returns its kid.
    pub fn insert(&mut self, key: VerifyingKey) -> Kid {
        let kid = Kid::of(&key);
        self.keys.entry(kid).or_insert(Entry {
            key,
            retire_at: None,
            revoked: false,
        });
        kid
    }

    /// Refuses grants signed with this key from `at` (Unix seconds) onwards.
    ///
    /// # Errors
    ///
    /// [`GrantError::UnknownKid`] if the key is not in the set.
    pub fn retire_at(&mut self, kid: Kid, at: u64) -> Result<(), GrantError> {
        self.entry_mut(kid)?.retire_at = Some(at);
        Ok(())
    }

    /// Refuses grants signed with this key immediately and for good. The key
    /// stays in the set so that refusals carry a distinct code.
    ///
    /// # Errors
    ///
    /// [`GrantError::UnknownKid`] if the key is not in the set.
    pub fn revoke(&mut self, kid: Kid) -> Result<(), GrantError> {
        self.entry_mut(kid)?.revoked = true;
        Ok(())
    }

    /// The key to verify a grant signed by `kid` at time `now`.
    ///
    /// # Errors
    ///
    /// Unknown ([`GrantError::UnknownKid`]), revoked
    /// ([`GrantError::KeyRevoked`]) or retired ([`GrantError::KeyRetired`]).
    pub fn lookup(&self, kid: Kid, now: u64) -> Result<&VerifyingKey, GrantError> {
        let entry = self.keys.get(&kid).ok_or(GrantError::UnknownKid(kid))?;
        if entry.revoked {
            return Err(GrantError::KeyRevoked(kid));
        }
        if entry.retire_at.is_some_and(|at| now >= at) {
            return Err(GrantError::KeyRetired(kid));
        }
        Ok(&entry.key)
    }

    fn entry_mut(&mut self, kid: Kid) -> Result<&mut Entry, GrantError> {
        self.keys.get_mut(&kid).ok_or(GrantError::UnknownKid(kid))
    }
}

/// Signs grants with the active key (core side).
pub struct Issuer {
    key: SigningKey,
    kid: Kid,
    ttl_secs: u32,
}

impl Issuer {
    /// An issuer with the default lifetime of 60 s.
    pub fn new(key: SigningKey) -> Self {
        let kid = Kid::of(&key.verifying_key());
        Self {
            key,
            kid,
            ttl_secs: DEFAULT_TTL_SECS,
        }
    }

    /// Changes the lifetime (at least 1 s).
    #[must_use]
    pub fn with_ttl(mut self, ttl_secs: u32) -> Self {
        self.ttl_secs = ttl_secs.max(1);
        self
    }

    /// Identifier of the active key.
    pub fn kid(&self) -> Kid {
        self.kid
    }

    /// Public key to distribute to gateways.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Issues a grant valid from `now` for the configured lifetime, with a
    /// fresh random jti.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Random`] if no jti can be drawn, [`CryptoError::Signing`] if
    /// the signature fails.
    pub fn issue(&self, claims: &Claims, now: u64) -> Result<SignedGrant, CryptoError> {
        let grant = Grant {
            kid: self.kid,
            jti: Jti::random()?,
            claims: Claims {
                max_session_secs: claims.max_session_secs.max(1),
                ..*claims
            },
            issued_at: now,
            expires_at: now.saturating_add(u64::from(self.ttl_secs)),
        };
        self.sign(&grant)
    }

    /// Signs arbitrary grant content (tests and tooling).
    pub(crate) fn sign(&self, grant: &Grant) -> Result<SignedGrant, CryptoError> {
        let unsigned = format::encode_unsigned(grant);
        let signature = self.key.sign(&format::signed_message(&unsigned))?;
        Ok(format::assemble(&unsigned, &signature.to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> VerifyingKey {
        SigningKey::generate().unwrap().0.verifying_key()
    }

    #[test]
    fn lookup_states() {
        let mut set = KeySet::new();
        let a = set.insert(key());
        let b = set.insert(key());
        let unknown = Kid::of(&key());
        assert!(set.lookup(a, 100).is_ok());
        assert_eq!(
            set.lookup(unknown, 100),
            Err(GrantError::UnknownKid(unknown))
        );

        set.retire_at(a, 200).unwrap();
        assert!(set.lookup(a, 199).is_ok());
        assert_eq!(set.lookup(a, 200), Err(GrantError::KeyRetired(a)));

        set.retire_at(b, 1_000).unwrap();
        set.revoke(b).unwrap();
        assert_eq!(set.lookup(b, 0), Err(GrantError::KeyRevoked(b)));
        assert_eq!(set.revoke(unknown), Err(GrantError::UnknownKid(unknown)));
    }

    #[test]
    fn reinserting_does_not_clear_revocation() {
        let mut set = KeySet::new();
        let k = key();
        let kid = set.insert(k);
        set.revoke(kid).unwrap();
        set.insert(k);
        assert_eq!(set.lookup(kid, 0), Err(GrantError::KeyRevoked(kid)));
    }
}
