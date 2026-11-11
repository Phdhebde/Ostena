//! Grant verification (gateway side).
//!
//! Order: structure and header, key lookup, **signature**, then the other
//! fields, audience, lifetimes, validity window, and finally consumption of
//! the jti. No field other than the header is trusted before the signature.

use crate::error::GrantError;
use crate::format::{self, GRANT_LEN, Grant, SignedGrant};
use crate::ids::GatewayGroupId;
use crate::keys::KeySet;
use crate::replay::{Freshness, ReplayStore};
use ostena_crypto::ed25519::Signature;

/// Verification limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Accepted clock difference with the core, in seconds.
    pub clock_skew_secs: u64,
    /// Longest grant lifetime accepted (`expires_at − issued_at`).
    pub max_ttl_secs: u64,
    /// Longest session length accepted.
    pub max_session_secs: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            clock_skew_secs: 5,
            max_ttl_secs: 300,
            max_session_secs: 12 * 3600,
        }
    }
}

/// Verifies grants for one gateway group.
#[derive(Debug, Clone)]
pub struct Verifier {
    keys: KeySet,
    audience: GatewayGroupId,
    policy: Policy,
}

impl Verifier {
    /// A verifier for the gateway group `audience`.
    pub fn new(keys: KeySet, audience: GatewayGroupId, policy: Policy) -> Self {
        Self {
            keys,
            audience,
            policy,
        }
    }

    /// The key set, for rotation and revocation.
    pub fn keys_mut(&mut self) -> &mut KeySet {
        &mut self.keys
    }

    /// Every check except anti-replay. The core uses it before consuming the
    /// jti in its own store.
    ///
    /// # Errors
    ///
    /// The first failed check, see [`GrantError`].
    pub fn check(&self, bytes: &[u8], now: u64) -> Result<Grant, GrantError> {
        let signed = SignedGrant::from_bytes(bytes)?;
        let raw: &[u8; GRANT_LEN] = signed.as_bytes();

        let kid = format::parse_header(raw)?;
        let key = self.keys.lookup(kid, now)?;
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&raw[format::SIGNED_LEN..]);
        key.verify(&format::signed_message(raw), &Signature::from_bytes(&sig))
            .map_err(|_| GrantError::BadSignature)?;

        let grant = format::parse_body(raw)?;
        if grant.claims.audience != self.audience {
            return Err(GrantError::WrongAudience {
                expected: self.audience,
                got: grant.claims.audience,
            });
        }
        if grant.expires_at - grant.issued_at > self.policy.max_ttl_secs {
            return Err(GrantError::OutOfBounds("durée de vie du grant trop longue"));
        }
        if grant.claims.max_session_secs > self.policy.max_session_secs {
            return Err(GrantError::OutOfBounds("durée de session trop longue"));
        }
        if grant.issued_at > now.saturating_add(self.policy.clock_skew_secs) {
            return Err(GrantError::NotYetValid {
                issued_at: grant.issued_at,
                now,
            });
        }
        if now >= grant.expires_at {
            return Err(GrantError::Expired {
                expires_at: grant.expires_at,
                now,
            });
        }
        Ok(grant)
    }

    /// Full verification, consuming the jti in `store`. Emits the
    /// `grant.accepted` / `grant.rejected` events.
    ///
    /// # Errors
    ///
    /// The first failed check, see [`GrantError`]. A store failure refuses the
    /// grant ([`GrantError::ReplayStore`]).
    pub async fn verify<S: ReplayStore>(
        &self,
        bytes: &[u8],
        now: u64,
        store: &S,
    ) -> Result<Grant, GrantError> {
        let result = self.verify_inner(bytes, now, store).await;
        match &result {
            Ok(g) => tracing::info!(
                event = "grant.accepted",
                jti = %g.jti,
                kid = %g.kid,
                subject = %g.claims.subject,
                resource = %g.claims.resource,
                protocol = ?g.claims.protocol,
                rights = g.claims.rights.bits(),
            ),
            Err(e) => tracing::warn!(event = "grant.rejected", code = e.code(), "{e}"),
        }
        result
    }

    async fn verify_inner<S: ReplayStore>(
        &self,
        bytes: &[u8],
        now: u64,
        store: &S,
    ) -> Result<Grant, GrantError> {
        let grant = self.check(bytes, now)?;
        match store.consume(grant.jti, grant.expires_at).await {
            Ok(Freshness::Fresh) => Ok(grant),
            Ok(Freshness::Replayed) => Err(GrantError::Replayed("jti déjà consommé")),
            Ok(Freshness::Fenced) => Err(GrantError::Replayed(
                "émis avant la dernière réparation du journal anti-rejeu",
            )),
            Err(e) => Err(GrantError::ReplayStore(e.0)),
        }
    }
}

#[cfg(test)]
mod tests;
