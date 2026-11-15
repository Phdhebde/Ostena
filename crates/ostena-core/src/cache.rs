//! The registry as the TLS handshake sees it (ADR-0011).
//!
//! rustls asks synchronously, at every handshake, whether an agent
//! certificate is known: it reads this copy of the registry, loaded at
//! startup, written after every change committed to the database, and
//! reloaded in full every 60 s. While the copy cannot be reloaded, it is
//! **unavailable** and every new agent is refused (`TUN-E029`): the core
//! never serves a stale copy.

use std::collections::HashMap;
use std::sync::RwLock;

use ostena_crypto::tls::{ClientAuthorizer, ClientRefusal};
use ostena_tunnel::Uuid;

/// One agent certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertEntry {
    /// Gateway group of the agent.
    pub group: Uuid,
    /// Agent identifier.
    pub agent: Uuid,
    /// Revoked (the certificate or its agent).
    pub revoked: bool,
}

/// The copy of the registry; empty and unavailable until the first load.
#[derive(Debug, Default)]
pub struct AgentCache(RwLock<Option<HashMap<[u8; 32], CertEntry>>>);

impl AgentCache {
    /// Replaces the whole copy (full reload).
    pub fn replace(&self, entries: HashMap<[u8; 32], CertEntry>) {
        if let Ok(mut state) = self.0.write() {
            *state = Some(entries);
        }
    }

    /// Marks the copy unavailable: new agents are refused until the next
    /// successful [`AgentCache::replace`].
    pub fn invalidate(&self) {
        if let Ok(mut state) = self.0.write() {
            *state = None;
        }
    }

    /// Whether the copy can be used.
    pub fn is_available(&self) -> bool {
        self.0.read().is_ok_and(|s| s.is_some())
    }

    /// Adds a certificate committed to the database. Ignored while
    /// unavailable: the next reload brings it.
    pub fn insert(&self, fingerprint: [u8; 32], entry: CertEntry) {
        if let Ok(mut state) = self.0.write()
            && let Some(map) = state.as_mut()
        {
            map.insert(fingerprint, entry);
        }
    }

    /// Marks every certificate of `agent` revoked and returns their
    /// fingerprints.
    pub fn revoke_agent(&self, agent: Uuid) -> Vec<[u8; 32]> {
        let Ok(mut state) = self.0.write() else {
            return Vec::new();
        };
        let Some(map) = state.as_mut() else {
            return Vec::new();
        };
        map.iter_mut()
            .filter(|(_, e)| e.agent == agent)
            .map(|(fp, e)| {
                e.revoked = true;
                *fp
            })
            .collect()
    }

    /// The certificate `fingerprint`, if known, not revoked, and the copy
    /// available.
    pub fn active(&self, fingerprint: &[u8; 32]) -> Option<CertEntry> {
        self.0
            .read()
            .ok()?
            .as_ref()?
            .get(fingerprint)
            .copied()
            .filter(|e| !e.revoked)
    }
}

impl ClientAuthorizer for AgentCache {
    fn authorize(&self, fingerprint: &[u8; 32]) -> Result<(), ClientRefusal> {
        let state = self.0.read().map_err(|_| ClientRefusal::Unavailable)?;
        let map = state.as_ref().ok_or(ClientRefusal::Unavailable)?;
        match map.get(fingerprint) {
            Some(e) if !e.revoked => Ok(()),
            Some(_) => Err(ClientRefusal::Revoked),
            None => Err(ClientRefusal::Unknown),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(agent: u8) -> CertEntry {
        CertEntry {
            group: Uuid::from_bytes([9; 16]),
            agent: Uuid::from_bytes([agent; 16]),
            revoked: false,
        }
    }

    #[test]
    fn unavailable_until_loaded_and_after_invalidation() {
        let cache = AgentCache::default();
        assert_eq!(cache.authorize(&[1; 32]), Err(ClientRefusal::Unavailable));
        cache.insert([1; 32], entry(1));
        assert_eq!(cache.authorize(&[1; 32]), Err(ClientRefusal::Unavailable));
        cache.replace(HashMap::from([([1; 32], entry(1))]));
        assert_eq!(cache.authorize(&[1; 32]), Ok(()));
        assert_eq!(cache.authorize(&[2; 32]), Err(ClientRefusal::Unknown));
        cache.invalidate();
        assert_eq!(cache.authorize(&[1; 32]), Err(ClientRefusal::Unavailable));
        assert_eq!(cache.active(&[1; 32]), None);
    }

    #[test]
    fn revoking_an_agent_revokes_all_its_certificates() {
        let cache = AgentCache::default();
        cache.replace(HashMap::from([
            ([1; 32], entry(1)),
            ([2; 32], entry(1)),
            ([3; 32], entry(2)),
        ]));
        let mut revoked = cache.revoke_agent(Uuid::from_bytes([1; 16]));
        revoked.sort_unstable();
        assert_eq!(revoked, vec![[1; 32], [2; 32]]);
        assert_eq!(cache.authorize(&[1; 32]), Err(ClientRefusal::Revoked));
        assert_eq!(cache.authorize(&[2; 32]), Err(ClientRefusal::Revoked));
        assert_eq!(cache.authorize(&[3; 32]), Ok(()));
        assert_eq!(
            cache.active(&[3; 32]).map(|e| e.agent),
            Some(Uuid::from_bytes([2; 16]))
        );
    }
}
