//! Persistent anti-replay: a jti is consumed at most once.
//!
//! Two consumers are planned (ADR-0004): the gateway's local file
//! ([`FileReplayStore`]), and the core's PostgreSQL table when the gateway asks
//! the core for the session parameters, which covers several gateways of the
//! same group. [`Chain`] runs two stores one after the other; a grant is
//! accepted only if every store sees its jti for the first time.

mod file;

use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;

pub use file::{FileReplayStore, RepairReport, repair};

use crate::ids::Jti;

/// Answer of a store for one jti.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// First use: the jti is now consumed.
    Fresh,
    /// Already consumed.
    Replayed,
    /// Expires before the store's fence, set by a repair: it may have been
    /// consumed in a record that was lost.
    Fenced,
}

/// The store cannot answer. Callers must refuse the grant (fail closed).
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ReplayStoreError(pub String);

/// Atomic consumption of a jti.
pub trait ReplayStore {
    /// Consumes `jti` if it was never seen. `expires_at` (Unix seconds) tells
    /// how long the entry must be kept. The answer must be durable before the
    /// future resolves.
    fn consume(
        &self,
        jti: Jti,
        expires_at: u64,
    ) -> impl Future<Output = Result<Freshness, ReplayStoreError>> + Send;
}

/// Two stores in sequence: `B` is asked only if `A` answers [`Freshness::Fresh`].
#[derive(Debug)]
pub struct Chain<A, B>(pub A, pub B);

impl<A, B> ReplayStore for Chain<A, B>
where
    A: ReplayStore + Sync,
    B: ReplayStore + Sync,
{
    async fn consume(&self, jti: Jti, expires_at: u64) -> Result<Freshness, ReplayStoreError> {
        match self.0.consume(jti, expires_at).await? {
            Freshness::Fresh => self.1.consume(jti, expires_at).await,
            other => Ok(other),
        }
    }
}

/// In-memory store, lost on restart: tests and development only.
#[derive(Debug, Default)]
pub struct MemoryReplayStore {
    seen: Mutex<HashMap<Jti, u64>>,
}

impl MemoryReplayStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl ReplayStore for MemoryReplayStore {
    fn consume(
        &self,
        jti: Jti,
        expires_at: u64,
    ) -> impl Future<Output = Result<Freshness, ReplayStoreError>> + Send {
        let result = self
            .seen
            .lock()
            .map_err(|_| ReplayStoreError("verrou de l'anti-rejeu empoisonné".into()))
            .map(|mut seen| {
                if seen.insert(jti, expires_at).is_some() {
                    Freshness::Replayed
                } else {
                    Freshness::Fresh
                }
            });
        std::future::ready(result)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    use super::*;

    /// Minimal executor for futures that never wait on I/O readiness.
    pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        let mut cx = Context::from_waker(Waker::noop());
        loop {
            if let Poll::Ready(v) = future.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    #[test]
    fn memory_store_consumes_once() {
        let store = MemoryReplayStore::new();
        let jti = Jti::from_bytes([1; 16]);
        assert_eq!(block_on(store.consume(jti, 10)).unwrap(), Freshness::Fresh);
        assert_eq!(
            block_on(store.consume(jti, 10)).unwrap(),
            Freshness::Replayed
        );
    }

    #[test]
    fn chain_requires_both_fresh() {
        let local = MemoryReplayStore::new();
        let central = MemoryReplayStore::new();
        let jti = Jti::from_bytes([2; 16]);
        // Already consumed centrally, by another gateway of the group.
        block_on(central.consume(jti, 10)).unwrap();
        let chain = Chain(local, central);
        assert_eq!(
            block_on(chain.consume(jti, 10)).unwrap(),
            Freshness::Replayed
        );
        // Now locally consumed too.
        assert_eq!(
            block_on(chain.0.consume(jti, 10)).unwrap(),
            Freshness::Replayed
        );

        let other = Jti::from_bytes([3; 16]);
        assert_eq!(
            block_on(chain.consume(other, 10)).unwrap(),
            Freshness::Fresh
        );
        assert_eq!(
            block_on(chain.consume(other, 10)).unwrap(),
            Freshness::Replayed
        );
    }
}
