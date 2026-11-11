//! Short-lived session grants (ADR-0004).
//!
//! The core authorises a session and signs a compact binary grant with Ed25519;
//! the gateway verifies it, checks it is meant for its group, and consumes its
//! jti once. A grant carries the authorisation, never a secret.
//!
//! - [`replay`] — persistent anti-replay behind the [`ReplayStore`] trait.

#![forbid(unsafe_code)]

mod ids;
pub mod replay;


pub use ids::{GatewayGroupId, Jti, Kid, ResourceId, SubjectId};
pub use replay::{Chain, FileReplayStore, Freshness, MemoryReplayStore, ReplayStore};

/// Current time in Unix seconds.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
