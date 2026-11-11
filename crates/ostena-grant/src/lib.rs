//! Short-lived session grants (ADR-0004).
//!
//! The core authorises a session and signs a compact binary grant with ECDSA P-256;
//! the gateway verifies it, checks it is meant for its group, and consumes its
//! jti once. A grant carries the authorisation, never a secret.
//!
//! - [`format`] — the 168-byte layout and its base64url text form;
//! - [`keys`] — key set by kid (rotation, revocation) and issuer;
//! - [`verify`] — verification policy and verifier;
//! - [`replay`] — persistent anti-replay behind the [`ReplayStore`] trait.

#![forbid(unsafe_code)]

mod error;
pub mod format;
mod ids;
pub mod keys;
pub mod replay;
pub mod verify;

#[doc(hidden)]
pub mod fuzz;

pub use error::GrantError;
pub use format::{Claims, GRANT_LEN, Grant, Protocol, Rights, SignedGrant, TEXT_LEN};
pub use ids::{GatewayGroupId, Jti, Kid, ResourceId, SubjectId};
pub use keys::{DEFAULT_TTL_SECS, Issuer, KeySet};
pub use replay::{Chain, FileReplayStore, Freshness, MemoryReplayStore, ReplayStore};
pub use verify::{Policy, Verifier};

/// Current time in Unix seconds.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
