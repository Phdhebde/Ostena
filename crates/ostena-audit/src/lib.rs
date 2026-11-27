//! Tamper-evident audit chain of the core (ADR-0012).
//!
//! Every audit event is a canonical binary record linked to the previous one
//! by a plain SHA-256 hash; the core periodically signs the tip of the chain
//! with ECDSA P-256 (a *head*), so anyone holding the public key can check an
//! export offline, without any secret.
//!
//! - [`record`] — the record v1 format, its strict decoder and its hash;
//! - [`event`] — the documented event kinds and a record builder;
//! - [`head`] — signed heads v1, their text form and the trusted keys;
//! - [`export`] — the streamed export container v1;
//! - [`verify`] — the streaming verifier, its findings and its report;
//! - [`timestamp`] — the RFC 3161 time-stamps of the heads, as records;
//! - [`siem`] — OCSF events in RFC 5424 messages, framed as RFC 5425 says.
//!
//! This crate has no I/O of its own besides [`std::io::Read`] and
//! [`std::io::Write`], and no database: the core writes records and heads
//! to PostgreSQL and uses the same verifier on its own segments.

#![forbid(unsafe_code)]

mod error;
pub mod event;
pub mod export;
pub mod head;
mod ids;
pub mod record;
pub mod siem;
pub mod timestamp;
pub mod transcripts;
pub mod verify;

#[doc(hidden)]
pub mod fuzz;

pub use error::AuditError;
pub use event::{ChainTip, Event, EventKind, field};
pub use export::{ExportReader, ExportWriter, Frame};
pub use head::{HEAD_LEN, Head, MAX_TRUSTED_KEYS, TrustedKeys, UnsignedHead};
pub use ids::{ChainId, Kid};
pub use record::{
    ActorKind, Digest, Field, MAX_RECORD_LEN, MIN_RECORD_LEN, Outcome, Record, Value, ZERO_DIGEST,
    record_hash,
};
pub use verify::{
    Finding, Options, Report, Severity, SshSession, TranscriptSeal, Verifier, verify_export,
};

/// Current time in Unix milliseconds.
pub fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}
