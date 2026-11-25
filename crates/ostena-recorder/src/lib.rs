//! Session recordings (ADR-0016).
//!
//! The agent captures what a session shows (terminal output and window
//! sizes) and streams it to the core, which stores it as an asciicast v2
//! file and seals its SHA-256 in the audit chain. The agent keeps nothing.
//!
//! - [`event`] — the recorded events and their bounds;
//! - [`wire`] — the agent-to-core stream: canonical frames, strict
//!   streaming decoder;
//! - [`cast`] — the deterministic asciicast v2 writer of the core, hashed as
//!   it is written.
//!
//! No I/O of its own besides [`std::io::Write`], no runtime, no database:
//! the decoder runs on untrusted input and is fuzzed on its own.

#![forbid(unsafe_code)]

pub mod cast;
mod error;
pub mod event;
pub mod wire;

#[doc(hidden)]
pub mod fuzz;

pub use cast::{CastWriter, Sealed};
pub use error::RecorderError;
pub use event::{EndReason, Event, Exit, Frame};
pub use wire::{Decoder, Limits, encode};
