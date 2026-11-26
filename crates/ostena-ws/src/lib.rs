//! WebSocket (RFC 6455), server side only (ADR-0020, § 2).
//!
//! The browser gateway of the core, and later the RD Gateway, accept
//! WebSocket connections from hostile clients. This crate holds what reads
//! their bytes, without any I/O, runtime or dependency, so that it is tested
//! and fuzzed alone:
//!
//! - [`handshake`] — the checks of an upgrade request (method, `Upgrade`,
//!   `Connection`, version 13, form of `Sec-WebSocket-Key`, offered
//!   subprotocols). The `Sec-WebSocket-Accept` value is computed by
//!   `ostena_crypto::websocket`, the only place where SHA-1 is admitted for
//!   it (ADR-0009, amendment of 2026-11-26);
//! - [`frame`] — the frame codec: a [`Parser`] of client frames and the
//!   encoders of server frames.
//!
//! What the parser enforces, every refusal ending the connection with a
//! close code ([`WsError::close_code`]):
//!
//! - client frames are masked; reserved bits are zero: no extension is ever
//!   negotiated (no `permessage-deflate`);
//! - text messages are refused (`1003`): the gateway carries binary frames
//!   only;
//! - a message is at most [`MAX_MESSAGE`] bytes (`1009`), checked from the
//!   length field, before the payload is read;
//! - lengths use their shortest encoding; control frames are final and at
//!   most 125 bytes; continuations follow a started message, and a data
//!   frame never interrupts one;
//! - a close frame has no body or a valid code and a UTF-8 reason (`1007`
//!   for a reason that is not UTF-8); nothing may follow it.

#![forbid(unsafe_code)]

pub mod frame;
pub mod handshake;

#[cfg(any(test, feature = "client"))]
pub mod client;

#[doc(hidden)]
pub mod fuzz;

pub use frame::{CloseCode, Event, MAX_HEADER, Opcode, Parser, WsError};
pub use handshake::{HandshakeError, Upgrade};

/// Largest message the parser accepts, in bytes (ADR-0020): one frame of
/// `ostena-frame` with its largest fragment fits in it.
pub const MAX_MESSAGE: usize = 32 * 1024;
