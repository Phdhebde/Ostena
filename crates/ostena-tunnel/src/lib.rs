//! Dial-back mTLS tunnel between the gateway agent and the core (ADR-0008).
//!
//! The agent dials the core over QUIC with the fixed TLS 1.3 configuration
//! of `ostena-crypto::tls`, opens the control stream and says hello. Then:
//!
//! - [`control`] — strict JSON control messages, every one validated as
//!   untrusted input;
//! - [`channel`] — one stream per session and traffic class, input first;
//! - [`limits`] — bounds on sessions, streams, buffers and timers;
//! - [`tunnel`] — connection, heartbeat, channels, on both ends.

#![forbid(unsafe_code)]

pub mod channel;
pub mod control;
mod error;
mod ids;
pub mod limits;
pub mod tunnel;

#[cfg(feature = "testing")]
pub mod testing;

#[doc(hidden)]
pub mod fuzz;

pub use channel::StreamClass;
pub use error::TunnelError;
pub use ids::Uuid;
pub use limits::Limits;
pub use tunnel::{
    ALPN, Accepted, AgentConfig, AgentTunnel, Channel, CoreListener, CoreTunnel, Hello, HelloAck,
    connect,
};
