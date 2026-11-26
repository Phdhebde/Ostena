//! Dial-back mTLS tunnel between the gateway agent and the core (ADR-0008).
//!
//! The agent dials the core over QUIC with the fixed TLS 1.3 configuration
//! of `ostena-crypto::tls`, opens the control stream and says hello. Then:
//!
//! - [`control`] — strict JSON control messages, every one validated as
//!   untrusted input;
//! - [`channel`] — one stream per session and traffic class, input first;
//! - [`limits`] — bounds on sessions, streams, buffers and timers;
//! - [`recording`] — the transcript stream of a session, agent side;
//! - [`tunnel`] — connection, heartbeat, channels, on both ends;
//! - [`mux`] — the multiplexer of the TLS 1.3 over TCP fallback;
//! - [`transport`] — QUIC and TCP behind one interface.

#![forbid(unsafe_code)]

pub mod browser;
pub mod channel;
pub mod control;
pub mod enroll;
mod error;
pub mod gateway;
mod ids;
pub mod limits;
pub mod link;
pub mod mux;
pub mod recording;
pub mod renewal;
pub mod ssh;
pub mod transport;
pub mod tunnel;

#[cfg(feature = "testing")]
pub mod testing;

#[doc(hidden)]
pub mod fuzz;

pub use channel::StreamClass;
pub use error::TunnelError;
pub use ids::Uuid;
pub use limits::Limits;
pub use transport::{ChannelRecv, ChannelSend, StreamError, Transport, TransportMode};
pub use tunnel::{
    ALPN, Accepted, AgentConfig, AgentTunnel, Channel, CoreListener, CoreTunnel, FALLBACK_AFTER,
    Hello, HelloAck, connect, connect_with,
};
