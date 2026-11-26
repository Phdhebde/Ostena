//! The minimal multiplexer of the TLS 1.3 over TCP fallback (ADR-0008).
//!
//! QUIC stays the main transport. When UDP does not get through, the agent
//! carries the same tunnel over one TLS 1.3 connection on TCP, with the same
//! TLS configuration (`ostena-crypto::tls`), and this multiplexer on top:
//!
//! - the same streams: the control stream first, then up to four session
//!   streams per session, each with its 18-byte channel header;
//! - strict priorities: the writer always serves the highest priority with
//!   something to send, round robin among equals, at most one frame of
//!   16 KiB at a time ([`frame::MAX_DATA`]);
//! - end-to-end flow control: per stream and per connection windows, as
//!   QUIC's ([`crate::Limits`]), and a stream limit raised as streams close;
//! - liveness: a ping every `keep_alive`, the connection declared lost after
//!   `idle_timeout` without a frame, on top of the application heartbeat;
//! - a close frame that carries the reason (the `TUN-` code) to the peer.
//!
//! TCP orders every byte: a lost segment delays every stream, which QUIC
//! avoids. That is the price of the fallback, a performance downgrade only.

mod conn;
pub mod frame;
pub mod state;

pub use conn::{Connection, IoMapper, RecvStream, SendStream};
pub use state::{Side, StreamError};
