//! Versioned binary framing between the gateway and the browser (ADR-0006).
//!
//! `no_std` + `alloc`, without dependencies: the same crate is built for the
//! gateway and, in WebAssembly, for `ostena-web-client`.
//!
//! - [`header`] — the frozen 16-byte header and the v1 type table (direction,
//!   class, maximum length, fragmentation);
//! - [`payload`] — typed payloads, read in place;
//! - [`codec`] — zero-copy, allocation-free decoding, and encoding;
//! - [`session`] — version negotiation and receive-side state;
//! - [`scheduler`] — priority scheduling (inputs before display) and
//!   sequence numbering, without a runtime;
//! - [`reassembly`] — bounded reassembly of fragmented messages.
//!
//! No frame carries a secret: authentication happens in the WebSocket
//! handshake, before the first frame.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod codec;
mod error;
pub mod header;
pub mod payload;
pub mod reassembly;
pub mod scheduler;
pub mod session;

#[doc(hidden)]
pub mod fuzz;

pub use codec::{Decoded, Frame, decode_message, decode_stream, encode};
pub use error::{Code, FrameError};
pub use header::{
    CURRENT_VERSION, Class, Direction, Flags, FrameType, HEADER_LEN, Header, MAX_FRAGMENT,
};
pub use payload::Payload;
pub use reassembly::{Message, Reassembler};
pub use scheduler::{Limits, Outgoing, Scheduler, Sender};
pub use session::{Receiver, SUPPORTED_VERSIONS, negotiate};
