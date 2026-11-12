//! Entry point shared by the cargo-fuzz target (`fuzz/`) and the stable test
//! that replays its corpus. Not part of the API.

use crate::channel::{self, HEADER_LEN};
use crate::control::{self, AgentMessage, CoreMessage};
use crate::enroll;

/// Runs every decoder of the tunnel (control, channel header, enrolment) on
/// untrusted input. Must never panic.
pub fn decode(data: &[u8]) {
    let _ = control::decode::<CoreMessage>(data);
    let _ = control::decode::<AgentMessage>(data);
    let _ = enroll::decode_server(data);
    let _ = enroll::decode_client(data);
    if let Some(header) = data.first_chunk::<HEADER_LEN>() {
        let _ = channel::decode_header(header);
    }
}
