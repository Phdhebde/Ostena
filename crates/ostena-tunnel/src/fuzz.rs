//! Entry point shared by the cargo-fuzz target (`fuzz/`) and the stable test
//! that replays its corpus. Not part of the API.

use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Notify;

use crate::channel::{self, HEADER_LEN};
use crate::control::{self, AgentMessage, CoreMessage};
use crate::enroll;
use crate::limits::Limits;
use crate::mux::frame;
use crate::mux::state::{Side, State};

/// Runs every decoder of the tunnel (control, channel header, enrolment,
/// browser stream opening and answer) on untrusted input. Must never panic.
pub fn decode(data: &[u8]) {
    let _ = control::decode::<CoreMessage>(data);
    let _ = control::decode::<AgentMessage>(data);
    let _ = enroll::decode_server(data);
    let _ = enroll::decode_client(data);
    let _ = crate::browser::decode_open(data);
    let _ = crate::browser::Answer::decode(data);
    if let Some(header) = data.first_chunk::<HEADER_LEN>() {
        let _ = channel::decode_header(header);
    }
}

/// Feeds untrusted bytes to the TCP multiplexer as its peer would: the
/// frames decoded from `data` drive a connection state (core side), which
/// reads what arrives, answers and drains its writer between frames. Must
/// never panic, and the state must stay within its bounds.
///
/// A first byte of 0 starts with valid settings, so that the fuzzer
/// reaches the streams quickly.
pub fn mux(data: &[u8]) {
    let limits = Limits {
        max_sessions: 2,
        stream_window: 16 * 1024,
        connection_window: 64 * 1024,
        ..Limits::default()
    };
    let mut state = State::new(
        Side::Core,
        limits,
        Arc::new(Notify::new()),
        Arc::new(Notify::new()),
    );
    let now = Instant::now();
    let mut input = Vec::with_capacity(data.len() + 32);
    if data.first() == Some(&0) {
        let peer = State::new(
            Side::Agent,
            limits,
            Arc::new(Notify::new()),
            Arc::new(Notify::new()),
        );
        frame::encode(&peer.settings(), &mut input);
        input.extend_from_slice(&data[1..]);
    } else {
        input.extend_from_slice(data);
    }
    let mut at = 0;
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let mut accepted = Vec::new();
    while let Ok(Some((f, used))) = frame::decode(&input[at..]) {
        at += used;
        if state.on_frame(&f, now).is_err() {
            break;
        }
        while let Ok(Some((id, _))) = state.accept() {
            accepted.push(id);
        }
        for (i, id) in accepted.iter().enumerate() {
            let _ = state.read(*id, &mut buf);
            if i % 2 == 0 {
                let _ = state.write(*id, &buf[..64]);
            }
            if i % 3 == 0 {
                let _ = state.finish(*id);
            }
        }
        out.clear();
        state.next_batch(&mut out, 64 * 1024);
        assert!(state.stream_count() <= limits.max_streams() as usize);
        assert!(state.buffered() <= 2 * limits.connection_window as usize);
    }
}
