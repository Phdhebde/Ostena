//! Entry points for `cargo fuzz` (the `fuzz/` workspace) and for the stable
//! tests that replay their corpora (ADR-0019 section 7). Each one takes
//! arbitrary bytes from the target and must never panic.
//!
//! The answers of a KDC are not fuzzed here: `sspi` 0.23.0 panics on an
//! empty encryption type list (`unwrap()` on KDC data, reported upstream),
//! which a fuzzer finds at once. In the agent that panic is contained to
//! the task of the connection (`RDP-E099`).

use ironrdp_core::decode;
use ironrdp_pdu::mcs::McsMessage;
use ironrdp_pdu::nego::ConnectionConfirm;
use ironrdp_pdu::rdp::server_license::LicensePdu;
use ironrdp_pdu::x224::X224;
use sspi::credssp::{EarlyUserAuthResult, TsRequest};

use crate::session::Demux;
use crate::{credssp, guard, profile};

/// X.224 Connection Confirm, negotiation response or failure, through the
/// guard in both modes.
pub fn x224(data: &[u8]) {
    let _ = decode::<X224<ConnectionConfirm>>(data);
    let _ = guard::check_connection_confirm(data, false);
    let _ = guard::check_connection_confirm(data, true);
}

/// MCS Connect Response with the server GCC blocks, channel join confirms
/// and other MCS messages; the guard on a Connect Initial.
pub fn mcs_gcc(data: &[u8]) {
    let _ = profile::server_settings(data);
    let _ = decode::<X224<McsMessage<'_>>>(data);
    let _ = guard::early_capabilities_of(data);
    let _ = guard::rewrite_connect_initial(data, guard::allowed_early_capabilities());
}

/// `TSRequest` (DER), with its SPNEGO tokens checked for NTLM, and the
/// Early User Authorization Result.
pub fn ts_request(data: &[u8]) {
    if let Ok(Some(size)) = credssp::ts_request_size(data)
        && let Some(bytes) = data.get(..size)
        && let Ok(request) = TsRequest::from_buffer(bytes)
    {
        for token in [
            &request.nego_tokens,
            &request.pub_key_auth,
            &request.auth_info,
        ]
        .into_iter()
        .flatten()
        {
            let _ = credssp::carries_ntlm(token);
        }
    }
    let _ = EarlyUserAuthResult::from_buffer(data);
}

/// Licensing PDUs (request, platform challenge, new or upgraded licence,
/// error), raw and inside an MCS indication.
pub fn license(data: &[u8]) {
    let _ = decode::<LicensePdu>(data);
    if let Ok(indication) = ironrdp_pdu::mcs::decode_send_data_indication(data) {
        let _ = decode::<LicensePdu>(indication.user_data);
    }
}

/// The session demultiplexer: fast-path and slow-path frames, I/O channel
/// (error information, deactivation, redirection), message channel
/// (Auto-Detect). The first two bytes choose the channels.
pub fn session(data: &[u8]) {
    let (head, frames) = data.split_at(data.len().min(2));
    let io = 1003;
    let message = head.first().map(|b| 1003 + u16::from(*b % 4));
    let mut demux = Demux::new(io, message, 1002);
    let _ = demux.feed(frames);
}
