//! Entry points shared by the cargo-fuzz targets (`fuzz/`) and the stable
//! tests that replay their corpus. Not part of the API.

use alloc::vec::Vec;

use crate::codec::{Decoded, decode_message, decode_stream, encode};
use crate::header::{Direction, Flags};
use crate::reassembly::Reassembler;
use crate::session::Receiver;

/// Every decoder on arbitrary input, both directions. Must never panic, and a
/// decoded frame must re-encode to the same bytes.
pub fn decode(data: &[u8]) {
    for direction in [Direction::ToGateway, Direction::ToBrowser] {
        if let Ok(frame) = decode_message(data, direction) {
            let mut out = Vec::new();
            let h = frame.header;
            let reencoded = encode(
                &frame.payload,
                direction,
                h.version,
                h.channel,
                h.flags,
                h.sequence,
                &mut out,
            );
            assert!(
                reencoded.is_ok() && out == data,
                "decode then encode is not the identity"
            );
        }
        // The same bytes as a stream of frames.
        let mut rest = data;
        let mut receiver = Receiver::new();
        while let Ok(Decoded::Frame(frame, used)) = decode_stream(rest, direction) {
            let _ = receiver.accept(&frame);
            rest = &rest[used..];
        }
    }
}

/// Fragment streams: the input is cut into frames by its own length bytes,
/// fed to a receiver and a bounded reassembler. Must never panic.
pub fn reassembly(data: &[u8]) {
    let mut receiver = Receiver::new();
    receiver.set_version(1);
    let mut reassembler = Reassembler::new(64 * 1024, 4);
    let mut rest = data;
    let mut sequence = 0u64;
    while rest.len() >= 3 {
        // [type selector][flags][length] then data.
        let (selector, more, len) = (rest[0], rest[1] & 1 == 1, usize::from(rest[2]));
        let body = &rest[3..(3 + len).min(rest.len())];
        rest = &rest[3 + body.len()..];
        let payload = if selector % 2 == 0 {
            crate::payload::Payload::DisplayUpdate {
                codec: crate::payload::Codec::Png,
                rect: crate::payload::Rect {
                    x: 0,
                    y: 0,
                    width: u16::from(selector) + 1,
                    height: 1,
                },
                data: crate::payload::Opaque::new(if body.is_empty() { &[0] } else { body }),
            }
        } else {
            crate::payload::Payload::ClipboardData {
                format: crate::payload::ClipboardFormat::Text,
                data: crate::payload::Opaque::new(body),
            }
        };
        let flags = if more { Flags::MORE } else { Flags::NONE };
        let mut buf = Vec::new();
        if encode(
            &payload,
            Direction::ToBrowser,
            1,
            u16::from(selector % 3),
            flags,
            sequence,
            &mut buf,
        )
        .is_ok()
            && let Ok(frame) = decode_message(&buf, Direction::ToBrowser)
        {
            if receiver.accept(&frame).is_ok() {
                sequence += 1;
            }
            let _ = reassembler.feed(&frame);
        }
    }
}
