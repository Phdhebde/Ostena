//! Proves that decoding (and receive-side checks) do not allocate (dhat).
//! Alone in its file: dhat counts every allocation of the process.

#![allow(clippy::unwrap_used, reason = "test setup")]

use std::hint::black_box;

use ostena_frame::payload::{Codec, KeyInput, KeyKind, Opaque, PointerInput, Rect};
use ostena_frame::{Direction, Flags, Payload, Receiver, decode_message, decode_stream, encode};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[test]
fn decoding_does_not_allocate() {
    let data = vec![5u8; 16 * 1024];
    let inputs = [
        Payload::Key(KeyInput {
            code: 0x1e,
            kind: KeyKind::Scancode,
            pressed: true,
            modifiers: 0,
        }),
        Payload::Pointer(PointerInput {
            x: 1,
            y: 2,
            buttons: 1,
            wheel_x: 0,
            wheel_y: 0,
        }),
    ];
    let mut to_gateway = Vec::new();
    for (i, p) in inputs.iter().enumerate() {
        let mut b = Vec::new();
        encode(p, Direction::ToGateway, 1, 0, Flags::NONE, i as u64, &mut b).unwrap();
        to_gateway.push(b);
    }
    let display = Payload::DisplayUpdate {
        codec: Codec::H264,
        rect: Rect {
            x: 0,
            y: 0,
            width: 640,
            height: 480,
        },
        data: Opaque::new(&data),
    };
    let mut to_browser = Vec::new();
    encode(
        &display,
        Direction::ToBrowser,
        1,
        1,
        Flags::NONE,
        0,
        &mut to_browser,
    )
    .unwrap();

    let _profiler = dhat::Profiler::builder().testing().build();
    let before = dhat::HeapStats::get();
    for _ in 0..1000 {
        let mut receiver = Receiver::new();
        receiver.set_version(1);
        for b in &to_gateway {
            let frame = decode_message(black_box(b), Direction::ToGateway).unwrap();
            receiver.accept(&frame).unwrap();
            black_box(frame);
        }
        black_box(decode_message(black_box(&to_browser), Direction::ToBrowser).unwrap());
        black_box(decode_stream(black_box(&to_browser), Direction::ToBrowser).unwrap());
    }
    let after = dhat::HeapStats::get();
    dhat::assert_eq!(after.total_blocks, before.total_blocks);
}
