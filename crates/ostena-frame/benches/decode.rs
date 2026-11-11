//! Micro-benchmark of frame decoding. Target (ADR-0006): an input frame in
//! less than 50 ns. Printed, not a gate yet.
//!
//! `cargo bench -p ostena-frame`

#![allow(
    clippy::unwrap_used,
    clippy::print_stdout,
    reason = "benchmark binary: prints its results, fixed inputs"
)]

use std::hint::black_box;
use std::time::Instant;

use ostena_frame::payload::{Codec, KeyInput, KeyKind, Opaque, PointerInput, Rect};
use ostena_frame::{Direction, Flags, Payload, Receiver, decode_message, encode};

const ITERATIONS: u32 = 5_000_000;

fn frame(p: &Payload<'_>, d: Direction) -> Vec<u8> {
    let mut b = Vec::new();
    encode(p, d, 1, 0, Flags::NONE, 0, &mut b).unwrap();
    b
}

fn bench(label: &str, mut f: impl FnMut()) {
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        f();
    }
    let ns = start.elapsed().as_secs_f64() * 1e9 / f64::from(ITERATIONS);
    println!("{label:<28} {ns:>6.1} ns");
}

fn main() {
    let key = frame(
        &Payload::Key(KeyInput {
            code: 0x1e,
            kind: KeyKind::Scancode,
            pressed: true,
            modifiers: 0,
        }),
        Direction::ToGateway,
    );
    let pointer = frame(
        &Payload::Pointer(PointerInput {
            x: 100,
            y: 200,
            buttons: 1,
            wheel_x: 0,
            wheel_y: -120,
        }),
        Direction::ToGateway,
    );
    let data = vec![1u8; 16 * 1024];
    let display = frame(
        &Payload::DisplayUpdate {
            codec: Codec::H264,
            rect: Rect {
                x: 0,
                y: 0,
                width: 640,
                height: 480,
            },
            data: Opaque::new(&data),
        },
        Direction::ToBrowser,
    );
    bench("decode key", || {
        black_box(decode_message(black_box(&key), Direction::ToGateway).unwrap());
    });
    bench("decode pointer", || {
        black_box(decode_message(black_box(&pointer), Direction::ToGateway).unwrap());
    });
    bench("decode + accept pointer", || {
        let mut r = Receiver::new();
        r.set_version(1);
        let f = decode_message(black_box(&pointer), Direction::ToGateway).unwrap();
        r.accept(&f).unwrap();
        black_box(&r);
    });
    bench("decode display (16 KiB)", || {
        black_box(decode_message(black_box(&display), Direction::ToBrowser).unwrap());
    });
}
