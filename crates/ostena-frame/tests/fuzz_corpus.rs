//! Replays the cargo-fuzz corpora (`fuzz/corpus/frame_*`) on the stable
//! toolchain, so that every input the fuzzer kept is a regression test.

#![allow(
    clippy::expect_used,
    clippy::too_many_lines,
    reason = "test helpers outside #[test] functions; seed list"
)]

use std::path::PathBuf;

fn replay(target: &str, run: fn(&[u8])) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/corpus")
        .join(target);
    let mut count = 0;
    for entry in std::fs::read_dir(&dir).expect("corpus directory must exist") {
        let data = std::fs::read(entry.expect("entry").path()).expect("corpus file");
        run(&data);
        count += 1;
    }
    assert!(count > 0, "empty corpus {}", dir.display());
}

#[test]
fn replay_frame_decode_corpus() {
    replay("frame_decode", ostena_frame::fuzz::decode);
}

#[test]
fn replay_frame_reassembly_corpus() {
    replay("frame_reassembly", ostena_frame::fuzz::reassembly);
}

/// Regenerates the seed inputs:
/// `cargo test -p ostena-frame --test fuzz_corpus -- --ignored`.
#[test]
#[ignore = "writes files; run on demand"]
fn write_seed_corpus() {
    use ostena_frame::payload::*;
    use ostena_frame::{Direction, Flags, FrameType, Payload, encode};

    let data = [0xabu8; 64];
    let size = Size {
        width: 1920,
        height: 1080,
        scale_percent: 125,
    };
    let payloads = [
        Payload::Hello {
            versions: 1,
            capabilities: 0,
        },
        Payload::HelloAck {
            version: 1,
            capabilities: 0,
        },
        Payload::Close { reason: 1 },
        Payload::Error { code: 9, detail: 0 },
        Payload::Ping { token: 1 },
        Payload::Pong { token: 1 },
        Payload::Ack { sequence: 41 },
        Payload::Resume { sequence: 41 },
        Payload::Key(KeyInput {
            code: 0x61,
            kind: KeyKind::Keysym,
            pressed: true,
            modifiers: 0,
        }),
        Payload::Pointer(PointerInput {
            x: 1,
            y: 2,
            buttons: 1,
            wheel_x: 0,
            wheel_y: 120,
        }),
        Payload::Touch(TouchInput {
            id: 1,
            phase: TouchPhase::Start,
            x: 3,
            y: 4,
            pressure: 9,
        }),
        Payload::DisplayUpdate {
            codec: Codec::Jpeg,
            rect: Rect {
                x: 0,
                y: 0,
                width: 8,
                height: 8,
            },
            data: Opaque::new(&data),
        },
        Payload::DisplaySize(size),
        Payload::ResizeRequest(size),
        Payload::ClipboardOffer(ClipboardFormats::TEXT),
        Payload::ClipboardData {
            format: ClipboardFormat::Html,
            data: Opaque::new(&data),
        },
        Payload::FileOffer {
            transfer: 1,
            size: 64,
            name: FileName::new("notes.txt").expect("valid name"),
        },
        Payload::FileChunk {
            transfer: 1,
            offset: 0,
            data: Opaque::new(&data),
        },
        Payload::FileEnd {
            transfer: 1,
            digest: [1; 32],
        },
        Payload::FileCancel {
            transfer: 1,
            reason: 3,
        },
        Payload::ObserverPresence {
            observers: 2,
            recording: true,
        },
    ];
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus");
    let mut stream = Vec::new();
    for p in &payloads {
        let t: FrameType = p.frame_type();
        let d = if t.allowed(Direction::ToGateway) {
            Direction::ToGateway
        } else {
            Direction::ToBrowser
        };
        let version = u8::from(!matches!(
            p,
            Payload::Hello { .. } | Payload::HelloAck { .. }
        ));
        let mut b = Vec::new();
        encode(p, d, version, 0, Flags::NONE, 0, &mut b).expect("encodable");
        std::fs::write(
            dir.join("frame_decode")
                .join(format!("seed-{:02x}", t as u8)),
            &b,
        )
        .expect("write");
        stream.extend_from_slice(&b);
    }
    std::fs::write(dir.join("frame_decode/seed-stream"), &stream).expect("write");
    // Reassembly input: [selector][flags][length][data]...
    let frags = [
        0u8, 1, 3, b'a', b'b', b'c', 0, 1, 2, b'd', b'e', 0, 0, 1, b'f', 1, 0, 0,
    ];
    std::fs::write(
        dir.join("frame_reassembly/seed-display-then-clipboard"),
        frags,
    )
    .expect("write");
    std::fs::write(dir.join("frame_reassembly/seed-empty"), b"").expect("write");
}
