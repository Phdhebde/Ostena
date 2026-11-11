use alloc::vec::Vec;

use super::*;
use crate::codec::{decode_message, tests::samples};
use crate::payload::{Codec, KeyInput, KeyKind, PointerInput, Rect, Size};

const TO_GATEWAY: Direction = Direction::ToGateway;
const TO_BROWSER: Direction = Direction::ToBrowser;

fn out(p: &Payload<'_>, d: Direction) -> Outgoing {
    Outgoing::new(p, d, 0, Flags::NONE).unwrap()
}

fn pointer(x: u16, buttons: u8) -> Outgoing {
    out(
        &Payload::Pointer(PointerInput {
            x,
            y: 0,
            buttons,
            wheel_x: 0,
            wheel_y: 0,
        }),
        TO_GATEWAY,
    )
}

fn key() -> Outgoing {
    out(
        &Payload::Key(KeyInput {
            code: 1,
            kind: KeyKind::Keysym,
            pressed: true,
            modifiers: 0,
        }),
        TO_GATEWAY,
    )
}

fn display(len: usize) -> Vec<Outgoing> {
    let data = alloc::vec![1u8; len];
    let p = Payload::DisplayUpdate {
        codec: Codec::H264,
        rect: Rect {
            x: 0,
            y: 0,
            width: 8,
            height: 8,
        },
        data: Opaque::new(&data),
    };
    Outgoing::fragments(&p, TO_BROWSER, 0, 4096).unwrap()
}

fn drain(s: &mut Scheduler) -> Vec<FrameType> {
    core::iter::from_fn(|| s.pop())
        .map(|f| f.frame_type())
        .collect()
}

#[test]
fn inputs_and_control_pass_before_bulk() {
    let mut s = Scheduler::default();
    let resize = Payload::ResizeRequest(Size {
        width: 800,
        height: 600,
        scale_percent: 100,
    });
    s.push(out(&resize, TO_GATEWAY)).unwrap();
    s.push(out(&samples()[15], TO_GATEWAY)).unwrap(); // clipboard data
    s.push(key()).unwrap();
    s.push(out(&samples()[4], TO_GATEWAY)).unwrap(); // ping
    assert_eq!(
        drain(&mut s),
        [
            FrameType::Ping,
            FrameType::Key,
            FrameType::ResizeRequest,
            FrameType::ClipboardData
        ]
    );
}

#[test]
fn pointer_moves_are_coalesced_but_not_clicks() {
    let mut s = Scheduler::default();
    s.push(pointer(1, 0)).unwrap();
    s.push(pointer(2, 0)).unwrap();
    s.push(pointer(3, 1)).unwrap(); // button pressed: kept
    s.push(pointer(4, 1)).unwrap();
    s.push(key()).unwrap();
    s.push(pointer(5, 1)).unwrap(); // the key is in between: kept
    let xs: Vec<u16> = core::iter::from_fn(|| s.pop())
        .filter_map(|f| {
            let mut b = Vec::new();
            let mut sender = Sender::new(TO_GATEWAY);
            sender.set_version(1);
            sender.encode(&f, &mut b).unwrap();
            match decode_message(&b, TO_GATEWAY).unwrap().payload {
                Payload::Pointer(p) => Some(p.x),
                _ => None,
            }
        })
        .collect();
    assert_eq!(xs, [2, 4, 5]);
}

#[test]
fn resize_requests_keep_only_the_latest() {
    let mut s = Scheduler::default();
    for w in [640, 800, 1024] {
        let p = Payload::ResizeRequest(Size {
            width: w,
            height: 600,
            scale_percent: 100,
        });
        s.push(out(&p, TO_GATEWAY)).unwrap();
    }
    assert_eq!(s.len(), 1);
}

#[test]
fn bulk_classes_share_bandwidth() {
    let mut s = Scheduler::default();
    for f in display(200 * 1024) {
        s.push(f).unwrap();
    }
    let chunk = Payload::FileChunk {
        transfer: 1,
        offset: 0,
        data: Opaque::new(&[3u8; 16 * 1024]),
    };
    for _ in 0..20 {
        s.push(out(&chunk, TO_BROWSER)).unwrap();
    }
    // In the first 20 frames, the file transfer does not starve the display
    // nor the other way round.
    let first: Vec<FrameType> = (0..20)
        .filter_map(|_| s.pop().map(|f| f.frame_type()))
        .collect();
    let files = first.iter().filter(|t| **t == FrameType::FileChunk).count();
    assert!((3..=17).contains(&files), "{first:?}");
}

#[test]
fn a_new_input_overtakes_queued_display() {
    let mut s = Scheduler::default();
    for f in display(64 * 1024) {
        s.push(f).unwrap();
    }
    assert_eq!(
        s.pop().map(|f| f.frame_type()),
        Some(FrameType::DisplayUpdate)
    );
    s.push(out(&samples()[6], TO_BROWSER)).unwrap(); // Ack (control)
    assert_eq!(s.pop().map(|f| f.frame_type()), Some(FrameType::Ack));
}

#[test]
fn e012_full_queue() {
    let mut s = Scheduler::new(Limits {
        frames_per_class: 2,
        ..Limits::default()
    });
    s.push(key()).unwrap();
    s.push(key()).unwrap();
    assert_eq!(s.push(key()).unwrap_err().code, Code::QueueFull);
}

#[test]
fn fragments_carry_more_except_the_last() {
    let frags = display(10_000);
    assert_eq!(frags.len(), 3);
    assert!(frags[..2].iter().all(|f| f.flags.more()));
    assert!(!frags[2].flags.more());
    // 16 KiB at most, whatever the sender asks.
    let data = alloc::vec![0u8; 40_000];
    let p = Payload::ClipboardData {
        format: crate::payload::ClipboardFormat::Text,
        data: Opaque::new(&data),
    };
    let big = Outgoing::fragments(&p, TO_GATEWAY, 0, 1 << 20).unwrap();
    assert_eq!(big.len(), 3);
    assert!(Outgoing::fragments(&samples()[8], TO_GATEWAY, 0, 1024).is_err());
}

#[test]
fn sender_numbers_from_zero_and_requires_negotiation() {
    let mut sender = Sender::new(TO_GATEWAY);
    let mut buf = Vec::new();
    assert_eq!(
        sender.encode(&key(), &mut buf).unwrap_err().code,
        Code::NotNegotiated
    );
    sender
        .encode(&out(&samples()[0], TO_GATEWAY), &mut buf)
        .unwrap(); // Hello, seq 0
    sender.set_version(1);
    let mut k = Vec::new();
    sender.encode(&key(), &mut k).unwrap();
    let hello = decode_message(&buf, TO_GATEWAY).unwrap();
    let frame = decode_message(&k, TO_GATEWAY).unwrap();
    assert_eq!((hello.header.version, hello.header.sequence), (0, 0));
    assert_eq!((frame.header.version, frame.header.sequence), (1, 1));
    assert_eq!(sender.next_sequence(), 2);
}
