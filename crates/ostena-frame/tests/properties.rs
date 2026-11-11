//! Properties of the framing (ADR-0006).

#![allow(
    clippy::unwrap_used,
    clippy::many_single_char_names,
    clippy::too_many_lines,
    reason = "test generators: one arm per frame type"
)]

use ostena_frame::payload::{
    ClipboardFormat, ClipboardFormats, Codec, FileName, KeyInput, KeyKind, Opaque, PointerInput,
    Rect, Size, TouchInput, TouchPhase,
};
use ostena_frame::{
    Class, Direction, Flags, MAX_FRAGMENT, Outgoing, Payload, Scheduler, decode_message, encode,
};
use proptest::prelude::*;

/// A payload with owned data, from which a borrowed [`Payload`] is built.
#[derive(Debug, Clone)]
struct Owned {
    kind: u8,
    a: u64,
    b: u32,
    c: u16,
    d: u16,
    e: u8,
    data: Vec<u8>,
    name: String,
}

impl Owned {
    fn payload(&self) -> Payload<'_> {
        let (a, b, c, d, e) = (self.a, self.b, self.c, self.d, self.e);
        let size = Size {
            width: c % 16_384 + 1,
            height: d % 16_384 + 1,
            scale_percent: 50 + c % 351,
        };
        let rect = Rect {
            x: c,
            y: d,
            width: c.max(1),
            height: d.max(1),
        };
        let data = Opaque::new(&self.data);
        let nonempty = Opaque::new(if self.data.is_empty() {
            &[0]
        } else {
            &self.data
        });
        match self.kind % 21 {
            0 => Payload::Hello {
                versions: b.max(1),
                capabilities: 0,
            },
            1 => Payload::HelloAck {
                version: e % 32 + 1,
                capabilities: 0,
            },
            2 => Payload::Close { reason: c },
            3 => Payload::Error { code: c, detail: d },
            4 => Payload::Ping { token: a },
            5 => Payload::Pong { token: a },
            6 => Payload::Ack { sequence: a },
            7 => Payload::Resume { sequence: a },
            8 => Payload::Key(KeyInput {
                code: b,
                kind: if e % 2 == 0 {
                    KeyKind::Scancode
                } else {
                    KeyKind::Keysym
                },
                pressed: e % 3 == 0,
                modifiers: c,
            }),
            9 => Payload::Pointer(PointerInput {
                x: c,
                y: d,
                buttons: e & 0x1f,
                wheel_x: c.cast_signed(),
                wheel_y: d.cast_signed(),
            }),
            10 => Payload::Touch(TouchInput {
                id: c,
                phase: [
                    TouchPhase::Start,
                    TouchPhase::Move,
                    TouchPhase::End,
                    TouchPhase::Cancel,
                ][usize::from(e % 4)],
                x: c,
                y: d,
                pressure: c ^ d,
            }),
            11 => Payload::DisplayUpdate {
                codec: [Codec::Raw, Codec::Png, Codec::Jpeg, Codec::H264][usize::from(e % 4)],
                rect,
                data: nonempty,
            },
            12 => Payload::DisplaySize(size),
            13 => Payload::ResizeRequest(size),
            14 => Payload::ClipboardOffer(ClipboardFormats::from_bits(b & 0b111).unwrap()),
            15 => Payload::ClipboardData {
                format: [
                    ClipboardFormat::Text,
                    ClipboardFormat::Html,
                    ClipboardFormat::Png,
                ][usize::from(e % 3)],
                data,
            },
            16 => Payload::FileOffer {
                transfer: b,
                size: a,
                name: FileName::new(&self.name).unwrap(),
            },
            17 => Payload::FileChunk {
                transfer: b,
                offset: a,
                data: nonempty,
            },
            18 => Payload::FileEnd {
                transfer: b,
                digest: [e; 32],
            },
            19 => Payload::FileCancel {
                transfer: b,
                reason: c,
            },
            _ => Payload::ObserverPresence {
                observers: c,
                recording: e % 2 == 1,
            },
        }
    }
}

fn owned() -> impl Strategy<Value = Owned> {
    (
        any::<u8>(),
        any::<u64>(),
        any::<u32>(),
        any::<u16>(),
        any::<u16>(),
        any::<u8>(),
        prop_oneof![
            9 => proptest::collection::vec(any::<u8>(), 0..512),
            // Full-size fragments, without generating 16 KiB byte by byte.
            1 => any::<u8>().prop_map(|b| vec![b; MAX_FRAGMENT]),
        ],
        "f[a-zA-Z0-9_-]{0,40}\\.(txt|pdf|log)",
    )
        .prop_map(|(kind, a, b, c, d, e, data, name)| Owned {
            kind,
            a,
            b,
            c,
            d,
            e,
            data,
            name,
        })
}

fn direction_of(p: &Payload<'_>) -> Direction {
    if p.frame_type().allowed(Direction::ToGateway) {
        Direction::ToGateway
    } else {
        Direction::ToBrowser
    }
}

fn version_of(p: &Payload<'_>) -> u8 {
    u8::from(!matches!(
        p,
        Payload::Hello { .. } | Payload::HelloAck { .. }
    ))
}

fn encoded(o: &Owned, channel: u16, seq: u64) -> (Vec<u8>, Direction) {
    let p = o.payload();
    let d = direction_of(&p);
    let channel = if p.frame_type().channel_zero_only() {
        0
    } else {
        channel
    };
    let mut out = Vec::new();
    encode(&p, d, version_of(&p), channel, Flags::NONE, seq, &mut out).unwrap();
    (out, d)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Encode then decode is the identity, for every type.
    #[test]
    fn prop_encode_decode_identity(o in owned(), channel in any::<u16>(), seq in any::<u64>()) {
        let (bytes, d) = encoded(&o, channel, seq);
        let frame = decode_message(&bytes, d).unwrap();
        prop_assert_eq!(frame.payload, o.payload());
        prop_assert_eq!(frame.header.sequence, seq);
        // And decode then encode gives back the same bytes.
        let h = frame.header;
        let mut again = Vec::new();
        encode(&frame.payload, d, h.version, h.channel, h.flags, h.sequence, &mut again).unwrap();
        prop_assert_eq!(again, bytes);
    }

    /// Any truncated or extended frame is refused.
    #[test]
    fn prop_truncated_or_extended_is_refused(o in owned(), cut in any::<prop::sample::Index>(), extra in proptest::collection::vec(any::<u8>(), 1..32)) {
        let (bytes, d) = encoded(&o, 0, 0);
        let cut = cut.index(bytes.len());
        prop_assert!(decode_message(&bytes[..cut], d).is_err());
        let mut longer = bytes.clone();
        longer.extend_from_slice(&extra);
        prop_assert!(decode_message(&longer, d).is_err());
    }

    /// A type received in the wrong direction is refused.
    #[test]
    fn prop_wrong_direction_is_refused(o in owned()) {
        let (bytes, d) = encoded(&o, 0, 0);
        let t = o.payload().frame_type();
        let other = match d { Direction::ToGateway => Direction::ToBrowser, Direction::ToBrowser => Direction::ToGateway };
        if !t.allowed(other) {
            prop_assert!(decode_message(&bytes, other).is_err());
        }
    }

    /// Whatever is queued, no frame of a lower class leaves while a frame of
    /// a higher class is waiting: inputs always pass before the display.
    #[test]
    fn prop_scheduler_respects_priority(items in proptest::collection::vec((owned(), any::<bool>()), 1..60)) {
        let mut s = Scheduler::default();
        for (o, pop_now) in &items {
            let p = o.payload();
            let f = Outgoing::new(&p, direction_of(&p), 0, Flags::NONE).unwrap();
            let _ = s.push(f);
            if *pop_now && let Some(f) = s.pop() {
                let c = f.frame_type().class();
                prop_assert!(!queued_higher(&s, c), "{c:?} left before a higher class");
            }
        }
        while let Some(f) = s.pop() {
            let c = f.frame_type().class();
            prop_assert!(!queued_higher(&s, c), "{c:?} left before a higher class");
        }
    }
}

/// Whether a frame of a strictly higher priority class than `c` is waiting
/// (bulk classes share the same level).
fn queued_higher(s: &Scheduler, c: Class) -> bool {
    let level = |k: Class| match k {
        Class::Control => 0,
        Class::Input => 1,
        Class::Audit => 2,
        Class::Display | Class::Clipboard | Class::File => 3,
    };
    [
        Class::Control,
        Class::Input,
        Class::Audit,
        Class::Display,
        Class::Clipboard,
        Class::File,
    ]
    .into_iter()
    .any(|k| s.is_waiting(k) && level(k) < level(c))
}
