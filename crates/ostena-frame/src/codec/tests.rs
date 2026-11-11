use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::error::Code;
use crate::header::{CURRENT_VERSION, FrameType, MAX_FRAGMENT};
use crate::payload::*;
use crate::reassembly::{Kind, Reassembler};
use crate::session::{Receiver, SUPPORTED_VERSIONS, negotiate};

static DATA: [u8; 64] = [0xab; 64];
static BIG: [u8; MAX_FRAGMENT] = [7; MAX_FRAGMENT];

/// One payload of every v1 type.
pub(crate) fn samples() -> Vec<Payload<'static>> {
    let size = Size {
        width: 1920,
        height: 1080,
        scale_percent: 100,
    };
    vec![
        Payload::Hello {
            versions: SUPPORTED_VERSIONS,
            capabilities: 0,
        },
        Payload::HelloAck {
            version: 1,
            capabilities: 0,
        },
        Payload::Close { reason: 1 },
        Payload::Error {
            code: Code::Length.number(),
            detail: 0x20,
        },
        Payload::Ping { token: 42 },
        Payload::Pong { token: 42 },
        Payload::Ack { sequence: 9 },
        Payload::Resume { sequence: 9 },
        Payload::Key(KeyInput {
            code: 0x1e,
            kind: KeyKind::Scancode,
            pressed: true,
            modifiers: 1,
        }),
        Payload::Pointer(PointerInput {
            x: 10,
            y: 20,
            buttons: 1,
            wheel_x: 0,
            wheel_y: -120,
        }),
        Payload::Touch(TouchInput {
            id: 3,
            phase: TouchPhase::Move,
            x: 5,
            y: 6,
            pressure: 300,
        }),
        Payload::DisplayUpdate {
            codec: Codec::Png,
            rect: Rect {
                x: 0,
                y: 0,
                width: 64,
                height: 64,
            },
            data: Opaque::new(&DATA),
        },
        Payload::DisplaySize(size),
        Payload::ResizeRequest(size),
        Payload::ClipboardOffer(ClipboardFormats::TEXT),
        Payload::ClipboardData {
            format: ClipboardFormat::Text,
            data: Opaque::new(&DATA),
        },
        Payload::FileOffer {
            transfer: 7,
            size: 1 << 20,
            name: FileName::new("rapport.pdf").unwrap(),
        },
        Payload::FileChunk {
            transfer: 7,
            offset: 0,
            data: Opaque::new(&BIG),
        },
        Payload::FileEnd {
            transfer: 7,
            digest: [9; 32],
        },
        Payload::FileCancel {
            transfer: 7,
            reason: 2,
        },
        Payload::ObserverPresence {
            observers: 1,
            recording: true,
        },
    ]
}

fn version_for(p: &Payload<'_>) -> u8 {
    if matches!(p, Payload::Hello { .. } | Payload::HelloAck { .. }) {
        0
    } else {
        CURRENT_VERSION
    }
}

fn bytes(p: &Payload<'_>, direction: Direction) -> Vec<u8> {
    let mut out = Vec::new();
    encode(p, direction, version_for(p), 0, Flags::NONE, 5, &mut out).unwrap();
    out
}

fn allowed_direction(t: FrameType) -> Direction {
    if t.allowed(Direction::ToGateway) {
        Direction::ToGateway
    } else {
        Direction::ToBrowser
    }
}

fn code(buf: &[u8], direction: Direction) -> Code {
    decode_message(buf, direction).unwrap_err().code
}

#[test]
fn every_type_round_trips_in_its_directions() {
    let all = samples();
    assert_eq!(all.len(), FrameType::ALL.len());
    for p in &all {
        for direction in [Direction::ToGateway, Direction::ToBrowser] {
            let mut out = Vec::new();
            let encoded = encode(p, direction, version_for(p), 0, Flags::NONE, 5, &mut out);
            if p.frame_type().allowed(direction) {
                encoded.unwrap();
                let frame = decode_message(&out, direction).unwrap();
                assert_eq!(frame.payload, *p);
                assert_eq!(frame.header.sequence, 5);
                assert_eq!(usize::from(frame.header.length), p.encoded_len());
            } else {
                assert_eq!(
                    encoded.unwrap_err().code,
                    Code::WrongDirection,
                    "{:?}",
                    p.frame_type()
                );
                // Crafted anyway: the decoder refuses it too (E005).
                let other = match direction {
                    Direction::ToGateway => Direction::ToBrowser,
                    Direction::ToBrowser => Direction::ToGateway,
                };
                let crafted = bytes(p, other);
                assert_eq!(
                    code(&crafted, direction),
                    Code::WrongDirection,
                    "{:?}",
                    p.frame_type()
                );
            }
        }
    }
}

#[test]
fn e001_e002_truncated_and_extended() {
    for p in samples() {
        let d = allowed_direction(p.frame_type());
        let b = bytes(&p, d);
        assert_eq!(code(&b[..b.len() - 1], d), Code::Truncated);
        assert_eq!(code(&b[..HEADER_LEN - 1], d), Code::Truncated);
        let mut longer = b.clone();
        longer.push(0);
        assert_eq!(code(&longer, d), Code::TrailingBytes);
    }
}

#[test]
fn e003_versions() {
    let key = samples()[8];
    let mut b = bytes(&key, Direction::ToGateway);
    b[0] = 2;
    assert_eq!(code(&b, Direction::ToGateway), Code::Version);
    b[0] = 0; // inputs never use the negotiation version
    assert_eq!(code(&b, Direction::ToGateway), Code::Version);
    let mut hello = bytes(&samples()[0], Direction::ToGateway);
    hello[0] = 1; // Hello is always version 0
    assert_eq!(code(&hello, Direction::ToGateway), Code::Version);
    // Error and Close accept both.
    let mut err = bytes(&samples()[3], Direction::ToBrowser);
    err[0] = 0;
    assert!(decode_message(&err, Direction::ToBrowser).is_ok());
}

#[test]
fn e004_unknown_type() {
    let mut b = bytes(&samples()[4], Direction::ToBrowser);
    for t in [0x00, 0x09, 0x13, 0x60, 0xff] {
        b[1] = t;
        assert_eq!(code(&b, Direction::ToBrowser), Code::UnknownType, "{t:#x}");
    }
}

#[test]
fn e006_lengths() {
    // Declared length above the type maximum, refused from the header alone.
    let mut b = bytes(&samples()[9], Direction::ToGateway);
    b[6..8].copy_from_slice(&10u16.to_be_bytes());
    assert_eq!(code(&b[..HEADER_LEN], Direction::ToGateway), Code::Length);
    // A fixed-size type with a shorter payload.
    let mut b = bytes(&samples()[4], Direction::ToBrowser);
    b[6..8].copy_from_slice(&7u16.to_be_bytes());
    b.pop();
    assert_eq!(code(&b, Direction::ToBrowser), Code::Length);
    // Display data above 16 KiB cannot be expressed: max_payload bounds it.
    assert_eq!(FrameType::DisplayUpdate.max_payload(), 9 + MAX_FRAGMENT);
    // Empty display data and empty file chunk.
    let mut d = bytes(&samples()[11], Direction::ToBrowser);
    d.truncate(HEADER_LEN + 9);
    d[6..8].copy_from_slice(&9u16.to_be_bytes());
    assert_eq!(code(&d, Direction::ToBrowser), Code::Length);
}

#[test]
fn e007_reserved() {
    let mut b = bytes(&samples()[4], Direction::ToBrowser);
    b[3] = 1;
    assert_eq!(code(&b, Direction::ToBrowser), Code::Reserved);
    let mut b = bytes(&samples()[4], Direction::ToBrowser);
    b[2] = 0x02;
    assert_eq!(code(&b, Direction::ToBrowser), Code::Reserved);
    let mut close = bytes(&samples()[2], Direction::ToBrowser);
    close[HEADER_LEN + 3] = 1;
    assert_eq!(code(&close, Direction::ToBrowser), Code::Reserved);
    let mut hello = bytes(&samples()[0], Direction::ToGateway);
    hello[HEADER_LEN + 7] = 1; // capabilities reserved in v1
    assert_eq!(code(&hello, Direction::ToGateway), Code::Reserved);
}

#[test]
fn e008_invalid_fields() {
    let cases: [(usize, usize, u8, Direction); 7] = [
        (0, 3, 0, Direction::ToGateway),    // Hello without any version
        (8, 4, 3, Direction::ToGateway),    // unknown key kind
        (8, 5, 2, Direction::ToGateway),    // unknown key state
        (9, 4, 0x20, Direction::ToGateway), // unknown pointer button
        (10, 2, 4, Direction::ToGateway),   // unknown touch phase
        (11, 0, 9, Direction::ToBrowser),   // unknown codec
        (15, 0, 3, Direction::ToGateway),   // unknown clipboard format
    ];
    let all = samples();
    for (sample, offset, value, d) in cases {
        let mut b = bytes(&all[sample], d);
        if sample == 0 {
            b[HEADER_LEN..HEADER_LEN + 4].fill(0);
        } else {
            b[HEADER_LEN + offset] = value;
        }
        assert_eq!(code(&b, d), Code::InvalidField, "sample {sample}");
    }
    let mut size = bytes(&all[13], Direction::ToGateway);
    size[HEADER_LEN..HEADER_LEN + 2].fill(0);
    assert_eq!(code(&size, Direction::ToGateway), Code::InvalidField);
    let mut name = bytes(&all[16], Direction::ToBrowser);
    let at = name.len() - 3;
    name[at..].copy_from_slice(b"..\\"); // "rapport...\\": backslash
    assert_eq!(code(&name, Direction::ToBrowser), Code::InvalidField);
}

#[test]
fn e011_more_on_non_fragmentable() {
    let mut out = Vec::new();
    let r = encode(
        &samples()[9],
        Direction::ToGateway,
        1,
        0,
        Flags::MORE,
        0,
        &mut out,
    );
    assert_eq!(r.unwrap_err().code, Code::Fragmentation);
    let mut b = bytes(&samples()[9], Direction::ToGateway);
    b[2] = 1;
    assert_eq!(code(&b, Direction::ToGateway), Code::Fragmentation);
}

#[test]
fn e014_control_on_channel_zero() {
    let mut out = Vec::new();
    let r = encode(
        &samples()[4],
        Direction::ToBrowser,
        1,
        3,
        Flags::NONE,
        0,
        &mut out,
    );
    assert_eq!(r.unwrap_err().code, Code::Channel);
    let mut b = bytes(&samples()[20], Direction::ToBrowser);
    b[5] = 1;
    assert_eq!(code(&b, Direction::ToBrowser), Code::Channel);
    // Other types may use any channel.
    let mut out = Vec::new();
    encode(
        &samples()[11],
        Direction::ToBrowser,
        1,
        7,
        Flags::NONE,
        0,
        &mut out,
    )
    .unwrap();
}

#[test]
fn stream_decoding() {
    let mut stream = Vec::new();
    for p in samples()
        .iter()
        .filter(|p| p.frame_type().allowed(Direction::ToBrowser))
    {
        stream.extend(bytes(p, Direction::ToBrowser));
    }
    let mut rest = &stream[..];
    let mut count = 0;
    while !rest.is_empty() {
        // Every strict prefix of the next frame is incomplete, not an error.
        let Decoded::Frame(_, used) = decode_stream(rest, Direction::ToBrowser).unwrap() else {
            panic!("frame expected")
        };
        for cut in [0, 1, HEADER_LEN - 1, HEADER_LEN, used - 1] {
            assert!(matches!(
                decode_stream(&rest[..cut], Direction::ToBrowser),
                Ok(Decoded::Incomplete { .. })
            ));
        }
        rest = &rest[used..];
        count += 1;
    }
    let expected = FrameType::ALL
        .iter()
        .filter(|t| t.allowed(Direction::ToBrowser))
        .count();
    assert_eq!((count, expected), (16, 16));
    // An oversized header is refused before its payload arrives.
    let mut b = bytes(&samples()[4], Direction::ToBrowser);
    b[6..8].copy_from_slice(&u16::MAX.to_be_bytes());
    assert_eq!(
        decode_stream(&b[..HEADER_LEN], Direction::ToBrowser)
            .unwrap_err()
            .code,
        Code::Length
    );
}

fn frame_bytes(
    p: &Payload<'_>,
    d: Direction,
    version: u8,
    channel: u16,
    flags: Flags,
    seq: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    encode(p, d, version, channel, flags, seq, &mut out).unwrap();
    out
}

#[test]
fn receiver_negotiation_and_sequence() {
    let all = samples();
    let mut gateway = Receiver::new();
    // E013: an input before negotiation.
    let key = frame_bytes(&all[8], Direction::ToGateway, 1, 0, Flags::NONE, 0);
    let f = decode_message(&key, Direction::ToGateway).unwrap();
    assert_eq!(gateway.accept(&f).unwrap_err().code, Code::NotNegotiated);
    // Hello at sequence 0, then the gateway negotiates.
    let hello = frame_bytes(&all[0], Direction::ToGateway, 0, 0, Flags::NONE, 0);
    let f = decode_message(&hello, Direction::ToGateway).unwrap();
    gateway.accept(&f).unwrap();
    let Payload::Hello { versions, .. } = f.payload else {
        unreachable!()
    };
    gateway.set_version(negotiate(SUPPORTED_VERSIONS, versions).unwrap());
    // E010: duplicate (0) and gap (2).
    for seq in [0, 2] {
        let k = frame_bytes(&all[8], Direction::ToGateway, 1, 0, Flags::NONE, seq);
        let f = decode_message(&k, Direction::ToGateway).unwrap();
        assert_eq!(gateway.accept(&f).unwrap_err().code, Code::Sequence);
    }
    let k = frame_bytes(&all[8], Direction::ToGateway, 1, 0, Flags::NONE, 1);
    gateway
        .accept(&decode_message(&k, Direction::ToGateway).unwrap())
        .unwrap();
    assert_eq!(gateway.next_sequence(), 2);
    // A second Hello is refused.
    let again = frame_bytes(&all[0], Direction::ToGateway, 0, 0, Flags::NONE, 2);
    assert_eq!(
        gateway
            .accept(&decode_message(&again, Direction::ToGateway).unwrap())
            .unwrap_err()
            .code,
        Code::Version
    );

    // Browser side: HelloAck sets the version; an unsupported one is refused.
    let mut browser = Receiver::new();
    let ack = frame_bytes(&all[1], Direction::ToBrowser, 0, 0, Flags::NONE, 0);
    browser
        .accept(&decode_message(&ack, Direction::ToBrowser).unwrap())
        .unwrap();
    assert_eq!(browser.version(), Some(1));
    let mut other = Receiver::new();
    let bad = frame_bytes(
        &Payload::HelloAck {
            version: 2,
            capabilities: 0,
        },
        Direction::ToBrowser,
        0,
        0,
        Flags::NONE,
        0,
    );
    assert_eq!(
        other
            .accept(&decode_message(&bad, Direction::ToBrowser).unwrap())
            .unwrap_err()
            .code,
        Code::NoCommonVersion
    );
}

#[test]
fn e009_no_common_version() {
    assert_eq!(
        negotiate(SUPPORTED_VERSIONS, 0b10).unwrap_err().code,
        Code::NoCommonVersion
    );
}

#[test]
fn reassembly() {
    let part = |data: &'static [u8], more: bool, seq: u64| {
        let p = Payload::DisplayUpdate {
            codec: Codec::Jpeg,
            rect: Rect {
                x: 1,
                y: 2,
                width: 3,
                height: 4,
            },
            data: Opaque::new(data),
        };
        frame_bytes(
            &p,
            Direction::ToBrowser,
            1,
            2,
            if more { Flags::MORE } else { Flags::NONE },
            seq,
        )
    };
    let frames = [
        part(b"abc", true, 0),
        part(b"def", true, 1),
        part(b"g", false, 2),
    ];
    let mut r = Reassembler::new(16, 2);
    let mut recv = Receiver::new();
    recv.set_version(1);
    let mut done = None;
    for f in &frames {
        let frame = decode_message(f, Direction::ToBrowser).unwrap();
        recv.accept(&frame).unwrap();
        done = r.feed(&frame).unwrap();
    }
    let m = done.unwrap();
    assert_eq!(m.data, b"abcdefg");
    assert_eq!(m.channel, 2);
    assert!(matches!(
        m.kind,
        Kind::Display {
            codec: Codec::Jpeg,
            ..
        }
    ));

    // Over the bound.
    let mut small = Reassembler::new(5, 2);
    let first = decode_message(&frames[0], Direction::ToBrowser).unwrap();
    let second = decode_message(&frames[1], Direction::ToBrowser).unwrap();
    small.feed(&first).unwrap();
    assert_eq!(small.feed(&second).unwrap_err().code, Code::Fragmentation);

    // A fragment with another rectangle.
    let mut r = Reassembler::new(64, 2);
    r.feed(&first).unwrap();
    let other = Payload::DisplayUpdate {
        codec: Codec::Jpeg,
        rect: Rect {
            x: 9,
            y: 2,
            width: 3,
            height: 4,
        },
        data: Opaque::new(b"x"),
    };
    let b = frame_bytes(&other, Direction::ToBrowser, 1, 2, Flags::NONE, 1);
    assert_eq!(
        r.feed(&decode_message(&b, Direction::ToBrowser).unwrap())
            .unwrap_err()
            .code,
        Code::Fragmentation
    );
}
