use proptest::prelude::*;

use super::*;

fn start(command: Option<&[u8]>) -> Frame {
    Frame {
        at_us: 0,
        event: Event::Start {
            cols: 80,
            rows: 24,
            started_ms: 1_800_000_000_123,
            term: "xterm-256color".into(),
            command: command.map(<[u8]>::to_vec),
        },
    }
}

fn output(at_us: u64, data: &[u8]) -> Frame {
    Frame {
        at_us,
        event: Event::Output(data.to_vec()),
    }
}

fn end(at_us: u64, output_bytes: u64) -> Frame {
    Frame {
        at_us,
        event: Event::End {
            reason: EndReason::Closed,
            output_bytes,
        },
    }
}

fn stream(frames: &[Frame]) -> Vec<u8> {
    let mut out = Vec::new();
    for f in frames {
        encode(f, &mut out).unwrap();
    }
    out
}

fn decode_all(bytes: &[u8], limits: Limits) -> Result<Vec<Frame>, RecorderError> {
    let mut d = Decoder::new(limits);
    d.feed(bytes);
    let mut frames = Vec::new();
    while let Some(f) = d.next_frame()? {
        frames.push(f);
    }
    d.finish()?;
    Ok(frames)
}

fn session() -> Vec<Frame> {
    vec![
        start(None),
        output(10, b"bonjour\r\n"),
        Frame {
            at_us: 20,
            event: Event::Resize {
                cols: 132,
                rows: 50,
            },
        },
        output(20, b"$ "),
        end(1_000_000, 11),
    ]
}

#[test]
fn a_session_round_trips() {
    let frames = session();
    assert_eq!(decode_all(&stream(&frames), Limits::default()), Ok(frames));
    let exec = vec![start(Some(b"uname -a")), end(5, 0)];
    assert_eq!(decode_all(&stream(&exec), Limits::default()), Ok(exec));
}

#[test]
fn known_encoding() {
    let mut out = Vec::new();
    encode(&output(0x0102, b"ab"), &mut out).unwrap();
    assert_eq!(out, [2, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 2, b'a', b'b']);
    out.clear();
    encode(&end(0, 7), &mut out).unwrap();
    assert_eq!(
        out,
        [
            4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 1, 0, 0, 0, 0, 0, 0, 0, 7
        ]
    );
}

#[test]
fn encoding_refuses_events_out_of_bounds() {
    let mut out = Vec::new();
    assert!(encode(&output(0, b""), &mut out).is_err());
    assert_eq!(out, Vec::<u8>::new());
}

#[test]
fn large_outputs_are_split() {
    let mut out = Vec::new();
    encode_output(3, &vec![b'x'; MAX_OUTPUT * 2 + 1], &mut out);
    let mut frames = Vec::new();
    let mut d = Decoder::new(Limits::default());
    let mut bytes = stream(&[start(None)]);
    bytes.extend_from_slice(&out);
    d.feed(&bytes);
    while let Some(f) = d.next_frame().unwrap() {
        frames.push(f);
    }
    assert_eq!(frames.len(), 4);
    assert_eq!(d.output_bytes(), (MAX_OUTPUT * 2 + 1) as u64);
    encode_output(3, b"", &mut out);
}

fn code(frames: &[Frame]) -> &'static str {
    decode_all(&stream(frames), Limits::default())
        .unwrap_err()
        .code()
}

#[test]
fn order_is_enforced() {
    assert_eq!(code(&[output(0, b"a")]), "REC-E001", "no start");
    assert_eq!(code(&[start(None), start(None)]), "REC-E001", "two starts");
    let mut late = start(None);
    late.at_us = 1;
    assert_eq!(code(&[late]), "REC-E001", "start at a non-zero time");
    assert_eq!(
        code(&[start(None), output(5, b"a"), output(4, b"b")]),
        "REC-E001",
        "time going back"
    );
    assert_eq!(
        code(&[start(None), output(5, b"a"), end(6, 2)]),
        "REC-E001",
        "wrong count"
    );
    assert_eq!(
        code(&[start(None), end(6, 0), output(7, b"a")]),
        "REC-E001",
        "frame after the end"
    );
    assert_eq!(code(&[start(None), output(5, b"a")]), "REC-E005", "no end");
    assert_eq!(code(&[]), "REC-E005", "empty stream");
}

fn exit(at_us: u64, exit: Exit) -> Frame {
    Frame {
        at_us,
        event: Event::Exit(exit),
    }
}

/// The exit status or signal of the target: once, before the end.
#[test]
fn the_exit_comes_once_before_the_end() {
    let killed = Exit::Signal {
        name: "KILL".into(),
        core_dumped: true,
    };
    for frames in [
        vec![start(None), exit(3, Exit::Status(130)), end(4, 0)],
        vec![
            start(None),
            output(1, b"a"),
            exit(2, killed.clone()),
            end(2, 1),
        ],
    ] {
        assert_eq!(decode_all(&stream(&frames), Limits::default()), Ok(frames));
    }
    let mut out = Vec::new();
    encode(&exit(1, killed.clone()), &mut out).unwrap();
    assert_eq!(out[FRAME_HEADER_LEN..], *b"\x02\x01KILL");
    encode(&exit(1, Exit::Status(258)), &mut out).unwrap();
    assert_eq!(out[out.len() - 5..], [1, 0, 0, 1, 2]);
    assert_eq!(code(&[exit(0, Exit::Status(0))]), "REC-E001", "no start");
    assert_eq!(
        code(&[start(None), exit(1, Exit::Status(0)), exit(2, killed)]),
        "REC-E001",
        "two exits"
    );
    assert_eq!(
        code(&[start(None), end(1, 0), exit(2, Exit::Status(0))]),
        "REC-E001",
        "exit after the end"
    );
    // Malformed payloads: kind, core flag, length, name.
    let good = stream(&[start(None), exit(1, Exit::Status(7)), end(1, 0)]);
    let at = good.len() - (FRAME_HEADER_LEN + 9) - 5;
    for (offset, byte) in [(0, 3), (0, 0)] {
        let mut bad = good.clone();
        bad[at + offset] = byte;
        assert_eq!(
            decode_all(&bad, Limits::default()).unwrap_err().code(),
            "REC-E001"
        );
    }
    let signal = stream(&[
        start(None),
        exit(
            1,
            Exit::Signal {
                name: "HUP".into(),
                core_dumped: false,
            },
        ),
        end(1, 0),
    ]);
    let at = signal.len() - (FRAME_HEADER_LEN + 9) - 5;
    for (offset, byte) in [(1, 2), (2, b' '), (3, 0xff)] {
        let mut bad = signal.clone();
        bad[at + offset] = byte;
        assert_eq!(
            decode_all(&bad, Limits::default()).unwrap_err().code(),
            "REC-E001",
            "{offset}"
        );
    }
}

#[test]
fn limits_are_enforced() {
    let limits = Limits {
        max_output_bytes: 3,
        max_duration_us: 100,
    };
    let big = stream(&[start(None), output(1, b"abcd"), end(2, 4)]);
    assert_eq!(decode_all(&big, limits).unwrap_err().code(), "REC-E003");
    let long = stream(&[start(None), output(101, b"a"), end(101, 1)]);
    assert_eq!(decode_all(&long, limits).unwrap_err().code(), "REC-E003");
    let ok = stream(&[start(None), output(100, b"abc"), end(100, 3)]);
    assert!(decode_all(&ok, limits).is_ok());
}

#[test]
fn malformed_frames_are_refused() {
    let good = stream(&session());
    // Unknown type.
    let mut bad = good.clone();
    bad[0] = 9;
    assert_eq!(
        decode_all(&bad, Limits::default()).unwrap_err().code(),
        "REC-E001"
    );
    // A length above the largest payload fails at once, without waiting.
    let mut d = Decoder::new(Limits::default());
    let mut header = vec![2u8, 0, 0, 0, 0, 0, 0, 0, 0];
    header.extend_from_slice(&u32::try_from(MAX_PAYLOAD + 1).unwrap().to_be_bytes());
    d.feed(&stream(&[start(None)]));
    d.feed(&header);
    assert!(d.next_frame().unwrap().is_some());
    assert_eq!(d.next_frame().unwrap_err().code(), "REC-E001");
    assert!(d.next_frame().is_err(), "a refused stream stays refused");
    assert!(d.finish().is_err());
    // Bytes after the end.
    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(
        decode_all(&trailing, Limits::default()).unwrap_err().code(),
        "REC-E001"
    );
    // Cut in the middle of a frame.
    assert_eq!(
        decode_all(&good[..good.len() - 1], Limits::default())
            .unwrap_err()
            .code(),
        "REC-E005"
    );
}

#[test]
fn malformed_starts_are_refused() {
    let base = stream(&[start(Some(b"id"))]);
    let refused = |change: &dyn Fn(&mut Vec<u8>)| {
        let mut b = base.clone();
        change(&mut b);
        decode_all(&b, Limits::default()).unwrap_err().code()
    };
    // Command flag 2.
    let flag = FRAME_HEADER_LEN + 13 + "xterm-256color".len();
    assert_eq!(refused(&|b| b[flag] = 2), "REC-E001");
    // Terminal type with a space.
    assert_eq!(refused(&|b| b[FRAME_HEADER_LEN + 14] = b' '), "REC-E001");
    // No command but trailing bytes.
    assert_eq!(refused(&|b| b[flag] = 0), "REC-E001");
    // Terminal type longer than the payload.
    assert_eq!(refused(&|b| b[FRAME_HEADER_LEN + 12] = 200), "REC-E001");
}

fn arb_event() -> impl Strategy<Value = Event> {
    prop_oneof![
        proptest::collection::vec(any::<u8>(), 1..64).prop_map(Event::Output),
        (1..=MAX_CELLS_T, 1..=MAX_CELLS_T).prop_map(|(cols, rows)| Event::Resize { cols, rows }),
    ]
}

const MAX_CELLS_T: u16 = crate::event::MAX_CELLS;

fn arb_exit() -> impl Strategy<Value = Exit> {
    prop_oneof![
        any::<u32>().prop_map(Exit::Status),
        ("[A-Z0-9@.-]{1,32}", any::<bool>())
            .prop_map(|(name, core_dumped)| Exit::Signal { name, core_dumped }),
    ]
}

fn arb_session() -> impl Strategy<Value = Vec<Frame>> {
    (
        proptest::option::of(proptest::collection::vec(any::<u8>(), 0..64)),
        proptest::collection::vec((0u64..1000, arb_event()), 0..32),
        proptest::option::of(arb_exit()),
        proptest::sample::select(EndReason::ALL.to_vec()),
    )
        .prop_map(|(command, events, exit, reason)| {
            let mut frames = vec![Frame {
                at_us: 0,
                event: Event::Start {
                    cols: 0,
                    rows: 0,
                    started_ms: 7,
                    term: String::new(),
                    command,
                },
            }];
            let mut at = 0;
            let mut output = 0;
            for (delta, event) in events {
                at += delta;
                if let Event::Output(d) = &event {
                    output += d.len() as u64;
                }
                frames.push(Frame { at_us: at, event });
            }
            if let Some(exit) = exit {
                frames.push(Frame {
                    at_us: at,
                    event: Event::Exit(exit),
                });
            }
            frames.push(Frame {
                at_us: at,
                event: Event::End {
                    reason,
                    output_bytes: output,
                },
            });
            frames
        })
}

proptest! {
    #[test]
    fn prop_round_trip_whatever_the_chunking(frames in arb_session(), chunk in 1usize..50) {
        let bytes = stream(&frames);
        let mut d = Decoder::new(Limits::default());
        let mut got = Vec::new();
        for piece in bytes.chunks(chunk) {
            d.feed(piece);
            while let Some(f) = d.next_frame().unwrap() {
                got.push(f);
            }
        }
        prop_assert!(d.finish().is_ok());
        prop_assert!(d.ended());
        prop_assert_eq!(got, frames);
    }

    #[test]
    fn prop_any_cut_is_incomplete(frames in arb_session(), cut in any::<prop::sample::Index>()) {
        let bytes = stream(&frames);
        let n = cut.index(bytes.len());
        prop_assert_eq!(decode_all(&bytes[..n], Limits::default()).unwrap_err().code(), "REC-E005");
    }

    #[test]
    fn prop_decoder_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        crate::fuzz::decode(&data);
        crate::fuzz::cast(&data);
    }

    #[test]
    fn prop_flipped_byte_never_panics(frames in arb_session(), at in any::<prop::sample::Index>(), x in 1u8..) {
        let mut bytes = stream(&frames);
        let i = at.index(bytes.len());
        bytes[i] ^= x;
        let mut data = vec![7u8];
        data.extend_from_slice(&bytes);
        crate::fuzz::decode(&data);
        crate::fuzz::cast(&bytes);
    }
}
