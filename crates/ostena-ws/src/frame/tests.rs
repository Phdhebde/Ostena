use std::path::PathBuf;

use proptest::prelude::*;

use super::*;
use crate::client;

const MASK: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];

fn masked(opcode: Opcode, fin: bool, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    client::encode(opcode, fin, payload, MASK, &mut out);
    out
}

/// Every event of `input`, owned, or the first error.
fn parse_all(input: &[u8]) -> Result<Vec<String>, WsError> {
    let mut parser = Parser::default();
    let mut at = 0;
    let mut out = Vec::new();
    loop {
        let (n, event) = parser.parse(&input[at..])?;
        if n == 0 {
            return Ok(out);
        }
        at += n;
        match event {
            Some(Event::Binary(m)) => out.push(format!("bin:{}", m.len())),
            Some(Event::Ping(p)) => out.push(format!("ping:{p:?}")),
            Some(Event::Pong(p)) => out.push(format!("pong:{p:?}")),
            Some(Event::Close(c)) => out.push(format!("close:{c:?}")),
            None => out.push("fragment".into()),
        }
    }
}

#[test]
fn example_frames_of_rfc_6455() {
    // RFC 6455, § 5.7: a masked "Hello" (here as binary) and a masked ping.
    let mut hello = vec![
        0x82, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
    ];
    let mut parser = Parser::default();
    assert_eq!(
        parser.parse(&hello),
        Ok((11, Some(Event::Binary(b"Hello"))))
    );
    hello[0] = 0x89;
    assert_eq!(parser.parse(&hello), Ok((11, Some(Event::Ping(b"Hello")))));
    // Fragmented: "Hel" then "lo".
    let mut input = masked(Opcode::Binary, false, b"Hel");
    input.extend(masked(Opcode::Continuation, true, b"lo"));
    let (n, event) = parser.parse(&input).unwrap();
    assert!(event.is_none());
    assert_eq!(
        parser.parse(&input[n..]),
        Ok((input.len() - n, Some(Event::Binary(b"Hello"))))
    );
}

#[test]
fn incomplete_input_waits() {
    let frame = masked(Opcode::Binary, true, &[7; 300]);
    let mut parser = Parser::default();
    for cut in 0..frame.len() {
        assert_eq!(parser.parse(&frame[..cut]), Ok((0, None)), "{cut}");
    }
    assert_eq!(
        parser.parse(&frame).unwrap().0,
        frame.len(),
        "the whole frame is used"
    );
}

#[test]
fn control_frames_interleave_with_a_fragmented_message() {
    let mut input = masked(Opcode::Binary, false, b"ab");
    input.extend(masked(Opcode::Ping, true, b"p"));
    input.extend(masked(Opcode::Continuation, false, b"cd"));
    input.extend(masked(Opcode::Pong, true, b""));
    input.extend(masked(Opcode::Continuation, true, b"e"));
    input.extend(masked(Opcode::Close, true, &[0x03, 0xe8, b'o', b'k']));
    assert_eq!(
        parse_all(&input).unwrap(),
        [
            "fragment",
            "ping:[112]",
            "fragment",
            "pong:[]",
            "bin:5",
            "close:Some((CloseCode(1000), \"ok\"))"
        ]
    );
}

#[test]
#[allow(clippy::too_many_lines, reason = "one case per refusal")]
fn every_violation_is_refused_with_its_code() {
    let cases: Vec<(Vec<u8>, WsError, u16)> = vec![
        // Unmasked: the mask bit cleared.
        (vec![0x82, 0x01, 0x00], WsError::Unmasked, 1002),
        (
            {
                let mut f = Vec::new();
                client::encode_raw(0xc2, b"x", MASK, &mut f);
                f
            },
            WsError::Reserved,
            1002,
        ),
        (
            {
                let mut f = Vec::new();
                client::encode_raw(0x83, b"x", MASK, &mut f);
                f
            },
            WsError::Opcode(3),
            1002,
        ),
        (masked(Opcode::Text, true, b"hi"), WsError::Text, 1003),
        (
            masked(Opcode::Ping, false, b""),
            WsError::ControlFragmented,
            1002,
        ),
        (
            masked(Opcode::Ping, true, &[0; 126]),
            WsError::ControlLength,
            1002,
        ),
        (
            masked(Opcode::Continuation, true, b"x"),
            WsError::Continuation,
            1002,
        ),
        (
            {
                let mut f = masked(Opcode::Binary, false, b"x");
                f.extend(masked(Opcode::Binary, true, b"y"));
                f
            },
            WsError::Interrupted,
            1002,
        ),
        (
            {
                let mut f = masked(Opcode::Binary, false, b"x");
                f.extend(masked(Opcode::Text, true, b"y"));
                f
            },
            WsError::Text,
            1003,
        ),
        (masked(Opcode::Close, true, &[3]), WsError::CloseBody, 1002),
        (
            masked(Opcode::Close, true, &[0x03, 0xed]),
            WsError::CloseBody,
            1002,
        ),
        (
            masked(Opcode::Close, true, &[0x03, 0xe8, 0xff]),
            WsError::CloseReason,
            1007,
        ),
        (
            {
                let mut f = masked(Opcode::Close, true, b"");
                f.extend(masked(Opcode::Binary, true, b"x"));
                f
            },
            WsError::AfterClose,
            1002,
        ),
        // 16-bit length for 125 bytes, 64-bit length for 65535 bytes.
        (vec![0x82, 0xfe, 0x00, 0x7d], WsError::Length, 1002),
        (
            vec![0x82, 0xff, 0, 0, 0, 0, 0, 0, 0xff, 0xff],
            WsError::Length,
            1002,
        ),
        (
            vec![0x82, 0xff, 0x80, 0, 0, 0, 0, 0, 0, 0],
            WsError::Length,
            1002,
        ),
        // Refused from the header, before the payload arrives.
        (
            vec![0x82, 0xff, 0, 0, 0, 0, 0, 1, 0, 0, 1, 2, 3, 4],
            WsError::TooBig,
            1009,
        ),
        (
            vec![0x82, 0xfe, 0x80, 0x01, 1, 2, 3, 4],
            WsError::TooBig,
            1009,
        ),
        (
            {
                let mut f = masked(Opcode::Binary, false, &vec![0; MAX_MESSAGE]);
                f.extend(masked(Opcode::Continuation, true, b"x"));
                f
            },
            WsError::TooBig,
            1009,
        ),
    ];
    for (input, error, code) in cases {
        assert_eq!(parse_all(&input), Err(error), "{input:02x?}");
        assert_eq!(error.close_code().0, code, "{error}");
        assert_ne!(error.to_string(), "");
    }
    // Exactly the bound passes.
    assert_eq!(
        parse_all(&masked(Opcode::Binary, true, &vec![0; MAX_MESSAGE])).unwrap(),
        [format!("bin:{MAX_MESSAGE}")]
    );
    // A smaller bound applies.
    let mut small = Parser::new(4);
    assert_eq!(
        small.parse(&masked(Opcode::Binary, true, b"12345")),
        Err(WsError::TooBig)
    );
}

#[test]
fn close_codes() {
    for code in [1000, 1001, 1002, 1003, 1007, 1011, 3000, 4003, 4999] {
        assert!(CloseCode(code).is_valid(), "{code}");
    }
    for code in [0, 999, 1004, 1005, 1006, 1012, 1015, 2999, 5000] {
        assert!(!CloseCode(code).is_valid(), "{code}");
    }
    let mut out = Vec::new();
    encode_close(CloseCode(4003), &"é".repeat(100), &mut out);
    let (_, frame) = client::decode(&out).unwrap();
    assert_eq!(frame.opcode, 0x8);
    assert!(frame.payload.len() <= MAX_CONTROL);
    assert_eq!(&frame.payload[..2], &4003u16.to_be_bytes());
    // Cut on a character boundary.
    assert!(std::str::from_utf8(&frame.payload[2..]).is_ok());
    assert_eq!(frame.payload.len(), 2 + 122);
}

#[test]
fn server_frames_use_the_shortest_length() {
    for (len, header) in [
        (0usize, 2usize),
        (125, 2),
        (126, 4),
        (65535, 4),
        (65536, 10),
    ] {
        let payload = vec![1u8; len];
        let mut out = Vec::new();
        encode(Opcode::Binary, &payload, &mut out);
        assert_eq!(out.len(), header + len, "{len}");
        let (used, frame) = client::decode(&out).unwrap();
        assert_eq!(used, out.len());
        assert!(frame.fin);
        assert_eq!((frame.opcode, frame.payload.len()), (2, len));
    }
}

#[test]
fn replay_ws_frame_corpus() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/ws_frame");
    let mut count = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        crate::fuzz::frame(&std::fs::read(entry.unwrap().path()).unwrap());
        count += 1;
    }
    assert!(count > 0, "empty corpus {}", dir.display());
}

/// Regenerates the seed inputs:
/// `cargo test -p ostena-ws -- --ignored write_seed_corpus`.
#[test]
#[ignore = "writes files; run on demand"]
fn write_seed_corpus() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/ws_frame");
    let mut fragmented = masked(Opcode::Binary, false, b"Hel");
    fragmented.extend(masked(Opcode::Ping, true, b"p"));
    fragmented.extend(masked(Opcode::Continuation, true, b"lo"));
    fragmented.extend(masked(Opcode::Close, true, &[0x03, 0xe8, b'o', b'k']));
    let seeds: [(&str, Vec<u8>); 6] = [
        ("seed-binary", masked(Opcode::Binary, true, b"Hello")),
        ("seed-medium", masked(Opcode::Binary, true, &[9; 300])),
        (
            "seed-large",
            masked(Opcode::Binary, true, &vec![9; 33_000])[..20].to_vec(),
        ),
        ("seed-fragmented", fragmented),
        ("seed-text", masked(Opcode::Text, true, b"hi")),
        (
            "seed-handshake",
            b"\x01upgrade: websocket\nconnection: Upgrade\nsec-websocket-version: 13\n\
              sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\n\
              sec-websocket-protocol: ostena-frame.v1, ostena-grant.AAAA\n"
                .to_vec(),
        ),
    ];
    for (name, data) in seeds {
        std::fs::write(dir.join(name), data).unwrap();
    }
}

/// A frame sent by a client in a property test.
#[derive(Debug, Clone)]
enum Sent {
    Message(Vec<Vec<u8>>),
    Ping(Vec<u8>),
}

fn sent() -> impl Strategy<Value = Sent> {
    prop_oneof![
        prop::collection::vec(prop::collection::vec(any::<u8>(), 0..300), 1..4)
            .prop_map(Sent::Message),
        prop::collection::vec(any::<u8>(), 0..=MAX_CONTROL).prop_map(Sent::Ping),
    ]
}

proptest! {
    #[test]
    fn prop_messages_round_trip_whatever_the_reads(
        frames in prop::collection::vec(sent(), 1..8),
        mask in any::<[u8; 4]>(),
        chunk in 1usize..64,
    ) {
        let mut input = Vec::new();
        let mut expected = Vec::new();
        for f in &frames {
            match f {
                Sent::Message(parts) => {
                    for (i, part) in parts.iter().enumerate() {
                        let op = if i == 0 { Opcode::Binary } else { Opcode::Continuation };
                        client::encode(op, i + 1 == parts.len(), part, mask, &mut input);
                    }
                    expected.push((true, parts.concat()));
                }
                Sent::Ping(p) => {
                    client::encode(Opcode::Ping, true, p, mask, &mut input);
                    expected.push((false, p.clone()));
                }
            }
        }
        let mut parser = Parser::default();
        let mut got = Vec::new();
        let mut buffer = Vec::new();
        for piece in input.chunks(chunk) {
            buffer.extend_from_slice(piece);
            let mut at = 0;
            loop {
                let (n, event) = parser.parse(&buffer[at..]).unwrap();
                if n == 0 {
                    break;
                }
                at += n;
                match event {
                    Some(Event::Binary(m)) => got.push((true, m.to_vec())),
                    Some(Event::Ping(p)) => got.push((false, p.to_vec())),
                    Some(other) => prop_assert!(false, "unexpected {other:?}"),
                    None => {}
                }
            }
            buffer.drain(..at);
        }
        prop_assert!(buffer.is_empty());
        prop_assert_eq!(got, expected);
    }

    #[test]
    fn prop_parse_never_panics(data in prop::collection::vec(any::<u8>(), 0..512)) {
        crate::fuzz::frame(&data);
    }

    #[test]
    fn prop_close_reason_survives_encoding(code in 3000u16..5000, reason in ".{0,60}") {
        let mut out = Vec::new();
        encode_close(CloseCode(code), &reason, &mut out);
        let (_, frame) = client::decode(&out).unwrap();
        let mut back = Vec::new();
        client::encode(Opcode::Close, true, frame.payload, MASK, &mut back);
        let mut parser = Parser::default();
        let (_, event) = parser.parse(&back).unwrap();
        let Some(Event::Close(Some((c, r)))) = event else {
            return Err(TestCaseError::fail("no close"));
        };
        prop_assert_eq!(c, CloseCode(code));
        prop_assert!(reason.starts_with(r));
    }
}
