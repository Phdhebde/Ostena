use proptest::prelude::*;

use super::*;
use crate::event::{EndReason, Exit};

const SESSION: [u8; 16] = [
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
];

fn frame(at_us: u64, event: Event) -> Frame {
    Frame { at_us, event }
}

fn start(term: &str, command: Option<&[u8]>) -> Frame {
    let terminal = !term.is_empty();
    frame(
        0,
        Event::Start {
            cols: if terminal { 100 } else { 0 },
            rows: if terminal { 30 } else { 0 },
            started_ms: 1_800_000_000_999,
            term: term.into(),
            command: command.map(<[u8]>::to_vec),
        },
    )
}

fn out(at_us: u64, data: &[u8]) -> Frame {
    frame(at_us, Event::Output(data.to_vec()))
}

fn end(at_us: u64) -> Frame {
    frame(
        at_us,
        Event::End {
            reason: EndReason::Closed,
            output_bytes: 0,
        },
    )
}

fn write(frames: &[Frame]) -> (Sealed, String) {
    let mut w = CastWriter::new(Vec::new(), SESSION);
    for f in frames {
        w.push(f).unwrap();
    }
    let (sealed, bytes) = w.finish().unwrap();
    assert_eq!(sealed.size, bytes.len() as u64);
    assert_eq!(sealed.sha256, ostena_crypto::sha256::digest(&bytes));
    (sealed, String::from_utf8(bytes).unwrap())
}

#[test]
fn a_shell_session_has_the_expected_bytes() {
    let (sealed, text) = write(&[
        start("xterm-256color", None),
        out(1_500, b"\x1b[1mgras\x1b[0m \"q\" \\ \t\r\n"),
        frame(2_000_000, Event::Resize { cols: 80, rows: 24 }),
        out(12_345_678, "été\u{7f}\u{85}".as_bytes()),
        end(13_000_000),
    ]);
    let expected = concat!(
        "{\"version\":2,\"width\":100,\"height\":30,\"timestamp\":1800000000,",
        "\"title\":\"ostena 12345678-9abc-def0-0123-456789abcdef\",",
        "\"env\":{\"TERM\":\"xterm-256color\"}}\n",
        "[0.001500,\"o\",\"\\u001b[1mgras\\u001b[0m \\\"q\\\" \\\\ \\t\\r\\n\"]\n",
        "[2.000000,\"r\",\"80x24\"]\n",
        "[12.345678,\"o\",\"été\\u007f\\u0085\"]\n",
    );
    assert_eq!(text, expected);
    assert_eq!(sealed.events, 3);
    assert_eq!(sealed.invalid_utf8, 0);
}

#[test]
fn an_exec_without_terminal_has_a_command_and_a_default_size() {
    let (_, text) = write(&[start("", Some(b"echo \"a\"\n\xff")), end(1)]);
    assert_eq!(
        text,
        concat!(
            "{\"version\":2,\"width\":80,\"height\":24,\"timestamp\":1800000000,",
            "\"command\":\"echo \\\"a\\\"\\n\u{fffd}\",",
            "\"title\":\"ostena 12345678-9abc-def0-0123-456789abcdef\"}\n"
        )
    );
}

/// The bidirectional format characters, which could make a command read
/// as another, are escaped like the control characters.
#[test]
fn bidirectional_format_characters_are_escaped() {
    let (_, text) = write(&[
        start(
            "",
            Some("rm -rf /tmp/a\u{202e}gpj.\u{2066}x\u{200f}".as_bytes()),
        ),
        out(1, "a\u{061c}b\u{2069}".as_bytes()),
        end(2),
    ]);
    assert!(text.contains("\"command\":\"rm -rf /tmp/a\\u202egpj.\\u2066x\\u200f\""));
    assert!(text.contains("\"a\\u061cb\\u2069\""));
    assert!(!text.chars().any(is_bidi_format));
    let header: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert_eq!(
        header["command"].as_str(),
        Some("rm -rf /tmp/a\u{202e}gpj.\u{2066}x\u{200f}")
    );
}

/// The exit status or signal of the target is a marker.
#[test]
fn the_exit_is_a_marker() {
    let (sealed, text) = write(&[
        start("", Some(b"sleep 60")),
        frame(1_000_000, Event::Exit(Exit::Status(0))),
        end(1_000_000),
    ]);
    assert_eq!(
        text.lines().nth(1),
        Some("[1.000000,\"m\",\"exit-status 0\"]")
    );
    assert_eq!(sealed.events, 1);
    let killed = |core_dumped| {
        frame(
            2,
            Event::Exit(Exit::Signal {
                name: "SEGV".into(),
                core_dumped,
            }),
        )
    };
    let (_, text) = write(&[start("", None), killed(true), end(2)]);
    assert_eq!(
        text.lines().nth(1),
        Some("[0.000002,\"m\",\"exit-signal SEGV core-dumped\"]")
    );
    let (_, text) = write(&[start("", None), killed(false), end(2)]);
    assert_eq!(
        text.lines().nth(1),
        Some("[0.000002,\"m\",\"exit-signal SEGV\"]")
    );
}

#[test]
fn utf8_split_across_events_is_joined() {
    let euro = "€".as_bytes();
    let (sealed, text) = write(&[
        start("xterm", None),
        out(1, &euro[..1]),
        out(2, &euro[1..2]),
        out(3, &[euro[2], b'!']),
        end(4),
    ]);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[1..], ["[0.000003,\"o\",\"€!\"]"]);
    assert_eq!(sealed.invalid_utf8, 0);
    assert_eq!(sealed.events, 1);
}

#[test]
fn invalid_utf8_is_replaced_and_counted() {
    let (sealed, text) = write(&[
        start("xterm", None),
        out(1, b"a\xffb\xc3"),
        out(2, b"(c"),
        out(3, b"\xe2\x82"),
        end(9),
    ]);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines[1..],
        [
            "[0.000001,\"o\",\"a\u{fffd}b\"]",
            "[0.000002,\"o\",\"\u{fffd}(c\"]",
            // The incomplete tail is flushed at the end, at its time.
            "[0.000009,\"o\",\"\u{fffd}\"]",
        ]
    );
    assert_eq!(sealed.invalid_utf8, 3);
}

#[test]
fn an_incomplete_transcript_flushes_at_its_last_event() {
    let mut w = CastWriter::new(Vec::new(), SESSION);
    w.push(&start("xterm", None)).unwrap();
    w.push(&out(5, b"\xe2")).unwrap();
    let (sealed, bytes) = w.finish().unwrap();
    assert!(
        String::from_utf8(bytes)
            .unwrap()
            .ends_with("[0.000005,\"o\",\"\u{fffd}\"]\n")
    );
    assert_eq!(sealed.invalid_utf8, 1);
}

#[test]
fn checkpoints_hash_the_prefix() {
    let mut w = CastWriter::new(Vec::new(), SESSION);
    w.push(&start("xterm", None)).unwrap();
    w.push(&out(1, b"abc")).unwrap();
    let (offset, digest) = w.checkpoint();
    w.push(&out(2, b"def")).unwrap();
    let (_, bytes) = w.finish().unwrap();
    let prefix = &bytes[..usize::try_from(offset).unwrap()];
    assert_eq!(digest, ostena_crypto::sha256::digest(prefix));
    assert!(prefix.ends_with(b"\n"));
}

#[test]
fn events_before_the_start_or_a_second_start_are_refused() {
    let mut w = CastWriter::new(Vec::new(), SESSION);
    assert!(w.push(&out(1, b"a")).is_err());
    w.push(&start("", None)).unwrap();
    assert!(w.push(&start("", None)).is_err());
}

#[test]
fn write_errors_are_io_errors() {
    struct Full;
    impl Write for Full {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("disque plein"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut w = CastWriter::new(Full, SESSION);
    assert_eq!(w.push(&start("", None)).unwrap_err().code(), "REC-E004");
}

fn arb_frames() -> impl Strategy<Value = Vec<Frame>> {
    (
        proptest::option::of(proptest::collection::vec(any::<u8>(), 0..40)),
        proptest::collection::vec(
            (
                0u64..3_000_000,
                prop_oneof![
                    proptest::collection::vec(any::<u8>(), 1..40).prop_map(Event::Output),
                    (1u16..500, 1u16..500).prop_map(|(cols, rows)| Event::Resize { cols, rows }),
                    any::<u32>().prop_map(|s| Event::Exit(Exit::Status(s))),
                ],
            ),
            0..20,
        ),
        any::<bool>(),
    )
        .prop_map(|(command, events, terminal)| {
            let mut frames = vec![start(
                if terminal { "xterm" } else { "" },
                command.as_deref(),
            )];
            let mut at = 0;
            for (d, e) in events {
                at += d;
                frames.push(frame(at, e));
            }
            frames.push(end(at));
            frames
        })
}

proptest! {
    #[test]
    fn prop_every_line_is_json_and_output_survives(frames in arb_frames()) {
        let (sealed, text) = write(&frames);
        let (again, _) = write(&frames);
        prop_assert_eq!(&sealed, &again, "deterministic");
        let mut lines = text.lines();
        let header: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        prop_assert_eq!(header["version"].as_u64(), Some(2));
        let mut shown = String::new();
        let mut count = 0;
        let mut last = 0.0f64;
        for line in lines {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            let t = v[0].as_f64().unwrap();
            prop_assert!(t >= last);
            last = t;
            match v[1].as_str().unwrap() {
                "o" => shown.push_str(v[2].as_str().unwrap()),
                "r" => {}
                "m" => prop_assert!(v[2].as_str().unwrap().starts_with("exit-status ")),
                other => prop_assert!(false, "type {other}"),
            }
            count += 1;
        }
        prop_assert_eq!(count, sealed.events);
        prop_assert!(!text.chars().any(|c| (c.is_control() && c != '\n') || is_bidi_format(c)));
        // The text shown is the lossy decoding of all the output joined.
        let all: Vec<u8> = frames
            .iter()
            .filter_map(|f| match &f.event {
                Event::Output(d) => Some(d.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        prop_assert_eq!(shown, String::from_utf8_lossy(&all).into_owned());
    }
}
