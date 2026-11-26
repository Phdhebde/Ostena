//! Replays the cargo-fuzz corpora (`fuzz/corpus/recorder_decode` and
//! `fuzz/corpus/recorder_cast`) on the stable toolchain, so that every
//! input the fuzzer kept is a regression test.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside #[test] functions"
)]

use std::path::PathBuf;

use ostena_recorder::{EndReason, Event, Frame, NoteKind, encode};

fn corpus_dir(target: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../fuzz/corpus/{target}"))
}

fn replay(target: &str, run: fn(&[u8])) {
    let mut count = 0;
    for entry in std::fs::read_dir(corpus_dir(target)).expect("corpus directory must exist") {
        let path = entry.expect("readable entry").path();
        let data = std::fs::read(&path).expect("readable corpus file");
        run(&data);
        count += 1;
    }
    assert!(count > 0, "empty corpus {target}");
}

#[test]
fn replay_decode_corpus() {
    replay("recorder_decode", ostena_recorder::fuzz::decode);
}

#[test]
fn replay_cast_corpus() {
    replay("recorder_cast", ostena_recorder::fuzz::cast);
}

fn stream(frames: &[Frame]) -> Vec<u8> {
    let mut out = Vec::new();
    for f in frames {
        encode(f, &mut out).unwrap();
    }
    out
}

/// A shell session with a terminal, UTF-8 split across outputs, an invalid
/// byte and an escape sequence; and an exec without terminal.
fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    let shell = stream(&[
        Frame {
            at_us: 0,
            event: Event::Start {
                cols: 80,
                rows: 24,
                started_ms: 1_800_000_000_000,
                term: "xterm".into(),
                command: None,
            },
        },
        Frame {
            at_us: 10,
            event: Event::Output(b"\x1b[1m\xe2\x82".to_vec()),
        },
        Frame {
            at_us: 20,
            event: Event::Output(b"\xac \xff ok\r\n".to_vec()),
        },
        Frame {
            at_us: 30,
            event: Event::Resize {
                cols: 100,
                rows: 40,
            },
        },
        Frame {
            at_us: 40,
            event: Event::End {
                reason: EndReason::Closed,
                output_bytes: 14,
            },
        },
    ]);
    let exec = stream(&[
        Frame {
            at_us: 0,
            event: Event::Start {
                cols: 0,
                rows: 0,
                started_ms: 1,
                term: String::new(),
                command: Some(b"uname -a".to_vec()),
            },
        },
        Frame {
            at_us: 4,
            event: Event::Exit(ostena_recorder::Exit::Signal {
                name: "TERM".into(),
                core_dumped: false,
            }),
        },
        Frame {
            at_us: 5,
            event: Event::End {
                reason: EndReason::Expired,
                output_bytes: 0,
            },
        },
    ]);
    let transfer = stream(&[
        Frame {
            at_us: 0,
            event: Event::Start {
                cols: 0,
                rows: 0,
                started_ms: 2,
                term: String::new(),
                command: None,
            },
        },
        Frame {
            at_us: 1,
            event: Event::Note {
                kind: NoteKind::Transfer,
                text: b"sftp".to_vec(),
            },
        },
        Frame {
            at_us: 2,
            event: Event::Note {
                kind: NoteKind::Rename,
                text: b"/tmp/a\0/tmp/\xe2\x82".to_vec(),
            },
        },
        Frame {
            at_us: 3,
            event: Event::End {
                reason: EndReason::Closed,
                output_bytes: 0,
            },
        },
    ]);
    vec![
        ("seed-shell.bin", shell.clone()),
        ("seed-exec.bin", exec),
        ("seed-transfer.bin", transfer),
        ("seed-truncated.bin", shell[..shell.len() - 3].to_vec()),
        ("seed-empty.bin", Vec::new()),
    ]
}

/// Regenerates the seed inputs:
/// `cargo test -p ostena-recorder --test fuzz_corpus -- --ignored`. The
/// decode target reads a chunk size first.
#[test]
#[ignore = "writes files; run on demand"]
fn write_seed_corpus() {
    for (target, chunked) in [("recorder_decode", true), ("recorder_cast", false)] {
        let dir = corpus_dir(target);
        std::fs::create_dir_all(&dir).unwrap();
        for (name, data) in seeds() {
            let mut file = if chunked { vec![7u8] } else { Vec::new() };
            file.extend_from_slice(&data);
            std::fs::write(dir.join(name), file).unwrap();
        }
    }
}

/// The complete seeds decode to the end, otherwise the fuzzer never reaches
/// the writer.
#[test]
fn complete_seeds_decode_to_the_end() {
    for (name, data) in seeds().into_iter().take(3) {
        let mut d = ostena_recorder::Decoder::new(ostena_recorder::Limits::default());
        d.feed(&data);
        while d.next_frame().unwrap().is_some() {}
        assert!(d.finish().is_ok(), "{name}");
    }
}
