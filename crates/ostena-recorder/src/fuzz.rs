//! Entry points shared by the cargo-fuzz targets (`fuzz/`) and the stable
//! tests that replay their corpora. Not part of the API.

use crate::cast::CastWriter;
use crate::error::RecorderError;
use crate::event::Frame;
use crate::wire::{Decoder, Limits, encode};

/// Decodes `stream` fed in chunks of `chunk` bytes (at least 1): the frames
/// taken, then the outcome.
fn decode_chunked(
    stream: &[u8],
    chunk: usize,
    limits: Limits,
) -> (Vec<Frame>, Result<(), RecorderError>) {
    let mut decoder = Decoder::new(limits);
    let mut frames = Vec::new();
    for piece in stream.chunks(chunk.max(1)) {
        decoder.feed(piece);
        loop {
            match decoder.next_frame() {
                Ok(Some(frame)) => frames.push(frame),
                Ok(None) => break,
                Err(e) => return (frames, Err(e)),
            }
        }
    }
    let end = decoder.finish();
    (frames, end)
}

/// Small limits, so that the fuzzer reaches them.
fn fuzz_limits() -> Limits {
    Limits {
        max_output_bytes: 4096,
        max_duration_us: 60_000_000,
    }
}

/// The decoder on untrusted input: the first byte sets the chunk size, the
/// rest is the stream. Must never panic; the outcome must not depend on
/// the chunking, and every frame taken re-encodes to the bytes it came from.
pub fn decode(data: &[u8]) {
    let Some((&chunk, stream)) = data.split_first() else {
        return;
    };
    let (frames, end) = decode_chunked(stream, usize::from(chunk), fuzz_limits());
    let (whole, whole_end) = decode_chunked(stream, stream.len(), fuzz_limits());
    assert_eq!(frames, whole, "frames independent of the chunking");
    assert_eq!(
        end.as_ref().map_err(RecorderError::code),
        whole_end.as_ref().map_err(RecorderError::code),
        "outcome independent of the chunking"
    );
    let mut encoded = Vec::new();
    for frame in &frames {
        assert!(encode(frame, &mut encoded).is_ok(), "decoded frames encode");
    }
    assert_eq!(
        &stream[..encoded.len()],
        encoded.as_slice(),
        "canonical frames"
    );
    if end.is_ok() {
        assert_eq!(
            encoded.len(),
            stream.len(),
            "a complete stream is all frames"
        );
    }
}

/// The decoder, then the asciicast writer, on untrusted input. Must never
/// panic; the file must be UTF-8 lines without any control character, and
/// its seal must hash what was written.
pub fn cast(data: &[u8]) {
    let (frames, _) = decode_chunked(data, data.len(), fuzz_limits());
    let mut writer = CastWriter::new(Vec::new(), [0x5a; 16]);
    for frame in &frames {
        if writer.push(frame).is_err() {
            return;
        }
    }
    let Ok((sealed, file)) = writer.finish() else {
        return;
    };
    assert_eq!(sealed.size, file.len() as u64);
    assert_eq!(sealed.sha256, ostena_crypto::sha256::digest(&file));
    let text = std::str::from_utf8(&file);
    assert!(text.is_ok(), "the file is UTF-8");
    let text = text.unwrap_or_default();
    assert!(
        !text.chars().any(|c| c.is_control() && c != '\n'),
        "no control character in the file"
    );
    assert!(file.is_empty() || file.ends_with(b"\n"));
    for (i, line) in text.lines().enumerate() {
        let first = if i == 0 { '{' } else { '[' };
        assert!(line.starts_with(first), "line {i} starts with {first}");
    }
}
