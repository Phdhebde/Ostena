//! Entry points shared by the cargo-fuzz target `ws_frame` (`fuzz/`) and the
//! stable tests that replay its corpus. Not part of the API.

use crate::frame::{Event, Parser};
use crate::{MAX_MESSAGE, handshake};

/// What a parse gave, owned, to compare two runs.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close(Option<(u16, String)>),
    Error(crate::WsError),
}

/// Parses `data` as it arrives in chunks of `chunk` bytes, as the gateway
/// reads a socket.
fn run(data: &[u8], chunk: usize) -> Vec<Seen> {
    let mut parser = Parser::default();
    let mut seen = Vec::new();
    let mut buffer = Vec::new();
    for piece in data.chunks(chunk.max(1)) {
        buffer.extend_from_slice(piece);
        let mut at = 0;
        loop {
            match parser.parse(&buffer[at..]) {
                Ok((0, _)) => break,
                Ok((n, event)) => {
                    at += n;
                    match event {
                        Some(Event::Binary(m)) => {
                            assert!(m.len() <= MAX_MESSAGE, "message above the bound");
                            seen.push(Seen::Binary(m.to_vec()));
                        }
                        Some(Event::Ping(p)) => seen.push(Seen::Ping(p.to_vec())),
                        Some(Event::Pong(p)) => seen.push(Seen::Pong(p.to_vec())),
                        Some(Event::Close(c)) => {
                            seen.push(Seen::Close(c.map(|(code, r)| (code.0, r.to_owned()))));
                        }
                        None => {}
                    }
                }
                Err(e) => {
                    seen.push(Seen::Error(e));
                    return seen;
                }
            }
        }
        buffer.drain(..at);
    }
    seen
}

/// The parser on arbitrary input: never panics, never yields a message
/// above the bound, and gives the same events whatever the cut of the
/// input into reads. The same bytes are also read as the headers of an
/// upgrade request, one `name: value` per line.
pub fn frame(data: &[u8]) {
    let whole = run(data, data.len());
    let chunk = usize::from(data.first().copied().unwrap_or(1) % 16) + 1;
    assert_eq!(
        whole,
        run(data, chunk),
        "events depend on the cut of the input"
    );
    let headers: Vec<(&str, &[u8])> = data
        .split(|b| *b == b'\n')
        .filter_map(|line| {
            let colon = line.iter().position(|b| *b == b':')?;
            let name = std::str::from_utf8(&line[..colon]).ok()?;
            Some((name, &line[colon + 1..]))
        })
        .collect();
    if let Ok(up) = handshake::check("GET", true, headers) {
        assert_eq!(up.key.len(), handshake::KEY_LEN);
        assert!(up.protocols().len() <= handshake::MAX_PROTOCOLS);
    }
}
