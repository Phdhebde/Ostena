//! Frames of the TCP multiplexer (ADR-0008): an 8-byte header, then at most
//! [`MAX_DATA`] bytes of payload.
//!
//! ```text
//! 0      1      2             4                           8
//! +------+------+-------------+---------------------------+----------...
//! | type | 0x00 | length (BE) | stream (BE)               | payload
//! +------+------+-------------+---------------------------+----------...
//! ```
//!
//! The decoder is a network parser: the header is checked (known type, zero
//! flags, length allowed for the type, stream zero or not as the type
//! requires) before the payload is awaited, so that a forged length never
//! makes the reader buffer more than one frame.

use std::fmt;

/// Version of the multiplexer, announced in [`Frame::Settings`].
pub const VERSION: u8 = 1;
/// Length of a frame header.
pub const HEADER_LEN: usize = 8;
/// Largest payload of a [`Frame::Data`]: one frame never holds the link
/// longer than 16 KiB, so that input overtakes a transfer quickly.
pub const MAX_DATA: usize = 16 * 1024;
/// Largest reason of a [`Frame::Close`].
pub const MAX_REASON: usize = 200;
/// Largest encoded frame.
pub const MAX_FRAME: usize = HEADER_LEN + MAX_DATA;

const SETTINGS_LEN: usize = 13;

const T_SETTINGS: u8 = 0;
const T_OPEN: u8 = 1;
const T_DATA: u8 = 2;
const T_FIN: u8 = 3;
const T_RESET: u8 = 4;
const T_STOP: u8 = 5;
const T_CREDIT: u8 = 6;
const T_FIN_ACK: u8 = 7;
const T_MAX_STREAMS: u8 = 8;
const T_PING: u8 = 9;
const T_PONG: u8 = 10;
const T_CLOSE: u8 = 11;

/// One frame. Stream 0 is the connection itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame<'a> {
    /// First frame of each side: version and the bounds it enforces on the
    /// peer.
    Settings {
        /// [`VERSION`].
        version: u8,
        /// Streams the peer may open at first (cumulative count, raised by
        /// [`Frame::MaxStreams`]).
        max_streams: u32,
        /// Receive window of each stream, in bytes.
        stream_window: u32,
        /// Receive window of the connection, in bytes.
        connection_window: u32,
    },
    /// Opens a stream: odd identifiers for the agent, even for the core,
    /// each one the next of its side.
    Open {
        /// Stream.
        stream: u32,
    },
    /// Stream bytes, 1 to [`MAX_DATA`].
    Data {
        /// Stream.
        stream: u32,
        /// Bytes.
        payload: &'a [u8],
    },
    /// End of the sender's direction.
    Fin {
        /// Stream.
        stream: u32,
    },
    /// The sender abandons its direction.
    Reset {
        /// Stream.
        stream: u32,
        /// Application code.
        code: u32,
    },
    /// The receiver asks the sender to stop.
    Stop {
        /// Stream.
        stream: u32,
        /// Application code.
        code: u32,
    },
    /// The receiver read `increment` more bytes: the sender may send them
    /// (stream 0: the connection window).
    Credit {
        /// Stream, or 0.
        stream: u32,
        /// Bytes, at least 1.
        increment: u32,
    },
    /// The receiver got every byte and the end of the stream.
    FinAck {
        /// Stream.
        stream: u32,
    },
    /// The peer may now open up to `total` streams since the start.
    MaxStreams {
        /// Cumulative count.
        total: u32,
    },
    /// Liveness probe, echoed by [`Frame::Pong`].
    Ping {
        /// Opaque value.
        opaque: u64,
    },
    /// Answer to [`Frame::Ping`].
    Pong {
        /// The value of the ping.
        opaque: u64,
    },
    /// The sender closes the connection.
    Close {
        /// Application code (0: normal).
        code: u32,
        /// Reason, at most [`MAX_REASON`] bytes.
        reason: &'a [u8],
    },
}

/// Why a frame is refused. Any of them closes the connection (`TUN-E010`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// Unknown frame type.
    UnknownType(u8),
    /// Reserved flags not zero.
    Flags(u8),
    /// Length not allowed for this type.
    Length {
        /// Frame type.
        kind: u8,
        /// Length received.
        len: usize,
    },
    /// Stream 0 where a stream is required, or the reverse.
    Stream {
        /// Frame type.
        kind: u8,
        /// Stream received.
        stream: u32,
    },
    /// A zero credit increment.
    ZeroCredit,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownType(t) => write!(f, "type de trame inconnu {t}"),
            Self::Flags(v) => write!(f, "drapeaux réservés non nuls ({v})"),
            Self::Length { kind, len } => write!(f, "longueur {len} invalide pour le type {kind}"),
            Self::Stream { kind, stream } => {
                write!(f, "flux {stream} invalide pour le type {kind}")
            }
            Self::ZeroCredit => f.write_str("crédit nul"),
        }
    }
}

impl std::error::Error for FrameError {}

fn u32_at(b: &[u8], at: usize) -> u32 {
    let mut v = [0u8; 4];
    v.copy_from_slice(&b[at..at + 4]);
    u32::from_be_bytes(v)
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[at..at + 8]);
    u64::from_be_bytes(v)
}

/// Checks a header alone; returns the type, the stream and the payload
/// length.
///
/// # Errors
///
/// The first rule the header breaks.
pub fn check_header(header: &[u8; HEADER_LEN]) -> Result<(u8, u32, usize), FrameError> {
    let kind = header[0];
    if header[1] != 0 {
        return Err(FrameError::Flags(header[1]));
    }
    let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
    let stream = u32_at(header, 4);
    // (length allowed, stream required); CREDIT takes both (0: connection).
    let (len_ok, needs_stream) = match kind {
        T_SETTINGS => (len == SETTINGS_LEN, false),
        T_OPEN | T_FIN | T_FIN_ACK => (len == 0, true),
        T_DATA => ((1..=MAX_DATA).contains(&len), true),
        T_RESET | T_STOP | T_CREDIT => (len == 4, true),
        T_MAX_STREAMS => (len == 4, false),
        T_PING | T_PONG => (len == 8, false),
        T_CLOSE => ((4..=4 + MAX_REASON).contains(&len), false),
        other => return Err(FrameError::UnknownType(other)),
    };
    if !len_ok {
        return Err(FrameError::Length { kind, len });
    }
    if kind != T_CREDIT && needs_stream != (stream != 0) {
        return Err(FrameError::Stream { kind, stream });
    }
    Ok((kind, stream, len))
}

/// Decodes the frame at the start of `buf`; `Ok(None)` while it is
/// incomplete. Returns the frame and the bytes it took.
///
/// # Errors
///
/// [`FrameError`] as soon as the header is known to be invalid, without
/// waiting for its payload.
pub fn decode(buf: &[u8]) -> Result<Option<(Frame<'_>, usize)>, FrameError> {
    let Some(header) = buf.first_chunk::<HEADER_LEN>() else {
        return Ok(None);
    };
    let (kind, stream, len) = check_header(header)?;
    let Some(p) = buf.get(HEADER_LEN..HEADER_LEN + len) else {
        return Ok(None);
    };
    let frame = match kind {
        T_SETTINGS => Frame::Settings {
            version: p[0],
            max_streams: u32_at(p, 1),
            stream_window: u32_at(p, 5),
            connection_window: u32_at(p, 9),
        },
        T_OPEN => Frame::Open { stream },
        T_DATA => Frame::Data { stream, payload: p },
        T_FIN => Frame::Fin { stream },
        T_RESET => Frame::Reset {
            stream,
            code: u32_at(p, 0),
        },
        T_STOP => Frame::Stop {
            stream,
            code: u32_at(p, 0),
        },
        T_CREDIT => {
            let increment = u32_at(p, 0);
            if increment == 0 {
                return Err(FrameError::ZeroCredit);
            }
            Frame::Credit { stream, increment }
        }
        T_FIN_ACK => Frame::FinAck { stream },
        T_MAX_STREAMS => Frame::MaxStreams {
            total: u32_at(p, 0),
        },
        T_PING => Frame::Ping {
            opaque: u64_at(p, 0),
        },
        T_PONG => Frame::Pong {
            opaque: u64_at(p, 0),
        },
        // check_header refused every other type.
        _ => Frame::Close {
            code: u32_at(p, 0),
            reason: &p[4..],
        },
    };
    Ok(Some((frame, HEADER_LEN + len)))
}

fn header(out: &mut Vec<u8>, kind: u8, stream: u32, len: usize) {
    out.push(kind);
    out.push(0);
    // Every caller bounds `len` by MAX_DATA or a fixed size.
    out.extend_from_slice(&u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes());
    out.extend_from_slice(&stream.to_be_bytes());
}

/// Appends `frame` to `out`. A [`Frame::Data`] payload longer than
/// [`MAX_DATA`] or a reason longer than [`MAX_REASON`] is truncated: the
/// callers never build one.
pub fn encode(frame: &Frame<'_>, out: &mut Vec<u8>) {
    match *frame {
        Frame::Settings {
            version,
            max_streams,
            stream_window,
            connection_window,
        } => {
            header(out, T_SETTINGS, 0, SETTINGS_LEN);
            out.push(version);
            out.extend_from_slice(&max_streams.to_be_bytes());
            out.extend_from_slice(&stream_window.to_be_bytes());
            out.extend_from_slice(&connection_window.to_be_bytes());
        }
        Frame::Open { stream } => header(out, T_OPEN, stream, 0),
        Frame::Data { stream, payload } => {
            let payload = &payload[..payload.len().min(MAX_DATA)];
            header(out, T_DATA, stream, payload.len());
            out.extend_from_slice(payload);
        }
        Frame::Fin { stream } => header(out, T_FIN, stream, 0),
        Frame::Reset { stream, code } => {
            header(out, T_RESET, stream, 4);
            out.extend_from_slice(&code.to_be_bytes());
        }
        Frame::Stop { stream, code } => {
            header(out, T_STOP, stream, 4);
            out.extend_from_slice(&code.to_be_bytes());
        }
        Frame::Credit { stream, increment } => {
            header(out, T_CREDIT, stream, 4);
            out.extend_from_slice(&increment.to_be_bytes());
        }
        Frame::FinAck { stream } => header(out, T_FIN_ACK, stream, 0),
        Frame::MaxStreams { total } => {
            header(out, T_MAX_STREAMS, 0, 4);
            out.extend_from_slice(&total.to_be_bytes());
        }
        Frame::Ping { opaque } => {
            header(out, T_PING, 0, 8);
            out.extend_from_slice(&opaque.to_be_bytes());
        }
        Frame::Pong { opaque } => {
            header(out, T_PONG, 0, 8);
            out.extend_from_slice(&opaque.to_be_bytes());
        }
        Frame::Close { code, reason } => {
            let reason = &reason[..reason.len().min(MAX_REASON)];
            header(out, T_CLOSE, 0, 4 + reason.len());
            out.extend_from_slice(&code.to_be_bytes());
            out.extend_from_slice(reason);
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn round_trip(frame: Frame<'_>) {
        let mut out = Vec::new();
        encode(&frame, &mut out);
        assert_eq!(decode(&out), Ok(Some((frame, out.len()))));
        // Every strict prefix is incomplete, never an error.
        for cut in 0..out.len() {
            assert_eq!(decode(&out[..cut]), Ok(None), "{frame:?} cut at {cut}");
        }
    }

    #[test]
    fn every_frame_round_trips() {
        let data = [7u8; MAX_DATA];
        for frame in [
            Frame::Settings {
                version: VERSION,
                max_streams: 1025,
                stream_window: 256 * 1024,
                connection_window: 8 << 20,
            },
            Frame::Open { stream: 1 },
            Frame::Data {
                stream: 3,
                payload: b"x",
            },
            Frame::Data {
                stream: 3,
                payload: &data,
            },
            Frame::Fin { stream: 5 },
            Frame::Reset { stream: 2, code: 9 },
            Frame::Stop { stream: 4, code: 1 },
            Frame::Credit {
                stream: 0,
                increment: 1,
            },
            Frame::Credit {
                stream: 7,
                increment: u32::MAX,
            },
            Frame::FinAck { stream: 9 },
            Frame::MaxStreams { total: 2000 },
            Frame::Ping { opaque: 42 },
            Frame::Pong { opaque: u64::MAX },
            Frame::Close {
                code: 1,
                reason: b"[TUN-E005] revoked",
            },
            Frame::Close {
                code: 0,
                reason: b"",
            },
        ] {
            round_trip(frame);
        }
    }

    #[test]
    fn bad_headers_are_refused_before_the_payload() {
        // A DATA header announcing 65535 bytes is refused at once.
        let mut h = [T_DATA, 0, 0xff, 0xff, 0, 0, 0, 1];
        assert_eq!(
            decode(&h),
            Err(FrameError::Length {
                kind: T_DATA,
                len: 65535
            })
        );
        h = [T_DATA, 0, 0, 0, 0, 0, 0, 1];
        assert!(matches!(decode(&h), Err(FrameError::Length { .. })));
        h = [T_DATA, 1, 0, 1, 0, 0, 0, 1];
        assert_eq!(decode(&h), Err(FrameError::Flags(1)));
        h = [T_DATA, 0, 0, 1, 0, 0, 0, 0];
        assert!(matches!(decode(&h), Err(FrameError::Stream { .. })));
        h = [T_PING, 0, 0, 8, 0, 0, 0, 1];
        assert!(matches!(decode(&h), Err(FrameError::Stream { .. })));
        h = [12, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(decode(&h), Err(FrameError::UnknownType(12)));
        h = [T_CLOSE, 0, 0, 255, 0, 0, 0, 0];
        assert!(matches!(decode(&h), Err(FrameError::Length { .. })));
        let zero = [T_CREDIT, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 0];
        assert_eq!(decode(&zero), Err(FrameError::ZeroCredit));
    }

    proptest! {
        #[test]
        fn prop_decode_never_panics_and_never_overreads(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            if let Ok(Some((_, used))) = decode(&bytes) {
                prop_assert!(used <= bytes.len());
                prop_assert!(used <= MAX_FRAME);
            }
        }

        #[test]
        fn prop_data_round_trips(stream in 1u32.., payload in proptest::collection::vec(any::<u8>(), 1..=MAX_DATA)) {
            let mut out = Vec::new();
            encode(&Frame::Data { stream, payload: &payload }, &mut out);
            prop_assert_eq!(decode(&out), Ok(Some((Frame::Data { stream, payload: &payload }, out.len()))));
        }

        #[test]
        fn prop_concatenated_frames_decode_in_order(codes in proptest::collection::vec(any::<u32>(), 1..20)) {
            let mut out = Vec::new();
            for (i, code) in codes.iter().enumerate() {
                let stream = u32::try_from(i).unwrap_or(0) + 1;
                encode(&Frame::Reset { stream, code: *code }, &mut out);
            }
            let mut at = 0;
            for (i, code) in codes.iter().enumerate() {
                let (frame, used) = decode(&out[at..]).ok().flatten().ok_or_else(|| TestCaseError::fail("incomplete"))?;
                let stream = u32::try_from(i).unwrap_or(0) + 1;
                prop_assert_eq!(frame, Frame::Reset { stream, code: *code });
                at += used;
            }
            prop_assert_eq!(at, out.len());
        }
    }
}
