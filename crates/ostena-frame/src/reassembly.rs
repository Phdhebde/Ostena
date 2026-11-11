//! Reassembly of fragmented messages (display updates, clipboard data). Off
//! the hot path: it allocates, within a bound.

use alloc::vec::Vec;

use crate::codec::Frame;
use crate::error::{Code, FrameError};
use crate::header::FrameType;
use crate::payload::{ClipboardFormat, Codec, Payload, Rect};

/// What identifies a message besides its data; every fragment repeats it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Display update of a rectangle.
    Display {
        /// Encoding.
        codec: Codec,
        /// Updated area.
        rect: Rect,
    },
    /// Clipboard content.
    Clipboard {
        /// Format.
        format: ClipboardFormat,
    },
}

/// A complete message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Channel.
    pub channel: u16,
    /// Kind and metadata.
    pub kind: Kind,
    /// Concatenated data.
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
struct Pending {
    frame_type: FrameType,
    channel: u16,
    kind: Kind,
    data: Vec<u8>,
}

/// Collects fragments per (type, channel) up to `max_bytes` per message.
#[derive(Debug, Clone)]
pub struct Reassembler {
    max_bytes: usize,
    max_pending: usize,
    pending: Vec<Pending>,
}

impl Reassembler {
    /// A reassembler bounded to `max_bytes` per message and `max_pending`
    /// messages in progress.
    pub fn new(max_bytes: usize, max_pending: usize) -> Self {
        Self {
            max_bytes,
            max_pending,
            pending: Vec::new(),
        }
    }

    /// Feeds a frame; returns a message when its last fragment arrives.
    /// Frames of other types are ignored (`Ok(None)`).
    ///
    /// # Errors
    ///
    /// `FRM-E011` when a fragment does not match the message in progress
    /// (other codec, rectangle or format), when the message exceeds
    /// `max_bytes`, or when too many messages are in progress.
    pub fn feed(&mut self, frame: &Frame<'_>) -> Result<Option<Message>, FrameError> {
        let (kind, data) = match frame.payload {
            Payload::DisplayUpdate { codec, rect, data } => (Kind::Display { codec, rect }, data),
            Payload::ClipboardData { format, data } => (Kind::Clipboard { format }, data),
            _ => return Ok(None),
        };
        let (frame_type, channel, more) = (
            frame.header.frame_type,
            frame.header.channel,
            frame.header.flags.more(),
        );
        let slot = self
            .pending
            .iter()
            .position(|p| p.frame_type == frame_type && p.channel == channel);
        let mut message = match slot {
            Some(i) => {
                let p = self.pending.swap_remove(i);
                if p.kind != kind {
                    return Err(FrameError::new(
                        Code::Fragmentation,
                        "fragment incohérent avec le message en cours",
                    ));
                }
                p
            }
            None if !more => {
                return Ok(Some(Message {
                    channel,
                    kind,
                    data: data.as_bytes().to_vec(),
                }));
            }
            None => {
                if self.pending.len() >= self.max_pending {
                    return Err(FrameError::new(
                        Code::Fragmentation,
                        "trop de messages fragmentés en cours",
                    ));
                }
                Pending {
                    frame_type,
                    channel,
                    kind,
                    data: Vec::new(),
                }
            }
        };
        if message.data.len() + data.len() > self.max_bytes {
            return Err(FrameError::new(
                Code::Fragmentation,
                "message réassemblé au-delà de la taille maximale",
            ));
        }
        message.data.extend_from_slice(data.as_bytes());
        if more {
            self.pending.push(message);
            Ok(None)
        } else {
            Ok(Some(Message {
                channel,
                kind: message.kind,
                data: message.data,
            }))
        }
    }

    /// Drops every message in progress (e.g. after a resume).
    pub fn clear(&mut self) {
        self.pending.clear();
    }
}
