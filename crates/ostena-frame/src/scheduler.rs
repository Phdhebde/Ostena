//! Outgoing frames: priority scheduling and sequence numbering, without a
//! runtime. The session loop (tokio on the gateway, the browser event loop in
//! WebAssembly) pushes frames and pops them when the transport can write.
//!
//! Priority is strict between classes: control, then inputs, then audit. The
//! bulk classes (display, clipboard, file) share what is left by deficit
//! round robin, so that a file transfer cannot starve the screen. Sequence
//! numbers are given when a frame leaves the scheduler, so the wire order is
//! always the numbering order.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::codec::encode;
use crate::error::{Code, FrameError};
use crate::header::{
    Class, Direction, Flags, FrameType, HEADER_LEN, MAX_FRAGMENT, NEGOTIATION_VERSION,
};
use crate::payload::{Opaque, Payload};

/// A frame waiting to be sent: its payload is already encoded; the header is
/// written by [`Sender::encode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    frame_type: FrameType,
    channel: u16,
    flags: Flags,
    payload: Vec<u8>,
    /// Pointer buttons, to coalesce only moves that keep the same buttons.
    buttons: Option<u8>,
}

impl Outgoing {
    /// Prepares a frame.
    ///
    /// # Errors
    ///
    /// The same checks as [`encode`]: direction, channel, flags, length.
    pub fn new(
        payload: &Payload<'_>,
        direction: Direction,
        channel: u16,
        flags: Flags,
    ) -> Result<Self, FrameError> {
        // Validate once with a dummy version and sequence; the sender writes the real ones.
        let version = if matches!(payload, Payload::Hello { .. } | Payload::HelloAck { .. }) {
            NEGOTIATION_VERSION
        } else {
            crate::header::CURRENT_VERSION
        };
        let mut check = Vec::with_capacity(HEADER_LEN + payload.encoded_len());
        encode(payload, direction, version, channel, flags, 0, &mut check)?;
        Ok(Self {
            frame_type: payload.frame_type(),
            channel,
            flags,
            payload: check.split_off(HEADER_LEN),
            buttons: match payload {
                Payload::Pointer(p) => Some(p.buttons),
                _ => None,
            },
        })
    }

    /// Splits a display update or clipboard data into fragments of at most
    /// `fragment` bytes of data (capped at 16 KiB), `MORE` on all but the last.
    ///
    /// # Errors
    ///
    /// `FRM-E011` for another payload type or a zero fragment size; the checks
    /// of [`Outgoing::new`] otherwise.
    pub fn fragments(
        payload: &Payload<'_>,
        direction: Direction,
        channel: u16,
        fragment: usize,
    ) -> Result<Vec<Self>, FrameError> {
        let size = fragment.min(MAX_FRAGMENT);
        if size == 0 {
            return Err(FrameError::new(
                Code::Fragmentation,
                "taille de fragment nulle",
            ));
        }
        let data = match payload {
            Payload::DisplayUpdate { data, .. } | Payload::ClipboardData { data, .. } => {
                data.as_bytes()
            }
            _ => {
                return Err(FrameError::new(
                    Code::Fragmentation,
                    "type non fragmentable",
                ));
            }
        };
        let pieces: Vec<&[u8]> = if data.is_empty() {
            alloc::vec![data]
        } else {
            data.chunks(size).collect()
        };
        let last = pieces.len() - 1;
        pieces
            .into_iter()
            .enumerate()
            .map(|(i, piece)| {
                let part = match *payload {
                    Payload::DisplayUpdate { codec, rect, .. } => Payload::DisplayUpdate {
                        codec,
                        rect,
                        data: Opaque::new(piece),
                    },
                    Payload::ClipboardData { format, .. } => Payload::ClipboardData {
                        format,
                        data: Opaque::new(piece),
                    },
                    _ => *payload,
                };
                let flags = if i < last { Flags::MORE } else { Flags::NONE };
                Self::new(&part, direction, channel, flags)
            })
            .collect()
    }

    /// The frame type.
    pub fn frame_type(&self) -> FrameType {
        self.frame_type
    }

    /// Encoded size on the wire.
    pub fn wire_len(&self) -> usize {
        HEADER_LEN + self.payload.len()
    }
}

/// Queue bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Frames per class queue.
    pub frames_per_class: usize,
    /// Bytes served per round to each bulk class (at least one full frame).
    pub quantum: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            frames_per_class: 1024,
            quantum: HEADER_LEN + 13 + MAX_FRAGMENT,
        }
    }
}

const CLASSES: usize = 6;
const BULK: [usize; 3] = [
    Class::Display as usize,
    Class::Clipboard as usize,
    Class::File as usize,
];

/// Priority scheduler for one direction.
#[derive(Debug, Clone)]
pub struct Scheduler {
    queues: [VecDeque<Outgoing>; CLASSES],
    deficit: [usize; CLASSES],
    next_bulk: usize,
    /// The current bulk class already received its quantum for this round.
    topped: bool,
    limits: Limits,
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new(Limits::default())
    }
}

impl Scheduler {
    /// An empty scheduler.
    pub fn new(limits: Limits) -> Self {
        let quantum = limits.quantum.max(HEADER_LEN + 13 + MAX_FRAGMENT);
        Self {
            queues: Default::default(),
            deficit: [0; CLASSES],
            next_bulk: 0,
            topped: false,
            limits: Limits { quantum, ..limits },
        }
    }

    /// Queues a frame. A pointer move replaces the last queued pointer frame
    /// when the buttons did not change, and a resize request replaces any
    /// queued one: only the latest state matters and inputs stay fresh.
    ///
    /// # Errors
    ///
    /// `FRM-E012` when the class queue is full; the caller decides (drop,
    /// close, slow the source down).
    pub fn push(&mut self, frame: Outgoing) -> Result<(), FrameError> {
        let q = &mut self.queues[frame.frame_type.class() as usize];
        match frame.frame_type {
            FrameType::Pointer => {
                if let Some(last) = q.back_mut()
                    && last.frame_type == FrameType::Pointer
                    && last.channel == frame.channel
                    && last.buttons == frame.buttons
                {
                    *last = frame;
                    return Ok(());
                }
            }
            FrameType::ResizeRequest => {
                if let Some(queued) = q
                    .iter_mut()
                    .find(|f| f.frame_type == FrameType::ResizeRequest)
                {
                    *queued = frame;
                    return Ok(());
                }
            }
            _ => {}
        }
        if q.len() >= self.limits.frames_per_class {
            return Err(FrameError::new(Code::QueueFull, "file d'émission pleine"));
        }
        q.push_back(frame);
        Ok(())
    }

    /// Next frame to send, if any.
    pub fn pop(&mut self) -> Option<Outgoing> {
        for class in [Class::Control, Class::Input, Class::Audit] {
            if let Some(f) = self.queues[class as usize].pop_front() {
                return Some(f);
            }
        }
        // Deficit round robin over the bulk classes: a class receives its
        // quantum when its turn comes, sends while the deficit covers the front
        // frame, then yields. The quantum covers the largest frame, so each
        // turn sends at least one frame.
        for _ in 0..=BULK.len() {
            let class = BULK[self.next_bulk];
            let Some(len) = self.queues[class].front().map(Outgoing::wire_len) else {
                self.deficit[class] = 0;
                self.advance();
                continue;
            };
            if !self.topped {
                self.deficit[class] += self.limits.quantum;
                self.topped = true;
            }
            if self.deficit[class] >= len {
                self.deficit[class] -= len;
                return self.queues[class].pop_front();
            }
            self.advance();
        }
        None
    }

    fn advance(&mut self) {
        self.next_bulk = (self.next_bulk + 1) % BULK.len();
        self.topped = false;
    }

    /// Whether a frame of `class` is waiting.
    pub fn is_waiting(&self, class: Class) -> bool {
        !self.queues[class as usize].is_empty()
    }

    /// Frames waiting.
    pub fn len(&self) -> usize {
        self.queues.iter().map(VecDeque::len).sum()
    }

    /// Whether nothing is waiting.
    pub fn is_empty(&self) -> bool {
        self.queues.iter().all(VecDeque::is_empty)
    }
}

/// Writes headers and sequence numbers (per direction, from 0).
#[derive(Debug, Clone)]
pub struct Sender {
    direction: Direction,
    version: Option<u8>,
    next_sequence: u64,
}

impl Sender {
    /// A sender for `direction`, before negotiation.
    pub const fn new(direction: Direction) -> Self {
        Self {
            direction,
            version: None,
            next_sequence: 0,
        }
    }

    /// Records the negotiated version.
    pub fn set_version(&mut self, version: u8) {
        self.version = Some(version);
    }

    /// Sequence number of the next frame (frames before it can be acknowledged
    /// or replayed after a resume).
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Encodes a frame with the next sequence number and appends it to `out`.
    ///
    /// # Errors
    ///
    /// `FRM-E013` for a non-negotiation frame before negotiation; the header
    /// checks of [`encode`] otherwise.
    pub fn encode(&mut self, frame: &Outgoing, out: &mut Vec<u8>) -> Result<(), FrameError> {
        let version = match (frame.frame_type, self.version) {
            (FrameType::Hello | FrameType::HelloAck, _)
            | (FrameType::Error | FrameType::Close, None) => NEGOTIATION_VERSION,
            (_, Some(v)) => v,
            (_, None) => {
                return Err(FrameError::new(
                    Code::NotNegotiated,
                    "trame avant la négociation",
                ));
            }
        };
        let mut h = [0u8; HEADER_LEN];
        crate::header::Header {
            version,
            frame_type: frame.frame_type,
            flags: frame.flags,
            channel: frame.channel,
            length: u16::try_from(frame.payload.len())
                .map_err(|_| FrameError::new(Code::Length, "charge utile trop longue"))?,
            sequence: self.next_sequence,
        }
        .write(&mut h);
        crate::header::Header::parse(&h, self.direction)?;
        out.extend_from_slice(&h);
        out.extend_from_slice(&frame.payload);
        self.next_sequence = self.next_sequence.wrapping_add(1);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
