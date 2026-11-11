//! Fixed 16-byte header and the v1 type table (ADR-0006).
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0 | 1 | version (0 while negotiating) |
//! | 1 | 1 | type |
//! | 2 | 1 | flags (bit 0: `MORE`) |
//! | 3 | 1 | reserved, 0 |
//! | 4 | 2 | channel |
//! | 6 | 2 | payload length |
//! | 8 | 8 | sequence number |
//!
//! The header layout is frozen for every version; only payloads evolve.

use crate::error::{Code, FrameError};

/// Header length.
pub const HEADER_LEN: usize = 16;

/// Largest data part of a fragment (display, clipboard, file chunk). The
/// sender may use smaller fragments (e.g. 4 KiB on slow links).
pub const MAX_FRAGMENT: usize = 16 * 1024;

/// Version used by Hello and HelloAck, before negotiation.
pub const NEGOTIATION_VERSION: u8 = 0;

/// Highest version this crate implements.
pub const CURRENT_VERSION: u8 = 1;

/// Which way a frame travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// From the browser to the gateway.
    ToGateway,
    /// From the gateway to the browser.
    ToBrowser,
}

/// Header flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Flags(u8);

impl Flags {
    /// More fragments of the same message follow on this type and channel.
    pub const MORE: Self = Self(1);
    /// No flag.
    pub const NONE: Self = Self(0);

    pub(crate) const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !Self::MORE.0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// Raw bits.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Whether `MORE` is set.
    pub const fn more(self) -> bool {
        self.0 & Self::MORE.0 != 0
    }
}

/// Scheduling class, highest priority first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Class {
    /// Negotiation, errors, keep-alive, acknowledgements.
    Control,
    /// Keyboard, pointer, touch.
    Input,
    /// Live audit (observer presence).
    Audit,
    /// Screen updates and size changes.
    Display,
    /// Clipboard.
    Clipboard,
    /// File transfer.
    File,
}

const BOTH: [bool; 2] = [true, true];
const TO_GATEWAY: [bool; 2] = [true, false];
const TO_BROWSER: [bool; 2] = [false, true];

macro_rules! frame_types {
    ($($(#[$doc:meta])* $name:ident = $code:literal, $dirs:ident, $class:ident, $max:expr, $frag:literal;)*) => {
        /// Frame types of v1.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[repr(u8)]
        pub enum FrameType {
            $($(#[$doc])* $name = $code,)*
        }

        impl FrameType {
            /// Every type.
            pub const ALL: &'static [Self] = &[$(Self::$name,)*];

            /// The type of a code, if known.
            pub const fn from_code(code: u8) -> Option<Self> {
                match code {
                    $($code => Some(Self::$name),)*
                    _ => None,
                }
            }

            /// Whether the type may travel in `direction`.
            pub const fn allowed(self, direction: Direction) -> bool {
                let dirs = match self { $(Self::$name => $dirs,)* };
                match direction {
                    Direction::ToGateway => dirs[0],
                    Direction::ToBrowser => dirs[1],
                }
            }

            /// Scheduling class.
            pub const fn class(self) -> Class {
                match self { $(Self::$name => Class::$class,)* }
            }

            /// Largest payload, in bytes.
            pub const fn max_payload(self) -> usize {
                match self { $(Self::$name => $max,)* }
            }

            /// Whether `MORE` may be set (the message spans several frames).
            pub const fn fragmentable(self) -> bool {
                match self { $(Self::$name => $frag,)* }
            }
        }
    };
}

frame_types! {
    /// Supported versions and capabilities (browser opens).
    Hello = 0x01, TO_GATEWAY, Control, 8, false;
    /// Version chosen by the gateway.
    HelloAck = 0x02, TO_BROWSER, Control, 8, false;
    /// Orderly close, with a reason code.
    Close = 0x03, BOTH, Control, 4, false;
    /// Error code, no text.
    Error = 0x04, BOTH, Control, 4, false;
    /// Keep-alive request.
    Ping = 0x05, BOTH, Control, 8, false;
    /// Keep-alive answer.
    Pong = 0x06, BOTH, Control, 8, false;
    /// Highest sequence number received without gap.
    Ack = 0x07, BOTH, Control, 8, false;
    /// Resume after a reconnection: highest sequence number received.
    Resume = 0x08, BOTH, Control, 8, false;
    /// Key press or release.
    Key = 0x10, TO_GATEWAY, Input, 8, false;
    /// Pointer position, buttons and wheel.
    Pointer = 0x11, TO_GATEWAY, Input, 9, false;
    /// Touch point.
    Touch = 0x12, TO_GATEWAY, Input, 9, false;
    /// Screen update (video or image), fragmentable.
    DisplayUpdate = 0x20, TO_BROWSER, Display, 9 + MAX_FRAGMENT, true;
    /// Size imposed by the gateway.
    DisplaySize = 0x21, TO_BROWSER, Display, 6, false;
    /// Size requested by the browser.
    ResizeRequest = 0x22, TO_GATEWAY, Display, 6, false;
    /// Available clipboard formats.
    ClipboardOffer = 0x30, BOTH, Clipboard, 4, false;
    /// Clipboard content, fragmentable.
    ClipboardData = 0x31, BOTH, Clipboard, 1 + MAX_FRAGMENT, true;
    /// File transfer announcement: identifier, size, name.
    FileOffer = 0x40, BOTH, File, 13 + 255, false;
    /// File data at an offset.
    FileChunk = 0x41, BOTH, File, 12 + MAX_FRAGMENT, false;
    /// End of file, with a digest computed outside this crate.
    FileEnd = 0x42, BOTH, File, 36, false;
    /// Transfer cancelled.
    FileCancel = 0x43, BOTH, File, 6, false;
    /// Number of live observers and recording state.
    ObserverPresence = 0x50, TO_BROWSER, Audit, 4, false;
}

impl FrameType {
    /// Types valid before negotiation (header version 0).
    pub const fn negotiation(self) -> bool {
        matches!(
            self,
            Self::Hello | Self::HelloAck | Self::Error | Self::Close
        )
    }

    /// Control and audit frames always use channel 0.
    pub const fn channel_zero_only(self) -> bool {
        matches!(self.class(), Class::Control | Class::Audit)
    }
}

/// A decoded header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Version (0 while negotiating).
    pub version: u8,
    /// Type.
    pub frame_type: FrameType,
    /// Flags.
    pub flags: Flags,
    /// Channel.
    pub channel: u16,
    /// Payload length.
    pub length: u16,
    /// Sequence number (per direction, starts at 0).
    pub sequence: u64,
}

impl Header {
    /// Parses and checks a header received in `direction`.
    ///
    /// # Errors
    ///
    /// Any header rule broken: truncated, unknown version or type, wrong
    /// direction, reserved bits, channel, or length above the type maximum.
    pub fn parse(buf: &[u8], direction: Direction) -> Result<Self, FrameError> {
        let Some(h) = buf.first_chunk::<HEADER_LEN>() else {
            return Err(FrameError::new(Code::Truncated, "en-tête incomplet"));
        };
        let version = h[0];
        let frame_type =
            FrameType::from_code(h[1]).ok_or(FrameError::new(Code::UnknownType, "type inconnu"))?;
        if version > CURRENT_VERSION {
            return Err(FrameError::new(Code::Version, "version inconnue"));
        }
        if (version == NEGOTIATION_VERSION) != frame_type.negotiation()
            && !(version == CURRENT_VERSION
                && matches!(frame_type, FrameType::Error | FrameType::Close))
        {
            return Err(FrameError::new(
                Code::Version,
                "version incompatible avec le type (0 réservé à la négociation)",
            ));
        }
        if !frame_type.allowed(direction) {
            return Err(FrameError::new(
                Code::WrongDirection,
                "type interdit dans ce sens",
            ));
        }
        let flags =
            Flags::from_bits(h[2]).ok_or(FrameError::new(Code::Reserved, "drapeau inconnu"))?;
        if flags.more() && !frame_type.fragmentable() {
            return Err(FrameError::new(
                Code::Fragmentation,
                "type non fragmentable",
            ));
        }
        if h[3] != 0 {
            return Err(FrameError::new(Code::Reserved, "octet réservé non nul"));
        }
        let channel = u16::from_be_bytes([h[4], h[5]]);
        if channel != 0 && frame_type.channel_zero_only() {
            return Err(FrameError::new(
                Code::Channel,
                "canal 0 obligatoire pour ce type",
            ));
        }
        let length = u16::from_be_bytes([h[6], h[7]]);
        if usize::from(length) > frame_type.max_payload() {
            return Err(FrameError::new(
                Code::Length,
                "longueur au-delà du maximum du type",
            ));
        }
        let mut seq = [0u8; 8];
        seq.copy_from_slice(&h[8..16]);
        Ok(Self {
            version,
            frame_type,
            flags,
            channel,
            length,
            sequence: u64::from_be_bytes(seq),
        })
    }

    /// Writes the header.
    pub fn write(&self, out: &mut [u8; HEADER_LEN]) {
        out[0] = self.version;
        out[1] = self.frame_type as u8;
        out[2] = self.flags.bits();
        out[3] = 0;
        out[4..6].copy_from_slice(&self.channel.to_be_bytes());
        out[6..8].copy_from_slice(&self.length.to_be_bytes());
        out[8..16].copy_from_slice(&self.sequence.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_table() {
        for t in FrameType::ALL {
            assert_eq!(FrameType::from_code(*t as u8), Some(*t));
            assert!(t.allowed(Direction::ToGateway) || t.allowed(Direction::ToBrowser));
            assert!(u16::try_from(t.max_payload()).is_ok());
        }
        assert!(FrameType::Key.allowed(Direction::ToGateway));
        assert!(!FrameType::Key.allowed(Direction::ToBrowser));
        assert!(!FrameType::DisplayUpdate.allowed(Direction::ToGateway));
        assert!(FrameType::ClipboardData.allowed(Direction::ToGateway));
        assert!(FrameType::ClipboardData.allowed(Direction::ToBrowser));
        assert!(FrameType::FileChunk.allowed(Direction::ToGateway));
        assert!(FrameType::FileChunk.allowed(Direction::ToBrowser));
        assert!(!FrameType::ObserverPresence.allowed(Direction::ToGateway));
        assert_eq!(FrameType::from_code(0x99), None);
    }

    #[test]
    fn classes_order_inputs_before_display() {
        assert!(Class::Control < Class::Input);
        assert!(Class::Input < Class::Audit);
        assert!(Class::Audit < Class::Display);
        assert_eq!(FrameType::Pointer.class(), Class::Input);
        assert_eq!(FrameType::DisplayUpdate.class(), Class::Display);
    }
}
