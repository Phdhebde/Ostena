//! Typed payloads of v1, read at fixed offsets without copying.
//!
//! No payload carries a secret or free text (ADR-0006): errors are codes, and
//! user data (keys, clipboard, files) is wrapped in types whose `Debug` does
//! not show it.

use alloc::vec::Vec;
use core::fmt;

use crate::error::{Code, FrameError};
use crate::header::{FrameType, MAX_FRAGMENT};

fn invalid(reason: &'static str) -> FrameError {
    FrameError::new(Code::InvalidField, reason)
}

fn length(reason: &'static str) -> FrameError {
    FrameError::new(Code::Length, reason)
}

/// Opaque user data (screen, clipboard, file). `Debug` shows the length only.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Opaque<'a>(&'a [u8]);

impl<'a> Opaque<'a> {
    /// Wraps borrowed bytes.
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    /// The bytes.
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// Length in bytes.
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether empty.
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Opaque<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Opaque({} octets)", self.0.len())
    }
}

/// Windows reserved device names, refused with or without extension.
const RESERVED_NAMES: [&str; 28] = [
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "COM\u{b9}",
    "COM\u{b2}",
    "COM\u{b3}",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
    "LPT\u{b9}",
    "LPT\u{b2}",
    "LPT\u{b3}",
];

/// A file name, validated: UTF-8, 1 to 255 bytes, a single path component
/// that is safe on Windows and Unix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileName<'a>(&'a str);

impl<'a> FileName<'a> {
    /// Validates a name.
    ///
    /// # Errors
    ///
    /// `FRM-E008` for an empty or overlong name, control characters,
    /// separators or characters forbidden on Windows (`<>:"/\|?*`), `.` and
    /// `..`, a trailing dot or space, or a Windows reserved device name
    /// (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, with or
    /// without extension, any case).
    pub fn new(name: &'a str) -> Result<Self, FrameError> {
        if name.is_empty() || name.len() > 255 {
            return Err(invalid("nom de fichier vide ou de plus de 255 octets"));
        }
        if name.chars().any(|c| {
            c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
        }) {
            return Err(invalid("caractère interdit dans le nom de fichier"));
        }
        if name == "." || name == ".." || name.ends_with('.') || name.ends_with(' ') {
            return Err(invalid(
                "nom de fichier « . », « .. » ou terminé par un point ou une espace",
            ));
        }
        let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
        if RESERVED_NAMES.iter().any(|r| r.eq_ignore_ascii_case(stem)) {
            return Err(invalid("nom de périphérique réservé de Windows"));
        }
        Ok(Self(name))
    }

    /// The name.
    pub const fn as_str(&self) -> &'a str {
        self.0
    }
}

/// How a key is identified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// PC scancode (RDP).
    Scancode = 1,
    /// X11 keysym (VNC).
    Keysym = 2,
}

/// A key press or release. `Debug` hides the key: keystrokes may be secrets.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KeyInput {
    /// Scancode or keysym.
    pub code: u32,
    /// Interpretation of `code`.
    pub kind: KeyKind,
    /// Pressed (`true`) or released.
    pub pressed: bool,
    /// Modifier state (bit set, interpreted by the session layer).
    pub modifiers: u16,
}

impl fmt::Debug for KeyInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyInput([REDACTED])")
    }
}

/// Pointer state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointerInput {
    /// Absolute position.
    pub x: u16,
    /// Absolute position.
    pub y: u16,
    /// Pressed buttons (bit 0: left, 1: right, 2: middle, 3–4: extra).
    pub buttons: u8,
    /// Horizontal wheel delta.
    pub wheel_x: i16,
    /// Vertical wheel delta.
    pub wheel_y: i16,
}

/// Touch phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(missing_docs, reason = "standard touch phases")]
pub enum TouchPhase {
    Start = 0,
    Move = 1,
    End = 2,
    Cancel = 3,
}

/// A touch point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TouchInput {
    /// Touch identifier.
    pub id: u16,
    /// Phase.
    pub phase: TouchPhase,
    /// Absolute position.
    pub x: u16,
    /// Absolute position.
    pub y: u16,
    /// Pressure, 0 to 65535.
    pub pressure: u16,
}

/// Display encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(missing_docs, reason = "codec names")]
pub enum Codec {
    Raw = 1,
    Png = 2,
    Jpeg = 3,
    H264 = 4,
}

/// Rectangle of a display update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(missing_docs, reason = "rectangle coordinates")]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
}

/// A display size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Size {
    /// Width in pixels, 1 to 16384.
    pub width: u16,
    /// Height in pixels, 1 to 16384.
    pub height: u16,
    /// Scale factor in percent, 50 to 400.
    pub scale_percent: u16,
}

/// Clipboard formats (bit set).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClipboardFormats(u32);

impl ClipboardFormats {
    /// Plain text (UTF-8).
    pub const TEXT: Self = Self(1);
    /// HTML.
    pub const HTML: Self = Self(1 << 1);
    /// PNG image.
    pub const PNG: Self = Self(1 << 2);
    const KNOWN: u32 = 0b111;

    /// Parses a bit set; `None` for unknown bits.
    pub const fn from_bits(bits: u32) -> Option<Self> {
        if bits & !Self::KNOWN == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// Raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

/// A single clipboard format, for data frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(missing_docs, reason = "see ClipboardFormats")]
pub enum ClipboardFormat {
    Text = 0,
    Html = 1,
    Png = 2,
}

/// Every v1 payload, borrowing the frame buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Payload<'a> {
    /// Supported versions (bit `v - 1` for version `v`) and capabilities.
    Hello {
        /// Version bit set.
        versions: u32,
        /// Capability bit set (reserved, 0 in v1).
        capabilities: u32,
    },
    /// Chosen version.
    HelloAck {
        /// Version.
        version: u8,
        /// Capability bit set (reserved, 0 in v1).
        capabilities: u32,
    },
    /// Orderly close.
    Close {
        /// Reason code.
        reason: u16,
    },
    /// Error code (e.g. an `FRM-E0xx` number), no text.
    Error {
        /// Error code.
        code: u16,
        /// Detail code (e.g. the offending frame type).
        detail: u16,
    },
    /// Keep-alive request.
    Ping {
        /// Opaque token echoed in Pong.
        token: u64,
    },
    /// Keep-alive answer.
    Pong {
        /// Token of the Ping.
        token: u64,
    },
    /// Highest sequence number received without gap.
    Ack {
        /// Sequence number.
        sequence: u64,
    },
    /// Resume: highest sequence number received before the cut.
    Resume {
        /// Sequence number.
        sequence: u64,
    },
    /// Key.
    Key(KeyInput),
    /// Pointer.
    Pointer(PointerInput),
    /// Touch.
    Touch(TouchInput),
    /// Screen update fragment.
    DisplayUpdate {
        /// Encoding.
        codec: Codec,
        /// Updated area.
        rect: Rect,
        /// Encoded data (1 to 16 KiB per fragment).
        data: Opaque<'a>,
    },
    /// Size imposed by the gateway.
    DisplaySize(Size),
    /// Size requested by the browser.
    ResizeRequest(Size),
    /// Available clipboard formats.
    ClipboardOffer(ClipboardFormats),
    /// Clipboard data fragment (may be empty: empty clipboard).
    ClipboardData {
        /// Format.
        format: ClipboardFormat,
        /// Data (0 to 16 KiB per fragment).
        data: Opaque<'a>,
    },
    /// File transfer announcement.
    FileOffer {
        /// Transfer identifier.
        transfer: u32,
        /// Total size in bytes.
        size: u64,
        /// Validated name.
        name: FileName<'a>,
    },
    /// File data.
    FileChunk {
        /// Transfer identifier.
        transfer: u32,
        /// Offset of `data` in the file.
        offset: u64,
        /// Data (1 to 16 KiB).
        data: Opaque<'a>,
    },
    /// End of file.
    FileEnd {
        /// Transfer identifier.
        transfer: u32,
        /// Digest of the whole file, computed outside this crate.
        digest: [u8; 32],
    },
    /// Transfer cancelled.
    FileCancel {
        /// Transfer identifier.
        transfer: u32,
        /// Reason code.
        reason: u16,
    },
    /// Live audit information shown to the user.
    ObserverPresence {
        /// Number of live observers.
        observers: u16,
        /// The session is recorded.
        recording: bool,
    },
}

/// Bounds-checked big-endian reader over a payload.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> u8 {
        let v = self.buf[self.pos];
        self.pos += 1;
        v
    }

    fn u16(&mut self) -> u16 {
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        v
    }

    fn u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        b.copy_from_slice(&self.buf[self.pos..self.pos + 4]);
        self.pos += 4;
        u32::from_be_bytes(b)
    }

    fn u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        u64::from_be_bytes(b)
    }

    fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }
}

/// Fixed part length of each type (the whole payload for fixed types).
const fn fixed_len(t: FrameType) -> usize {
    match t {
        FrameType::Hello
        | FrameType::HelloAck
        | FrameType::Ping
        | FrameType::Pong
        | FrameType::Ack
        | FrameType::Resume
        | FrameType::Key => 8,
        FrameType::Close
        | FrameType::Error
        | FrameType::ClipboardOffer
        | FrameType::ObserverPresence => 4,
        FrameType::Pointer | FrameType::Touch | FrameType::DisplayUpdate => 9,
        FrameType::DisplaySize | FrameType::ResizeRequest | FrameType::FileCancel => 6,
        FrameType::ClipboardData => 1,
        FrameType::FileOffer => 13,
        FrameType::FileChunk => 12,
        FrameType::FileEnd => 36,
    }
}

fn size(r: &mut Reader<'_>) -> Result<Size, FrameError> {
    let s = Size {
        width: r.u16(),
        height: r.u16(),
        scale_percent: r.u16(),
    };
    let ok = (1..=16_384).contains(&s.width)
        && (1..=16_384).contains(&s.height)
        && (50..=400).contains(&s.scale_percent);
    ok.then_some(s)
        .ok_or(invalid("taille d'affichage hors bornes"))
}

impl<'a> Payload<'a> {
    /// The frame type of this payload.
    pub const fn frame_type(&self) -> FrameType {
        match self {
            Self::Hello { .. } => FrameType::Hello,
            Self::HelloAck { .. } => FrameType::HelloAck,
            Self::Close { .. } => FrameType::Close,
            Self::Error { .. } => FrameType::Error,
            Self::Ping { .. } => FrameType::Ping,
            Self::Pong { .. } => FrameType::Pong,
            Self::Ack { .. } => FrameType::Ack,
            Self::Resume { .. } => FrameType::Resume,
            Self::Key(_) => FrameType::Key,
            Self::Pointer(_) => FrameType::Pointer,
            Self::Touch(_) => FrameType::Touch,
            Self::DisplayUpdate { .. } => FrameType::DisplayUpdate,
            Self::DisplaySize(_) => FrameType::DisplaySize,
            Self::ResizeRequest(_) => FrameType::ResizeRequest,
            Self::ClipboardOffer(_) => FrameType::ClipboardOffer,
            Self::ClipboardData { .. } => FrameType::ClipboardData,
            Self::FileOffer { .. } => FrameType::FileOffer,
            Self::FileChunk { .. } => FrameType::FileChunk,
            Self::FileEnd { .. } => FrameType::FileEnd,
            Self::FileCancel { .. } => FrameType::FileCancel,
            Self::ObserverPresence { .. } => FrameType::ObserverPresence,
        }
    }

    /// Parses the payload of a frame of type `t`. `buf` is exactly the
    /// payload (its length was checked against the type maximum).
    ///
    /// # Errors
    ///
    /// `FRM-E006` for a length that does not match the type, `FRM-E007` for a
    /// reserved field not zero, `FRM-E008` for a field out of its domain.
    #[expect(
        clippy::too_many_lines,
        reason = "one arm per frame type, read in place"
    )]
    pub fn parse(t: FrameType, buf: &'a [u8]) -> Result<Self, FrameError> {
        let fixed = fixed_len(t);
        let variable = matches!(
            t,
            FrameType::DisplayUpdate
                | FrameType::ClipboardData
                | FrameType::FileOffer
                | FrameType::FileChunk
        );
        if buf.len() < fixed || (!variable && buf.len() != fixed) {
            return Err(length("longueur de charge utile incorrecte pour le type"));
        }
        let mut r = Reader { buf, pos: 0 };
        let reserved = |ok: bool| {
            if ok {
                Ok(())
            } else {
                Err(FrameError::new(Code::Reserved, "champ réservé non nul"))
            }
        };
        Ok(match t {
            FrameType::Hello => {
                let versions = r.u32();
                let capabilities = r.u32();
                if versions == 0 {
                    return Err(invalid("aucune version annoncée"));
                }
                reserved(capabilities == 0)?;
                Self::Hello {
                    versions,
                    capabilities,
                }
            }
            FrameType::HelloAck => {
                let version = r.u8();
                reserved(r.u8() == 0 && r.u16() == 0)?;
                let capabilities = r.u32();
                reserved(capabilities == 0)?;
                if version == 0 || version > 32 {
                    return Err(invalid("version retenue hors bornes"));
                }
                Self::HelloAck {
                    version,
                    capabilities,
                }
            }
            FrameType::Close => {
                let reason = r.u16();
                reserved(r.u16() == 0)?;
                Self::Close { reason }
            }
            FrameType::Error => Self::Error {
                code: r.u16(),
                detail: r.u16(),
            },
            FrameType::Ping => Self::Ping { token: r.u64() },
            FrameType::Pong => Self::Pong { token: r.u64() },
            FrameType::Ack => Self::Ack { sequence: r.u64() },
            FrameType::Resume => Self::Resume { sequence: r.u64() },
            FrameType::Key => {
                let code = r.u32();
                let kind = match r.u8() {
                    1 => KeyKind::Scancode,
                    2 => KeyKind::Keysym,
                    _ => return Err(invalid("type de touche inconnu")),
                };
                let pressed = match r.u8() {
                    0 => false,
                    1 => true,
                    _ => return Err(invalid("état de touche inconnu")),
                };
                Self::Key(KeyInput {
                    code,
                    kind,
                    pressed,
                    modifiers: r.u16(),
                })
            }
            FrameType::Pointer => {
                let (x, y) = (r.u16(), r.u16());
                let buttons = r.u8();
                if buttons & !0b1_1111 != 0 {
                    return Err(invalid("bouton de pointeur inconnu"));
                }
                #[expect(clippy::cast_possible_wrap, reason = "two's complement on purpose")]
                let (wheel_x, wheel_y) = (r.u16() as i16, r.u16() as i16);
                Self::Pointer(PointerInput {
                    x,
                    y,
                    buttons,
                    wheel_x,
                    wheel_y,
                })
            }
            FrameType::Touch => {
                let id = r.u16();
                let phase = match r.u8() {
                    0 => TouchPhase::Start,
                    1 => TouchPhase::Move,
                    2 => TouchPhase::End,
                    3 => TouchPhase::Cancel,
                    _ => return Err(invalid("phase tactile inconnue")),
                };
                Self::Touch(TouchInput {
                    id,
                    phase,
                    x: r.u16(),
                    y: r.u16(),
                    pressure: r.u16(),
                })
            }
            FrameType::DisplayUpdate => {
                let codec = match r.u8() {
                    1 => Codec::Raw,
                    2 => Codec::Png,
                    3 => Codec::Jpeg,
                    4 => Codec::H264,
                    _ => return Err(invalid("codec d'affichage inconnu")),
                };
                let rect = Rect {
                    x: r.u16(),
                    y: r.u16(),
                    width: r.u16(),
                    height: r.u16(),
                };
                if rect.width == 0 || rect.height == 0 {
                    return Err(invalid("rectangle d'affichage vide"));
                }
                let data = r.rest();
                if data.is_empty() || data.len() > MAX_FRAGMENT {
                    return Err(length("données d'affichage vides ou au-delà de 16 Kio"));
                }
                Self::DisplayUpdate {
                    codec,
                    rect,
                    data: Opaque(data),
                }
            }
            FrameType::DisplaySize => Self::DisplaySize(size(&mut r)?),
            FrameType::ResizeRequest => Self::ResizeRequest(size(&mut r)?),
            FrameType::ClipboardOffer => Self::ClipboardOffer(
                ClipboardFormats::from_bits(r.u32())
                    .ok_or(invalid("format de presse-papiers inconnu"))?,
            ),
            FrameType::ClipboardData => {
                let format = match r.u8() {
                    0 => ClipboardFormat::Text,
                    1 => ClipboardFormat::Html,
                    2 => ClipboardFormat::Png,
                    _ => return Err(invalid("format de presse-papiers inconnu")),
                };
                let data = r.rest();
                if data.len() > MAX_FRAGMENT {
                    return Err(length("données de presse-papiers au-delà de 16 Kio"));
                }
                Self::ClipboardData {
                    format,
                    data: Opaque(data),
                }
            }
            FrameType::FileOffer => {
                let transfer = r.u32();
                let size = r.u64();
                let name_len = usize::from(r.u8());
                let raw = r.rest();
                if name_len == 0 || raw.len() != name_len {
                    return Err(length("longueur du nom de fichier incohérente"));
                }
                let text =
                    core::str::from_utf8(raw).map_err(|_| invalid("nom de fichier non UTF-8"))?;
                Self::FileOffer {
                    transfer,
                    size,
                    name: FileName::new(text)?,
                }
            }
            FrameType::FileChunk => {
                let transfer = r.u32();
                let offset = r.u64();
                let data = r.rest();
                if data.is_empty() || data.len() > MAX_FRAGMENT {
                    return Err(length("morceau de fichier vide ou au-delà de 16 Kio"));
                }
                Self::FileChunk {
                    transfer,
                    offset,
                    data: Opaque(data),
                }
            }
            FrameType::FileEnd => {
                let transfer = r.u32();
                let mut digest = [0u8; 32];
                digest.copy_from_slice(r.rest());
                Self::FileEnd { transfer, digest }
            }
            FrameType::FileCancel => Self::FileCancel {
                transfer: r.u32(),
                reason: r.u16(),
            },
            FrameType::ObserverPresence => {
                let observers = r.u16();
                let flags = r.u8();
                reserved(flags & !1 == 0 && r.u8() == 0)?;
                Self::ObserverPresence {
                    observers,
                    recording: flags & 1 == 1,
                }
            }
        })
    }

    /// Encoded payload length.
    pub fn encoded_len(&self) -> usize {
        let t = self.frame_type();
        fixed_len(t)
            + match self {
                Self::DisplayUpdate { data, .. }
                | Self::ClipboardData { data, .. }
                | Self::FileChunk { data, .. } => data.len(),
                Self::FileOffer { name, .. } => name.as_str().len(),
                _ => 0,
            }
    }

    /// Appends the encoded payload to `out`.
    pub fn write(&self, out: &mut Vec<u8>) {
        match *self {
            Self::Hello {
                versions,
                capabilities,
            } => {
                out.extend_from_slice(&versions.to_be_bytes());
                out.extend_from_slice(&capabilities.to_be_bytes());
            }
            Self::HelloAck {
                version,
                capabilities,
            } => {
                out.extend_from_slice(&[version, 0, 0, 0]);
                out.extend_from_slice(&capabilities.to_be_bytes());
            }
            Self::Close { reason } => {
                out.extend_from_slice(&reason.to_be_bytes());
                out.extend_from_slice(&[0, 0]);
            }
            Self::Error { code, detail } => {
                out.extend_from_slice(&code.to_be_bytes());
                out.extend_from_slice(&detail.to_be_bytes());
            }
            Self::Ping { token } | Self::Pong { token } => {
                out.extend_from_slice(&token.to_be_bytes());
            }
            Self::Ack { sequence } | Self::Resume { sequence } => {
                out.extend_from_slice(&sequence.to_be_bytes());
            }
            Self::Key(k) => {
                out.extend_from_slice(&k.code.to_be_bytes());
                out.extend_from_slice(&[k.kind as u8, u8::from(k.pressed)]);
                out.extend_from_slice(&k.modifiers.to_be_bytes());
            }
            Self::Pointer(p) => {
                out.extend_from_slice(&p.x.to_be_bytes());
                out.extend_from_slice(&p.y.to_be_bytes());
                out.push(p.buttons);
                out.extend_from_slice(&p.wheel_x.to_be_bytes());
                out.extend_from_slice(&p.wheel_y.to_be_bytes());
            }
            Self::Touch(t) => {
                out.extend_from_slice(&t.id.to_be_bytes());
                out.push(t.phase as u8);
                out.extend_from_slice(&t.x.to_be_bytes());
                out.extend_from_slice(&t.y.to_be_bytes());
                out.extend_from_slice(&t.pressure.to_be_bytes());
            }
            Self::DisplayUpdate { codec, rect, data } => {
                out.push(codec as u8);
                for v in [rect.x, rect.y, rect.width, rect.height] {
                    out.extend_from_slice(&v.to_be_bytes());
                }
                out.extend_from_slice(data.as_bytes());
            }
            Self::DisplaySize(s) | Self::ResizeRequest(s) => {
                for v in [s.width, s.height, s.scale_percent] {
                    out.extend_from_slice(&v.to_be_bytes());
                }
            }
            Self::ClipboardOffer(f) => out.extend_from_slice(&f.bits().to_be_bytes()),
            Self::ClipboardData { format, data } => {
                out.push(format as u8);
                out.extend_from_slice(data.as_bytes());
            }
            Self::FileOffer {
                transfer,
                size,
                name,
            } => {
                out.extend_from_slice(&transfer.to_be_bytes());
                out.extend_from_slice(&size.to_be_bytes());
                // FileName guarantees 1 to 255 bytes.
                out.push(u8::try_from(name.as_str().len()).unwrap_or(u8::MAX));
                out.extend_from_slice(name.as_str().as_bytes());
            }
            Self::FileChunk {
                transfer,
                offset,
                data,
            } => {
                out.extend_from_slice(&transfer.to_be_bytes());
                out.extend_from_slice(&offset.to_be_bytes());
                out.extend_from_slice(data.as_bytes());
            }
            Self::FileEnd { transfer, digest } => {
                out.extend_from_slice(&transfer.to_be_bytes());
                out.extend_from_slice(&digest);
            }
            Self::FileCancel { transfer, reason } => {
                out.extend_from_slice(&transfer.to_be_bytes());
                out.extend_from_slice(&reason.to_be_bytes());
            }
            Self::ObserverPresence {
                observers,
                recording,
            } => {
                out.extend_from_slice(&observers.to_be_bytes());
                out.extend_from_slice(&[u8::from(recording), 0]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;

    use super::*;

    #[test]
    fn file_names() {
        for ok in [
            "rapport.pdf",
            "a",
            "Ünïcødé.txt",
            "CONFIG.SYS",
            "COM10",
            "console.log",
            ".bashrc",
            "a b.txt",
        ] {
            assert!(FileName::new(ok).is_ok(), "{ok}");
        }
        let long = "a".repeat(256);
        for bad in [
            "",
            ".",
            "..",
            "a.",
            "a ",
            "a/b",
            "a\\b",
            "c:x",
            "a<b",
            "a>b",
            "a\"b",
            "a|b",
            "a?b",
            "a*b",
            "a\u{0}b",
            "a\nb",
            "CON",
            "con",
            "Nul.txt",
            "aux.tar.gz",
            "COM1",
            "com9.log",
            "LPT3",
            "lpt1.txt",
            "COM\u{b9}",
            "CON .txt",
            long.as_str(),
        ] {
            let e = FileName::new(bad).unwrap_err();
            assert_eq!(e.code, Code::InvalidField, "{bad:?}");
        }
    }

    #[test]
    fn user_data_is_not_shown_by_debug() {
        let key = KeyInput {
            code: 0x1e,
            kind: KeyKind::Scancode,
            pressed: true,
            modifiers: 0,
        };
        assert_eq!(format!("{key:?}"), "KeyInput([REDACTED])");
        let data = Opaque::new(b"hunter2");
        assert_eq!(format!("{data:?}"), "Opaque(7 octets)");
    }
}
