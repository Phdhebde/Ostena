//! Stable error codes (ADR-0006). `Copy` and allocation-free.

use core::fmt;

/// Stable codes. Never renumber or reuse one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Code {
    /// Truncated frame (header or payload).
    Truncated,
    /// Bytes after the frame.
    TrailingBytes,
    /// Unknown version, or not the negotiated one.
    Version,
    /// Unknown frame type.
    UnknownType,
    /// Frame type not allowed in this direction.
    WrongDirection,
    /// Payload length out of bounds for the type.
    Length,
    /// Unknown flag, or reserved byte not zero.
    Reserved,
    /// Payload field out of its domain.
    InvalidField,
    /// No common version.
    NoCommonVersion,
    /// Unexpected sequence number.
    Sequence,
    /// Invalid fragmentation.
    Fragmentation,
    /// Scheduler queue full.
    QueueFull,
    /// Frame received before version negotiation.
    NotNegotiated,
    /// Channel not allowed for the type.
    Channel,
}

impl Code {
    /// Every code, in numbering order.
    pub const ALL: [Self; 14] = [
        Self::Truncated,
        Self::TrailingBytes,
        Self::Version,
        Self::UnknownType,
        Self::WrongDirection,
        Self::Length,
        Self::Reserved,
        Self::InvalidField,
        Self::NoCommonVersion,
        Self::Sequence,
        Self::Fragmentation,
        Self::QueueFull,
        Self::NotNegotiated,
        Self::Channel,
    ];

    /// The code as written in messages, e.g. `FRM-E005`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Truncated => "FRM-E001",
            Self::TrailingBytes => "FRM-E002",
            Self::Version => "FRM-E003",
            Self::UnknownType => "FRM-E004",
            Self::WrongDirection => "FRM-E005",
            Self::Length => "FRM-E006",
            Self::Reserved => "FRM-E007",
            Self::InvalidField => "FRM-E008",
            Self::NoCommonVersion => "FRM-E009",
            Self::Sequence => "FRM-E010",
            Self::Fragmentation => "FRM-E011",
            Self::QueueFull => "FRM-E012",
            Self::NotNegotiated => "FRM-E013",
            Self::Channel => "FRM-E014",
        }
    }

    /// Numeric value carried by an Error frame (1 for `FRM-E001`…).
    pub const fn number(self) -> u16 {
        match self {
            Self::Truncated => 1,
            Self::TrailingBytes => 2,
            Self::Version => 3,
            Self::UnknownType => 4,
            Self::WrongDirection => 5,
            Self::Length => 6,
            Self::Reserved => 7,
            Self::InvalidField => 8,
            Self::NoCommonVersion => 9,
            Self::Sequence => 10,
            Self::Fragmentation => 11,
            Self::QueueFull => 12,
            Self::NotNegotiated => 13,
            Self::Channel => 14,
        }
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A refused frame: a stable code and a fixed French explanation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameError {
    /// Stable code.
    pub code: Code,
    /// What was wrong (static text: never data from the frame).
    pub reason: &'static str,
}

impl FrameError {
    pub(crate) const fn new(code: Code, reason: &'static str) -> Self {
        Self { code, reason }
    }
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] trame refusée : {}", self.code, self.reason)
    }
}

impl core::error::Error for FrameError {}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn codes_are_numbered() {
        for (i, c) in Code::ALL.iter().enumerate() {
            assert_eq!(c.as_str(), format!("FRM-E{:03}", i + 1));
            assert_eq!(usize::from(c.number()), i + 1);
        }
        let e = FrameError::new(Code::Length, "longueur");
        assert_eq!(e.to_string(), "[FRM-E006] trame refusée : longueur");
    }
}
