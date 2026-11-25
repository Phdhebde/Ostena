//! Errors of the transcript stream and of the writer, with stable codes
//! (ADR-0016). `REC-E002` (session not recordable) and `REC-E004` (storage)
//! belong to the core, which receives and stores the stream.

/// Why a transcript stream is refused. Codes are stable: never renumber or
/// reuse one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecorderError {
    /// A frame does not follow the canonical encoding, or the frames are not
    /// in the required order.
    #[error("[REC-E001] flux de transcript mal formé : {0}")]
    Malformed(&'static str),
    /// The transcript exceeds its size or duration limit.
    #[error("[REC-E003] transcript au-delà de sa limite : {0}")]
    Limit(&'static str),
    /// The stream ended before its end frame, or in the middle of a frame.
    #[error("[REC-E005] transcript incomplet : {0}")]
    Incomplete(&'static str),
    /// The transcript file cannot be written.
    #[error("[REC-E004] écriture du transcript impossible : {0}")]
    Io(String),
}

impl RecorderError {
    /// The stable code, e.g. `REC-E001`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Malformed(_) => "REC-E001",
            Self::Limit(_) => "REC-E003",
            Self::Io(_) => "REC-E004",
            Self::Incomplete(_) => "REC-E005",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_start_with_their_code() {
        for e in [
            RecorderError::Malformed("x"),
            RecorderError::Limit("x"),
            RecorderError::Incomplete("x"),
            RecorderError::Io("x".into()),
        ] {
            assert!(e.to_string().starts_with(&format!("[{}]", e.code())));
        }
    }
}
