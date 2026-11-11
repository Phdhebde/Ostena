//! Stable error codes of the platform layer (ADR-0007).

/// Stable error codes of the agent platform layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Code {
    /// Administrator (root) rights needed.
    Privileges,
    /// Installation failed.
    Install,
    /// Uninstallation failed.
    Uninstall,
    /// Service state unavailable.
    State,
    /// Service runtime failure.
    Runtime,
    /// The control plane name is already taken (another agent, or a squat).
    ControlNameTaken,
    /// The control plane server is not the agent service.
    ControlNotAuthentic,
    /// Control plane I/O failure, timeout or oversized message.
    ControlIo,
    /// Control plane access refused to the caller.
    ControlDenied,
}

impl Code {
    /// The code as written in messages, e.g. `AGT-E001`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Privileges => "AGT-E001",
            Self::Install => "AGT-E002",
            Self::Uninstall => "AGT-E003",
            Self::State => "AGT-E004",
            Self::Runtime => "AGT-E005",
            Self::ControlNameTaken => "AGT-E006",
            Self::ControlNotAuthentic => "AGT-E007",
            Self::ControlIo => "AGT-E008",
            Self::ControlDenied => "AGT-E009",
        }
    }
}

/// A platform failure, with a stable code and a French message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("[{}] {message}", code.as_str())]
pub struct PlatformError {
    /// Stable code.
    pub code: Code,
    /// What went wrong.
    pub message: String,
}

impl PlatformError {
    /// A failure with its code.
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}
