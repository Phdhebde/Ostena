//! Refusals of the session manager, each with a stable code.

/// Why a session is refused. Codes are stable: never renumber or reuse one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    /// The sessions of the agent are at their bound.
    #[error("[SES-E001] nombre maximal de sessions de l'agent atteint ({0})")]
    AgentLimit(usize),
    /// The sessions of this user are at their bound.
    #[error("[SES-E002] nombre maximal de sessions de cet utilisateur atteint ({0})")]
    UserLimit(usize),
    /// The sessions towards this target are at their bound.
    #[error("[SES-E003] nombre maximal de sessions vers cette cible atteint ({0})")]
    TargetLimit(usize),
    /// A session with this identifier is already open on the agent: the
    /// identifier comes from the core and is never reused.
    #[error("[SES-E004] identifiant de session déjà utilisé sur l'agent : refusé")]
    DuplicateId,
    /// The agent is stopping: no new session.
    #[error("[SES-E005] arrêt de l'agent en cours : aucune nouvelle session")]
    ShuttingDown,
}

impl SessionError {
    /// The stable code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::AgentLimit(_) => "SES-E001",
            Self::UserLimit(_) => "SES-E002",
            Self::TargetLimit(_) => "SES-E003",
            Self::DuplicateId => "SES-E004",
            Self::ShuttingDown => "SES-E005",
        }
    }

    /// A quota refusal (`SES-E001` to `SES-E003`), as opposed to a refused
    /// identifier or a stop.
    pub fn is_limit(&self) -> bool {
        matches!(
            self,
            Self::AgentLimit(_) | Self::UserLimit(_) | Self::TargetLimit(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_in_the_messages() {
        for error in [
            SessionError::AgentLimit(1),
            SessionError::UserLimit(2),
            SessionError::TargetLimit(3),
            SessionError::DuplicateId,
            SessionError::ShuttingDown,
        ] {
            assert!(
                error
                    .to_string()
                    .starts_with(&format!("[{}]", error.code()))
            );
        }
        assert!(SessionError::UserLimit(1).is_limit());
        assert!(!SessionError::DuplicateId.is_limit());
    }
}
