//! Errors of the SSH session path (ADR-0010), each with a stable code. The
//! pre-check (`SSH-E001` to `SSH-E006`) and the keys (`SSH-E007` to
//! `SSH-E009`) have their own types.

use crate::cert::CertError;
use crate::login::LoginError;

/// Why a connection, an access or a request is refused. Codes are stable:
/// never renumber or reuse one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SshError {
    /// Invalid `account@resource`.
    #[error("{0}")]
    Login(LoginError),
    /// User certificate refused (format, authority, signature, policy).
    #[error("[SSH-E011] certificat utilisateur refusé : {0}")]
    UserCertificate(CertError),
    /// A bare key instead of a certificate.
    #[error(
        "[SSH-E012] clé publique nue refusée : seul un certificat d'`ostena login` est accepté"
    )]
    BareKey,
    /// The access was refused; `code` is the underlying one (`GRT-E…`,
    /// `SCP-E…`, `TUN-E…`, a code of the core).
    #[error("[SSH-E013] accès refusé ({code}) : {message}")]
    AccessRefused {
        /// Underlying code.
        code: String,
        /// Explanation.
        message: String,
    },
    /// The target host key is not the pinned one.
    #[error("[SSH-E014] clé d'hôte de la cible différente de celle épinglée : connexion refusée")]
    TargetHostKey,
    /// The target refused the agent key.
    #[error("[SSH-E015] la cible a refusé l'authentification de l'agent")]
    TargetAuth,
    /// The target cannot be reached in time.
    #[error("[SSH-E016] cible injoignable : {0}")]
    TargetUnreachable(String),
    /// Channel or request refused.
    #[error("[SSH-E017] canal ou requête refusé : {0}")]
    Refused(&'static str),
    /// Invalid host certificate or SSH identity of the agent.
    #[error("[SSH-E018] identité SSH de l'agent invalide : {0}")]
    Identity(String),
    /// A server limit is reached.
    #[error("[SSH-E019] limite du serveur SSH atteinte : {0}")]
    Limit(&'static str),
    /// The transcript can no longer be handed to the core: the session is
    /// cut (ADR-0016, fail closed). `SSH-E020` belongs to the agent
    /// (revocations lost).
    #[error("[SSH-E021] transcript non transmissible au core, session coupée : {0}")]
    TranscriptLost(String),
}

impl SshError {
    /// The stable code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Login(_) => "SSH-E010",
            Self::UserCertificate(_) => "SSH-E011",
            Self::BareKey => "SSH-E012",
            Self::AccessRefused { .. } => "SSH-E013",
            Self::TargetHostKey => "SSH-E014",
            Self::TargetAuth => "SSH-E015",
            Self::TargetUnreachable(_) => "SSH-E016",
            Self::Refused(_) => "SSH-E017",
            Self::Identity(_) => "SSH-E018",
            Self::Limit(_) => "SSH-E019",
            Self::TranscriptLost(_) => "SSH-E021",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_starts_with_code() {
        let samples = [
            SshError::Login(LoginError::NoResource),
            SshError::UserCertificate(CertError::BadSignature),
            SshError::BareKey,
            SshError::AccessRefused {
                code: "GRT-E010".into(),
                message: "x".into(),
            },
            SshError::TargetHostKey,
            SshError::TargetAuth,
            SshError::TargetUnreachable("x".into()),
            SshError::Refused("x"),
            SshError::Identity("x".into()),
            SshError::Limit("x"),
        ];
        for (i, e) in samples.iter().enumerate() {
            let code = format!("SSH-E{:03}", i + 10);
            assert_eq!(e.code(), code);
            assert!(e.to_string().starts_with(&format!("[{code}]")), "{e}");
        }
        let lost = SshError::TranscriptLost("x".into());
        assert_eq!(lost.code(), "SSH-E021");
        assert!(lost.to_string().starts_with("[SSH-E021]"));
    }
}
