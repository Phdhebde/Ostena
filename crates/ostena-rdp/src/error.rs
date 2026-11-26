//! Errors of the RDP driver, each with a stable code (ADR-0019).

/// Why a connection to an RDP target failed or a session ended in error.
/// Codes are stable: never renumber or reuse one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RdpError {
    /// The target certificate is not the pinned one, or not valid for the
    /// PKI: refused before any credential.
    #[error("[RDP-E001] certificat de la cible refusé ({0}) : aucun identifiant envoyé")]
    Certificate(&'static str),
    /// The target cannot be reached (TCP), or closed the connection.
    #[error("[RDP-E002] cible injoignable ou connexion fermée : {0}")]
    Unreachable(String),
    /// The target does not offer network level authentication (CredSSP).
    #[error("[RDP-E003] la cible ne propose pas l'authentification réseau (NLA) : refusé")]
    NoNla,
    /// TLS handshake failed (no common version, suite, group or signature
    /// with the target profile).
    #[error("[RDP-E004] négociation TLS impossible avec la cible : {0}")]
    Tls(String),
    /// CredSSP failed: the target refused the account or the exchange.
    #[error("[RDP-E005] authentification CredSSP refusée par la cible : {0}")]
    Authentication(String),
    /// Kerberos failed: no KDC configured for the realm, KDC unreachable,
    /// refusal, or no common encryption type (AES only).
    #[error("[RDP-E006] Kerberos impossible : {0}")]
    Kerberos(String),
    /// The target speaks a CredSSP version older than 6 (CVE-2018-0886).
    #[error("[RDP-E007] version CredSSP {0} de la cible : la version 6 est exigée")]
    CredSspVersion(u32),
    /// Restricted Admin required but not announced by the target.
    #[error("[RDP-E008] la cible n'accepte pas le mode Restricted Admin : refusé, sans repli")]
    RestrictedAdminUnsupported,
    /// The target refused the user after CredSSP (early user authorization).
    #[error("[RDP-E009] accès refusé par la cible après l'authentification")]
    AccessDenied,
    /// RDS licensing failed.
    #[error("[RDP-E010] licence RDS refusée : {0}")]
    License(String),
    /// NTLM would be used where it is not admitted (password delegated, or
    /// `ntlm_fallback` off).
    #[error("[RDP-E011] repli NTLM refusé : {0}")]
    NtlmRefused(&'static str),
    /// The target broke the sequence (unexpected or malformed PDU).
    #[error("[RDP-E012] séquence RDP invalide : {0}")]
    Protocol(String),
    /// The target asked to redirect the connection elsewhere.
    #[error("[RDP-E013] redirection demandée par la cible : refusée")]
    Redirected,
    /// The target ended the session with an error code.
    #[error("[RDP-E014] session terminée par la cible (code 0x{0:08x})")]
    ServerError(u32),
    /// The connection sequence took longer than its delay.
    #[error("[RDP-E015] délai d'établissement de la session dépassé")]
    Timeout,
    /// The secret of the account cannot be read on the agent.
    #[error("[RDP-E016] secret du compte indisponible sur l'agent : {0}")]
    Secret(String),
    /// The session parameters sent by the core are invalid.
    #[error("[RDP-E017] paramètres de session invalides : {0}")]
    Params(String),
    /// A dependency panicked; the session is cut, the agent goes on.
    #[error("[RDP-E099] erreur interne du driver RDP : session coupée")]
    Internal,
}

impl RdpError {
    /// The stable code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Certificate(_) => "RDP-E001",
            Self::Unreachable(_) => "RDP-E002",
            Self::NoNla => "RDP-E003",
            Self::Tls(_) => "RDP-E004",
            Self::Authentication(_) => "RDP-E005",
            Self::Kerberos(_) => "RDP-E006",
            Self::CredSspVersion(_) => "RDP-E007",
            Self::RestrictedAdminUnsupported => "RDP-E008",
            Self::AccessDenied => "RDP-E009",
            Self::License(_) => "RDP-E010",
            Self::NtlmRefused(_) => "RDP-E011",
            Self::Protocol(_) => "RDP-E012",
            Self::Redirected => "RDP-E013",
            Self::ServerError(_) => "RDP-E014",
            Self::Timeout => "RDP-E015",
            Self::Secret(_) => "RDP-E016",
            Self::Params(_) => "RDP-E017",
            Self::Internal => "RDP-E099",
        }
    }

    /// The event emitted for this error.
    pub fn event(&self) -> &'static str {
        match self {
            Self::Certificate(_) => "rdp.certificate_mismatch",
            Self::Unreachable(_) | Self::Timeout => "rdp.target_unreachable",
            Self::NoNla
            | Self::Tls(_)
            | Self::CredSspVersion(_)
            | Self::RestrictedAdminUnsupported
            | Self::Protocol(_)
            | Self::Redirected => "rdp.target_refused",
            Self::Authentication(_)
            | Self::Kerberos(_)
            | Self::AccessDenied
            | Self::NtlmRefused(_)
            | Self::Secret(_) => "rdp.target_auth_failed",
            Self::License(_) => "rdp.license_failed",
            Self::ServerError(_) => "rdp.session_error",
            Self::Params(_) => "rdp.params_refused",
            Self::Internal => "rdp.internal_error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_in_the_messages_and_unique() {
        let all = [
            RdpError::Certificate("x"),
            RdpError::Unreachable("x".into()),
            RdpError::NoNla,
            RdpError::Tls("x".into()),
            RdpError::Authentication("x".into()),
            RdpError::Kerberos("x".into()),
            RdpError::CredSspVersion(5),
            RdpError::RestrictedAdminUnsupported,
            RdpError::AccessDenied,
            RdpError::License("x".into()),
            RdpError::NtlmRefused("x"),
            RdpError::Protocol("x".into()),
            RdpError::Redirected,
            RdpError::ServerError(1),
            RdpError::Timeout,
            RdpError::Secret("x".into()),
            RdpError::Params("x".into()),
            RdpError::Internal,
        ];
        let mut codes = std::collections::HashSet::new();
        for e in &all {
            assert!(e.to_string().starts_with(&format!("[{}]", e.code())));
            assert!(e.event().starts_with("rdp."));
            assert!(codes.insert(e.code()));
        }
    }
}
