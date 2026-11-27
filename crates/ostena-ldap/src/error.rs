//! LDAP errors, each with a stable code (ADR-0021).

/// Why an LDAP exchange failed. Codes are stable: never renumber or reuse
/// one. No variant carries a password or a filter value typed by a user.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LdapError {
    /// The bytes received are not a valid message of the supported subset.
    #[error("[LDAP-E001] message LDAP mal formé : {0}")]
    Malformed(&'static str),
    /// A message is longer than the configured limit.
    #[error("[LDAP-E002] message LDAP de {0} octets, au-delà de la limite")]
    TooLong(usize),
    /// The connection failed or was closed.
    #[error("[LDAP-E003] connexion à l'annuaire interrompue : {0}")]
    Io(String),
    /// The server answered with another message identifier or operation.
    #[error("[LDAP-E004] réponse inattendue de l'annuaire : {0}")]
    Unexpected(&'static str),
    /// The server refused the operation.
    #[error("[LDAP-E005] l'annuaire a refusé l'opération : code {code} ({})", result_name(*.code))]
    Refused {
        /// The LDAP result code (RFC 4511, § 4.1.9).
        code: u32,
        /// The diagnostic message of the server, truncated, without control
        /// characters. Active Directory puts its sub-code there
        /// (`data 52e`, `data 533`…).
        diagnostic: String,
    },
    /// The server announced that it closes the connection (notice of
    /// disconnection, RFC 4511 § 4.4.1).
    #[error("[LDAP-E006] l'annuaire a annoncé la fermeture de la connexion")]
    Disconnected,
    /// A search returned more entries than the limit of the caller.
    #[error("[LDAP-E007] recherche de plus de {0} entrées : limite atteinte")]
    TooManyEntries(usize),
    /// A simple bind with an empty name or password: an unauthenticated bind
    /// (RFC 4513 § 5.1.2), always refused before it is sent.
    #[error("[LDAP-E008] liaison simple sans nom ou sans mot de passe refusée")]
    EmptyCredentials,
    /// A search filter in text form (RFC 4515) cannot be read.
    #[error("[LDAP-E009] filtre de recherche invalide : {0}")]
    Filter(&'static str),
}

impl LdapError {
    /// The stable code, e.g. `LDAP-E005`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Malformed(_) => "LDAP-E001",
            Self::TooLong(_) => "LDAP-E002",
            Self::Io(_) => "LDAP-E003",
            Self::Unexpected(_) => "LDAP-E004",
            Self::Refused { .. } => "LDAP-E005",
            Self::Disconnected => "LDAP-E006",
            Self::TooManyEntries(_) => "LDAP-E007",
            Self::EmptyCredentials => "LDAP-E008",
            Self::Filter(_) => "LDAP-E009",
        }
    }

    /// Whether the server refused a bind for its credentials
    /// (`invalidCredentials`, 49).
    pub fn is_invalid_credentials(&self) -> bool {
        matches!(self, Self::Refused { code: 49, .. })
    }

    /// Whether the error comes from the transport or the server state rather
    /// than from the request: another server of the source may answer.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::Io(_)
                | Self::Disconnected
                | Self::Refused {
                    code: 51..=53 | 80,
                    ..
                }
        )
    }
}

impl From<std::io::Error> for LdapError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.kind().to_string())
    }
}

/// The name of the result codes the client meets (RFC 4511, appendix A).
pub fn result_name(code: u32) -> &'static str {
    match code {
        0 => "success",
        1 => "operationsError",
        2 => "protocolError",
        3 => "timeLimitExceeded",
        4 => "sizeLimitExceeded",
        10 => "referral",
        11 => "adminLimitExceeded",
        12 => "unavailableCriticalExtension",
        13 => "confidentialityRequired",
        32 => "noSuchObject",
        34 => "invalidDNSyntax",
        48 => "inappropriateAuthentication",
        49 => "invalidCredentials",
        50 => "insufficientAccessRights",
        51 => "busy",
        52 => "unavailable",
        53 => "unwillingToPerform",
        80 => "other",
        _ => "autre code",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_starts_with_code() {
        let samples = [
            LdapError::Malformed("x"),
            LdapError::TooLong(1),
            LdapError::Io("x".into()),
            LdapError::Unexpected("x"),
            LdapError::Refused {
                code: 49,
                diagnostic: String::new(),
            },
            LdapError::Disconnected,
            LdapError::TooManyEntries(1),
            LdapError::EmptyCredentials,
            LdapError::Filter("x"),
        ];
        for (i, e) in samples.iter().enumerate() {
            let code = format!("LDAP-E{:03}", i + 1);
            assert_eq!(e.code(), code);
            assert!(e.to_string().starts_with(&format!("[{code}]")), "{e}");
        }
    }

    #[test]
    fn classes() {
        let refused = |code| LdapError::Refused {
            code,
            diagnostic: String::new(),
        };
        assert!(refused(49).is_invalid_credentials());
        assert!(!refused(50).is_invalid_credentials());
        assert!(refused(52).is_transient());
        assert!(!refused(49).is_transient());
        assert!(LdapError::Io("reset".into()).is_transient());
    }
}
