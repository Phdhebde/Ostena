//! Tunnel errors, each with a stable code (ADR-0008).

use quinn::{ConnectionError, TransportErrorCode};

/// Why a tunnel failed or a message was refused. Codes are stable: never
/// renumber or reuse one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TunnelError {
    /// The peer does not offer the `SecP256r1MLKEM768` group.
    #[error("[TUN-E001] le pair ne propose pas le groupe d'échange de clés SecP256r1MLKEM768")]
    NoCommonGroup,
    /// No common cipher suite or TLS version.
    #[error("[TUN-E002] négociation TLS impossible (suite ou version) : {0}")]
    Negotiation(String),
    /// Certificate not issued by the pinned CA.
    #[error("[TUN-E003] certificat émis par une autorité inconnue")]
    UnknownIssuer,
    /// Certificate expired or not valid yet.
    #[error("[TUN-E004] certificat expiré ou pas encore valide ; vérifiez l'horloge et renouvelez")]
    CertificateValidity,
    /// Agent certificate revoked by the core.
    #[error("[TUN-E005] certificat d'agent révoqué")]
    Revoked,
    /// Agent certificate unknown to the core registry.
    #[error("[TUN-E006] certificat d'agent inconnu du core")]
    UnknownAgent,
    /// No client certificate presented.
    #[error("[TUN-E007] aucun certificat client présenté")]
    NoClientCertificate,
    /// No common application protocol.
    #[error("[TUN-E008] protocole applicatif (ALPN) non pris en charge")]
    ApplicationProtocol,
    /// The core certificate is valid for another name.
    #[error("[TUN-E009] le certificat du core ne correspond pas au nom attendu")]
    NameMismatch,
    /// A message or stream header broke the protocol.
    #[error("[TUN-E010] violation du protocole du tunnel : {0}")]
    Protocol(String),
    /// Protocol version not supported.
    #[error("[TUN-E011] version du protocole du tunnel non prise en charge : {0}")]
    Version(u16),
    /// No answer to the heartbeat in time.
    #[error("[TUN-E012] le pair ne répond plus au heartbeat")]
    HeartbeatTimeout,
    /// The connection was lost or closed.
    #[error("[TUN-E013] connexion au pair perdue : {0}")]
    ConnectionLost(String),
    /// Local endpoint or I/O failure.
    #[error("[TUN-E014] erreur locale du tunnel : {0}")]
    Io(String),
    /// Invalid configuration (limits, TLS).
    #[error("[TUN-E015] configuration du tunnel invalide : {0}")]
    Config(String),
    /// Any other handshake failure.
    #[error("[TUN-E016] échec de la poignée de main TLS : {0}")]
    Handshake(String),
}

impl TunnelError {
    /// The stable code, e.g. `TUN-E005`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoCommonGroup => "TUN-E001",
            Self::Negotiation(_) => "TUN-E002",
            Self::UnknownIssuer => "TUN-E003",
            Self::CertificateValidity => "TUN-E004",
            Self::Revoked => "TUN-E005",
            Self::UnknownAgent => "TUN-E006",
            Self::NoClientCertificate => "TUN-E007",
            Self::ApplicationProtocol => "TUN-E008",
            Self::NameMismatch => "TUN-E009",
            Self::Protocol(_) => "TUN-E010",
            Self::Version(_) => "TUN-E011",
            Self::HeartbeatTimeout => "TUN-E012",
            Self::ConnectionLost(_) => "TUN-E013",
            Self::Io(_) => "TUN-E014",
            Self::Config(_) => "TUN-E015",
            Self::Handshake(_) => "TUN-E016",
        }
    }
}

// TLS alerts (RFC 8446 section 6), carried in QUIC as CRYPTO_ERROR 0x100 + alert.
const ALERT_HANDSHAKE_FAILURE: u8 = 40;
const ALERT_BAD_CERTIFICATE: u8 = 42;
const ALERT_CERTIFICATE_REVOKED: u8 = 44;
const ALERT_CERTIFICATE_EXPIRED: u8 = 45;
const ALERT_UNKNOWN_CA: u8 = 48;
const ALERT_ACCESS_DENIED: u8 = 49;
const ALERT_DECRYPT_ERROR: u8 = 51;
const ALERT_PROTOCOL_VERSION: u8 = 70;
const ALERT_CERTIFICATE_REQUIRED: u8 = 116;
const ALERT_NO_APPLICATION_PROTOCOL: u8 = 120;

/// The TLS alert inside a QUIC `CRYPTO_ERROR` code, if any.
fn crypto_alert(code: TransportErrorCode) -> Option<u8> {
    let raw = u64::from(code);
    (0x100..0x200)
        .contains(&raw)
        .then(|| u8::try_from(raw - 0x100).ok())
        .flatten()
}

/// Maps a TLS failure: the alert, refined by the local rustls message when
/// this side detected it.
fn from_alert(alert: u8, reason: &str) -> TunnelError {
    match alert {
        ALERT_HANDSHAKE_FAILURE if reason.contains("NoKxGroupsInCommon") => {
            TunnelError::NoCommonGroup
        }
        ALERT_HANDSHAKE_FAILURE | ALERT_PROTOCOL_VERSION => {
            TunnelError::Negotiation(reason.to_owned())
        }
        // decrypt_error: a certificate whose issuer has the name of the pinned
        // CA but not its key, or a handshake signed with another key. Either
        // way the peer is not vouched for by the pinned CA.
        ALERT_UNKNOWN_CA | ALERT_DECRYPT_ERROR => TunnelError::UnknownIssuer,
        ALERT_CERTIFICATE_EXPIRED => TunnelError::CertificateValidity,
        ALERT_CERTIFICATE_REVOKED => TunnelError::Revoked,
        ALERT_ACCESS_DENIED => TunnelError::UnknownAgent,
        ALERT_CERTIFICATE_REQUIRED => TunnelError::NoClientCertificate,
        ALERT_NO_APPLICATION_PROTOCOL => TunnelError::ApplicationProtocol,
        ALERT_BAD_CERTIFICATE if reason.contains("not valid for name") => TunnelError::NameMismatch,
        ALERT_BAD_CERTIFICATE if reason.contains("not valid yet") => {
            TunnelError::CertificateValidity
        }
        _ => TunnelError::Handshake(format!("alerte TLS {alert} {reason}")),
    }
}

impl From<ConnectionError> for TunnelError {
    fn from(error: ConnectionError) -> Self {
        match &error {
            ConnectionError::TransportError(e) => match crypto_alert(e.code) {
                Some(alert) => from_alert(alert, &e.reason),
                None => Self::ConnectionLost(error.to_string()),
            },
            ConnectionError::ConnectionClosed(frame) => match crypto_alert(frame.error_code) {
                Some(alert) => from_alert(alert, &String::from_utf8_lossy(&frame.reason)),
                None => Self::ConnectionLost(error.to_string()),
            },
            ConnectionError::ApplicationClosed(frame) => {
                Self::ConnectionLost(String::from_utf8_lossy(&frame.reason).into_owned())
            }
            ConnectionError::VersionMismatch => Self::Negotiation(error.to_string()),
            _ => Self::ConnectionLost(error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_starts_with_code() {
        let samples = [
            TunnelError::NoCommonGroup,
            TunnelError::Negotiation("x".into()),
            TunnelError::UnknownIssuer,
            TunnelError::CertificateValidity,
            TunnelError::Revoked,
            TunnelError::UnknownAgent,
            TunnelError::NoClientCertificate,
            TunnelError::ApplicationProtocol,
            TunnelError::NameMismatch,
            TunnelError::Protocol("x".into()),
            TunnelError::Version(2),
            TunnelError::HeartbeatTimeout,
            TunnelError::ConnectionLost("x".into()),
            TunnelError::Io("x".into()),
            TunnelError::Config("x".into()),
            TunnelError::Handshake("x".into()),
        ];
        for (i, e) in samples.iter().enumerate() {
            let code = format!("TUN-E{:03}", i + 1);
            assert_eq!(e.code(), code);
            assert!(e.to_string().starts_with(&format!("[{code}]")), "{e}");
        }
    }

    #[test]
    fn crypto_alerts_are_mapped() {
        let code = |alert: u8| TransportErrorCode::crypto(alert);
        assert_eq!(crypto_alert(code(48)), Some(48));
        assert_eq!(crypto_alert(TransportErrorCode::PROTOCOL_VIOLATION), None);
        assert_eq!(
            from_alert(
                ALERT_HANDSHAKE_FAILURE,
                "peer is incompatible: NoKxGroupsInCommon"
            ),
            TunnelError::NoCommonGroup
        );
        assert!(matches!(
            from_alert(ALERT_HANDSHAKE_FAILURE, ""),
            TunnelError::Negotiation(_)
        ));
        assert_eq!(
            from_alert(ALERT_CERTIFICATE_REVOKED, ""),
            TunnelError::Revoked
        );
    }
}
