//! Grant refusals, each with a stable code (ADR-0004).

use crate::ids::{GatewayGroupId, Kid};

/// Why a grant is refused. Codes are stable: never renumber or reuse one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrantError {
    /// Wrong length, magic, reserved bytes or text encoding.
    #[error("[GRT-E001] grant mal formé : {0}")]
    Malformed(&'static str),
    /// Format version not supported.
    #[error("[GRT-E002] version de grant non prise en charge : {0}")]
    UnsupportedVersion(u8),
    /// Algorithm other than Ed25519.
    #[error("[GRT-E003] algorithme de signature interdit : {0} (seul Ed25519 est accepté)")]
    AlgorithmNotAllowed(u8),
    /// Unknown protocol, unknown right, or inconsistent value.
    #[error("[GRT-E004] champ de grant invalide : {0}")]
    InvalidField(&'static str),
    /// No key with this identifier.
    #[error("[GRT-E005] clé de signature inconnue : kid {0}")]
    UnknownKid(Kid),
    /// The signature does not verify.
    #[error("[GRT-E006] signature de grant invalide")]
    BadSignature,
    /// Issued in the future, beyond the clock tolerance.
    #[error(
        "[GRT-E007] grant pas encore valide (émis à {issued_at}, heure locale {now}) ; \
         vérifiez la synchronisation de l'horloge (NTP/NTS)"
    )]
    NotYetValid {
        /// Issue time (Unix seconds).
        issued_at: u64,
        /// Local time (Unix seconds).
        now: u64,
    },
    /// Expired.
    #[error(
        "[GRT-E008] grant expiré (expiration {expires_at}, heure locale {now}) ; si cela se \
         répète pour des grants récents, vérifiez la synchronisation de l'horloge (NTP/NTS)"
    )]
    Expired {
        /// Expiry time (Unix seconds).
        expires_at: u64,
        /// Local time (Unix seconds).
        now: u64,
    },
    /// Lifetime or session length above the policy maximum.
    #[error("[GRT-E009] durée hors limites : {0}")]
    OutOfBounds(&'static str),
    /// Already used (or issued before the last replay store repair).
    #[error("[GRT-E010] grant déjà utilisé : {0}")]
    Replayed(&'static str),
    /// Meant for another gateway group.
    #[error(
        "[GRT-E011] grant destiné à un autre groupe de passerelles ({got}, attendu {expected})"
    )]
    WrongAudience {
        /// This gateway's group.
        expected: GatewayGroupId,
        /// Audience in the grant.
        got: GatewayGroupId,
    },
    /// Signed with a revoked key.
    #[error("[GRT-E012] clé de signature révoquée : kid {0}")]
    KeyRevoked(Kid),
    /// Signed with a key past its retirement date.
    #[error("[GRT-E013] clé de signature retirée : kid {0}")]
    KeyRetired(Kid),
    /// The replay store cannot answer: refuse rather than risk a replay.
    #[error("[GRT-E014] anti-rejeu indisponible, grant refusé : {0}")]
    ReplayStore(String),
}

impl GrantError {
    /// The stable code, e.g. `GRT-E005`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Malformed(_) => "GRT-E001",
            Self::UnsupportedVersion(_) => "GRT-E002",
            Self::AlgorithmNotAllowed(_) => "GRT-E003",
            Self::InvalidField(_) => "GRT-E004",
            Self::UnknownKid(_) => "GRT-E005",
            Self::BadSignature => "GRT-E006",
            Self::NotYetValid { .. } => "GRT-E007",
            Self::Expired { .. } => "GRT-E008",
            Self::OutOfBounds(_) => "GRT-E009",
            Self::Replayed(_) => "GRT-E010",
            Self::WrongAudience { .. } => "GRT-E011",
            Self::KeyRevoked(_) => "GRT-E012",
            Self::KeyRetired(_) => "GRT-E013",
            Self::ReplayStore(_) => "GRT-E014",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_starts_with_code() {
        let kid = Kid::from_bytes([0xab; 8]);
        let samples = [
            GrantError::Malformed("x"),
            GrantError::UnsupportedVersion(2),
            GrantError::AlgorithmNotAllowed(2),
            GrantError::InvalidField("x"),
            GrantError::UnknownKid(kid),
            GrantError::BadSignature,
            GrantError::NotYetValid {
                issued_at: 2,
                now: 1,
            },
            GrantError::Expired {
                expires_at: 1,
                now: 2,
            },
            GrantError::OutOfBounds("x"),
            GrantError::Replayed("x"),
            GrantError::WrongAudience {
                expected: GatewayGroupId::from_bytes([1; 16]),
                got: GatewayGroupId::from_bytes([2; 16]),
            },
            GrantError::KeyRevoked(kid),
            GrantError::KeyRetired(kid),
            GrantError::ReplayStore("x".into()),
        ];
        for (i, e) in samples.iter().enumerate() {
            let code = format!("GRT-E{:03}", i + 1);
            assert_eq!(e.code(), code);
            assert!(e.to_string().starts_with(&format!("[{code}]")), "{e}");
        }
    }
}
