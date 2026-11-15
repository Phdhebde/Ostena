//! Errors of the audit formats and of head verification, each with a stable
//! code (ADR-0012). The chain-level findings of the verifier (`AUD-E005` to
//! `AUD-E014`, `AUD-W001` to `AUD-W004`) are in [`crate::verify::Finding`].

use ostena_crypto::CryptoError;

use crate::head::MAX_TRUSTED_KEYS;
use crate::ids::Kid;

/// Why a record, a head or an export is refused. Codes are stable: never
/// renumber or reuse one. `AUD-E010` is reserved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuditError {
    /// A record does not follow the canonical v1 encoding.
    #[error("[AUD-E001] enregistrement d'audit mal formé : {0}")]
    MalformedRecord(&'static str),
    /// Unknown record or head version, or a head algorithm other than ECDSA
    /// P-256 / SHA-256 (value 2).
    #[error("[AUD-E002] {what} non pris en charge : {value}")]
    Unsupported {
        /// What carries the value.
        what: &'static str,
        /// The value found.
        value: u8,
    },
    /// A head does not follow the v1 encoding (length, fields, text form).
    #[error("[AUD-E003] tête de chaîne mal formée : {0}")]
    MalformedHead(&'static str),
    /// The export container is malformed or truncated.
    #[error("[AUD-E004] export d'audit mal formé ou tronqué : {0}")]
    MalformedExport(String),
    /// The export cannot be read or written (input/output error).
    #[error("[AUD-E004] export d'audit illisible : {0}")]
    Io(String),
    /// The head signature does not verify.
    #[error("[AUD-E008] signature de la tête n° {head_no} invalide")]
    BadSignature {
        /// Number of the head.
        head_no: u64,
    },
    /// The head is signed with a key that is not trusted.
    #[error("[AUD-E009] tête n° {head_no} signée par une clé inconnue : kid {kid}")]
    UnknownKid {
        /// Number of the head.
        head_no: u64,
        /// Identifier of the signing key.
        kid: Kid,
    },
    /// Signing a head or drawing a chain identifier failed.
    #[error("[AUD-E015] échec cryptographique : {0}")]
    Crypto(CryptoError),
    /// More trusted keys than the verifier accepts.
    #[error("[AUD-E016] trop de clés de confiance : au plus {MAX_TRUSTED_KEYS}")]
    TooManyKeys,
}

impl AuditError {
    /// The stable code, e.g. `AUD-E001`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MalformedRecord(_) => "AUD-E001",
            Self::Unsupported { .. } => "AUD-E002",
            Self::MalformedHead(_) => "AUD-E003",
            Self::MalformedExport(_) | Self::Io(_) => "AUD-E004",
            Self::BadSignature { .. } => "AUD-E008",
            Self::UnknownKid { .. } => "AUD-E009",
            Self::Crypto(_) => "AUD-E015",
            Self::TooManyKeys => "AUD-E016",
        }
    }

    pub(crate) fn io(e: &std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            Self::MalformedExport("fin de fichier inattendue".into())
        } else {
            Self::Io(e.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_starts_with_code() {
        let samples = [
            AuditError::MalformedRecord("x"),
            AuditError::Unsupported {
                what: "version",
                value: 2,
            },
            AuditError::MalformedHead("x"),
            AuditError::MalformedExport("x".into()),
            AuditError::Io("x".into()),
            AuditError::BadSignature { head_no: 1 },
            AuditError::UnknownKid {
                head_no: 1,
                kid: Kid::from_bytes([0xab; 8]),
            },
            AuditError::Crypto(CryptoError::Signing),
            AuditError::TooManyKeys,
        ];
        let codes = [
            "AUD-E001", "AUD-E002", "AUD-E003", "AUD-E004", "AUD-E004", "AUD-E008", "AUD-E009",
            "AUD-E015", "AUD-E016",
        ];
        for (e, code) in samples.iter().zip(codes) {
            assert_eq!(e.code(), code);
            assert!(e.to_string().starts_with(&format!("[{code}]")), "{e}");
        }
    }

    #[test]
    fn unexpected_end_of_file_is_a_truncation() {
        let eof = std::io::Error::from(std::io::ErrorKind::UnexpectedEof);
        assert_eq!(AuditError::io(&eof).code(), "AUD-E004");
        assert!(matches!(
            AuditError::io(&eof),
            AuditError::MalformedExport(_)
        ));
        let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert!(matches!(AuditError::io(&denied), AuditError::Io(_)));
    }
}
