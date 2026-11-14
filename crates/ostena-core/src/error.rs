//! Core errors, each with a stable code (ADR-0011).

/// Why the core cannot start or an operation failed. Codes are stable: never
/// renumber or reuse one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CoreError {
    /// The database cannot be reached or a query failed.
    #[error("[CORE-E001] base PostgreSQL injoignable ou requête en échec : {0}")]
    Database(String),
    /// The server is older than PostgreSQL 16.
    #[error("[CORE-E002] PostgreSQL {0} trop ancien : version 16 ou ultérieure requise")]
    ServerVersion(i32),
    /// In production, the server did not authenticate the core by `peer`.
    #[error(
        "[CORE-E003] PostgreSQL a authentifié le core par « {0} » : seule l'authentification \
         peer sur le socket Unix est acceptée en production (pg_hba.conf : local … peer)"
    )]
    NotPeer(String),
    /// Applying the embedded migrations failed.
    #[error("[CORE-E004] migration du schéma en échec : {0}")]
    Migration(String),
    /// The schema is not the one this binary expects.
    #[error("[CORE-E005] schéma de la base différent de celui du binaire : {0}")]
    Schema(String),
    /// A key or certificate of the core cannot be loaded.
    #[error("[CORE-E006] clé ou certificat du core inutilisable : {0}")]
    Keys(String),
    /// A listener or the runtime cannot start.
    #[error("[CORE-E007] démarrage du core impossible : {0}")]
    Startup(String),
    /// Variables of the environment that would reach the database server.
    #[error(
        "[CORE-E008] variable(s) d'environnement {0} définie(s) : elles atteindraient le serveur \
         PostgreSQL sans passer par la configuration ; retirez-les de l'environnement du service"
    )]
    Environment(String),
    /// An agent, a group or a token is unknown.
    #[error("[CORE-E009] {0} inconnu")]
    NotFound(String),
}

impl CoreError {
    /// The stable code, e.g. `CORE-E003`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Database(_) => "CORE-E001",
            Self::ServerVersion(_) => "CORE-E002",
            Self::NotPeer(_) => "CORE-E003",
            Self::Migration(_) => "CORE-E004",
            Self::Schema(_) => "CORE-E005",
            Self::Keys(_) => "CORE-E006",
            Self::Startup(_) => "CORE-E007",
            Self::Environment(_) => "CORE-E008",
            Self::NotFound(_) => "CORE-E009",
        }
    }
}

impl From<sqlx::Error> for CoreError {
    fn from(e: sqlx::Error) -> Self {
        Self::Database(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_starts_with_code() {
        let samples = [
            CoreError::Database("x".into()),
            CoreError::ServerVersion(150_000),
            CoreError::NotPeer("scram-sha-256".into()),
            CoreError::Migration("x".into()),
            CoreError::Schema("x".into()),
            CoreError::Keys("x".into()),
            CoreError::Startup("x".into()),
            CoreError::Environment("PGOPTIONS".into()),
            CoreError::NotFound("agent".into()),
        ];
        for (i, e) in samples.iter().enumerate() {
            let code = format!("CORE-E{:03}", i + 1);
            assert_eq!(e.code(), code);
            assert!(e.to_string().starts_with(&format!("[{code}]")), "{e}");
        }
    }
}
