//! Embedded migrations (ADR-0011): applied by `ostena core run` under the
//! advisory lock of sqlx, checked by `ostena core migrate --check` and by the
//! administration commands, which never change the schema.

use sqlx::PgPool;
use sqlx::migrate::Migrator;

use crate::error::CoreError;

/// The migrations of this binary.
pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Where the schema of the database stands against this binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaState {
    /// Every migration of this binary is applied, and nothing else.
    UpToDate,
    /// Migrations of this binary are not applied yet.
    Pending(Vec<i64>),
}

/// Applies the pending migrations; several cores starting together wait on
/// the same advisory lock. Returns the versions that were pending (empty if
/// none), for the `core.migrated` audit record.
///
/// # Errors
///
/// [`CoreError::Migration`], or [`CoreError::Schema`] if the database holds
/// a migration this binary does not know (a newer binary migrated it).
pub async fn migrate(pool: &PgPool) -> Result<Vec<i64>, CoreError> {
    let before = state(pool).await?;
    MIGRATOR
        .run(pool)
        .await
        .map_err(|e| CoreError::Migration(e.to_string()))?;
    match before {
        SchemaState::Pending(versions) => {
            tracing::info!(event = "core.migrated", versions = ?versions, "schéma mis à jour");
            Ok(versions)
        }
        SchemaState::UpToDate => Ok(Vec::new()),
    }
}

/// Compares the applied migrations with those of this binary.
///
/// # Errors
///
/// [`CoreError::Schema`] for a migration unknown to this binary, a changed
/// checksum or a failed migration; [`CoreError::Database`] otherwise.
pub async fn state(pool: &PgPool) -> Result<SchemaState, CoreError> {
    let exists: bool = sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations') IS NOT NULL")
        .fetch_one(pool)
        .await?;
    let applied: Vec<(i64, Vec<u8>, bool)> = if exists {
        // sqlx's own table: its shape is fixed by sqlx, not by our migrations.
        sqlx::query_as("SELECT version, checksum, success FROM _sqlx_migrations ORDER BY version")
            .fetch_all(pool)
            .await?
    } else {
        Vec::new()
    };
    compare(
        &applied,
        MIGRATOR.iter().map(|m| (m.version, m.checksum.as_ref())),
    )
}

/// The comparison itself, on (version, checksum, success) rows.
fn compare<'a>(
    applied: &[(i64, Vec<u8>, bool)],
    embedded: impl Iterator<Item = (i64, &'a [u8])>,
) -> Result<SchemaState, CoreError> {
    let embedded: Vec<(i64, &[u8])> = embedded.collect();
    for (version, checksum, success) in applied {
        if !success {
            return Err(CoreError::Schema(format!(
                "la migration {version} a échoué ; corrigez la base avant de redémarrer"
            )));
        }
        match embedded.iter().find(|(v, _)| v == version) {
            None => {
                return Err(CoreError::Schema(format!(
                    "migration {version} inconnue de ce binaire (base migrée par une version plus récente)"
                )));
            }
            Some((_, expected)) if *expected != checksum.as_slice() => {
                return Err(CoreError::Schema(format!(
                    "migration {version} modifiée depuis son application"
                )));
            }
            Some(_) => {}
        }
    }
    let pending: Vec<i64> = embedded
        .iter()
        .map(|(v, _)| *v)
        .filter(|v| !applied.iter().any(|(a, _, _)| a == v))
        .collect();
    Ok(if pending.is_empty() {
        SchemaState::UpToDate
    } else {
        SchemaState::Pending(pending)
    })
}

/// Refuses a schema that is not exactly the one of this binary (the
/// administration commands run against a migrated database).
///
/// # Errors
///
/// [`CoreError::Schema`].
pub async fn require_up_to_date(pool: &PgPool) -> Result<(), CoreError> {
    match state(pool).await? {
        SchemaState::UpToDate => Ok(()),
        SchemaState::Pending(versions) => Err(CoreError::Schema(format!(
            "migrations {versions:?} non appliquées ; démarrez le core (ostena core run) ou lancez \
             ostena core migrate"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &[u8] = b"a";
    const B: &[u8] = b"b";

    #[test]
    fn fresh_database_has_every_migration_pending() {
        let state = compare(&[], [(1, A), (2, B)].into_iter()).unwrap();
        assert_eq!(state, SchemaState::Pending(vec![1, 2]));
    }

    #[test]
    fn applied_migrations_are_up_to_date() {
        let applied = [(1, A.to_vec(), true), (2, B.to_vec(), true)];
        let state = compare(&applied, [(1, A), (2, B)].into_iter()).unwrap();
        assert_eq!(state, SchemaState::UpToDate);
    }

    #[test]
    fn unknown_changed_or_failed_migrations_are_refused() {
        let newer = [(1, A.to_vec(), true), (3, B.to_vec(), true)];
        let changed = [(1, B.to_vec(), true)];
        let failed = [(1, A.to_vec(), false)];
        for applied in [&newer[..], &changed[..], &failed[..]] {
            let e = compare(applied, [(1, A), (2, B)].into_iter()).unwrap_err();
            assert_eq!(e.code(), "CORE-E005");
        }
    }

    #[test]
    fn embedded_migrations_are_numbered_from_one() {
        let versions: Vec<i64> = MIGRATOR.iter().map(|m| m.version).collect();
        assert_eq!(versions[0], 1);
        assert!(
            versions.windows(2).all(|w| w[1] == w[0] + 1),
            "{versions:?}"
        );
    }
}
