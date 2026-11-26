//! Embedded migrations (ADR-0011): applied by `ostena core migrate` under
//! the advisory lock of sqlx, as the owner of the schema; checked by `ostena
//! core migrate --check`, by `ostena core run` and by the administration
//! commands, which never change the schema.
//!
//! From migration 6 on, each migration is reversible: a `.down.sql` file
//! takes the schema back to the previous version without touching the rows
//! that version knows (`ostena core migrate --revert-to`). Migrations 1 to 5
//! (M1) have none.

use sqlx::PgPool;
use sqlx::migrate::{Migration, Migrator};

use crate::db::OWNER_ROLE;
use crate::error::CoreError;

/// The migrations of this binary, up and down.
pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// The migrations that move the schema forward (no `.down.sql`).
fn forward() -> impl Iterator<Item = &'static Migration> {
    MIGRATOR
        .iter()
        .filter(|m| !m.migration_type.is_down_migration())
}

/// The latest schema version of this binary.
pub fn latest_version() -> i64 {
    forward().map(|m| m.version).max().unwrap_or(0)
}

/// The lowest version `ostena core migrate --revert-to` accepts: every
/// migration above it has a down migration.
pub fn revert_floor() -> i64 {
    forward()
        .filter(|m| !has_down(m.version))
        .map(|m| m.version)
        .max()
        .unwrap_or(0)
}

fn has_down(version: i64) -> bool {
    MIGRATOR
        .iter()
        .any(|m| m.version == version && m.migration_type.is_down_migration())
}

/// Refuses a session that is not the owner of the schema: objects created
/// under another role would escape the separation of the roles.
async fn require_owner(pool: &PgPool) -> Result<(), CoreError> {
    let current: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(pool)
        .await?;
    if current == OWNER_ROLE {
        Ok(())
    } else {
        Err(CoreError::Roles(format!(
            "migrations sous le rôle {current} : seul {OWNER_ROLE} modifie le schéma"
        )))
    }
}

/// Where the schema of the database stands against this binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaState {
    /// Every migration of this binary is applied, and nothing else.
    UpToDate,
    /// Migrations of this binary are not applied yet.
    Pending(Vec<i64>),
}

/// Applies the pending migrations, as [`OWNER_ROLE`] (a pool of
/// [`crate::db::Role::Owner`]); two runs together wait on the same advisory
/// lock. Returns the versions that were pending (empty if none), for the
/// `core.migrated` audit record.
///
/// # Errors
///
/// [`CoreError::Migration`], [`CoreError::Roles`] for another role, or
/// [`CoreError::Schema`] if the database holds a migration this binary does
/// not know (a newer binary migrated it).
pub async fn migrate(pool: &PgPool) -> Result<Vec<i64>, CoreError> {
    require_owner(pool).await?;
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

/// Reverts the applied migrations above `target`, newest first, with their
/// down migrations, as [`OWNER_ROLE`]. Returns the reverted versions (empty
/// if none), for the `core.migration_reverted` audit record.
///
/// # Errors
///
/// [`CoreError::Migration`] for a target below [`revert_floor`] or a failed
/// down migration, [`CoreError::Roles`], [`CoreError::Schema`] as
/// [`migrate`].
pub async fn revert(pool: &PgPool, target: i64) -> Result<Vec<i64>, CoreError> {
    require_owner(pool).await?;
    let floor = revert_floor();
    if target < floor {
        return Err(CoreError::Migration(format!(
            "retour à la version {target} impossible : les migrations 1 à {floor} n'ont pas de \
             migration inverse"
        )));
    }
    // A failed or unknown migration is refused before anything is undone.
    let _ = state(pool).await?;
    let applied: Vec<i64> = sqlx::query_scalar(
        "SELECT version FROM _sqlx_migrations WHERE version > $1 ORDER BY version DESC",
    )
    .bind(target)
    .fetch_all(pool)
    .await?;
    MIGRATOR
        .undo(pool, target)
        .await
        .map_err(|e| CoreError::Migration(e.to_string()))?;
    if !applied.is_empty() {
        tracing::info!(
            event = "core.migration_reverted",
            versions = ?applied,
            schema_version = target,
            "schéma ramené à une version antérieure"
        );
    }
    Ok(applied)
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
            .await
            .map_err(|e| {
                // ostena_app reads it from migration 6 on: an M1 database
                // not migrated yet.
                if e.as_database_error()
                    .and_then(sqlx::error::DatabaseError::code)
                    .is_some_and(|c| c == "42501")
                {
                    CoreError::Schema(
                        "état des migrations illisible pour ce rôle : base antérieure à la \
                         séparation des rôles ; lancez ostena core migrate"
                            .into(),
                    )
                } else {
                    CoreError::Database(e.to_string())
                }
            })?
    } else {
        Vec::new()
    };
    compare(
        &applied,
        forward().map(|m| (m.version, m.checksum.as_ref())),
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
            "migrations {versions:?} non appliquées ; lancez ostena core migrate sous le compte \
             d'administration"
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
    fn migrations_from_six_on_are_reversible() {
        assert_eq!(revert_floor(), 5);
        assert!(latest_version() >= 6);
        for version in 6..=latest_version() {
            assert!(has_down(version), "migration {version} sans .down.sql");
        }
    }

    #[test]
    fn embedded_migrations_are_numbered_from_one() {
        let versions: Vec<i64> = forward().map(|m| m.version).collect();
        assert_eq!(versions[0], 1);
        assert!(
            versions.windows(2).all(|w| w[1] == w[0] + 1),
            "{versions:?}"
        );
    }
}
