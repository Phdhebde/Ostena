//! The roles of the core database (ADR-0011, separate roles).
//!
//! - [`OWNER_ROLE`] (`NOLOGIN`) owns the database and every object of the
//!   schema: only `ostena core migrate` takes it.
//! - [`APP_ROLE`] (`NOLOGIN`) gets from the migrations the DML each table
//!   needs, and only `SELECT` and `INSERT` on the audit chain.
//! - The login roles (`core.database.user` for the service,
//!   `core.database.migration_user` for the migrations) are members of one
//!   group role each, with `SET` but without `INHERIT`: they can do nothing
//!   until they take it, which [`crate::db::connect`] does.
//!
//! `ostena core db init` creates all of them as a role allowed to (the
//! `postgres` superuser in production), creates the database owned by
//! [`OWNER_ROLE`], and hands over to it what an M1 installation left owned
//! by the service account. Every step is idempotent.

use ostena_common::config::{APP_ROLE, Mode, OWNER_ROLE};
use sqlx::PgPool;

use crate::error::CoreError;

/// Advisory lock taken while the roles are created: several test databases
/// (or two operators) may set them up together, and concurrent `CREATE
/// ROLE` or `GRANT` on the same role fail.
const ROLES_LOCK_KEY: i64 = 0x6f73_7465_6e61_524f;

/// The two login roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Logins<'a> {
    /// `core.database.user`: the service and the administration commands.
    pub service: &'a str,
    /// `core.database.migration_user`: `ostena core migrate`.
    pub migration: &'a str,
}

/// What a setup step changed, for the operator.
pub type Changes = Vec<String>;

/// `"name"`: the identifiers come from the validated configuration
/// (lowercase, digits, `_`), quoted anyway.
fn quote(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

async fn exec(conn: &mut sqlx::PgConnection, sql: String) -> Result<(), CoreError> {
    sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(|e| CoreError::Roles(e.to_string()))
}

async fn role_exists(conn: &mut sqlx::PgConnection, name: &str) -> Result<Option<bool>, CoreError> {
    sqlx::query_scalar::<_, bool>("SELECT rolcanlogin FROM pg_roles WHERE rolname = $1")
        .bind(name)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| CoreError::Roles(e.to_string()))
}

/// Creates the group roles and the login roles that are missing, and makes
/// each login role a member of its group role (`SET TRUE`, `INHERIT
/// FALSE`). Run on any database of the cluster, as a role allowed to create
/// roles.
///
/// # Errors
///
/// [`CoreError::Roles`]: a group role that can log in, or a refused
/// statement.
pub async fn init_cluster(pool: &PgPool, logins: Logins<'_>) -> Result<Changes, CoreError> {
    let mut changes = Changes::new();
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(ROLES_LOCK_KEY)
        .execute(&mut *tx)
        .await?;
    for group in [OWNER_ROLE, APP_ROLE] {
        match role_exists(&mut tx, group).await? {
            None => {
                exec(&mut tx, format!("CREATE ROLE {} NOLOGIN", quote(group))).await?;
                changes.push(format!("rôle de groupe {group} créé"));
            }
            Some(true) => {
                return Err(CoreError::Roles(format!(
                    "{group} peut se connecter (LOGIN) : un rôle de groupe ne doit jamais le pouvoir"
                )));
            }
            Some(false) => {}
        }
    }
    for login in [logins.service, logins.migration] {
        match role_exists(&mut tx, login).await? {
            None => {
                exec(&mut tx, format!("CREATE ROLE {} LOGIN", quote(login))).await?;
                changes.push(format!("rôle de connexion {login} créé"));
            }
            Some(false) => {
                return Err(CoreError::Roles(format!(
                    "{login} existe sans pouvoir se connecter (NOLOGIN)"
                )));
            }
            Some(true) => {}
        }
    }
    for (group, login) in [(APP_ROLE, logins.service), (OWNER_ROLE, logins.migration)] {
        exec(
            &mut tx,
            format!(
                "GRANT {} TO {} WITH INHERIT FALSE, SET TRUE",
                quote(group),
                quote(login)
            ),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(changes)
}

/// Creates database `name` owned by [`OWNER_ROLE`], or gives it to that
/// role if it exists (an M1 installation), then lets only the two login
/// roles connect. Run on another database of the cluster (`postgres`), as
/// a role allowed to create databases and to take [`OWNER_ROLE`].
///
/// # Errors
///
/// [`CoreError::Roles`].
pub async fn init_database(
    pool: &PgPool,
    name: &str,
    logins: Logins<'_>,
) -> Result<Changes, CoreError> {
    let mut changes = Changes::new();
    // CREATE DATABASE cannot run in a transaction; one connection, so that
    // SET ROLE applies to the statements after it.
    let mut conn = pool.acquire().await?;
    let owner = sqlx::query_scalar::<_, String>(
        "SELECT pg_get_userbyid(datdba)::text FROM pg_database WHERE datname = $1",
    )
    .bind(name)
    .fetch_optional(&mut *conn)
    .await?;
    let db = quote(name);
    match owner.as_deref() {
        None => {
            exec(
                &mut conn,
                format!("CREATE DATABASE {db} OWNER {OWNER_ROLE}"),
            )
            .await?;
            changes.push(format!("base {name} créée, propriété de {OWNER_ROLE}"));
        }
        Some(OWNER_ROLE) => {}
        Some(other) => {
            exec(
                &mut conn,
                format!("ALTER DATABASE {db} OWNER TO {OWNER_ROLE}"),
            )
            .await?;
            changes.push(format!(
                "base {name} : propriété passée de {other} à {OWNER_ROLE}"
            ));
        }
    }
    // As the owner: a creator that only has SET on it can grant then.
    exec(&mut conn, format!("SET ROLE {OWNER_ROLE}")).await?;
    let granted = async {
        exec(
            &mut conn,
            format!("REVOKE ALL ON DATABASE {db} FROM PUBLIC"),
        )
        .await?;
        exec(
            &mut conn,
            format!(
                "GRANT CONNECT ON DATABASE {db} TO {}, {}",
                quote(logins.service),
                quote(logins.migration)
            ),
        )
        .await
    }
    .await;
    // Never hand a connection back to the pool under another role.
    let _ = sqlx::Connection::close(conn.detach()).await;
    granted?;
    Ok(changes)
}

/// Gives to [`OWNER_ROLE`] the objects of the current database that the
/// service account owns: the single role of M1 owned the whole schema.
/// Run on the core database, as a superuser. Nothing to do on a new
/// installation.
///
/// # Errors
///
/// [`CoreError::Roles`].
pub async fn adopt_m1_objects(pool: &PgPool, service: &str) -> Result<Changes, CoreError> {
    let owned = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner
          WHERE r.rolname = $1 AND c.relnamespace = 'public'::regnamespace",
    )
    .bind(service)
    .fetch_one(pool)
    .await?;
    if owned == 0 {
        return Ok(Changes::new());
    }
    let mut conn = pool.acquire().await?;
    exec(
        &mut conn,
        format!("REASSIGN OWNED BY {} TO {OWNER_ROLE}", quote(service)),
    )
    .await?;
    Ok(vec![format!(
        "{owned} objet(s) de {service} (installation M1) donnés à {OWNER_ROLE}"
    )])
}

/// What weakens the separation for login role `service`: it could become
/// the owner of the schema, or it is the migration role. Empty when the
/// installation follows the procedure. Readable by any role.
///
/// # Errors
///
/// [`CoreError::Database`].
pub async fn weaknesses(pool: &PgPool, logins: Logins<'_>) -> Result<Vec<String>, CoreError> {
    let (superuser, createrole, owner): (bool, bool, bool) = sqlx::query_as(
        "SELECT rolsuper, rolcreaterole, pg_has_role(oid, $2, 'MEMBER')
           FROM pg_roles WHERE rolname = $1",
    )
    .bind(logins.service)
    .bind(OWNER_ROLE)
    .fetch_optional(pool)
    .await?
    .unwrap_or((false, false, false));
    let mut out = Vec::new();
    if logins.service == logins.migration {
        out.push(format!(
            "{} sert au service et aux migrations : un core compromis peut modifier le schéma",
            logins.service
        ));
    }
    if superuser {
        out.push(format!("{} est superutilisateur", logins.service));
    } else if owner {
        out.push(format!(
            "{} est membre de {OWNER_ROLE}, propriétaire du schéma",
            logins.service
        ));
    }
    if createrole && !superuser {
        out.push(format!(
            "{} peut créer des rôles (CREATEROLE)",
            logins.service
        ));
    }
    Ok(out)
}

/// Logs each weakness of [`weaknesses`] (`core.database_role_weak`) and,
/// in production, refuses them: the separation of the roles is only worth
/// what the login roles allow. Development tolerates them (a single test
/// account plays every role).
///
/// # Errors
///
/// [`CoreError::RolesWeak`] in production, [`CoreError::Database`].
pub async fn enforce(pool: &PgPool, logins: Logins<'_>, mode: Mode) -> Result<(), CoreError> {
    let weak = weaknesses(pool, logins).await?;
    for reason in &weak {
        tracing::warn!(
            event = "core.database_role_weak",
            reason = %reason,
            refused = mode == Mode::Production,
            "séparation des rôles de la base affaiblie"
        );
    }
    if mode == Mode::Production && !weak.is_empty() {
        return Err(CoreError::RolesWeak(weak.join(" ; ")));
    }
    Ok(())
}

/// Checks, before the service starts, that the schema is held as the
/// separation requires: no object owned by the login role of the service
/// (an M1 installation that `ostena core db init` did not convert) nor by
/// [`APP_ROLE`], and no `UPDATE`, `DELETE`, `TRUNCATE`, `TRIGGER` nor
/// `REFERENCES` of [`APP_ROLE`] on the audit chain. Needs an up-to-date
/// schema.
///
/// # Errors
///
/// [`CoreError::Roles`] naming what is wrong.
pub async fn check_service(pool: &PgPool) -> Result<(), CoreError> {
    let owned: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_class c
          WHERE c.relnamespace = 'public'::regnamespace
            AND (c.relowner = (SELECT oid FROM pg_roles WHERE rolname = session_user)
                 OR c.relowner = (SELECT oid FROM pg_roles WHERE rolname = $1))
          ORDER BY 1",
    )
    .bind(APP_ROLE)
    .fetch_all(pool)
    .await?;
    if !owned.is_empty() {
        return Err(CoreError::Roles(format!(
            "le compte du service possède {} objet(s) du schéma ({}) : installation M1 non \
             convertie",
            owned.len(),
            owned.join(", ")
        )));
    }
    let rights: Vec<String> = sqlx::query_scalar(
        "SELECT t || ' ' || p FROM unnest(ARRAY['audit_record', 'audit_head']) t,
                unnest(ARRAY['UPDATE', 'DELETE', 'TRUNCATE', 'TRIGGER', 'REFERENCES']) p
          WHERE has_table_privilege($1, t, p)
             OR (p IN ('UPDATE', 'REFERENCES') AND has_any_column_privilege($1, t, p))
          ORDER BY 1",
    )
    .bind(APP_ROLE)
    .fetch_all(pool)
    .await?;
    if !rights.is_empty() {
        return Err(CoreError::Roles(format!(
            "{APP_ROLE} peut modifier la chaîne d'audit ({})",
            rights.join(", ")
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_quoted() {
        assert_eq!(quote("ostena"), "\"ostena\"");
        assert_eq!(quote("a\"b"), "\"a\"\"b\"");
    }
}
