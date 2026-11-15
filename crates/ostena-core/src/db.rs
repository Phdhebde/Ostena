//! The PostgreSQL connection (ADR-0011).
//!
//! Production reaches the server through the local Unix socket, with `peer`
//! authentication only: no password and no network. Every connection
//! setting comes from the configuration; the `PG*` variables of the
//! environment never change where or as whom the core connects.

use std::path::Path;
use std::time::Duration;

use ostena_common::config::{DatabaseConfig, Mode};
use ostena_common::secret::SecretBytes;
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};

use crate::error::CoreError;

/// The connection pool (the CLI does not name sqlx).
pub type Pool = PgPool;

/// Lowest supported server version (`server_version_num`).
pub const MIN_SERVER_VERSION: i32 = 160_000;

/// `application_name` of the core connections.
pub const APPLICATION_NAME: &str = "ostena-core";

/// Variables that sqlx reads and that no setting can clear afterwards: a
/// password, and server options (`-c search_path=…`). The core refuses to
/// start while they are set rather than let them reach the server.
pub const UNCLEARABLE_VARIABLES: [&str; 2] = ["PGPASSWORD", "PGOPTIONS"];

/// Connection options built from `config` only.
///
/// sqlx starts from the environment (`PGHOST`, `PGUSER`…); every field it
/// reads there is set again here, except the two of
/// [`UNCLEARABLE_VARIABLES`], refused by [`check_environment`]. `~/.pgpass`
/// is never read.
///
/// # Errors
///
/// [`CoreError::Database`] if the password file cannot be read.
pub fn options(config: &DatabaseConfig) -> Result<PgConnectOptions, CoreError> {
    let base = PgConnectOptions::new_without_pgpass()
        .port(config.port)
        .username(&config.user)
        .database(&config.name)
        .application_name(APPLICATION_NAME)
        // No TLS in this build (ADR-0011): never try it, whatever PGSSLMODE says.
        .ssl_mode(PgSslMode::Disable);
    let Some(tcp) = &config.tcp else {
        // A host starting with `/` is a socket directory; `socket` takes
        // precedence over any host anyway.
        let dir = config.socket_dir.to_string_lossy();
        return Ok(base.host(&dir).socket(&config.socket_dir));
    };
    let options = base.host(&tcp.host);
    match &tcp.password_file {
        None => Ok(options),
        Some(path) => {
            let password = read_password(path)?;
            // SECRET-EXPOSURE: handed to sqlx for SCRAM (development only, CFG-P014).
            #[expect(clippy::disallowed_methods)]
            let text = std::str::from_utf8(password.expose_secret())
                .map_err(|_| {
                    CoreError::Database(format!("{} : mot de passe non UTF-8", path.display()))
                })?
                .trim_end_matches(['\r', '\n']);
            Ok(options.password(text))
        }
    }
}

fn read_password(path: &Path) -> Result<SecretBytes, CoreError> {
    std::fs::read(path)
        .map(SecretBytes::from)
        .map_err(|e| CoreError::Database(format!("{} : {e}", path.display())))
}

/// Refuses the variables listed in [`UNCLEARABLE_VARIABLES`], whatever the
/// mode.
///
/// # Errors
///
/// [`CoreError::Environment`] naming them.
pub fn check_environment(get: impl Fn(&str) -> Option<String>) -> Result<(), CoreError> {
    let set: Vec<&str> = UNCLEARABLE_VARIABLES
        .into_iter()
        .filter(|name| get(name).is_some())
        .collect();
    if set.is_empty() {
        Ok(())
    } else {
        Err(CoreError::Environment(set.join(", ")))
    }
}

/// Connects the pool, then checks the server version and, in production,
/// that the server authenticated the core by `peer`.
///
/// # Errors
///
/// [`CoreError`] with the reason (`CORE-E001` to `CORE-E003`, `CORE-E008`).
pub async fn connect(config: &DatabaseConfig, mode: Mode) -> Result<PgPool, CoreError> {
    check_environment(|name| std::env::var(name).ok())?;
    let options = options(config)?;
    let pool = PgPoolOptions::new()
        .max_connections(config.max_connections)
        .acquire_timeout(Duration::from_secs(config.connect_timeout_secs))
        .connect_with(options)
        .await
        .map_err(|e| CoreError::Database(e.to_string()))?;
    let (version, user): (i32, Option<String>) =
        sqlx::query_as("SELECT current_setting('server_version_num')::int, system_user")
            .fetch_one(&pool)
            .await
            .map_err(|e| CoreError::Database(e.to_string()))?;
    check_server(version, user.as_deref(), mode)?;
    tracing::info!(
        event = "core.database_connected",
        server_version = version,
        authentication = user
            .as_deref()
            .and_then(|u| u.split_once(':'))
            .map_or("trust", |(m, _)| m),
        "base PostgreSQL jointe"
    );
    Ok(pool)
}

/// The checks on the server: version 16 or later, and `peer`
/// authentication in production (`system_user` is `peer:<account>`; it is
/// null for `trust`).
///
/// # Errors
///
/// `CORE-E002` for an older server, `CORE-E003` for another authentication
/// in production.
pub fn check_server(version: i32, system_user: Option<&str>, mode: Mode) -> Result<(), CoreError> {
    if version < MIN_SERVER_VERSION {
        return Err(CoreError::ServerVersion(version));
    }
    let method = system_user.and_then(|u| u.split_once(':')).map(|(m, _)| m);
    if method == Some("peer") {
        return Ok(());
    }
    let method = method.unwrap_or("trust").to_owned();
    match mode {
        Mode::Production => Err(CoreError::NotPeer(method)),
        Mode::Development => {
            tracing::warn!(
                event = "core.database_not_peer",
                authentication = %method,
                "authentification PostgreSQL autre que peer, acceptée en développement seulement"
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
