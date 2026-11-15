//! Test databases (feature `testing`). Never in a release binary: `cargo
//! xtask check-release` refuses the feature and [`MARKER`].
//!
//! The PostgreSQL server comes from the environment:
//!
//! - `OSTENA_TEST_DB_SOCKET=/var/run/postgresql`: the Unix socket, `peer`
//!   authentication, production mode (CI);
//! - or `OSTENA_TEST_DB_TCP=127.0.0.1:55432` with `OSTENA_TEST_DB_PASSWORD_FILE`:
//!   TCP, development mode (a local container);
//! - `OSTENA_TEST_DB_USER`: the role (it must be allowed to create
//!   databases).
//!
//! Each test gets a database of its own, dropped at the end. Without these
//! variables the tests are skipped with a message, unless
//! `OSTENA_REQUIRE_DB=1` (CI).

#![allow(
    clippy::print_stderr,
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    reason = "test helpers"
)]

use std::path::PathBuf;

use ostena_common::config::{DatabaseConfig, DatabaseTcp, Mode};

use crate::db;

/// Text present in any binary that links this module (the same as the test
/// core of ostena-tunnel, so that one check covers both).
pub const MARKER: &str = "ostena-testing-core: never in a release build";

/// A database created for one test.
#[derive(Debug)]
pub struct TestDb {
    /// Its connection settings.
    pub config: DatabaseConfig,
    /// Production with the socket (peer), development over TCP.
    pub mode: Mode,
    admin: DatabaseConfig,
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// The server configuration from the environment, on database `name`.
pub fn server(name: &str) -> Option<(DatabaseConfig, Mode)> {
    let user = var("OSTENA_TEST_DB_USER");
    let base = |user: String| DatabaseConfig {
        name: name.into(),
        user,
        max_connections: 4,
        ..DatabaseConfig::default()
    };
    if let (Some(dir), Some(user)) = (var("OSTENA_TEST_DB_SOCKET"), user.clone()) {
        return Some((
            DatabaseConfig {
                socket_dir: PathBuf::from(dir),
                ..base(user)
            },
            Mode::Production,
        ));
    }
    if let (Some(address), Some(user)) = (var("OSTENA_TEST_DB_TCP"), user) {
        let (host, port) = address.rsplit_once(':')?;
        return Some((
            DatabaseConfig {
                port: port.parse().ok()?,
                tcp: Some(DatabaseTcp {
                    host: host.into(),
                    password_file: var("OSTENA_TEST_DB_PASSWORD_FILE").map(PathBuf::from),
                }),
                ..base(user)
            },
            Mode::Development,
        ));
    }
    None
}

impl TestDb {
    /// A fresh, empty database, or `None` (test skipped) without a server.
    pub async fn create(test: &str) -> Option<Self> {
        tracing::debug!(marker = MARKER);
        let Some((admin, mode)) = server("postgres") else {
            assert!(
                var("OSTENA_REQUIRE_DB").as_deref() != Some("1"),
                "aucun serveur PostgreSQL de test alors que OSTENA_REQUIRE_DB=1"
            );
            eprintln!("{test} : sauté (OSTENA_TEST_DB_SOCKET ou OSTENA_TEST_DB_TCP absent)");
            return None;
        };
        let suffix: [u8; 6] = ostena_crypto::rand::array().unwrap();
        let name = suffix
            .iter()
            .fold(String::from("ostena_test_"), |mut s, b| {
                use std::fmt::Write as _;
                let _ = write!(s, "{b:02x}");
                s
            });
        let pool = db::connect(&admin, mode).await.unwrap();
        // The name is ours: a fixed prefix and random hexadecimal digits.
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        let config = DatabaseConfig {
            name,
            ..admin.clone()
        };
        Some(Self {
            config,
            mode,
            admin,
        })
    }

    /// A pool on the test database.
    pub async fn pool(&self) -> db::Pool {
        db::connect(&self.config, self.mode).await.unwrap()
    }

    /// Runs SQL statements on the test database as its owner: what a
    /// database administrator could do behind the core.
    pub async fn execute(&self, sql: &str) {
        let pool = self.pool().await;
        sqlx::raw_sql(sqlx::AssertSqlSafe(sql.to_owned()))
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
    }

    /// Drops the database (connections closed first).
    pub async fn drop_database(self) {
        let pool = db::connect(&self.admin, self.mode).await.unwrap();
        let _ = sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE IF EXISTS {} WITH (FORCE)",
            self.config.name
        )))
        .execute(&pool)
        .await;
        pool.close().await;
    }
}

/// Runs `body` on a small multi-thread runtime.
pub fn block_on<F: Future>(body: F) -> F::Output {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(body)
}
