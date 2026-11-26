//! The separate roles of the database (ADR-0011): what the service role
//! `ostena_app` may do, and above all what it may not (see `common/mod.rs`
//! for the environment).

#![allow(clippy::unwrap_used, reason = "test helpers")]

mod common;

use common::{TestDb, block_on};
use ostena_common::config::{DatabaseConfig, Mode};
use ostena_core::db::{self, APP_ROLE, OWNER_ROLE, Role};
use ostena_core::roles::{self, Logins};
use ostena_core::{audit, schema};
use sqlx::PgPool;

/// The audit chain (ADR-0012).
const AUDIT_TABLES: [&str; 2] = ["audit_record", "audit_head"];

/// Every privilege of `ostena_app` on the objects of the schema, table by
/// table: a privilege granted beyond this list fails the test, as does a
/// table forgotten by a migration. Column privileges are `table.column`.
const EXPECTED: &[(&str, &[&str])] = &[
    ("_sqlx_migrations", &["SELECT"]),
    ("access_grant", &["INSERT", "SELECT", "UPDATE"]),
    ("access_right", &["INSERT", "SELECT", "UPDATE"]),
    ("access_session", &["INSERT", "SELECT", "UPDATE"]),
    ("agent", &["INSERT", "SELECT", "UPDATE"]),
    ("agent_certificate", &["INSERT", "SELECT", "UPDATE"]),
    ("agent_ssh", &["INSERT", "SELECT", "UPDATE"]),
    ("app_user", &["INSERT", "SELECT", "UPDATE"]),
    ("audit_head", &["INSERT", "SELECT"]),
    ("audit_record", &["INSERT", "SELECT"]),
    ("enrollment_token", &["INSERT", "SELECT", "UPDATE"]),
    ("gateway_group", &["INSERT", "SELECT", "UPDATE"]),
    ("grant_key", &["INSERT", "SELECT", "UPDATE"]),
    ("grant_key_set", &["INSERT", "SELECT", "UPDATE"]),
    ("login_session", &["INSERT", "SELECT", "UPDATE"]),
    ("push_version", &["USAGE"]),
    ("resource", &["INSERT", "SELECT"]),
    ("resource.disabled_at", &["UPDATE"]),
    ("session_transcript", &["INSERT", "SELECT", "UPDATE"]),
    ("target_account", &["INSERT", "SELECT"]),
    ("target_account.disabled_at", &["UPDATE"]),
    ("user_credential", &["INSERT", "SELECT", "UPDATE"]),
    ("user_group", &["INSERT", "SELECT"]),
    ("user_group_member", &["DELETE", "INSERT", "SELECT"]),
    ("user_role", &["DELETE", "INSERT", "SELECT"]),
    ("web_session", &["INSERT", "SELECT", "UPDATE"]),
];

/// The privileges of `grantee` (a role name, or `PUBLIC`) on the objects of
/// the schema, as `object privilege` lines.
async fn privileges(pool: &PgPool, grantee: &str) -> Vec<String> {
    sqlx::query_scalar(
        "WITH g AS (SELECT CASE WHEN $1 = 'PUBLIC' THEN 0::oid
                                ELSE (SELECT oid FROM pg_roles WHERE rolname = $1) END AS oid)
         SELECT c.relname || ' ' || a.privilege_type
           FROM pg_class c, aclexplode(c.relacl) a, g
          WHERE c.relnamespace = 'public'::regnamespace AND a.grantee = g.oid
         UNION ALL
         SELECT c.relname || '.' || att.attname || ' ' || a.privilege_type
           FROM pg_attribute att JOIN pg_class c ON c.oid = att.attrelid,
                aclexplode(att.attacl) a, g
          WHERE c.relnamespace = 'public'::regnamespace AND a.grantee = g.oid
         ORDER BY 1",
    )
    .bind(grantee)
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn migrated(test: &str) -> Option<TestDb> {
    let db = TestDb::create(test).await?;
    db.migrate().await;
    Some(db)
}

#[test]
fn the_service_role_cannot_change_or_remove_audit_records() {
    block_on(async {
        let Some(db) = migrated("the_service_role_cannot_change_or_remove_audit_records").await
        else {
            return;
        };
        let app = db.pool().await;
        // A chain to change: genesis and one record, written as the service.
        audit::ensure_genesis(&app).await.unwrap();
        audit::record_migration(&app, &[6], 6, false).await.unwrap();

        // In the catalog: none of these rights, on the table or a column,
        // directly or through a role, and not the owner.
        let granted: Vec<String> = sqlx::query_scalar(
            "SELECT t || ' ' || p
               FROM unnest($1::text[]) t,
                    unnest(ARRAY['UPDATE', 'DELETE', 'TRUNCATE', 'TRIGGER', 'REFERENCES']) p
              WHERE has_table_privilege($2, t, p)
                 OR (p IN ('UPDATE', 'REFERENCES') AND has_any_column_privilege($2, t, p))
                 OR pg_has_role($2, (SELECT tableowner FROM pg_tables WHERE tablename = t), 'USAGE')",
        )
        .bind(&AUDIT_TABLES[..])
        .bind(APP_ROLE)
        .fetch_all(&app)
        .await
        .unwrap();
        assert_eq!(granted, Vec::<String>::new());

        // In practice: refused by the privileges, before the append-only
        // triggers (whose message says « en ajout seul ») are even reached.
        for sql in [
            "UPDATE audit_record SET event = 'x.y' WHERE seq = 1",
            "UPDATE audit_record SET event = 'x.y' WHERE false",
            "DELETE FROM audit_record WHERE seq = 2",
            "DELETE FROM audit_record WHERE false",
            "TRUNCATE audit_record CASCADE",
            "UPDATE audit_head SET record_seq = 1",
            "DELETE FROM audit_head",
            "TRUNCATE audit_head",
            "ALTER TABLE audit_record DISABLE TRIGGER USER",
            "ALTER TABLE audit_head DISABLE TRIGGER audit_head_append_only",
            "DROP TRIGGER audit_record_append_only ON audit_record",
            "DROP TABLE audit_head",
            "CREATE TABLE audit_shadow (seq bigint)",
            "CREATE OR REPLACE FUNCTION audit_append_only() RETURNS trigger LANGUAGE plpgsql \
             AS $$ BEGIN RETURN NEW; END; $$",
        ] {
            let e = sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
                .execute(&app)
                .await
                .unwrap_err();
            let d = e.as_database_error().unwrap();
            assert_eq!(d.code().as_deref(), Some("42501"), "{sql}: {e}");
            assert!(!e.to_string().contains("ajout seul"), "{sql}: {e}");
        }
        let records: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_record")
            .fetch_one(&app)
            .await
            .unwrap();
        assert_eq!(records, 2);
        app.close().await;
        db.drop_database().await;
    });
}

#[test]
fn the_service_role_has_exactly_the_listed_privileges() {
    block_on(async {
        let Some(db) = migrated("the_service_role_has_exactly_the_listed_privileges").await else {
            return;
        };
        let owner = db.owner_pool().await;
        let mut expected: Vec<String> = EXPECTED
            .iter()
            .flat_map(|(object, rights)| rights.iter().map(move |r| format!("{object} {r}")))
            .collect();
        expected.sort();
        assert_eq!(privileges(&owner, APP_ROLE).await, expected);
        // Nothing for PUBLIC.
        assert_eq!(privileges(&owner, "PUBLIC").await, Vec::<String>::new());
        // Everything belongs to the owner role: tables, sequence, functions,
        // and the database.
        let others: Vec<String> = sqlx::query_scalar(
            "SELECT relname::text FROM pg_class
              WHERE relnamespace = 'public'::regnamespace AND relowner <> $1::regrole
             UNION ALL
             SELECT proname::text FROM pg_proc
              WHERE pronamespace = 'public'::regnamespace AND proowner <> $1::regrole
             UNION ALL
             SELECT datname::text FROM pg_database
              WHERE datname = current_database() AND datdba <> $1::regrole",
        )
        .bind(OWNER_ROLE)
        .fetch_all(&owner)
        .await
        .unwrap();
        assert_eq!(others, Vec::<String>::new());
        roles::check_service(&owner).await.unwrap();

        // One right too many on the audit chain: the core refuses to start.
        db.execute("GRANT DELETE ON audit_head TO ostena_app").await;
        let e = roles::check_service(&owner).await.unwrap_err();
        assert_eq!(e.code(), "CORE-E013");
        assert!(e.to_string().contains("audit_head DELETE"), "{e}");
        owner.close().await;
        db.drop_database().await;
    });
}

#[test]
fn production_refuses_weak_login_roles() {
    block_on(async {
        let Some(db) = migrated("production_refuses_weak_login_roles").await else {
            return;
        };
        let login = db.login_pool().await;
        let user = db.config.user.clone();
        // The test account plays both login roles: refused in production,
        // tolerated (and logged) in development.
        let single = Logins {
            service: &user,
            migration: &user,
        };
        let e = roles::enforce(&login, single, Mode::Production)
            .await
            .unwrap_err();
        assert_eq!(e.code(), "CORE-E014");
        assert!(
            e.to_string().contains("sert au service et aux migrations"),
            "{e}"
        );
        roles::enforce(&login, single, Mode::Development)
            .await
            .unwrap();

        // A service account of its own, member of ostena_app only, not a
        // superuser: accepted in production.
        let suffix: [u8; 4] = ostena_crypto::rand::array().unwrap();
        let service = suffix
            .iter()
            .fold(String::from("ostena_test_svc_"), |mut s, b| {
                use std::fmt::Write as _;
                let _ = write!(s, "{b:02x}");
                s
            });
        let logins = Logins {
            service: &service,
            migration: &user,
        };
        roles::init_cluster(&login, logins).await.unwrap();
        roles::enforce(&login, logins, Mode::Production)
            .await
            .unwrap();
        // Made a member of the owner role: refused again.
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "GRANT {OWNER_ROLE} TO {service}"
        )))
        .execute(&login)
        .await
        .unwrap();
        let e = roles::enforce(&login, logins, Mode::Production)
            .await
            .unwrap_err();
        assert!(e.to_string().contains(OWNER_ROLE), "{e}");
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP ROLE {service}")))
            .execute(&login)
            .await
            .unwrap();
        login.close().await;
        db.drop_database().await;
    });
}

#[test]
fn login_roles_only_take_their_group_role() {
    block_on(async {
        let Some(db) = migrated("login_roles_only_take_their_group_role").await else {
            return;
        };
        // Without SET ROLE, a login role holds nothing (INHERIT FALSE)…
        let login = db.login_pool().await;
        let inherited: Vec<bool> = sqlx::query_scalar(
            "SELECT inherit_option FROM pg_auth_members
              WHERE member = (SELECT oid FROM pg_roles WHERE rolname = session_user)
                AND roleid IN ($1::regrole, $2::regrole)",
        )
        .bind(OWNER_ROLE)
        .bind(APP_ROLE)
        .fetch_all(&login)
        .await
        .unwrap();
        assert!(inherited.iter().all(|i| !i), "{inherited:?}");
        login.close().await;
        // …and the group roles cannot log in.
        let owner = db.owner_pool().await;
        let can_login: Vec<bool> =
            sqlx::query_scalar("SELECT rolcanlogin FROM pg_roles WHERE rolname IN ($1, $2)")
                .bind(OWNER_ROLE)
                .bind(APP_ROLE)
                .fetch_all(&owner)
                .await
                .unwrap();
        assert_eq!(can_login, [false, false]);
        // The test role plays both login roles: reported as a weakness.
        let user = db.config.user.clone();
        let weak = roles::weaknesses(
            &owner,
            Logins {
                service: &user,
                migration: &user,
            },
        )
        .await
        .unwrap();
        assert!(
            weak[0].contains("sert au service et aux migrations"),
            "{weak:?}"
        );
        // Setting up the roles again changes nothing.
        let changes = roles::init_cluster(
            &db.login_pool().await,
            Logins {
                service: &user,
                migration: &user,
            },
        )
        .await
        .unwrap();
        assert_eq!(changes, Vec::<String>::new());
        assert_eq!(
            schema::state(&owner).await.unwrap(),
            schema::SchemaState::UpToDate
        );
        owner.close().await;
        db.drop_database().await;
    });
}

#[test]
fn db_init_takes_over_an_m1_database() {
    block_on(async {
        let Some(db) = TestDb::create("db_init_takes_over_an_m1_database").await else {
            return;
        };
        let login = db.login_pool().await;
        let superuser: bool =
            sqlx::query_scalar("SELECT rolsuper FROM pg_roles WHERE rolname = session_user")
                .fetch_one(&login)
                .await
                .unwrap();
        if !superuser {
            // REASSIGN OWNED needs the privileges of both roles.
            eprintln!(
                "db_init_takes_over_an_m1_database : sauté (rôle de test non superutilisateur)"
            );
            login.close().await;
            db.drop_database().await;
            return;
        }
        // An M1 database: owned by the service account, which applied the
        // M1 migrations itself and wrote rows.
        let user = db.config.user.clone();
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "ALTER DATABASE {} OWNER TO \"{user}\"",
            db.config.name
        )))
        .execute(&login)
        .await
        .unwrap();
        schema::MIGRATOR
            .run_to(schema::revert_floor(), &login)
            .await
            .unwrap();
        audit::ensure_genesis(&login).await.unwrap();
        let logins = Logins {
            service: &user,
            migration: &user,
        };

        // ostena core db init: the database, then the objects.
        let cluster = DatabaseConfig {
            name: "postgres".into(),
            ..db.config.clone()
        };
        let postgres = db::connect(&cluster, db.mode, Role::Login).await.unwrap();
        let changes = roles::init_database(&postgres, &db.config.name, logins)
            .await
            .unwrap();
        assert!(changes[0].contains("propriété passée"), "{changes:?}");
        postgres.close().await;
        let changes = roles::adopt_m1_objects(&login, &user).await.unwrap();
        assert!(changes[0].contains("installation M1"), "{changes:?}");
        assert_eq!(
            roles::adopt_m1_objects(&login, &user).await.unwrap(),
            Vec::<String>::new()
        );
        login.close().await;

        // ostena core migrate, then the service starts on the M1 rows.
        db.migrate().await;
        let app = db.pool().await;
        roles::check_service(&app).await.unwrap();
        schema::require_up_to_date(&app).await.unwrap();
        let records: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_record")
            .fetch_one(&app)
            .await
            .unwrap();
        assert_eq!(records, 1);
        audit::record_migration(&app, &[6], 6, false).await.unwrap();
        app.close().await;
        db.drop_database().await;
    });
}
