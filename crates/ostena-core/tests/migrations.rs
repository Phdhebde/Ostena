//! Reversible migrations (ADR-0011): for every migration N that has a down
//! migration, N-1 -> N -> N-1 -> N on a database holding rows, without
//! losing any of them and with the schema of N-1 back exactly (see
//! `common/mod.rs` for the environment).

#![allow(clippy::unwrap_used, reason = "test helpers")]

mod common;

use common::{TestDb, block_on};
use ostena_core::schema::{self, MIGRATOR};
use ostena_core::{audit, store};
use ostena_tunnel::Uuid;
use sqlx::PgPool;

/// The schema as text: columns, constraints, indexes, triggers (and whether
/// they are enabled), functions, sequences, owners and privileges.
async fn schema_of(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        r#"WITH rel AS (SELECT oid, relname FROM pg_class
                        WHERE relnamespace = 'public'::regnamespace)
        SELECT 'column ' || table_name || '.' || column_name || ' ' || data_type || ' '
               || is_nullable || ' ' || coalesce(column_default, '')
          FROM information_schema.columns WHERE table_schema = 'public'
        UNION ALL
        SELECT 'constraint ' || conrelid::regclass || ' ' || conname || ' '
               || pg_get_constraintdef(oid)
          FROM pg_constraint WHERE connamespace = 'public'::regnamespace
        UNION ALL
        SELECT 'index ' || indexdef FROM pg_indexes WHERE schemaname = 'public'
        UNION ALL
        SELECT 'trigger ' || tgrelid::regclass || ' ' || tgname || ' ' || tgenabled::text
          FROM pg_trigger WHERE NOT tgisinternal
        UNION ALL
        SELECT 'function ' || oid::regprocedure || ' ' || md5(prosrc) || ' '
               || pg_get_userbyid(proowner) || ' '
               || coalesce(proacl, acldefault('f', proowner))::text
          FROM pg_proc WHERE pronamespace = 'public'::regnamespace
        UNION ALL
        SELECT 'relation ' || relname || ' ' || relkind::text || ' ' || pg_get_userbyid(relowner)
               || ' '
               || coalesce(relacl, acldefault(CASE relkind WHEN 'S' THEN 's' ELSE 'r' END::"char", relowner))::text
          FROM pg_class WHERE oid IN (SELECT oid FROM rel)
        UNION ALL
        SELECT 'column privileges ' || rel.relname || '.' || attname || ' ' || attacl::text
          FROM pg_attribute JOIN rel ON rel.oid = attrelid WHERE cardinality(attacl) > 0
        ORDER BY 1"#,
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// The rows of every table but sqlx's own, and the sequences, as text.
async fn rows_of(pool: &PgPool) -> Vec<String> {
    let tables: Vec<(String, bool)> = sqlx::query_as(
        "SELECT relname::text, relkind = 'S' FROM pg_class
          WHERE relnamespace = 'public'::regnamespace AND relkind IN ('r', 'S')
            AND relname <> '_sqlx_migrations'
          ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    let mut out = Vec::new();
    for (table, sequence) in tables {
        // Names read from the catalog of the schema, quoted.
        let sql = if sequence {
            format!("SELECT last_value || ' ' || is_called FROM \"{table}\"")
        } else {
            format!(
                "SELECT count(*) || ' ' || md5(coalesce(string_agg(t::text, '|' ORDER BY \
                 t::text), '')) FROM \"{table}\" t"
            )
        };
        let line: String = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .fetch_one(pool)
            .await
            .unwrap();
        out.push(format!("{table} {line}"));
    }
    out
}

/// Rows in the tables of M1, written as the owner (before migration 6 the
/// service role has no privilege yet).
async fn seed(pool: &PgPool, n: u8) {
    audit::ensure_genesis(pool).await.unwrap();
    store::issue_token(
        pool,
        Uuid::from_bytes([n; 16]),
        std::time::Duration::from_secs(600),
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO app_user (id, name, display_name) VALUES ($1::text::uuid, $2, 'Utilisateur')",
    )
    .bind(Uuid::from_bytes([n.wrapping_add(1); 16]).to_string())
    .bind(format!("user{n}"))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("SELECT nextval('push_version')")
        .execute(pool)
        .await
        .unwrap();
}

#[test]
fn every_reversible_migration_goes_down_and_up_without_loss() {
    block_on(async {
        let floor = schema::revert_floor();
        let latest = schema::latest_version();
        for version in floor + 1..=latest {
            let Some(db) = TestDb::create(&format!("migration_round_trip_{version}")).await else {
                return;
            };
            let owner = db.owner_pool().await;
            MIGRATOR.run_to(version - 1, &owner).await.unwrap();
            seed(&owner, 1).await;
            let before = schema_of(&owner).await;

            MIGRATOR.run_to(version, &owner).await.unwrap();
            let upgraded = schema_of(&owner).await;
            assert_ne!(upgraded, before, "migration {version} ne change rien");
            // Rows written once upgraded, by the service when it can.
            if version == latest {
                let app = db.pool().await;
                seed(&app, 2).await;
                app.close().await;
            } else {
                seed(&owner, 2).await;
            }
            let rows = rows_of(&owner).await;

            // N -> N-1: the schema of N-1 exactly, every row kept.
            assert_eq!(
                schema::revert(&owner, version - 1).await.unwrap(),
                [version]
            );
            assert_eq!(schema_of(&owner).await, before, "retour de {version}");
            assert_eq!(
                rows_of(&owner).await,
                rows,
                "lignes après retour de {version}"
            );
            // Nothing left to revert down to the same version.
            assert_eq!(
                schema::revert(&owner, version - 1).await.unwrap(),
                Vec::<i64>::new()
            );

            // N-1 -> N again: the same schema as the first time.
            MIGRATOR.run_to(version, &owner).await.unwrap();
            assert_eq!(
                schema_of(&owner).await,
                upgraded,
                "nouvelle montée à {version}"
            );
            assert_eq!(rows_of(&owner).await, rows);
            owner.close().await;
            db.drop_database().await;
        }
    });
}

#[test]
fn reverting_below_the_m1_schema_is_refused() {
    block_on(async {
        let Some(db) = TestDb::create("reverting_below_the_m1_schema_is_refused").await else {
            return;
        };
        db.migrate().await;
        let owner = db.owner_pool().await;
        let floor = schema::revert_floor();
        let e = schema::revert(&owner, floor - 1).await.unwrap_err();
        assert_eq!(e.code(), "CORE-E004", "{e}");
        // Nothing was undone.
        assert_eq!(
            schema::state(&owner).await.unwrap(),
            schema::SchemaState::UpToDate
        );
        // The service role cannot revert either.
        let app = db.pool().await;
        assert_eq!(
            schema::revert(&app, floor).await.unwrap_err().code(),
            "CORE-E013"
        );
        // Back at the M1 schema, the service role has no privilege left and
        // is told to migrate.
        schema::revert(&owner, floor).await.unwrap();
        let e = schema::require_up_to_date(&app).await.unwrap_err();
        assert_eq!(e.code(), "CORE-E005", "{e}");
        app.close().await;
        owner.close().await;
        db.drop_database().await;
    });
}
