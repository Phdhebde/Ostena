//! The audit chain of the core on a real PostgreSQL server (ADR-0012; see
//! `common/mod.rs` for the environment).

#![allow(clippy::unwrap_used, reason = "test helpers")]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{TestDb, block_on};
use ostena_audit::{
    ActorKind, ChainId, Event, EventKind, Head, Options, Outcome, Record, Report, TrustedKeys,
    verify_export,
};
use ostena_core::audit::{self, Cadence, HeadSigner, ManualClock, Recorder};
use ostena_core::cache::AgentCache;
use ostena_core::schema;
use ostena_core::store::{self, PgStore};
use ostena_crypto::p256::SigningKey;
use ostena_tunnel::enroll::{AgentRegistry, TokenRecord, TokenStore};
use ostena_tunnel::{TunnelError, Uuid};
use sqlx::PgPool;

const HEARTBEAT: u32 = 60;

fn now_ms() -> u64 {
    ostena_audit::unix_now_ms()
}

fn group() -> Uuid {
    Uuid::from_bytes([0x2f; 16])
}

fn cadence() -> Cadence {
    Cadence {
        head_interval: Duration::from_secs(10),
        heartbeat_secs: HEARTBEAT,
        max_records: 1000,
    }
}

/// A migrated test database and a store on it.
async fn migrated(test: &str) -> Option<(TestDb, PgStore)> {
    let db = TestDb::create(test).await?;
    let pool = db.pool().await;
    schema::migrate(&pool).await.unwrap();
    Some((db, PgStore::new(pool, Arc::new(AgentCache::default()))))
}

struct Signer {
    signer: HeadSigner,
    key: Arc<SigningKey>,
    clock: Arc<ManualClock>,
}

impl Signer {
    fn new(pool: &PgPool, recorder: Arc<Recorder>, start_ms: u64) -> Self {
        let key = Arc::new(SigningKey::generate().unwrap().0);
        Self::with_key(pool, recorder, start_ms, key)
    }

    fn with_key(
        pool: &PgPool,
        recorder: Arc<Recorder>,
        start_ms: u64,
        key: Arc<SigningKey>,
    ) -> Self {
        let clock = Arc::new(ManualClock::new(start_ms));
        let signer = HeadSigner::new(
            pool.clone(),
            key.clone(),
            cadence(),
            clock.clone(),
            recorder,
        );
        Self { signer, key, clock }
    }

    fn keys(&self) -> TrustedKeys {
        let mut keys = TrustedKeys::new();
        keys.insert(self.key.verifying_key()).unwrap();
        keys
    }
}

fn event(n: u64) -> Event {
    Event::new(
        EventKind::CoreStarted,
        Outcome::Success,
        ActorKind::Core,
        "core",
    )
    .u64("version", n)
}

async fn append(pool: &PgPool, n: u64) -> audit::Appended {
    let mut tx = pool.begin().await.unwrap();
    let appended = audit::append(&mut tx, event(n)).await.unwrap();
    tx.commit().await.unwrap();
    appended
}

async fn count(pool: &PgPool, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
}

async fn last_event(pool: &PgPool) -> Record {
    let body: Vec<u8> =
        sqlx::query_scalar("SELECT body FROM audit_record ORDER BY seq DESC LIMIT 1")
            .fetch_one(pool)
            .await
            .unwrap();
    Record::decode(&body).unwrap()
}

async fn export_and_verify(
    pool: &PgPool,
    from_head: Option<u64>,
    keys: TrustedKeys,
    external: Vec<Head>,
) -> Report {
    let (bytes, _) = audit::export(pool, Vec::new(), from_head).await.unwrap();
    let options = Options {
        external_heads: external,
        ..Options::default()
    };
    verify_export(bytes.as_slice(), keys, options).unwrap()
}

fn codes(report: &Report) -> Vec<&'static str> {
    report.findings.iter().map(|f| f.code()).collect()
}

/// Runs `sql` as the owner with the user triggers of both tables disabled:
/// what an administrator of the database can always do (ADR-0011, single
/// role).
async fn as_owner(pool: &PgPool, sql: &str) {
    let mut tx = pool.begin().await.unwrap();
    for statement in [
        "ALTER TABLE audit_record DISABLE TRIGGER USER",
        "ALTER TABLE audit_head DISABLE TRIGGER USER",
    ] {
        sqlx::query(statement).execute(&mut *tx).await.unwrap();
    }
    sqlx::raw_sql(sqlx::AssertSqlSafe(sql.to_owned()))
        .execute(&mut *tx)
        .await
        .unwrap();
    for statement in [
        "ALTER TABLE audit_record ENABLE TRIGGER USER",
        "ALTER TABLE audit_head ENABLE TRIGGER USER",
    ] {
        sqlx::query(statement).execute(&mut *tx).await.unwrap();
    }
    tx.commit().await.unwrap();
}

#[test]
fn genesis_is_written_once_even_concurrently() {
    block_on(async {
        let Some((db, store)) = migrated("genesis_is_written_once_even_concurrently").await else {
            return;
        };
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let pool = store.pool().clone();
                tokio::spawn(async move { audit::ensure_genesis(&pool).await.unwrap() })
            })
            .collect();
        let mut ids = Vec::new();
        for task in tasks {
            ids.push(task.await.unwrap());
        }
        assert!(ids.windows(2).all(|w| w[0] == w[1]), "{ids:?}");
        assert_eq!(
            count(store.pool(), "SELECT count(*) FROM audit_record").await,
            1
        );
        let first = last_event(store.pool()).await;
        assert_eq!(
            (first.seq, first.event.as_str()),
            (1, "audit.chain_started")
        );
        assert_eq!(first.chain_id, ids[0]);
        assert_eq!(audit::ensure_genesis(store.pool()).await.unwrap(), ids[0]);
        drop(store);
        db.drop_database().await;
    });
}

#[test]
fn concurrent_appends_are_contiguous_and_verify_online() {
    block_on(async {
        let Some((db, store)) =
            migrated("concurrent_appends_are_contiguous_and_verify_online").await
        else {
            return;
        };
        audit::ensure_genesis(store.pool()).await.unwrap();
        let tasks: Vec<_> = (0..16)
            .map(|n| {
                let pool = store.pool().clone();
                tokio::spawn(async move { append(&pool, n).await.seq })
            })
            .collect();
        let mut seqs = Vec::new();
        for task in tasks {
            seqs.push(task.await.unwrap());
        }
        seqs.sort_unstable();
        assert_eq!(seqs, (2..=17).collect::<Vec<u64>>());
        let signer = Signer::new(store.pool(), store.recorder(), now_ms());
        let head = signer.signer.sign_now().await.unwrap().unwrap();
        assert_eq!((head.head_no(), head.record_seq()), (1, 17));
        let report = audit::verify_online(store.pool(), signer.keys())
            .await
            .unwrap();
        assert_eq!(codes(&report), Vec::<&str>::new());
        assert_eq!((report.exit_code(), report.records), (0, 17));
        drop(store);
        db.drop_database().await;
    });
}

#[test]
fn triggers_refuse_changes_and_wrong_numbers() {
    block_on(async {
        let Some((db, store)) = migrated("triggers_refuse_changes_and_wrong_numbers").await else {
            return;
        };
        let pool = store.pool();
        append(pool, 1).await;
        let signer = Signer::new(pool, store.recorder(), now_ms());
        signer.signer.sign_now().await.unwrap().unwrap();
        for sql in [
            "UPDATE audit_record SET event = 'x' WHERE seq = 1",
            "DELETE FROM audit_record WHERE seq = 2",
            "TRUNCATE audit_record CASCADE",
            "UPDATE audit_head SET record_seq = 1",
            "DELETE FROM audit_head",
            "TRUNCATE audit_head",
        ] {
            let e = sqlx::query(sql).execute(pool).await.unwrap_err();
            let code = e.as_database_error().unwrap().code().unwrap().into_owned();
            assert_eq!(code, "42501", "{sql}: {e}");
        }
        // The next seq only, the next head number only, never past the tip.
        let body: Vec<u8> = sqlx::query_scalar("SELECT body FROM audit_record WHERE seq = 2")
            .fetch_one(pool)
            .await
            .unwrap();
        for seq in [2_i64, 4] {
            let e = sqlx::query(
                "INSERT INTO audit_record (seq, body, hash, event) VALUES ($1, $2, $3, 'x.y')",
            )
            .bind(seq)
            .bind(&body)
            .bind(vec![0u8; 32])
            .execute(pool)
            .await
            .unwrap_err();
            let code = e.as_database_error().unwrap().code().unwrap().into_owned();
            assert!(code == "23514" || code == "23505", "{seq}: {e}");
        }
        let head: Vec<u8> = sqlx::query_scalar("SELECT body FROM audit_head WHERE head_no = 1")
            .fetch_one(pool)
            .await
            .unwrap();
        for (head_no, record_seq) in [(1_i64, 2_i64), (3, 2), (2, 9)] {
            let e = sqlx::query(
                "INSERT INTO audit_head (head_no, record_seq, body, hash) VALUES ($1, $2, $3, $4)",
            )
            .bind(head_no)
            .bind(record_seq)
            .bind(&head)
            .bind(vec![0u8; 32])
            .execute(pool)
            .await
            .unwrap_err();
            let code = e.as_database_error().unwrap().code().unwrap().into_owned();
            assert!(
                ["23514", "23505", "23503"].contains(&code.as_str()),
                "{head_no}/{record_seq}: {e}"
            );
        }
        assert_eq!(count(pool, "SELECT count(*) FROM audit_record").await, 2);
        drop(store);
        db.drop_database().await;
    });
}

#[test]
fn enrolment_and_renewal_have_their_own_records() {
    block_on(async {
        let Some((db, store)) = migrated("enrolment_and_renewal_have_their_own_records").await
        else {
            return;
        };
        let pool = store.pool().clone();
        let agent = Uuid::from_bytes([0xa1; 16]);
        store.register([1; 32], group(), agent).await.unwrap();
        let enrolled = last_event(&pool).await;
        assert_eq!(enrolled.event, "agent.enrolled");
        assert_eq!(enrolled.actor, agent.to_string());
        assert_eq!(
            enrolled.field("fingerprint"),
            Some(&ostena_audit::Value::Bytes(vec![1; 32]))
        );
        store.register([2; 32], group(), agent).await.unwrap();
        assert_eq!(last_event(&pool).await.event, "agent.certificate_renewed");
        // A refused renewal (another group) is rolled back: no record.
        let before = count(&pool, "SELECT count(*) FROM audit_record").await;
        assert_eq!(
            store
                .register([3; 32], Uuid::from_bytes([0x30; 16]), agent)
                .await,
            Err(TunnelError::Revoked)
        );
        assert_eq!(
            count(&pool, "SELECT count(*) FROM audit_record").await,
            before
        );
        // Token issuance and consumption, revocation.
        let token = store::issue_token(&pool, group(), Duration::from_mins(15))
            .await
            .unwrap();
        let issued = last_event(&pool).await;
        assert_eq!(
            (issued.event.as_str(), issued.actor_kind),
            ("enroll.token_issued", ActorKind::Admin)
        );
        store
            .decide(
                token.id(),
                Box::new(|r: &mut TokenRecord| {
                    r.used = true;
                    Ok(())
                }),
            )
            .await
            .unwrap();
        assert_eq!(last_event(&pool).await.event, "enroll.token_consumed");
        store::revoke_agent(&pool, agent).await.unwrap();
        assert_eq!(last_event(&pool).await.event, "agent.revoked");
        drop(store);
        db.drop_database().await;
    });
}

#[test]
fn granting_operations_fail_closed_protective_ones_do_not() {
    block_on(async {
        let Some((db, store)) =
            migrated("granting_operations_fail_closed_protective_ones_do_not").await
        else {
            return;
        };
        let pool = store.pool().clone();
        let known = Uuid::from_bytes([0xa1; 16]);
        store.register([1; 32], group(), known).await.unwrap();
        let token = [7; 16];
        store
            .insert(
                token,
                TokenRecord::new([4; 32], group(), now_ms() / 1000 + 600),
            )
            .await
            .unwrap();
        // From now on, no audit record can be written.
        sqlx::raw_sql(
            "CREATE FUNCTION test_refuse() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN RAISE EXCEPTION 'audit indisponible (test)'; END; $$;
             CREATE TRIGGER z_test_refuse BEFORE INSERT ON audit_record
                 FOR EACH ROW EXECUTE FUNCTION test_refuse();",
        )
        .execute(&pool)
        .await
        .unwrap();
        let records = count(&pool, "SELECT count(*) FROM audit_record").await;

        // Granting: refused, nothing committed.
        let fresh = Uuid::from_bytes([0xb2; 16]);
        assert_eq!(
            store.register([2; 32], group(), fresh).await,
            Err(TunnelError::RegistryUnavailable)
        );
        assert_eq!(count(&pool, "SELECT count(*) FROM agent").await, 1);
        assert_eq!(
            count(&pool, "SELECT count(*) FROM agent_certificate").await,
            1
        );
        let Err(e) = store::issue_token(&pool, group(), Duration::from_mins(15)).await else {
            panic!("jeton émis sans son enregistrement d'audit");
        };
        assert_eq!(e.code(), "CORE-E010");
        assert_eq!(
            count(&pool, "SELECT count(*) FROM enrollment_token").await,
            1
        );
        assert_eq!(
            store
                .decide(
                    token,
                    Box::new(|r: &mut TokenRecord| {
                        r.used = true;
                        Ok(())
                    })
                )
                .await,
            Err(TunnelError::RegistryUnavailable)
        );
        let used: bool = sqlx::query_scalar("SELECT used FROM enrollment_token")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(!used, "token spent without its record");

        // Protective: committed anyway, the failure counted.
        let failures = audit::protective_failures();
        store::revoke_agent(&pool, known).await.unwrap();
        let revoked: bool = sqlx::query_scalar(
            "SELECT revoked_at IS NOT NULL FROM agent WHERE id = $1::text::uuid",
        )
        .bind(known.to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(revoked);
        let e = store
            .decide(
                token,
                Box::new(|r: &mut TokenRecord| {
                    r.failures += 1;
                    Err(TunnelError::ProofOfPossession)
                }),
            )
            .await
            .unwrap_err();
        assert_eq!(e, TunnelError::ProofOfPossession);
        let failed: i16 = sqlx::query_scalar("SELECT failures FROM enrollment_token")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(failed, 1);
        assert!(audit::protective_failures() >= failures + 2);
        assert_eq!(
            count(&pool, "SELECT count(*) FROM audit_record").await,
            records
        );
        drop(store);
        db.drop_database().await;
    });
}

#[test]
fn heads_cover_the_tip_and_follow_the_heartbeat() {
    block_on(async {
        let Some((db, store)) = migrated("heads_cover_the_tip_and_follow_the_heartbeat").await
        else {
            return;
        };
        let pool = store.pool().clone();
        let signer = Signer::new(&pool, store.recorder(), now_ms());
        // Empty chain: nothing to sign.
        assert_eq!(signer.signer.sign_now().await.unwrap(), None);
        for n in 0..3 {
            let appended = append(&pool, n).await;
            store.recorder().critical(&[appended]);
        }
        let first = signer.signer.sign_now().await.unwrap().unwrap();
        // Genesis and three records.
        assert_eq!((first.head_no(), first.record_seq()), (1, 4));
        assert_eq!(first.heartbeat_secs(), HEARTBEAT);
        first.verify(&signer.keys()).unwrap();
        assert_eq!(audit::last_head(&pool).await.unwrap(), Some(first));
        // Nothing changed, heartbeat not due: no head.
        signer.clock.advance(Duration::from_secs(30));
        assert_eq!(signer.signer.sign_now().await.unwrap(), None);
        // Heartbeat due: a new head on the same record.
        signer
            .clock
            .advance(Duration::from_secs(u64::from(HEARTBEAT)));
        let beat = signer.signer.sign_now().await.unwrap().unwrap();
        assert_eq!((beat.head_no(), beat.record_seq()), (2, 4));
        assert_eq!(beat.prev_head_hash(), first.hash());
        // The tip moved: a head at once.
        append(&pool, 9).await;
        let moved = signer.signer.sign_now().await.unwrap().unwrap();
        assert_eq!((moved.head_no(), moved.record_seq()), (3, 5));
        let report = audit::verify_online(&pool, signer.keys()).await.unwrap();
        assert_eq!(codes(&report), Vec::<&str>::new());
        // A new signer key (rotation) anchors on heads of the previous one,
        // announced by audit.signing_started.
        let mut tx = pool.begin().await.unwrap();
        audit::append(&mut tx, signer.signer.signing_started())
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let next = Signer::new(&pool, store.recorder(), now_ms());
        let rotated = next.signer.sign_now().await.unwrap().unwrap();
        assert_eq!(rotated.head_no(), 4);
        drop(store);
        db.drop_database().await;
    });
}

/// A chain of 8 records with head 1 on record 3; the signer, a pool.
async fn chain_with_uncovered_tail(test: &str) -> Option<(TestDb, PgStore, Signer, ChainId)> {
    let (db, store) = migrated(test).await?;
    let pool = store.pool().clone();
    let chain = audit::ensure_genesis(&pool).await.unwrap();
    let signer = Signer::new(&pool, store.recorder(), now_ms());
    for n in 0..2 {
        append(&pool, n).await;
    }
    signer.signer.sign_now().await.unwrap().unwrap();
    for n in 0..5 {
        append(&pool, n).await;
    }
    Some((db, store, signer, chain))
}

#[test]
fn tampering_stops_the_signer_and_is_found_by_the_verifier() {
    block_on(async {
        // The bytes of the time of record 5 (offset 57 to 65): it still
        // decodes, but its hash changes.
        let edit = "UPDATE audit_record SET body = overlay(body placing '\\xffff'::bytea from 60 for 2) WHERE seq = 5";
        let cases: [(&str, &str, &[&str]); 4] = [
            ("edit", edit, &["AUD-E007"]),
            (
                "delete",
                "DELETE FROM audit_record WHERE seq = 5",
                &["AUD-E006"],
            ),
            (
                "swap",
                "UPDATE audit_record SET seq = seq + 1000 WHERE seq IN (5, 6);
                 UPDATE audit_record SET seq = 6 WHERE seq = 1005;
                 UPDATE audit_record SET seq = 5 WHERE seq = 1006;",
                &["AUD-E006"],
            ),
            ("insert", "", &["AUD-E007"]),
        ];
        for (name, sql, expected) in cases {
            let Some((db, store, signer, chain)) =
                chain_with_uncovered_tail(&format!("tampering_{name}")).await
            else {
                return;
            };
            let pool = store.pool().clone();
            if name == "insert" {
                // A record forged at the tip, linked to nothing.
                let body = event(99)
                    .into_record(chain, 9, [7; 32], now_ms())
                    .unwrap()
                    .encode()
                    .unwrap();
                let hash = ostena_audit::record_hash(&body);
                let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
                as_owner(
                    &pool,
                    &format!(
                        "INSERT INTO audit_record (seq, body, hash, event) VALUES (9, '\\x{}', '\\x{}', 'core.started')",
                        hex(&body),
                        hex(&hash)
                    ),
                )
                .await;
            } else {
                as_owner(&pool, sql).await;
            }
            let e = signer.signer.sign_now().await.unwrap_err();
            assert_eq!(e.code(), "CORE-E011", "{name}: {e}");
            assert!(signer.signer.is_broken());
            // Stopped for good, even if asked again.
            assert_eq!(
                signer.signer.sign_now().await.unwrap_err().code(),
                "CORE-E011"
            );
            let report = export_and_verify(&pool, None, signer.keys(), Vec::new()).await;
            assert_eq!(report.exit_code(), 1, "{name}: {:?}", codes(&report));
            for code in expected {
                assert!(report.has(code), "{name}: {:?}", codes(&report));
            }
            drop(store);
            db.drop_database().await;
        }
    });
}

#[test]
fn records_written_by_the_core_are_checked_before_signing() {
    block_on(async {
        let Some((db, store, signer, _)) =
            chain_with_uncovered_tail("records_written_by_the_core_are_checked_before_signing")
                .await
        else {
            return;
        };
        let pool = store.pool().clone();
        let mine = append(&pool, 42).await;
        store.recorder().critical(&[mine]);
        // Rewritten consistently (hash column and next links): only the
        // memory of the core sees it.
        let body = event(43)
            .into_record(
                last_event(&pool).await.chain_id,
                mine.seq,
                last_event(&pool).await.prev_hash,
                now_ms(),
            )
            .unwrap()
            .encode()
            .unwrap();
        let hash = ostena_audit::record_hash(&body);
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        as_owner(
            &pool,
            &format!(
                "UPDATE audit_record SET body = '\\x{}', hash = '\\x{}' WHERE seq = {}",
                hex(&body),
                hex(&hash),
                mine.seq
            ),
        )
        .await;
        let e = signer.signer.sign_now().await.unwrap_err();
        assert_eq!(e.code(), "CORE-E011");
        assert!(e.to_string().contains("écrit par le core"), "{e}");
        drop(store);
        db.drop_database().await;
    });
}

#[test]
fn an_acknowledged_break_lets_the_signer_resume() {
    block_on(async {
        let Some((db, store, signer, _)) =
            chain_with_uncovered_tail("an_acknowledged_break_lets_the_signer_resume").await
        else {
            return;
        };
        let pool = store.pool().clone();
        as_owner(&pool, "DELETE FROM audit_record WHERE seq = 5").await;
        assert_eq!(
            signer.signer.sign_now().await.unwrap_err().code(),
            "CORE-E011"
        );
        // An acknowledgement before the break does not count.
        let ack = audit::acknowledge_break(&pool, 7).await.unwrap();
        let fresh = Signer::with_key(
            &pool,
            Arc::new(Recorder::new()),
            now_ms(),
            signer.key.clone(),
        );
        assert_eq!(
            fresh.signer.sign_now().await.unwrap_err().code(),
            "CORE-E011"
        );
        let ack2 = audit::acknowledge_break(&pool, 5).await.unwrap();
        assert!(ack2.seq > ack.seq);
        let fresh = Signer::with_key(
            &pool,
            Arc::new(Recorder::new()),
            now_ms(),
            signer.key.clone(),
        );
        let head = fresh.signer.sign_now().await.unwrap().unwrap();
        assert_eq!(head.record_seq(), ack2.seq);
        // The break stays visible to any verifier.
        let report = export_and_verify(&pool, None, signer.keys(), Vec::new()).await;
        assert!(report.has("AUD-E006"), "{:?}", codes(&report));
        drop(store);
        db.drop_database().await;
    });
}

#[test]
fn tail_truncation_needs_an_external_head_or_freshness() {
    block_on(async {
        let Some((db, store)) =
            migrated("tail_truncation_needs_an_external_head_or_freshness").await
        else {
            return;
        };
        let pool = store.pool().clone();
        // Heads signed an hour ago (heartbeat 60 s).
        let signer = Signer::new(&pool, store.recorder(), now_ms() - 3_600_000);
        for n in 0..3 {
            append(&pool, n).await;
        }
        let kept = signer.signer.sign_now().await.unwrap().unwrap();
        for n in 0..3 {
            append(&pool, n).await;
        }
        signer.clock.advance(Duration::from_secs(1));
        let lost = signer.signer.sign_now().await.unwrap().unwrap();
        assert_eq!((kept.record_seq(), lost.record_seq()), (4, 7));
        // The owner removes the tail and the head that covers it.
        as_owner(
            &pool,
            "DELETE FROM audit_head WHERE head_no = 2; DELETE FROM audit_record WHERE seq > 4",
        )
        .await;
        // Consistent on its own: only the age of the last head shows it.
        let report = export_and_verify(&pool, None, signer.keys(), Vec::new()).await;
        assert_eq!(codes(&report), ["AUD-W004"]);
        assert_eq!(report.exit_code(), 2);
        // With the head kept outside the bastion: a truncation.
        let report = export_and_verify(&pool, None, signer.keys(), vec![lost]).await;
        assert!(report.has("AUD-E013"), "{:?}", codes(&report));
        assert_eq!(report.exit_code(), 1);
        drop(store);
        db.drop_database().await;
    });
}

#[test]
fn partial_export_verifies_from_its_anchor() {
    block_on(async {
        let Some((db, store)) = migrated("partial_export_verifies_from_its_anchor").await else {
            return;
        };
        let pool = store.pool().clone();
        let signer = Signer::new(&pool, store.recorder(), now_ms());
        for n in 0..3 {
            append(&pool, n).await;
        }
        let anchor = signer.signer.sign_now().await.unwrap().unwrap();
        for n in 0..4 {
            append(&pool, n).await;
        }
        let last = signer.signer.sign_now().await.unwrap().unwrap();
        let (bytes, summary) = audit::export(&pool, Vec::new(), Some(anchor.head_no()))
            .await
            .unwrap();
        assert_eq!(
            (
                summary.first_seq,
                summary.last_seq,
                summary.records,
                summary.heads
            ),
            (5, Some(8), 4, 2)
        );
        let report = verify_export(bytes.as_slice(), signer.keys(), Options::default()).unwrap();
        assert_eq!(codes(&report), Vec::<&str>::new());
        assert_eq!(report.covered_seq, Some(last.record_seq()));
        // Unknown head; full export of the same chain.
        assert_eq!(
            audit::export(&pool, Vec::new(), Some(9))
                .await
                .unwrap_err()
                .code(),
            "CORE-E009"
        );
        let report = export_and_verify(&pool, None, signer.keys(), Vec::new()).await;
        assert_eq!(
            (report.exit_code(), report.records, report.heads),
            (0, 8, 2)
        );
        audit::record_export(&pool, &summary).await.unwrap();
        assert_eq!(last_event(&pool).await.event, "audit.exported");
        drop(store);
        db.drop_database().await;
    });
}

#[test]
fn best_effort_events_are_written_and_losses_reported() {
    block_on(async {
        let Some((db, store)) =
            migrated("best_effort_events_are_written_and_losses_reported").await
        else {
            return;
        };
        let pool = store.pool().clone();
        let recorder = store.recorder();
        // No writer yet: the queue fills, then events are counted as lost.
        for n in 0..(audit::QUEUE_CAPACITY as u64 + 2) {
            recorder.emit(event(n));
        }
        assert_eq!(recorder.lost(), 2);
        let writer = tokio::spawn(audit::run_writer(pool.clone(), recorder.clone()));
        assert!(recorder.flush(Duration::from_secs(10)).await);
        let deadline = Instant::now() + Duration::from_secs(10);
        while recorder.lost() > 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(recorder.lost(), 0);
        let lost: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_record WHERE event = 'audit.events_lost'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(lost, 1);
        // Genesis, the lost-events record, the queued events.
        assert_eq!(
            count(&pool, "SELECT count(*) FROM audit_record").await,
            2 + audit::QUEUE_CAPACITY as i64
        );
        writer.abort();
        let signer = Signer::new(&pool, Arc::new(Recorder::new()), now_ms());
        signer.signer.sign_now().await.unwrap().unwrap();
        let report = audit::verify_online(&pool, signer.keys()).await.unwrap();
        assert_eq!(report.exit_code(), 0, "{:?}", codes(&report));
        drop(store);
        db.drop_database().await;
    });
}

/// Measures what the granting record adds to an enrolment: run with
/// `--ignored --nocapture`.
#[test]
#[ignore = "measurement"]
fn measure_registration_latency() {
    block_on(async {
        let Some((db, store)) = migrated("measure_registration_latency").await else {
            return;
        };
        let pool = store.pool().clone();
        audit::ensure_genesis(&pool).await.unwrap();
        let n: u32 = 200;
        let start = Instant::now();
        for i in 0..n {
            let mut fp = [0u8; 32];
            fp[..4].copy_from_slice(&i.to_be_bytes());
            let agent = Uuid::from_bytes([
                fp[0], fp[1], fp[2], fp[3], 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
            ]);
            store.register(fp, group(), agent).await.unwrap();
        }
        let register = start.elapsed() / n;
        // The same statements as register, without the audit record.
        let start = Instant::now();
        for i in 0..n {
            let mut tx = pool.begin().await.unwrap();
            let agent = format!("00000000-0000-4000-8000-{i:012x}");
            sqlx::query("INSERT INTO agent (id, gateway_group) VALUES ($1::text::uuid, $2::text::uuid) ON CONFLICT (id) DO NOTHING")
                .bind(&agent)
                .bind(group().to_string())
                .execute(&mut *tx)
                .await
                .unwrap();
            let mut fp = vec![7u8; 32];
            fp[..4].copy_from_slice(&i.to_be_bytes());
            sqlx::query("INSERT INTO agent_certificate (fingerprint, agent_id) SELECT $1, id FROM agent WHERE id = $2::text::uuid AND gateway_group = $3::text::uuid AND revoked_at IS NULL")
                .bind(fp)
                .bind(&agent)
                .bind(group().to_string())
                .execute(&mut *tx)
                .await
                .unwrap();
            sqlx::query("SELECT pg_notify('x', 'registered')")
                .execute(&mut *tx)
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }
        let baseline = start.elapsed() / n;
        let start = Instant::now();
        for i in 0..n {
            append(&pool, u64::from(i)).await;
        }
        let append_only = start.elapsed() / n;
        let signer = Signer::new(&pool, store.recorder(), now_ms());
        let start = Instant::now();
        signer.signer.sign_now().await.unwrap().unwrap();
        let first_head = start.elapsed();
        eprintln!(
            "register with agent.enrolled: {register:?} per call; same statements without the \
             record: {baseline:?}; audit append alone (own transaction): {append_only:?}; \
             first head over {} records: {first_head:?}",
            3 * n + 1
        );
        drop(store);
        db.drop_database().await;
    });
}
