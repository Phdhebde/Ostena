//! RFC 3161 time-stamps of the heads against a local authority over HTTP,
//! on a real PostgreSQL server (ADR-0012; see `common/mod.rs` for the
//! environment). Everything runs offline: the authority is `TestTsa`.

#![allow(clippy::unwrap_used, reason = "test helpers")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{TestDb, block_on};
use ostena_audit::{EventKind, TrustedKeys, field, timestamp};
use ostena_common::config::HttpTarget;
use ostena_core::audit::{self, Cadence, HeadSigner, ManualClock};
use ostena_core::cache::AgentCache;
use ostena_core::store::PgStore;
use ostena_core::timestamping::{StampError, Timestamper, failed_event};
use ostena_crypto::p256::SigningKey;
use ostena_crypto::tsp::testing::TestTsa;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// How the local authority answers.
#[derive(Clone, Copy)]
enum Answer {
    Granted,
    Status500,
}

/// A local authority on 127.0.0.1: one answer per connection.
async fn serve(tsa: Arc<TestTsa>, answer: Answer) -> HttpTarget {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let tsa = tsa.clone();
            tokio::spawn(async move {
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 4096];
                let (end, length) = loop {
                    let n = tcp.read(&mut chunk).await.unwrap();
                    assert!(n > 0, "requête tronquée");
                    buffer.extend_from_slice(&chunk[..n]);
                    if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buffer[..end]).to_lowercase();
                        assert!(head.starts_with("post /tsa http/1.1"), "{head}");
                        assert!(head.contains("content-type: application/timestamp-query"));
                        let length = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length: "))
                            .unwrap()
                            .trim()
                            .parse::<usize>()
                            .unwrap();
                        break (end + 4, length);
                    }
                };
                while buffer.len() < end + length {
                    let n = tcp.read(&mut chunk).await.unwrap();
                    assert!(n > 0, "corps tronqué");
                    buffer.extend_from_slice(&chunk[..n]);
                }
                let (status, body) = match answer {
                    Answer::Granted => (
                        "200 OK",
                        tsa.respond(&buffer[end..end + length], ostena_audit::unix_now_ms()),
                    ),
                    Answer::Status500 => ("500 Internal Server Error", Vec::new()),
                };
                let head = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/timestamp-reply\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                tcp.write_all(head.as_bytes()).await.unwrap();
                tcp.write_all(&body).await.unwrap();
                let _ = tcp.shutdown().await;
            });
        }
    });
    HttpTarget {
        host: "127.0.0.1".into(),
        port,
        path: "/tsa".into(),
    }
}

fn timestamper(target: HttpTarget, tsa: &TestTsa) -> Timestamper {
    Timestamper::new(
        target,
        tsa.trust(),
        Duration::from_secs(60),
        Duration::from_secs(5),
    )
}

#[test]
fn the_last_head_is_stamped_recorded_and_verified() {
    block_on(async {
        let Some(db) = TestDb::create("the_last_head_is_stamped_recorded_and_verified").await
        else {
            return;
        };
        db.migrate().await;
        let store = PgStore::new(db.pool().await, Arc::new(AgentCache::default()));
        let pool = store.pool().clone();
        audit::ensure_genesis(&pool).await.unwrap();
        let key = Arc::new(SigningKey::generate().unwrap().0);
        let signer = HeadSigner::new(
            pool.clone(),
            key.clone(),
            Cadence {
                head_interval: Duration::from_secs(10),
                heartbeat_secs: 60,
                max_records: 1000,
            },
            Arc::new(ManualClock::new(ostena_audit::unix_now_ms())),
            store.recorder(),
        );
        let mut keys = TrustedKeys::new();
        keys.insert(key.verifying_key()).unwrap();
        let tsa = Arc::new(TestTsa::new());
        let stamper = timestamper(serve(tsa.clone(), Answer::Granted).await, &tsa);

        // No head yet: nothing to stamp.
        assert!(
            stamper
                .stamp_last_head(&pool, None)
                .await
                .unwrap()
                .is_none()
        );
        let head = signer.sign_now().await.unwrap().unwrap();
        let (head_no, event) = stamper.stamp_last_head(&pool, None).await.unwrap().unwrap();
        assert_eq!(head_no, head.head_no());
        // The head stamped last is not stamped again.
        assert!(
            stamper
                .stamp_last_head(&pool, Some(head_no))
                .await
                .unwrap()
                .is_none()
        );
        let mut tx = pool.begin().await.unwrap();
        let appended = audit::append(&mut tx, event).await.unwrap();
        tx.commit().await.unwrap();
        signer.sign_now().await.unwrap().unwrap();

        // The record carries the token, which verifies on its own.
        let body: Vec<u8> = sqlx::query_scalar("SELECT body FROM audit_record WHERE seq = $1")
            .bind(i64::try_from(appended.seq).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
        let record = ostena_audit::Record::decode(&body).unwrap();
        assert_eq!(record.event, EventKind::AuditHeadTimestamped.name());
        let token = timestamp::Stamped::of(&record).unwrap().unwrap();
        assert_eq!(token.head_hash, head.hash());
        token.verify(&tsa.trust()).unwrap();

        // Online verification with the anchors of the authority.
        let report = audit::verify_online(&pool, keys.clone(), Some(tsa.trust()))
            .await
            .unwrap();
        assert!(report.findings.is_empty(), "{:?}", report.findings);
        assert_eq!((report.timestamps, report.timestamps_verified), (1, 1));
        assert_eq!(report.last_timestamp.map(|(h, _)| h), Some(head_no));
        // Another authority: the token is refused (AUD-E021).
        let other = TestTsa::new();
        let report = audit::verify_online(&pool, keys, Some(other.trust()))
            .await
            .unwrap();
        let codes: Vec<_> = report
            .findings
            .iter()
            .map(ostena_audit::Finding::code)
            .collect();
        assert_eq!(codes, ["AUD-E021"]);
        drop(store);
        db.drop_database().await;
    });
}

#[test]
fn failures_have_their_codes_and_are_recorded() {
    block_on(async {
        let Some(db) = TestDb::create("failures_have_their_codes_and_are_recorded").await else {
            return;
        };
        db.migrate().await;
        let store = PgStore::new(db.pool().await, Arc::new(AgentCache::default()));
        let pool = store.pool().clone();
        audit::ensure_genesis(&pool).await.unwrap();
        let key = Arc::new(SigningKey::generate().unwrap().0);
        let signer = HeadSigner::new(
            pool.clone(),
            key,
            Cadence {
                head_interval: Duration::from_secs(10),
                heartbeat_secs: 60,
                max_records: 1000,
            },
            Arc::new(ManualClock::new(ostena_audit::unix_now_ms())),
            store.recorder(),
        );
        signer.sign_now().await.unwrap().unwrap();
        let tsa = Arc::new(TestTsa::new());

        // An HTTP error: unreachable (TSP-E007).
        let refusing = timestamper(serve(tsa.clone(), Answer::Status500).await, &tsa);
        let e = refusing.stamp_last_head(&pool, None).await.unwrap_err();
        assert_eq!(e.code(), "TSP-E007");
        assert!(e.to_string().contains("500"), "{e}");
        // Nobody listening: unreachable.
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = HttpTarget {
            host: "127.0.0.1".into(),
            port: closed.local_addr().unwrap().port(),
            path: "/tsa".into(),
        };
        drop(closed);
        let e = timestamper(target, &tsa)
            .stamp_last_head(&pool, None)
            .await
            .unwrap_err();
        assert!(matches!(e, StampError::Unreachable(_)), "{e:?}");
        // An authority that is not trusted: refused (TSP-E005).
        let other = TestTsa::new();
        let untrusted = timestamper(serve(tsa.clone(), Answer::Granted).await, &other);
        let e = untrusted.stamp_last_head(&pool, None).await.unwrap_err();
        assert_eq!(e.code(), "TSP-E005");
        // The record of a failure.
        let event = failed_event(&e);
        let mut tx = pool.begin().await.unwrap();
        let appended = audit::append(&mut tx, event).await.unwrap();
        tx.commit().await.unwrap();
        let body: Vec<u8> = sqlx::query_scalar("SELECT body FROM audit_record WHERE seq = $1")
            .bind(i64::try_from(appended.seq).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
        let record = ostena_audit::Record::decode(&body).unwrap();
        assert_eq!(record.event, EventKind::AuditTimestampFailed.name());
        assert_eq!(
            record.field(field::CODE),
            Some(&ostena_audit::Value::Text("TSP-E005".into()))
        );
        drop(store);
        db.drop_database().await;
    });
}
