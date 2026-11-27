//! Export of the audit chain to a syslog collector over TLS (RFC 5425, OCSF
//! events), on a real PostgreSQL server (ADR-0012; see `common/mod.rs` for
//! the environment). The collector is a local TLS listener of the test
//! PKI: everything runs offline.

#![allow(clippy::unwrap_used, reason = "test helpers")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{TestDb, block_on};
use ostena_audit::siem::{FrameDecoder, parse_message};
use ostena_audit::{ActorKind, Event, EventKind, Outcome, Record, Value, field};
use ostena_core::audit;
use ostena_core::cache::AgentCache;
use ostena_core::forwarding::Forwarder;
use ostena_core::store::PgStore;
use ostena_crypto::tls::ServerName;
use ostena_crypto::tls::syslog::syslog_client_config;
use ostena_crypto::tls::syslog::testing::collector_config;
use ostena_crypto::tls::target::testing::{KeyKind, TargetCa, Usage};
use sqlx::PgPool;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;

/// A collector on 127.0.0.1 that sends every message it reads, as text;
/// its listener task, to stop it.
async fn collector(
    ca: &TargetCa,
) -> (
    u16,
    mpsc::UnboundedReceiver<String>,
    tokio::task::JoinHandle<()>,
) {
    let identity = ca
        .issue(KeyKind::EcdsaP256, &["siem.test"], Some(Usage::ServerAuth))
        .unwrap();
    let acceptor = TlsAcceptor::from(collector_config(&identity, None, false).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let (acceptor, tx) = (acceptor.clone(), tx.clone());
            connections.spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut decoder = FrameDecoder::new();
                let mut buffer = [0u8; 8192];
                while let Ok(n) = tls.read(&mut buffer).await {
                    if n == 0 {
                        return;
                    }
                    decoder.push(&buffer[..n]);
                    while let Some(message) = decoder.next_message().unwrap() {
                        let _ = tx.send(String::from_utf8(message).unwrap());
                    }
                }
            });
        }
    });
    (port, rx, task)
}

fn forwarder(port: u16, ca: &TargetCa) -> Forwarder {
    Forwarder::new(
        format!("siem.test:{port}"),
        "127.0.0.1".into(),
        port,
        ServerName::try_from("siem.test").unwrap(),
        syslog_client_config(&[ca.anchor()], None).unwrap(),
        "core-test".into(),
    )
    .with_position_interval(Duration::from_millis(200))
}

async fn append(pool: &PgPool, n: u64) {
    let mut tx = pool.begin().await.unwrap();
    audit::append(
        &mut tx,
        Event::new(
            EventKind::CoreStarted,
            Outcome::Success,
            ActorKind::Core,
            "core",
        )
        .u64("version", n),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

/// The seq of a received message, read from its OCSF `metadata.sequence`.
fn sequence(message: &str) -> u64 {
    let parsed = parse_message(message.as_bytes()).unwrap();
    assert_eq!(
        (parsed.facility, parsed.app_name, parsed.msg_id),
        (13, "ostena", "audit")
    );
    assert_eq!(parsed.hostname, "core-test");
    let json = std::str::from_utf8(parsed.msg).unwrap();
    let after = json.split("\"sequence\":").nth(1).unwrap();
    after
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

/// Receives messages until `seq` arrives; their seqs in order.
async fn until(rx: &mut mpsc::UnboundedReceiver<String>, seq: u64) -> Vec<u64> {
    let mut seqs = Vec::new();
    let received = tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(message) = rx.recv().await {
            let s = sequence(&message);
            seqs.push(s);
            if s == seq {
                return;
            }
        }
    })
    .await;
    assert!(received.is_ok(), "seq {seq} non reçu : {seqs:?}");
    seqs
}

async fn tail(pool: &PgPool) -> u64 {
    let seq: i64 = sqlx::query_scalar("SELECT max(seq) FROM audit_record")
        .fetch_one(pool)
        .await
        .unwrap();
    u64::try_from(seq).unwrap()
}

async fn last_of(pool: &PgPool, event: &str) -> Option<Record> {
    let body: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT body FROM audit_record WHERE event = $1 ORDER BY seq DESC LIMIT 1",
    )
    .bind(event)
    .fetch_optional(pool)
    .await
    .unwrap();
    body.map(|b| Record::decode(&b).unwrap())
}

#[test]
fn the_chain_reaches_the_collector_in_order_and_resumes_after_its_position() {
    block_on(async {
        let Some(db) = TestDb::create(
            "the_chain_reaches_the_collector_in_order_and_resumes_after_its_position",
        )
        .await
        else {
            return;
        };
        db.migrate().await;
        let store = PgStore::new(db.pool().await, Arc::new(AgentCache::default()));
        let pool = store.pool().clone();
        audit::ensure_genesis(&pool).await.unwrap();
        let writer = tokio::spawn(audit::run_writer(pool.clone(), store.recorder()));
        for n in 0..5 {
            append(&pool, n).await;
        }
        let ca = TargetCa::new("siem ca").unwrap();
        let (port, mut rx, server) = collector(&ca).await;
        let forwarder = forwarder(port, &ca);
        assert_eq!(forwarder.position(&pool).await.unwrap(), 0);
        let task = forwarder.clone().spawn(pool.clone(), store.recorder());

        // Everything, in order, from the first record.
        let end = tail(&pool).await;
        assert_eq!(until(&mut rx, end).await, (1..=end).collect::<Vec<_>>());
        // The position is recorded in the chain, then exported too.
        let position = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let p = forwarder.position(&pool).await.unwrap();
                if p >= end {
                    return p;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
        let record = last_of(&pool, EventKind::AuditForwarded.name())
            .await
            .unwrap();
        assert_eq!(
            record.field(field::DESTINATION),
            Some(&Value::Text(format!("siem.test:{port}")))
        );
        let forwarded_seq = record.seq;
        until(&mut rx, forwarded_seq).await;

        // The collector goes away; the export resumes after the position
        // with a new collector at the same address, losing nothing.
        task.abort();
        server.abort();
        drop(rx);
        for n in 5..8 {
            append(&pool, n).await;
        }
        let (port2, mut rx2, server2) = collector(&ca).await;
        let again = Forwarder::new(
            format!("siem.test:{port}"),
            "127.0.0.1".into(),
            port2,
            ServerName::try_from("siem.test").unwrap(),
            syslog_client_config(&[ca.anchor()], None).unwrap(),
            "core-test".into(),
        );
        assert_eq!(again.position(&pool).await.unwrap(), position);
        let task2 = again.spawn(pool.clone(), store.recorder());
        let end2 = tail(&pool).await;
        let seqs = until(&mut rx2, end2).await;
        assert_eq!(seqs, (position + 1..=end2).collect::<Vec<_>>());
        task2.abort();
        server2.abort();
        drop(writer);
        drop(store);
        db.drop_database().await;
    });
}

#[test]
fn an_untrusted_collector_is_refused_and_recorded_once() {
    block_on(async {
        let Some(db) = TestDb::create("an_untrusted_collector_is_refused_and_recorded_once").await
        else {
            return;
        };
        db.migrate().await;
        let store = PgStore::new(db.pool().await, Arc::new(AgentCache::default()));
        let pool = store.pool().clone();
        audit::ensure_genesis(&pool).await.unwrap();
        let _writer = tokio::spawn(audit::run_writer(pool.clone(), store.recorder()));
        let ca = TargetCa::new("siem ca").unwrap();
        let other = TargetCa::new("other ca").unwrap();
        let (port, mut rx, server) = collector(&ca).await;
        let task = forwarder(port, &other).spawn(pool.clone(), store.recorder());
        let record = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(r) = last_of(&pool, EventKind::AuditForwardFailed.name()).await {
                    return r;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            record.field(field::CODE),
            Some(&Value::Text("SYS-E001".into()))
        );
        // A second attempt (after a second) is logged, not recorded again.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_record WHERE event = 'audit.forward_failed'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 1);
        assert!(
            rx.try_recv().is_err(),
            "rien n'est envoyé à un collecteur refusé"
        );
        task.abort();
        server.abort();
        drop(store);
        db.drop_database().await;
    });
}
