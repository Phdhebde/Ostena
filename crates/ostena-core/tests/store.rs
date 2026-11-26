//! The registry and the tokens on a real PostgreSQL server (see
//! `common/mod.rs` for the environment).

#![allow(clippy::unwrap_used, reason = "test helpers")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{TestDb, block_on};
use ostena_common::config::Mode;
use ostena_core::cache::AgentCache;
use ostena_core::schema::{self, SchemaState};
use ostena_core::store::{self, CHANNEL, Notice, PgStore};
use ostena_core::{CoreError, db};
use ostena_crypto::tls::{ClientAuthorizer, ClientRefusal};
use ostena_tunnel::enroll::{AgentRegistry, TokenRecord, TokenStore};
use ostena_tunnel::{TunnelError, Uuid};
use sqlx::postgres::PgListener;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn group() -> Uuid {
    Uuid::from_bytes([0x2f; 16])
}

/// A migrated test database and a store on it.
async fn migrated(test: &str) -> Option<(TestDb, PgStore)> {
    let db = TestDb::create(test).await?;
    db.migrate().await;
    let pool = db.pool().await;
    // As `ostena core run` does before anything is audited.
    ostena_core::audit::ensure_genesis(&pool).await.unwrap();
    Some((db, PgStore::new(pool, Arc::new(AgentCache::default()))))
}

#[test]
fn production_refuses_a_server_that_asks_for_a_password() {
    block_on(async {
        let Some(db) = TestDb::create("production_refuses_a_server_that_asks_for_a_password").await
        else {
            return;
        };
        if db.config.tcp.is_some() {
            // The local container authenticates TCP clients by SCRAM.
            let e = db::connect(&db.config, Mode::Production, db::Role::App)
                .await
                .unwrap_err();
            assert!(
                matches!(e, CoreError::NotPeer(ref m) if m.starts_with("scram")),
                "{e}"
            );
        } else {
            // CI: the socket with peer is accepted in production.
            let pool = db::connect(&db.config, Mode::Production, db::Role::App)
                .await
                .unwrap();
            pool.close().await;
        }
        db.drop_database().await;
    });
}

#[test]
fn migrations_apply_once_and_are_checked() {
    block_on(async {
        let Some(db) = TestDb::create("migrations_apply_once_and_are_checked").await else {
            return;
        };
        let pool = db.pool().await;
        assert!(matches!(
            schema::state(&pool).await.unwrap(),
            SchemaState::Pending(_)
        ));
        assert_eq!(
            schema::require_up_to_date(&pool).await.unwrap_err().code(),
            "CORE-E005"
        );
        // The service role never changes the schema.
        assert_eq!(
            schema::migrate(&pool).await.unwrap_err().code(),
            "CORE-E013"
        );
        let owner = db.owner_pool().await;
        assert_ne!(schema::migrate(&owner).await.unwrap(), Vec::<i64>::new());
        assert_eq!(schema::migrate(&owner).await.unwrap(), Vec::<i64>::new());
        owner.close().await;
        assert_eq!(schema::state(&pool).await.unwrap(), SchemaState::UpToDate);
        schema::require_up_to_date(&pool).await.unwrap();
        pool.close().await;
        db.drop_database().await;
    });
}

#[test]
fn a_token_is_spent_once_even_under_concurrent_attempts() {
    block_on(async {
        let Some((db, store)) =
            migrated("a_token_is_spent_once_even_under_concurrent_attempts").await
        else {
            return;
        };
        let id = [1; 16];
        store
            .insert(id, TokenRecord::new([2; 32], group(), now() + 600))
            .await
            .unwrap();
        let attempts = (0..8).map(|_| {
            let store = store.clone();
            tokio::spawn(async move {
                store
                    .decide(
                        id,
                        Box::new(|r: &mut TokenRecord| {
                            if r.used {
                                return Err(TunnelError::TokenUsed);
                            }
                            r.used = true;
                            Ok(())
                        }),
                    )
                    .await
            })
        });
        let mut spent = 0;
        for attempt in attempts.collect::<Vec<_>>() {
            match attempt.await.unwrap() {
                Ok(()) => spent += 1,
                Err(e) => assert_eq!(e, TunnelError::TokenUsed),
            }
        }
        assert_eq!(spent, 1);
        drop(store);
        db.drop_database().await;
    });
}

#[test]
fn a_failed_decision_is_stored_too() {
    block_on(async {
        let Some((db, store)) = migrated("a_failed_decision_is_stored_too").await else {
            return;
        };
        let id = [3; 16];
        store
            .insert(id, TokenRecord::new([4; 32], group(), now() + 600))
            .await
            .unwrap();
        for expected in 1..=3u8 {
            let e = store
                .decide(
                    id,
                    Box::new(move |r: &mut TokenRecord| {
                        r.failures += 1;
                        r.burned = r.failures >= 3;
                        assert_eq!(r.failures, expected);
                        Err(TunnelError::ProofOfPossession)
                    }),
                )
                .await
                .unwrap_err();
            assert_eq!(e, TunnelError::ProofOfPossession);
        }
        // Burned: no longer valid, so the listener has nothing to wait for.
        assert_eq!(store.next_expiry(now()).await.unwrap(), None);
        let unknown = store.decide([9; 16], Box::new(|_| Ok(()))).await;
        assert_eq!(unknown, Err(TunnelError::TokenUnknown));
        drop(store);
        db.drop_database().await;
    });
}

#[test]
fn next_expiry_skips_used_burned_and_expired_tokens() {
    block_on(async {
        let Some((db, store)) = migrated("next_expiry_skips_used_burned_and_expired_tokens").await
        else {
            return;
        };
        let t = now();
        let mut used = TokenRecord::new([0; 32], group(), t + 100);
        used.used = true;
        let mut burned = TokenRecord::new([0; 32], group(), t + 200);
        burned.burned = true;
        // insert() stores a fresh token: mark them through decide().
        for (id, record) in [(1u8, used), (2, burned)] {
            store.insert([id; 16], record).await.unwrap();
            store
                .decide(
                    [id; 16],
                    Box::new(move |r: &mut TokenRecord| {
                        *r = record;
                        Ok(())
                    }),
                )
                .await
                .unwrap();
        }
        store
            .insert([3; 16], TokenRecord::new([0; 32], group(), t + 300))
            .await
            .unwrap();
        store
            .insert([4; 16], TokenRecord::new([0; 32], group(), t + 1))
            .await
            .unwrap();
        assert_eq!(store.next_expiry(t).await.unwrap(), Some(t + 1));
        assert_eq!(store.next_expiry(t + 1).await.unwrap(), Some(t + 300));
        assert_eq!(store.next_expiry(t + 300).await.unwrap(), None);
        drop(store);
        db.drop_database().await;
    });
}

#[test]
fn registration_revocation_and_reload() {
    block_on(async {
        let Some((db, store)) = migrated("registration_revocation_and_reload").await else {
            return;
        };
        let cache = store.cache();
        store.reload().await.unwrap();
        let agent = Uuid::from_bytes([0xa1; 16]);
        store.register([1; 32], group(), agent).await.unwrap();
        // Renewal: a second certificate for the same agent.
        store.register([2; 32], group(), agent).await.unwrap();
        assert_eq!(cache.authorize(&[1; 32]), Ok(()));
        // Another group for the same agent is refused.
        let other = Uuid::from_bytes([0x30; 16]);
        assert_eq!(
            store.register([3; 32], other, agent).await,
            Err(TunnelError::Revoked)
        );

        let agents = store::list_agents(store.pool()).await.unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!((agents[0].id, agents[0].certificates), (agent, 2));
        assert_eq!(agents[0].revoked_at, None);

        let mut notices = PgListener::connect_with(store.pool()).await.unwrap();
        notices.listen(CHANNEL).await.unwrap();
        store::revoke_agent(store.pool(), agent).await.unwrap();
        let notice = tokio::time::timeout(Duration::from_secs(5), notices.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            Notice::parse(notice.payload()),
            Some(Notice::Revoked(agent))
        );
        // Revoking again changes nothing; an unknown agent is reported.
        store::revoke_agent(store.pool(), agent).await.unwrap();
        assert_eq!(
            store::revoke_agent(store.pool(), Uuid::from_bytes([0xee; 16]))
                .await
                .unwrap_err()
                .code(),
            "CORE-E009"
        );

        store.reload().await.unwrap();
        assert_eq!(cache.authorize(&[1; 32]), Err(ClientRefusal::Revoked));
        assert_eq!(cache.authorize(&[2; 32]), Err(ClientRefusal::Revoked));
        assert_eq!(
            store.register([4; 32], group(), agent).await,
            Err(TunnelError::Revoked)
        );
        assert!(
            store::list_agents(store.pool()).await.unwrap()[0]
                .revoked_at
                .is_some()
        );
        drop(notices);
        drop(store);
        db.drop_database().await;
    });
}

#[test]
fn a_token_issued_by_another_process_is_notified() {
    block_on(async {
        let Some((db, store)) = migrated("a_token_issued_by_another_process_is_notified").await
        else {
            return;
        };
        let mut notices = PgListener::connect_with(store.pool()).await.unwrap();
        notices.listen(CHANNEL).await.unwrap();
        let token = store::issue_token(store.pool(), group(), Duration::from_mins(15))
            .await
            .unwrap();
        let notice = tokio::time::timeout(Duration::from_secs(5), notices.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(Notice::parse(notice.payload()), Some(Notice::Token));
        // Only the digest is stored.
        let (digest,): (Vec<u8>,) =
            sqlx::query_as("SELECT digest FROM enrollment_token WHERE id = $1")
                .bind(&token.id()[..])
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!(digest, token.secret_digest());
        assert!(store.next_expiry(now()).await.unwrap().is_some());
        let Err(too_long) =
            store::issue_token(store.pool(), group(), Duration::from_hours(2)).await
        else {
            panic!("jeton de deux heures accepté");
        };
        assert_eq!(too_long.code(), "CORE-E007");
        drop(notices);
        drop(store);
        db.drop_database().await;
    });
}

#[test]
fn an_unreadable_registry_refuses_every_agent() {
    block_on(async {
        let Some((db, store)) = migrated("an_unreadable_registry_refuses_every_agent").await else {
            return;
        };
        let cache = store.cache();
        store
            .register([1; 32], group(), Uuid::from_bytes([1; 16]))
            .await
            .unwrap();
        store.reload().await.unwrap();
        assert_eq!(cache.authorize(&[1; 32]), Ok(()));
        store.pool().close().await;
        assert!(store.reload().await.is_err());
        assert_eq!(cache.authorize(&[1; 32]), Err(ClientRefusal::Unavailable));
        assert_eq!(
            store
                .register([2; 32], group(), Uuid::from_bytes([1; 16]))
                .await,
            Err(TunnelError::RegistryUnavailable)
        );
        drop(store);
        db.drop_database().await;
    });
}
