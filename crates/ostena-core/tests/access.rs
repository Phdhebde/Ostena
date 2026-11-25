//! The inventory, the SSH access decision and the consumption of grants on
//! a real PostgreSQL server (see `common/mod.rs` for the environment).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test helpers and scenarios"
)]

mod common;

use std::sync::Arc;

use common::{TestDb, block_on};
use ostena_common::config::scope::{AllowRuleSpec, PolicySpec};
use ostena_core::access::{self, Refusal, SshRequest};
use ostena_core::cache::AgentCache;
use ostena_core::grant_keys::GrantAuthority;
use ostena_core::ssh_ca::SshAuthorities;
use ostena_core::store::PgStore;
use ostena_core::{inventory, login, pushes, schema};
use ostena_crypto::p256::SigningKey;
use ostena_grant::{
    Binding, Claims, GatewayGroupId, Issuer, Protocol, ResourceId, Rights, SignedGrant, SubjectId,
};
use ostena_tunnel::Uuid;
use ostena_tunnel::control::{CoreMessage, SessionProtocol};
use ostena_tunnel::enroll::AgentRegistry;
use sqlx::PgPool;

const GROUP: Uuid = Uuid::from_bytes([0x2f; 16]);
const OTHER_GROUP: Uuid = Uuid::from_bytes([0x3e; 16]);
const AGENT: Uuid = Uuid::from_bytes([0xa1; 16]);
const OTHER_AGENT: Uuid = Uuid::from_bytes([0xa2; 16]);
/// A second agent of `GROUP`.
const SIBLING: Uuid = Uuid::from_bytes([0xa3; 16]);
const CERT: [u8; 32] = [0xc5; 32];

fn now() -> u64 {
    ostena_grant::unix_now()
}

struct Fixture {
    db: TestDb,
    pool: PgPool,
    authority: GrantAuthority,
    user: Uuid,
    login: Uuid,
    target_key: [u8; 65],
}

async fn audit_count(pool: &PgPool, event: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_record WHERE event = $1")
        .bind(event)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn open_login(pool: &PgPool, user: Uuid, cert: [u8; 32], secs: u64) -> Uuid {
    let session = login::new_session_id().unwrap();
    let mut tx = pool.begin().await.unwrap();
    login::open_session(&mut tx, session, user, cert, now() + secs)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    session
}

/// A migrated database with one group (`lab`), one user (`alice`), one
/// resource `srv-lab01` with the accounts `root` (right of one hour per
/// session, one day) and `backup` (no right), one agent of the group and a
/// login session of alice.
async fn fixture(test: &str) -> Option<Fixture> {
    let db = TestDb::create(test).await?;
    let pool = db.pool().await;
    schema::migrate(&pool).await.unwrap();
    ostena_core::audit::ensure_genesis(&pool).await.unwrap();
    let store = PgStore::new(pool.clone(), Arc::new(AgentCache::default()));
    store.register([1; 32], GROUP, AGENT).await.unwrap();
    store
        .register([2; 32], OTHER_GROUP, OTHER_AGENT)
        .await
        .unwrap();
    store.register([3; 32], GROUP, SIBLING).await.unwrap();
    inventory::create_group(&pool, Some(GROUP), "lab", &["bastion.lab".into()])
        .await
        .unwrap();
    inventory::create_group(&pool, Some(OTHER_GROUP), "other", &[])
        .await
        .unwrap();
    let user = inventory::add_user(&pool, "alice", "Alice Martin")
        .await
        .unwrap();
    let target = SigningKey::generate().unwrap().0.verifying_key();
    inventory::add_resource(&pool, "srv-lab01", "10.20.0.5", 22, "lab", &target)
        .await
        .unwrap();
    inventory::add_resource(&pool, "srv-other", "10.30.0.5", 22, "other", &target)
        .await
        .unwrap();
    for (resource, account) in [
        ("srv-lab01", "root"),
        ("srv-lab01", "backup"),
        ("srv-other", "root"),
    ] {
        inventory::add_account(&pool, resource, account)
            .await
            .unwrap();
    }
    inventory::grant_right(&pool, "alice", "srv-lab01", "root", now() + 86_400, 3600)
        .await
        .unwrap();
    inventory::grant_right(&pool, "alice", "srv-other", "root", now() + 86_400, 3600)
        .await
        .unwrap();
    let issuer = Arc::new(Issuer::new(SigningKey::generate().unwrap().0));
    let (authority, activated) = GrantAuthority::load(&pool, issuer).await.unwrap();
    assert!(activated.is_some());
    let login = open_login(&pool, user, CERT, 7200).await;
    Some(Fixture {
        db,
        pool,
        authority,
        user,
        login,
        target_key: target.to_bytes(),
    })
}

impl Fixture {
    fn request(&self, resource: &str, account: &str) -> SshRequest {
        SshRequest {
            subject: self.user,
            login_session: self.login,
            certificate_sha256: CERT,
            account: account.into(),
            resource: resource.into(),
            client_address: "192.0.2.7:50022".into(),
        }
    }

    async fn grant(&self, request: &SshRequest) -> Result<access::Issued, Refusal> {
        access::ssh_grant(&self.pool, &self.authority, AGENT, GROUP, request, now()).await
    }

    async fn code(&self, request: &SshRequest) -> &'static str {
        self.grant(request).await.unwrap_err().code
    }

    async fn open(&self, grant: &str) -> Result<access::Opened, Refusal> {
        access::open_session(&self.pool, &self.authority, AGENT, GROUP, 7, grant, now()).await
    }
}

#[test]
fn ssh_grant_follows_the_inventory_and_the_login_session() {
    block_on(async {
        let Some(f) = fixture("ssh_grant_follows_the_inventory_and_the_login_session").await else {
            return;
        };
        let request = f.request("srv-lab01", "root");
        let issued = f.grant(&request).await.unwrap();
        let claims = issued.content.claims;
        assert_eq!(claims.subject.to_bytes(), f.user.to_bytes());
        assert_eq!(claims.audience.to_bytes(), GROUP.to_bytes());
        assert_eq!(claims.protocol, Protocol::Ssh);
        assert_eq!(claims.binding, Binding::of(f.login.to_bytes(), "root"));
        assert_eq!(claims.max_session_secs, 3600);
        assert_eq!(audit_count(&f.pool, "access.ssh_granted").await, 1);

        // Each refusal, with its code.
        let mut other = f.request("srv-lab01", "root");
        other.login_session = Uuid::from_bytes([9; 16]);
        assert_eq!(f.code(&other).await, access::LOGIN_UNKNOWN);
        let mut other = f.request("srv-lab01", "root");
        other.certificate_sha256 = [0; 32];
        assert_eq!(f.code(&other).await, access::LOGIN_MISMATCH);
        let mut other = f.request("srv-lab01", "root");
        other.subject = Uuid::from_bytes([8; 16]);
        assert_eq!(f.code(&other).await, access::LOGIN_MISMATCH);
        assert_eq!(
            f.code(&f.request("srv-nowhere", "root")).await,
            access::RESOURCE_UNKNOWN
        );
        assert_eq!(
            f.code(&f.request("srv-other", "root")).await,
            access::OTHER_GROUP
        );
        assert_eq!(
            f.code(&f.request("srv-lab01", "admin")).await,
            access::ACCOUNT_UNKNOWN
        );
        assert_eq!(
            f.code(&f.request("srv-lab01", "backup")).await,
            access::NO_RIGHT
        );
        // No grant was recorded for the refusals.
        let grants: i64 = sqlx::query_scalar("SELECT count(*) FROM access_grant")
            .fetch_one(&f.pool)
            .await
            .unwrap();
        assert_eq!(grants, 1);

        // A short login session bounds the session length.
        let short = open_login(&f.pool, f.user, [0xd1; 32], 600).await;
        let mut request = f.request("srv-lab01", "root");
        request.login_session = short;
        request.certificate_sha256 = [0xd1; 32];
        let max = f
            .grant(&request)
            .await
            .unwrap()
            .content
            .claims
            .max_session_secs;
        assert!((590..=600).contains(&max), "{max}");

        // The right revoked.
        let rights = inventory::list_rights(&f.pool).await.unwrap();
        let right = rights
            .iter()
            .find(|r| r.resource == "srv-lab01" && r.account == "root")
            .unwrap();
        inventory::revoke_right(&f.pool, right.id).await.unwrap();
        assert_eq!(
            f.code(&f.request("srv-lab01", "root")).await,
            access::NO_RIGHT
        );
        // Again: nothing changes, audited once.
        inventory::revoke_right(&f.pool, right.id).await.unwrap();
        assert_eq!(audit_count(&f.pool, "right.revoked").await, 1);
        assert_eq!(
            inventory::revoke_right(&f.pool, Uuid::from_bytes([6; 16]))
                .await
                .unwrap_err()
                .code(),
            "CORE-E009"
        );

        // The user disabled (without the CLI, which also revokes sessions).
        sqlx::query("UPDATE app_user SET state = 'disabled', disabled_at = now()")
            .execute(&f.pool)
            .await
            .unwrap();
        assert_eq!(
            f.code(&f.request("srv-other", "root")).await,
            access::USER_INACTIVE
        );
        sqlx::query("UPDATE app_user SET state = 'active', disabled_at = NULL")
            .execute(&f.pool)
            .await
            .unwrap();

        // The login session expired, then revoked.
        sqlx::query("UPDATE login_session SET started_at = started_at - 100, expires_at = started_at - 99 WHERE id = $1::uuid")
            .bind(f.login.to_string())
            .execute(&f.pool)
            .await
            .unwrap();
        assert_eq!(
            f.code(&f.request("srv-lab01", "root")).await,
            access::LOGIN_EXPIRED
        );
        login::revoke_session(&f.pool, f.login, "poste perdu")
            .await
            .unwrap();
        assert_eq!(
            f.code(&f.request("srv-lab01", "root")).await,
            access::LOGIN_REVOKED
        );
        f.db.drop_database().await;
    });
}

#[test]
fn a_grant_opens_one_session_once() {
    block_on(async {
        let Some(f) = fixture("a_grant_opens_one_session_once").await else {
            return;
        };
        let issued = f.grant(&f.request("srv-lab01", "root")).await.unwrap();
        let opened = f.open(&issued.grant).await.unwrap();
        let CoreMessage::SessionParams {
            request_id,
            session_id,
            protocol,
            host,
            port,
            max_session_secs,
            account,
            target_p256_public,
        } = &opened.params
        else {
            panic!("pas des paramètres de session");
        };
        opened.params.validate().unwrap();
        assert_eq!(*request_id, 7);
        assert_eq!(session_id, &opened.session.to_string());
        assert_eq!(*protocol, SessionProtocol::Ssh);
        assert_eq!((host.as_str(), *port), ("10.20.0.5", 22));
        assert_eq!(*max_session_secs, 3600);
        assert_eq!(account.as_deref(), Some("root"));
        let key = ostena_tunnel::control::p256_point("k", target_p256_public.as_ref().unwrap());
        assert_eq!(key.unwrap().to_bytes(), f.target_key);
        assert_eq!(audit_count(&f.pool, "access.session_opened").await, 1);

        // Once only, for the whole group.
        assert_eq!(f.open(&issued.grant).await.unwrap_err().code, "GRT-E010");
        // Not for another group.
        let refused = access::open_session(
            &f.pool,
            &f.authority,
            OTHER_AGENT,
            OTHER_GROUP,
            1,
            &issued.grant,
            now(),
        )
        .await
        .unwrap_err();
        assert_eq!(refused.code, "GRT-E011");

        // Signed by the core but never issued by it: unknown.
        let claims = Claims {
            subject: SubjectId::from_bytes(f.user.to_bytes()),
            resource: ResourceId::from_bytes([1; 16]),
            audience: GatewayGroupId::from_bytes(GROUP.to_bytes()),
            protocol: Protocol::Ssh,
            rights: Rights::NONE,
            max_session_secs: 60,
            binding: Binding::of(f.login.to_bytes(), "root"),
        };
        let forged = f
            .authority
            .issuer()
            .issue(&claims, now())
            .unwrap()
            .to_text();
        assert_eq!(
            f.open(&forged).await.unwrap_err().code,
            access::GRANT_UNKNOWN
        );
        // Signed by another key.
        let stranger = Issuer::new(SigningKey::generate().unwrap().0);
        let foreign = stranger.issue(&claims, now()).unwrap().to_text();
        assert_eq!(f.open(&foreign).await.unwrap_err().code, "GRT-E005");
        assert_eq!(
            access::jti_of(&foreign),
            Some(
                SignedGrant::from_text(&foreign).unwrap().as_bytes()[16..32]
                    .try_into()
                    .unwrap()
            )
        );

        // A grant whose login session is revoked before it is used.
        let issued = f.grant(&f.request("srv-lab01", "root")).await.unwrap();
        login::revoke_session(&f.pool, f.login, "test")
            .await
            .unwrap();
        assert_eq!(
            f.open(&issued.grant).await.unwrap_err().code,
            access::LOGIN_REVOKED
        );

        // The end of a session, once.
        let closed = access::close_session(&f.pool, AGENT, opened.session, "fin", 10, 20, now())
            .await
            .unwrap();
        assert!(closed.is_some());
        let again = access::close_session(&f.pool, AGENT, opened.session, "fin", 10, 20, now())
            .await
            .unwrap();
        assert!(again.is_none());
        let other = access::close_session(&f.pool, OTHER_AGENT, opened.session, "fin", 0, 0, now())
            .await
            .unwrap();
        assert!(other.is_none());
        f.db.drop_database().await;
    });
}

#[test]
fn a_session_uses_any_valid_right_on_the_account() {
    block_on(async {
        let Some(f) = fixture("a_session_uses_any_valid_right_on_the_account").await else {
            return;
        };
        // A longer right granted between the grant and its session: the
        // session opens under it.
        let issued = f.grant(&f.request("srv-lab01", "root")).await.unwrap();
        let longer = inventory::grant_right(
            &f.pool,
            "alice",
            "srv-lab01",
            "root",
            now() + 2 * 86_400,
            3600,
        )
        .await
        .unwrap();
        f.open(&issued.grant).await.unwrap();
        // The right of the grant revoked, another valid: still opens.
        let issued = f.grant(&f.request("srv-lab01", "root")).await.unwrap();
        let rights = inventory::list_rights(&f.pool).await.unwrap();
        for right in rights
            .iter()
            .filter(|r| r.resource == "srv-lab01" && r.account == "root" && r.id != longer)
        {
            inventory::revoke_right(&f.pool, right.id).await.unwrap();
        }
        f.open(&issued.grant).await.unwrap();
        // No valid right left: refused.
        let issued = f.grant(&f.request("srv-lab01", "root")).await.unwrap();
        inventory::revoke_right(&f.pool, longer).await.unwrap();
        assert_eq!(
            f.open(&issued.grant).await.unwrap_err().code,
            access::NO_RIGHT
        );
        f.db.drop_database().await;
    });
}

#[test]
fn concurrent_session_requests_consume_a_jti_once() {
    block_on(async {
        let Some(f) = fixture("concurrent_session_requests_consume_a_jti_once").await else {
            return;
        };
        let f = Arc::new(f);
        for _ in 0..5 {
            let issued = f.grant(&f.request("srv-lab01", "root")).await.unwrap();
            let tasks: Vec<_> = (0..4)
                .map(|_| {
                    let f = f.clone();
                    let grant = issued.grant.clone();
                    tokio::spawn(async move { f.open(&grant).await })
                })
                .collect();
            let mut opened = 0;
            for task in tasks {
                match task.await.unwrap() {
                    Ok(_) => opened += 1,
                    Err(refusal) => assert_eq!(refusal.code, "GRT-E010"),
                }
            }
            assert_eq!(opened, 1);
        }
        let Ok(f) = Arc::try_unwrap(f) else {
            panic!("fixture encore partagée");
        };
        f.db.drop_database().await;
    });
}

/// Waits until `count` transactions of the test database wait for a lock.
async fn lock_waiters(pool: &PgPool, count: i64) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity
             WHERE datname = current_database() AND wait_event_type = 'Lock'",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        if waiting >= count {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{count} attentes de verrou attendues, {waiting} vues"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

#[test]
fn disabling_a_user_during_a_grant_request_does_not_deadlock() {
    block_on(async {
        let Some(f) = fixture("disabling_a_user_during_a_grant_request_does_not_deadlock").await
        else {
            return;
        };
        let f = Arc::new(f);
        // The user row held, so that both transactions queue on it: the
        // disabling first, then the grant request. Taking the login session
        // before the user, the request would hold what the disabling needs
        // next, and PostgreSQL would abort one of them (40P01).
        let mut blocker = f.pool.begin().await.unwrap();
        sqlx::query("SELECT 1 FROM app_user WHERE id = $1::uuid FOR UPDATE")
            .bind(f.user.to_string())
            .execute(&mut *blocker)
            .await
            .unwrap();
        let disable = {
            let pool = f.pool.clone();
            tokio::spawn(async move { inventory::disable_user(&pool, "alice").await })
        };
        lock_waiters(&f.pool, 1).await;
        let grant = {
            let f = f.clone();
            tokio::spawn(async move { f.grant(&f.request("srv-lab01", "root")).await })
        };
        lock_waiters(&f.pool, 2).await;
        blocker.rollback().await.unwrap();
        assert_eq!(disable.await.unwrap().unwrap(), 1);
        let refused = grant.await.unwrap().unwrap_err();
        assert!(
            [access::LOGIN_REVOKED, access::USER_INACTIVE].contains(&refused.code),
            "{refused:?}"
        );
        let Ok(f) = Arc::try_unwrap(f) else {
            panic!("fixture encore partagée");
        };
        f.db.drop_database().await;
    });
}

#[test]
fn revocations_are_repeated_to_the_agents_that_received_grants() {
    block_on(async {
        let Some(f) = fixture("revocations_are_repeated_to_the_agents_that_received_grants").await
        else {
            return;
        };
        f.grant(&f.request("srv-lab01", "root")).await.unwrap();
        let unused = open_login(&f.pool, f.user, [0xe1; 32], 3600).await;
        assert_eq!(
            login::revoked_for_agent(&f.pool, AGENT).await.unwrap(),
            Vec::<Uuid>::new()
        );
        login::revoke_session(&f.pool, f.login, "test")
            .await
            .unwrap();
        login::revoke_session(&f.pool, unused, "test")
            .await
            .unwrap();
        // Twice changes nothing.
        login::revoke_session(&f.pool, f.login, "encore")
            .await
            .unwrap();
        assert_eq!(
            login::revoke_session(&f.pool, Uuid::from_bytes([5; 16]), "x")
                .await
                .unwrap_err()
                .code(),
            "CORE-E009"
        );
        assert_eq!(audit_count(&f.pool, "login_session.revoked").await, 2);
        assert_eq!(
            login::agents_to_notify(&f.pool, f.login).await.unwrap(),
            vec![AGENT]
        );
        assert_eq!(
            login::agents_to_notify(&f.pool, unused).await.unwrap(),
            Vec::<Uuid>::new()
        );
        assert_eq!(
            login::revoked_for_agent(&f.pool, AGENT).await.unwrap(),
            vec![f.login]
        );
        assert_eq!(
            login::revoked_for_agent(&f.pool, OTHER_AGENT)
                .await
                .unwrap(),
            Vec::<Uuid>::new()
        );
        // Expired: no longer repeated.
        sqlx::query("UPDATE login_session SET started_at = started_at - 100, expires_at = started_at - 99 WHERE id = $1::uuid")
            .bind(f.login.to_string())
            .execute(&f.pool)
            .await
            .unwrap();
        assert_eq!(
            login::revoked_for_agent(&f.pool, AGENT).await.unwrap(),
            Vec::<Uuid>::new()
        );

        // Disabling a user revokes their valid sessions.
        let fresh = open_login(&f.pool, f.user, [0xe2; 32], 3600).await;
        assert_eq!(inventory::disable_user(&f.pool, "alice").await.unwrap(), 1);
        let revoked: bool = sqlx::query_scalar(
            "SELECT revoked_at IS NOT NULL FROM login_session WHERE id = $1::uuid",
        )
        .bind(fresh.to_string())
        .fetch_one(&f.pool)
        .await
        .unwrap();
        assert!(revoked);
        assert_eq!(audit_count(&f.pool, "user.disabled").await, 1);
        let sessions_revoked = audit_count(&f.pool, "login_session.revoked").await;
        // Again: nothing left, nothing audited.
        assert_eq!(inventory::disable_user(&f.pool, "alice").await.unwrap(), 0);
        assert_eq!(audit_count(&f.pool, "user.disabled").await, 1);
        assert_eq!(
            audit_count(&f.pool, "login_session.revoked").await,
            sessions_revoked
        );
        // A login session opened meanwhile is revoked, without a second
        // `user.disabled`.
        open_login(&f.pool, f.user, [0xe3; 32], 3600).await;
        assert_eq!(inventory::disable_user(&f.pool, "alice").await.unwrap(), 1);
        assert_eq!(audit_count(&f.pool, "user.disabled").await, 1);
        assert_eq!(
            audit_count(&f.pool, "login_session.revoked").await,
            sessions_revoked + 1
        );
        f.db.drop_database().await;
    });
}

#[test]
fn revocations_reach_the_agent_that_consumed_the_grant() {
    block_on(async {
        let Some(f) = fixture("revocations_reach_the_agent_that_consumed_the_grant").await else {
            return;
        };
        // Issued to one agent, consumed by another of the group.
        let issued = f.grant(&f.request("srv-lab01", "root")).await.unwrap();
        access::open_session(
            &f.pool,
            &f.authority,
            SIBLING,
            GROUP,
            1,
            &issued.grant,
            now(),
        )
        .await
        .unwrap();
        login::revoke_session(&f.pool, f.login, "test")
            .await
            .unwrap();
        let mut agents = login::agents_to_notify(&f.pool, f.login).await.unwrap();
        agents.sort_by_key(|a| a.to_bytes());
        assert_eq!(agents, vec![AGENT, SIBLING]);
        for agent in [AGENT, SIBLING] {
            assert_eq!(
                login::revoked_for_agent(&f.pool, agent).await.unwrap(),
                vec![f.login],
                "{agent}"
            );
        }
        assert_eq!(
            login::revoked_for_agent(&f.pool, OTHER_AGENT)
                .await
                .unwrap(),
            Vec::<Uuid>::new()
        );
        f.db.drop_database().await;
    });
}

#[test]
fn pushed_versions_never_go_back() {
    block_on(async {
        let Some(f) = fixture("pushed_versions_never_go_back").await else {
            return;
        };
        // Grant key set: same key, same version; a new key, a new version
        // that keeps the old key until its grants expire.
        let CoreMessage::KeySet { version: v1, keys } = f.authority.key_set_message() else {
            panic!("pas un jeu de clés");
        };
        assert_eq!(keys.len(), 1);
        let next = Arc::new(Issuer::new(SigningKey::generate().unwrap().0));
        let again = GrantAuthority::load(&f.pool, next).await.unwrap().0;
        let CoreMessage::KeySet { version: v2, keys } = again.key_set_message() else {
            panic!("pas un jeu de clés");
        };
        assert!(v2 > v1);
        assert_eq!(keys.len(), 2);
        assert!(keys[0].retire_at.is_none());
        assert!(keys[1].retire_at.is_some());
        again.key_set_message().validate().unwrap();
        assert_eq!(audit_count(&f.pool, "grant.key_activated").await, 2);

        // Policies.
        let policy = PolicySpec {
            allow: vec![AllowRuleSpec {
                label: None,
                networks: vec!["10.20.0.0/16".into()],
                ports: vec!["22".into()],
            }],
            ..PolicySpec::default()
        };
        assert!(
            pushes::policy_message(&f.pool, GROUP)
                .await
                .unwrap()
                .is_none()
        );
        let p1 = inventory::set_group_policy(&f.pool, "lab", &policy)
            .await
            .unwrap();
        let p2 = inventory::set_group_policy(&f.pool, "lab", &policy)
            .await
            .unwrap();
        assert!(p1 > v2 && p2 > p1);
        let Some(message @ CoreMessage::Policy { version, .. }) =
            pushes::policy_message(&f.pool, GROUP).await.unwrap()
        else {
            panic!("pas de politique");
        };
        assert_eq!(version, p2);
        message.validate().unwrap();
        let weak = PolicySpec {
            allow_short_names: true,
            ..policy.clone()
        };
        assert_eq!(
            inventory::set_group_policy(&f.pool, "lab", &weak)
                .await
                .unwrap_err()
                .code(),
            "CORE-E012"
        );

        // SSH trust: stable while unchanged, a new version once the host
        // key is certified.
        let ssh = SshAuthorities::new(
            SigningKey::generate().unwrap().0,
            SigningKey::generate().unwrap().0,
            30,
        )
        .unwrap();
        let trust = |m: CoreMessage| match m {
            CoreMessage::SshTrust {
                version,
                host_certificate,
                ..
            } => (version, host_certificate),
            _ => panic!("pas une confiance SSH"),
        };
        let (t1, cert) = trust(
            pushes::ssh_trust_message(&f.pool, &ssh, AGENT, now())
                .await
                .unwrap(),
        );
        assert!(cert.is_none() && t1 > p2);
        let (t2, _) = trust(
            pushes::ssh_trust_message(&f.pool, &ssh, AGENT, now())
                .await
                .unwrap(),
        );
        assert_eq!(t1, t2);
        let host = SigningKey::generate().unwrap().0.verifying_key();
        let certified = pushes::certify_host(&f.pool, &ssh, AGENT, GROUP, &host, false, now())
            .await
            .unwrap();
        assert!(certified.is_some());
        // Current: not again, unless forced.
        assert!(
            pushes::certify_host(&f.pool, &ssh, AGENT, GROUP, &host, false, now())
                .await
                .unwrap()
                .is_none()
        );
        let message = pushes::ssh_trust_message(&f.pool, &ssh, AGENT, now())
            .await
            .unwrap();
        message.validate().unwrap();
        let (t3, cert) = trust(message);
        assert!(t3 > t2);
        let blob = ostena_tunnel::control::host_certificate(&cert.unwrap()).unwrap();
        let parsed = ostena_ssh::cert::parse(&blob).unwrap();
        parsed.verify(&[ssh.host_ca_public()]).unwrap();
        assert_eq!(parsed.principals, ["bastion.lab"]);
        assert_eq!(audit_count(&f.pool, "ssh.host_certified").await, 1);
        // A group without SSH host names: the key is kept, not certified.
        let refused =
            pushes::certify_host(&f.pool, &ssh, OTHER_AGENT, OTHER_GROUP, &host, false, now())
                .await
                .unwrap_err();
        assert_eq!(refused.code, access::NO_HOST_NAME);
        assert_eq!(
            pushes::stored_host_key(&f.pool, OTHER_AGENT).await.unwrap(),
            Some(host)
        );
        f.db.drop_database().await;
    });
}

#[test]
fn administration_rules_and_dry_run() {
    block_on(async {
        let Some(f) = fixture("administration_rules_and_dry_run").await else {
            return;
        };
        let code = |r: Result<Uuid, ostena_core::CoreError>| r.unwrap_err().code();
        let key = SigningKey::generate().unwrap().0.verifying_key();
        assert_eq!(
            code(inventory::add_user(&f.pool, "alice", "Doublon").await),
            "CORE-E012"
        );
        assert_eq!(
            code(inventory::add_user(&f.pool, "Bob", "Bob").await),
            "CORE-E012"
        );
        assert_eq!(
            code(inventory::add_user(&f.pool, "bob", "").await),
            "CORE-E012"
        );
        assert_eq!(
            code(inventory::add_resource(&f.pool, "srv-lab01", "10.0.0.1", 22, "lab", &key).await),
            "CORE-E012"
        );
        assert_eq!(
            code(inventory::add_resource(&f.pool, "srv-x", "10.0.0.1", 22, "nowhere", &key).await),
            "CORE-E009"
        );
        assert_eq!(
            code(inventory::add_resource(&f.pool, "srv-x", "bad host", 22, "lab", &key).await),
            "CORE-E012"
        );
        assert_eq!(
            code(inventory::add_account(&f.pool, "srv-lab01", " root").await),
            "CORE-E012"
        );
        // A right ends, within 366 days, with sessions of 60 s to 12 h.
        for (until, max) in [
            (now(), 3600),
            (now() + 367 * 86_400, 3600),
            (now() + 3600, 59),
            (now() + 3600, 43_201),
        ] {
            assert_eq!(
                code(
                    inventory::grant_right(&f.pool, "alice", "srv-lab01", "backup", until, max)
                        .await
                ),
                "CORE-E012",
                "{until} {max}"
            );
        }
        assert_eq!(
            code(
                inventory::grant_right(&f.pool, "nobody", "srv-lab01", "root", now() + 60, 60)
                    .await
            ),
            "CORE-E009"
        );
        assert_eq!(
            code(inventory::create_group(&f.pool, None, "lab", &[]).await),
            "CORE-E012"
        );
        inventory::set_group_host_names(&f.pool, "other", &["other.lab".into()])
            .await
            .unwrap();
        let groups = inventory::list_groups(&f.pool).await.unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[1].ssh_host_names, ["other.lab"]);
        let resources = inventory::list_resources(&f.pool).await.unwrap();
        assert_eq!(resources[0].accounts, ["backup", "root"]);
        assert!(resources[0].host_key_pinned);
        assert_eq!(
            inventory::list_users(&f.pool).await.unwrap()[0].state,
            "active"
        );

        // The dry run writes nothing, not even to the audit chain.
        let records: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_record")
            .fetch_one(&f.pool)
            .await
            .unwrap();
        let allowed = access::check(&f.pool, "alice", "srv-lab01", "root", now())
            .await
            .unwrap();
        assert_eq!(allowed.max_session_secs, 3600);
        assert_eq!(allowed.group, GROUP);
        assert_eq!(
            access::check(&f.pool, "alice", "srv-lab01", "backup", now())
                .await
                .unwrap_err()
                .code,
            access::NO_RIGHT
        );
        assert_eq!(
            access::check(&f.pool, "zoe", "srv-lab01", "root", now())
                .await
                .unwrap_err()
                .code,
            access::USER_INACTIVE
        );
        let after: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_record")
            .fetch_one(&f.pool)
            .await
            .unwrap();
        assert_eq!(records, after);
        f.db.drop_database().await;
    });
}
