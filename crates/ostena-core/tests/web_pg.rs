//! Browser sessions of the portal on a real PostgreSQL server (ADR-0020):
//! the web listener with the PostgreSQL store, behind the authenticator of
//! `ostena login`. Cookie digest only in the database, rotation,
//! idle time, source binding, logout, administrator revocation, disabled
//! user, shared lockout, audit records.

#![allow(
    clippy::unwrap_used,
    clippy::too_many_lines,
    reason = "test helpers and scenarios"
)]

mod common;
mod web_stub;

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{TestDb, block_on};
use hyper::StatusCode;
use ostena_common::api::web::{AccessGrant, LoginSessionList, Role, SessionInfo};
use ostena_common::config::CoreLoginConfig;
use ostena_common::secret::{SecretBytes, SecretString};
use ostena_core::api::Attempts;
use ostena_core::audit::{self, Recorder};
use ostena_core::authn::PgAuthenticator;
use ostena_core::cache::AgentCache;
use ostena_core::credential::{self, TotpKey};
use ostena_core::functions::Functions;
use ostena_core::grant_keys::GrantAuthority;
use ostena_core::inventory;
use ostena_core::ssh_ca::SshAuthorities;
use ostena_core::store::PgStore;
use ostena_core::web::pg::{Agents, PgWebBackend, WebAccess};
use ostena_core::web::{WebListener, WebSettings};
use ostena_crypto::p256::SigningKey;
use ostena_crypto::pki::testing::TestPki;
use ostena_crypto::tls::testing::{Offer, browser_client_config};
use ostena_crypto::tls::{self, WebGroups};
use ostena_crypto::totp::{TotpAlgorithm, TotpSecret, step_at};
use ostena_grant::{Binding, GatewayGroupId, Issuer, SignedGrant, Verifier};
use ostena_tunnel::Uuid;
use ostena_tunnel::enroll::AgentRegistry;
use sqlx::PgPool;
use web_stub::{Connection, ORIGIN, bare, request};

const PASSWORD: &str = "correct horse battery";
const GROUP: Uuid = Uuid::from_bytes([0x2f; 16]);
const AGENT: Uuid = Uuid::from_bytes([0xa1; 16]);

/// The agents of the test: `AGENT` of `GROUP`, connected or not.
struct FakeAgents(AtomicBool);

impl Agents for FakeAgents {
    fn pick(&self, group: Uuid) -> Option<Uuid> {
        (group == GROUP && self.0.load(Ordering::Relaxed)).then_some(AGENT)
    }

    // No tunnel here: the gateway is tested end to end in web_gateway.rs.
    fn tunnel(&self, _: Uuid) -> Option<Arc<ostena_tunnel::CoreTunnel>> {
        None
    }
}

fn now() -> u64 {
    ostena_grant::unix_now()
}

fn settings() -> CoreLoginConfig {
    toml::from_str(
        "listen = \"127.0.0.1:0\"\ntotp_key = { credential = \"totp.key\" }\n\
         ssh_hosts = [\"bastion.lab\"]\nmax_failures = 3\nlockout_minutes = 15\n",
    )
    .unwrap()
}

async fn audit_count(pool: &PgPool, event: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_record WHERE event = $1")
        .bind(event)
        .fetch_one(pool)
        .await
        .unwrap()
}

struct Fixture {
    db: TestDb,
    pool: PgPool,
    recorder: Arc<Recorder>,
    pki: TestPki,
    listener: WebListener,
    totp: Vec<(String, TotpSecret)>,
    agents: Arc<FakeAgents>,
    grants: Arc<GrantAuthority>,
    backend: Arc<PgWebBackend>,
}

async fn enroll(pool: &PgPool, key: &TotpKey, name: &str) -> TotpSecret {
    inventory::add_user(pool, name, name).await.unwrap();
    credential::set_password(pool, name, SecretString::from(PASSWORD.to_owned()))
        .await
        .unwrap();
    let totp = credential::enroll_totp(pool, key, name, TotpAlgorithm::Sha1)
        .await
        .unwrap();
    credential::confirm_totp(pool, key, name, &totp.code(step_at(now())))
        .await
        .unwrap();
    totp
}

async fn fixture(test: &str) -> Option<Fixture> {
    let db = TestDb::create(test).await?;
    db.migrate().await;
    let pool = db.pool().await;
    audit::ensure_genesis(&pool).await.unwrap();
    let bytes: [u8; 32] = ostena_crypto::rand::array().unwrap();
    let key = Arc::new(TotpKey::from_bytes(&SecretBytes::from(bytes.to_vec()), &[]).unwrap());
    let mut totp = Vec::new();
    for name in ["alice", "root"] {
        totp.push((name.to_owned(), enroll(&pool, &key, name).await));
    }
    assert!(
        inventory::grant_role(&pool, "root", Role::Admin)
            .await
            .unwrap()
    );
    assert!(
        !inventory::grant_role(&pool, "root", Role::Admin)
            .await
            .unwrap()
    );
    let recorder = Arc::new(Recorder::new());
    tokio::spawn(audit::run_writer(pool.clone(), recorder.clone()));
    let ssh = Arc::new(
        SshAuthorities::new(
            SigningKey::generate().unwrap().0,
            SigningKey::generate().unwrap().0,
            30,
        )
        .unwrap(),
    );
    let auth = PgAuthenticator::new(pool.clone(), recorder.clone(), ssh, key, &settings())
        .with_refusal_floor(Duration::ZERO);
    // The inventory of the access requests: alice has a right on
    // root@srv-lab01, none on backup@srv-lab01.
    let store = PgStore::new(pool.clone(), Arc::new(AgentCache::default()));
    store.register([1; 32], GROUP, AGENT).await.unwrap();
    inventory::create_group(&pool, Some(GROUP), "lab", &["bastion.lab".into()])
        .await
        .unwrap();
    let target = SigningKey::generate().unwrap().0.verifying_key();
    inventory::add_resource(&pool, "srv-lab01", "10.20.0.5", 22, "lab", &target)
        .await
        .unwrap();
    for account in ["root", "backup"] {
        inventory::add_account(&pool, "srv-lab01", account)
            .await
            .unwrap();
    }
    inventory::grant_right(
        &pool,
        "alice",
        "srv-lab01",
        "root",
        now() + 86_400,
        3600,
        Functions::NONE,
    )
    .await
    .unwrap();
    let issuer = Arc::new(Issuer::new(SigningKey::generate().unwrap().0));
    let grants = Arc::new(GrantAuthority::load(&pool, issuer).await.unwrap().0);
    let agents = Arc::new(FakeAgents(AtomicBool::new(true)));
    let access = WebAccess {
        grants: grants.clone(),
        agents: agents.clone(),
        relays: Arc::default(),
    };
    let pki = TestPki::new("web-pg").unwrap();
    let server = pki.server(&["core.test"]).unwrap();
    let backend = Arc::new(PgWebBackend::new(Arc::new(auth)).with_access(access));
    let listener = WebListener::bind(
        "127.0.0.1:0".parse().unwrap(),
        tls::web_server_config(&server, WebGroups::Hybrid).unwrap(),
        WebSettings::new(ORIGIN.into()),
        backend.clone(),
        Arc::new(Attempts::new(600)),
    )
    .await
    .unwrap();
    Some(Fixture {
        db,
        pool,
        recorder,
        pki,
        listener,
        totp,
        agents,
        grants,
        backend,
    })
}

impl Fixture {
    async fn connect(&self, from: &str) -> Connection {
        let config = browser_client_config(Offer::X25519MlKem768, &self.pki.root_anchor()).unwrap();
        let from: IpAddr = from.parse().unwrap();
        Connection::open(self.listener.local_addr(), from, config)
            .await
            .unwrap()
    }

    /// A code of the current step, accepted once: the steps already used
    /// are forgotten first (each login of a test consumes one).
    async fn code(&self, name: &str) -> String {
        sqlx::query("UPDATE user_credential SET totp_last_step = 0")
            .execute(&self.pool)
            .await
            .unwrap();
        let totp = &self.totp.iter().find(|(n, _)| n == name).unwrap().1;
        // SECRET-EXPOSURE: test builds the request body.
        #[expect(clippy::disallowed_methods)]
        let code = totp.code(step_at(now())).expose_secret().to_owned();
        code
    }

    async fn login(&self, name: &str, from: &str) -> (String, SessionInfo) {
        let body = format!(
            r#"{{"username":"{name}","password":"{PASSWORD}","totp":"{}"}}"#,
            self.code(name).await
        );
        let reply = self
            .connect(from)
            .await
            .send(request("POST", "/api/v1/session", None, &body))
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.code());
        (
            reply.cookie().unwrap(),
            SessionInfo::parse(&reply.body).unwrap(),
        )
    }

    async fn get(&self, cookie: &str, from: &str) -> web_stub::Reply {
        self.connect(from)
            .await
            .send(bare("GET", "/api/v1/session", Some(cookie)))
            .await
    }

    async fn flushed(&self) {
        assert!(self.recorder.flush(Duration::from_secs(5)).await);
    }

    async fn end(self) {
        self.listener.close();
        self.pool.close().await;
        self.db.drop_database().await;
    }
}

fn digest_of(cookie: &str) -> Vec<u8> {
    let raw = URL_SAFE_NO_PAD.decode(cookie).unwrap();
    ostena_crypto::sha256::digest(&raw).to_vec()
}

#[test]
fn a_browser_session_in_postgresql() {
    block_on(async {
        let Some(f) = fixture("web_pg_session").await else {
            return;
        };
        let (cookie, info) = f.login("alice", "127.0.0.1").await;
        assert_eq!(info.username, "alice");
        assert_eq!(info.roles, []);
        // Only the digest is stored; a login session of channel web,
        // without certificate.
        let (stored, channel, certificate): (Vec<u8>, String, Option<Vec<u8>>) = sqlx::query_as(
            "SELECT w.cookie_sha256, s.channel, s.certificate_sha256
             FROM web_session w JOIN login_session s ON s.id = w.login_session_id",
        )
        .fetch_one(&f.pool)
        .await
        .unwrap();
        assert_eq!(stored, digest_of(&cookie));
        assert_ne!(stored, cookie.as_bytes());
        assert_eq!(channel, "web");
        assert!(certificate.is_none());
        let body: Vec<u8> =
            sqlx::query_scalar("SELECT body FROM audit_record WHERE event = 'login.succeeded'")
                .fetch_one(&f.pool)
                .await
                .unwrap();
        let record = ostena_audit::Record::decode(&body).unwrap();
        assert_eq!(
            record.field(ostena_audit::field::CHANNEL),
            Some(&ostena_audit::Value::Text("web".into()))
        );
        assert_eq!(audit_count(&f.pool, "login.succeeded").await, 1);

        let reply = f.get(&cookie, "127.0.0.1").await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(
            SessionInfo::parse(&reply.body).unwrap().login_session,
            info.login_session
        );

        // Re-authentication: a new value, the old one is dead.
        let body = format!(
            r#"{{"password":"{PASSWORD}","totp":"{}"}}"#,
            f.code("alice").await
        );
        let reply = f
            .connect("127.0.0.1")
            .await
            .send(request(
                "POST",
                "/api/v1/session/reauthenticate",
                Some(&cookie),
                &body,
            ))
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.code());
        let renewed = reply.cookie().unwrap();
        assert_eq!(f.get(&cookie, "127.0.0.1").await.code(), "WEB-E001");
        assert_eq!(f.get(&renewed, "127.0.0.1").await.status, StatusCode::OK);
        assert_eq!(audit_count(&f.pool, "web_session.reauthenticated").await, 1);

        // A wrong password counts toward the lockout of the account.
        let reply = f
            .connect("127.0.0.1")
            .await
            .send(request(
                "POST",
                "/api/v1/session/reauthenticate",
                Some(&renewed),
                r#"{"password":"wrong","totp":"000000"}"#,
            ))
            .await;
        assert_eq!(reply.code(), "AUTH-E001");
        let failures: i32 =
            sqlx::query_scalar("SELECT failed_attempts FROM user_credential c JOIN app_user u ON u.id = c.user_id WHERE u.name = 'alice'")
                .fetch_one(&f.pool)
                .await
                .unwrap();
        assert_eq!(failures, 1);
        assert_eq!(audit_count(&f.pool, "login.refused").await, 1);

        // Logout.
        let reply = f
            .connect("127.0.0.1")
            .await
            .send(request("DELETE", "/api/v1/session", Some(&renewed), ""))
            .await;
        assert_eq!(reply.status, StatusCode::NO_CONTENT);
        assert_eq!(f.get(&renewed, "127.0.0.1").await.code(), "WEB-E001");
        let reason: String =
            sqlx::query_scalar("SELECT revocation_reason FROM login_session WHERE channel = 'web'")
                .fetch_one(&f.pool)
                .await
                .unwrap();
        assert_eq!(reason, "déconnexion du portail");
        f.flushed().await;
        assert_eq!(audit_count(&f.pool, "login_session.revoked").await, 1);
        f.end().await;
    });
}

#[test]
fn idle_and_moved_sessions_are_revoked() {
    block_on(async {
        let Some(f) = fixture("web_pg_idle").await else {
            return;
        };
        // Idle: the deadline is the server's.
        let (idle, _) = f.login("alice", "127.0.0.1").await;
        sqlx::query("UPDATE web_session SET authenticated_at = $1, last_activity_at = $1")
            .bind(i64::try_from(now() - 901).unwrap())
            .execute(&f.pool)
            .await
            .unwrap();
        assert_eq!(f.get(&idle, "127.0.0.1").await.code(), "WEB-E001");
        assert_eq!(audit_count(&f.pool, "web_session.expired").await, 1);
        let revoked: bool = sqlx::query_scalar(
            "SELECT revoked_at IS NOT NULL FROM login_session WHERE revocation_reason = 'inactivité du portail'",
        )
        .fetch_one(&f.pool)
        .await
        .unwrap();
        assert!(revoked);

        // Another source: revoked, also for its own source afterwards.
        let (moved, _) = f.login("alice", "127.0.0.1").await;
        assert_eq!(f.get(&moved, "127.0.0.2").await.code(), "WEB-E001");
        assert_eq!(f.get(&moved, "127.0.0.1").await.code(), "WEB-E001");
        assert_eq!(audit_count(&f.pool, "web_session.source_changed").await, 1);

        // A background request does not push the idle deadline back.
        let (quiet, info) = f.login("alice", "127.0.0.1").await;
        sqlx::query("UPDATE web_session SET authenticated_at = $1, last_activity_at = $1 WHERE cookie_sha256 = $2")
            .bind(i64::try_from(now() - 600).unwrap())
            .bind(digest_of(&quiet))
            .execute(&f.pool)
            .await
            .unwrap();
        let mut background = bare("GET", "/api/v1/session", Some(&quiet));
        background
            .headers_mut()
            .insert("x-ostena-background", "1".parse().unwrap());
        let reply = f.connect("127.0.0.1").await.send(background).await;
        let seen = SessionInfo::parse(&reply.body).unwrap();
        assert_eq!(seen.idle_expires_at, now() - 600 + 900);
        // An active request does.
        let reply = f.get(&quiet, "127.0.0.1").await;
        let seen = SessionInfo::parse(&reply.body).unwrap();
        assert!(seen.idle_expires_at >= now() + 890);
        assert_eq!(seen.login_session, info.login_session);
        f.end().await;
    });
}

#[test]
fn administrators_revoke_and_disabling_ends_sessions() {
    block_on(async {
        let Some(f) = fixture("web_pg_admin").await else {
            return;
        };
        let (alice, alice_info) = f.login("alice", "127.0.0.1").await;
        let (root, root_info) = f.login("root", "127.0.0.1").await;
        assert_eq!(root_info.roles, [Role::Admin]);
        // alice is not an administrator.
        let reply = f
            .connect("127.0.0.1")
            .await
            .send(bare("GET", "/api/v1/login-sessions", Some(&alice)))
            .await;
        assert_eq!(reply.code(), "WEB-E004");
        let reply = f
            .connect("127.0.0.1")
            .await
            .send(bare("GET", "/api/v1/login-sessions", Some(&root)))
            .await;
        assert_eq!(reply.status, StatusCode::OK);
        let list = LoginSessionList::parse(&reply.body).unwrap();
        assert_eq!(list.sessions.len(), 2);
        let reply = f
            .connect("127.0.0.1")
            .await
            .send(request(
                "DELETE",
                &format!("/api/v1/login-sessions/{}", alice_info.login_session),
                Some(&root),
                r#"{"reason":"poste perdu"}"#,
            ))
            .await;
        assert_eq!(reply.status, StatusCode::NO_CONTENT, "{}", reply.code());
        assert_eq!(f.get(&alice, "127.0.0.1").await.code(), "WEB-E001");
        let (by, reason): (String, String) = sqlx::query_as(
            "SELECT revoked_by, revocation_reason FROM login_session WHERE id = $1::uuid",
        )
        .bind(&alice_info.login_session)
        .fetch_one(&f.pool)
        .await
        .unwrap();
        assert_eq!(by, format!("user:{}", root_info.user));
        assert_eq!(reason, "poste perdu");
        // An unknown session.
        let reply = f
            .connect("127.0.0.1")
            .await
            .send(request(
                "DELETE",
                "/api/v1/login-sessions/0b8f4c1e-7a52-4d0e-9f3b-2c6d1a9e8f70",
                Some(&root),
                r#"{"reason":"x"}"#,
            ))
            .await;
        assert_eq!(reply.code(), "WEB-E005");

        // Losing the role takes effect at the next request.
        assert!(
            inventory::revoke_role(&f.pool, "root", Role::Admin)
                .await
                .unwrap()
        );
        let reply = f
            .connect("127.0.0.1")
            .await
            .send(bare("GET", "/api/v1/login-sessions", Some(&root)))
            .await;
        assert_eq!(reply.code(), "WEB-E004");
        // Disabling the user revokes their browser sessions.
        inventory::disable_user(&f.pool, "root").await.unwrap();
        assert_eq!(f.get(&root, "127.0.0.1").await.code(), "WEB-E001");
        f.flushed().await;
        assert_eq!(audit_count(&f.pool, "user.role_granted").await, 1);
        assert_eq!(audit_count(&f.pool, "user.role_revoked").await, 1);
        f.end().await;
    });
}

/// `POST /api/v1/access` of `account@srv-lab01` for `cookie`.
async fn ask_access(f: &Fixture, cookie: &str, account: &str) -> web_stub::Reply {
    let body = format!(r#"{{"resource":"srv-lab01","account":"{account}","protocol":"ssh"}}"#);
    f.connect("127.0.0.1")
        .await
        .send(request("POST", "/api/v1/access", Some(cookie), &body))
        .await
}

#[test]
fn an_access_of_the_portal_issues_a_web_grant() {
    block_on(async {
        let Some(f) = fixture("web_pg_access").await else {
            return;
        };
        let (cookie, info) = f.login("alice", "127.0.0.1").await;
        let reply = ask_access(&f, &cookie, "root").await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.code());
        let granted = AccessGrant::parse(&reply.body).unwrap();
        assert_eq!(granted.grant.len(), ostena_grant::TEXT_LEN);
        assert_eq!(
            (granted.max_session_secs, granted.account.as_str()),
            (3600, "root")
        );
        // A grant of the group, bound to the browser session and the account.
        let verifier = Verifier::new(
            f.grants.keys().clone(),
            GatewayGroupId::from_bytes(GROUP.to_bytes()),
            ostena_grant::Policy::default(),
        );
        let signed = SignedGrant::from_text(&granted.grant).unwrap();
        let grant = verifier.check(signed.as_bytes(), now()).unwrap();
        let login = Uuid::parse(&info.login_session).unwrap();
        assert_eq!(grant.claims.binding, Binding::of(login.to_bytes(), "root"));
        assert_eq!(grant.expires_at, granted.expires_at);
        // Recorded with channel web, for the agent chosen, not presented.
        let (channel, agent, presented): (String, String, Option<i64>) = sqlx::query_as(
            "SELECT channel, agent_id::text, presented_at FROM access_grant WHERE jti = $1",
        )
        .bind(&grant.jti.to_bytes()[..])
        .fetch_one(&f.pool)
        .await
        .unwrap();
        assert_eq!((channel.as_str(), presented), ("web", None));
        assert_eq!(agent, AGENT.to_string());
        f.flushed().await;
        assert_eq!(audit_count(&f.pool, "access.web_granted").await, 1);

        // Never presented on the gateway: the agent cannot open it.
        let refused = ostena_core::access::open_session(
            &f.pool,
            &f.grants,
            AGENT,
            GROUP,
            1,
            &granted.grant,
            now(),
        )
        .await
        .unwrap_err();
        assert_eq!(refused.code, "ACC-E008");
        // Presented by its browser session, once.
        let by = ostena_core::access::Presenter {
            subject: Uuid::parse(&info.user).unwrap(),
            login_session: login,
            client_address: "127.0.0.1:1",
        };
        let presented =
            ostena_core::access::present_web_grant(&f.pool, &f.grants, &by, &granted.grant, now())
                .await
                .unwrap();
        assert_eq!((presented.agent, presented.group), (AGENT, GROUP));
        let again =
            ostena_core::access::present_web_grant(&f.pool, &f.grants, &by, &granted.grant, now())
                .await
                .unwrap_err();
        assert_eq!(again.code, "GTW-E001");
        let other = ostena_core::access::Presenter {
            login_session: Uuid::from_bytes([9; 16]),
            ..by
        };
        assert_eq!(
            ostena_core::access::present_web_grant(
                &f.pool,
                &f.grants,
                &other,
                &granted.grant,
                now()
            )
            .await
            .unwrap_err()
            .code,
            "GTW-E001"
        );
        // The agent opens the session as for native SSH: the web grant
        // goes the common way (ADR-0014).
        let opened = ostena_core::access::open_session(
            &f.pool,
            &f.grants,
            AGENT,
            GROUP,
            1,
            &granted.grant,
            now(),
        )
        .await
        .unwrap();
        assert!(matches!(
            opened.params,
            ostena_tunnel::control::CoreMessage::SessionParams { .. }
        ));

        // Refusals: a code and its generic label, the reason in the audit.
        let reply = ask_access(&f, &cookie, "backup").await;
        assert_eq!(
            (reply.status, reply.code().as_str()),
            (StatusCode::FORBIDDEN, "ACC-E006")
        );
        assert!(!String::from_utf8_lossy(&reply.body).contains("backup"));
        let body = r#"{"resource":"srv-absent","account":"root","protocol":"ssh"}"#;
        let reply = f
            .connect("127.0.0.1")
            .await
            .send(request("POST", "/api/v1/access", Some(&cookie), body))
            .await;
        assert_eq!(
            (reply.status, reply.code().as_str()),
            (StatusCode::FORBIDDEN, "INV-E001")
        );
        f.agents.0.store(false, Ordering::Relaxed);
        let reply = ask_access(&f, &cookie, "root").await;
        assert_eq!(
            (reply.status, reply.code().as_str()),
            (StatusCode::SERVICE_UNAVAILABLE, "GTW-E003")
        );
        f.flushed().await;
        assert_eq!(audit_count(&f.pool, "access.web_refused").await, 3);
        // Without a session, nothing is decided.
        let reply = f
            .connect("127.0.0.1")
            .await
            .send(request(
                "POST",
                "/api/v1/access",
                None,
                r#"{"resource":"srv-lab01","account":"root","protocol":"ssh"}"#,
            ))
            .await;
        assert_eq!(reply.code(), "WEB-E001");
        // The requests of one session are limited.
        f.agents.0.store(true, Ordering::Relaxed);
        let mut limited = false;
        for _ in 0..12 {
            if ask_access(&f, &cookie, "root").await.status == StatusCode::TOO_MANY_REQUESTS {
                limited = true;
                break;
            }
        }
        assert!(limited, "no limit on the access requests");
        f.end().await;
    });
}

#[test]
fn idle_browser_sessions_are_swept() {
    use ostena_core::web::session::WebBackend;
    block_on(async {
        let Some(f) = fixture("web_pg_sweep").await else {
            return;
        };
        let (idle, _) = f.login("alice", "127.0.0.1").await;
        let (active, _) = f.login("root", "127.0.0.1").await;
        sqlx::query("UPDATE web_session SET authenticated_at = $1, last_activity_at = $1 WHERE cookie_sha256 = $2")
            .bind(i64::try_from(now() - 3600).unwrap())
            .bind(digest_of(&idle))
            .execute(&f.pool)
            .await
            .unwrap();
        // Revoked without a request of its own, the other one stays.
        assert_eq!(f.backend.sweep(now(), 900).await.unwrap(), 1);
        assert_eq!(f.backend.sweep(now(), 900).await.unwrap(), 0);
        assert_eq!(
            f.get(&idle, "127.0.0.1").await.status,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(f.get(&active, "127.0.0.1").await.status, StatusCode::OK);
        f.flushed().await;
        assert_eq!(audit_count(&f.pool, "web_session.expired").await, 1);
        f.end().await;
    });
}
