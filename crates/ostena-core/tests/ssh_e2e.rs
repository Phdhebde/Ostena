//! Native SSH authorisation end to end (ADR-0014): the real core on a
//! PostgreSQL server, an agent link and gateway of `ostena-tunnel`. The
//! agent receives the key set, the policy and the SSH trust when it
//! connects, gets its host key certified, asks for a grant and opens a
//! session; a revoked login session reaches it at once, and again when it
//! reconnects after a revocation made while it was cut off.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test helpers and scenarios"
)]

mod common;

use std::net::{Ipv4Addr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{TestDb, block_on};
use ostena_common::config::scope::{AllowRuleSpec, PolicySpec};
use ostena_common::config::{CoreConfig, Mode};
use ostena_core::cache::AgentCache;
use ostena_core::server::{Keys, RunningCore, StartInfo};
use ostena_core::ssh_ca::SshAuthorities;
use ostena_core::store::PgStore;
use ostena_core::{inventory, login, schema};
use ostena_crypto::p256::SigningKey;
use ostena_crypto::pki::testing::{TestPki, valid};
use ostena_crypto::pki::{pem_certificate, pem_private_key};
use ostena_crypto::tls::{self, Identity};
use ostena_grant::{Issuer, MemoryReplayStore};
use ostena_platform::private_file::{self, Reader};
use ostena_scope::{LocalAddresses, SharedLocalAddresses};
use ostena_tunnel::enroll::AgentRegistry;
use ostena_tunnel::gateway::{Gateway, GatewayParams, GatewayState, SshAccess};
use ostena_tunnel::link::{AgentLink, Backoff, LinkParams, SystemClock};
use ostena_tunnel::{Hello, Limits, Uuid};
use tokio::sync::broadcast;

const GROUP: &str = "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6";
const WAIT: Duration = Duration::from_secs(15);

fn now() -> u64 {
    ostena_grant::unix_now()
}

fn free_port() -> u16 {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn config(port: u16) -> CoreConfig {
    // Key sources are not read: the keys are built in memory below.
    toml::from_str(&format!(
        "tunnel_listen = \"127.0.0.1:{port}\"\n\
         enrollment_listen = \"127.0.0.1:{}\"\n\
         tls_root_ca = \"/unused/root.pem\"\n\
         tls_certificate = \"/unused/server.pem\"\n\
         tls_private_key = {{ credential = \"server.key\" }}\n\
         issuing_certificate = \"/unused/issuing.pem\"\n\
         issuing_private_key = {{ credential = \"issuing.key\" }}\n\
         grant_signing_key = {{ credential = \"grant.key\" }}\n\
         [audit]\nsigning_key = {{ credential = \"audit.key\" }}\nhead_interval_secs = 1\n",
        free_port()
    ))
    .unwrap()
}

fn keys(pki: TestPki) -> Keys {
    let (server_key, server_pkcs8) = SigningKey::generate().unwrap();
    let server = pki
        .root
        .sign_server(&server_key.verifying_key(), &["127.0.0.1"], valid())
        .unwrap();
    Keys {
        root: pki.root_anchor(),
        server: Identity::new(vec![server], server_pkcs8).unwrap(),
        issuing: Arc::new(pki.issuing),
        audit: Arc::new(SigningKey::generate().unwrap().0),
        grant: Arc::new(Issuer::new(SigningKey::generate().unwrap().0)),
        ssh: Some(Arc::new(
            SshAuthorities::new(
                SigningKey::generate().unwrap().0,
                SigningKey::generate().unwrap().0,
                30,
            )
            .unwrap(),
        )),
        totp: None,
    }
}

fn allow_lab() -> PolicySpec {
    PolicySpec {
        allow: vec![AllowRuleSpec {
            label: None,
            networks: vec!["10.20.0.0/16".into()],
            ports: vec!["22".into()],
        }],
        ..PolicySpec::default()
    }
}

/// The agent: a link to the core and its gateway, with files in `dir`; the
/// link also carries the host key, as the agent SSH server sends it.
fn agent(
    dir: &Path,
    port: u16,
    keys: &Keys,
    cert_pem: &str,
    key_pem: &[u8],
) -> (Gateway, Arc<AgentLink>) {
    let certificate = dir.join("agent.crt");
    let private_key = dir.join("agent.key");
    std::fs::write(&certificate, cert_pem).unwrap();
    private_file::create(&private_key, key_pem, Reader::CurrentProcess).unwrap();
    let group = Uuid::parse(GROUP).unwrap();
    let link = Arc::new(AgentLink::spawn(LinkParams {
        core_address: format!("127.0.0.1:{port}"),
        certificate,
        private_key,
        root: tls::TrustAnchor::from_der(keys.root.certificate().clone()),
        hello: Hello {
            agent_version: "test".into(),
            gateway_group: group,
            config_fingerprint: format!("sha256:{}", "0".repeat(64)),
        },
        limits: Limits::default(),
        backoff: Backoff {
            base: Duration::from_millis(100),
            max: Duration::from_millis(400),
            stable_after: Duration::from_secs(60),
        },
        clock: Arc::new(SystemClock),
        write_key: |path, bytes| private_file::create(path, bytes, Reader::CurrentProcess),
    }));
    let state = GatewayState::open(GatewayParams {
        gateway_group: group,
        mode: Mode::Production,
        local_policy: PolicySpec {
            gateway_group: GROUP.into(),
            ..allow_lab()
        },
        infrastructure: Arc::new(Mutex::new(Vec::new())),
        local_addresses: SharedLocalAddresses::new(LocalAddresses::from_addrs([])),
        keyset_state: dir.join("keyset.version"),
        write_private: |path, bytes| private_file::create(path, bytes, Reader::CurrentProcess),
        grant_policy: ostena_grant::Policy::default(),
    })
    .unwrap();
    (Gateway::start(Arc::new(state), link.clone()).unwrap(), link)
}

async fn until(what: &str, check: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !check() {
        assert!(tokio::time::Instant::now() < deadline, "attente : {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn revoked(receiver: &mut broadcast::Receiver<Uuid>, session: Uuid) {
    let found = tokio::time::timeout(WAIT, async {
        loop {
            if receiver.recv().await.unwrap() == session {
                return;
            }
        }
    })
    .await;
    assert!(found.is_ok(), "login_revoked {session} non reçu");
}

async fn open_login(pool: &sqlx::PgPool, user: Uuid, cert: [u8; 32]) -> Uuid {
    let session = login::new_session_id().unwrap();
    let mut tx = pool.begin().await.unwrap();
    login::open_session(&mut tx, session, user, cert, now() + 3600)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    session
}

#[test]
fn ssh_access_and_login_revocation_end_to_end() {
    block_on(async {
        let Some(db) = TestDb::create("ssh_access_and_login_revocation_end_to_end").await else {
            return;
        };
        let pool = db.pool().await;
        schema::migrate(&pool).await.unwrap();
        let dir =
            Dir(std::env::temp_dir().join(format!("ostena-core-ssh-e2e-{}", std::process::id())));
        let _ = std::fs::remove_dir_all(&dir.0);
        std::fs::create_dir_all(&dir.0).unwrap();

        // The PKI, the agent certificate registered, the inventory.
        let pki = TestPki::new("Ostena e2e").unwrap();
        let group = Uuid::parse(GROUP).unwrap();
        let agent_id = Uuid::random().unwrap();
        let (agent_key, agent_pkcs8) = SigningKey::generate().unwrap();
        let agent_cert = pki
            .issuing
            .issue_agent(
                &agent_key.verifying_key(),
                GROUP,
                &agent_id.to_string(),
                valid(),
            )
            .unwrap();
        let fingerprint = tls::fingerprint(&agent_cert);
        let keys = keys(pki);
        let store = PgStore::new(pool.clone(), Arc::new(AgentCache::default()));
        ostena_core::audit::ensure_genesis(&pool).await.unwrap();
        store.register(fingerprint, group, agent_id).await.unwrap();
        inventory::create_group(&pool, Some(group), "lab", &["bastion.lab".into()])
            .await
            .unwrap();
        inventory::set_group_policy(&pool, "lab", &allow_lab())
            .await
            .unwrap();
        let user = inventory::add_user(&pool, "alice", "Alice").await.unwrap();
        let target = SigningKey::generate().unwrap().0.verifying_key();
        inventory::add_resource(&pool, "srv-lab01", "10.20.0.5", 22, "lab", &target)
            .await
            .unwrap();
        for account in ["root", "backup"] {
            inventory::add_account(&pool, "srv-lab01", account)
                .await
                .unwrap();
        }
        inventory::grant_right(&pool, "alice", "srv-lab01", "root", now() + 86_400, 1800)
            .await
            .unwrap();

        // The core, then the agent: it receives the pushes.
        let port = free_port();
        let config = config(port);
        let core_store = || PgStore::new(pool.clone(), Arc::new(AgentCache::default()));
        let core = RunningCore::start(&config, core_store(), &keys, &StartInfo::default())
            .await
            .unwrap();
        // SECRET-EXPOSURE: test only, the key file `agent enroll` would write.
        #[expect(clippy::disallowed_methods)]
        let key_pem = pem_private_key(&agent_pkcs8).expose_secret().to_vec();
        let (gateway, link) = agent(&dir.0, port, &keys, &pem_certificate(&agent_cert), &key_pem);
        let mut revocations = gateway.subscribe_login_revocations();
        until("politique, clés et confiance SSH", || {
            let v = gateway.state().versions();
            v.policy.is_some() && v.keyset.is_some() && v.ssh_trust.is_some()
        })
        .await;
        let ssh = keys.ssh.as_ref().unwrap();
        let trust = gateway.state().ssh_trust().unwrap();
        assert_eq!(trust.user_cas, [ssh.user_ca_public()]);
        assert_eq!(trust.host_cas, [ssh.host_ca_public()]);
        assert!(trust.host_certificate.is_none());

        // The host key, certified with the SSH host names of the group.
        let (host_key, _) = SigningKey::generate().unwrap();
        let message = ostena_tunnel::ssh::host_key_message(&host_key, &fingerprint).unwrap();
        link.send(&message).await.unwrap();
        until("certificat d'hôte", || {
            gateway
                .state()
                .ssh_trust()
                .is_some_and(|t| t.host_certificate.is_some())
        })
        .await;
        let trust = gateway.state().ssh_trust().unwrap();
        let blob = trust.host_certificate.as_deref().unwrap();
        let parsed = ostena_ssh::cert::parse(blob).unwrap();
        parsed.verify(&[ssh.host_ca_public()]).unwrap();
        ostena_ssh::cert::check_host(&parsed, &host_key.verifying_key(), now()).unwrap();
        assert_eq!(parsed.principals, ["bastion.lab"]);

        // A native SSH access: grant, then session.
        let cert = [0xc5; 32];
        let first = open_login(&pool, user, cert).await;
        let access = |session: Uuid, cert: [u8; 32], account: &str| SshAccess {
            subject: user,
            login_session: session,
            certificate_sha256: cert,
            account: account.into(),
            resource: "srv-lab01".into(),
            client_address: "192.0.2.7:50022".parse().unwrap(),
        };
        let replay = MemoryReplayStore::default();
        let opened = gateway
            .open_ssh_session(&access(first, cert, "root"), now(), &replay)
            .await
            .unwrap();
        assert_eq!(opened.account, "root");
        assert_eq!(opened.target_host_key, target);
        assert_eq!(opened.session.max_session_secs, 1800);
        // No right on backup: the precise code reaches the agent.
        let refused = gateway
            .open_ssh_session(&access(first, cert, "backup"), now(), &replay)
            .await
            .unwrap_err();
        assert_eq!(refused.code(), "ACC-E006");

        // Revoked while connected: the agent is told at once.
        login::revoke_session(&pool, first, "poste perdu")
            .await
            .unwrap();
        revoked(&mut revocations, first).await;
        let refused = gateway
            .open_ssh_session(&access(first, cert, "root"), now(), &replay)
            .await
            .unwrap_err();
        assert_eq!(refused.code(), "ACC-E003");

        // Revoked while the agent is cut off (the core is stopped): told
        // again when it reconnects.
        let second_cert = [0xd7; 32];
        let second = open_login(&pool, user, second_cert).await;
        gateway
            .open_ssh_session(&access(second, second_cert, "root"), now(), &replay)
            .await
            .unwrap();
        core.stop().await;
        login::revoke_session(&pool, second, "révocation hors ligne")
            .await
            .unwrap();
        // The sockets of the stopped core are released once its tasks end.
        let mut attempts = 0;
        let core = loop {
            match RunningCore::start(&config, core_store(), &keys, &StartInfo::default()).await {
                Ok(core) => break core,
                Err(e) if attempts < 50 => {
                    attempts += 1;
                    assert_eq!(e.code(), "CORE-E007", "{e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(e) => panic!("{e}"),
            }
        };
        revoked(&mut revocations, second).await;
        core.stop().await;

        let events: Vec<String> = sqlx::query_scalar(
            "SELECT event FROM audit_record WHERE event LIKE 'access.%'
                OR event LIKE 'ssh.%' OR event LIKE 'login_session.%' ORDER BY seq",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        for expected in [
            "ssh.host_certified",
            "access.ssh_granted",
            "access.session_opened",
            "access.ssh_refused",
            "login_session.revoked",
            "login_session.revocation_applied",
        ] {
            assert!(
                events.iter().any(|e| e == expected),
                "{expected} : {events:?}"
            );
        }
        drop(gateway);
        link.stop().await;
        pool.close().await;
        db.drop_database().await;
    });
}

/// Notices sent while the core cannot hear them are lost; once its
/// listening connection is cut and opened again, the core replays what they
/// would have applied: a revoked login session and new host names of the
/// group reach the connected agent. Then, too many grant requests from the
/// agent are refused by the limit (`ACC-E009`).
#[test]
fn notices_lost_while_the_listener_is_cut_are_replayed() {
    block_on(async {
        let Some(db) = TestDb::create("notices_lost_while_the_listener_is_cut_are_replayed").await
        else {
            return;
        };
        let pool = db.pool().await;
        schema::migrate(&pool).await.unwrap();
        let dir = Dir(
            std::env::temp_dir().join(format!("ostena-core-ssh-replay-{}", std::process::id()))
        );
        let _ = std::fs::remove_dir_all(&dir.0);
        std::fs::create_dir_all(&dir.0).unwrap();
        let pki = TestPki::new("Ostena replay").unwrap();
        let group = Uuid::parse(GROUP).unwrap();
        let agent_id = Uuid::random().unwrap();
        let (agent_key, agent_pkcs8) = SigningKey::generate().unwrap();
        let agent_cert = pki
            .issuing
            .issue_agent(
                &agent_key.verifying_key(),
                GROUP,
                &agent_id.to_string(),
                valid(),
            )
            .unwrap();
        let fingerprint = tls::fingerprint(&agent_cert);
        let keys = keys(pki);
        let store = PgStore::new(pool.clone(), Arc::new(AgentCache::default()));
        ostena_core::audit::ensure_genesis(&pool).await.unwrap();
        store.register(fingerprint, group, agent_id).await.unwrap();
        inventory::create_group(&pool, Some(group), "lab", &["bastion.lab".into()])
            .await
            .unwrap();
        inventory::set_group_policy(&pool, "lab", &allow_lab())
            .await
            .unwrap();
        let user = inventory::add_user(&pool, "alice", "Alice").await.unwrap();
        let target = SigningKey::generate().unwrap().0.verifying_key();
        inventory::add_resource(&pool, "srv-lab01", "10.20.0.5", 22, "lab", &target)
            .await
            .unwrap();
        inventory::add_account(&pool, "srv-lab01", "root")
            .await
            .unwrap();
        inventory::grant_right(&pool, "alice", "srv-lab01", "root", now() + 86_400, 1800)
            .await
            .unwrap();

        let port = free_port();
        let config = config(port);
        let core = RunningCore::start(
            &config,
            PgStore::new(pool.clone(), Arc::new(AgentCache::default())),
            &keys,
            &StartInfo::default(),
        )
        .await
        .unwrap();
        // SECRET-EXPOSURE: test only, the key file `agent enroll` would write.
        #[expect(clippy::disallowed_methods)]
        let key_pem = pem_private_key(&agent_pkcs8).expose_secret().to_vec();
        let (gateway, link) = agent(&dir.0, port, &keys, &pem_certificate(&agent_cert), &key_pem);
        let mut revocations = gateway.subscribe_login_revocations();
        until("politique et clés de grant", || {
            let v = gateway.state().versions();
            v.policy.is_some() && v.keyset.is_some()
        })
        .await;
        let (host_key, _) = SigningKey::generate().unwrap();
        let message = ostena_tunnel::ssh::host_key_message(&host_key, &fingerprint).unwrap();
        link.send(&message).await.unwrap();
        let principals = || {
            gateway
                .state()
                .ssh_trust()
                .and_then(|t| {
                    let blob = t.host_certificate.clone()?;
                    let parsed = ostena_ssh::cert::parse(&blob).ok()?;
                    Some(
                        parsed
                            .principals
                            .iter()
                            .map(|p| (*p).to_owned())
                            .collect::<Vec<_>>(),
                    )
                })
                .unwrap_or_default()
        };
        until("certificat d'hôte", || principals() == ["bastion.lab"]).await;
        let cert = [0xc5; 32];
        let session = open_login(&pool, user, cert).await;
        let access = SshAccess {
            subject: user,
            login_session: session,
            certificate_sha256: cert,
            account: "root".into(),
            resource: "srv-lab01".into(),
            client_address: "192.0.2.7:50022".parse().unwrap(),
        };
        gateway
            .open_ssh_session(&access, now(), &MemoryReplayStore::default())
            .await
            .unwrap();

        // Two changes whose notices are lost (made without notifying), then
        // the server cuts the listening connection of the core.
        sqlx::query(
            "UPDATE login_session SET revoked_at = now(), revoked_by = 'test'
             WHERE id = $1::uuid",
        )
        .bind(session.to_string())
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("UPDATE gateway_group SET ssh_host_names = '{jump.lab}' WHERE id = $1::uuid")
            .bind(GROUP)
            .execute(&pool)
            .await
            .unwrap();
        let cut: Vec<bool> = sqlx::query_scalar(
            "SELECT pg_terminate_backend(pid, 5000) FROM pg_stat_activity
             WHERE datname = current_database() AND query ILIKE 'LISTEN%'",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(cut, [true]);
        revoked(&mut revocations, session).await;
        until("certificat d'hôte des nouveaux noms", || {
            principals() == ["jump.lab"]
        })
        .await;

        // Too many grant requests from one agent: refused by the limit,
        // before the database, after the burst.
        let replay = MemoryReplayStore::default();
        let mut answered = 0;
        let limited = loop {
            let refusal = gateway
                .open_ssh_session(&access, now(), &replay)
                .await
                .unwrap_err()
                .code();
            if refusal == "ACC-E009" {
                break true;
            }
            assert_eq!(refusal, "ACC-E003");
            answered += 1;
            if answered > 200 {
                break false;
            }
        };
        assert!(limited && answered >= 40, "{answered}");

        core.stop().await;
        drop(gateway);
        link.stop().await;
        pool.close().await;
        db.drop_database().await;
    });
}
