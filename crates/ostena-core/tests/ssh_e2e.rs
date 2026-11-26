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
use ostena_core::functions::Functions;
use ostena_core::server::{Keys, RunningCore, StartInfo};
use ostena_core::ssh_ca::SshAuthorities;
use ostena_core::store::PgStore;
use ostena_core::transcripts::Transcripts;
use ostena_core::{inventory, login};
use ostena_crypto::hmac::HmacKey;
use ostena_crypto::p256::SigningKey;
use ostena_crypto::pki::testing::{TestPki, valid};
use ostena_crypto::pki::{pem_certificate, pem_private_key};
use ostena_crypto::tls::{self, Identity};
use ostena_grant::{Issuer, MemoryReplayStore};
use ostena_platform::private_file::{self, Reader};
use ostena_recorder::{EndReason, NoteKind};
use ostena_scope::{LocalAddresses, SharedLocalAddresses};
use ostena_ssh::transcript::Transcript;
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

fn keys(pki: TestPki, transcripts: &Path) -> Keys {
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
        transcripts: Some(Arc::new(
            Transcripts::open(
                transcripts,
                HmacKey::new(&HmacKey::generate().unwrap()).unwrap(),
            )
            .unwrap(),
        )),
    }
}

/// Runs the transcript of a session as the agent SSH server does: pump on
/// the recording stream, then `events` recorded through `Transcript`.
fn record(
    stream: ostena_tunnel::Channel,
) -> (
    Transcript,
    tokio::task::JoinHandle<Result<(), ostena_tunnel::TunnelError>>,
) {
    let (transcript, rx) = Transcript::channel(ostena_tunnel::recording::QUEUE);
    (
        transcript,
        tokio::spawn(ostena_tunnel::recording::pump(rx, stream)),
    )
}

/// The state of the transcript row of `session`.
async fn transcript_state(pool: &sqlx::PgPool, session: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT state FROM session_transcript WHERE session_id = $1::uuid")
        .bind(session.to_string())
        .fetch_optional(pool)
        .await
        .unwrap()
}

async fn until_sealed(pool: &sqlx::PgPool, session: Uuid) -> String {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        match transcript_state(pool, session).await {
            Some(state) if state != "recording" => return state,
            _ => {}
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "transcript {session} non scellé"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
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
    agent_via(
        dir,
        &format!("127.0.0.1:{port}"),
        ostena_tunnel::TransportMode::Auto,
        keys,
        cert_pem,
        key_pem,
    )
}

/// The same, dialling `core_address` with `transport`.
fn agent_via(
    dir: &Path,
    core_address: &str,
    transport: ostena_tunnel::TransportMode,
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
        core_address: core_address.to_owned(),
        certificate,
        private_key,
        root: tls::TrustAnchor::from_der(keys.root.certificate().clone()),
        hello: Hello {
            agent_version: "test".into(),
            gateway_group: group,
            config_fingerprint: format!("sha256:{}", "0".repeat(64)),
        },
        transport,
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
        db.migrate().await;
        let pool = db.pool().await;
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
        let transcripts_dir = dir.0.join("transcripts");
        let keys = keys(pki, &transcripts_dir);
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
        inventory::grant_right(
            &pool,
            "alice",
            "srv-lab01",
            "root",
            now() + 86_400,
            1800,
            Functions::NONE,
        )
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

        // Its transcript (ADR-0016): received, written, sealed.
        let session_id = opened.session.session_id;
        let (transcript, pumped) = record(opened.recording);
        // A refusal before the start is kept, then recorded (ADR-0010).
        assert!(transcript.note_later(NoteKind::Refused, b"agent-forwarding "));
        transcript
            .start(None, Some(b"cat /etc/shadow"))
            .await
            .unwrap();
        transcript
            .output(b"root:*:19000:0:99999:7:::\n")
            .await
            .unwrap();
        transcript.note(NoteKind::Transfer, b"sftp").await.unwrap();
        transcript
            .note(NoteKind::Rename, b"/tmp/a\0/tmp/b")
            .await
            .unwrap();
        assert!(transcript.note_later(NoteKind::Forward, b"port-forwarding 10.0.0.9:443"));
        transcript.end(EndReason::Closed).await.unwrap();
        drop(transcript);
        pumped.await.unwrap().unwrap();
        assert_eq!(until_sealed(&pool, session_id).await, "sealed");
        let file = keys.transcripts.as_ref().unwrap().path(session_id);
        let written = std::fs::read(&file).unwrap();
        let text = String::from_utf8(written.clone()).unwrap();
        assert!(text.starts_with("{\"version\":2,"), "{text}");
        assert!(text.contains("cat /etc/shadow") && text.contains("root:*:19000"));
        // The notes are markers of the transcript.
        for marker in [
            "\"m\",\"refused agent-forwarding \"]",
            "\"m\",\"transfer sftp\"]",
            "\"m\",\"file-rename /tmp/a -> /tmp/b\"]",
            "\"m\",\"forward port-forwarding 10.0.0.9:443\"]",
        ] {
            assert!(text.contains(marker), "{marker} in {text}");
        }
        // Transfers, refusals and forwardings are audited, not file
        // operations.
        for (event, value) in [
            ("access.ssh_request_refused", "agent-forwarding "),
            ("access.ssh_transfer", "sftp"),
            ("access.ssh_forward", "port-forwarding 10.0.0.9:443"),
        ] {
            let bodies: Vec<Vec<u8>> =
                sqlx::query_scalar("SELECT body FROM audit_record WHERE event = $1")
                    .bind(event)
                    .fetch_all(&pool)
                    .await
                    .unwrap();
            assert_eq!(bodies.len(), 1, "{event}");
            let record = ostena_audit::Record::decode(&bodies[0]).unwrap();
            assert!(
                record
                    .fields
                    .iter()
                    .any(|f| f.value == ostena_audit::Value::Text(value.to_owned())),
                "{event}: {record:?}"
            );
        }
        let (sha256, size, hmac, kid): (Vec<u8>, i64, Vec<u8>, String) = sqlx::query_as(
            "SELECT sha256, size, command_hmac, command_kid FROM session_transcript
             WHERE session_id = $1::uuid",
        )
        .bind(session_id.to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(sha256, ostena_crypto::sha256::digest(&written));
        assert_eq!(usize::try_from(size).unwrap(), written.len());
        assert_eq!(
            hmac,
            keys.transcripts
                .as_ref()
                .unwrap()
                .command_tag(session_id, b"cat /etc/shadow")
        );
        let key_id = keys.transcripts.as_ref().unwrap().key_id();
        assert_eq!(kid, key_id);
        assert_eq!(key_id.len(), 16);
        // The seal carries the keyed hash and the key identifier (R2).
        let fields: Vec<u8> = sqlx::query_scalar(
            "SELECT body FROM audit_record WHERE event = 'transcript.sealed' ORDER BY seq DESC LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let sealed_record = ostena_audit::Record::decode(&fields).unwrap();
        let get = |name: &str| {
            sealed_record
                .fields
                .iter()
                .find(|f| f.name == name)
                .map(|f| f.value.clone())
        };
        assert_eq!(
            get("command_hmac"),
            Some(ostena_audit::Value::Bytes(hmac.clone()))
        );
        assert_eq!(
            get("kid"),
            Some(ostena_audit::Value::Text(key_id.to_owned()))
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&file).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o400);
        }

        // A stream for a session of nobody: refused, the agent sees it.
        let foreign = link
            .open_channel(
                Uuid::random().unwrap(),
                ostena_tunnel::StreamClass::Recording,
            )
            .await
            .unwrap();
        let (transcript, pumped) = record(foreign);
        transcript.start(None, None).await.unwrap();
        tokio::time::timeout(WAIT, transcript.closed())
            .await
            .unwrap();
        assert!(pumped.await.unwrap().is_err());
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
        let live = gateway
            .open_ssh_session(&access(second, second_cert, "root"), now(), &replay)
            .await
            .unwrap();
        let live_id = live.session.session_id;
        let (live_transcript, live_pumped) = record(live.recording);
        live_transcript.start(None, None).await.unwrap();
        live_transcript.output(b"$ ").await.unwrap();
        until("transcript en cours", || {
            keys.transcripts.as_ref().unwrap().path(live_id).exists()
        })
        .await;
        core.stop().await;
        // Fail closed: the stop of the core cuts the live session.
        tokio::time::timeout(WAIT, live_transcript.closed())
            .await
            .unwrap();
        assert!(live_pumped.await.unwrap().is_err());
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
        // Cut by the stop: sealed incomplete, by the core that stopped or
        // at this start.
        assert_eq!(until_sealed(&pool, live_id).await, "incomplete");

        // Refused streams beyond the limit: the core closes the tunnel of
        // the agent, which reconnects.
        let connections = link.status().connections;
        let mut sent = 0;
        while link.status().connections == connections {
            assert!(sent < 40, "tunnel jamais fermé");
            sent += 1;
            let Ok(foreign) = link
                .open_channel(
                    Uuid::random().unwrap(),
                    ostena_tunnel::StreamClass::Recording,
                )
                .await
            else {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            };
            let (transcript, pumped) = record(foreign);
            let _ = transcript.start(None, None).await;
            let _ = tokio::time::timeout(WAIT, transcript.closed()).await;
            drop(transcript);
            let _ = pumped.await;
        }
        assert!(sent > 8, "{sent}");
        core.stop().await;

        // The audit export and the transcript directory verify offline.
        let (export, _) = ostena_core::audit::export(&pool, Vec::new(), None)
            .await
            .unwrap();
        let mut trusted = ostena_audit::TrustedKeys::new();
        trusted.insert(keys.audit.verifying_key()).unwrap();
        let mut report = ostena_audit::verify_export(
            export.as_slice(),
            trusted,
            ostena_audit::Options::default(),
        )
        .unwrap();
        assert_eq!(report.transcripts.len(), 2);
        ostena_audit::transcripts::check(&mut report, &transcripts_dir).unwrap();
        let codes: Vec<&str> = report
            .findings
            .iter()
            .map(ostena_audit::Finding::code)
            .collect();
        assert!(!codes.iter().any(|c| c.starts_with("AUD-E")), "{codes:?}");
        assert!(codes.contains(&"AUD-W006"), "{codes:?}");

        let events: Vec<String> = sqlx::query_scalar(
            "SELECT event FROM audit_record WHERE event LIKE 'access.%'
                OR event LIKE 'ssh.%' OR event LIKE 'login_session.%'
                OR event LIKE 'transcript.%' ORDER BY seq",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        for expected in [
            "ssh.host_certified",
            "access.ssh_granted",
            "access.session_opened",
            "access.ssh_refused",
            "access.ssh_exec",
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
        db.migrate().await;
        let pool = db.pool().await;
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
        let keys = keys(pki, &dir.0.join("transcripts"));
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
        inventory::grant_right(
            &pool,
            "alice",
            "srv-lab01",
            "root",
            now() + 86_400,
            1800,
            Functions::NONE,
        )
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
        // As the login role: ostena_app sees neither the queries of the
        // sessions nor may it end them.
        let login = db.login_pool().await;
        let cut: Vec<bool> = sqlx::query_scalar(
            "SELECT pg_terminate_backend(pid, 5000) FROM pg_stat_activity
             WHERE datname = current_database() AND query ILIKE 'LISTEN%'",
        )
        .fetch_all(&login)
        .await
        .unwrap();
        login.close().await;
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

/// A UDP relay between the agent and the core that can drop every packet,
/// as a network cut does: neither end sees a close, each finds the
/// connection lost after its idle delay.
struct Cut {
    addr: std::net::SocketAddr,
    blocked: Arc<std::sync::atomic::AtomicBool>,
}

impl Cut {
    async fn start(core: std::net::SocketAddr) -> Self {
        use std::sync::atomic::{AtomicBool, Ordering};
        let front = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let back = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        back.connect(core).await.unwrap();
        let blocked = Arc::new(AtomicBool::new(false));
        let client = Arc::new(Mutex::new(None::<std::net::SocketAddr>));
        tokio::spawn({
            let (front, back, blocked, client) =
                (front.clone(), back.clone(), blocked.clone(), client.clone());
            async move {
                let mut buf = vec![0u8; 65_536];
                while let Ok((n, from)) = front.recv_from(&mut buf).await {
                    if blocked.load(Ordering::SeqCst) {
                        continue;
                    }
                    *client.lock().unwrap() = Some(from);
                    let _ = back.send(&buf[..n]).await;
                }
            }
        });
        tokio::spawn({
            let (front, blocked) = (front.clone(), blocked.clone());
            async move {
                let mut buf = vec![0u8; 65_536];
                while let Ok(n) = back.recv(&mut buf).await {
                    let to = *client.lock().unwrap();
                    if blocked.load(Ordering::SeqCst) {
                        continue;
                    }
                    if let Some(to) = to {
                        let _ = front.send_to(&buf[..n], to).await;
                    }
                }
            }
        });
        Self {
            addr: front.local_addr().unwrap(),
            blocked,
        }
    }

    fn set(&self, blocked: bool) {
        self.blocked
            .store(blocked, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Runs the transcript of a session with a grace, as the agent SSH server
/// does (ADR-0016).
fn record_with_grace(
    link: &Arc<AgentLink>,
    session: Uuid,
    stream: ostena_tunnel::Channel,
    grace: Duration,
) -> (
    Transcript,
    tokio::task::JoinHandle<Result<(), ostena_tunnel::TunnelError>>,
) {
    use ostena_tunnel::recording::{Options, QUEUE, Resume, run};
    let (transcript, rx) = Transcript::channel(QUEUE);
    let options = Options {
        resume: Some(Resume {
            link: link.clone(),
            session,
            grace,
        }),
        ..Options::default()
    };
    (transcript, tokio::spawn(run(rx, stream, options)))
}

/// Criterion L2 of the tunnel (ADR-0008, ADR-0016): a 30 s network cut
/// between the agent and the core. The link comes back on its own; a
/// session whose grace is longer than the cut is kept, what it showed
/// during the cut reaches the core once the transcript is resumed, and the
/// transcript is sealed complete. A session whose grace is shorter is cut,
/// and its transcript is sealed incomplete: nothing is lost silently.
#[test]
fn a_network_cut_shorter_than_the_grace_keeps_the_ssh_sessions() {
    block_on(async {
        let Some(db) = TestDb::create("a_network_cut_shorter_than_the_grace_keeps_ssh").await
        else {
            return;
        };
        db.migrate().await;
        let pool = db.pool().await;
        let dir =
            Dir(std::env::temp_dir().join(format!("ostena-core-ssh-grace-{}", std::process::id())));
        let _ = std::fs::remove_dir_all(&dir.0);
        std::fs::create_dir_all(&dir.0).unwrap();
        let pki = TestPki::new("Ostena grace").unwrap();
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
        let keys = keys(pki, &dir.0.join("transcripts"));
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
        let cut = Cut::start(core.tunnel_addr()).await;
        // SECRET-EXPOSURE: test only, the key file `agent enroll` would write.
        #[expect(clippy::disallowed_methods)]
        let key_pem = pem_private_key(&agent_pkcs8).expose_secret().to_vec();
        let (gateway, link) = agent_via(
            &dir.0,
            &cut.addr.to_string(),
            ostena_tunnel::TransportMode::Quic,
            &keys,
            &pem_certificate(&agent_cert),
            &key_pem,
        );
        until("politique et clés", || {
            let v = gateway.state().versions();
            v.policy.is_some() && v.keyset.is_some() && v.ssh_trust.is_some()
        })
        .await;

        // Two live sessions: one with a grace of 60 s, one of 3 s.
        let cert = [0xe1; 32];
        let login_session = open_login(&pool, user, cert).await;
        let access = SshAccess {
            subject: user,
            login_session,
            certificate_sha256: cert,
            account: "root".into(),
            resource: "srv-lab01".into(),
            client_address: "192.0.2.7:50022".parse().unwrap(),
        };
        let replay = MemoryReplayStore::default();
        let kept = gateway
            .open_ssh_session(&access, now(), &replay)
            .await
            .unwrap();
        let kept_id = kept.session.session_id;
        let (kept_transcript, kept_pumped) =
            record_with_grace(&link, kept_id, kept.recording, Duration::from_secs(60));
        let short = gateway
            .open_ssh_session(&access, now(), &replay)
            .await
            .unwrap();
        let short_id = short.session.session_id;
        let (short_transcript, short_pumped) =
            record_with_grace(&link, short_id, short.recording, Duration::from_secs(3));
        kept_transcript.start(None, None).await.unwrap();
        kept_transcript.output(b"before the cut\n").await.unwrap();
        short_transcript.start(None, None).await.unwrap();
        short_transcript.output(b"short grace\n").await.unwrap();
        until("transcripts en cours", || {
            let t = keys.transcripts.as_ref().unwrap();
            t.path(kept_id).exists() && t.path(short_id).exists()
        })
        .await;
        tokio::time::sleep(Duration::from_millis(500)).await;

        // The cut: 30 s, the session keeps showing output meanwhile.
        cut.set(true);
        let started = tokio::time::Instant::now();
        let mut shown = vec![b"before the cut\n".to_vec()];
        let mut i = 0;
        while started.elapsed() < Duration::from_secs(30) {
            let output = format!("during the cut {i}\n").into_bytes();
            kept_transcript.output(&output).await.unwrap();
            shown.push(output);
            i += 1;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        // The short grace is over: that session is cut.
        tokio::time::timeout(Duration::from_millis(10), short_transcript.closed())
            .await
            .expect("session with a 3 s grace cut during a 30 s cut");
        let error = short_pumped.await.unwrap().unwrap_err().to_string();
        assert!(error.contains("grâce"), "{error}");
        cut.set(false);

        // The link comes back by itself, the transcript is resumed.
        until("lien rétabli", || link.status().connections >= 2).await;
        let output = b"after the cut\n".to_vec();
        kept_transcript.output(&output).await.unwrap();
        shown.push(output);
        kept_transcript.end(EndReason::Closed).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), kept_transcript.closed())
                .await
                .is_err(),
            "session with a 60 s grace kept"
        );
        drop(kept_transcript);
        tokio::time::timeout(Duration::from_secs(30), kept_pumped)
            .await
            .expect("transcript resumed and acknowledged")
            .unwrap()
            .unwrap();
        assert_eq!(until_sealed(&pool, kept_id).await, "sealed");
        let text = String::from_utf8(
            std::fs::read(keys.transcripts.as_ref().unwrap().path(kept_id)).unwrap(),
        )
        .unwrap();
        let mut at = 0;
        for line in &shown {
            let escaped = String::from_utf8(line.clone())
                .unwrap()
                .replace('\n', "\\n");
            let found = text[at..]
                .find(&escaped)
                .unwrap_or_else(|| panic!("{escaped} absent ou déplacé"));
            at += found + escaped.len();
        }

        // The cut session: sealed incomplete once the core's wait is over
        // (grace announced plus margin), never left unsealed.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            if transcript_state(&pool, short_id).await.as_deref() == Some("incomplete") {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "transcript coupé non scellé incomplet"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let seal_code: Option<String> =
            sqlx::query_scalar("SELECT code FROM session_transcript WHERE session_id = $1::uuid")
                .bind(short_id.to_string())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(seal_code.as_deref(), Some("REC-E005"));
        core.stop().await;
        drop(gateway);
        link.stop().await;
        pool.close().await;
        db.drop_database().await;
    });
}
