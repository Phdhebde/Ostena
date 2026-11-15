//! End to end native SSH access for `tests/ssh/native-e2e.sh`: the agent
//! SSH server, deciding through the gateway and the in-process test core
//! (grant, jti consumed on both sides, scope pinning), its driver joining a
//! real OpenSSH target. Built from dev-dependencies only (test core): never
//! part of `ostena`.
//!
//! ```text
//! gateway_e2e --target <ip:port> --target-host-key <public key file>
//!             --agent-key <private key file> --user-public <public key file>
//!             --account <account> --work <directory>
//! ```
//!
//! The target is published as the resource `debian12`. Once ready, the
//! directory holds `port`, `user-cert.pub` (certificate of the user key,
//! signed by the test core authority) and `known_hosts` (the host
//! authority, `@cert-authority`). JSON events go to the standard output.
//! Serves until killed.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "test helper: fixed inputs, prints its results"
)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ostena_common::config::{LoggingConfig, Mode};
use ostena_common::secret::SecretBytes;
use ostena_crypto::p256::{SigningKey, VerifyingKey};
use ostena_grant::MemoryReplayStore;
use ostena_scope::{AllowRuleSpec, LocalAddresses, PolicySpec, SharedLocalAddresses};
use ostena_ssh::cert::{self, Kind, Template};
use ostena_ssh::server::{
    AccessRequest, Authorized, Authorizer, Refusal, ServerSettings, SessionSummary, SshIdentity,
    SshServer,
};
use ostena_tunnel::control::CoreMessage;
use ostena_tunnel::gateway::{Gateway, GatewayParams, GatewayState, SshAccess};
use ostena_tunnel::link::{AgentLink, Backoff, LinkParams, LinkState, SystemClock};
use ostena_tunnel::testing::{Behaviour, SshResource, TestCore, valid};
use ostena_tunnel::{Hello, Limits, Uuid};

const GROUP: &str = "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6";

struct Args {
    target: std::net::SocketAddr,
    target_host_key: PathBuf,
    agent_key: PathBuf,
    user_public: PathBuf,
    account: String,
    work: PathBuf,
}

fn args() -> Args {
    let mut it = std::env::args().skip(1);
    let mut get = |name: &str| {
        assert_eq!(it.next().as_deref(), Some(name), "attendu {name}");
        it.next().expect("valeur manquante")
    };
    Args {
        target: get("--target").parse().expect("--target ip:port"),
        target_host_key: get("--target-host-key").into(),
        agent_key: get("--agent-key").into(),
        user_public: get("--user-public").into(),
        account: get("--account"),
        work: get("--work").into(),
    }
}

/// The P-256 point of an OpenSSH public key line.
fn point_of_line(path: &Path) -> VerifyingKey {
    let line = std::fs::read_to_string(path).unwrap();
    let blob = STANDARD
        .decode(line.split_whitespace().nth(1).unwrap())
        .unwrap();
    let point: [u8; 65] = blob[blob.len() - 65..].try_into().unwrap();
    VerifyingKey::from_bytes(&point).unwrap()
}

fn public_line(key: &VerifyingKey) -> String {
    let mut blob = Vec::new();
    for part in [&b"ecdsa-sha2-nistp256"[..], b"nistp256", &key.to_bytes()] {
        blob.extend_from_slice(&u32::try_from(part.len()).unwrap().to_be_bytes());
        blob.extend_from_slice(part);
    }
    format!("ecdsa-sha2-nistp256 {}", STANDARD.encode(blob))
}

fn write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

/// Decides through the gateway: grant from the core, jti consumed on both
/// sides, target pinned by the scope control.
struct ViaGateway {
    gateway: Gateway,
    store: MemoryReplayStore,
}

impl Authorizer for ViaGateway {
    async fn authorize(&self, request: AccessRequest) -> Result<Authorized, Refusal> {
        let access = SshAccess {
            subject: Uuid::from_bytes(request.identity.subject),
            login_session: Uuid::from_bytes(request.identity.login_session),
            certificate_sha256: request.identity.certificate_sha256,
            account: request.account.clone(),
            resource: request.resource.clone(),
            client_address: request.client_address,
        };
        match self
            .gateway
            .open_ssh_session(&access, ostena_grant::unix_now(), &self.store)
            .await
        {
            Ok(session) => Ok(Authorized {
                session_id: session.session.session_id.to_bytes(),
                target: session.session.target,
                target_host_key: session.target_host_key,
                account: session.account,
                max_session: Duration::from_secs(session.session.max_session_secs.into()),
            }),
            Err(e) => Err(Refusal {
                code: e.code(),
                message: e.to_string(),
            }),
        }
    }

    fn closed(&self, summary: SessionSummary) {
        println!(
            "closed reason={} bytes_to_target={} bytes_from_target={}",
            summary.reason, summary.bytes_to_target, summary.bytes_from_target
        );
    }
}

#[allow(clippy::too_many_lines, reason = "one linear scenario")]
async fn run(args: Args) {
    let group = Uuid::parse(GROUP).unwrap();
    let core = TestCore::start(Limits::default(), Behaviour::default()).unwrap();
    let (certificate, key) = core.agent_files(group, valid()).unwrap();
    let agent_certificate = args.work.join("agent.crt");
    let agent_tls_key = args.work.join("agent.key");
    std::fs::write(&agent_certificate, certificate).unwrap();
    // SECRET-EXPOSURE: test helper, the key file `agent enroll` would write.
    #[expect(clippy::disallowed_methods)]
    std::fs::write(&agent_tls_key, key.expose_secret()).unwrap();
    let link = Arc::new(AgentLink::spawn(LinkParams {
        core_address: core.addr().to_string(),
        certificate: agent_certificate,
        private_key: agent_tls_key,
        root: ostena_crypto::tls::TrustAnchor::from_der(core.trust_anchor().certificate().clone()),
        hello: Hello {
            agent_version: "e2e".into(),
            gateway_group: group,
            config_fingerprint: format!("sha256:{}", "0".repeat(64)),
        },
        limits: Limits::default(),
        backoff: Backoff::default(),
        clock: Arc::new(SystemClock),
        write_key: write,
    }));
    while !matches!(link.status().state, LinkState::Connected { .. }) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let policy = PolicySpec {
        gateway_group: GROUP.into(),
        allow: vec![AllowRuleSpec {
            label: Some("cible e2e".into()),
            networks: vec![format!("{}/32", args.target.ip())],
            ports: vec![args.target.port().to_string()],
        }],
        ..PolicySpec::default()
    };
    let state = GatewayState::open(GatewayParams {
        gateway_group: group,
        mode: Mode::Production,
        local_policy: policy.clone(),
        infrastructure: Arc::new(Mutex::new(Vec::new())),
        local_addresses: SharedLocalAddresses::new(LocalAddresses::from_addrs([])),
        keyset_state: args.work.join("keyset.version"),
        write_private: write,
        grant_policy: ostena_grant::Policy::default(),
    })
    .unwrap();
    let gateway = Gateway::start(Arc::new(state), link).unwrap();
    core.push(&CoreMessage::KeySet {
        version: 1,
        keys: vec![core.grant_key()],
    })
    .await;
    core.push(&CoreMessage::Policy { version: 1, policy }).await;
    core.push_ssh_trust(1, None).await;
    while gateway.state().versions().ssh_trust.is_none() {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    core.add_ssh_resource(
        "debian12",
        SshResource::new(
            &args.target.ip().to_string(),
            args.target.port(),
            point_of_line(&args.target_host_key),
        ),
    );

    // The agent identity: its host key, certified by a host authority.
    let host_key = ostena_ssh::keys::generate("gateway-e2e").unwrap();
    let host_key = ostena_ssh::keys::load(&host_key.private).unwrap();
    let host_ca = SigningKey::generate().unwrap().0;
    let now = ostena_grant::unix_now();
    let host_point = VerifyingKey::from_bytes(
        &ostena_ssh::driver::sec1_point(host_key.public_key())
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let host_certificate = cert::issue(
        &Template {
            kind: Kind::Host,
            public: host_point,
            serial: 1,
            key_id: "gateway-e2e".into(),
            principals: vec!["127.0.0.1".into()],
            valid_after: now - 60,
            valid_before: now + 86_400,
            critical_options: vec![],
            extensions: vec![],
        },
        &host_ca,
    )
    .unwrap();
    let trust = gateway.state().ssh_trust().unwrap();
    let identity =
        SshIdentity::new(host_key, &host_certificate, trust.user_cas.clone(), now).unwrap();
    let (_identity, identity_rx) = tokio::sync::watch::channel(Some(Arc::new(identity)));
    let agent_key = SecretBytes::from(std::fs::read(&args.agent_key).unwrap());
    let agent_key = Arc::new(ostena_ssh::keys::load(&agent_key).unwrap());
    let server = SshServer::new(
        ServerSettings::default(),
        identity_rx,
        agent_key,
        Arc::new(ViaGateway {
            gateway,
            store: MemoryReplayStore::new(),
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    // What the user gets from `ostena login`.
    let user = cert::issue(
        &Template {
            kind: Kind::User,
            public: point_of_line(&args.user_public),
            serial: 1,
            key_id: "7a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d".into(),
            principals: vec!["5d1c2b3a-4e5f-4a6b-8c7d-9e0f1a2b3c4d".into()],
            valid_after: now - 60,
            valid_before: now + 3600,
            critical_options: vec![],
            extensions: vec![],
        },
        core.ssh_user_ca(),
    )
    .unwrap();
    std::fs::write(
        args.work.join("user-cert.pub"),
        format!("{} {} e2e\n", cert::CERT_TYPE, STANDARD.encode(user)),
    )
    .unwrap();
    std::fs::write(
        args.work.join("known_hosts"),
        format!(
            "@cert-authority [127.0.0.1]:{port} {}\n",
            public_line(&host_ca.verifying_key())
        ),
    )
    .unwrap();
    std::fs::write(args.work.join("port"), port.to_string()).unwrap();
    eprintln!("prêt sur 127.0.0.1:{port}, compte {}", args.account);
    let (_stop, stop) = tokio::sync::watch::channel(false);
    server.serve(listener, stop).await.unwrap();
}

fn main() {
    ostena_common::logging::init(&LoggingConfig::default()).unwrap();
    let args = args();
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(run(args));
}
