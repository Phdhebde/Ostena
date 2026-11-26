//! In-process test core (feature `testing`). Never in a release binary:
//! `cargo xtask check-release` refuses the feature and [`MARKER`].
//!
//! It plays the core side of the tunnel: its own PKI, a registry of agent
//! certificates, the enrolment service, hello checks, heartbeat answers,
//! certificate renewal, revocation that closes live tunnels, and echo of every
//! session channel. Policy and key pushes come with the next lots.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ostena_common::secret::SecretBytes;
use ostena_crypto::p256;
use ostena_crypto::pki::testing::TestPki;
pub use ostena_crypto::pki::testing::valid;
use ostena_crypto::pki::{IssuingAuthority, Validity};
use ostena_crypto::tls::{
    self, ClientAuth, ClientAuthorizer, ClientRefusal, Identity, ServerConfig, TrustAnchor,
};
use tokio::task::JoinHandle;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ostena_grant::{
    Binding, Claims, GatewayGroupId, Issuer, KeySet, Kid, MemoryReplayStore, Protocol, ResourceId,
    Rights, SignedGrant, SubjectId, Verifier,
};

use crate::channel::StreamClass;
use crate::control::{AgentMessage, CoreMessage, GrantKey, PROTOCOL_VERSION, SessionProtocol};
use crate::enroll::{
    AgentRegistry, DEFAULT_CERTIFICATE_LIFETIME, EnrollmentService, EnrollmentToken,
    MemoryTokenStore, StoreFuture,
};
use crate::error::TunnelError;
use crate::ids::Uuid;
use crate::limits::Limits;
use crate::link::{Clock, SystemClock};
use crate::renewal;
use crate::transport::Transport;
use crate::tunnel::{ALPN, AgentConfig, Channel, CoreListener, CoreTunnel, Hello};

/// Text present in any binary that links the test core.
pub const MARKER: &str = "ostena-testing-core: never in a release build";

#[derive(Debug, Clone, Copy)]
struct Entry {
    group: Uuid,
    agent: Uuid,
    revoked: bool,
}

/// The test core registry of agent certificates.
#[derive(Debug, Default)]
pub struct Registry(Mutex<HashMap<[u8; 32], Entry>>);

impl ClientAuthorizer for Registry {
    fn authorize(&self, fingerprint: &[u8; 32]) -> Result<(), ClientRefusal> {
        match self.0.lock().ok().and_then(|r| r.get(fingerprint).copied()) {
            Some(Entry { revoked: false, .. }) => Ok(()),
            Some(_) => Err(ClientRefusal::Revoked),
            None => Err(ClientRefusal::Unknown),
        }
    }
}

impl Registry {
    fn entry(&self, fingerprint: &[u8; 32]) -> Option<Entry> {
        self.0.lock().ok()?.get(fingerprint).copied()
    }

    fn group(&self, fingerprint: &[u8; 32]) -> Option<Uuid> {
        self.entry(fingerprint).map(|e| e.group)
    }
}

impl AgentRegistry for Registry {
    fn register(&self, fingerprint: [u8; 32], group: Uuid, agent: Uuid) -> StoreFuture<'_, ()> {
        self.insert(fingerprint, group, agent);
        Box::pin(std::future::ready(Ok(())))
    }
}

impl Registry {
    fn insert(&self, fingerprint: [u8; 32], group: Uuid, agent: Uuid) {
        if let Ok(mut r) = self.0.lock() {
            r.insert(
                fingerprint,
                Entry {
                    group,
                    agent,
                    revoked: false,
                },
            );
        }
    }
}

/// How the test core behaves.
#[derive(Debug, Clone, Copy, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent knobs of the test core"
)]
pub struct Behaviour {
    /// Stop answering heartbeats once connected (QUIC stays up).
    pub mute: bool,
    /// Present a server certificate signed by the issuing CA (with its
    /// chain), as an attacker holding that key would.
    pub rogue_server: bool,
    /// Accept transcript streams but never read them, as a core that no
    /// longer reads.
    pub stall_recordings: bool,
    /// Drop QUIC connection attempts unanswered, as a firewall that blocks
    /// UDP: only the TCP fallback gets through.
    pub udp_blocked: bool,
}

/// What the test inventory answers for a granted resource.
#[derive(Debug, Clone)]
struct Target {
    host: String,
    port: u16,
    /// For SSH: the account and the target host key answered.
    ssh: Option<(Option<String>, Option<String>)>,
}

/// An SSH resource of the test inventory, reached by its name
/// (`account@name`), with knobs to make the core misbehave.
#[derive(Debug, Clone)]
pub struct SshResource {
    /// Target host (checked again by the agent scope control).
    pub host: String,
    /// Target port.
    pub port: u16,
    /// Pinned host key of the target.
    pub target_p256_public: p256::VerifyingKey,
    /// Maximum session length granted, in seconds.
    pub max_session_secs: u32,
    /// Grant another subject than the one asking (a faulty core).
    pub grant_subject: Option<Uuid>,
    /// Grant another protocol than SSH (a faulty core).
    pub grant_protocol: Protocol,
    /// Answer another account than the one asked (a faulty core).
    pub answer_account: Option<String>,
    /// Bind the grant to another account than the one asked (a faulty
    /// core: the agent burns the grant, `TUN-E010`).
    pub bind_account: Option<String>,
    /// Answer the session parameters without the target host key (a
    /// faulty core: the agent refuses the message, `TUN-E010`).
    pub omit_target_key: bool,
}

impl SshResource {
    /// A well-behaved resource.
    pub fn new(host: &str, port: u16, target_p256_public: p256::VerifyingKey) -> Self {
        Self {
            host: host.to_owned(),
            port,
            target_p256_public,
            max_session_secs: 3600,
            grant_subject: None,
            grant_protocol: Protocol::Ssh,
            answer_account: None,
            bind_account: None,
            omit_target_key: false,
        }
    }
}

/// The grant side of the test core: its signing key, its replay store and a
/// minimal inventory (resource → host, port), plus the SSH side: resources
/// by name, the user certificate authority, what the agents sent.
struct Grants {
    issuer: Issuer,
    replay: MemoryReplayStore,
    resources: Mutex<HashMap<[u8; 16], Target>>,
    ssh_resources: Mutex<HashMap<String, SshResource>>,
    ssh_user_ca: p256::SigningKey,
    ssh_host_ca: p256::SigningKey,
    ssh_host_keys: Mutex<Vec<p256::VerifyingKey>>,
    ssh_requests: Mutex<Vec<AgentMessage>>,
    ssh_issued: Mutex<Vec<String>>,
}

impl Grants {
    /// A grant for `group` and `subject`, its target recorded; text form.
    fn issue(
        &self,
        group: Uuid,
        subject: Uuid,
        protocol: Protocol,
        max_session_secs: u32,
        binding: Binding,
        target: Target,
    ) -> Result<String, TunnelError> {
        let config = |e: ostena_crypto::CryptoError| TunnelError::Config(e.to_string());
        let resource = Uuid::random().map_err(config)?;
        if let Ok(mut resources) = self.resources.lock() {
            resources.insert(resource.to_bytes(), target);
        }
        let claims = Claims {
            subject: SubjectId::from_bytes(subject.to_bytes()),
            resource: ResourceId::from_bytes(resource.to_bytes()),
            audience: GatewayGroupId::from_bytes(group.to_bytes()),
            protocol,
            rights: Rights::NONE,
            max_session_secs,
            binding,
        };
        Ok(self
            .issuer
            .issue(&claims, ostena_grant::unix_now())
            .map_err(config)?
            .to_text())
    }

    /// The core side of an SSH grant request: the resource from the
    /// inventory, a grant for the subject (the real core checks the login
    /// session and the right first).
    fn ssh_grant(&self, group: Option<Uuid>, request: &AgentMessage) -> CoreMessage {
        let AgentMessage::SshGrantRequest {
            request_id,
            subject,
            login_session,
            account,
            resource,
            ..
        } = request
        else {
            return CoreMessage::Shutdown {
                reason: "pas une demande SSH".into(),
            };
        };
        if let Ok(mut r) = self.ssh_requests.lock() {
            r.push(request.clone());
        }
        let refused = |code: &str, message: &str| CoreMessage::SessionRefused {
            request_id: *request_id,
            code: code.to_owned(),
            message: message.to_owned(),
        };
        let Some(group) = group else {
            return refused("TUN-E006", "agent inconnu");
        };
        let found = self
            .ssh_resources
            .lock()
            .ok()
            .and_then(|r| r.get(resource).cloned());
        let (Some(found), Some(subject), Some(login_session)) =
            (found, Uuid::parse(subject), Uuid::parse(login_session))
        else {
            return refused("INV-E001", "ressource inconnue de l'inventaire");
        };
        let binding = Binding::of(
            login_session.to_bytes(),
            found.bind_account.as_deref().unwrap_or(account),
        );
        let target = Target {
            host: found.host.clone(),
            port: found.port,
            ssh: Some((
                Some(found.answer_account.unwrap_or_else(|| account.clone())),
                (!found.omit_target_key)
                    .then(|| URL_SAFE_NO_PAD.encode(found.target_p256_public.to_bytes())),
            )),
        };
        match self.issue(
            group,
            found.grant_subject.unwrap_or(subject),
            found.grant_protocol,
            found.max_session_secs,
            binding,
            target,
        ) {
            Ok(grant) => {
                if let Ok(mut g) = self.ssh_issued.lock() {
                    g.push(grant.clone());
                }
                CoreMessage::SshGrant {
                    request_id: *request_id,
                    grant,
                }
            }
            Err(e) => refused("TUN-E014", &e.to_string()),
        }
    }
}

impl std::fmt::Debug for Grants {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Grants")
            .field("kid", &self.issuer.kid())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct State {
    errors: Mutex<Vec<TunnelError>>,
    tunnels: Mutex<Vec<([u8; 32], Arc<CoreTunnel>)>>,
    grants: Grants,
    /// Transcript streams received, by session, and whether each ended
    /// cleanly (finished by the agent).
    recordings: Mutex<HashMap<Uuid, (Vec<u8>, bool)>>,
    /// Session reports received: session and reason.
    closed: Mutex<Vec<(String, String)>>,
}

impl State {
    fn new() -> Result<Self, TunnelError> {
        let generate = || {
            p256::SigningKey::generate()
                .map(|(k, _)| k)
                .map_err(|e| TunnelError::Config(e.to_string()))
        };
        Ok(Self {
            errors: Mutex::default(),
            tunnels: Mutex::default(),
            recordings: Mutex::default(),
            closed: Mutex::default(),
            grants: Grants {
                issuer: Issuer::new(generate()?),
                replay: MemoryReplayStore::new(),
                resources: Mutex::default(),
                ssh_resources: Mutex::default(),
                ssh_user_ca: generate()?,
                ssh_host_ca: generate()?,
                ssh_host_keys: Mutex::default(),
                ssh_requests: Mutex::default(),
                ssh_issued: Mutex::default(),
            },
        })
    }
}

/// A core listening on 127.0.0.1, for tests and benchmarks.
pub struct TestCore {
    pki: Arc<TestPki>,
    registry: Arc<Registry>,
    issuer: Arc<IssuingAuthority>,
    server_tls: Arc<ServerConfig>,
    behaviour: Behaviour,
    limits: Limits,
    running: Mutex<Option<(Arc<CoreListener>, JoinHandle<()>)>>,
    enrollment: EnrollmentService,
    addr: SocketAddr,
    state: Arc<State>,
}

impl std::fmt::Debug for TestCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestCore")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl TestCore {
    /// Starts a test core with `limits`.
    ///
    /// # Errors
    ///
    /// If the certificates or the listener cannot be created.
    ///
    /// # Panics
    ///
    /// Outside a Tokio runtime (it spawns the accept loop).
    pub fn start(limits: Limits, behaviour: Behaviour) -> Result<Self, TunnelError> {
        Self::start_with_clock(limits, behaviour, Arc::new(SystemClock))
    }

    /// [`TestCore::start`], with `clock` for the enrolment tokens.
    ///
    /// # Errors
    ///
    /// If the certificates or the listener cannot be created.
    ///
    /// # Panics
    ///
    /// Outside a Tokio runtime (it spawns the accept loop).
    pub fn start_with_clock(
        limits: Limits,
        behaviour: Behaviour,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, TunnelError> {
        tracing::debug!(marker = MARKER);
        let config = |e: ostena_crypto::pki::PkiError| TunnelError::Config(e.to_string());
        let pki = Arc::new(TestPki::new("Ostena test core").map_err(config)?);
        let names = ["localhost", "127.0.0.1"];
        let server = if behaviour.rogue_server {
            pki.rogue_server(&names).map_err(config)?
        } else {
            pki.server(&names).map_err(config)?
        };
        let registry = Arc::new(Registry::default());
        let tls = tls::server_config(
            &server,
            ClientAuth::Required {
                issuing_cas: vec![pki.issuing_anchor()],
                authorizer: registry.clone(),
            },
            &[ALPN],
        )
        .map_err(|e| TunnelError::Config(e.to_string()))?;
        // QUIC takes a free UDP port, TCP the same port number: retry on the
        // rare collision with a TCP port already taken.
        let mut bound = CoreListener::bind((Ipv4Addr::LOCALHOST, 0).into(), tls.clone(), limits);
        for _ in 0..10 {
            if bound.is_ok() {
                break;
            }
            bound = CoreListener::bind((Ipv4Addr::LOCALHOST, 0).into(), tls.clone(), limits);
        }
        let listener = Arc::new(bound?);
        let addr = listener.local_addr()?;
        let issuer = Arc::new(
            IssuingAuthority::from_parts(
                pki.issuing.common_name(),
                &pki.issuing_key,
                pki.issuing_certificate.clone(),
            )
            .map_err(config)?,
        );
        // The enrolment listener is bound only while a token is valid: reserve
        // a free port now, so that the agents know where to go.
        let enroll_port = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .and_then(|s| s.local_addr())
            .map_err(|e| TunnelError::Io(e.to_string()))?
            .port();
        let enrollment = EnrollmentService::new(
            (Ipv4Addr::LOCALHOST, enroll_port).into(),
            &server,
            issuer.clone(),
            registry.clone(),
            Arc::new(MemoryTokenStore::default()),
            DEFAULT_CERTIFICATE_LIFETIME,
            Duration::from_secs(5),
        )?
        .with_clock(clock);
        let core = Self {
            pki,
            registry,
            issuer,
            server_tls: tls,
            behaviour,
            limits,
            running: Mutex::new(None),
            enrollment,
            addr,
            state: Arc::new(State::new()?),
        };
        core.listen(listener);
        Ok(core)
    }

    /// The listening address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The root the agents pin.
    pub fn trust_anchor(&self) -> TrustAnchor {
        self.pki.root_anchor()
    }

    /// Issues an agent certificate for `group` with `validity` and, if
    /// `register`, records it in the registry.
    ///
    /// # Errors
    ///
    /// If the key or the certificate cannot be created.
    pub fn agent_identity(
        &self,
        group: Uuid,
        validity: Validity,
        register: bool,
    ) -> Result<Identity, TunnelError> {
        let (key, pkcs8) =
            p256::SigningKey::generate().map_err(|e| TunnelError::Config(e.to_string()))?;
        let cert = self
            .pki
            .issuing
            .issue_agent(
                &key.verifying_key(),
                &group.to_string(),
                "test-agent",
                validity,
            )
            .map_err(|e| TunnelError::Config(e.to_string()))?;
        if register {
            let agent = Uuid::random().map_err(|e| TunnelError::Config(e.to_string()))?;
            self.registry.insert(tls::fingerprint(&cert), group, agent);
        }
        Identity::new(vec![cert], pkcs8).map_err(|e| TunnelError::Config(e.to_string()))
    }

    /// Revokes an agent certificate: refused at the next handshakes, and its
    /// open tunnels are closed at once (`TUN-E005`).
    pub fn revoke(&self, identity: &Identity) {
        self.revoke_fingerprint(&tls::fingerprint(identity.certificate()));
    }

    /// Revokes the certificate whose SHA-256 is `fingerprint`.
    pub fn revoke_fingerprint(&self, fingerprint: &[u8; 32]) {
        if let Ok(mut r) = self.registry.0.lock()
            && let Some(e) = r.get_mut(fingerprint)
        {
            e.revoked = true;
        }
        if let Ok(tunnels) = self.state.tunnels.lock() {
            for (fp, tunnel) in tunnels.iter() {
                if fp == fingerprint {
                    tunnel.close(TunnelError::Revoked);
                }
            }
        }
    }

    /// Issues an enrolment token for `group`, valid `ttl`; the enrolment
    /// listener opens.
    ///
    /// # Errors
    ///
    /// See [`EnrollmentService::issue_token`].
    pub async fn issue_token(
        &self,
        group: Uuid,
        ttl: Duration,
    ) -> Result<EnrollmentToken, TunnelError> {
        self.enrollment.issue_token(group, ttl).await
    }

    /// The enrolment listener address.
    pub fn enrollment_addr(&self) -> SocketAddr {
        self.enrollment.addr()
    }

    /// Whether the enrolment listener is bound.
    pub fn enrollment_open(&self) -> bool {
        self.enrollment.is_open()
    }

    /// A ready agent configuration for `identity` and `group`.
    ///
    /// # Errors
    ///
    /// If the TLS configuration is refused.
    pub fn agent_config(
        &self,
        identity: &Identity,
        group: Uuid,
        limits: Limits,
    ) -> Result<AgentConfig, TunnelError> {
        Ok(AgentConfig {
            core: self.addr,
            server_name: "localhost".into(),
            tls: tls::client_config(&self.trust_anchor(), Some(identity), &[ALPN])
                .map_err(|e| TunnelError::Config(e.to_string()))?,
            transport: Transport::Quic,
            limits,
            hello: Hello {
                agent_version: "test".into(),
                gateway_group: group,
                config_fingerprint: format!("sha256:{}", "0".repeat(64)),
            },
        })
    }

    /// Errors seen while accepting connections, oldest first.
    pub fn errors(&self) -> Vec<TunnelError> {
        self.state
            .errors
            .lock()
            .map(|e| e.clone())
            .unwrap_or_default()
    }

    /// Waits up to `limit` for an accept error and returns it.
    pub async fn wait_error(&self, limit: Duration) -> Option<TunnelError> {
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            if let Some(e) = self.errors().into_iter().next() {
                return Some(e);
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// The transcript stream received for `session`, and whether the agent
    /// finished it; `None` before its first byte.
    pub fn recording(&self, session: Uuid) -> Option<(Vec<u8>, bool)> {
        self.state.recordings.lock().ok()?.get(&session).cloned()
    }

    /// The transcript stream of `session` once the test core has read it
    /// to its end, waiting up to `within`; `None` past it. The agent's pump
    /// returns once the transport acknowledged every byte and the end
    /// (ADR-0016): the core has received them, not necessarily read them
    /// yet.
    pub async fn finished_recording(
        &self,
        session: Uuid,
        within: Duration,
    ) -> Option<(Vec<u8>, bool)> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            match self.recording(session) {
                Some(recorded) if recorded.1 => return Some(recorded),
                _ if tokio::time::Instant::now() >= deadline => return None,
                _ => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    }

    /// Open tunnels.
    pub fn tunnels(&self) -> usize {
        self.state
            .tunnels
            .lock()
            .map_or(0, |t| t.iter().filter(|(_, t)| !t.is_closed()).count())
    }

    /// Sends `message` on every open tunnel.
    pub async fn broadcast(&self, message: &CoreMessage) {
        let tunnels: Vec<_> = self
            .state
            .tunnels
            .lock()
            .map(|t| t.iter().map(|(_, t)| t.clone()).collect())
            .unwrap_or_default();
        for t in tunnels {
            let _ = t.send(message).await;
        }
    }

    fn listen(&self, listener: Arc<CoreListener>) {
        if self.behaviour.udp_blocked {
            listener.drop_quic_for_tests();
        }
        let task = tokio::spawn(serve(
            listener.clone(),
            self.registry.clone(),
            self.issuer.clone(),
            self.state.clone(),
            self.behaviour,
            self.limits,
        ));
        if let Ok(mut running) = self.running.lock() {
            *running = Some((listener, task));
        }
    }

    /// Stops the core: closes the listener and every tunnel.
    pub fn stop(&self) {
        let running = self.running.lock().ok().and_then(|mut r| r.take());
        if let Some((listener, task)) = running {
            task.abort();
            listener.close();
        }
        // Open tunnels keep the socket alive: close and forget them.
        let tunnels = self
            .state
            .tunnels
            .lock()
            .map(|mut t| std::mem::take(&mut *t));
        for (_, tunnel) in tunnels.unwrap_or_default() {
            tunnel.close(TunnelError::ConnectionLost("arrêt du core".into()));
        }
    }

    /// Starts again on the same address, with the same PKI and registry,
    /// after [`TestCore::stop`].
    ///
    /// # Errors
    ///
    /// If the address cannot be bound again within two seconds.
    pub async fn restart(&self) -> Result<(), TunnelError> {
        self.stop();
        let mut last = TunnelError::Io("rebind".into());
        for _ in 0..40 {
            match CoreListener::bind(self.addr, self.server_tls.clone(), self.limits) {
                Ok(listener) => {
                    self.listen(Arc::new(listener));
                    return Ok(());
                }
                Err(e) => last = e,
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Err(last)
    }

    /// An agent certificate (PEM) and key (PEM PKCS#8) for `group`, valid
    /// `validity`, recorded in the registry: what `ostena agent enroll`
    /// would write.
    ///
    /// # Errors
    ///
    /// If the key or the certificate cannot be created.
    pub fn agent_files(
        &self,
        group: Uuid,
        validity: Validity,
    ) -> Result<(String, SecretBytes), TunnelError> {
        let (key, pkcs8) =
            p256::SigningKey::generate().map_err(|e| TunnelError::Config(e.to_string()))?;
        let agent = Uuid::random().map_err(|e| TunnelError::Config(e.to_string()))?;
        let cert = self
            .issuer
            .issue_agent(
                &key.verifying_key(),
                &group.to_string(),
                &agent.to_string(),
                validity,
            )
            .map_err(|e| TunnelError::Config(e.to_string()))?;
        self.registry.insert(tls::fingerprint(&cert), group, agent);
        Ok((
            ostena_crypto::pki::pem_certificate(&cert),
            ostena_crypto::pki::pem_private_key(&pkcs8),
        ))
    }

    /// The public key of the grant issuer, as pushed in a key set.
    pub fn grant_key(&self) -> GrantKey {
        let key = self.state.grants.issuer.verifying_key();
        GrantKey {
            kid: Kid::of(&key).to_string(),
            public_key: URL_SAFE_NO_PAD.encode(key.to_bytes()),
            retire_at: None,
        }
    }

    /// A grant for `group` to reach `host:port` with `protocol`, recorded in
    /// the test inventory; text form.
    ///
    /// # Errors
    ///
    /// If the random generator fails.
    pub fn issue_grant(
        &self,
        group: Uuid,
        protocol: Protocol,
        host: &str,
        port: u16,
    ) -> Result<String, TunnelError> {
        let subject = Uuid::random().map_err(|e| TunnelError::Config(e.to_string()))?;
        // An SSH session needs an account and a pinned host key.
        let ssh = match protocol {
            Protocol::Ssh => {
                let (key, _) =
                    p256::SigningKey::generate().map_err(|e| TunnelError::Config(e.to_string()))?;
                Some((
                    Some("ostena".to_owned()),
                    Some(URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes())),
                ))
            }
            _ => None,
        };
        let target = Target {
            host: host.to_owned(),
            port,
            ssh,
        };
        // No login session here: bound to the subject and the account.
        let binding = Binding::of(subject.to_bytes(), "ostena");
        self.state
            .grants
            .issue(group, subject, protocol, 3600, binding, target)
    }

    /// The authority of the user certificates, pushed in
    /// [`TestCore::push_ssh_trust`]: tests sign user certificates with it.
    pub fn ssh_user_ca(&self) -> &p256::SigningKey {
        &self.state.grants.ssh_user_ca
    }

    /// The authority of the host certificates, pushed in
    /// [`TestCore::push_ssh_trust`]: tests sign the agent host certificate
    /// with it.
    pub fn ssh_host_ca(&self) -> &p256::SigningKey {
        &self.state.grants.ssh_host_ca
    }

    /// Adds an SSH resource to the test inventory, reached as
    /// `account@name`.
    pub fn add_ssh_resource(&self, name: &str, resource: SshResource) {
        if let Ok(mut r) = self.state.grants.ssh_resources.lock() {
            r.insert(name.to_owned(), resource);
        }
    }

    /// Pushes the SSH trust (the test user and host authorities and
    /// `host_certificate`) with `version` to every connected agent; returns
    /// how many.
    pub async fn push_ssh_trust(&self, version: u64, host_certificate: Option<&[u8]>) -> usize {
        let ca = self.state.grants.ssh_user_ca.verifying_key();
        let host_ca = self.state.grants.ssh_host_ca.verifying_key();
        self.push(&CoreMessage::SshTrust {
            version,
            user_ca_p256_public: vec![URL_SAFE_NO_PAD.encode(ca.to_bytes())],
            host_ca_p256_public: vec![URL_SAFE_NO_PAD.encode(host_ca.to_bytes())],
            host_certificate: host_certificate.map(|c| URL_SAFE_NO_PAD.encode(c)),
        })
        .await
    }

    /// Revokes an `ostena login` session: every agent is told; returns how
    /// many.
    pub async fn revoke_login(&self, login_session: Uuid) -> usize {
        self.push(&CoreMessage::LoginRevoked {
            login_session: login_session.to_string(),
        })
        .await
    }

    /// The SSH host keys the agents sent, proof checked.
    pub fn ssh_host_keys(&self) -> Vec<p256::VerifyingKey> {
        self.state
            .grants
            .ssh_host_keys
            .lock()
            .map(|k| k.clone())
            .unwrap_or_default()
    }

    /// The SSH grant requests received, oldest first.
    pub fn ssh_grant_requests(&self) -> Vec<AgentMessage> {
        self.state
            .grants
            .ssh_requests
            .lock()
            .map(|r| r.clone())
            .unwrap_or_default()
    }

    /// The session reports received (session, reason), oldest first.
    pub fn sessions_closed(&self) -> Vec<(String, String)> {
        self.state
            .closed
            .lock()
            .map(|c| c.clone())
            .unwrap_or_default()
    }

    /// The SSH grants issued (text form), oldest first.
    pub fn ssh_grants(&self) -> Vec<String> {
        self.state
            .grants
            .ssh_issued
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// Sends `message` to every connected agent; returns how many.
    pub async fn push(&self, message: &CoreMessage) -> usize {
        let tunnels: Vec<Arc<CoreTunnel>> = self
            .state
            .tunnels
            .lock()
            .map(|t| t.iter().map(|(_, t)| t.clone()).collect())
            .unwrap_or_default();
        let mut sent = 0;
        for tunnel in tunnels.iter().filter(|t| !t.is_closed()) {
            if tunnel.send(message).await.is_ok() {
                sent += 1;
            }
        }
        sent
    }
}

impl Drop for TestCore {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn serve(
    listener: Arc<CoreListener>,
    registry: Arc<Registry>,
    issuer: Arc<IssuingAuthority>,
    state: Arc<State>,
    behaviour: Behaviour,
    limits: Limits,
) {
    while let Some(accepted) = listener.accept().await {
        let accepted = match accepted {
            Ok(a) => a,
            Err(e) => {
                if let Ok(mut errors) = state.errors.lock() {
                    errors.push(e);
                }
                continue;
            }
        };
        if registry.group(&accepted.fingerprint) != Some(accepted.hello.gateway_group) {
            let e = TunnelError::Protocol("groupe annoncé différent du certificat".into());
            accepted.tunnel.close(e.clone());
            if let Ok(mut errors) = state.errors.lock() {
                errors.push(e);
            }
            continue;
        }
        let heartbeat_secs =
            u16::try_from(limits.heartbeat_interval.as_secs().clamp(1, 60)).unwrap_or(10);
        let ack = CoreMessage::HelloAck {
            protocol: PROTOCOL_VERSION,
            core_version: "test".into(),
            heartbeat_secs,
        };
        if accepted.tunnel.send(&ack).await.is_err() {
            continue;
        }
        let tunnel = Arc::new(accepted.tunnel);
        if behaviour.mute {
            // Keep QUIC alive but stop reading the control stream: pings
            // pile up unanswered.
            tunnel.mute_for_tests();
        }
        if let Ok(mut t) = state.tunnels.lock() {
            t.push((accepted.fingerprint, tunnel.clone()));
        }
        tokio::spawn(control(
            tunnel.clone(),
            accepted.fingerprint,
            registry.clone(),
            issuer.clone(),
            state.clone(),
        ));
        tokio::spawn(echo_channels(
            tunnel,
            state.clone(),
            behaviour.stall_recordings,
        ));
    }
}

async fn echo_channels(tunnel: Arc<CoreTunnel>, state: Arc<State>, stall_recordings: bool) {
    while let Ok((session, class, mut channel)) = tunnel.accept_channel().await {
        if class == StreamClass::Recording {
            if stall_recordings {
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(120)).await;
                    drop(channel);
                });
            } else {
                tokio::spawn(keep_recording(session, channel, state.clone()));
            }
            continue;
        }
        tokio::spawn(async move {
            let mut buf = vec![0u8; 16 * 1024];
            while let Ok(Some(n)) = channel.recv.read(&mut buf).await {
                if channel.send.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
            let _ = channel.send.finish();
        });
    }
}

/// Keeps what a transcript stream carries, without decoding it.
async fn keep_recording(session: Uuid, mut channel: Channel, state: Arc<State>) {
    let mut buf = vec![0u8; 16 * 1024];
    let clean = loop {
        match channel.recv.read(&mut buf).await {
            Ok(Some(n)) => {
                if let Ok(mut r) = state.recordings.lock() {
                    r.entry(session).or_default().0.extend_from_slice(&buf[..n]);
                }
            }
            Ok(None) => break true,
            Err(_) => break false,
        }
    };
    if let Ok(mut r) = state.recordings.lock() {
        r.entry(session).or_default().1 = clean;
    }
}

/// Control messages from one agent: certificate renewal, session requests.
async fn control(
    tunnel: Arc<CoreTunnel>,
    fingerprint: [u8; 32],
    registry: Arc<Registry>,
    issuer: Arc<IssuingAuthority>,
    state: Arc<State>,
) {
    while let Some(message) = tunnel.recv().await {
        let request = match message {
            AgentMessage::Renew { request } => request,
            AgentMessage::SessionRequest { request_id, grant } => {
                let group = registry.entry(&fingerprint).map(|e| e.group);
                let reply = session(&state.grants, group, request_id, &grant).await;
                let _ = tunnel.send(&reply).await;
                continue;
            }
            request @ AgentMessage::SshGrantRequest { .. } => {
                let group = registry.entry(&fingerprint).map(|e| e.group);
                let reply = state.grants.ssh_grant(group, &request);
                let _ = tunnel.send(&reply).await;
                continue;
            }
            AgentMessage::SessionClosed {
                session_id, reason, ..
            } => {
                if let Ok(mut closed) = state.closed.lock() {
                    closed.push((session_id, reason));
                }
                continue;
            }
            AgentMessage::SshHostKey { p256_public, proof } => {
                match crate::ssh::verify_host_key(&p256_public, &proof, &fingerprint) {
                    Ok(key) => {
                        if let Ok(mut keys) = state.grants.ssh_host_keys.lock() {
                            keys.push(key);
                        }
                    }
                    Err(e) => {
                        tunnel.close(e);
                        break;
                    }
                }
                continue;
            }
            _ => continue,
        };
        let renewed = renewal::verify(&request, &fingerprint).and_then(|key| {
            let entry = registry
                .entry(&fingerprint)
                .ok_or(TunnelError::UnknownAgent)?;
            let validity = valid();
            let cert = issuer
                .issue_agent(
                    &key,
                    &entry.group.to_string(),
                    &entry.agent.to_string(),
                    validity,
                )
                .map_err(|e| TunnelError::Io(e.to_string()))?;
            registry.insert(tls::fingerprint(&cert), entry.group, entry.agent);
            Ok(CoreMessage::Certificate {
                certificate: ostena_crypto::pki::pem_certificate(&cert),
                not_before: validity.not_before,
                not_after: validity.not_after,
            })
        });
        match renewed {
            Ok(reply) => {
                let _ = tunnel.send(&reply).await;
            }
            Err(e) => {
                tunnel.close(e);
                break;
            }
        }
    }
}

/// The core side of a session request: the grant verified again and its jti
/// consumed in the core store (ADR-0004), then the target from the
/// inventory.
async fn session(
    grants: &Grants,
    group: Option<Uuid>,
    request_id: u64,
    grant: &str,
) -> CoreMessage {
    let refused = |code: &str, message: String| CoreMessage::SessionRefused {
        request_id,
        code: code.to_owned(),
        message,
    };
    let Some(group) = group else {
        return refused("TUN-E006", "agent inconnu".into());
    };
    let mut keys = KeySet::new();
    keys.insert(grants.issuer.verifying_key());
    let verifier = Verifier::new(
        keys,
        GatewayGroupId::from_bytes(group.to_bytes()),
        ostena_grant::Policy::default(),
    );
    let checked = match SignedGrant::from_text(grant) {
        Ok(signed) => {
            verifier
                .verify(signed.as_bytes(), ostena_grant::unix_now(), &grants.replay)
                .await
        }
        Err(e) => Err(e),
    };
    let accepted = match checked {
        Ok(g) => g,
        Err(e) => return refused(e.code(), e.to_string()),
    };
    let target = grants
        .resources
        .lock()
        .ok()
        .and_then(|r| r.get(&accepted.claims.resource.to_bytes()).cloned());
    let Some(Target { host, port, ssh }) = target else {
        // Test core only: the real core answers from its inventory.
        return refused("INV-E001", "ressource inconnue de l'inventaire".into());
    };
    let protocol = match accepted.claims.protocol {
        Protocol::Ssh => SessionProtocol::Ssh,
        Protocol::Rdp => SessionProtocol::Rdp,
        Protocol::Vnc => SessionProtocol::Vnc,
        Protocol::Web => SessionProtocol::Web,
    };
    let Ok(session_id) = Uuid::random() else {
        return refused("TUN-E014", "aléa indisponible".into());
    };
    CoreMessage::SessionParams {
        request_id,
        session_id: session_id.to_string(),
        protocol,
        host,
        port,
        max_session_secs: accepted.claims.max_session_secs,
        account: ssh
            .as_ref()
            .and_then(|s| s.0.clone())
            .filter(|_| protocol == SessionProtocol::Ssh),
        target_p256_public: ssh
            .and_then(|s| s.1)
            .filter(|_| protocol == SessionProtocol::Ssh),
    }
}
