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
    Claims, GatewayGroupId, Issuer, KeySet, Kid, MemoryReplayStore, Protocol, ResourceId, Rights,
    SignedGrant, SubjectId, Verifier,
};

use crate::control::{AgentMessage, CoreMessage, GrantKey, PROTOCOL_VERSION, SessionProtocol};
use crate::enroll::{
    AgentRegistry, DEFAULT_CERTIFICATE_LIFETIME, EnrollmentService, EnrollmentToken,
};
use crate::error::TunnelError;
use crate::ids::Uuid;
use crate::limits::Limits;
use crate::link::{Clock, SystemClock};
use crate::renewal;
use crate::tunnel::{ALPN, AgentConfig, CoreListener, CoreTunnel, Hello};

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
    fn register(&self, fingerprint: [u8; 32], group: Uuid, agent: Uuid) {
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
pub struct Behaviour {
    /// Stop answering heartbeats once connected (QUIC stays up).
    pub mute: bool,
    /// Present a server certificate signed by the issuing CA (with its
    /// chain), as an attacker holding that key would.
    pub rogue_server: bool,
}

/// The grant side of the test core: its signing key, its replay store and a
/// minimal inventory (resource → host, port).
struct Grants {
    issuer: Issuer,
    replay: MemoryReplayStore,
    resources: Mutex<HashMap<[u8; 16], (String, u16)>>,
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
}

impl State {
    fn new() -> Result<Self, TunnelError> {
        let (key, _) =
            p256::SigningKey::generate().map_err(|e| TunnelError::Config(e.to_string()))?;
        Ok(Self {
            errors: Mutex::default(),
            tunnels: Mutex::default(),
            grants: Grants {
                issuer: Issuer::new(key),
                replay: MemoryReplayStore::new(),
                resources: Mutex::default(),
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
        let listener = Arc::new(CoreListener::bind(
            (Ipv4Addr::LOCALHOST, 0).into(),
            tls.clone(),
            limits,
        )?);
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
            self.registry
                .register(tls::fingerprint(&cert), group, agent);
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
    pub fn issue_token(&self, group: Uuid, ttl: Duration) -> Result<EnrollmentToken, TunnelError> {
        self.enrollment.issue_token(group, ttl)
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
        self.registry
            .register(tls::fingerprint(&cert), group, agent);
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
        let random = |e: ostena_crypto::CryptoError| TunnelError::Config(e.to_string());
        let resource = Uuid::random().map_err(|e| TunnelError::Config(e.to_string()))?;
        let subject = Uuid::random().map_err(|e| TunnelError::Config(e.to_string()))?;
        if let Ok(mut resources) = self.state.grants.resources.lock() {
            resources.insert(resource.to_bytes(), (host.to_owned(), port));
        }
        let claims = Claims {
            subject: SubjectId::from_bytes(subject.to_bytes()),
            resource: ResourceId::from_bytes(resource.to_bytes()),
            audience: GatewayGroupId::from_bytes(group.to_bytes()),
            protocol,
            rights: Rights::NONE,
            max_session_secs: 3600,
        };
        let now = ostena_grant::unix_now();
        Ok(self
            .state
            .grants
            .issuer
            .issue(&claims, now)
            .map_err(random)?
            .to_text())
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
        tokio::spawn(echo_channels(tunnel));
    }
}

async fn echo_channels(tunnel: Arc<CoreTunnel>) {
    while let Ok((_, _, mut channel)) = tunnel.accept_channel().await {
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
            registry.register(tls::fingerprint(&cert), entry.group, entry.agent);
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
    let Some((host, port)) = target else {
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
    }
}
