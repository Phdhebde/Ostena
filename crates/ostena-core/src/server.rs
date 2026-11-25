//! The running core (ADR-0011): tunnel listener, enrolment listener,
//! certificate renewal, revocation that closes live tunnels.
//!
//! The copy of the registry is reloaded every [`RELOAD_INTERVAL`], and every
//! [`RETRY_INTERVAL`] while it cannot be read. Notifications from the
//! administration commands (token issued, agent revoked) apply at once.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ostena_audit::{ActorKind, Event, EventKind, Outcome, field};
use ostena_common::config::{CoreConfig, KeySource};
use ostena_common::secret::SecretBytes;
use ostena_crypto::p256::SigningKey;
use ostena_crypto::pki::{IssuingAuthority, Validity};
use ostena_crypto::tls::{self, ClientAuth, Identity, TrustAnchor};
use ostena_tunnel::control::{AgentMessage, CoreMessage, PROTOCOL_VERSION};
use ostena_tunnel::enroll::{AgentRegistry, EnrollmentService};
use ostena_tunnel::{ALPN, CoreListener, CoreTunnel, Limits, TunnelError, Uuid, renewal};
use sqlx::postgres::PgListener;
use tokio::task::JoinHandle;

use crate::audit::{self, Cadence, HeadSigner, Recorder, SystemClock};
use crate::cache::AgentCache;
use crate::error::CoreError;
use crate::store::{CHANNEL, Notice, PgStore, agent_event, truncate};

/// Full reload of the registry copy.
pub const RELOAD_INTERVAL: Duration = Duration::from_secs(60);
/// Reload attempts while the copy is unavailable.
pub const RETRY_INTERVAL: Duration = Duration::from_secs(5);
/// Tolerated clock difference at the start of an agent certificate.
const SKEW: u64 = 300;
const DAY: u64 = 86_400;
/// Time allowed for the enrolment handshake and exchange.
const ENROLL_TIMEOUT: Duration = Duration::from_secs(10);

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The keys and certificates of the core.
pub struct Keys {
    /// The root the agents pin (signs the server certificate).
    pub root: TrustAnchor,
    /// The server certificate and its key.
    pub server: Identity,
    /// The issuing CA (agent certificates).
    pub issuing: Arc<IssuingAuthority>,
    /// The key that signs the heads of the audit chain (ADR-0012).
    pub audit: Arc<SigningKey>,
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys")
            .field("issuing", &self.issuing.common_name())
            .finish_non_exhaustive()
    }
}

fn read(path: &Path) -> Result<Vec<u8>, CoreError> {
    std::fs::read(path).map_err(|e| CoreError::Keys(format!("{} : {e}", path.display())))
}

/// Reads a private key: a plain file (`CFG-P012`), or a systemd credential
/// from `credentials` (`$CREDENTIALS_DIRECTORY`).
fn read_key(
    field: &str,
    source: &KeySource,
    credentials: Option<&Path>,
) -> Result<SecretBytes, CoreError> {
    let path = match source {
        KeySource::File(path) => path.clone(),
        KeySource::Credential(name) => credentials
            .ok_or_else(|| {
                CoreError::Keys(format!(
                    "{field} : credential « {name} » demandé, mais CREDENTIALS_DIRECTORY n'est pas \
                     défini (LoadCredentialEncrypted= dans l'unité systemd)"
                ))
            })?
            .join(name),
    };
    std::fs::read(&path)
        .map(SecretBytes::from)
        .map_err(|e| CoreError::Keys(format!("{field} {} : {e}", path.display())))
}

impl Keys {
    /// Loads the keys and certificates named by `config`; credentials are
    /// read from `credentials`.
    ///
    /// # Errors
    ///
    /// [`CoreError::Keys`] naming the file at fault.
    pub fn load(config: &CoreConfig, credentials: Option<&Path>) -> Result<Self, CoreError> {
        let keys = |what: &str, e: &dyn std::fmt::Display| CoreError::Keys(format!("{what} : {e}"));
        let root = TrustAnchor::from_pem(&read(&config.tls_root_ca)?)
            .map_err(|e| keys("core.tls_root_ca", &e))?;
        let server_key = read_key("core.tls_private_key", &config.tls_private_key, credentials)?;
        let server = Identity::from_pem(&read(&config.tls_certificate)?, &server_key)
            .map_err(|e| keys("core.tls_certificate / core.tls_private_key", &e))?;
        let issuing_key = ostena_crypto::pki::pkcs8_from_pem(&read_key(
            "core.issuing_private_key",
            &config.issuing_private_key,
            credentials,
        )?)
        .map_err(|e| keys("core.issuing_private_key", &e))?;
        let issuing_certificate = TrustAnchor::from_pem(&read(&config.issuing_certificate)?)
            .map_err(|e| keys("core.issuing_certificate", &e))?
            .certificate()
            .clone();
        let issuing = IssuingAuthority::from_certificate(&issuing_key, issuing_certificate)
            .map_err(|e| {
                keys(
                    "core.issuing_certificate / core.issuing_private_key",
                    &format!("{e} (la clé n'est pas celle du certificat ?)"),
                )
            })?;
        let audit = ostena_crypto::pki::signing_key_from_pem(&read_key(
            "core.audit.signing_key",
            &config.audit.signing_key,
            credentials,
        )?)
        .map_err(|e| keys("core.audit.signing_key", &e))?;
        Ok(Self {
            root,
            server,
            issuing: Arc::new(issuing),
            audit: Arc::new(audit),
        })
    }
}

/// `$CREDENTIALS_DIRECTORY`, set by systemd for the credentials of the unit.
pub fn credentials_directory() -> Option<PathBuf> {
    std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from)
}

/// Open tunnels, by certificate fingerprint.
#[derive(Debug, Default)]
struct Tunnels(Mutex<HashMap<[u8; 32], Vec<Arc<CoreTunnel>>>>);

impl Tunnels {
    fn add(&self, fingerprint: [u8; 32], tunnel: Arc<CoreTunnel>) {
        if let Ok(mut map) = self.0.lock() {
            let list = map.entry(fingerprint).or_default();
            list.retain(|t| !t.is_closed());
            list.push(tunnel);
        }
    }

    /// Closes the tunnels of `fingerprints` with `error`.
    fn close(&self, fingerprints: &[[u8; 32]], error: &TunnelError) -> usize {
        let Ok(mut map) = self.0.lock() else {
            return 0;
        };
        let mut closed = 0;
        for fp in fingerprints {
            for tunnel in map.remove(fp).unwrap_or_default() {
                if !tunnel.is_closed() {
                    tunnel.close(error.clone());
                    closed += 1;
                }
            }
        }
        closed
    }

    /// Closes the tunnels whose certificate `keep` refuses.
    fn sweep(&self, keep: impl Fn(&[u8; 32]) -> bool) -> usize {
        let doomed: Vec<[u8; 32]> = self
            .0
            .lock()
            .map(|map| map.keys().filter(|fp| !keep(fp)).copied().collect())
            .unwrap_or_default();
        self.close(&doomed, &TunnelError::Revoked)
    }

    fn open(&self) -> usize {
        self.0.lock().map_or(0, |map| {
            map.values().flatten().filter(|t| !t.is_closed()).count()
        })
    }

    fn close_all(&self, error: &TunnelError) {
        let all = self
            .0
            .lock()
            .map(|mut map| std::mem::take(&mut *map))
            .unwrap_or_default();
        for tunnel in all.into_values().flatten() {
            tunnel.close(error.clone());
        }
    }
}

struct Shared {
    store: PgStore,
    cache: Arc<AgentCache>,
    issuer: Arc<IssuingAuthority>,
    enrollment: EnrollmentService,
    tunnels: Tunnels,
    certificate_lifetime: u64,
    limits: Limits,
    recorder: Arc<Recorder>,
}

/// What the start of the core writes to the audit chain besides
/// `core.started`: the migrations it applied and the weakenings in effect.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StartInfo {
    /// Versions of the migrations applied at this start.
    pub migrations: Vec<i64>,
    /// Weakening options and dated waivers in effect: (code, message).
    pub waivers: Vec<(String, String)>,
}

/// Time allowed at stop for the queue, `core.stopped` and the final head.
const STOP_TIMEOUT: Duration = Duration::from_secs(2);

/// Writes granting events in one transaction and tells the signer.
async fn write_granting(store: &PgStore, events: Vec<Event>) -> Result<(), CoreError> {
    let mut tx = store
        .pool()
        .begin()
        .await
        .map_err(|e| CoreError::AuditWrite(e.to_string()))?;
    let appended = audit::append_many(&mut tx, events).await?;
    tx.commit()
        .await
        .map_err(|e| CoreError::AuditWrite(e.to_string()))?;
    store.recorder().critical(&appended);
    Ok(())
}

fn core_event(kind: EventKind) -> Event {
    Event::new(kind, Outcome::Success, ActorKind::Core, audit::CORE_ACTOR)
}

/// The start records besides `core.started`.
fn start_events(signer: &HeadSigner, info: &StartInfo) -> Vec<Event> {
    let mut events = vec![signer.signing_started()];
    if let Some(last) = info.migrations.last() {
        let list = info
            .migrations
            .iter()
            .map(i64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        events.push(
            core_event(EventKind::CoreMigrated)
                .text(field::MIGRATIONS, truncate(&list))
                .u64(field::SCHEMA_VERSION, u64::try_from(*last).unwrap_or(0)),
        );
    }
    for (code, message) in &info.waivers {
        events.push(
            core_event(EventKind::ConfigWaiver)
                .text(field::CODE, truncate(code))
                .text(field::REASON, truncate(message)),
        );
    }
    events
}

/// A started core. Dropping it does not stop it: call [`RunningCore::stop`].
pub struct RunningCore {
    shared: Arc<Shared>,
    listener: Arc<CoreListener>,
    tunnel_addr: SocketAddr,
    tasks: Vec<JoinHandle<()>>,
    writer: JoinHandle<()>,
    signer: Arc<HeadSigner>,
}

impl std::fmt::Debug for RunningCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunningCore")
            .field("tunnel_addr", &self.tunnel_addr)
            .finish_non_exhaustive()
    }
}

impl RunningCore {
    /// Loads the registry, checks the audit chain and signs a head, writes
    /// the start records, binds the tunnel listener, prepares the enrolment
    /// listener (opened if a token is valid) and starts the background
    /// tasks.
    ///
    /// # Errors
    ///
    /// [`CoreError`] if the registry cannot be read, a listener cannot be
    /// bound, the audit chain is inconsistent (`CORE-E011`) or a start
    /// record cannot be written (`CORE-E010`).
    ///
    /// # Panics
    ///
    /// Outside a Tokio runtime.
    pub async fn start(
        config: &CoreConfig,
        store: PgStore,
        keys: &Keys,
        info: &StartInfo,
    ) -> Result<Self, CoreError> {
        let cache = store.cache();
        store.reload().await?;
        let recorder = store.recorder();
        let chain = audit::ensure_genesis(store.pool()).await?;
        let signer = Arc::new(HeadSigner::new(
            store.pool().clone(),
            keys.audit.clone(),
            Cadence::from(&config.audit),
            Arc::new(SystemClock),
            recorder.clone(),
        ));
        // A broken segment refuses the start (CORE-E011).
        signer.sign_now().await?;
        write_granting(&store, start_events(&signer, info)).await?;
        let startup = |e: TunnelError| CoreError::Startup(e.to_string());
        let tls = tls::server_config(
            &keys.server,
            ClientAuth::Required {
                issuing_cas: vec![keys.issuing.trust_anchor()],
                authorizer: cache.clone(),
            },
            &[ALPN],
        )
        .map_err(|e| CoreError::Startup(e.to_string()))?;
        let limits = Limits::default();
        let listener =
            Arc::new(CoreListener::bind(config.tunnel_listen, tls, limits).map_err(startup)?);
        let tunnel_addr = listener.local_addr().map_err(startup)?;
        let certificate_lifetime = u64::from(config.agent_certificate_days) * DAY;
        let enrollment = EnrollmentService::new(
            config.enrollment_listen(),
            &keys.server,
            keys.issuing.clone(),
            Arc::new(store.clone()),
            Arc::new(store.clone()),
            Duration::from_secs(certificate_lifetime),
            ENROLL_TIMEOUT,
        )
        .map_err(startup)?;
        let shared = Arc::new(Shared {
            store,
            cache,
            issuer: keys.issuing.clone(),
            enrollment,
            tunnels: Tunnels::default(),
            certificate_lifetime,
            limits,
            recorder: recorder.clone(),
        });
        write_granting(
            &shared.store,
            vec![
                core_event(EventKind::CoreStarted)
                    .text(field::VERSION, env!("CARGO_PKG_VERSION"))
                    .text(field::PEER_ADDR, tunnel_addr.to_string()),
            ],
        )
        .await?;
        // Tokens issued while the core was stopped.
        shared.enrollment.wake().await.map_err(startup)?;
        let mut notices = PgListener::connect_with(shared.store.pool()).await?;
        notices.listen(CHANNEL).await?;
        let writer = tokio::spawn(audit::run_writer(shared.store.pool().clone(), recorder));
        let tasks = vec![
            tokio::spawn(accept(listener.clone(), shared.clone())),
            tokio::spawn(follow_notices(notices, shared.clone())),
            tokio::spawn(reload_periodically(shared.clone())),
            tokio::spawn(signer.clone().run()),
        ];
        tracing::info!(
            event = "core.started",
            tunnel = %tunnel_addr,
            enrollment = %shared.enrollment.addr(),
            chain = %chain,
            kid = %signer.kid(),
            "core démarré"
        );
        Ok(Self {
            shared,
            listener,
            tunnel_addr,
            tasks,
            writer,
            signer,
        })
    }

    /// The bound tunnel address.
    pub fn tunnel_addr(&self) -> SocketAddr {
        self.tunnel_addr
    }

    /// The enrolment address.
    pub fn enrollment_addr(&self) -> SocketAddr {
        self.shared.enrollment.addr()
    }

    /// Whether the enrolment listener is bound.
    pub fn enrollment_open(&self) -> bool {
        self.shared.enrollment.is_open()
    }

    /// Open tunnels.
    pub fn open_tunnels(&self) -> usize {
        self.shared.tunnels.open()
    }

    /// Whether the copy of the registry can be used.
    pub fn registry_available(&self) -> bool {
        self.shared.cache.is_available()
    }

    /// The head signer.
    pub fn signer(&self) -> &Arc<HeadSigner> {
        &self.signer
    }

    /// Stops: closes both listeners and every tunnel, writes the queued
    /// audit events and `core.stopped`, then signs a last head; each step
    /// gets at most two seconds.
    pub async fn stop(self) {
        for task in &self.tasks {
            task.abort();
        }
        self.listener.close();
        self.shared.enrollment.close();
        self.shared
            .tunnels
            .close_all(&TunnelError::ConnectionLost("arrêt du core".into()));
        if !self.shared.recorder.flush(STOP_TIMEOUT).await {
            tracing::warn!(
                event = "audit.append_failed",
                pending = self.shared.recorder.pending(),
                "file d'audit non vidée à l'arrêt"
            );
        }
        let stopped = tokio::time::timeout(
            STOP_TIMEOUT,
            write_granting(&self.shared.store, vec![core_event(EventKind::CoreStopped)]),
        )
        .await;
        match stopped {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(event = "audit.append_failed", code = e.code(), "{e}"),
            Err(_) => tracing::warn!(
                event = "audit.append_failed",
                code = "CORE-E010",
                "core.stopped non écrit en 2 s"
            ),
        }
        match tokio::time::timeout(STOP_TIMEOUT, self.signer.sign_now()).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => tracing::warn!(event = "audit.head_failed", code = e.code(), "{e}"),
            Err(_) => tracing::warn!(
                event = "audit.head_failed",
                "dernière tête non signée en 2 s"
            ),
        }
        self.writer.abort();
        tracing::info!(event = "core.stopped", "core arrêté");
    }
}

async fn accept(listener: Arc<CoreListener>, shared: Arc<Shared>) {
    while let Some(accepted) = listener.accept().await {
        let accepted = match accepted {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(event = "tunnel.refused", code = e.code(), "{e}");
                continue;
            }
        };
        let fingerprint = accepted.fingerprint;
        let Some(entry) = shared.cache.active(&fingerprint) else {
            accepted.tunnel.close(TunnelError::UnknownAgent);
            continue;
        };
        if entry.group != accepted.hello.gateway_group {
            let e = TunnelError::Protocol("groupe annoncé différent du certificat".into());
            tracing::warn!(
                event = "tunnel.refused",
                agent = %entry.agent,
                code = e.code(),
                "{e}"
            );
            shared.recorder.emit(
                agent_event(EventKind::TunnelRefused, Outcome::Refused, entry.agent)
                    .uuid(field::GROUP_ID, entry.group.to_bytes())
                    .text(field::CODE, e.code()),
            );
            accepted.tunnel.close(e);
            continue;
        }
        let heartbeat_secs =
            u16::try_from(shared.limits.heartbeat_interval.as_secs().clamp(1, 60)).unwrap_or(10);
        let ack = CoreMessage::HelloAck {
            protocol: PROTOCOL_VERSION,
            core_version: env!("CARGO_PKG_VERSION").into(),
            heartbeat_secs,
        };
        if accepted.tunnel.send(&ack).await.is_err() {
            continue;
        }
        let tunnel = Arc::new(accepted.tunnel);
        shared.tunnels.add(fingerprint, tunnel.clone());
        // A revocation committed during the handshake: the notice may have
        // been handled before the tunnel was listed.
        if shared.cache.active(&fingerprint).is_none() {
            shared.tunnels.close(&[fingerprint], &TunnelError::Revoked);
            continue;
        }
        tracing::info!(
            event = "tunnel.agent_connected",
            agent = %entry.agent,
            group = %entry.group,
            agent_version = %accepted.hello.agent_version,
        );
        shared.recorder.emit(
            agent_event(
                EventKind::TunnelAgentConnected,
                Outcome::Success,
                entry.agent,
            )
            .uuid(field::GROUP_ID, entry.group.to_bytes())
            .text(
                field::AGENT_VERSION,
                truncate(&accepted.hello.agent_version),
            ),
        );
        tokio::spawn(control(tunnel, fingerprint, entry.agent, shared.clone()));
    }
}

/// Control messages of one agent: certificate renewal; session requests are
/// refused until the inventory exists.
async fn control(tunnel: Arc<CoreTunnel>, fingerprint: [u8; 32], agent: Uuid, shared: Arc<Shared>) {
    while let Some(message) = tunnel.recv().await {
        match message {
            AgentMessage::Renew { request } => match renew(&shared, &fingerprint, &request).await {
                Ok(reply) => {
                    let _ = tunnel.send(&reply).await;
                }
                Err(e) => {
                    tracing::warn!(
                        event = "agent.renewal_refused",
                        agent = %agent,
                        code = e.code(),
                        "{e}"
                    );
                    shared.recorder.emit(
                        agent_event(EventKind::AgentRenewalRefused, Outcome::Refused, agent)
                            .text(field::CODE, e.code()),
                    );
                    tunnel.close(e);
                    break;
                }
            },
            AgentMessage::SessionRequest { request_id, .. } => {
                let reply = CoreMessage::SessionRefused {
                    request_id,
                    code: "INV-E001".into(),
                    message: "ressource inconnue de l'inventaire".into(),
                };
                let _ = tunnel.send(&reply).await;
            }
            _ => {}
        }
    }
}

async fn renew(
    shared: &Shared,
    fingerprint: &[u8; 32],
    request: &str,
) -> Result<CoreMessage, TunnelError> {
    let key = renewal::verify(request, fingerprint)?;
    let entry = shared
        .cache
        .active(fingerprint)
        .ok_or(TunnelError::UnknownAgent)?;
    let now = unix_now();
    let validity = Validity {
        not_before: now.saturating_sub(SKEW),
        not_after: now + shared.certificate_lifetime,
    };
    let cert = shared
        .issuer
        .issue_agent(
            &key,
            &entry.group.to_string(),
            &entry.agent.to_string(),
            validity,
        )
        .map_err(|e| TunnelError::Io(e.to_string()))?;
    let new_fingerprint = tls::fingerprint(&cert);
    shared
        .store
        .register(new_fingerprint, entry.group, entry.agent)
        .await?;
    tracing::info!(
        event = "agent.certificate_renewed",
        agent = %entry.agent,
        fingerprint = %hex(&new_fingerprint),
        not_after = validity.not_after,
    );
    Ok(CoreMessage::Certificate {
        certificate: ostena_crypto::pki::pem_certificate(&cert),
        not_before: validity.not_before,
        not_after: validity.not_after,
    })
}

async fn follow_notices(mut notices: PgListener, shared: Arc<Shared>) {
    loop {
        match notices.recv().await {
            Ok(notice) => {
                // Any change may have appended to the chain (administration
                // commands notify in the transaction of their record).
                shared.recorder.wake();
                match Notice::parse(notice.payload()) {
                    Some(Notice::Token) => {
                        if let Err(e) = shared.enrollment.wake().await {
                            tracing::warn!(event = "enroll.wake_failed", code = e.code(), "{e}");
                        }
                    }
                    Some(Notice::Revoked(agent)) => {
                        let fingerprints = shared.cache.revoke_agent(agent);
                        let closed = shared.tunnels.close(&fingerprints, &TunnelError::Revoked);
                        tracing::warn!(
                            event = "agent.revocation_applied",
                            agent = %agent,
                            tunnels_closed = closed,
                        );
                        shared.recorder.emit(
                            agent_event(EventKind::AgentRevocationApplied, Outcome::Success, agent)
                                .u64(field::CLOSED_TUNNELS, closed as u64),
                        );
                    }
                    // Applied to the agents once the core serves SSH access.
                    Some(
                        Notice::Registered
                        | Notice::Audit
                        | Notice::LoginRevoked(_)
                        | Notice::Group(_),
                    )
                    | None => {}
                }
            }
            Err(e) => {
                // The listener reconnects on the next call; notices sent in
                // between are lost, so reload everything now.
                tracing::warn!(event = "core.notices_interrupted", "{e}");
                reload(&shared).await;
                tokio::time::sleep(RETRY_INTERVAL).await;
            }
        }
    }
}

/// Reloads the copy; then closes the tunnels it no longer accepts (a lost
/// revocation notice). While the copy is unavailable, open tunnels are kept
/// and new agents refused.
async fn reload(shared: &Shared) -> bool {
    if shared.store.reload().await.is_err() {
        return false;
    }
    let closed = shared.tunnels.sweep(|fp| shared.cache.active(fp).is_some());
    if closed > 0 {
        tracing::warn!(event = "agent.revocation_applied", tunnels_closed = closed);
        shared.recorder.emit(
            Event::new(
                EventKind::AgentRevocationApplied,
                Outcome::Success,
                ActorKind::Core,
                audit::CORE_ACTOR,
            )
            .u64(field::CLOSED_TUNNELS, closed as u64),
        );
    }
    true
}

async fn reload_periodically(shared: Arc<Shared>) {
    let mut wait = RELOAD_INTERVAL;
    loop {
        tokio::time::sleep(wait).await;
        wait = if reload(&shared).await {
            RELOAD_INTERVAL
        } else {
            RETRY_INTERVAL
        };
    }
}
