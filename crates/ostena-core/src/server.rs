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

use ostena_common::config::{CoreConfig, KeySource};
use ostena_common::secret::SecretBytes;
use ostena_crypto::pki::{IssuingAuthority, Validity};
use ostena_crypto::tls::{self, ClientAuth, Identity, TrustAnchor};
use ostena_tunnel::control::{AgentMessage, CoreMessage, PROTOCOL_VERSION};
use ostena_tunnel::enroll::{AgentRegistry, EnrollmentService};
use ostena_tunnel::{ALPN, CoreListener, CoreTunnel, Limits, TunnelError, renewal};
use sqlx::postgres::PgListener;
use tokio::task::JoinHandle;

use crate::cache::AgentCache;
use crate::error::CoreError;
use crate::store::{CHANNEL, Notice, PgStore};

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
        Ok(Self {
            root,
            server,
            issuing: Arc::new(issuing),
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
}

/// A started core. Dropping it does not stop it: call [`RunningCore::stop`].
pub struct RunningCore {
    shared: Arc<Shared>,
    listener: Arc<CoreListener>,
    tunnel_addr: SocketAddr,
    tasks: Vec<JoinHandle<()>>,
}

impl std::fmt::Debug for RunningCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunningCore")
            .field("tunnel_addr", &self.tunnel_addr)
            .finish_non_exhaustive()
    }
}

impl RunningCore {
    /// Loads the registry, binds the tunnel listener, prepares the
    /// enrolment listener (opened if a token is valid) and starts the
    /// background tasks.
    ///
    /// # Errors
    ///
    /// [`CoreError`] if the registry cannot be read or a listener cannot be
    /// bound.
    ///
    /// # Panics
    ///
    /// Outside a Tokio runtime.
    pub async fn start(
        config: &CoreConfig,
        store: PgStore,
        keys: &Keys,
    ) -> Result<Self, CoreError> {
        let cache = store.cache();
        store.reload().await?;
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
        });
        // Tokens issued while the core was stopped.
        shared.enrollment.wake().await.map_err(startup)?;
        let mut notices = PgListener::connect_with(shared.store.pool()).await?;
        notices.listen(CHANNEL).await?;
        let tasks = vec![
            tokio::spawn(accept(listener.clone(), shared.clone())),
            tokio::spawn(follow_notices(notices, shared.clone())),
            tokio::spawn(reload_periodically(shared.clone())),
        ];
        tracing::info!(
            event = "core.started",
            tunnel = %tunnel_addr,
            enrollment = %shared.enrollment.addr(),
            "core démarré"
        );
        Ok(Self {
            shared,
            listener,
            tunnel_addr,
            tasks,
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

    /// Stops: closes both listeners and every tunnel.
    pub fn stop(self) {
        for task in &self.tasks {
            task.abort();
        }
        self.listener.close();
        self.shared.enrollment.close();
        self.shared
            .tunnels
            .close_all(&TunnelError::ConnectionLost("arrêt du core".into()));
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
        tokio::spawn(control(tunnel, fingerprint, shared.clone()));
    }
}

/// Control messages of one agent: certificate renewal; session requests are
/// refused until the inventory exists.
async fn control(tunnel: Arc<CoreTunnel>, fingerprint: [u8; 32], shared: Arc<Shared>) {
    while let Some(message) = tunnel.recv().await {
        match message {
            AgentMessage::Renew { request } => match renew(&shared, &fingerprint, &request).await {
                Ok(reply) => {
                    let _ = tunnel.send(&reply).await;
                }
                Err(e) => {
                    tracing::warn!(event = "agent.renewal_refused", code = e.code(), "{e}");
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
            Ok(notice) => match Notice::parse(notice.payload()) {
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
                }
                Some(Notice::Registered) | None => {}
            },
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
