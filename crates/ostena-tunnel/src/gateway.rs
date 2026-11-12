//! What the agent holds from the core (ADR-0008), and the session requests.
//!
//! - **Policy**: the scope policy pushed for the gateway group is
//!   intersected with the local one: a target passes only if both allow it,
//!   the floor and the Ostena components being refused by both. The local
//!   configuration is a ceiling the core cannot widen. Until the core has
//!   pushed a policy, nothing passes (`TUN-E026`); an empty local policy lets
//!   nothing pass either. A lower version is refused (`TUN-E025`).
//! - **Grant keys**: the key set pushed by the core replaces the previous
//!   one; its version only increases (`TUN-E024`). The last version accepted
//!   is kept in a state file, written atomically with private rights, so that
//!   the refusal survives a restart of the agent.
//! - **Session requests**: the agent verifies the grant with the pushed keys
//!   and consumes its jti in its own store, then asks the core, which
//!   verifies it again and consumes the jti in its store (ADR-0004); the
//!   target the core answers is pinned by the agent scope control.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ostena_common::config::Mode;
use ostena_grant::{GatewayGroupId, Grant, GrantError, KeySet, ReplayStore, SignedGrant, Verifier};
use ostena_scope::{
    CompiledPolicy, InfrastructureSpec, PinnedTarget, PolicySpec, Scope, ScopeError,
    SharedLocalAddresses, SystemResolver,
};
use serde::Serialize;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::control::{AgentMessage, CoreMessage, GrantKey, SessionProtocol};
use crate::error::TunnelError;
use crate::ids::Uuid;
use crate::link::{AgentLink, KeyWriter};

/// How long the agent waits for the core to answer a session request.
pub const SESSION_ANSWER_TIMEOUT: Duration = Duration::from_secs(5);

/// The agent's parameters.
#[derive(Debug, Clone)]
pub struct GatewayParams {
    /// Gateway group of the agent (the grant audience).
    pub gateway_group: Uuid,
    /// Development or production (a pushed policy is compiled in it).
    pub mode: Mode,
    /// Local scope policy: the ceiling.
    pub local_policy: PolicySpec,
    /// Ostena components resolved by the agent (`CFG-P010`), refused as
    /// targets whatever the policies.
    pub infrastructure: Arc<Mutex<Vec<InfrastructureSpec>>>,
    /// Addresses of the agent itself, refused as targets.
    pub local_addresses: SharedLocalAddresses,
    /// The last key set version accepted.
    pub keyset_state: PathBuf,
    /// Writes the state file with private rights.
    pub write_private: KeyWriter,
    /// Grant verification limits.
    pub grant_policy: ostena_grant::Policy,
}

/// Versions applied, for `ostena agent status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Versions {
    /// Policy applied.
    pub policy: Option<u64>,
    /// Key set loaded.
    pub keyset: Option<u64>,
    /// Last key set version accepted, possibly before a restart.
    pub keyset_floor: Option<u64>,
}

/// What a push changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    /// Applied.
    Applied,
    /// The same version again: nothing to do.
    Unchanged,
}

struct Applies {
    version: u64,
    local: Arc<CompiledPolicy>,
    pushed: Arc<CompiledPolicy>,
}

#[derive(Default)]
struct Inner {
    policy: Option<Applies>,
    keys: Option<(u64, Verifier)>,
    keyset_floor: Option<u64>,
}

/// Policy and keys pushed by the core.
pub struct GatewayState {
    params: GatewayParams,
    audience: GatewayGroupId,
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for GatewayState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayState")
            .field("versions", &self.versions())
            .finish_non_exhaustive()
    }
}

fn read_floor(path: &Path) -> Result<Option<u64>, TunnelError> {
    match std::fs::read_to_string(path) {
        Ok(text) => text.trim().parse().map(Some).map_err(|_| {
            TunnelError::Config(format!(
                "{} : version du jeu de clés illisible ; l'interdiction de revenir en arrière ne \
                 peut pas être garantie",
                path.display()
            ))
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(TunnelError::Config(format!("{} : {e}", path.display()))),
    }
}

/// Replaces `path` atomically: a new file with private rights, synced, then
/// renamed over the old one.
fn write_floor(path: &Path, version: u64, write: KeyWriter) -> std::io::Result<()> {
    let mut name = path.as_os_str().to_owned();
    name.push(".new");
    let next = PathBuf::from(name);
    let _ = std::fs::remove_file(&next);
    write(&next, format!("{version}\n").as_bytes())?;
    std::fs::rename(&next, path)?;
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

fn key_set(keys: &[GrantKey]) -> Result<KeySet, TunnelError> {
    let mut set = KeySet::new();
    for key in keys {
        let kid = set.insert(key.verifying_key()?);
        if let Some(at) = key.retire_at {
            set.retire_at(kid, at)
                .map_err(|e| TunnelError::Protocol(e.to_string()))?;
        }
    }
    Ok(set)
}

impl GatewayState {
    /// Reads the last key set version accepted.
    ///
    /// # Errors
    ///
    /// [`TunnelError::Config`] if the state file exists but cannot be read:
    /// the rollback protection could not be guaranteed.
    pub fn open(params: GatewayParams) -> Result<Self, TunnelError> {
        let keyset_floor = read_floor(&params.keyset_state)?;
        let audience = GatewayGroupId::from_bytes(params.gateway_group.to_bytes());
        Ok(Self {
            params,
            audience,
            inner: Mutex::new(Inner {
                keyset_floor,
                ..Inner::default()
            }),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Versions applied.
    pub fn versions(&self) -> Versions {
        let inner = self.lock();
        Versions {
            policy: inner.policy.as_ref().map(|p| p.version),
            keyset: inner.keys.as_ref().map(|k| k.0),
            keyset_floor: inner.keyset_floor,
        }
    }

    fn compile(&self, spec: &PolicySpec) -> Result<Arc<CompiledPolicy>, TunnelError> {
        let mut spec = spec.clone();
        spec.gateway_group = self.params.gateway_group.to_string();
        if let Ok(infrastructure) = self.params.infrastructure.lock() {
            spec.infrastructure.extend(infrastructure.iter().cloned());
        }
        CompiledPolicy::compile(&spec, self.params.mode)
            .map(Arc::new)
            .map_err(|e| TunnelError::PolicyInvalid(e.to_string()))
    }

    /// Applies a policy pushed by the core.
    ///
    /// # Errors
    ///
    /// [`TunnelError::PolicyRollback`] for a lower version,
    /// [`TunnelError::PolicyInvalid`] for another gateway group or if it does
    /// not compile here (a
    /// weakening refused in production, for example). The previous policy
    /// stays.
    pub fn apply_policy(&self, version: u64, policy: &PolicySpec) -> Result<Applied, TunnelError> {
        if policy.gateway_group != self.params.gateway_group.to_string() {
            return Err(TunnelError::PolicyInvalid(format!(
                "politique du groupe « {} », pas de celui de l'agent",
                policy.gateway_group
            )));
        }
        if let Some(current) = self.lock().policy.as_ref().map(|p| p.version) {
            if version < current {
                return Err(TunnelError::PolicyRollback {
                    got: version,
                    current,
                });
            }
            if version == current {
                return Ok(Applied::Unchanged);
            }
        }
        let pushed = self.compile(policy)?;
        let local = self.compile(&self.params.local_policy)?;
        let mut inner = self.lock();
        if inner.policy.as_ref().is_some_and(|p| p.version >= version) {
            return Ok(Applied::Unchanged);
        }
        inner.policy = Some(Applies {
            version,
            local,
            pushed,
        });
        Ok(Applied::Applied)
    }

    /// Applies a key set pushed by the core. A higher version is written to
    /// the state file before it is used.
    ///
    /// # Errors
    ///
    /// [`TunnelError::KeySetRollback`] below the last version accepted, even
    /// before a restart; [`TunnelError::Protocol`] for an invalid key;
    /// [`TunnelError::Io`] if the version cannot be persisted (refused: the
    /// rollback protection would not survive a restart).
    pub fn apply_keyset(&self, version: u64, keys: &[GrantKey]) -> Result<Applied, TunnelError> {
        let (loaded, floor) = {
            let inner = self.lock();
            (inner.keys.as_ref().map(|k| k.0), inner.keyset_floor)
        };
        let current = loaded.max(floor);
        if let Some(current) = current
            && version < current
        {
            return Err(TunnelError::KeySetRollback {
                got: version,
                current,
            });
        }
        if loaded == Some(version) {
            return Ok(Applied::Unchanged);
        }
        let verifier = Verifier::new(key_set(keys)?, self.audience, self.params.grant_policy);
        if floor.is_none_or(|f| version > f) {
            write_floor(
                &self.params.keyset_state,
                version,
                self.params.write_private,
            )
            .map_err(|e| {
                TunnelError::Io(format!("{} : {e}", self.params.keyset_state.display()))
            })?;
        }
        let mut inner = self.lock();
        inner.keyset_floor = Some(inner.keyset_floor.map_or(version, |f| f.max(version)));
        inner.keys = Some((version, verifier));
        Ok(Applied::Applied)
    }

    /// Verifies a grant with the pushed keys and consumes its jti in `store`.
    ///
    /// # Errors
    ///
    /// [`SessionError::Tunnel`] (`TUN-E026`) before the first key set,
    /// [`SessionError::Grant`] otherwise.
    pub async fn verify_grant<S: ReplayStore>(
        &self,
        grant: &str,
        now: u64,
        store: &S,
    ) -> Result<Grant, SessionError> {
        let verifier =
            self.lock()
                .keys
                .as_ref()
                .map(|k| k.1.clone())
                .ok_or(SessionError::Tunnel(TunnelError::NotReady(
                    "les clés de vérification des grants",
                )))?;
        let signed = SignedGrant::from_text(grant).map_err(SessionError::Grant)?;
        verifier
            .verify(signed.as_bytes(), now, store)
            .await
            .map_err(SessionError::Grant)
    }

    /// Pins `host:port` through the effective policy: resolved once, every
    /// address allowed by the local policy and by the pushed one.
    ///
    /// # Errors
    ///
    /// [`SessionError::Tunnel`] (`TUN-E026`) before the first policy,
    /// [`SessionError::Scope`] for a refusal.
    pub async fn pin(&self, host: &str, port: u16) -> Result<PinnedTarget, SessionError> {
        let (local, pushed) = self
            .lock()
            .policy
            .as_ref()
            .map(|p| (p.local.clone(), p.pushed.clone()))
            .ok_or(SessionError::Tunnel(TunnelError::NotReady(
                "de politique de périmètre",
            )))?;
        let scope = Scope::new(
            local,
            self.params.local_addresses.clone(),
            SystemResolver::new(Duration::from_secs(5), 8),
        );
        let pinned = scope
            .pin(host, port)
            .await
            .map_err(|e| SessionError::Scope(Box::new(e)))?;
        let addresses = self.params.local_addresses.snapshot();
        for addr in pinned.addrs() {
            pushed.check(*addr, &addresses).map_err(|refusal| {
                SessionError::Scope(Box::new(ScopeError::Refused {
                    requested: format!("{host}:{port}"),
                    rule: format!("politique du core : {}", pushed.describe(refusal.rule)),
                    via_name: false,
                    address: addr.to_string(),
                    refusal,
                }))
            })?;
        }
        Ok(pinned)
    }
}

/// Why a session cannot open. Each variant has a stable code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    /// Refused by the agent's grant verification (`GRT-E…`).
    #[error("{0}")]
    Grant(GrantError),
    /// Refused by the scope control (`SCP-E…`).
    #[error("{0}")]
    Scope(Box<ScopeError>),
    /// Tunnel or push state (`TUN-E…`).
    #[error("{0}")]
    Tunnel(TunnelError),
    /// Refused by the core, with its code.
    #[error("[{code}] refusé par le core : {message}")]
    Core {
        /// Stable code given by the core.
        code: String,
        /// Explanation.
        message: String,
    },
    /// The core answered parameters that do not match the grant.
    #[error("[TUN-E010] réponse du core incohérente avec le grant : {0}")]
    Mismatch(&'static str),
}

impl SessionError {
    /// The stable code.
    pub fn code(&self) -> String {
        match self {
            Self::Grant(e) => e.code().to_owned(),
            Self::Scope(e) => e.code().as_str().to_owned(),
            Self::Tunnel(e) => e.code().to_owned(),
            Self::Core { code, .. } => code.clone(),
            Self::Mismatch(_) => "TUN-E010".to_owned(),
        }
    }
}

/// A session the agent may open.
#[derive(Debug, Clone)]
pub struct Session {
    /// Session identifier given by the core.
    pub session_id: Uuid,
    /// The grant, verified.
    pub grant: Grant,
    /// The target, pinned.
    pub target: PinnedTarget,
    /// Maximum length, in seconds.
    pub max_session_secs: u32,
}

fn same_protocol(answer: SessionProtocol, grant: ostena_grant::Protocol) -> bool {
    matches!(
        (answer, grant),
        (SessionProtocol::Ssh, ostena_grant::Protocol::Ssh)
            | (SessionProtocol::Rdp, ostena_grant::Protocol::Rdp)
            | (SessionProtocol::Vnc, ostena_grant::Protocol::Vnc)
            | (SessionProtocol::Web, ostena_grant::Protocol::Web)
    )
}

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<CoreMessage>>>>;

/// Applies the pushes of the core and opens sessions through it.
#[derive(Debug)]
pub struct Gateway {
    state: Arc<GatewayState>,
    link: Arc<AgentLink>,
    pending: Pending,
    next_request: AtomicU64,
    task: JoinHandle<()>,
}

impl Gateway {
    /// Starts applying what the core pushes on `link`.
    ///
    /// # Errors
    ///
    /// The pushes of `link` were already taken.
    ///
    /// # Panics
    ///
    /// Outside a Tokio runtime.
    pub fn start(state: Arc<GatewayState>, link: Arc<AgentLink>) -> Result<Self, TunnelError> {
        let pushes = link
            .take_pushes()
            .ok_or_else(|| TunnelError::Config("messages du core déjà pris".into()))?;
        let pending = Pending::default();
        let task = tokio::spawn(dispatch(pushes, state.clone(), pending.clone()));
        Ok(Self {
            state,
            link,
            pending,
            next_request: AtomicU64::new(1),
            task,
        })
    }

    /// The state the core pushed.
    pub fn state(&self) -> &GatewayState {
        &self.state
    }

    /// Opens a session for `grant`: verified here and its jti consumed in
    /// `store`, then verified and consumed by the core, whose answer gives the
    /// target, pinned here through the effective policy.
    ///
    /// # Errors
    ///
    /// The first refusal, see [`SessionError`].
    pub async fn open_session<S: ReplayStore>(
        &self,
        grant: &str,
        now: u64,
        store: &S,
    ) -> Result<Session, SessionError> {
        // Nothing passes before the core has pushed a policy.
        if self.state.versions().policy.is_none() {
            return Err(SessionError::Tunnel(TunnelError::NotReady(
                "de politique de périmètre",
            )));
        }
        let verified = self.state.verify_grant(grant, now, store).await?;
        let request_id = self.next_request.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        if let Ok(mut pending) = self.pending.lock() {
            pending.insert(request_id, tx);
        }
        let forget = || {
            if let Ok(mut pending) = self.pending.lock() {
                pending.remove(&request_id);
            }
        };
        let sent = self
            .link
            .send(&AgentMessage::SessionRequest {
                request_id,
                grant: grant.to_owned(),
            })
            .await;
        if let Err(e) = sent {
            forget();
            return Err(SessionError::Tunnel(e));
        }
        let Ok(Ok(answer)) = tokio::time::timeout(SESSION_ANSWER_TIMEOUT, rx).await else {
            forget();
            return Err(SessionError::Tunnel(TunnelError::NoAnswer));
        };
        match answer {
            CoreMessage::SessionParams {
                session_id,
                protocol,
                host,
                port,
                max_session_secs,
                ..
            } => {
                if !same_protocol(protocol, verified.claims.protocol) {
                    return Err(SessionError::Mismatch("protocole"));
                }
                if max_session_secs > verified.claims.max_session_secs {
                    return Err(SessionError::Mismatch("durée de session"));
                }
                let session_id =
                    Uuid::parse(&session_id).ok_or(SessionError::Mismatch("session"))?;
                let target = self.state.pin(&host, port).await?;
                tracing::info!(
                    event = "agent.session_granted",
                    session = %session_id,
                    jti = %verified.jti,
                    target = %format_args!("{host}:{port}"),
                );
                Ok(Session {
                    session_id,
                    grant: verified,
                    target,
                    max_session_secs,
                })
            }
            CoreMessage::SessionRefused { code, message, .. } => {
                tracing::warn!(event = "agent.session_refused", code = %code, "{message}");
                Err(SessionError::Core { code, message })
            }
            _ => Err(SessionError::Mismatch("type de réponse")),
        }
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn dispatch(
    mut pushes: mpsc::Receiver<CoreMessage>,
    state: Arc<GatewayState>,
    pending: Pending,
) {
    while let Some(message) = pushes.recv().await {
        match message {
            CoreMessage::Policy { version, policy } => match state.apply_policy(version, &policy) {
                Ok(Applied::Applied) => {
                    tracing::info!(event = "agent.policy_applied", version);
                }
                Ok(Applied::Unchanged) => {}
                Err(e) => tracing::warn!(
                    event = "agent.policy_refused",
                    version,
                    code = e.code(),
                    "{e}"
                ),
            },
            CoreMessage::KeySet { version, keys } => match state.apply_keyset(version, &keys) {
                Ok(Applied::Applied) => {
                    tracing::info!(event = "agent.keyset_applied", version, keys = keys.len());
                }
                Ok(Applied::Unchanged) => {}
                Err(e) => tracing::warn!(
                    event = "agent.keyset_refused",
                    version,
                    code = e.code(),
                    "{e}"
                ),
            },
            CoreMessage::SessionParams { request_id, .. }
            | CoreMessage::SessionRefused { request_id, .. } => {
                let waiter = pending.lock().ok().and_then(|mut p| p.remove(&request_id));
                if let Some(waiter) = waiter {
                    let _ = waiter.send(message);
                } else {
                    tracing::warn!(
                        event = "agent.session_answer_unexpected",
                        request_id,
                        "réponse du core sans demande en attente, ignorée"
                    );
                }
            }
            _ => {}
        }
    }
}
