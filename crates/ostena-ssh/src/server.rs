//! The native SSH server of the agent (ADR-0010): certificate-only, behind
//! the pre-check, one session channel per connection relayed to a target
//! through the [`driver`](crate::driver).
//!
//! **Authentication.** Only an OpenSSH user certificate is accepted; a bare
//! key is refused (`SSH-E012`). The SSH library checks the dates and the
//! signature of the certificate with its own cryptography, not the
//! authority, the type, the principals, the options nor the extensions:
//! the certificate is encoded again and checked a second time by
//! [`cert`](crate::cert) (`ostena-crypto`): authority among the pushed
//! ones, strict signature, user policy (`SSH-E011`). Then the user name is
//! split into `account@resource` (`SSH-E010`) and the [`Authorizer`]
//! decides (`SSH-E013`, with the underlying code). The library is told to
//! accept only once all of it succeeded.
//!
//! **Bounds.** Connections not yet authenticated, authenticated sessions
//! and authorisations in flight are bounded (`SSH-E019`), a connection must
//! authenticate within `login_grace`, a session ends at its maximum length,
//! on a revocation of its login session or on stop.
//!
//! **Channel.** One session channel; terminal (if the certificate allows
//! it, bounded), shell, command (32 KiB at most), window changes, signals
//! and `LANG`/`LC_*` are relayed. Subsystems (sftp), port forwarding in
//! both directions, agent and X11 forwarding are refused
//! (`ssh.channel_refused`, `SSH-E017`). A command is logged by its length
//! and SHA-256 only: secrets can appear in a command line; its text belongs
//! to the transcripts.
//!
//! Events: `ssh.connection_limited`, `ssh.connection_refused`,
//! `ssh.auth_refused`, `ssh.access_refused`, `ssh.session_opened`,
//! `ssh.exec`, `ssh.session_expired`, `ssh.session_revoked`,
//! `ssh.session_closed`, `ssh.channel_refused`.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ostena_crypto::p256::VerifyingKey;
use ostena_scope::PinnedTarget;
use russh::keys::{Certificate, PrivateKey};
use russh::server::{Auth, ChannelOpenHandle, Msg, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId, ChannelMsg, ChannelWriteHalf, Disconnect, Pty, Sig, client};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::task::JoinHandle;

use crate::cert::{self, UserIdentity, format_uuid};
use crate::config;
use crate::driver::{self, TargetSession, sec1_point};
use crate::error::SshError;
use crate::login::parse_login;
use crate::precheck::Role;
use crate::precheck::stream::Prechecked;

/// Longest command accepted.
pub const MAX_COMMAND: usize = 32 * 1024;
/// Longest terminal type.
const MAX_TERM: usize = 64;
/// Largest terminal, in characters.
const MAX_CELLS: u32 = 10_000;
/// Largest terminal, in pixels.
const MAX_PIXELS: u32 = 100_000;
/// Longest environment value relayed.
const MAX_ENV_VALUE: usize = 256;
/// How long a request relayed to the target may wait for its answer.
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a session may take to end once disconnected.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Bounds and delays of the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerSettings {
    /// Authenticated sessions at once.
    pub max_sessions: usize,
    /// Connections not yet authenticated at once.
    pub max_unauthenticated: usize,
    /// Connections not yet authenticated at once from one source address.
    pub max_unauthenticated_per_source: usize,
    /// Authorisations in flight at once (requests to the core).
    pub max_authorizations: usize,
    /// Delay to authenticate.
    pub login_grace: Duration,
    /// Delay to reach a target.
    pub target_connect_timeout: Duration,
    /// Authentication attempts per connection.
    pub max_auth_attempts: usize,
    /// Delay of the pre-check (identification and first packet).
    pub precheck_timeout: Duration,
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            max_sessions: 64,
            max_unauthenticated: 16,
            max_unauthenticated_per_source: 4,
            max_authorizations: 32,
            login_grace: Duration::from_secs(30),
            target_connect_timeout: Duration::from_secs(5),
            max_auth_attempts: 3,
            precheck_timeout: crate::precheck::stream::DEFAULT_TIMEOUT,
        }
    }
}

/// What the server presents and trusts, pushed by the core (ADR-0010).
pub struct SshIdentity {
    host_key: PrivateKey,
    host_certificate: Certificate,
    user_cas: Vec<VerifyingKey>,
}

impl std::fmt::Debug for SshIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshIdentity")
            .field("authorities", &self.user_cas.len())
            .finish_non_exhaustive()
    }
}

impl SshIdentity {
    /// The host key, its host certificate (OpenSSH blob) signed by one of
    /// `host_cas` and checked at `now` (type host, for that key, valid now,
    /// no option), the user authorities (at least one).
    ///
    /// # Errors
    ///
    /// [`SshError::Identity`] (`SSH-E018`).
    pub fn new(
        host_key: PrivateKey,
        host_certificate: &[u8],
        host_cas: &[VerifyingKey],
        user_cas: Vec<VerifyingKey>,
        now: u64,
    ) -> Result<Self, SshError> {
        let invalid = |what: String| SshError::Identity(what);
        if user_cas.is_empty() {
            return Err(invalid("aucune autorité d'utilisateurs".into()));
        }
        if host_cas.is_empty() {
            return Err(invalid("aucune autorité d'hôtes".into()));
        }
        let point = sec1_point(host_key.public_key())
            .and_then(|p| p.try_into().ok())
            .and_then(|p: &[u8; 65]| VerifyingKey::from_bytes(p).ok())
            .ok_or_else(|| invalid("clé d'hôte hors de la liste figée".into()))?;
        let parsed = cert::parse(host_certificate).map_err(|e| invalid(e.to_string()))?;
        parsed
            .verify(host_cas)
            .map_err(|e| invalid(format!("certificat d'hôte : {e}")))?;
        cert::check_host(&parsed, &point, now).map_err(|e| invalid(e.to_string()))?;
        let host_certificate =
            Certificate::from_bytes(host_certificate).map_err(|e| invalid(e.to_string()))?;
        Ok(Self {
            host_key,
            host_certificate,
            user_cas,
        })
    }
}

/// An access to authorise: who, as which account, on which resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessRequest {
    /// The checked certificate.
    pub identity: UserIdentity,
    /// Account on the target.
    pub account: String,
    /// Resource name (mapped by the core, never resolved here).
    pub resource: String,
    /// Address of the SSH client.
    pub client_address: SocketAddr,
}

/// An authorised access: the target to reach and how.
#[derive(Debug, Clone)]
pub struct Authorized {
    /// Session identifier given by the core.
    pub session_id: [u8; 16],
    /// The target, pinned by the scope control.
    pub target: PinnedTarget,
    /// Its host key, pinned in the inventory.
    pub target_host_key: VerifyingKey,
    /// Account on the target.
    pub account: String,
    /// Maximum length of the session.
    pub max_session: Duration,
}

/// Why an access is refused: the underlying stable code and a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// Stable code (`GRT-E…`, `SCP-E…`, `TUN-E…`, a code of the core).
    pub code: String,
    /// Explanation.
    pub message: String,
}

/// How a session ended, for the core (`session_closed`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSummary {
    /// Session identifier given by the core.
    pub session_id: [u8; 16],
    /// The user.
    pub subject: [u8; 16],
    /// The login session.
    pub login_session: [u8; 16],
    /// Account on the target.
    pub account: String,
    /// Resource name.
    pub resource: String,
    /// Bytes relayed to the target.
    pub bytes_to_target: u64,
    /// Bytes relayed from the target.
    pub bytes_from_target: u64,
    /// Why it ended.
    pub reason: &'static str,
    /// How long it lasted.
    pub duration: Duration,
}

/// Decides the accesses: in the agent, through the core (grant, scope).
pub trait Authorizer: Send + Sync + 'static {
    /// Authorises `request`, or refuses it with a stable code.
    fn authorize(
        &self,
        request: AccessRequest,
    ) -> impl Future<Output = Result<Authorized, Refusal>> + Send;

    /// A session authorised by [`Authorizer::authorize`] ended.
    fn closed(&self, summary: SessionSummary);
}

/// Sees what is relayed; the hook of the future transcripts. Does nothing
/// by default.
pub trait SessionObserver: Send + Sync + 'static {
    /// Bytes from the user to the target.
    fn user_data(&self, _session: &[u8; 16], _data: &[u8]) {}
    /// Bytes from the target to the user.
    fn target_data(&self, _session: &[u8; 16], _data: &[u8]) {}
}

struct NoObserver;

impl SessionObserver for NoObserver {}

/// A live authenticated session, for revocations.
struct Live {
    login_session: [u8; 16],
    revoke: watch::Sender<bool>,
    /// Authorised (until then, registered while the authoriser decides,
    /// so that a revocation in between is not lost).
    active: bool,
}

struct Shared<A> {
    settings: ServerSettings,
    identity: watch::Receiver<Option<Arc<SshIdentity>>>,
    target_key: Arc<PrivateKey>,
    authorizer: Arc<A>,
    observer: Arc<dyn SessionObserver>,
    unauthenticated: Arc<Semaphore>,
    sessions: Arc<Semaphore>,
    authorizations: Arc<Semaphore>,
    live: Mutex<HashMap<u64, Live>>,
    sources: Mutex<HashMap<std::net::IpAddr, usize>>,
    next: AtomicU64,
}

/// The agent SSH server.
pub struct SshServer<A> {
    shared: Arc<Shared<A>>,
}

impl<A> std::fmt::Debug for SshServer<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshServer")
            .field("settings", &self.shared.settings)
            .finish_non_exhaustive()
    }
}

impl<A> Clone for SshServer<A> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
        }
    }
}

/// A Unicode format character (category Cf): bidirectional controls
/// (U+202A–202E, U+2066–2069), zero-width characters, tags… They can
/// disguise a logged text.
fn is_format(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

/// Printable, bounded text from the peer, for events: control and format
/// characters are replaced.
fn sanitize(text: &str) -> String {
    text.chars()
        .take(64)
        .map(|c| {
            if c.is_control() || is_format(c) {
                '?'
            } else {
                c
            }
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn limited(peer: SocketAddr, listener: SocketAddr, what: &'static str) {
    let error = SshError::Limit(what);
    tracing::warn!(
        event = "ssh.connection_limited",
        code = error.code(),
        peer = %peer,
        listener = %listener,
        "{error}"
    );
}

impl<A: Authorizer> SshServer<A> {
    /// A server presenting the latest `identity`, joining the targets with
    /// `target_key`, deciding through `authorizer`.
    pub fn new(
        settings: ServerSettings,
        identity: watch::Receiver<Option<Arc<SshIdentity>>>,
        target_key: Arc<PrivateKey>,
        authorizer: Arc<A>,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                settings,
                identity,
                target_key,
                authorizer,
                observer: Arc::new(NoObserver),
                unauthenticated: Arc::new(Semaphore::new(settings.max_unauthenticated)),
                sessions: Arc::new(Semaphore::new(settings.max_sessions)),
                authorizations: Arc::new(Semaphore::new(settings.max_authorizations)),
                live: Mutex::new(HashMap::new()),
                sources: Mutex::new(HashMap::new()),
                next: AtomicU64::new(1),
            }),
        }
    }

    /// The same server, with `observer` seeing what is relayed. Call it
    /// before [`SshServer::serve`].
    #[must_use]
    pub fn with_observer(self, observer: Arc<dyn SessionObserver>) -> Self {
        let shared = Arc::try_unwrap(self.shared).map_or_else(
            |shared| shared,
            |mut shared| {
                shared.observer = observer;
                Arc::new(shared)
            },
        );
        Self { shared }
    }

    /// Serves the connections of `listener` until `stop` turns true; the
    /// sessions in progress are then disconnected.
    ///
    /// # Errors
    ///
    /// Never for now: accept errors are retried.
    pub async fn serve(
        &self,
        listener: TcpListener,
        mut stop: watch::Receiver<bool>,
    ) -> std::io::Result<()> {
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((tcp, peer)) = accepted else {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    };
                    let shared = self.shared.clone();
                    tokio::spawn(connection(shared, tcp, peer, stop.clone()));
                }
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() {
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Cuts every session of the login session `login_session` (revoked on
    /// the core); returns how many.
    pub fn revoke_login(&self, login_session: [u8; 16]) -> usize {
        let live = self
            .shared
            .live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut count = 0;
        for l in live.values().filter(|l| l.login_session == login_session) {
            l.revoke.send_replace(true);
            count += 1;
        }
        count
    }

    /// Authenticated sessions now.
    pub fn sessions(&self) -> usize {
        self.shared
            .live
            .lock()
            .map(|l| l.values().filter(|s| s.active).count())
            .unwrap_or_default()
    }
}

/// What the handler tells the connection task.
#[derive(Default)]
struct Conn {
    /// Set once authorised: the session permit and what was authorised.
    authorized: Mutex<Option<(OwnedSemaphorePermit, AccessRequest, Authorized)>>,
    /// The target, once connected.
    target: Mutex<Option<Arc<TargetSession>>>,
    /// The registration in `live` of the authorised session and its
    /// revocation signal.
    live: Mutex<Option<(u64, watch::Receiver<bool>)>>,
    /// A certificate reached our checks (the library refuses an expired
    /// one or a bad signature before them, without telling).
    certificate_checked: AtomicBool,
    to_target: Arc<AtomicU64>,
    from_target: Arc<AtomicU64>,
}

struct Relay {
    id: ChannelId,
    target: Arc<ChannelWriteHalf<client::Msg>>,
    replies: mpsc::Receiver<bool>,
    allow_pty: bool,
}

struct Handler<A> {
    shared: Arc<Shared<A>>,
    conn: Arc<Conn>,
    identity: Arc<SshIdentity>,
    peer: SocketAddr,
    listener: SocketAddr,
    authenticated: watch::Sender<bool>,
    target: Option<JoinHandle<Result<TargetSession, SshError>>>,
    relay: Option<Relay>,
    access: Option<(AccessRequest, Authorized)>,
    session_id: [u8; 16],
}

impl<A: Authorizer> Handler<A> {
    fn auth_refused(&self, error: &SshError, account: Option<&str>) {
        tracing::warn!(
            event = "ssh.auth_refused",
            code = error.code(),
            peer = %self.peer,
            listener = %self.listener,
            account = account.map(sanitize).unwrap_or_default(),
            "{error}"
        );
    }

    fn channel_refused(&self, kind: &str) {
        let error = SshError::Refused("non autorisé par Ostena");
        tracing::warn!(
            event = "ssh.channel_refused",
            code = error.code(),
            peer = %self.peer,
            listener = %self.listener,
            kind = sanitize(kind),
            "{error}"
        );
    }

    /// Asks the authoriser, the session registered in `live` meanwhile: a
    /// revocation of the login session arriving before the decision is not
    /// lost. Unregistered if refused.
    async fn decide(
        &self,
        request: &AccessRequest,
    ) -> (u64, watch::Receiver<bool>, Result<Authorized, Refusal>) {
        let id = self.shared.next.fetch_add(1, Ordering::Relaxed);
        let (revoke, revoked) = watch::channel(false);
        if let Ok(mut live) = self.shared.live.lock() {
            live.insert(
                id,
                Live {
                    login_session: request.identity.login_session,
                    revoke,
                    active: false,
                },
            );
        }
        let decision = self.shared.authorizer.authorize(request.clone()).await;
        if let Ok(mut live) = self.shared.live.lock() {
            if decision.is_ok() {
                if let Some(entry) = live.get_mut(&id) {
                    entry.active = true;
                }
            } else {
                live.remove(&id);
            }
        }
        (id, revoked, decision)
    }

    /// The certificate checked a second time, the user name, then the
    /// authoriser.
    async fn authorize(&mut self, user: &str, certificate: &Certificate) -> Auth {
        let refuse = |error: &SshError, this: &Self| {
            this.auth_refused(error, None);
            Auth::reject()
        };
        let Ok(blob) = certificate.to_bytes() else {
            return refuse(
                &SshError::UserCertificate(cert::CertError::Malformed("encodage")),
                self,
            );
        };
        let now = ostena_grant::unix_now();
        let identity = cert::parse(&blob)
            .and_then(|c| c.verify(&self.identity.user_cas).map(|_| c))
            .and_then(|c| cert::check_user(&c, now));
        let identity = match identity {
            Ok(identity) => identity,
            Err(e) => return refuse(&SshError::UserCertificate(e), self),
        };
        let login = match parse_login(user) {
            Ok(login) => login,
            Err(e) => {
                self.auth_refused(&SshError::Login(e), Some(user));
                return Auth::reject();
            }
        };
        let Ok(_in_flight) = self.shared.authorizations.clone().try_acquire_owned() else {
            limited(self.peer, self.listener, "autorisations en cours");
            return Auth::reject();
        };
        let Ok(permit) = self.shared.sessions.clone().try_acquire_owned() else {
            limited(self.peer, self.listener, "sessions");
            return Auth::reject();
        };
        let request = AccessRequest {
            identity,
            account: login.account.to_owned(),
            resource: login.resource.to_owned(),
            client_address: self.peer,
        };
        let (id, revoked, decision) = self.decide(&request).await;
        match decision {
            Ok(authorized) => {
                if let Ok(mut slot) = self.conn.live.lock() {
                    *slot = Some((id, revoked));
                }
                self.session_id = authorized.session_id;
                // Eagerly: the target is reached while the client opens its
                // channel.
                let shared = self.shared.clone();
                let target = authorized.target.clone();
                let host_key = authorized.target_host_key;
                let account = authorized.account.clone();
                let label = format!("{}@{}", sanitize(&account), sanitize(&request.resource));
                self.target = Some(tokio::spawn(async move {
                    driver::connect(
                        &target,
                        &host_key,
                        &account,
                        shared.target_key.clone(),
                        shared.settings.target_connect_timeout,
                        &label,
                    )
                    .await
                }));
                self.access = Some((request.clone(), authorized.clone()));
                if let Ok(mut slot) = self.conn.authorized.lock() {
                    *slot = Some((permit, request, authorized));
                }
                self.authenticated.send_replace(true);
                Auth::Accept
            }
            Err(refusal) => {
                let error = SshError::AccessRefused {
                    code: refusal.code.clone(),
                    message: refusal.message,
                };
                tracing::warn!(
                    event = "ssh.access_refused",
                    code = error.code(),
                    cause = %refusal.code,
                    peer = %self.peer,
                listener = %self.listener,
                    subject = %format_uuid(&request.identity.subject),
                    login_session = %format_uuid(&request.identity.login_session),
                    account = %sanitize(&request.account),
                    resource = %request.resource,
                    "{error}"
                );
                Auth::reject()
            }
        }
    }

    /// Relays a request to the target and its answer to the user.
    async fn answer(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        let ok = match &mut self.relay {
            Some(relay) => matches!(
                tokio::time::timeout(REPLY_TIMEOUT, relay.replies.recv()).await,
                Ok(Some(true))
            ),
            None => false,
        };
        if ok {
            session.channel_success(channel)
        } else {
            session.channel_failure(channel)
        }
    }

    fn relay(&self, channel: ChannelId) -> Option<Arc<ChannelWriteHalf<client::Msg>>> {
        self.relay
            .as_ref()
            .filter(|r| r.id == channel)
            .map(|r| r.target.clone())
    }

    async fn open(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        let target = match self.target.take() {
            Some(join) => join
                .await
                .unwrap_or_else(|e| Err(SshError::TargetUnreachable(e.to_string()))),
            None => Err(SshError::Refused("aucune autorisation")),
        };
        let opened = match target {
            Ok(target) => {
                let target = Arc::new(target);
                if let Ok(mut slot) = self.conn.target.lock() {
                    *slot = Some(target.clone());
                }
                target.open_session().await
            }
            Err(e) => Err(e),
        };
        let Ok(target_channel) = opened else {
            reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
            session.disconnect(
                Disconnect::ByApplication,
                "cible injoignable ou refusée",
                "fr",
            )?;
            return Ok(());
        };
        let id = channel.id();
        reply.accept().await;
        let (user_read, user_write) = channel.split();
        let (target_read, target_write) = target_channel.split();
        let target_write = Arc::new(target_write);
        let (replies_tx, replies) = mpsc::channel(4);
        let allow_pty = self
            .access
            .as_ref()
            .is_some_and(|(r, _)| r.identity.allow_pty);
        tokio::spawn(user_to_target(
            user_read,
            target_write.clone(),
            self.conn.to_target.clone(),
            self.shared.observer.clone(),
            self.session_id,
        ));
        tokio::spawn(target_to_user(
            target_read,
            user_write,
            session.handle(),
            id,
            replies_tx,
            self.conn.from_target.clone(),
            self.shared.observer.clone(),
            self.session_id,
        ));
        self.relay = Some(Relay {
            id,
            target: target_write,
            replies,
            allow_pty,
        });
        if let Some((request, authorized)) = self.access.as_ref() {
            tracing::info!(
                event = "ssh.session_opened",
                session = %format_uuid(&authorized.session_id),
                subject = %format_uuid(&request.identity.subject),
                login_session = %format_uuid(&request.identity.login_session),
                account = %sanitize(&request.account),
                resource = %request.resource,
                peer = %self.peer,
                listener = %self.listener,
                terminal = allow_pty,
                "session SSH ouverte"
            );
        }
        Ok(())
    }
}

/// From the user to the target: data, end of data, close.
async fn user_to_target(
    mut user: russh::ChannelReadHalf,
    target: Arc<ChannelWriteHalf<client::Msg>>,
    count: Arc<AtomicU64>,
    observer: Arc<dyn SessionObserver>,
    session: [u8; 16],
) {
    while let Some(message) = user.wait().await {
        let sent = match message {
            ChannelMsg::Data { data } => {
                count.fetch_add(data.len() as u64, Ordering::Relaxed);
                observer.user_data(&session, &data);
                target.data_bytes(data).await
            }
            ChannelMsg::Eof => target.eof().await,
            ChannelMsg::Close => {
                let _ = target.close().await;
                break;
            }
            // Requests are decided by the handler; the rest is not relayed.
            _ => Ok(()),
        };
        if sent.is_err() {
            break;
        }
    }
}

/// From the target to the user: data, end of data, exit status, close;
/// the answers to the relayed requests go to the handler.
#[allow(clippy::too_many_arguments)]
async fn target_to_user(
    mut target: russh::ChannelReadHalf,
    user: ChannelWriteHalf<Msg>,
    handle: russh::server::Handle,
    id: ChannelId,
    replies: mpsc::Sender<bool>,
    count: Arc<AtomicU64>,
    observer: Arc<dyn SessionObserver>,
    session: [u8; 16],
) {
    while let Some(message) = target.wait().await {
        let sent = match message {
            ChannelMsg::Data { data } => {
                count.fetch_add(data.len() as u64, Ordering::Relaxed);
                observer.target_data(&session, &data);
                user.data_bytes(data).await
            }
            ChannelMsg::ExtendedData { data, ext } => {
                count.fetch_add(data.len() as u64, Ordering::Relaxed);
                observer.target_data(&session, &data);
                user.extended_data_bytes(ext, data).await
            }
            ChannelMsg::Eof => user.eof().await,
            ChannelMsg::ExitStatus { exit_status } => user.exit_status(exit_status).await,
            ChannelMsg::ExitSignal {
                signal_name,
                core_dumped,
                error_message,
                lang_tag,
            } => {
                let _ = handle
                    .exit_signal_request(id, signal_name, core_dumped, error_message, lang_tag)
                    .await;
                Ok(())
            }
            ChannelMsg::Success => {
                let _ = replies.send(true).await;
                Ok(())
            }
            ChannelMsg::Failure => {
                let _ = replies.send(false).await;
                Ok(())
            }
            ChannelMsg::Close => break,
            _ => Ok(()),
        };
        if sent.is_err() {
            break;
        }
    }
    let _ = user.close().await;
}

fn env_allowed(name: &str, value: &str) -> bool {
    let name_ok = name == "LANG"
        || name.strip_prefix("LC_").is_some_and(|rest| {
            !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
        });
    name_ok && value.len() <= MAX_ENV_VALUE && !value.chars().any(char::is_control)
}

#[allow(
    clippy::unused_async_trait_impl,
    reason = "the SSH handler methods are async by trait"
)]
impl<A: Authorizer> russh::server::Handler for Handler<A> {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        user: &str,
        _key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        self.auth_refused(&SshError::BareKey, Some(user));
        Ok(Auth::reject())
    }

    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        certificate: &Certificate,
    ) -> Result<Auth, Self::Error> {
        self.conn.certificate_checked.store(true, Ordering::Relaxed);
        if *self.authenticated.borrow() {
            return Ok(Auth::reject());
        }
        Ok(self.authorize(user, certificate).await)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.relay.is_some() || !*self.authenticated.borrow() {
            self.channel_refused("deuxième canal de session");
            drop(reply);
            return Ok(());
        }
        self.open(channel, reply, session).await
    }

    async fn channel_open_x11(
        &mut self,
        _channel: Channel<Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channel_refused("x11");
        drop(reply);
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channel_refused("direct-tcpip");
        drop(reply);
        Ok(())
    }

    async fn channel_open_forwarded_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channel_refused("forwarded-tcpip");
        drop(reply);
        Ok(())
    }

    async fn channel_open_direct_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _socket_path: &str,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channel_refused("direct-streamlocal");
        drop(reply);
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let bounded = !term.is_empty()
            && term.len() <= MAX_TERM
            && term.bytes().all(|b| b.is_ascii_graphic())
            && col_width <= MAX_CELLS
            && row_height <= MAX_CELLS
            && pix_width <= MAX_PIXELS
            && pix_height <= MAX_PIXELS;
        let allowed = self.relay.as_ref().is_some_and(|r| r.allow_pty);
        let Some(target) = self.relay(channel).filter(|_| bounded && allowed) else {
            self.channel_refused(if allowed { "pty hors bornes" } else { "pty" });
            return session.channel_failure(channel);
        };
        if target
            .request_pty(
                true, term, col_width, row_height, pix_width, pix_height, modes,
            )
            .await
            .is_err()
        {
            return session.channel_failure(channel);
        }
        self.answer(channel, session).await
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(target) = self.relay(channel) else {
            return session.channel_failure(channel);
        };
        if target.request_shell(true).await.is_err() {
            return session.channel_failure(channel);
        }
        self.answer(channel, session).await
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(target) = self.relay(channel) else {
            return session.channel_failure(channel);
        };
        if data.len() > MAX_COMMAND {
            self.channel_refused("commande de plus de 32 Kio");
            return session.channel_failure(channel);
        }
        tracing::info!(
            event = "ssh.exec",
            session = %format_uuid(&self.session_id),
            peer = %self.peer,
            listener = %self.listener,
            length = data.len(),
            sha256 = %hex(&ostena_crypto::sha256::digest(data)),
            "commande transmise à la cible"
        );
        if target.exec(true, data).await.is_err() {
            return session.channel_failure(channel);
        }
        self.answer(channel, session).await
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(target) = self
            .relay(channel)
            .filter(|_| env_allowed(variable_name, variable_value))
        else {
            return session.channel_failure(channel);
        };
        if target
            .set_env(true, variable_name, variable_value)
            .await
            .is_err()
        {
            return session.channel_failure(channel);
        }
        self.answer(channel, session).await
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let bounded = col_width <= MAX_CELLS
            && row_height <= MAX_CELLS
            && pix_width <= MAX_PIXELS
            && pix_height <= MAX_PIXELS;
        if let Some(target) = self.relay(channel).filter(|_| bounded) {
            let _ = target
                .window_change(col_width, row_height, pix_width, pix_height)
                .await;
        }
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(target) = self.relay(channel) {
            let _ = target.signal(signal).await;
        }
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channel_refused(&format!("sous-système {name}"));
        session.channel_failure(channel)
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _single_connection: bool,
        _x11_auth_protocol: &str,
        _x11_auth_cookie: &str,
        _x11_screen_number: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channel_refused("x11");
        session.channel_failure(channel)
    }

    async fn agent_request(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.channel_refused("agent");
        Ok(false)
    }

    async fn tcpip_forward(
        &mut self,
        _address: &str,
        _port: &mut u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.channel_refused("tcpip-forward");
        Ok(false)
    }

    async fn streamlocal_forward(
        &mut self,
        _socket_path: &str,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.channel_refused("streamlocal-forward");
        Ok(false)
    }
}

/// Unregisters a session from `live` when dropped.
struct Registered<'a, A> {
    shared: &'a Shared<A>,
    id: u64,
}

impl<A> Drop for Registered<'_, A> {
    fn drop(&mut self) {
        if let Ok(mut live) = self.shared.live.lock() {
            live.remove(&self.id);
        }
    }
}

/// A connection not yet authenticated: the global permit and the count of
/// its source address, both released when dropped.
struct PreAuth<A> {
    shared: Arc<Shared<A>>,
    source: std::net::IpAddr,
    _permit: OwnedSemaphorePermit,
}

impl<A> Drop for PreAuth<A> {
    fn drop(&mut self) {
        if let Ok(mut sources) = self.shared.sources.lock()
            && let Some(count) = sources.get_mut(&self.source)
        {
            *count -= 1;
            if *count == 0 {
                sources.remove(&self.source);
            }
        }
    }
}

/// Takes a slot for a connection not yet authenticated: within the global
/// bound and the bound per source address.
fn pre_auth<A: Authorizer>(
    shared: &Arc<Shared<A>>,
    peer: SocketAddr,
    listener: SocketAddr,
) -> Option<PreAuth<A>> {
    let Ok(permit) = shared.unauthenticated.clone().try_acquire_owned() else {
        limited(peer, listener, "connexions non authentifiées");
        return None;
    };
    let source = peer.ip().to_canonical();
    {
        let mut sources = shared
            .sources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = sources.entry(source).or_insert(0);
        if *count >= shared.settings.max_unauthenticated_per_source {
            if *count == 0 {
                sources.remove(&source);
            }
            drop(sources);
            limited(
                peer,
                listener,
                "connexions non authentifiées depuis cette adresse",
            );
            return None;
        }
        *count += 1;
    }
    Some(PreAuth {
        shared: shared.clone(),
        source,
        _permit: permit,
    })
}

async fn disconnect(handle: &russh::server::Handle, why: &str) {
    let _ = handle
        .disconnect(Disconnect::ByApplication, why.to_owned(), "fr".to_owned())
        .await;
}

/// How long a disconnected connection may take to end while an
/// authorisation may still be in progress (the core answers within 5 s,
/// the scope control resolves within 5 s).
const AUTHORIZATION_DRAIN: Duration = Duration::from_secs(30);

#[allow(clippy::too_many_lines)]
async fn connection<A: Authorizer>(
    shared: Arc<Shared<A>>,
    tcp: TcpStream,
    peer: SocketAddr,
    mut stop: watch::Receiver<bool>,
) {
    let Ok(listener) = tcp.local_addr() else {
        return;
    };
    // The library sets it only on the sockets it accepts itself: without it,
    // Nagle and delayed acknowledgements stall the handshake.
    let _ = tcp.set_nodelay(true);
    let Some(unauthenticated) = pre_auth(&shared, peer, listener) else {
        return;
    };
    let Some(identity) = shared.identity.borrow().clone() else {
        let error = SshError::Identity("pas encore reçue du core".into());
        tracing::warn!(
            event = "ssh.connection_refused",
            code = error.code(),
            peer = %peer,
            listener = %listener,
            "{error}"
        );
        return;
    };
    let config = config::session_server(
        vec![identity.host_key.clone()],
        vec![identity.host_certificate.clone()],
        shared.settings.max_auth_attempts,
    );
    let conn = Arc::new(Conn::default());
    let (authenticated, mut is_authenticated) = watch::channel(false);
    let handler = Handler {
        shared: shared.clone(),
        conn: conn.clone(),
        identity,
        peer,
        listener,
        authenticated,
        target: None,
        relay: None,
        access: None,
        session_id: [0; 16],
    };
    let grace = tokio::time::Instant::now() + shared.settings.login_grace;
    let stream = Prechecked::new(
        tcp,
        Role::Server,
        peer.to_string(),
        shared.settings.precheck_timeout,
    );
    let Ok(Ok(session)) =
        tokio::time::timeout_at(grace, russh::server::run_stream(config, stream, handler)).await
    else {
        return;
    };
    let handle = session.handle();
    tokio::pin!(session);

    // Until authorised, within the grace delay.
    let mut ended = false;
    tokio::select! {
        _ = &mut session => ended = true,
        ok = async { is_authenticated.wait_for(|a| *a).await.is_ok() } => {
            if !ok {
                // The handler is gone: the session is ending.
                ended = tokio::time::timeout(CLOSE_TIMEOUT, &mut session).await.is_ok();
            }
        }
        () = tokio::time::sleep_until(grace) => {
            let error = SshError::Limit("délai d'authentification dépassé");
            tracing::warn!(
                event = "ssh.auth_refused",
                code = error.code(),
                peer = %peer,
                listener = %listener,
                "{error}"
            );
            disconnect(&handle, "délai d'authentification dépassé").await;
            // An authorisation in progress ends first: if it was granted,
            // its session is closed below like any other.
            ended = tokio::time::timeout(AUTHORIZATION_DRAIN, &mut session).await.is_ok();
        }
    }
    // Every granted access goes through the close below, exactly once,
    // whatever ended the connection.
    let granted = conn.authorized.lock().ok().and_then(|mut a| a.take());
    let registration = conn.live.lock().ok().and_then(|mut l| l.take());
    let _registered = registration.as_ref().map(|(id, _)| Registered {
        shared: &shared,
        id: *id,
    });
    let (Some((permit, request, authorized)), Some((_, mut revoked))) = (granted, registration)
    else {
        if !conn.certificate_checked.load(Ordering::Relaxed) {
            let error = SshError::UserCertificate(cert::CertError::Refused(
                "aucun certificat accepté par la bibliothèque SSH (expiré, pas encore valide, \
                 signature invalide) ou aucun présenté",
            ));
            tracing::warn!(
                event = "ssh.auth_refused",
                code = error.code(),
                peer = %peer,
                listener = %listener,
                "{error}"
            );
        }
        return;
    };
    drop(unauthenticated);
    let started = Instant::now();
    let deadline = tokio::time::Instant::now() + authorized.max_session;
    let session_text = format_uuid(&authorized.session_id);
    let reason = if ended {
        "fermée"
    } else {
        tokio::select! {
            // A revocation that arrived during the authorisation is seen here
            // at once.
            biased;
            () = async { let _ = revoked.wait_for(|r| *r).await; } => {
                tracing::warn!(
                    event = "ssh.session_revoked",
                    session = %session_text,
                    login_session = %format_uuid(&request.identity.login_session),
                    peer = %peer,
                    listener = %listener,
                    "session de connexion révoquée"
                );
                disconnect(&handle, "session de connexion révoquée").await;
                "révoquée"
            }
            _ = &mut session => {
                ended = true;
                "fermée"
            }
            () = tokio::time::sleep_until(deadline) => {
                tracing::warn!(
                    event = "ssh.session_expired",
                    session = %session_text,
                    peer = %peer,
                    listener = %listener,
                    "durée maximale de la session atteinte"
                );
                disconnect(&handle, "durée maximale de la session atteinte").await;
                "expirée"
            }
            () = async { let _ = stop.wait_for(|s| *s).await; } => {
                disconnect(&handle, "arrêt de l'agent").await;
                "arrêt"
            }
        }
    };
    if !ended {
        let _ = tokio::time::timeout(CLOSE_TIMEOUT, &mut session).await;
    }
    let target = conn.target.lock().ok().and_then(|mut t| t.take());
    if let Some(target) = target {
        target.close().await;
    }
    drop(permit);
    let summary = SessionSummary {
        session_id: authorized.session_id,
        subject: request.identity.subject,
        login_session: request.identity.login_session,
        account: request.account.clone(),
        resource: request.resource.clone(),
        bytes_to_target: conn.to_target.load(Ordering::Relaxed),
        bytes_from_target: conn.from_target.load(Ordering::Relaxed),
        reason,
        duration: started.elapsed(),
    };
    tracing::info!(
        event = "ssh.session_closed",
        session = %session_text,
        peer = %peer,
        listener = %listener,
        reason,
        bytes_to_target = summary.bytes_to_target,
        bytes_from_target = summary.bytes_from_target,
        duration_secs = summary.duration.as_secs(),
        "session SSH terminée"
    );
    shared.authorizer.closed(summary);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_replaces_control_and_format_characters() {
        assert_eq!(sanitize("root"), "root");
        assert_eq!(sanitize(r"CORP\Jean Dupont"), r"CORP\Jean Dupont");
        assert_eq!(sanitize("a\nb\tc\u{7f}"), "a?b?c?");
        // Bidirectional overrides and isolates, zero-width, BOM, tags.
        assert_eq!(
            sanitize("adm\u{202E}nimda\u{2066}x\u{2069}\u{200B}\u{FEFF}\u{E0041}"),
            "adm?nimda?x????"
        );
        assert_eq!(sanitize("é€日本"), "é€日本");
        assert_eq!(sanitize(&"x".repeat(100)).len(), 64);
    }
}
