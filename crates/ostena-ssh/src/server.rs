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
//! **Bounds.** Connections not yet authenticated and authorisations in
//! flight are bounded (`SSH-E019`), a connection must authenticate within
//! `login_grace`. The sessions are those of the agent's
//! [`SessionManager`] (ADR-0018): a slot is reserved within the quotas of
//! the agent, of the user and of the resource before the core is asked
//! (`SSH-E019`, cause `SES-E001` to `SES-E003`), the identifier the core
//! gives must be unique (`SSH-E013`, cause `SES-E004`); a session ends at
//! its maximum length, at its idle delay (traffic from the user only), on a
//! revocation of its login session or on stop.
//!
//! **Channel.** One session channel; terminal (if the certificate allows
//! it, bounded), shell, command (32 KiB at most), window changes, signals
//! and `LANG`/`LC_*` are relayed. A command is logged by its length only:
//! secrets can appear in a command line; its text goes to the transcript,
//! and the core keeps a keyed hash of it (ADR-0016).
//!
//! **Functions of the right** (the rights bits of the grant, ADR-0010).
//! Without the transfer function, the `sftp` subsystem and the transfer
//! commands ([`transfer::classify`]) are refused; with it, the transfer is
//! noted in the transcript (`ssh.transfer_started`), the file operations of
//! an SFTP stream too, before they reach the target, but not the file
//! contents. Without the port forwarding function, `direct-tcpip` (`-L`,
//! `-W`, `ProxyJump`) is refused; with it, the channel is relayed to the
//! target, which opens the connection, and noted. Remote forwarding (`-R`,
//! under the port forwarding function), agent and X11 forwarding (under
//! their own) are asked of the target as the user asked them
//! (`ssh.forward_requested`); the channels the target then opens towards
//! the agent are relayed to the user only for what the target agreed to
//! (a port listened on, the agent, X11), at most [`MAX_FORWARDS`] at once,
//! each noted in the transcript before it is relayed; any other is refused
//! (`ssh.target_channel_refused`). Every refusal for lack of a function is
//! logged (`ssh.request_refused`, `SSH-E022`) and noted in the transcript;
//! other subsystems and Unix socket forwarding are refused
//! (`ssh.channel_refused`, `SSH-E017`).
//!
//! **Transcript** (ADR-0016). Every authorised access comes with its
//! [`Transcript`]: the start (terminal, command), the outputs of the target
//! and the window changes are recorded, an output **before** it reaches the
//! user. Fail closed: when the transcript can no longer reach the core, the
//! session is cut (`ssh.transcript_lost`, `SSH-E021`).
//!
//! Events: `ssh.connection_limited`, `ssh.connection_refused`,
//! `ssh.auth_refused`, `ssh.access_refused`, `ssh.session_opened`,
//! `ssh.exec`, `ssh.session_expired`, `ssh.session_idle`,
//! `ssh.session_revoked`, `ssh.session_closed`, `ssh.channel_refused`,
//! `ssh.transcript_lost`, `ssh.request_refused`, `ssh.transfer_started`,
//! `ssh.forward_requested`, `ssh.forward_opened`, `ssh.transfer_unreadable`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ostena_crypto::p256::VerifyingKey;
use ostena_scope::PinnedTarget;
use ostena_session::{
    Activity, Claim, Driver, EndReason as SessionEnd, Limits, Protocol, Session as ManagedSession,
    SessionError, SessionManager,
};
use russh::keys::{Certificate, PrivateKey};
use russh::server::{Auth, ChannelOpenHandle, Msg, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId, ChannelMsg, ChannelWriteHalf, Disconnect, Pty, Sig, client};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::task::JoinHandle;

use crate::cert::{self, UserIdentity, format_uuid};
use crate::config;
use crate::driver::{
    SshDriver, TargetChannel, TargetChannels, TargetParams, TargetSession, sec1_point,
};
use crate::error::SshError;
use crate::login::parse_login;
use crate::precheck::Role;
use crate::precheck::stream::Prechecked;
use crate::transcript::{Terminal, Transcript};
use crate::transfer::{self, Protocol as TransferProtocol, SftpObserver};
use ostena_grant::Rights;
use ostena_recorder::{EndReason, Exit, NoteKind};

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
/// Reason of a session cut because its transcript was lost.
const TRANSCRIPT_LOST: &str = "transcript perdu";
/// Reason of a session cut at its idle delay.
const IDLE: &str = "inactive";
/// Forwarded channels open at once on one connection, both ways.
const MAX_FORWARDS: usize = 8;
/// Ports the target listens on at once for one connection (`-R`).
const MAX_REMOTE: usize = 4;
/// Longest address of a remote forwarding.
const MAX_ADDRESS: usize = 255;
/// Longest X11 authentication protocol name or cookie relayed.
const MAX_X11_TEXT: usize = 128;
/// Longest text of a note built from what the client asked.
const MAX_LABEL: usize = 200;

/// How long the end of a transcript may take: a start and an end frame,
/// each waiting at most [`crate::transcript::SEND_TIMEOUT`], and the lock.
const END_TIMEOUT: Duration = Duration::from_secs(40);

/// Bounds and delays of the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerSettings {
    /// Authenticated sessions at once (the session manager built by
    /// [`SshServer::new`]).
    pub max_sessions: usize,
    /// Sessions of one user at once; `None`: only `max_sessions`.
    pub max_sessions_per_user: Option<usize>,
    /// Sessions towards one resource at once; `None`: only `max_sessions`.
    pub max_sessions_per_target: Option<usize>,
    /// A session without traffic from the user for this long is cut;
    /// `None`: never.
    pub idle_timeout: Option<Duration>,
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
            max_sessions_per_user: None,
            max_sessions_per_target: None,
            idle_timeout: None,
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

impl ServerSettings {
    /// The bounds of the session manager.
    pub fn limits(&self) -> Limits {
        Limits {
            max_per_user: self.max_sessions_per_user,
            max_per_target: self.max_sessions_per_target,
            idle_timeout: self.idle_timeout,
            ..Limits::new(self.max_sessions)
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

    /// The authorities the user certificates are checked against.
    pub fn user_authorities(&self) -> &[VerifyingKey] {
        &self.user_cas
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
    /// Its transcript, towards the core: no access without one.
    pub transcript: Transcript,
    /// The functions of the right, as the rights bits of the verified
    /// grant: transfers, forwarding (ADR-0010).
    pub rights: Rights,
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

struct Shared<A> {
    settings: ServerSettings,
    identity: watch::Receiver<Option<Arc<SshIdentity>>>,
    driver: SshDriver,
    authorizer: Arc<A>,
    unauthenticated: Arc<Semaphore>,
    sessions: SessionManager,
    authorizations: Arc<Semaphore>,
    sources: Mutex<HashMap<std::net::IpAddr, usize>>,
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
    /// `target_key`, deciding through `authorizer`, with its own session
    /// manager bounded by `settings`.
    pub fn new(
        settings: ServerSettings,
        identity: watch::Receiver<Option<Arc<SshIdentity>>>,
        target_key: Arc<PrivateKey>,
        authorizer: Arc<A>,
    ) -> Self {
        let sessions = SessionManager::new(settings.limits(), Vec::new());
        Self::with_sessions(settings, sessions, identity, target_key, authorizer)
    }

    /// As [`new`](Self::new), the sessions held in `sessions`, the manager
    /// of the agent shared with the other protocols (its bounds apply, not
    /// those of `settings`).
    pub fn with_sessions(
        settings: ServerSettings,
        sessions: SessionManager,
        identity: watch::Receiver<Option<Arc<SshIdentity>>>,
        target_key: Arc<PrivateKey>,
        authorizer: Arc<A>,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                settings,
                identity,
                driver: SshDriver::new(target_key),
                authorizer,
                unauthenticated: Arc::new(Semaphore::new(settings.max_unauthenticated)),
                sessions,
                authorizations: Arc::new(Semaphore::new(settings.max_authorizations)),
                sources: Mutex::new(HashMap::new()),
            }),
        }
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
        self.shared.sessions.cut_where(
            |s| s.claim.protocol == Protocol::Ssh && s.claim.login_session == login_session,
            SessionEnd::Revoked,
        )
    }

    /// Cuts every SSH session, authorised or being authorised, as a
    /// revocation does (a revocation may have been lost); returns how many.
    pub fn revoke_all(&self) -> usize {
        self.shared
            .sessions
            .cut_where(|s| s.claim.protocol == Protocol::Ssh, SessionEnd::Revoked)
    }

    /// Authenticated SSH sessions now.
    pub fn sessions(&self) -> usize {
        self.shared
            .sessions
            .count(|s| s.claim.protocol == Protocol::Ssh && s.session_id.is_some())
    }

    /// SSH sessions authorised or being authorised, until their end is
    /// handed to [`Authorizer::closed`]: what a stop waits for.
    pub fn in_progress(&self) -> usize {
        self.shared
            .sessions
            .count(|s| s.claim.protocol == Protocol::Ssh)
    }
}

/// What the handler tells the connection task.
#[derive(Default)]
struct Conn {
    /// Set once authorised: the session in the manager and what was
    /// authorised.
    authorized: Mutex<Option<(ManagedSession, AccessRequest, Authorized)>>,
    /// The target, once connected.
    target: Mutex<Option<Arc<TargetSession>>>,
    /// A certificate reached our checks (the library refuses an expired
    /// one or a bad signature before them, without telling).
    certificate_checked: AtomicBool,
    to_target: Arc<AtomicU64>,
    from_target: Arc<AtomicU64>,
    /// Forwarded channels open.
    forwards: Arc<AtomicUsize>,
}

struct Relay {
    id: ChannelId,
    target: Arc<ChannelWriteHalf<client::Msg>>,
    replies: mpsc::Receiver<bool>,
    allow_pty: bool,
    /// Outputs of the target recorded (not in a transfer: they are file
    /// contents or protocol).
    record_data: Arc<AtomicBool>,
    /// The SFTP observer of a transfer, fed by the relay to the target.
    observer: Arc<Mutex<Option<SftpObserver>>>,
}

/// What the target agreed to open towards the user, under the functions of
/// the right: the channels it opens are relayed only for these.
struct Inbound {
    session_id: [u8; 16],
    peer: SocketAddr,
    listener: SocketAddr,
    transcript: Transcript,
    /// The user's connection, known at its first request.
    user: Mutex<Option<russh::server::Handle>>,
    /// Ports the target listens on for the user (`-R`), as asked.
    remote: Mutex<Vec<(String, u32)>>,
    agent: AtomicBool,
    x11: AtomicBool,
    forwards: Arc<AtomicUsize>,
    to_target: Arc<AtomicU64>,
    from_target: Arc<AtomicU64>,
}

impl std::fmt::Debug for Inbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inbound")
            .field("session", &format_uuid(&self.session_id))
            .finish_non_exhaustive()
    }
}

impl Inbound {
    fn set_user(&self, handle: russh::server::Handle) {
        if let Ok(mut user) = self.user.lock() {
            user.get_or_insert(handle);
        }
    }

    fn listens(&self, address: &str, port: u32) -> bool {
        self.remote
            .lock()
            .is_ok_and(|r| r.iter().any(|(a, p)| a == address && *p == port))
    }
}

/// Opens on the user's connection the channel matching `kind`.
async fn open_towards_user(
    user: &russh::server::Handle,
    kind: &TargetChannel,
) -> Result<Channel<Msg>, russh::Error> {
    match kind {
        TargetChannel::ForwardedTcpip {
            address,
            port,
            originator,
            originator_port,
        } => {
            user.channel_open_forwarded_tcpip(
                address.clone(),
                *port,
                originator.clone(),
                *originator_port,
            )
            .await
        }
        TargetChannel::Agent => user.channel_open_agent().await,
        TargetChannel::X11 {
            originator,
            originator_port,
        } => {
            user.channel_open_x11(originator.clone(), *originator_port)
                .await
        }
    }
}

impl TargetChannels for Inbound {
    fn offer(
        &self,
        kind: TargetChannel,
        channel: Channel<client::Msg>,
        reply: client::ChannelOpenHandle,
    ) -> Result<(), client::ChannelOpenHandle> {
        let (function, what) = match &kind {
            TargetChannel::ForwardedTcpip {
                address,
                port,
                originator,
                originator_port,
            } if self.listens(address, *port) => (
                "port-forwarding",
                format!(
                    "-R {}:{port} <- {}:{originator_port}",
                    sanitize(address),
                    sanitize(originator)
                ),
            ),
            TargetChannel::Agent if self.agent.load(Ordering::SeqCst) => {
                ("agent-forwarding", "agent channel".to_owned())
            }
            TargetChannel::X11 {
                originator,
                originator_port,
            } if self.x11.load(Ordering::SeqCst) => (
                "x11-forwarding",
                format!("x11 <- {}:{originator_port}", sanitize(originator)),
            ),
            _ => return Err(reply),
        };
        let Some(user) = self.user.lock().ok().and_then(|u| u.clone()) else {
            return Err(reply);
        };
        if self.forwards.fetch_add(1, Ordering::SeqCst) >= MAX_FORWARDS {
            self.forwards.fetch_sub(1, Ordering::SeqCst);
            limited(self.peer, self.listener, "redirections ouvertes");
            return Err(reply);
        }
        let transcript = self.transcript.clone();
        let forwards = self.forwards.clone();
        let to_target = self.to_target.clone();
        let from_target = self.from_target.clone();
        let (session, peer, listener) = (self.session_id, self.peer, self.listener);
        tokio::spawn(async move {
            // Noted before anything is relayed: refused if it cannot be.
            let opened = match transcript
                .note(NoteKind::Forward, &label(&format!("{function} {what}")))
                .await
            {
                Ok(()) => open_towards_user(&user, &kind)
                    .await
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
            let user_channel = match opened {
                Ok(c) => c,
                Err(e) => {
                    forwards.fetch_sub(1, Ordering::SeqCst);
                    reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
                    let error = SshError::Refused("canal de la cible non relayé");
                    tracing::warn!(
                        event = "ssh.channel_refused",
                        code = error.code(),
                        session = %format_uuid(&session),
                        peer = %peer,
                        listener = %listener,
                        kind = %what,
                        "{error} : {}",
                        sanitize(&e)
                    );
                    return;
                }
            };
            reply.accept().await;
            tracing::info!(
                event = "ssh.forward_opened",
                session = %format_uuid(&session),
                peer = %peer,
                listener = %listener,
                function,
                destination = %what,
                "canal ouvert par la cible relayé à l'utilisateur"
            );
            let (user_read, user_write) = user_channel.split();
            let (target_read, target_write) = channel.split();
            let to = tokio::spawn(pipe(user_read, target_write, to_target));
            let from = tokio::spawn(pipe(target_read, user_write, from_target));
            let _ = tokio::join!(to, from);
            forwards.fetch_sub(1, Ordering::SeqCst);
        });
        Ok(())
    }
}

/// A note text from what the client asked: printable ASCII and spaces,
/// anything else `?`, at most [`MAX_LABEL`] bytes.
fn label(text: &str) -> Vec<u8> {
    text.bytes()
        .take(MAX_LABEL)
        .map(|b| {
            if b.is_ascii_graphic() || b == b' ' {
                b
            } else {
                b'?'
            }
        })
        .collect()
}

/// Whether `rights` has the transfer function: both ways (the agent does
/// not enforce a direction).
fn allows_transfer(rights: Rights) -> bool {
    rights.contains(Rights::FILE_UPLOAD.with(Rights::FILE_DOWNLOAD))
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
    /// The terminal relayed, for the start of the transcript.
    terminal: Option<Terminal>,
    /// Marks the traffic of the user, for the idle delay.
    activity: Option<Activity>,
    /// What the target agreed to open towards the user.
    inbound: Option<Arc<Inbound>>,
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

    fn session_limited(&self, error: SessionError) {
        let what = match error {
            SessionError::UserLimit(_) => "sessions de cet utilisateur",
            SessionError::TargetLimit(_) => "sessions vers cette ressource",
            SessionError::ShuttingDown => "arrêt en cours",
            SessionError::AgentLimit(_) | SessionError::DuplicateId => "sessions",
        };
        let limit = SshError::Limit(what);
        tracing::warn!(
            event = "ssh.connection_limited",
            code = limit.code(),
            cause = error.code(),
            peer = %self.peer,
            listener = %self.listener,
            "{limit} : {error}"
        );
    }

    fn access_refused(&self, request: &AccessRequest, refusal: Refusal) {
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
    }

    /// The functions of the right of the authorised access (none before).
    fn rights(&self) -> Rights {
        self.access
            .as_ref()
            .map_or(Rights::NONE, |(_, authorized)| authorized.rights)
    }

    /// Refuses a request for lack of `function`: logged
    /// (`ssh.request_refused`, `SSH-E022`) and noted in the transcript.
    fn refuse_request(&self, function: &'static str, detail: &str) {
        let error = SshError::FunctionMissing(function);
        let text = label(&format!("{function} {detail}"));
        let noted = self
            .transcript()
            .is_some_and(|t| t.note_later(NoteKind::Refused, &text));
        tracing::warn!(
            event = "ssh.request_refused",
            code = error.code(),
            session = %format_uuid(&self.session_id),
            peer = %self.peer,
            listener = %self.listener,
            function,
            detail = sanitize(detail),
            noted,
            "{error}"
        );
    }

    /// What the target of `authorized` may open towards the user: nothing
    /// until the user asks and the target agrees.
    fn inbound_for(&self, authorized: &Authorized) -> Arc<Inbound> {
        Arc::new(Inbound {
            session_id: authorized.session_id,
            peer: self.peer,
            listener: self.listener,
            transcript: authorized.transcript.clone(),
            user: Mutex::new(None),
            remote: Mutex::new(Vec::new()),
            agent: AtomicBool::new(false),
            x11: AtomicBool::new(false),
            forwards: self.conn.forwards.clone(),
            to_target: self.conn.to_target.clone(),
            from_target: self.conn.from_target.clone(),
        })
    }

    /// A forwarding the target agreed to, for the user: noted and logged
    /// (`ssh.forward_requested`).
    fn forward_requested(&self, function: &'static str, detail: &str) {
        let noted = self.transcript().is_some_and(|t| {
            t.note_later(NoteKind::Forward, &label(&format!("{function} {detail}")))
        });
        tracing::info!(
            event = "ssh.forward_requested",
            session = %format_uuid(&self.session_id),
            peer = %self.peer,
            listener = %self.listener,
            function,
            detail = sanitize(detail),
            noted,
            "redirection acceptée par la cible"
        );
    }

    /// Starts the transcript of a transfer (`command` for an `exec`), notes
    /// it, and stops recording the outputs of the target; `false` if the
    /// transcript cannot be started.
    async fn start_transfer(&self, command: Option<&[u8]>, protocol: TransferProtocol) -> bool {
        if !self.start_transcript(command).await {
            return false;
        }
        let Some(transcript) = self.transcript() else {
            return false;
        };
        if let Err(e) = transcript
            .note(NoteKind::Transfer, protocol.name().as_bytes())
            .await
        {
            tracing::warn!(
                event = "ssh.transcript_lost",
                code = e.code(),
                session = %format_uuid(&self.session_id),
                peer = %self.peer,
                listener = %self.listener,
                "{e}"
            );
            return false;
        }
        if let Some(relay) = &self.relay {
            relay.record_data.store(false, Ordering::SeqCst);
            if protocol == TransferProtocol::Sftp
                && let Ok(mut observer) = relay.observer.lock()
            {
                *observer = Some(SftpObserver::new());
            }
        }
        tracing::info!(
            event = "ssh.transfer_started",
            session = %format_uuid(&self.session_id),
            peer = %self.peer,
            listener = %self.listener,
            protocol = protocol.name(),
            "transfert de fichiers (noms dans le transcript)"
        );
        true
    }

    /// The connection to the target: the one being made since the
    /// authorisation, or the one already made.
    async fn target_session(&mut self) -> Result<Arc<TargetSession>, SshError> {
        if let Some(target) = self.conn.target.lock().ok().and_then(|t| t.clone()) {
            return Ok(target);
        }
        let target = match self.target.take() {
            Some(join) => join
                .await
                .unwrap_or_else(|e| Err(SshError::TargetUnreachable(e.to_string())))?,
            None => return Err(SshError::Refused("aucune autorisation")),
        };
        let target = Arc::new(target);
        if let Ok(mut slot) = self.conn.target.lock() {
            *slot = Some(target.clone());
        }
        Ok(target)
    }

    /// Relays a `direct-tcpip` channel to the target, under the port
    /// forwarding function; noted, its bytes counted with the session.
    async fn forward(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        host: &str,
        port: u32,
        originator: (&str, u32),
    ) {
        let what = format!("{}:{port}", sanitize(host));
        if !self.rights().contains(Rights::SSH_PORT_FORWARDING) {
            self.refuse_request("port-forwarding", &what);
            drop(reply);
            return;
        }
        if self.conn.forwards.fetch_add(1, Ordering::SeqCst) >= MAX_FORWARDS {
            self.conn.forwards.fetch_sub(1, Ordering::SeqCst);
            limited(self.peer, self.listener, "redirections ouvertes");
            drop(reply);
            return;
        }
        let opened = match self.target_session().await {
            Ok(target) => {
                target
                    .open_direct_tcpip(host, port, originator.0, originator.1)
                    .await
            }
            Err(e) => Err(e),
        };
        let target_channel = match opened {
            Ok(c) => c,
            Err(e) => {
                self.conn.forwards.fetch_sub(1, Ordering::SeqCst);
                self.channel_refused(&format!("direct-tcpip {what} : {e}"));
                reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
                return;
            }
        };
        if let Some(transcript) = self.transcript() {
            transcript.note_later(
                NoteKind::Forward,
                &label(&format!("port-forwarding {what}")),
            );
        }
        reply.accept().await;
        tracing::info!(
            event = "ssh.forward_opened",
            session = %format_uuid(&self.session_id),
            peer = %self.peer,
            listener = %self.listener,
            function = "port-forwarding",
            destination = %what,
            "redirection de port relayée à la cible"
        );
        let (user_read, user_write) = channel.split();
        let (target_read, target_write) = target_channel.split();
        let forwards = self.conn.forwards.clone();
        let to = tokio::spawn(pipe(user_read, target_write, self.conn.to_target.clone()));
        let from = tokio::spawn(pipe(target_read, user_write, self.conn.from_target.clone()));
        tokio::spawn(async move {
            let _ = tokio::join!(to, from);
            forwards.fetch_sub(1, Ordering::SeqCst);
        });
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
        // The slot is reserved while the authoriser decides: a revocation
        // of the login session arriving before the decision is not lost.
        let reservation = match self.shared.sessions.reserve(Claim {
            protocol: Protocol::Ssh,
            subject: identity.subject,
            login_session: identity.login_session,
            target: Arc::from(login.resource),
        }) {
            Ok(reservation) => reservation,
            Err(error) => {
                self.session_limited(error);
                return Auth::reject();
            }
        };
        let request = AccessRequest {
            identity,
            account: login.account.to_owned(),
            resource: login.resource.to_owned(),
            client_address: self.peer,
        };
        let authorized = match self.shared.authorizer.authorize(request.clone()).await {
            Ok(authorized) => authorized,
            Err(refusal) => {
                self.access_refused(&request, refusal);
                return Auth::reject();
            }
        };
        let session = match reservation.activate(authorized.session_id, authorized.max_session) {
            Ok(session) => session,
            Err(error) => {
                let refusal = Refusal {
                    code: error.code().to_owned(),
                    message: error.to_string(),
                };
                self.access_refused(&request, refusal);
                return Auth::reject();
            }
        };
        self.session_id = authorized.session_id;
        self.activity = Some(session.activity());
        // Eagerly: the target is reached while the client opens its channel.
        let shared = self.shared.clone();
        let target = authorized.target.clone();
        let inbound = self.inbound_for(&authorized);
        self.inbound = Some(inbound.clone());
        let params = TargetParams {
            channels: Some(inbound),
            host_key: authorized.target_host_key,
            account: authorized.account.clone(),
            label: format!(
                "{}@{}",
                sanitize(&authorized.account),
                sanitize(&request.resource)
            ),
        };
        self.target = Some(tokio::spawn(async move {
            shared
                .driver
                .connect(&target, params, shared.settings.target_connect_timeout)
                .await
        }));
        self.access = Some((request.clone(), authorized.clone()));
        if let Ok(mut slot) = self.conn.authorized.lock() {
            *slot = Some((session, request, authorized));
        }
        self.authenticated.send_replace(true);
        Auth::Accept
    }

    /// Relays a request to the target and its answer to the user.
    async fn answer(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        if self.replied().await {
            session.channel_success(channel)
        } else {
            session.channel_failure(channel)
        }
    }

    /// The answer of the target to the request just relayed on the session
    /// channel; `false` without one in [`REPLY_TIMEOUT`].
    async fn replied(&mut self) -> bool {
        match &mut self.relay {
            Some(relay) => matches!(
                tokio::time::timeout(REPLY_TIMEOUT, relay.replies.recv()).await,
                Ok(Some(true))
            ),
            None => false,
        }
    }

    fn transcript(&self) -> Option<Transcript> {
        self.access.as_ref().map(|(_, a)| a.transcript.clone())
    }

    /// Records the start of the shell or of `command` before it is relayed;
    /// `false` if it cannot be (lost, or already started).
    async fn start_transcript(&self, command: Option<&[u8]>) -> bool {
        let Some(transcript) = self.transcript() else {
            return false;
        };
        match transcript.start(self.terminal.as_ref(), command).await {
            Ok(()) => true,
            Err(e) => {
                // Lost: the session is cut (`SSH-E021`); otherwise only this
                // request is refused.
                let event = if matches!(e, SshError::TranscriptLost(_)) {
                    "ssh.transcript_lost"
                } else {
                    "ssh.channel_refused"
                };
                tracing::warn!(
                    event,
                    code = e.code(),
                    session = %format_uuid(&self.session_id),
                    peer = %self.peer,
                    listener = %self.listener,
                    "{e}"
                );
                false
            }
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
        let opened = match self.target_session().await {
            Ok(target) => target.open_session().await,
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
        let Some(transcript) = self.transcript() else {
            return Ok(());
        };
        let Some(activity) = self.activity.clone() else {
            return Ok(());
        };
        let record_data = Arc::new(AtomicBool::new(true));
        let observer = Arc::new(Mutex::new(None));
        tokio::spawn(user_to_target(
            user_read,
            target_write.clone(),
            self.conn.to_target.clone(),
            activity,
            Observed {
                observer: observer.clone(),
                transcript: transcript.clone(),
                session: self.session_id,
            },
        ));
        tokio::spawn(target_to_user(
            target_read,
            user_write,
            session.handle(),
            id,
            replies_tx,
            self.conn.from_target.clone(),
            transcript,
            record_data.clone(),
        ));
        self.relay = Some(Relay {
            id,
            target: target_write,
            replies,
            allow_pty,
            record_data,
            observer,
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

/// What the relay to the target observes in a transfer.
struct Observed {
    observer: Arc<Mutex<Option<SftpObserver>>>,
    transcript: Transcript,
    session: [u8; 16],
}

impl Observed {
    /// Notes the file operations `data` completes, before it is relayed;
    /// `false` if the stream cannot be followed or the transcript is lost:
    /// the relay stops (and the session ends).
    async fn note(&self, data: &[u8]) -> bool {
        let mut seen = Vec::new();
        let fed = match self.observer.lock() {
            Ok(mut observer) => match observer.as_mut() {
                Some(observer) => observer.feed(data, &mut seen),
                None => return true,
            },
            Err(_) => return false,
        };
        if let Err(e) = fed {
            let error = SshError::TransferUnreadable(e.to_string());
            tracing::warn!(
                event = "ssh.transfer_unreadable",
                code = error.code(),
                session = %format_uuid(&self.session),
                "{error}"
            );
            return false;
        }
        for operation in seen {
            if let Err(e) = self.transcript.note(operation.kind, &operation.text).await {
                tracing::warn!(
                    event = "ssh.transcript_lost",
                    code = e.code(),
                    session = %format_uuid(&self.session),
                    "{e}"
                );
                return false;
            }
        }
        true
    }
}

/// From the user to the target: data, end of data, close. Keystrokes are
/// not recorded (ADR-0016); they are the traffic of the idle delay. The file
/// operations of an SFTP transfer are
/// noted before they are relayed.
async fn user_to_target(
    mut user: russh::ChannelReadHalf,
    target: Arc<ChannelWriteHalf<client::Msg>>,
    count: Arc<AtomicU64>,
    activity: Activity,
    observed: Observed,
) {
    while let Some(message) = user.wait().await {
        let sent = match message {
            ChannelMsg::Data { data } => {
                activity.touch();
                if !observed.note(&data).await {
                    let _ = target.close().await;
                    break;
                }
                count.fetch_add(data.len() as u64, Ordering::Relaxed);
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

/// One way of a forwarded channel: data, end of data, close; counted, not
/// recorded.
async fn pipe<S>(mut from: russh::ChannelReadHalf, to: ChannelWriteHalf<S>, count: Arc<AtomicU64>)
where
    S: From<(ChannelId, ChannelMsg)> + Send + Sync + 'static,
{
    while let Some(message) = from.wait().await {
        let sent = match message {
            ChannelMsg::Data { data } => {
                count.fetch_add(data.len() as u64, Ordering::Relaxed);
                to.data_bytes(data).await
            }
            ChannelMsg::Eof => to.eof().await,
            ChannelMsg::Close => break,
            _ => Ok(()),
        };
        if sent.is_err() {
            break;
        }
    }
    let _ = to.close().await;
}

/// The name of a signal as SSH carries it (`KILL`, not `SIGKILL`).
fn signal_name_of(signal: &Sig) -> String {
    match signal {
        Sig::ABRT => "ABRT".into(),
        Sig::ALRM => "ALRM".into(),
        Sig::FPE => "FPE".into(),
        Sig::HUP => "HUP".into(),
        Sig::ILL => "ILL".into(),
        Sig::INT => "INT".into(),
        Sig::KILL => "KILL".into(),
        Sig::PIPE => "PIPE".into(),
        Sig::QUIT => "QUIT".into(),
        Sig::SEGV => "SEGV".into(),
        Sig::TERM => "TERM".into(),
        Sig::USR1 => "USR1".into(),
        Sig::Custom(name) => name.clone(),
    }
}

/// From the target to the user: data, end of data, exit status, close;
/// the answers to the relayed requests go to the handler. Each output is
/// recorded before it is relayed; an output that cannot be recorded is not
/// relayed, and the relay stops (the session is cut by its transcript).
#[allow(clippy::too_many_arguments)]
async fn target_to_user(
    mut target: russh::ChannelReadHalf,
    user: ChannelWriteHalf<Msg>,
    handle: russh::server::Handle,
    id: ChannelId,
    replies: mpsc::Sender<bool>,
    count: Arc<AtomicU64>,
    transcript: Transcript,
    record_data: Arc<AtomicBool>,
) {
    while let Some(message) = target.wait().await {
        let sent = match message {
            ChannelMsg::Data { data } => {
                // In a transfer, the standard output is file contents or
                // protocol: noted, not recorded.
                if record_data.load(Ordering::SeqCst) && transcript.output(&data).await.is_err() {
                    break;
                }
                count.fetch_add(data.len() as u64, Ordering::Relaxed);
                user.data_bytes(data).await
            }
            ChannelMsg::ExtendedData { data, ext } => {
                if transcript.output(&data).await.is_err() {
                    break;
                }
                count.fetch_add(data.len() as u64, Ordering::Relaxed);
                user.extended_data_bytes(ext, data).await
            }
            ChannelMsg::Eof => user.eof().await,
            ChannelMsg::ExitStatus { exit_status } => {
                if transcript.exit(Exit::Status(exit_status)).await.is_err() {
                    break;
                }
                user.exit_status(exit_status).await
            }
            ChannelMsg::ExitSignal {
                signal_name,
                core_dumped,
                error_message,
                lang_tag,
            } => {
                let name = signal_name_of(&signal_name);
                if transcript
                    .exit(Exit::Signal { name, core_dumped })
                    .await
                    .is_err()
                {
                    break;
                }
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
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !*self.authenticated.borrow() {
            drop(reply);
            return Ok(());
        }
        self.forward(
            channel,
            reply,
            host_to_connect,
            port_to_connect,
            (originator_address, originator_port),
        )
        .await;
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
        self.terminal = Some(Terminal {
            term: term.to_owned(),
            cols: col_width,
            rows: row_height,
        });
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
        if !self.start_transcript(None).await {
            return session.channel_failure(channel);
        }
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
        let started = match transfer::classify(data) {
            transfer::Command::Transfer(protocol) if allows_transfer(self.rights()) => {
                self.start_transfer(Some(data), protocol).await
            }
            transfer::Command::Transfer(protocol) => {
                self.refuse_request("transfer", protocol.name());
                return session.channel_failure(channel);
            }
            transfer::Command::Mentions(tool) if !allows_transfer(self.rights()) => {
                self.refuse_request("transfer", tool);
                return session.channel_failure(channel);
            }
            transfer::Command::Mentions(_) | transfer::Command::Ordinary => {
                self.start_transcript(Some(data)).await
            }
        };
        if !started {
            return session.channel_failure(channel);
        }
        tracing::info!(
            event = "ssh.exec",
            session = %format_uuid(&self.session_id),
            peer = %self.peer,
            listener = %self.listener,
            length = data.len(),
            "commande transmise à la cible (texte dans le transcript)"
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
            if let Some(transcript) = self.transcript() {
                // Kept, recorded before the next output: the handler never
                // waits for the core.
                transcript.resize(col_width, row_height);
            }
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
        if name != "sftp" {
            self.channel_refused(&format!("sous-système {name}"));
            return session.channel_failure(channel);
        }
        if !allows_transfer(self.rights()) {
            self.refuse_request("transfer", "sftp");
            return session.channel_failure(channel);
        }
        let Some(target) = self.relay(channel) else {
            return session.channel_failure(channel);
        };
        if !self.start_transfer(None, TransferProtocol::Sftp).await {
            return session.channel_failure(channel);
        }
        if target.request_subsystem(true, "sftp").await.is_err() {
            return session.channel_failure(channel);
        }
        self.answer(channel, session).await
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        single_connection: bool,
        x11_auth_protocol: &str,
        x11_auth_cookie: &str,
        x11_screen_number: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.rights().contains(Rights::SSH_X11_FORWARDING) {
            self.refuse_request("x11-forwarding", "");
            return session.channel_failure(channel);
        }
        let (Some(target), Some(inbound)) = (self.relay(channel), self.inbound.clone()) else {
            return session.channel_failure(channel);
        };
        // Relayed as the client sent them: its cookie is a stand-in, which
        // the client checks and replaces on each X11 channel.
        let valid = x11_auth_protocol.len() <= MAX_X11_TEXT
            && x11_auth_cookie.len() <= MAX_X11_TEXT
            && x11_auth_protocol.bytes().all(|b| b.is_ascii_graphic())
            && x11_auth_cookie.bytes().all(|b| b.is_ascii_hexdigit());
        if !valid {
            self.channel_refused("x11 (paramètres invalides)");
            return session.channel_failure(channel);
        }
        inbound.set_user(session.handle());
        let sent = target
            .request_x11(
                true,
                single_connection,
                x11_auth_protocol,
                x11_auth_cookie,
                x11_screen_number,
            )
            .await;
        if sent.is_err() || !self.replied().await {
            self.channel_refused("x11 (refusé par la cible)");
            return session.channel_failure(channel);
        }
        inbound.x11.store(true, Ordering::SeqCst);
        self.forward_requested("x11-forwarding", &format!("screen {x11_screen_number}"));
        session.channel_success(channel)
    }

    async fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if !self.rights().contains(Rights::SSH_AGENT_FORWARDING) {
            self.refuse_request("agent-forwarding", "");
            return Ok(false);
        }
        let (Some(target), Some(inbound)) = (self.relay(channel), self.inbound.clone()) else {
            return Ok(false);
        };
        inbound.set_user(session.handle());
        if target.agent_forward(true).await.is_err() || !self.replied().await {
            self.channel_refused("agent (refusé par la cible)");
            return Ok(false);
        }
        inbound.agent.store(true, Ordering::SeqCst);
        self.forward_requested("agent-forwarding", "agent");
        Ok(true)
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let what = format!("-R {}:{port}", sanitize(address));
        if !self.rights().contains(Rights::SSH_PORT_FORWARDING) {
            self.refuse_request("port-forwarding", &what);
            return Ok(false);
        }
        let Some(inbound) = self.inbound.clone() else {
            return Ok(false);
        };
        if address.len() > MAX_ADDRESS || *port > u32::from(u16::MAX) {
            self.channel_refused(&format!("tcpip-forward {what} (invalide)"));
            return Ok(false);
        }
        if inbound
            .remote
            .lock()
            .map_or(true, |r| r.len() >= MAX_REMOTE)
        {
            limited(self.peer, self.listener, "redirections distantes");
            return Ok(false);
        }
        inbound.set_user(session.handle());
        let listening = match self.target_session().await {
            Ok(target) => target.tcpip_forward(address, *port).await,
            Err(e) => Err(e),
        };
        let listening = match listening {
            Ok(p) => p,
            Err(e) => {
                self.channel_refused(&format!("tcpip-forward {what} : {e}"));
                return Ok(false);
            }
        };
        *port = listening;
        if let Ok(mut remote) = inbound.remote.lock() {
            remote.push((address.to_owned(), listening));
        }
        self.forward_requested(
            "port-forwarding",
            &format!("-R {}:{listening}", sanitize(address)),
        );
        Ok(true)
    }

    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let Some(inbound) = self.inbound.clone() else {
            return Ok(false);
        };
        if !inbound.listens(address, port) {
            return Ok(false);
        }
        // No longer relayed, whatever the target answers.
        if let Ok(mut remote) = inbound.remote.lock() {
            remote.retain(|(a, p)| !(a == address && *p == port));
        }
        let cancelled = match self.target_session().await {
            Ok(target) => target.cancel_tcpip_forward(address, port).await.is_ok(),
            Err(_) => false,
        };
        Ok(cancelled)
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
        terminal: None,
        activity: None,
        inbound: None,
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
    let Some((mut managed, request, authorized)) = granted else {
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
    let session_text = format_uuid(&authorized.session_id);
    let transcript = authorized.transcript.clone();
    let reason = if ended {
        "fermée"
    } else {
        tokio::select! {
            // A revocation that arrived during the authorisation is seen here
            // at once.
            biased;
            end = managed.ended() => match end {
                SessionEnd::Revoked => {
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
                SessionEnd::Expired => {
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
                SessionEnd::Idle => {
                    tracing::warn!(
                        event = "ssh.session_idle",
                        session = %session_text,
                        peer = %peer,
                        listener = %listener,
                        "délai d'inactivité de la session atteint"
                    );
                    disconnect(&handle, "délai d'inactivité atteint").await;
                    IDLE
                }
                SessionEnd::Shutdown => {
                    disconnect(&handle, "arrêt de l'agent").await;
                    "arrêt"
                }
                SessionEnd::Closed | SessionEnd::Error => {
                    disconnect(&handle, "session coupée par l'agent").await;
                    "coupée"
                }
            },
            _ = &mut session => {
                ended = true;
                "fermée"
            }
            () = async { let _ = stop.wait_for(|s| *s).await; } => {
                disconnect(&handle, "arrêt de l'agent").await;
                "arrêt"
            }
            () = transcript.closed() => {
                let error = SshError::TranscriptLost("flux vers le core perdu".into());
                tracing::warn!(
                    event = "ssh.transcript_lost",
                    code = error.code(),
                    session = %session_text,
                    peer = %peer,
                    listener = %listener,
                    "{error}"
                );
                disconnect(&handle, "enregistrement de la session impossible").await;
                TRANSCRIPT_LOST
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
    // The transcript has no idle reason (ADR-0016): an idle session
    // reached a limit of the agent, as an expired one.
    let (end, managed_end) = match reason {
        "révoquée" => (EndReason::Revoked, SessionEnd::Revoked),
        "expirée" => (EndReason::Expired, SessionEnd::Expired),
        IDLE => (EndReason::Expired, SessionEnd::Idle),
        "arrêt" => (EndReason::Shutdown, SessionEnd::Shutdown),
        TRANSCRIPT_LOST | "coupée" => (EndReason::Error, SessionEnd::Error),
        _ => (EndReason::Closed, SessionEnd::Closed),
    };
    // Bounded: the permit and the report below are always given back.
    let ended = tokio::time::timeout(END_TIMEOUT, transcript.end(end))
        .await
        .unwrap_or_else(|_| {
            Err(SshError::TranscriptLost(
                "fin du transcript non transmise dans le délai".into(),
            ))
        });
    if let Err(e) = ended
        && reason != TRANSCRIPT_LOST
    {
        tracing::warn!(
            event = "ssh.transcript_lost",
            code = e.code(),
            session = %session_text,
            peer = %peer,
            listener = %listener,
            "{e}"
        );
    }
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
    // Released once its end is handed over: what a stop waits for.
    managed.finish(managed_end);
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
