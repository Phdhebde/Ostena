//! The Windows sessions of the target account (ADR-0026).
//!
//! [MS-RDPBCGR] gives the client no way to log its session off: the
//! Shutdown Request PDU is denied by the server as soon as a user is logged
//! on (3.3.5.4.1), and the end of the connection only disconnects the
//! session, which the next connection of the same account reattaches. The
//! agent therefore drives the sessions of the target outside RDP, through a
//! [`SessionControl`]:
//!
//! - **before** a session ([`before_session`]): every session of the
//!   account that is not live is logged off; a live session of the account
//!   (another connection) refuses the new one (`RDP-E018`); any failure
//!   refuses it (`RDP-E019`);
//! - **at the end** ([`after_session`]): the session the target named in
//!   its logon notification (Save Session Info PDU, [MS-RDPBCGR] 2.2.10.1)
//!   is logged off once disconnected; without that notification, every
//!   disconnected session of the account is.
//!
//! The work is blocking (RPC to the target) and runs on a thread of its own
//! ([`run`]): the Windows implementation impersonates the account on that
//! thread, which ends with the work.
//!
//! The channel that carries this management (RPC over the named pipes of
//! the target, that is SMB) is opened by the **DNS name** of the target,
//! for Kerberos, once [`verify_name`] has checked through the scope
//! control that the name resolves to the pinned address; NTLM is refused
//! on it unless the development mode and `ntlm_fallback` admit it, and the
//! target must require SMB signing ([`SessionControl::smb_signing`]).

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ostena_common::secret::SecretString;

use crate::error::RdpError;

/// How long the end of a session waits for the target to see it
/// disconnected.
pub const DISCONNECT_WAIT: Duration = Duration::from_secs(3);
/// Polling interval while waiting.
const POLL: Duration = Duration::from_millis(200);
/// Bound of each step of the SMB signing probe.
pub const SMB_TIMEOUT: Duration = Duration::from_secs(3);

/// The state of a session on the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// A user is logged on and a client is connected.
    Active,
    /// A client is connected, no user logged on yet.
    Connected,
    /// The session is being connected.
    ConnectQuery,
    /// The session is shadowing another one.
    Shadow,
    /// A user is logged on, no client is connected.
    Disconnected,
    /// Any other state (idle, listening, reset, down, initialising).
    Other,
}

impl SessionState {
    /// Whether a client holds the session: it is never logged off by the
    /// agent, and a live session of the account refuses a new one.
    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Connected | Self::ConnectQuery | Self::Shadow
        )
    }
}

/// One session of the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetSession {
    /// Identifier on the target.
    pub id: u32,
    /// State.
    pub state: SessionState,
    /// User logged on, empty when none.
    pub user: String,
    /// Domain of the user.
    pub domain: String,
}

/// An open view on the sessions of a target. Blocking.
pub trait SessionView {
    /// The sessions of the target.
    ///
    /// # Errors
    ///
    /// Why they cannot be listed.
    fn sessions(&mut self) -> Result<Vec<TargetSession>, String>;

    /// Logs session `id` off, waiting for the end of the logoff.
    ///
    /// # Errors
    ///
    /// Why it cannot be logged off.
    fn logoff(&mut self, id: u32) -> Result<(), String>;
}

/// What a view is opened with.
pub struct ViewRequest {
    /// The pinned address of the target (scope control, ADR-0005).
    pub address: IpAddr,
    /// The DNS name the view is opened by, checked by [`verify_name`] to
    /// resolve to `address`.
    pub server: String,
    /// Kerberos only: no view without a service ticket for the target.
    pub kerberos_required: bool,
    /// The account, as in `session_params`.
    pub account: String,
    /// Its password, for the network authentication of the view.
    pub password: SecretString,
}

impl std::fmt::Debug for ViewRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ViewRequest")
            .field("address", &self.address)
            .field("server", &self.server)
            .field("kerberos_required", &self.kerberos_required)
            .field("account", &self.account)
            .field("password", &self.password.redacted())
            .finish()
    }
}

/// An open view, and how it authenticated.
pub struct Opened {
    /// The view.
    pub view: Box<dyn SessionView>,
    /// A Kerberos service ticket was obtained for the target before the
    /// view was opened; `false`: Windows may have negotiated NTLM.
    pub kerberos: bool,
}

/// Why a view cannot be opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    /// Kerberos is required and impossible towards the target.
    Kerberos(String),
    /// Anything else (no mechanism, credentials, target unreachable).
    Failed(String),
}

/// Opens views on targets: the WTS API on a Windows agent.
pub trait SessionControl: Send + Sync + 'static {
    /// A view on the target of `request`, on the calling thread.
    ///
    /// # Errors
    ///
    /// [`OpenError`].
    fn open(&self, request: &ViewRequest) -> Result<Opened, OpenError>;

    /// Whether the target at `addr` (pinned address, port 445) requires SMB
    /// signing. Blocking.
    ///
    /// # Errors
    ///
    /// Why the answer could not be had.
    fn smb_signing(&self, addr: SocketAddr) -> Result<bool, String> {
        crate::smb::probe(addr, SMB_TIMEOUT)
    }
}

/// The control of a platform without a mechanism: always refuses.
#[derive(Debug, Default, Clone, Copy)]
pub struct Unsupported;

impl SessionControl for Unsupported {
    fn open(&self, _: &ViewRequest) -> Result<Opened, OpenError> {
        Err(OpenError::Failed(
            "aucun mécanisme de fermeture des sessions Windows sur cet agent \
             (API WTS : agent Windows seulement)"
                .into(),
        ))
    }

    fn smb_signing(&self, _: SocketAddr) -> Result<bool, String> {
        Err("aucun mécanisme de fermeture des sessions Windows sur cet agent".into())
    }
}

/// Resolves the DNS name of a target through the scope control: the
/// agent gives its [`ostena_scope::Scope`].
pub trait TargetNames: Send + Sync + 'static {
    /// The addresses `name` resolves to, every one admitted by the scope
    /// for `port`.
    ///
    /// # Errors
    ///
    /// The refusal of the scope (resolution, rule, floor).
    fn resolve<'a>(
        &'a self,
        name: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, String>> + Send + 'a>>;
}

impl<R: ostena_scope::Resolver + Send + Sync + 'static> TargetNames for ostena_scope::Scope<R> {
    fn resolve<'a>(
        &'a self,
        name: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, String>> + Send + 'a>> {
        Box::pin(async move {
            self.pin(name, port)
                .await
                .map(|pinned| pinned.addrs().iter().map(SocketAddr::ip).collect())
                .map_err(|e| e.to_string())
        })
    }
}

/// Checks that `name` (the DNS name of the target, `None` when it has
/// none) resolves through the scope control, for the SMB port, to the
/// pinned `address`; gives the name the view is opened by.
///
/// # Errors
///
/// [`RdpError::SessionChannel`] when the name is missing, the scope
/// refuses it, or `address` is not among its addresses.
pub async fn verify_name(
    names: &dyn TargetNames,
    name: Option<&str>,
    address: IpAddr,
) -> Result<String, RdpError> {
    let name = name.ok_or_else(|| {
        RdpError::SessionChannel(
            "cible sans nom DNS : la vue de ses sessions passe par Kerberos, \
             qui demande le nom"
                .into(),
        )
    })?;
    let addresses = names
        .resolve(name, crate::smb::PORT)
        .await
        .map_err(|e| RdpError::SessionChannel(format!("{name} : {e}")))?;
    if !addresses.contains(&address) {
        return Err(RdpError::SessionChannel(format!(
            "{name} résout vers {addresses:?}, pas vers l'adresse épinglée {address}"
        )));
    }
    Ok(name.to_owned())
}

/// Whether the target at `address` requires SMB signing, asked on a thread
/// of its own.
///
/// # Errors
///
/// [`RdpError::SessionCleanup`] when the answer could not be had.
pub async fn smb_signing(
    control: Arc<dyn SessionControl>,
    address: IpAddr,
) -> Result<bool, RdpError> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("ostena-rdp-smb".into())
        .spawn(move || {
            let _ = tx.send(control.smb_signing(SocketAddr::new(address, crate::smb::PORT)));
        })
        .map_err(|e| RdpError::SessionCleanup(format!("fil de travail : {e}")))?;
    rx.await
        .unwrap_or_else(|_| Err("fil de travail interrompu".into()))
        .map_err(RdpError::SessionCleanup)
}

/// The control of this platform: `WtsControl` on Windows, [`Unsupported`]
/// elsewhere.
pub fn platform_control() -> Arc<dyn SessionControl> {
    #[cfg(windows)]
    {
        Arc::new(WtsControl)
    }
    #[cfg(not(windows))]
    {
        Arc::new(Unsupported)
    }
}

/// The user and the domain the account names: `DOMAIN\user`, `user@realm`
/// (no NetBIOS domain known) or `user`.
pub fn split_account(account: &str) -> (Option<&str>, &str) {
    if let Some((domain, user)) = account.split_once('\\') {
        return (Some(domain), user);
    }
    if let Some((user, _)) = account.rsplit_once('@') {
        return (None, user);
    }
    (None, account)
}

/// Whether `session` belongs to `account`: same user name, and same domain
/// when the account names one (case-insensitive, as Windows). Without a
/// domain, a homonym of another domain matches too: the agent then logs
/// off a disconnected session too many, or refuses for a live one, never
/// the reverse.
pub fn belongs_to(session: &TargetSession, account: &str) -> bool {
    let (domain, user) = split_account(account);
    !session.user.is_empty()
        && session.user.to_lowercase() == user.to_lowercase()
        && domain.is_none_or(|d| session.domain.to_lowercase() == d.to_lowercase())
}

/// A session the agent logged off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoggedOff {
    /// Identifier on the target.
    pub id: u32,
    /// State before the logoff.
    pub state: SessionState,
}

/// Before a session: logs off the sessions of `account` that are not live.
///
/// # Errors
///
/// [`RdpError::SessionInUse`] when a session of the account is live;
/// [`RdpError::SessionCleanup`] when the sessions cannot be listed or one
/// cannot be logged off.
pub fn before_session(
    view: &mut dyn SessionView,
    account: &str,
) -> Result<Vec<LoggedOff>, RdpError> {
    let mine: Vec<TargetSession> = view
        .sessions()
        .map_err(RdpError::SessionCleanup)?
        .into_iter()
        .filter(|s| belongs_to(s, account))
        .collect();
    if let Some(live) = mine.iter().find(|s| s.state.is_live()) {
        return Err(RdpError::SessionInUse(live.id));
    }
    let mut done = Vec::with_capacity(mine.len());
    for session in &mine {
        view.logoff(session.id).map_err(RdpError::SessionCleanup)?;
        done.push(LoggedOff {
            id: session.id,
            state: session.state,
        });
    }
    if !done.is_empty()
        && let Some(left) = view
            .sessions()
            .map_err(RdpError::SessionCleanup)?
            .into_iter()
            .find(|s| belongs_to(s, account) && s.state == SessionState::Disconnected)
    {
        return Err(RdpError::SessionCleanup(format!(
            "session {} toujours déconnectée après sa fermeture",
            left.id
        )));
    }
    Ok(done)
}

/// At the end of a session: logs off the session `id` the target named
/// (or, unknown, every session of `account`) once it is no longer live,
/// waiting at most `wait`; `sleep` waits between two looks.
///
/// # Errors
///
/// [`RdpError::SessionCleanup`] when the sessions cannot be listed, one
/// cannot be logged off, or one is still live after `wait` (another
/// connection took it over): it is left alone.
pub fn after_session(
    view: &mut dyn SessionView,
    account: &str,
    id: Option<u32>,
    wait: Duration,
    sleep: &dyn Fn(Duration),
) -> Result<Vec<LoggedOff>, RdpError> {
    let started = Instant::now();
    let mut waited = Duration::ZERO;
    loop {
        let candidates: Vec<TargetSession> = view
            .sessions()
            .map_err(RdpError::SessionCleanup)?
            .into_iter()
            .filter(|s| belongs_to(s, account) && id.is_none_or(|id| s.id == id))
            .collect();
        let live = candidates.iter().find(|s| s.state.is_live()).map(|s| s.id);
        if live.is_some() && waited < wait && started.elapsed() < wait {
            sleep(POLL);
            waited += POLL;
            continue;
        }
        let mut done = Vec::new();
        for session in candidates.iter().filter(|s| !s.state.is_live()) {
            view.logoff(session.id).map_err(RdpError::SessionCleanup)?;
            done.push(LoggedOff {
                id: session.id,
                state: session.state,
            });
        }
        return match live {
            Some(id) => Err(RdpError::SessionCleanup(format!(
                "session {id} encore tenue par une autre connexion : laissée ouverte"
            ))),
            None => Ok(done),
        };
    }
}

/// Runs `work` on a view of the target of `request`, on a thread of its
/// own, and gives its result and whether the view authenticated with
/// Kerberos.
///
/// # Errors
///
/// [`RdpError::SessionChannelNtlm`] when Kerberos is required and
/// impossible; [`RdpError::SessionCleanup`] when the view cannot be opened
/// or the thread cannot start; [`RdpError::Internal`] when it panicked;
/// what `work` returned.
pub async fn run<T: Send + 'static>(
    control: Arc<dyn SessionControl>,
    request: ViewRequest,
    work: impl FnOnce(&mut dyn SessionView, &str) -> Result<T, RdpError> + Send + 'static,
) -> Result<(T, bool), RdpError> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("ostena-rdp-sessions".into())
        .spawn(move || {
            let result = control
                .open(&request)
                .map_err(|e| match e {
                    OpenError::Kerberos(m) => RdpError::SessionChannelNtlm(m),
                    OpenError::Failed(m) => RdpError::SessionCleanup(m),
                })
                .and_then(|mut opened| {
                    work(opened.view.as_mut(), &request.account).map(|t| (t, opened.kerberos))
                });
            let _ = tx.send(result);
        })
        .map_err(|e| RdpError::SessionCleanup(format!("fil de travail : {e}")))?;
    rx.await.unwrap_or(Err(RdpError::Internal))
}

/// The WTS API of a Windows agent (`ostena-platform`): the view is opened
/// by the verified DNS name of the target, the thread impersonating the
/// network credentials of the account, after a Kerberos service ticket
/// for the target was obtained (or attempted, when NTLM is admitted).
#[cfg(windows)]
#[derive(Debug, Default, Clone, Copy)]
pub struct WtsControl;

#[cfg(windows)]
mod wts {
    use ostena_platform::Code;
    use ostena_platform::wts::{self, Authentication, NetworkCredentials, RemoteServer};

    use super::{
        OpenError, Opened, SessionControl, SessionState, SessionView, TargetSession, ViewRequest,
        WtsControl,
    };

    struct View(RemoteServer);

    impl SessionView for View {
        fn sessions(&mut self) -> Result<Vec<TargetSession>, String> {
            Ok(self
                .0
                .sessions()
                .map_err(|e| e.to_string())?
                .into_iter()
                .map(|s| TargetSession {
                    id: s.id,
                    state: match s.state {
                        wts::SessionState::Active => SessionState::Active,
                        wts::SessionState::Connected => SessionState::Connected,
                        wts::SessionState::ConnectQuery => SessionState::ConnectQuery,
                        wts::SessionState::Shadow => SessionState::Shadow,
                        wts::SessionState::Disconnected => SessionState::Disconnected,
                        _ => SessionState::Other,
                    },
                    user: s.user,
                    domain: s.domain,
                })
                .collect())
        }

        fn logoff(&mut self, id: u32) -> Result<(), String> {
            self.0.logoff(id).map_err(|e| e.to_string())
        }
    }

    impl SessionControl for WtsControl {
        fn open(&self, request: &ViewRequest) -> Result<Opened, OpenError> {
            let (domain, _) = super::split_account(&request.account);
            let upn = request.account.contains('@') && domain.is_none();
            let user = if upn {
                request.account.as_str()
            } else {
                super::split_account(&request.account).1
            };
            // A local account of the target authenticates in the domain of
            // the target computer: the first label of its name.
            let local = request
                .server
                .split('.')
                .next()
                .map(str::to_ascii_uppercase);
            let domain = if upn {
                None
            } else {
                domain
                    .map(str::to_owned)
                    .or(local)
                    .or_else(|| Some(".".into()))
            };
            let credentials = NetworkCredentials {
                user,
                domain: domain.as_deref(),
                password: &request.password,
            };
            let authentication = if request.kerberos_required {
                Authentication::Kerberos
            } else {
                Authentication::KerberosOrNtlm
            };
            RemoteServer::open(Some(&request.server), Some(&credentials), authentication)
                .map(|s| Opened {
                    kerberos: s.kerberos(),
                    view: Box::new(View(s)),
                })
                .map_err(|e| match e.code {
                    Code::Kerberos => OpenError::Kerberos(e.to_string()),
                    _ => OpenError::Failed(e.to_string()),
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[derive(Default)]
    struct Fake {
        sessions: Vec<TargetSession>,
        logged_off: Vec<u32>,
        refuse_logoff: bool,
        /// Live sessions turn disconnected after this many looks.
        disconnect_after: Option<u32>,
        looks: u32,
        list_fails: bool,
    }

    fn session(id: u32, state: SessionState, user: &str, domain: &str) -> TargetSession {
        TargetSession {
            id,
            state,
            user: user.into(),
            domain: domain.into(),
        }
    }

    impl SessionView for Fake {
        fn sessions(&mut self) -> Result<Vec<TargetSession>, String> {
            if self.list_fails {
                return Err("RPC refusé".into());
            }
            self.looks += 1;
            if self.disconnect_after.is_some_and(|n| self.looks > n) {
                for s in &mut self.sessions {
                    if s.state == SessionState::Active {
                        s.state = SessionState::Disconnected;
                    }
                }
            }
            Ok(self.sessions.clone())
        }

        fn logoff(&mut self, id: u32) -> Result<(), String> {
            if self.refuse_logoff {
                return Err("accès refusé".into());
            }
            self.logged_off.push(id);
            self.sessions.retain(|s| s.id != id);
            Ok(())
        }
    }

    #[test]
    fn accounts_are_split_and_matched_without_case() {
        assert_eq!(split_account("CORP\\admin"), (Some("CORP"), "admin"));
        assert_eq!(split_account("admin@corp.example"), (None, "admin"));
        assert_eq!(split_account("admin"), (None, "admin"));
        let s = session(2, SessionState::Disconnected, "Admin", "corp");
        assert!(belongs_to(&s, "CORP\\admin"));
        assert!(belongs_to(&s, "admin"));
        assert!(belongs_to(&s, "ADMIN@corp.example"));
        assert!(!belongs_to(&s, "OTHER\\admin"));
        assert!(!belongs_to(&s, "admin2"));
        // A session without user (listener, services, logon screen).
        assert!(!belongs_to(&session(0, SessionState::Other, "", ""), ""));
    }

    #[test]
    fn before_logs_off_the_disconnected_sessions_of_the_account_only() {
        let mut view = Fake {
            sessions: vec![
                session(0, SessionState::Other, "", ""),
                session(2, SessionState::Disconnected, "admin", "SRV"),
                session(3, SessionState::Disconnected, "someone", "SRV"),
                session(4, SessionState::Other, "admin", "SRV"),
                session(65536, SessionState::Other, "", ""),
            ],
            ..Fake::default()
        };
        let done = before_session(&mut view, "admin").unwrap();
        assert_eq!(view.logged_off, vec![2, 4]);
        assert_eq!(
            done,
            vec![
                LoggedOff {
                    id: 2,
                    state: SessionState::Disconnected
                },
                LoggedOff {
                    id: 4,
                    state: SessionState::Other
                }
            ]
        );
        // Nothing to do: nothing logged off, one look only.
        let mut empty = Fake::default();
        assert_eq!(before_session(&mut empty, "admin").unwrap(), Vec::new());
        assert_eq!(empty.looks, 1);
    }

    #[test]
    fn before_refuses_when_the_account_is_live_and_touches_nothing() {
        for state in [
            SessionState::Active,
            SessionState::Connected,
            SessionState::ConnectQuery,
            SessionState::Shadow,
        ] {
            let mut view = Fake {
                sessions: vec![
                    session(2, SessionState::Disconnected, "admin", "SRV"),
                    session(5, state, "admin", "SRV"),
                ],
                ..Fake::default()
            };
            assert_eq!(
                before_session(&mut view, "admin"),
                Err(RdpError::SessionInUse(5))
            );
            assert_eq!(view.logged_off, Vec::<u32>::new());
        }
    }

    #[test]
    fn before_refuses_when_it_cannot_close() {
        let mut refused = Fake {
            sessions: vec![session(2, SessionState::Disconnected, "admin", "SRV")],
            refuse_logoff: true,
            ..Fake::default()
        };
        assert!(matches!(
            before_session(&mut refused, "admin"),
            Err(RdpError::SessionCleanup(_))
        ));
        let mut unreachable = Fake {
            list_fails: true,
            ..Fake::default()
        };
        assert!(matches!(
            before_session(&mut unreachable, "admin"),
            Err(RdpError::SessionCleanup(_))
        ));
    }

    /// A target that reports success but keeps the session.
    #[test]
    fn before_checks_the_sessions_are_gone() {
        struct Liar(Vec<TargetSession>);
        impl SessionView for Liar {
            fn sessions(&mut self) -> Result<Vec<TargetSession>, String> {
                Ok(self.0.clone())
            }
            fn logoff(&mut self, _: u32) -> Result<(), String> {
                Ok(())
            }
        }
        let mut view = Liar(vec![session(2, SessionState::Disconnected, "admin", "")]);
        assert!(matches!(
            before_session(&mut view, "admin"),
            Err(RdpError::SessionCleanup(_))
        ));
    }

    #[test]
    fn after_waits_for_the_disconnection_then_logs_off_its_session_only() {
        let slept = Cell::new(0u32);
        let sleep = |_: Duration| slept.set(slept.get() + 1);
        let mut view = Fake {
            sessions: vec![
                session(2, SessionState::Active, "admin", "SRV"),
                session(3, SessionState::Disconnected, "admin", "SRV"),
            ],
            disconnect_after: Some(2),
            ..Fake::default()
        };
        let done = after_session(&mut view, "admin", Some(2), DISCONNECT_WAIT, &sleep).unwrap();
        assert_eq!(view.logged_off, vec![2]);
        assert_eq!(done.len(), 1);
        assert_eq!(slept.get(), 2);
        // Already gone (the user logged off): nothing to do.
        let mut gone = Fake::default();
        assert_eq!(
            after_session(&mut gone, "admin", Some(2), DISCONNECT_WAIT, &sleep).unwrap(),
            Vec::new()
        );
    }

    #[test]
    fn after_without_the_session_id_logs_off_the_disconnected_sessions_of_the_account() {
        let mut view = Fake {
            sessions: vec![
                session(2, SessionState::Disconnected, "admin", "SRV"),
                session(3, SessionState::Disconnected, "other", "SRV"),
            ],
            ..Fake::default()
        };
        after_session(&mut view, "admin", None, DISCONNECT_WAIT, &|_| {}).unwrap();
        assert_eq!(view.logged_off, vec![2]);
    }

    #[test]
    fn after_leaves_a_session_another_connection_holds() {
        let mut view = Fake {
            sessions: vec![session(2, SessionState::Active, "admin", "SRV")],
            ..Fake::default()
        };
        let error = after_session(&mut view, "admin", Some(2), DISCONNECT_WAIT, &|_| {});
        assert!(matches!(error, Err(RdpError::SessionCleanup(_))));
        assert_eq!(view.logged_off, Vec::<u32>::new());
        assert!(view.looks > 1);
    }

    #[tokio::test]
    async fn run_reports_an_unsupported_platform() {
        let request = ViewRequest {
            address: IpAddr::from([192, 0, 2, 1]),
            server: "srv.corp.example".into(),
            kerberos_required: true,
            account: "admin".into(),
            password: SecretString::from("x".to_owned()),
        };
        assert!(!format!("{request:?}").contains("\"x\""));
        let error = run(Arc::new(Unsupported), request, |view, account| {
            before_session(view, account)
        })
        .await
        .unwrap_err();
        assert!(matches!(error, RdpError::SessionCleanup(_)), "{error}");
    }
}
