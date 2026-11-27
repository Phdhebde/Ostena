//! Sessions of a Windows Remote Desktop server, through the WTS API
//! (ADR-0026): list the sessions of a target and log one off, from the
//! Windows agent, under the network credentials of the target account.
//!
//! - [`RemoteServer::open`] opens the server by its pinned address. With
//!   credentials, the calling thread first impersonates a
//!   `LOGON32_LOGON_NEW_CREDENTIALS` token: the credentials are used for
//!   the outbound authentication only (RPC over the named pipes of the
//!   target), never for a local logon of the agent.
//! - The impersonation is bound to the calling thread and reverted when the
//!   [`RemoteServer`] is dropped; [`RemoteServer`] is therefore neither
//!   `Send` nor `Sync`. Callers run it on a thread of their own, which ends
//!   with the work: a failed revert never leaks the identity to another task.
//! - Elsewhere than on Windows, every call fails with `AGT-E013`.

use std::marker::PhantomData;

use ostena_common::secret::SecretString;

use crate::error::{Code, PlatformError};

/// The state of a session (`WTS_CONNECTSTATE_CLASS`).
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
    /// The session waits for a client.
    Idle,
    /// The session listens for connections.
    Listen,
    /// The session is being reset.
    Reset,
    /// The session is down because of an error.
    Down,
    /// The session is initialising.
    Init,
    /// A value this version does not know.
    Unknown(i32),
}

impl SessionState {
    /// The state of a raw `WTS_CONNECTSTATE_CLASS` value.
    pub fn from_raw(value: i32) -> Self {
        match value {
            0 => Self::Active,
            1 => Self::Connected,
            2 => Self::ConnectQuery,
            3 => Self::Shadow,
            4 => Self::Disconnected,
            5 => Self::Idle,
            6 => Self::Listen,
            7 => Self::Reset,
            8 => Self::Down,
            9 => Self::Init,
            other => Self::Unknown(other),
        }
    }
}

/// One session of the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSession {
    /// Session identifier on the server.
    pub id: u32,
    /// State.
    pub state: SessionState,
    /// User logged on, empty when none.
    pub user: String,
    /// Domain of the user (the computer name for a local account).
    pub domain: String,
}

/// Network credentials of the target account.
pub struct NetworkCredentials<'a> {
    /// User name, or a user principal name (`user@realm`) without domain.
    pub user: &'a str,
    /// Domain (NetBIOS name, or the computer name for a local account).
    pub domain: Option<&'a str>,
    /// Password.
    pub password: &'a SecretString,
}

impl std::fmt::Debug for NetworkCredentials<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkCredentials")
            .field("user", &self.user)
            .field("domain", &self.domain)
            .field("password", &self.password.redacted())
            .finish()
    }
}

/// An open Remote Desktop server, under the given credentials.
pub struct RemoteServer {
    inner: imp::Server,
    /// Bound to the thread that impersonates.
    _thread: PhantomData<*const ()>,
}

impl std::fmt::Debug for RemoteServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteServer").finish_non_exhaustive()
    }
}

impl RemoteServer {
    /// Opens `server` (an address or a name; `None`: this machine), the
    /// calling thread impersonating `credentials` if given.
    ///
    /// # Errors
    ///
    /// `AGT-E013` when the credentials cannot be taken, or off Windows.
    pub fn open(
        server: Option<&str>,
        credentials: Option<&NetworkCredentials<'_>>,
    ) -> Result<Self, PlatformError> {
        Ok(Self {
            inner: imp::Server::open(server, credentials)?,
            _thread: PhantomData,
        })
    }

    /// The sessions of the server.
    ///
    /// # Errors
    ///
    /// `AGT-E013` when the server cannot be reached or refuses.
    pub fn sessions(&self) -> Result<Vec<RemoteSession>, PlatformError> {
        self.inner.sessions()
    }

    /// Logs session `id` off, waiting for the end of the logoff.
    ///
    /// # Errors
    ///
    /// `AGT-E013` when the server refuses or the session does not exist.
    pub fn logoff(&self, id: u32) -> Result<(), PlatformError> {
        self.inner.logoff(id)
    }
}

fn failure(what: &str, detail: impl std::fmt::Display) -> PlatformError {
    PlatformError::new(Code::RemoteSessions, format!("{what} : {detail}"))
}

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "WTS API, LogonUserW and impersonation; documented and tested"
)]
mod imp {
    use std::ffi::c_void;

    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
    use windows_sys::Win32::Security::{
        ImpersonateLoggedOnUser, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50,
        LogonUserW, RevertToSelf,
    };
    use windows_sys::Win32::System::RemoteDesktop::{
        WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFO_1W, WTSCloseServer, WTSEnumerateSessionsExW,
        WTSFreeMemoryExW, WTSLogoffSession, WTSOpenServerW, WTSTypeSessionInfoLevel1,
    };
    use zeroize::Zeroizing;

    use super::{NetworkCredentials, RemoteSession, SessionState, failure};
    use crate::error::PlatformError;

    /// Longest string read from a WTS structure, in UTF-16 units.
    const MAX_NAME: usize = 1024;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn last_error() -> u32 {
        // SAFETY: no precondition; reads the error code of this thread.
        unsafe { GetLastError() }
    }

    /// A string of a WTS structure: NUL-terminated UTF-16, or null.
    ///
    /// # Safety
    ///
    /// `ptr` is null or points to a NUL-terminated UTF-16 string, readable
    /// up to its NUL or `MAX_NAME` units.
    pub(super) unsafe fn from_wide(ptr: *const u16) -> String {
        if ptr.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        // SAFETY: by the contract, every unit up to the NUL is readable;
        // the scan stops at the NUL or at MAX_NAME.
        while len < MAX_NAME && unsafe { *ptr.add(len) } != 0 {
            len += 1;
        }
        // SAFETY: the `len` units scanned above are readable.
        let units = unsafe { std::slice::from_raw_parts(ptr, len) };
        String::from_utf16_lossy(units)
    }

    /// The thread impersonating a `NEW_CREDENTIALS` token.
    struct Impersonation {
        token: HANDLE,
    }

    impl Impersonation {
        #[expect(
            clippy::disallowed_methods,
            reason = "the password goes to LogonUserW in a zeroized buffer"
        )]
        fn start(credentials: &NetworkCredentials<'_>) -> Result<Self, PlatformError> {
            let user = wide(credentials.user);
            let domain = credentials.domain.map(wide);
            // SECRET-EXPOSURE: LogonUserW takes the password as UTF-16; the
            // copy is zeroized on drop.
            let secret = credentials.password.expose_secret();
            // Capacity for every unit and the NUL: no reallocation leaves a
            // copy of the password behind.
            let mut password = Zeroizing::new(Vec::<u16>::with_capacity(secret.len() + 1));
            password.extend(secret.encode_utf16().chain(std::iter::once(0)));
            let mut token: HANDLE = std::ptr::null_mut();
            // SAFETY: the three strings are NUL-terminated buffers alive for
            // the call (the domain may be null); `token` is a valid out
            // pointer.
            let ok = unsafe {
                LogonUserW(
                    user.as_ptr(),
                    domain.as_ref().map_or(std::ptr::null(), Vec::as_ptr),
                    password.as_ptr(),
                    LOGON32_LOGON_NEW_CREDENTIALS,
                    LOGON32_PROVIDER_WINNT50,
                    &raw mut token,
                )
            };
            if ok == 0 {
                return Err(failure(
                    "identifiants réseau du compte refusés (LogonUserW)",
                    last_error(),
                ));
            }
            // SAFETY: `token` is the valid token LogonUserW returned.
            if unsafe { ImpersonateLoggedOnUser(token) } == 0 {
                let code = last_error();
                // SAFETY: `token` is valid and owned here.
                unsafe { CloseHandle(token) };
                return Err(failure("emprunt d'identité impossible", code));
            }
            Ok(Self { token })
        }
    }

    impl Drop for Impersonation {
        fn drop(&mut self) {
            // SAFETY: no precondition; ends the impersonation of this
            // thread. A failure leaves the identity on this thread only,
            // which its owner ends (module documentation).
            if unsafe { RevertToSelf() } == 0 {
                tracing::error!(
                    code = last_error(),
                    "fin d'emprunt d'identité impossible : le fil s'arrête avec son travail"
                );
            }
            // SAFETY: `token` is valid and owned by this value.
            unsafe { CloseHandle(self.token) };
        }
    }

    /// Frees an enumeration.
    struct Enumeration {
        info: *mut WTS_SESSION_INFO_1W,
        count: u32,
    }

    impl Drop for Enumeration {
        fn drop(&mut self) {
            if !self.info.is_null() {
                // SAFETY: `info` and `count` are what WTSEnumerateSessionsExW
                // returned, freed once.
                unsafe {
                    WTSFreeMemoryExW(
                        WTSTypeSessionInfoLevel1,
                        self.info.cast::<c_void>().cast_const(),
                        self.count,
                    )
                };
            }
        }
    }

    pub(super) struct Server {
        handle: HANDLE,
        // Dropped after the handle is closed (fields drop after `drop`).
        _impersonation: Option<Impersonation>,
    }

    impl Server {
        pub(super) fn open(
            server: Option<&str>,
            credentials: Option<&NetworkCredentials<'_>>,
        ) -> Result<Self, PlatformError> {
            let impersonation = credentials.map(Impersonation::start).transpose()?;
            let handle = match server {
                None => WTS_CURRENT_SERVER_HANDLE,
                Some(name) => {
                    let name = wide(name);
                    // SAFETY: `name` is a NUL-terminated buffer alive for
                    // the call. An invalid handle shows on the next call.
                    unsafe { WTSOpenServerW(name.as_ptr()) }
                }
            };
            Ok(Self {
                handle,
                _impersonation: impersonation,
            })
        }

        pub(super) fn sessions(&self) -> Result<Vec<RemoteSession>, PlatformError> {
            let mut level = 1u32;
            let mut info: *mut WTS_SESSION_INFO_1W = std::ptr::null_mut();
            let mut count = 0u32;
            // SAFETY: `handle` comes from WTSOpenServerW (or is the current
            // server); the three out pointers are valid.
            let ok = unsafe {
                WTSEnumerateSessionsExW(
                    self.handle,
                    &raw mut level,
                    0,
                    &raw mut info,
                    &raw mut count,
                )
            };
            if ok == 0 {
                return Err(failure(
                    "liste des sessions de la cible impossible",
                    last_error(),
                ));
            }
            let enumeration = Enumeration { info, count };
            let len = usize::try_from(count).unwrap_or(0);
            if enumeration.info.is_null() || len == 0 {
                return Ok(Vec::new());
            }
            // SAFETY: the API returns `count` contiguous entries at `info`,
            // alive until `enumeration` frees them, after this function.
            let entries = unsafe { std::slice::from_raw_parts(enumeration.info, len) };
            Ok(entries
                .iter()
                .map(|e| RemoteSession {
                    id: e.SessionId,
                    state: SessionState::from_raw(e.State),
                    // SAFETY: the names of an entry are null or
                    // NUL-terminated strings owned by the enumeration.
                    user: unsafe { from_wide(e.pUserName) },
                    // SAFETY: as above.
                    domain: unsafe { from_wide(e.pDomainName) },
                })
                .collect())
        }

        pub(super) fn logoff(&self, id: u32) -> Result<(), PlatformError> {
            // SAFETY: `handle` comes from WTSOpenServerW (or is the current
            // server); TRUE waits for the end of the logoff.
            if unsafe { WTSLogoffSession(self.handle, id, 1) } == 0 {
                return Err(failure(
                    &format!("fermeture de la session {id} refusée"),
                    last_error(),
                ));
            }
            Ok(())
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            if self.handle != WTS_CURRENT_SERVER_HANDLE && !self.handle.is_null() {
                // SAFETY: a handle WTSOpenServerW returned, closed once.
                unsafe { WTSCloseServer(self.handle) };
            }
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::{NetworkCredentials, RemoteSession, failure};
    use crate::error::PlatformError;

    pub(super) struct Server;

    fn unsupported() -> PlatformError {
        failure(
            "sessions Bureau à distance",
            "API WTS disponible sur un agent Windows seulement",
        )
    }

    impl Server {
        pub(super) fn open(
            _: Option<&str>,
            _: Option<&NetworkCredentials<'_>>,
        ) -> Result<Self, PlatformError> {
            Err(unsupported())
        }

        #[allow(clippy::unused_self, reason = "same interface as on Windows")]
        pub(super) fn sessions(&self) -> Result<Vec<RemoteSession>, PlatformError> {
            Err(unsupported())
        }

        #[allow(clippy::unused_self, reason = "same interface as on Windows")]
        pub(super) fn logoff(&self, _: u32) -> Result<(), PlatformError> {
            Err(unsupported())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn states_are_mapped() {
        assert_eq!(SessionState::from_raw(0), SessionState::Active);
        assert_eq!(SessionState::from_raw(4), SessionState::Disconnected);
        assert_eq!(SessionState::from_raw(9), SessionState::Init);
        assert_eq!(SessionState::from_raw(42), SessionState::Unknown(42));
    }

    #[test]
    fn credentials_never_show_the_password() {
        let password = SecretString::from("hunter2-secret".to_owned());
        let credentials = NetworkCredentials {
            user: "admin",
            domain: Some("CORP"),
            password: &password,
        };
        assert!(!format!("{credentials:?}").contains("hunter2"));
    }

    #[cfg(not(windows))]
    #[test]
    fn unsupported_off_windows() {
        let error = RemoteServer::open(Some("192.0.2.1"), None).unwrap_err();
        assert_eq!(error.code, Code::RemoteSessions);
        assert!(error.to_string().starts_with("[AGT-E013]"));
    }

    #[cfg(windows)]
    #[test]
    #[allow(unsafe_code, reason = "test of the unsafe string reader")]
    fn from_wide_reads_up_to_the_nul_and_accepts_null() {
        let buffer: Vec<u16> = "ostena\0junk".encode_utf16().collect();
        // SAFETY: a NUL-terminated buffer alive for the call.
        assert_eq!(unsafe { imp::from_wide(buffer.as_ptr()) }, "ostena");
        // SAFETY: null is accepted.
        assert_eq!(unsafe { imp::from_wide(std::ptr::null()) }, "");
    }

    /// The sessions of this machine: the services session 0 at least, then
    /// the same under an impersonation (`NEW_CREDENTIALS` keeps the local
    /// identity), and a refused logoff of a session that does not exist.
    #[cfg(windows)]
    #[test]
    fn local_sessions_listed_and_bad_logoff_refused() {
        let local = RemoteServer::open(None, None).unwrap();
        let sessions = local.sessions().unwrap();
        assert!(sessions.iter().any(|s| s.id == 0), "{sessions:?}");
        let error = local.logoff(0xFFFF_FFF0).unwrap_err();
        assert_eq!(error.code, Code::RemoteSessions);
        drop(local);

        let password = SecretString::from("not-checked-locally".to_owned());
        let credentials = NetworkCredentials {
            user: "ostena-nobody",
            domain: Some("."),
            password: &password,
        };
        let impersonated = RemoteServer::open(None, Some(&credentials)).unwrap();
        assert!(impersonated.sessions().unwrap().iter().any(|s| s.id == 0));
        drop(impersonated);
        // Reverted: the thread lists again under its own identity.
        let again = RemoteServer::open(None, None).unwrap().sessions().unwrap();
        assert!(again.iter().any(|s| s.id == 0));
    }
}
