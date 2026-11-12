//! Local control plane transport (ADR-0007): a Unix socket on Linux, a named
//! pipe on Windows, both reachable only by the service account and the
//! administrators.
//!
//! - Linux: socket in a directory accessible to the service account only
//!   (`RuntimeDirectory`, mode 0700), socket mode 0600; the server checks the
//!   caller's uid (`SO_PEERCRED`: root or the service account); the client
//!   checks that the socket and its directory belong to root or the service
//!   account before talking.
//! - Windows: the first instance is created with `FILE_FLAG_FIRST_PIPE_INSTANCE`
//!   (a name already taken refuses the start: squatting), remote clients are
//!   rejected, and the DACL grants access to SYSTEM, the Administrators, the
//!   owner and the service account only; the client checks that the server
//!   process is the `OstenaAgent` service before reading its answer.
//!
//! Messages: a 4-byte big-endian length, then at most 4 KiB, with a timeout.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Code, PlatformError};

/// Largest message.
pub const MAX_MESSAGE: usize = 4096;
/// Time allowed for one request or answer.
pub const IO_TIMEOUT: Duration = Duration::from_secs(1);

/// Default endpoint: the socket path (Linux) or pipe name (Windows).
#[cfg(windows)]
pub const DEFAULT_ENDPOINT: &str = r"\\.\pipe\ostena-agent";
/// Default endpoint: the socket path (Linux) or pipe name (Windows).
#[cfg(not(windows))]
pub const DEFAULT_ENDPOINT: &str = "/run/ostena/agent.sock";

/// A bidirectional local stream.
pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

fn io(what: &str, e: impl std::fmt::Display) -> PlatformError {
    PlatformError::new(Code::ControlIo, format!("{what} : {e}"))
}

/// Writes one message.
///
/// # Errors
///
/// `AGT-E008` for an oversized message, an I/O error or a timeout.
pub async fn write_message(
    stream: &mut (impl Duplex + ?Sized),
    message: &[u8],
) -> Result<(), PlatformError> {
    if message.len() > MAX_MESSAGE {
        return Err(io("message", "au-delà de 4 Kio"));
    }
    let len = u32::try_from(message.len()).map_err(|e| io("message", e))?;
    let write = async {
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(message).await?;
        stream.flush().await
    };
    tokio::time::timeout(IO_TIMEOUT, write)
        .await
        .map_err(|_| io("écriture", "délai dépassé"))?
        .map_err(|e| io("écriture", e))
}

/// Reads one message.
///
/// # Errors
///
/// `AGT-E008` for an oversized message, an I/O error or a timeout.
pub async fn read_message(stream: &mut (impl Duplex + ?Sized)) -> Result<Vec<u8>, PlatformError> {
    let read = async {
        let mut len = [0u8; 4];
        stream.read_exact(&mut len).await?;
        let len = u32::from_be_bytes(len) as usize;
        if len > MAX_MESSAGE {
            return Err(std::io::Error::other("message au-delà de 4 Kio"));
        }
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;
        Ok(buf)
    };
    tokio::time::timeout(IO_TIMEOUT, read)
        .await
        .map_err(|_| io("lecture", "délai dépassé"))?
        .map_err(|e| io("lecture", e))
}

/// Who the client expects behind the endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedServer {
    /// The installed agent service (production).
    Service,
    /// A given process (tests, foreground runs).
    Process(u32),
}

#[cfg(unix)]
pub use unix::{ControlListener, connect};
#[cfg(windows)]
pub(crate) use windows::Descriptor;
#[cfg(windows)]
pub use windows::{ControlListener, connect, sddl};

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    use tokio::net::{UnixListener, UnixStream};

    use super::{Duplex, ExpectedServer};
    use crate::error::{Code, PlatformError};
    use crate::service::SERVICE_USER;

    /// Effective uid, from the owner of `/proc/self` (no FFI).
    fn euid() -> u32 {
        std::fs::metadata("/proc/self").map_or(u32::MAX, |m| m.uid())
    }

    /// Uid of the service account, from `/etc/passwd`.
    fn service_uid() -> Option<u32> {
        let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
        passwd.lines().find_map(|l| {
            let mut fields = l.split(':');
            (fields.next() == Some(SERVICE_USER)).then(|| fields.nth(1)?.parse().ok())?
        })
    }

    fn trusted(uid: u32) -> bool {
        uid == 0 || uid == euid() || Some(uid) == service_uid()
    }

    /// The socket server.
    #[derive(Debug)]
    pub struct ControlListener {
        listener: UnixListener,
        path: PathBuf,
    }

    impl ControlListener {
        /// Binds the socket. Refuses when another agent already listens
        /// (`AGT-E006`) or when the directory is open to other accounts.
        ///
        /// # Errors
        ///
        /// `AGT-E006` or `AGT-E008`.
        pub fn bind(endpoint: &str) -> Result<Self, PlatformError> {
            let path = PathBuf::from(endpoint);
            let dir = path.parent().ok_or_else(|| {
                PlatformError::new(Code::ControlIo, "chemin de socket sans dossier")
            })?;
            if !dir.exists() {
                std::fs::create_dir_all(dir).map_err(|e| super::io("dossier du socket", e))?;
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                    .map_err(|e| super::io("dossier du socket", e))?;
            }
            let meta = std::fs::metadata(dir).map_err(|e| super::io("dossier du socket", e))?;
            if meta.mode() & 0o077 != 0 || !trusted(meta.uid()) {
                return Err(PlatformError::new(
                    Code::ControlNameTaken,
                    format!(
                        "{} doit appartenir au compte du service, en mode 0700",
                        dir.display()
                    ),
                ));
            }
            if path.exists() {
                if std::os::unix::net::UnixStream::connect(&path).is_ok() {
                    return Err(PlatformError::new(
                        Code::ControlNameTaken,
                        format!("{endpoint} : un autre agent écoute déjà"),
                    ));
                }
                std::fs::remove_file(&path).map_err(|e| super::io("ancien socket", e))?;
            }
            let listener = UnixListener::bind(&path).map_err(|e| super::io("socket", e))?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| super::io("socket", e))?;
            Ok(Self { listener, path })
        }

        /// Next caller allowed by its uid (root or the service account);
        /// others are dropped and logged (`agent.control_denied`).
        ///
        /// # Errors
        ///
        /// `AGT-E008` when accepting fails.
        pub async fn accept(&self) -> Result<Box<dyn Duplex>, PlatformError> {
            loop {
                let (stream, _) = self
                    .listener
                    .accept()
                    .await
                    .map_err(|e| super::io("connexion", e))?;
                match stream.peer_cred() {
                    Ok(cred) if trusted(cred.uid()) => return Ok(Box::new(stream)),
                    Ok(cred) => tracing::warn!(
                        event = "agent.control_denied",
                        uid = cred.uid(),
                        "appelant refusé"
                    ),
                    Err(e) => tracing::warn!(
                        event = "agent.control_denied",
                        "identité de l'appelant inconnue : {e}"
                    ),
                }
            }
        }
    }

    impl Drop for ControlListener {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// Connects after checking that the socket and its directory belong to
    /// root or the service account (`AGT-E007` otherwise).
    ///
    /// # Errors
    ///
    /// `AGT-E007` or `AGT-E008`.
    pub async fn connect(
        endpoint: &str,
        _expected: ExpectedServer,
    ) -> Result<Box<dyn Duplex>, PlatformError> {
        let path = Path::new(endpoint);
        for (what, p) in [("socket", path), ("dossier", path.parent().unwrap_or(path))] {
            let meta = std::fs::metadata(p).map_err(|e| super::io(what, e))?;
            if !trusted(meta.uid()) || (what == "dossier" && meta.mode() & 0o077 != 0) {
                return Err(PlatformError::new(
                    Code::ControlNotAuthentic,
                    format!(
                        "{} n'appartient pas au compte du service (uid {})",
                        p.display(),
                        meta.uid()
                    ),
                ));
            }
        }
        let stream = UnixStream::connect(path)
            .await
            .map_err(|e| super::io("connexion", e))?;
        Ok(Box::new(stream))
    }
}

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "pipe security descriptor and server identity; documented and tested"
)]
mod windows {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;
    use std::ptr::null_mut;

    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
    use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;

    use super::{Duplex, ExpectedServer};
    use crate::acl::{SERVICE_ACCOUNT, account_sid};
    use crate::error::{Code, PlatformError};

    const ERROR_ACCESS_DENIED: i32 = 5;
    const ERROR_PIPE_BUSY: i32 = 231;

    /// DACL of the pipe: SYSTEM, Administrators, owner (the server process)
    /// and the service account; protected from inheritance.
    pub fn sddl() -> String {
        let service = account_sid(SERVICE_ACCOUNT)
            .map(|s| format!("(A;;GA;;;{s})"))
            .unwrap_or_default();
        format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW){service}")
    }

    /// A security descriptor built from SDDL, freed on drop.
    pub(crate) struct Descriptor(PSECURITY_DESCRIPTOR);

    impl Descriptor {
        pub(crate) fn from_sddl(sddl: &str) -> Result<Self, PlatformError> {
            let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
            let mut sd: PSECURITY_DESCRIPTOR = null_mut();
            // SAFETY: `wide` is NUL-terminated and outlives the call; on
            // success `sd` receives a LocalAlloc'd descriptor freed by Drop.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    SDDL_REVISION_1,
                    &raw mut sd,
                    null_mut(),
                )
            };
            if ok == 0 {
                return Err(super::io(
                    "descripteur de sécurité",
                    std::io::Error::last_os_error(),
                ));
            }
            Ok(Self(sd))
        }

        /// The raw descriptor, valid while `self` lives.
        pub(crate) fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
            self.0
        }
    }

    impl Drop for Descriptor {
        fn drop(&mut self) {
            // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW, freed once.
            unsafe { LocalFree(self.0) };
        }
    }

    fn create(
        name: &str,
        first: bool,
        descriptor: &Descriptor,
    ) -> std::io::Result<NamedPipeServer> {
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        // SAFETY: `attributes` points to a valid SECURITY_ATTRIBUTES whose
        // descriptor (`descriptor`) outlives the call; Windows copies it.
        unsafe {
            ServerOptions::new()
                .first_pipe_instance(first)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(name, (&raw mut attributes).cast::<c_void>())
        }
    }

    /// The pipe server.
    pub struct ControlListener {
        name: String,
        descriptor: Descriptor,
        next: tokio::sync::Mutex<NamedPipeServer>,
    }

    impl std::fmt::Debug for ControlListener {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ControlListener")
                .field("name", &self.name)
                .finish_non_exhaustive()
        }
    }

    // SAFETY: the descriptor is only read (by CreateNamedPipeW) and freed once.
    unsafe impl Send for ControlListener {}
    // SAFETY: as above; the pipe instance is behind a mutex.
    unsafe impl Sync for ControlListener {}

    impl ControlListener {
        /// Creates the first pipe instance. A name that already exists
        /// refuses the start (`AGT-E006`): another agent or a squat.
        ///
        /// # Errors
        ///
        /// `AGT-E006` or `AGT-E008`.
        pub fn bind(name: &str) -> Result<Self, PlatformError> {
            let descriptor = Descriptor::from_sddl(&sddl())?;
            let first = create(name, true, &descriptor).map_err(|e| {
                if e.raw_os_error() == Some(ERROR_ACCESS_DENIED) {
                    PlatformError::new(
                        Code::ControlNameTaken,
                        format!("{name} existe déjà (autre agent ou squat)"),
                    )
                } else {
                    super::io("pipe", e)
                }
            })?;
            Ok(Self {
                name: name.to_owned(),
                descriptor,
                next: tokio::sync::Mutex::new(first),
            })
        }

        /// Next caller (the DACL already restricts who can connect).
        ///
        /// # Errors
        ///
        /// `AGT-E008`.
        pub async fn accept(&self) -> Result<Box<dyn Duplex>, PlatformError> {
            let mut next = self.next.lock().await;
            next.connect()
                .await
                .map_err(|e| super::io("connexion", e))?;
            let fresh =
                create(&self.name, false, &self.descriptor).map_err(|e| super::io("pipe", e))?;
            let connected = std::mem::replace(&mut *next, fresh);
            Ok(Box::new(connected))
        }
    }

    /// Process id of the server end of a client pipe.
    pub(crate) fn server_process_id(handle: HANDLE) -> std::io::Result<u32> {
        let mut pid = 0u32;
        // SAFETY: `handle` is an open client pipe handle; `pid` is a valid out-pointer.
        if unsafe { GetNamedPipeServerProcessId(handle, &raw mut pid) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(pid)
    }

    fn service_pid() -> Result<u32, PlatformError> {
        use windows_service::service::ServiceAccess;
        use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| {
            PlatformError::new(
                Code::ControlNotAuthentic,
                format!("gestionnaire de services : {e}"),
            )
        })?;
        let service = manager
            .open_service(crate::service::SERVICE_NAME, ServiceAccess::QUERY_STATUS)
            .map_err(|e| {
                PlatformError::new(
                    Code::ControlNotAuthentic,
                    format!("service {} : {e}", crate::service::SERVICE_NAME),
                )
            })?;
        let status = service.query_status().map_err(|e| {
            PlatformError::new(Code::ControlNotAuthentic, format!("état du service : {e}"))
        })?;
        status.process_id.ok_or_else(|| {
            PlatformError::new(
                Code::ControlNotAuthentic,
                "le service n'est pas en cours d'exécution",
            )
        })
    }

    /// Connects, then checks that the server process is the expected one
    /// before anything is read (`AGT-E007` otherwise).
    ///
    /// # Errors
    ///
    /// `AGT-E007`, `AGT-E009` (access refused by the DACL) or `AGT-E008`.
    pub async fn connect(
        name: &str,
        expected: ExpectedServer,
    ) -> Result<Box<dyn Duplex>, PlatformError> {
        let mut attempts = 0;
        let client = loop {
            match ClientOptions::new().open(name) {
                Ok(c) => break c,
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempts < 20 => {
                    attempts += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED) => {
                    return Err(PlatformError::new(
                        Code::ControlDenied,
                        format!("{name} : accès refusé (administrateur requis)"),
                    ));
                }
                Err(e) => return Err(super::io("connexion", e)),
            }
        };
        let server = server_process_id(client.as_raw_handle())
            .map_err(|e| super::io("processus serveur", e))?;
        let wanted = match expected {
            ExpectedServer::Service => service_pid()?,
            ExpectedServer::Process(pid) => pid,
        };
        if server != wanted {
            return Err(PlatformError::new(
                Code::ControlNotAuthentic,
                format!("le serveur de {name} est le processus {server}, pas l'agent ({wanted})"),
            ));
        }
        Ok(Box::new(client))
    }
}

#[cfg(test)]
mod tests;
