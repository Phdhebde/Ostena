//! Private files (the agent key): created with their final rights before
//! the first byte is written, never widened afterwards.
//!
//! - Unix: mode `0600` given at creation (the umask can only narrow it).
//! - Windows: a protected security descriptor (no inheritance) given to
//!   `CreateFileW`: SYSTEM and the Administrators in full control, and one
//!   reader (read and delete, so that a renewal can replace the file).
//!
//! The file must not exist: an existing key is never overwritten.

use std::io::{self, Write};
use std::path::Path;

/// Who may read the file besides SYSTEM and the Administrators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reader {
    /// The agent service account (`NT SERVICE\OstenaAgent` on Windows), if it
    /// exists yet: for `ostena agent enroll`, run by an administrator.
    Service,
    /// The account of the current process: the service itself when the agent
    /// runs as a service, for the files it writes (renewal).
    CurrentProcess,
}

/// Creates `path` with its final rights, writes `bytes` and syncs.
///
/// # Errors
///
/// The file exists (`AlreadyExists`), or any creation or write error.
pub fn create(path: &Path, bytes: &[u8], reader: Reader) -> io::Result<()> {
    let mut file = imp::create(path, reader)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Creates `path` with its final rights and returns it open for writing,
/// for a content written as a stream (an audit export). The caller syncs.
///
/// # Errors
///
/// The file exists (`AlreadyExists`), or any creation error.
pub fn create_new(path: &Path, reader: Reader) -> io::Result<std::fs::File> {
    imp::create(path, reader)
}

#[cfg(unix)]
mod imp {
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;

    pub(super) fn create(path: &Path, _reader: super::Reader) -> io::Result<File> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }
}

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "CreateFileW with a security descriptor, token user SID; documented and tested"
)]
mod imp {
    use std::fs::File;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use std::path::Path;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::{
        CloseHandle, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_INFORMATION_CLASS,
        TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use crate::acl::{SERVICE_ACCOUNT, SYSTEM, account_sid, sid_string};
    use crate::control::Descriptor;

    /// One class of information about the current process token, in a buffer
    /// aligned for any token structure.
    fn token_information(class: TOKEN_INFORMATION_CLASS) -> io::Result<Vec<u64>> {
        let mut token: HANDLE = null_mut();
        // SAFETY: the pseudo-handle of the current process is always valid;
        // `token` receives a handle closed below.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut len = 0u32;
        // SAFETY: size query with a null buffer.
        unsafe { GetTokenInformation(token, class, null_mut(), 0, &raw mut len) };
        // u64 elements: the token structures need pointer alignment.
        let mut buffer = vec![0u64; (len as usize).div_ceil(8).max(1)];
        // SAFETY: `buffer` holds at least `len` bytes, suitably aligned.
        let ok = unsafe {
            GetTokenInformation(token, class, buffer.as_mut_ptr().cast(), len, &raw mut len)
        };
        let error = io::Error::last_os_error();
        // SAFETY: `token` was opened above and is closed once.
        unsafe { CloseHandle(token) };
        if ok == 0 {
            return Err(error);
        }
        Ok(buffer)
    }

    /// SID string of the account of the current process.
    ///
    /// # Errors
    ///
    /// The process token cannot be read.
    pub fn current_user_sid() -> io::Result<String> {
        let buffer = token_information(TokenUser)?;
        // SAFETY: on success the buffer starts with a TOKEN_USER whose SID
        // points into the same buffer, alive for this scope.
        let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        // SAFETY: `sid` points into `buffer`, alive for this call.
        unsafe { sid_string(sid) }
    }

    /// The DACL: protected, SYSTEM and Administrators in full control, the
    /// reader with read and delete (`FR` + `SD`).
    /// Whether the process token is elevated (UAC).
    fn elevated() -> io::Result<bool> {
        let buffer = token_information(TokenElevation)?;
        // SAFETY: on success the buffer starts with a TOKEN_ELEVATION.
        Ok(unsafe { (*buffer.as_ptr().cast::<TOKEN_ELEVATION>()).TokenIsElevated } != 0)
    }

    pub(crate) fn sddl(reader: super::Reader) -> io::Result<String> {
        let sid = match reader {
            super::Reader::Service => {
                let mut sids: Vec<String> = account_sid(SERVICE_ACCOUNT).ok().into_iter().collect();
                if !elevated()? {
                    sids.push(current_user_sid()?);
                }
                sids
            }
            super::Reader::CurrentProcess => vec![current_user_sid()?],
        };
        let mut reader = String::new();
        for s in sid.iter().filter(|s| *s != SYSTEM) {
            reader.push_str("(A;;FRSD;;;");
            reader.push_str(s);
            reader.push(')');
        }
        Ok(format!("D:P(A;;FA;;;SY)(A;;FA;;;BA){reader}"))
    }

    pub(super) fn create(path: &Path, reader: super::Reader) -> io::Result<File> {
        let descriptor =
            Descriptor::from_sddl(&sddl(reader)?).map_err(|e| io::Error::other(e.to_string()))?;
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
            lpSecurityDescriptor: descriptor.as_ptr(),
            bInheritHandle: 0,
        };
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        // SAFETY: `wide` is NUL-terminated; `attributes` and its descriptor
        // outlive the call (Windows copies the descriptor); CREATE_NEW fails
        // if the file exists.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_WRITE,
                0,
                &raw mut attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `handle` is a valid file handle we own; File closes it.
        Ok(unsafe { File::from_raw_handle(handle) })
    }
}

#[cfg(windows)]
pub use imp::current_user_sid;

#[cfg(test)]
mod tests;
