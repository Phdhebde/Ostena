//! Windows ACL checks for `CFG-P006`, `CFG-P008` and `CFG-P009`.
//!
//! A file (and its directory) may be owned and written only by SYSTEM, the
//! Administrators, `TrustedInstaller` and the agent service account
//! (`NT SERVICE\OstenaAgent`); a private file may not even be read by others.
//! Deny entries only restrict access and are ignored; inherit-only entries do
//! not apply to the object itself. A NULL DACL (full access to everyone) and
//! unsupported entry types are refused (fail closed).
//!
//! The decision ([`evaluate`]) is pure and tested on every platform; reading
//! the security descriptor needs Win32 calls, in the `ffi` module.

/// Well-known SIDs trusted to own and write protected files.
pub const SYSTEM: &str = "S-1-5-18";
/// `BUILTIN\Administrators`.
pub const ADMINISTRATORS: &str = "S-1-5-32-544";
/// `NT SERVICE\TrustedInstaller`.
pub const TRUSTED_INSTALLER: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
/// Name of the agent virtual service account.
pub const SERVICE_ACCOUNT: &str = "NT SERVICE\\OstenaAgent";

/// Access rights that modify a file or directory, or its security.
const WRITE_MASK: u32 = 0x0000_0002 // FILE_WRITE_DATA / FILE_ADD_FILE
    | 0x0000_0004 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
    | 0x0000_0010 // FILE_WRITE_EA
    | 0x0000_0040 // FILE_DELETE_CHILD
    | 0x0000_0100 // FILE_WRITE_ATTRIBUTES
    | 0x0001_0000 // DELETE
    | 0x0004_0000 // WRITE_DAC
    | 0x0008_0000 // WRITE_OWNER
    | 0x1000_0000 // GENERIC_ALL
    | 0x4000_0000; // GENERIC_WRITE

/// Access rights that read a file's content.
const READ_MASK: u32 = 0x0000_0001 // FILE_READ_DATA
    | 0x0000_0008 // FILE_READ_EA
    | 0x1000_0000 // GENERIC_ALL
    | 0x8000_0000; // GENERIC_READ

/// One access control entry, as far as the checks are concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    /// Trustee, as a SID string.
    pub sid: String,
    /// Allow (`true`) or deny entry.
    pub allow: bool,
    /// Access mask.
    pub mask: u32,
    /// Applies only to children, not to the object itself.
    pub inherit_only: bool,
}

/// Owner and DACL of a file or directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Security {
    /// Owner SID string.
    pub owner: String,
    /// `None` for a NULL DACL (everyone has full access).
    pub dacl: Option<Vec<Ace>>,
}

/// Pure decision. `trusted` lists the SIDs allowed to own and write (and, for
/// a private file, to read). Returns why the object is not protected.
pub fn evaluate(
    what: &str,
    security: &Security,
    trusted: &[&str],
    private: bool,
) -> Option<String> {
    if !trusted.contains(&security.owner.as_str()) {
        return Some(format!(
            "{what} appartient à {}, ni SYSTEM, ni les Administrateurs, ni le compte du service.",
            security.owner
        ));
    }
    let Some(dacl) = &security.dacl else {
        return Some(format!("{what} a une DACL nulle : accès total pour tous."));
    };
    for ace in dacl.iter().filter(|a| a.allow && !a.inherit_only) {
        if trusted.contains(&ace.sid.as_str()) {
            continue;
        }
        if ace.mask & WRITE_MASK != 0 {
            return Some(format!(
                "{what} est modifiable par {} (masque {:#x}) ; retirez ce droit.",
                ace.sid, ace.mask
            ));
        }
        if private && ace.mask & READ_MASK != 0 {
            return Some(format!(
                "{what} est lisible par {} (masque {:#x}) ; réservez-le au compte du service.",
                ace.sid, ace.mask
            ));
        }
    }
    None
}

#[cfg(windows)]
pub(crate) use ffi::sid_string;
#[cfg(windows)]
pub use ffi::{WindowsPermissions, account_sid, read_security};

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "Win32 security API; every block is documented and tested"
)]
mod ffi {
    use std::ffi::c_void;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::{addr_of, null, null_mut};
    use std::sync::OnceLock;

    use ostena_common::config::PermissionChecker;
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, INHERIT_ONLY_ACE,
        LookupAccountNameW, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SID_NAME_USE,
    };

    use super::{
        ADMINISTRATORS, Ace, SERVICE_ACCOUNT, SYSTEM, Security, TRUSTED_INSTALLER, evaluate,
    };

    // winnt.h ACE types (kept local: windows-sys has them behind another feature).
    const ACCESS_ALLOWED_ACE_TYPE: u32 = 0;
    const ACCESS_DENIED_ACE_TYPE: u32 = 1;

    fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    /// Frees a `LocalAlloc` block on drop.
    struct Local(*mut c_void);

    impl Drop for Local {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer was allocated by the Win32 call that
                // returned it (documented as LocalFree-able) and is freed once.
                unsafe { LocalFree(self.0) };
            }
        }
    }

    /// SID string (`S-1-…`) of a SID.
    ///
    /// # Safety
    ///
    /// `sid` must point to a valid SID for the duration of the call.
    pub(crate) unsafe fn sid_string(sid: PSID) -> io::Result<String> {
        let mut out: *mut u16 = null_mut();
        // SAFETY: `sid` is valid (caller contract); `out` receives a
        // LocalAlloc'd, NUL-terminated string, freed by `Local` below.
        if unsafe { ConvertSidToStringSidW(sid, &raw mut out) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let _free = Local(out.cast());
        let mut len = 0;
        // SAFETY: `out` is NUL-terminated; reading up to the terminator stays
        // within the allocation.
        while unsafe { *out.add(len) } != 0 {
            len += 1;
        }
        // SAFETY: `len` UTF-16 units were just read from `out`.
        let units = unsafe { std::slice::from_raw_parts(out, len) };
        Ok(String::from_utf16_lossy(units))
    }

    /// Owner and DACL of a file or directory.
    ///
    /// # Errors
    ///
    /// The object does not exist or its security cannot be read.
    pub fn read_security(path: &Path) -> io::Result<Security> {
        let name = wide(path.as_os_str());
        let mut owner: PSID = null_mut();
        let mut dacl: *mut ACL = null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `name` is NUL-terminated and outlives the call; every
        // out-pointer is valid. On success `descriptor` owns the memory that
        // `owner` and `dacl` point into, and is freed by `Local`.
        let rc = unsafe {
            GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &raw mut owner,
                null_mut(),
                &raw mut dacl,
                null_mut(),
                &raw mut descriptor,
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(
                i32::try_from(rc).unwrap_or(i32::MAX),
            ));
        }
        let _free = Local(descriptor);
        // SAFETY: `owner` points into `descriptor`, alive until `_free` drops.
        let owner = unsafe { sid_string(owner)? };
        let dacl = if dacl.is_null() {
            None
        } else {
            // SAFETY: `dacl` points into `descriptor`, alive until `_free` drops.
            Some(unsafe { read_aces(dacl)? })
        };
        Ok(Security { owner, dacl })
    }

    /// Entries of an ACL.
    ///
    /// # Safety
    ///
    /// `acl` must point to a valid ACL for the duration of the call.
    unsafe fn read_aces(acl: *const ACL) -> io::Result<Vec<Ace>> {
        // SAFETY: `acl` is valid (caller contract).
        let count = unsafe { (*acl).AceCount };
        let mut aces = Vec::with_capacity(usize::from(count));
        for i in 0..count {
            let mut ace: *mut c_void = null_mut();
            // SAFETY: `i < AceCount`; on success `ace` points to an entry of `acl`.
            if unsafe { GetAce(acl, u32::from(i), &raw mut ace) } == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: every ACE starts with an ACE_HEADER.
            let header = unsafe { *(ace as *const ACE_HEADER) };
            let allow = match u32::from(header.AceType) {
                ACCESS_ALLOWED_ACE_TYPE => true,
                ACCESS_DENIED_ACE_TYPE => false,
                other => {
                    return Err(io::Error::other(format!(
                        "entrée d'ACL de type {other} non prise en charge"
                    )));
                }
            };
            let entry = ace as *const ACCESS_ALLOWED_ACE;
            // SAFETY: allowed and denied ACEs share the ACCESS_ALLOWED_ACE
            // layout (header, mask, SID starting at `SidStart`) within `acl`.
            let (mask, sid) = unsafe { ((*entry).Mask, addr_of!((*entry).SidStart) as PSID) };
            // SAFETY: `sid` points to the SID stored in the entry.
            let sid = unsafe { sid_string(sid)? };
            aces.push(Ace {
                sid,
                allow,
                mask,
                inherit_only: u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0,
            });
        }
        Ok(aces)
    }

    /// SID string of an account name, e.g. `NT SERVICE\OstenaAgent`.
    ///
    /// # Errors
    ///
    /// The account does not exist.
    pub fn account_sid(name: &str) -> io::Result<String> {
        let account = wide(std::ffi::OsStr::new(name));
        let (mut sid_len, mut domain_len) = (0u32, 0u32);
        let mut kind: SID_NAME_USE = 0;
        // SAFETY: first call with null buffers only reports the sizes needed.
        let ok = unsafe {
            LookupAccountNameW(
                null(),
                account.as_ptr(),
                null_mut(),
                &raw mut sid_len,
                null_mut(),
                &raw mut domain_len,
                &raw mut kind,
            )
        };
        let err = io::Error::last_os_error();
        if ok != 0 || err.raw_os_error() != i32::try_from(ERROR_INSUFFICIENT_BUFFER).ok() {
            return Err(err);
        }
        let mut sid = vec![0u8; sid_len as usize];
        let mut domain = vec![0u16; domain_len as usize];
        // SAFETY: the buffers have the sizes reported by the first call.
        let ok = unsafe {
            LookupAccountNameW(
                null(),
                account.as_ptr(),
                sid.as_mut_ptr().cast(),
                &raw mut sid_len,
                domain.as_mut_ptr(),
                &raw mut domain_len,
                &raw mut kind,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `sid` now holds a valid SID.
        unsafe { sid_string(sid.as_mut_ptr().cast()) }
    }

    /// SIDs trusted to own and write protected files. The service account
    /// exists only once the agent is installed.
    fn trusted() -> &'static [String] {
        static TRUSTED: OnceLock<Vec<String>> = OnceLock::new();
        TRUSTED.get_or_init(|| {
            let mut t: Vec<String> = [SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER]
                .map(str::to_owned)
                .into();
            if let Ok(service) = account_sid(SERVICE_ACCOUNT) {
                t.push(service);
            }
            t
        })
    }

    fn check(path: &Path, private: bool) -> Result<(), String> {
        let trusted: Vec<&str> = trusted().iter().map(String::as_str).collect();
        let real = std::fs::canonicalize(path)
            .map_err(|e| format!("droits impossibles à vérifier ({e})."))?;
        let security =
            read_security(&real).map_err(|e| format!("ACL impossibles à lire ({e})."))?;
        let what = if real.is_dir() {
            "le dossier"
        } else {
            "le fichier"
        };
        if let Some(reason) = evaluate(what, &security, &trusted, private) {
            return Err(reason);
        }
        if let Some(parent) = real.parent().filter(|p| *p != real) {
            let security =
                read_security(parent).map_err(|e| format!("ACL impossibles à lire ({e})."))?;
            if let Some(reason) = evaluate("le dossier", &security, &trusted, false) {
                return Err(reason);
            }
        }
        Ok(())
    }

    /// ACL-based [`PermissionChecker`].
    #[derive(Debug, Clone, Copy, Default)]
    pub struct WindowsPermissions;

    impl PermissionChecker for WindowsPermissions {
        fn not_writable_by_others(&self, path: &Path) -> Result<(), String> {
            check(path, false)
        }

        fn private(&self, path: &Path) -> Result<(), String> {
            check(path, true)
        }
    }
}

#[cfg(test)]
mod tests;
