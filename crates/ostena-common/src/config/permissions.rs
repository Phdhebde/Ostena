//! File permission rules of the configuration (ADR-0003, ADR-0007):
//!
//! - `CFG-P006`: the configuration file and its directory are writable only by
//!   the service account or the administrators;
//! - `CFG-P008`: the agent private key is readable and writable only by them;
//! - `CFG-P009`: the anti-replay journal directory is writable only by them.
//!
//! The check is behind [`PermissionChecker`]: Unix permissions are checked
//! here; Windows ACLs need Win32 security calls (`unsafe`) and are checked by
//! `ostena-platform`, which callers inject. Without it, Windows fails closed.

use std::path::Path;

/// Platform permission checks. Errors are French explanations.
pub trait PermissionChecker: Sync {
    /// The file or directory, and its parent directory, can only be modified
    /// by the service account or the administrators.
    ///
    /// # Errors
    ///
    /// Why it is not the case, or why it cannot be checked.
    fn not_writable_by_others(&self, path: &Path) -> Result<(), String>;

    /// The file can only be read or written by the service account or the
    /// administrators, and its directory is protected as above.
    ///
    /// # Errors
    ///
    /// Why it is not the case, or why it cannot be checked.
    fn private(&self, path: &Path) -> Result<(), String>;
}

/// Unix permissions on Unix; on other platforms, refuses (fail closed) and
/// points to `ostena-platform`.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultPermissions;

#[cfg(unix)]
impl PermissionChecker for DefaultPermissions {
    fn not_writable_by_others(&self, path: &Path) -> Result<(), String> {
        check_unix(path, false)
    }

    fn private(&self, path: &Path) -> Result<(), String> {
        check_unix(path, true)
    }
}

#[cfg(not(unix))]
impl PermissionChecker for DefaultPermissions {
    fn not_writable_by_others(&self, _: &Path) -> Result<(), String> {
        Err(NO_PLATFORM_CHECKER.into())
    }

    fn private(&self, _: &Path) -> Result<(), String> {
        Err(NO_PLATFORM_CHECKER.into())
    }
}

#[cfg(not(unix))]
const NO_PLATFORM_CHECKER: &str = "vérification des ACL indisponible sans le vérificateur de \
     ostena-platform ; démarrage refusé en production";

/// Checks `path` (after resolving symbolic links) and its directory.
#[cfg(unix)]
fn check_unix(path: &Path, private: bool) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let real =
        std::fs::canonicalize(path).map_err(|e| format!("droits impossibles à vérifier ({e})."))?;
    let service_uid = service_uid();
    let parent = real.parent().unwrap_or(&real);
    let meta =
        std::fs::metadata(&real).map_err(|e| format!("droits impossibles à vérifier ({e})."))?;
    let what = if meta.is_dir() {
        "le dossier"
    } else {
        "le fichier"
    };
    let check = if private { evaluate_private } else { evaluate };
    if let Some(reason) = check(what, &real, meta.uid(), meta.mode(), service_uid) {
        return Err(reason);
    }
    if parent != real {
        let meta = std::fs::metadata(parent)
            .map_err(|e| format!("droits impossibles à vérifier ({e})."))?;
        if let Some(reason) = evaluate("le dossier", parent, meta.uid(), meta.mode(), service_uid) {
            return Err(reason);
        }
    }
    Ok(())
}

/// Effective uid of the process. `/proc/self` belongs to it on Linux, which
/// avoids `unsafe` FFI. If unavailable, assume an unknown account: only root
/// ownership is then accepted (fail closed).
#[cfg(unix)]
fn service_uid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").map_or(0, |m| m.uid())
}

const ROOT: u32 = 0;

fn owner_rule(what: &str, path: &Path, owner: u32, service_uid: u32) -> Option<String> {
    (owner != ROOT && owner != service_uid).then(|| {
        format!(
            "{what} {} appartient à l'uid {owner}, ni root ni le compte du service \
             (uid {service_uid}).",
            path.display()
        )
    })
}

/// Not writable by others: owner root or service, no group or other write.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn evaluate(
    what: &str,
    path: &Path,
    owner: u32,
    mode: u32,
    service_uid: u32,
) -> Option<String> {
    const GROUP_OR_OTHER_WRITE: u32 = 0o022;
    owner_rule(what, path, owner, service_uid).or_else(|| {
        (mode & GROUP_OR_OTHER_WRITE != 0).then(|| {
            format!(
                "{what} {} est modifiable par le groupe ou par tous (mode {:o}) ; \
                 retirez ces droits (chmod go-w).",
                path.display(),
                mode & 0o7777
            )
        })
    })
}

/// Private: owner root or service, no permission at all for group or others.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn evaluate_private(
    what: &str,
    path: &Path,
    owner: u32,
    mode: u32,
    service_uid: u32,
) -> Option<String> {
    const GROUP_OR_OTHER_ANY: u32 = 0o077;
    owner_rule(what, path, owner, service_uid).or_else(|| {
        (mode & GROUP_OR_OTHER_ANY != 0).then(|| {
            format!(
                "{what} {} est accessible au groupe ou à tous (mode {:o}) ; \
                 réservez-le au compte du service (chmod 600).",
                path.display(),
                mode & 0o7777
            )
        })
    })
}
