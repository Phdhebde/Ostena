//! `CFG-P006`: the configuration file and its directory must not be writable
//! by any account other than the service account or root.

use std::path::Path;

use super::validation::{Code, Violation};

/// Returns a `CFG-P006` violation if the file or its directory is not protected.
#[cfg(unix)]
pub(crate) fn check(path: &Path) -> Option<Violation> {
    use std::os::unix::fs::MetadataExt;

    let refuse = |reason: String| {
        Some(Violation::new(
            Code::ConfigFileWritableByOthers,
            format!("{} : {reason}", path.display()),
        ))
    };
    // Check the real file, not a symbolic link pointing to it.
    let real = match std::fs::canonicalize(path) {
        Ok(p) => p,
        Err(e) => return refuse(format!("droits impossibles à vérifier ({e}).")),
    };
    let service_uid = service_uid();
    let parent = real.parent().unwrap_or(&real);
    for (what, target) in [("le fichier", real.as_path()), ("le dossier", parent)] {
        let meta = match std::fs::metadata(target) {
            Ok(m) => m,
            Err(e) => return refuse(format!("droits impossibles à vérifier ({e}).")),
        };
        if let Some(reason) = evaluate(what, target, meta.uid(), meta.mode(), service_uid) {
            return refuse(reason);
        }
    }
    None
}

/// Windows ACLs are not checked yet: fail closed, refused in production.
// TODO(CFG-P006-windows): check that the DACL of the file and its directory only
// grants write access to SYSTEM, Administrators and the service account. It
// needs Win32 security APIs, hence `unsafe`: to be done in `ostena-platform`.
#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "same signature as the Unix version"
)]
pub(crate) fn check(path: &Path) -> Option<Violation> {
    Some(Violation::new(
        Code::ConfigFileWritableByOthers,
        format!(
            "{} : la vérification des ACL du fichier de configuration n'est pas encore \
             implémentée sous Windows (TODO CFG-P006-windows) ; démarrage refusé en \
             production.",
            path.display()
        ),
    ))
}

/// Effective uid of the process. `/proc/self` belongs to it on Linux, which
/// avoids `unsafe` FFI. If unavailable, assume an unknown account: only root
/// ownership is then accepted (fail closed).
#[cfg(unix)]
fn service_uid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").map_or(0, |m| m.uid())
}

/// Pure decision, testable on every platform.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn evaluate(
    what: &str,
    path: &Path,
    owner: u32,
    mode: u32,
    service_uid: u32,
) -> Option<String> {
    const ROOT: u32 = 0;
    const GROUP_OR_OTHER_WRITE: u32 = 0o022;
    if owner != ROOT && owner != service_uid {
        return Some(format!(
            "{what} {} appartient à l'uid {owner}, ni root ni le compte du service \
             (uid {service_uid}).",
            path.display()
        ));
    }
    if mode & GROUP_OR_OTHER_WRITE != 0 {
        return Some(format!(
            "{what} {} est modifiable par le groupe ou par tous (mode {:o}) ; \
             retirez ces droits (chmod go-w).",
            path.display(),
            mode & 0o7777
        ));
    }
    None
}
