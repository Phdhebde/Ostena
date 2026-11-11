//! systemd registration. Uses the standard tools (`id`, `useradd`,
//! `systemctl`) and the standard library: no `unsafe`.

use std::os::unix::fs::{PermissionsExt, chown};
use std::path::Path;
use std::process::Command;

use super::{
    Code, InstallOptions, PlatformError, SERVICE_USER, ServiceManager, ServiceState, UNIT_NAME,
    systemd_unit,
};

const UNIT_PATH: &str = "/etc/systemd/system/ostena-agent.service";

/// systemd service manager.
pub(super) struct Systemd;

fn run(code: Code, program: &str, args: &[&str]) -> Result<String, PlatformError> {
    let out = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| PlatformError::new(code, format!("{program} : {e}")))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    } else {
        Err(PlatformError::new(
            code,
            format!(
                "{program} {} : {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        ))
    }
}

fn require_root(code: Code) -> Result<(), PlatformError> {
    // The owner of /proc/self is the effective uid (no FFI needed).
    use std::os::unix::fs::MetadataExt;
    let uid = std::fs::metadata("/proc/self").map_or(u32::MAX, |m| m.uid());
    if uid == 0 {
        Ok(())
    } else {
        Err(PlatformError::new(code, "droits root nécessaires (sudo)"))
    }
}

/// Uid and gid of the service user, created if missing.
fn service_ids() -> Result<(u32, u32), PlatformError> {
    if run(Code::Install, "id", &["-u", SERVICE_USER]).is_err() {
        run(
            Code::Install,
            "useradd",
            &[
                "--system",
                "--user-group",
                "--no-create-home",
                "--home-dir",
                "/nonexistent",
                "--shell",
                "/usr/sbin/nologin",
                SERVICE_USER,
            ],
        )?;
    }
    let parse = |s: String| {
        s.parse::<u32>().map_err(|e| {
            PlatformError::new(
                Code::Install,
                format!("identifiant de {SERVICE_USER} : {e}"),
            )
        })
    };
    Ok((
        parse(run(Code::Install, "id", &["-u", SERVICE_USER])?)?,
        parse(run(Code::Install, "id", &["-g", SERVICE_USER])?)?,
    ))
}

fn set(path: &Path, owner: Option<(u32, u32)>, mode: u32) -> Result<(), PlatformError> {
    let fail =
        |e: std::io::Error| PlatformError::new(Code::Install, format!("{} : {e}", path.display()));
    if let Some((uid, gid)) = owner {
        chown(path, Some(uid), Some(gid)).map_err(fail)?;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(fail)
}

impl ServiceManager for Systemd {
    fn install(&self, o: &InstallOptions) -> Result<(), PlatformError> {
        require_root(Code::Privileges)?;
        let (uid, gid) = service_ids()?;
        // Configuration: root-owned, readable by the service group only.
        set(&o.config, Some((0, gid)), 0o640)?;
        // Private key: the service account alone (CFG-P008).
        if let Some(key) = &o.private_key {
            set(key, Some((uid, gid)), 0o600)?;
        }
        // The journal directory is the systemd StateDirectory when it is the
        // default; otherwise create it for the service account (CFG-P009).
        if let Some(dir) = &o.state_dir
            && dir != Path::new("/var/lib/ostena")
        {
            std::fs::create_dir_all(dir).map_err(|e| {
                PlatformError::new(Code::Install, format!("{} : {e}", dir.display()))
            })?;
            set(dir, Some((uid, gid)), 0o700)?;
        }
        let unit = systemd_unit(&o.executable, &o.config);
        std::fs::write(UNIT_PATH, unit)
            .map_err(|e| PlatformError::new(Code::Install, format!("{UNIT_PATH} : {e}")))?;
        set(Path::new(UNIT_PATH), None, 0o644)?;
        run(Code::Install, "systemctl", &["daemon-reload"])?;
        run(Code::Install, "systemctl", &["enable", UNIT_NAME])?;
        if o.start {
            run(Code::Install, "systemctl", &["restart", UNIT_NAME])?;
        }
        Ok(())
    }

    fn uninstall(&self) -> Result<(), PlatformError> {
        require_root(Code::Privileges)?;
        if Path::new(UNIT_PATH).exists() {
            // Already stopped or disabled is fine.
            let _ = run(
                Code::Uninstall,
                "systemctl",
                &["disable", "--now", UNIT_NAME],
            );
            std::fs::remove_file(UNIT_PATH)
                .map_err(|e| PlatformError::new(Code::Uninstall, format!("{UNIT_PATH} : {e}")))?;
            run(Code::Uninstall, "systemctl", &["daemon-reload"])?;
        }
        Ok(())
    }

    fn state(&self) -> Result<ServiceState, PlatformError> {
        if !Path::new(UNIT_PATH).exists() {
            return Ok(ServiceState::NotInstalled);
        }
        // `is-active` exits non-zero for inactive units: read stdout anyway.
        let out = Command::new("systemctl")
            .args(["is-active", UNIT_NAME])
            .output()
            .map_err(|e| PlatformError::new(Code::State, format!("systemctl : {e}")))?;
        Ok(match String::from_utf8_lossy(&out.stdout).trim() {
            "active" | "reloading" => ServiceState::Running,
            "activating" => ServiceState::Starting,
            "deactivating" => ServiceState::Stopping,
            "inactive" => ServiceState::Stopped,
            "failed" => ServiceState::Failed,
            other => ServiceState::Other(other.to_owned()),
        })
    }
}

/// Tells systemd the service is ready (`READY=1`) or stopping
/// (`STOPPING=1`). Does nothing outside systemd.
pub fn notify(state: &str) {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};

    let Some(target) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let bytes = target.as_encoded_bytes();
    let addr = match bytes.strip_prefix(b"@") {
        Some(abstract_name) => SocketAddr::from_abstract_name(abstract_name),
        None => SocketAddr::from_pathname(Path::new(&target)),
    };
    let sent = addr.and_then(|addr| UnixDatagram::unbound()?.send_to_addr(state.as_bytes(), &addr));
    if let Err(e) = sent {
        tracing::warn!(
            event = "agent.notify_failed",
            "notification systemd impossible : {e}"
        );
    }
}
