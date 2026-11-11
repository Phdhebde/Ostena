//! Windows SCM registration and service runtime (`windows-service`), plus the
//! one call it lacks (required privileges, through `windows-sys`).

use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;
use std::sync::mpsc;
use std::time::Duration;

use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceSidType, ServiceStartType, ServiceState as WinState, ServiceStatus,
    ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::service_manager::{ServiceManager as WinManager, ServiceManagerAccess};

use super::{
    Code, InstallOptions, PlatformError, RESTART_BURST, RESTART_DELAY_SECS, RESTART_WINDOW_SECS,
    ServiceManager, ServiceState,
};
use crate::acl::{ADMINISTRATORS, SERVICE_ACCOUNT, SYSTEM, account_sid};

/// SCM name of the agent service; its virtual account is `NT SERVICE\OstenaAgent`.
pub const SERVICE_NAME: &str = "OstenaAgent";
const DISPLAY_NAME: &str = "Ostena - agent passerelle";
const DESCRIPTION: &str = "Passerelle d'administration Ostena : sessions SSH, RDP et VNC tracées.";
/// Upper bound announced to the SCM while stopping (grace of at most 300 s).
const STOP_WAIT_HINT: Duration = Duration::from_secs(330);
const ERROR_ACCESS_DENIED: i32 = 5;
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;

/// Windows service manager.
pub(super) struct Scm;

fn os_error(e: &windows_service::Error) -> Option<i32> {
    match e {
        windows_service::Error::Winapi(io) => io.raw_os_error(),
        _ => None,
    }
}

fn fail(code: Code, what: &str, e: &windows_service::Error) -> PlatformError {
    if os_error(e) == Some(ERROR_ACCESS_DENIED) {
        PlatformError::new(
            Code::Privileges,
            format!("{what} : droits administrateur nécessaires"),
        )
    } else {
        PlatformError::new(code, format!("{what} : {e}"))
    }
}

fn icacls(path: &Path, args: &[&str]) -> Result<(), PlatformError> {
    let out = Command::new("icacls")
        .arg(path)
        .args(args)
        .output()
        .map_err(|e| PlatformError::new(Code::Install, format!("icacls : {e}")))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(PlatformError::new(
            Code::Install,
            format!(
                "icacls {} : {}",
                path.display(),
                String::from_utf8_lossy(&out.stdout).trim()
            ),
        ))
    }
}

/// Only SYSTEM and the Administrators control the object; the service gets
/// `service_rights` (`R`, `RX`, `(OI)(CI)M`…).
fn protect(
    path: &Path,
    service_sid: &str,
    service_rights: &str,
    directory: bool,
) -> Result<(), PlatformError> {
    let inherit = if directory { "(OI)(CI)" } else { "" };
    let system = format!("*{SYSTEM}:{inherit}F");
    let admins = format!("*{ADMINISTRATORS}:{inherit}F");
    let service = format!("*{service_sid}:{service_rights}");
    icacls(
        path,
        &["/inheritance:r", "/grant:r", &system, &admins, &service],
    )?;
    icacls(path, &["/setowner", "*S-1-5-32-544"])
}

/// Required privileges: only `SeChangeNotifyPrivilege` (bypass traverse
/// checking). Every other privilege is removed from the service token.
#[allow(
    unsafe_code,
    reason = "ChangeServiceConfig2W is not wrapped by windows-service"
)]
fn set_required_privileges(
    service: &windows_service::service::Service,
) -> Result<(), PlatformError> {
    use windows_sys::Win32::System::Services::{
        ChangeServiceConfig2W, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
        SERVICE_REQUIRED_PRIVILEGES_INFOW,
    };
    // Double NUL-terminated list (REG_MULTI_SZ).
    let mut list: Vec<u16> = "SeChangeNotifyPrivilege"
        .encode_utf16()
        .chain([0, 0])
        .collect();
    let info = SERVICE_REQUIRED_PRIVILEGES_INFOW {
        pmszRequiredPrivileges: list.as_mut_ptr(),
    };
    // SAFETY: the handle is an open service handle with SERVICE_CHANGE_CONFIG
    // access; `info` and `list` outlive the call, and `list` is a valid
    // double NUL-terminated wide string list.
    let ok = unsafe {
        ChangeServiceConfig2W(
            service.raw_handle(),
            SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
            (&raw const info).cast(),
        )
    };
    if ok == 0 {
        return Err(PlatformError::new(
            Code::Install,
            format!("privilèges requis : {}", std::io::Error::last_os_error()),
        ));
    }
    Ok(())
}

/// Bounded restarts: `RESTART_BURST` restarts after `RESTART_DELAY_SECS`,
/// counted over `RESTART_WINDOW_SECS`, then none (the service stays stopped;
/// the SCM logs events 7031/7034).
pub(crate) fn failure_actions() -> ServiceFailureActions {
    let restart = ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: Duration::from_secs(RESTART_DELAY_SECS),
    };
    let mut actions = vec![restart; RESTART_BURST as usize];
    actions.push(ServiceAction {
        action_type: ServiceActionType::None,
        delay: Duration::ZERO,
    });
    ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(RESTART_WINDOW_SECS)),
        reboot_msg: None,
        command: None,
        actions: Some(actions),
    }
}

pub(crate) fn service_info(o: &InstallOptions) -> ServiceInfo {
    ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: o.executable.clone(),
        launch_arguments: ["agent", "run", "--service", "--config"]
            .into_iter()
            .map(OsString::from)
            .chain(std::iter::once(o.config.clone().into_os_string()))
            .collect(),
        dependencies: vec![],
        account_name: Some(OsString::from(SERVICE_ACCOUNT)),
        account_password: None,
    }
}

impl ServiceManager for Scm {
    fn install(&self, o: &InstallOptions) -> Result<(), PlatformError> {
        let manager = WinManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .map_err(|e| fail(Code::Install, "gestionnaire de services", &e))?;
        let info = service_info(o);
        let access = ServiceAccess::QUERY_STATUS
            | ServiceAccess::CHANGE_CONFIG
            | ServiceAccess::START
            | ServiceAccess::STOP;
        let service = match manager.open_service(SERVICE_NAME, access) {
            Ok(service) => {
                service
                    .change_config(&info)
                    .map_err(|e| fail(Code::Install, "mise à jour du service", &e))?;
                service
            }
            Err(e) if os_error(&e) == Some(ERROR_SERVICE_DOES_NOT_EXIST) => manager
                .create_service(&info, access)
                .map_err(|e| fail(Code::Install, "création du service", &e))?,
            Err(e) => return Err(fail(Code::Install, "ouverture du service", &e)),
        };
        service
            .set_description(DESCRIPTION)
            .map_err(|e| fail(Code::Install, "description", &e))?;
        service
            .set_config_service_sid_info(ServiceSidType::Restricted)
            .map_err(|e| fail(Code::Install, "SID de service restreint", &e))?;
        set_required_privileges(&service)?;
        service
            .update_failure_actions(failure_actions())
            .map_err(|e| fail(Code::Install, "actions d'échec", &e))?;
        service
            .set_failure_actions_on_non_crash_failures(true)
            .map_err(|e| fail(Code::Install, "actions d'échec", &e))?;

        // The virtual account exists once the service is created.
        let sid = account_sid(SERVICE_ACCOUNT)
            .map_err(|e| PlatformError::new(Code::Install, format!("{SERVICE_ACCOUNT} : {e}")))?;
        protect(&o.config, &sid, "R", false)?;
        if let Some(dir) = o.config.parent().filter(|d| {
            d.file_name()
                .is_some_and(|n| n.eq_ignore_ascii_case("ostena"))
        }) {
            // A dedicated configuration directory (…\Ostena) is protected too
            // (CFG-P006 checks it); any other directory is left untouched.
            protect(dir, &sid, "(OI)(CI)RX", true)?;
        }
        if let Some(key) = &o.private_key {
            protect(key, &sid, "R", false)?;
        }
        if let Some(dir) = &o.state_dir {
            std::fs::create_dir_all(dir).map_err(|e| {
                PlatformError::new(Code::Install, format!("{} : {e}", dir.display()))
            })?;
            protect(dir, &sid, "(OI)(CI)M", true)?;
        }
        if o.start {
            service
                .start::<&OsStr>(&[])
                .or_else(|e| {
                    if os_error(&e) == Some(1056) {
                        Ok(())
                    } else {
                        Err(e)
                    }
                }) // already running
                .map_err(|e| fail(Code::Install, "démarrage", &e))?;
        }
        Ok(())
    }

    fn uninstall(&self) -> Result<(), PlatformError> {
        let manager = WinManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| fail(Code::Uninstall, "gestionnaire de services", &e))?;
        let service = match manager.open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        ) {
            Ok(s) => s,
            Err(e) if os_error(&e) == Some(ERROR_SERVICE_DOES_NOT_EXIST) => return Ok(()),
            Err(e) => return Err(fail(Code::Uninstall, "ouverture du service", &e)),
        };
        if service
            .query_status()
            .is_ok_and(|s| s.current_state != WinState::Stopped)
        {
            let _ = service.stop();
            for _ in 0..340 {
                if service
                    .query_status()
                    .is_ok_and(|s| s.current_state == WinState::Stopped)
                {
                    break;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        service
            .delete()
            .map_err(|e| fail(Code::Uninstall, "suppression du service", &e))
    }

    fn state(&self) -> Result<ServiceState, PlatformError> {
        let manager = WinManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|e| fail(Code::State, "gestionnaire de services", &e))?;
        let service = match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
            Ok(s) => s,
            Err(e) if os_error(&e) == Some(ERROR_SERVICE_DOES_NOT_EXIST) => {
                return Ok(ServiceState::NotInstalled);
            }
            Err(e) => return Err(fail(Code::State, "ouverture du service", &e)),
        };
        let status = service
            .query_status()
            .map_err(|e| fail(Code::State, "état du service", &e))?;
        Ok(match status.current_state {
            WinState::Running => ServiceState::Running,
            WinState::StartPending => ServiceState::Starting,
            WinState::StopPending => ServiceState::Stopping,
            WinState::Stopped => ServiceState::Stopped,
            other => ServiceState::Other(format!("{other:?}")),
        })
    }
}

// ---------------------------------------------------------------- runtime

/// What the agent main function receives when run by the SCM.
pub struct ServiceContext {
    /// Receives one message when the SCM asks the service to stop.
    pub stop: mpsc::Receiver<()>,
    /// Reports the service as running; call once ready.
    pub ready: Box<dyn FnOnce() + Send>,
}

type Main = Box<dyn Fn(ServiceContext) -> u32 + Send + Sync>;

static MAIN: OnceLock<Main> = OnceLock::new();
static HANDLE: OnceLock<ServiceStatusHandle> = OnceLock::new();

fn status(
    state: WinState,
    accept: ServiceControlAccept,
    exit: u32,
    wait: Duration,
) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(exit),
        checkpoint: 0,
        wait_hint: wait,
        process_id: None,
    }
}

fn report(state: WinState, accept: ServiceControlAccept, exit: u32, wait: Duration) {
    if let Some(handle) = HANDLE.get()
        && let Err(e) = handle.set_service_status(status(state, accept, exit, wait))
    {
        tracing::warn!(
            event = "agent.service_status_failed",
            "état du service non transmis : {e}"
        );
    }
}

#[allow(
    unsafe_code,
    reason = "the windows-service entry point macro parses raw arguments"
)]
mod entry {
    windows_service::define_windows_service!(ffi_service_main, service_main);

    fn service_main(_arguments: Vec<std::ffi::OsString>) {
        super::service_main();
    }

    pub(super) fn start() -> windows_service::Result<()> {
        windows_service::service_dispatcher::start(super::SERVICE_NAME, ffi_service_main)
    }
}

fn service_main() {
    let (stop_tx, stop_rx) = mpsc::channel();
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
            report(
                WinState::StopPending,
                ServiceControlAccept::empty(),
                0,
                STOP_WAIT_HINT,
            );
            let _ = stop_tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(handle) = service_control_handler::register(SERVICE_NAME, handler) else {
        return;
    };
    let _ = HANDLE.set(handle);
    report(
        WinState::StartPending,
        ServiceControlAccept::empty(),
        0,
        Duration::from_secs(30),
    );
    let ready = Box::new(|| {
        report(
            WinState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            0,
            Duration::ZERO,
        );
    });
    let exit = MAIN.get().map_or(1, |main| {
        main(ServiceContext {
            stop: stop_rx,
            ready,
        })
    });
    report(
        WinState::Stopped,
        ServiceControlAccept::empty(),
        exit,
        Duration::ZERO,
    );
}

/// Runs `main` under the SCM (`ostena agent run --service`). Blocks until the
/// service stops.
///
/// # Errors
///
/// `AGT-E005` when the process was not started by the SCM.
pub fn run_service(
    main: impl Fn(ServiceContext) -> u32 + Send + Sync + 'static,
) -> Result<(), PlatformError> {
    if MAIN.set(Box::new(main)).is_err() {
        return Err(PlatformError::new(Code::Runtime, "service déjà lancé"));
    }
    entry::start()
        .map_err(|e| PlatformError::new(Code::Runtime, format!("répartiteur de services : {e}")))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn failure_actions_are_bounded() {
        let a = failure_actions();
        let actions = a.actions.unwrap();
        assert_eq!(actions.len(), 4);
        assert!(
            actions[..3]
                .iter()
                .all(|x| x.action_type == ServiceActionType::Restart)
        );
        assert_eq!(actions[3].action_type, ServiceActionType::None);
        assert!(
            matches!(a.reset_period, ServiceFailureResetPeriod::After(d) if d == Duration::from_secs(600))
        );
    }

    #[test]
    fn service_runs_as_its_virtual_account() {
        let info = service_info(&InstallOptions {
            executable: PathBuf::from("C:\\Program Files\\Ostena\\ostena.exe"),
            config: PathBuf::from("C:\\ProgramData\\Ostena\\ostena.toml"),
            private_key: None,
            state_dir: None,
            start: false,
        });
        assert_eq!(
            info.account_name.as_deref(),
            Some(OsStr::new("NT SERVICE\\OstenaAgent"))
        );
        assert_eq!(
            info.launch_arguments.last().map(OsString::as_os_str),
            Some(OsStr::new("C:\\ProgramData\\Ostena\\ostena.toml"))
        );
        assert_eq!(
            info.launch_arguments[..3],
            ["agent", "run", "--service"].map(OsString::from)
        );
    }

    #[test]
    fn state_without_admin_rights() {
        // Querying the SCM needs no administrator rights; the service is not
        // installed on development machines.
        let state = Scm.state().unwrap();
        assert!(matches!(
            state,
            ServiceState::NotInstalled | ServiceState::Stopped | ServiceState::Running
        ));
    }

    #[test]
    fn install_without_admin_rights_is_refused_cleanly() {
        let elevated = Command::new("net")
            .arg("session")
            .output()
            .is_ok_and(|o| o.status.success());
        if elevated {
            return; // covered by the CI integration test
        }
        let err = Scm
            .install(&InstallOptions {
                executable: PathBuf::from("C:\\nonexistent\\ostena.exe"),
                config: PathBuf::from("C:\\nonexistent\\ostena.toml"),
                private_key: None,
                state_dir: None,
                start: false,
            })
            .unwrap_err();
        assert_eq!(err.code, Code::Privileges, "{err}");
    }
}
