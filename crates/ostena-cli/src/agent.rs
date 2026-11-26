//! `ostena agent install | uninstall | run | status` (ADR-0007).

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ostena_common::config::{self, AgentConfig, Config, LoggingConfig};
use ostena_grant::FileReplayStore;
use ostena_platform::control::{ControlListener, DEFAULT_ENDPOINT, ExpectedServer};
use ostena_platform::service::{InstallOptions, ServiceManager, ServiceState, service_manager};

use crate::control;
use crate::core_link;
use crate::sessions::Sessions;

/// Delay before the idle footprint is measured (`agent.idle_footprint`).
const IDLE_FOOTPRINT_DELAY: Duration = Duration::from_secs(5);

/// SHA-256 of the configuration file as loaded, for `status`.
fn fingerprint(path: &Path) -> String {
    std::fs::read(path).map_or_else(
        |_| "indisponible".to_owned(),
        |bytes| {
            use std::fmt::Write as _;
            let digest = ostena_crypto::sha256::digest(&bytes);
            digest.iter().fold(String::from("sha256:"), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            })
        },
    )
}

/// Exit code of `status` when the service is installed but not running
/// (LSB convention).
const NOT_RUNNING: u8 = 3;

/// Default configuration path.
pub(crate) fn default_config() -> PathBuf {
    if cfg!(windows) {
        let base = std::env::var_os("ProgramData")
            .map_or_else(|| PathBuf::from("C:\\ProgramData"), PathBuf::from);
        base.join("Ostena").join("ostena.toml")
    } else {
        PathBuf::from("/etc/ostena/ostena.toml")
    }
}

fn say(quiet: bool, text: &str) {
    if !quiet {
        let _ = writeln!(io::stdout(), "{text}");
    }
}

fn fail(text: &str) -> ExitCode {
    let _ = writeln!(io::stderr(), "{text}");
    ExitCode::FAILURE
}

/// Reads the configuration without the startup checks, to install or to set
/// up logging before the full load.
pub(crate) fn read(path: &Path) -> Result<Config, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{} : {e}", path.display()))?;
    Config::from_toml_str(&text).map_err(|e| e.to_string())
}

pub(crate) fn install(
    config: &Path,
    executable: Option<PathBuf>,
    start: bool,
    quiet: bool,
) -> ExitCode {
    let parsed = match read(config) {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    if let Err(v) = parsed.validate() {
        return fail(&v.to_string());
    }
    let Some(agent) = parsed.agent else {
        return fail(&format!("{} : section [agent] absente", config.display()));
    };
    let executable = match executable.map_or_else(std::env::current_exe, Ok) {
        Ok(p) => p,
        Err(e) => return fail(&format!("exécutable introuvable : {e}")),
    };
    let options = InstallOptions {
        executable,
        config: config.to_path_buf(),
        private_key: Some(agent.tls_private_key.clone()),
        state_dir: agent.replay_journal.parent().map(Path::to_path_buf),
        start,
    };
    match service_manager().and_then(|m| m.install(&options)) {
        Ok(()) => {
            say(
                quiet,
                if start {
                    "Agent installé et démarré."
                } else {
                    "Agent installé."
                },
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e.to_string()),
    }
}

pub(crate) fn uninstall(quiet: bool) -> ExitCode {
    match service_manager().and_then(ServiceManager::uninstall) {
        Ok(()) => {
            say(
                quiet,
                "Agent désinstallé (configuration, données et compte conservés).",
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e.to_string()),
    }
}

/// `ostena agent ssh-key`: the agent key on the targets and the
/// `authorized_keys` line (ADR-0010). Read only: the agent creates its keys.
pub(crate) fn ssh_key(config: &Path, from: &[String], pty: bool, line: bool) -> ExitCode {
    let parsed = match read(config) {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    let Some(agent) = parsed.agent else {
        return fail(&format!("{} : section [agent] absente", config.display()));
    };
    #[cfg(feature = "ssh")]
    match crate::ssh::show_key(&agent, from, pty, line) {
        Ok(text) => {
            let _ = write!(io::stdout(), "{}{}", text, if line { "\n" } else { "" });
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
    #[cfg(not(feature = "ssh"))]
    {
        let _ = (agent, from, pty, line);
        fail("ce binaire est construit sans le serveur SSH")
    }
}

/// Control plane endpoint of a configuration (or the platform default).
fn endpoint_of(config: &Path) -> String {
    read(config)
        .ok()
        .and_then(|c| c.agent)
        .and_then(|a| a.control_endpoint)
        .unwrap_or_else(|| DEFAULT_ENDPOINT.to_owned())
}

/// `ostena agent status`: the service state, then, if it runs, what its
/// control plane reports. `pid` targets a foreground agent (development).
pub(crate) fn status(config: &Path, pid: Option<u32>) -> ExitCode {
    let expected = if let Some(pid) = pid {
        ExpectedServer::Process(pid)
    } else {
        let state = match service_manager().and_then(ServiceManager::state) {
            Ok(s) => s,
            Err(e) => return fail(&e.to_string()),
        };
        let (text, code) = match state {
            ServiceState::Running => ("en cours d'exécution", 0),
            ServiceState::Starting => ("en cours de démarrage", 0),
            ServiceState::Stopping => ("en cours d'arrêt", NOT_RUNNING),
            ServiceState::Stopped => ("arrêté", NOT_RUNNING),
            ServiceState::Failed => ("arrêté après des échecs répétés", NOT_RUNNING),
            ServiceState::NotInstalled => ("non installé", 4),
            ServiceState::Other(ref s) => (s.as_str(), 1),
        };
        say(false, &format!("Agent : {text}"));
        if state != ServiceState::Running {
            return ExitCode::from(code);
        }
        ExpectedServer::Service
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => return fail(&e.to_string()),
    };
    let endpoint = endpoint_of(config);
    let answer = match runtime.block_on(control::query(&endpoint, expected, "status")) {
        Ok(a) => a,
        Err(e) => return fail(&e.to_string()),
    };
    let field = |k: &str| {
        answer[k]
            .as_str()
            .map_or_else(|| answer[k].to_string(), str::to_owned)
    };
    #[expect(clippy::cast_precision_loss, reason = "display only")]
    let mib = answer["resident_bytes"].as_u64().map_or_else(
        || "?".to_owned(),
        |b| format!("{:.1}", b as f64 / 1_048_576.0),
    );
    say(
        false,
        &format!(
            "Version : {}\nGroupe : {}\nCore : {}\nSessions : {}\nEn service depuis : {} s\nMémoire résidente : {mib} Mio\nEmpreinte de la configuration : {}",
            field("version"),
            field("gateway_group"),
            field("core"),
            field("sessions"),
            field("uptime_secs"),
            field("config_fingerprint"),
        ),
    );
    core_details(&answer);
    ssh_details(&answer["ssh"]);
    ExitCode::SUCCESS
}

/// What the agent says about its SSH server, if configured.
fn ssh_details(ssh: &serde_json::Value) {
    if !ssh.is_object() {
        return;
    }
    let listen = ssh["listen"].as_array().map_or_else(String::new, |a| {
        a.iter()
            .filter_map(serde_json::Value::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    });
    let identity = match (
        ssh["identity"].as_bool(),
        ssh["host_certificate_valid_before"].as_u64(),
    ) {
        (Some(true), Some(end)) => {
            let now = ostena_grant::unix_now();
            format!(
                "prête, certificat d'hôte valide encore {} h",
                end.saturating_sub(now) / 3600
            )
        }
        (Some(true), None) => "prête".to_owned(),
        _ => match ssh["identity_refusal"].as_str() {
            Some(reason) => format!("aucune : {reason} (aucune connexion SSH possible)"),
            None => "pas encore reçue du core (aucune connexion SSH possible)".to_owned(),
        },
    };
    let identity = match (
        ssh["trust_version"].as_u64(),
        ssh["trust_version_received"].as_u64(),
    ) {
        (Some(applied), Some(received)) if applied != received => format!(
            "{identity}, confiance version {applied} (version {received} reçue, non applicable)"
        ),
        (Some(applied), _) => format!("{identity}, confiance version {applied}"),
        (None, Some(received)) => {
            format!("{identity}, confiance version {received} reçue, non applicable")
        }
        (None, None) => identity,
    };
    say(
        false,
        &format!(
            "SSH : à l'écoute sur {listen}, {} session(s)\nIdentité SSH : {identity}",
            ssh["sessions"]
        ),
    );
}

/// What the agent says about the core: pushed versions, certificate.
fn core_details(answer: &serde_json::Value) {
    let pushes = &answer["pushes"];
    if pushes.is_object() {
        let policy = pushes["policy"].as_u64().map_or_else(
            || "non reçue (aucune session possible)".to_owned(),
            |v| format!("version {v}"),
        );
        let keys = match (pushes["keyset"].as_u64(), pushes["keyset_floor"].as_u64()) {
            (Some(v), _) => format!("version {v}"),
            (None, Some(floor)) => format!(
                "non reçues (dernière version acceptée : {floor}, aucune version inférieure ne \
                 sera acceptée)"
            ),
            (None, None) => "non reçues (aucune session possible)".to_owned(),
        };
        say(
            false,
            &format!("Politique du core : {policy}\nClés de grant : {keys}"),
        );
    }
    let link = &answer["core_link"];
    if let (Some(not_after), Some(due)) = (
        link["certificate_not_after"].as_u64(),
        link["renewal_due"].as_u64(),
    ) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let days = |t: u64| t.saturating_sub(now) / 86_400;
        say(
            false,
            &format!(
                "Certificat : expire dans {} j, renouvellement automatique dans {} j",
                days(not_after),
                days(due)
            ),
        );
        if link["renewal_overdue"].as_bool() == Some(true) {
            say(
                false,
                &format!(
                    "AVERTISSEMENT : certificat non renouvelé à 90 % de sa validité, il expire dans \
                     {} h. Vérifiez le lien avec le core (événement tunnel.renewal_overdue).",
                    not_after.saturating_sub(now) / 3600
                ),
            );
        }
    }
}

/// How the agent learns it must stop.
pub(crate) enum StopSource {
    /// `SIGTERM` or `SIGINT` (Unix), Ctrl-C (Windows console).
    Signals,
    /// The Windows SCM.
    #[cfg_attr(not(windows), expect(dead_code, reason = "Windows only"))]
    Service(std::sync::mpsc::Receiver<()>),
}

impl StopSource {
    /// Starts listening now (the signal handlers are installed before the
    /// agent says it started) and returns the wait for the stop request.
    fn arm(self) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>> {
        match self {
            Self::Service(rx) => Box::pin(async move {
                let _ = tokio::task::spawn_blocking(move || rx.recv()).await;
            }),
            Self::Signals => Box::pin(wait_for_signals()),
        }
    }
}

/// Installs the stop signal handlers at once, then returns the wait for the
/// first signal: a signal received in between is not lost.
#[cfg(unix)]
pub(crate) fn wait_for_signals() -> impl Future<Output = ()> + Send + 'static {
    use std::sync::Arc;
    use tokio::signal::unix::{SignalKind, signal};
    let notify = Arc::new(tokio::sync::Notify::new());
    for kind in [SignalKind::terminate(), SignalKind::interrupt()] {
        match signal(kind) {
            Ok(mut stream) => {
                let notify = Arc::clone(&notify);
                tokio::spawn(async move {
                    stream.recv().await;
                    notify.notify_one();
                });
            }
            Err(e) => tracing::error!(event = "agent.signal_failed", "signal non installé : {e}"),
        }
    }
    async move { notify.notified().await }
}

/// Installs the Ctrl-C handler at once, then returns the wait for it.
#[cfg(not(unix))]
pub(crate) fn wait_for_signals() -> impl Future<Output = ()> + Send + 'static {
    let installed = tokio::signal::windows::ctrl_c();
    async move {
        match installed {
            Ok(mut ctrl_c) => {
                ctrl_c.recv().await;
            }
            Err(e) => {
                tracing::error!(event = "agent.signal_failed", "Ctrl-C non installé : {e}");
                std::future::pending::<()>().await;
            }
        }
    }
}

/// `ostena agent run`: in the foreground, under systemd, or under the SCM
/// (`--service`, Windows).
pub(crate) fn run(config: &Path, service: bool) -> ExitCode {
    if service {
        #[cfg(windows)]
        {
            let config = config.to_path_buf();
            return match ostena_platform::service::run_service(move |ctx| {
                agent_main(&config, StopSource::Service(ctx.stop), ctx.ready)
            }) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(&e.to_string()),
            };
        }
        #[cfg(not(windows))]
        return fail(
            "--service n'existe que sous Windows ; sous Linux, systemd lance `ostena agent run`",
        );
    }
    let ready: Box<dyn FnOnce() + Send> = Box::new(|| {
        #[cfg(target_os = "linux")]
        ostena_platform::service::notify("READY=1");
    });
    ExitCode::from(u8::try_from(agent_main(config, StopSource::Signals, ready)).unwrap_or(1))
}

/// What the running agent shares between its parts.
struct Running {
    info: Arc<control::AgentInfo>,
    /// The anti-replay journal, for the SSH sessions.
    journal: Arc<FileReplayStore>,
}

/// The agent itself. Returns the process exit code.
fn agent_main(config_path: &Path, stop: StopSource, ready: Box<dyn FnOnce() + Send>) -> u32 {
    let started = Instant::now();
    // Logging first, from the raw configuration if it parses.
    let logging = read(config_path).map_or_else(|_| LoggingConfig::default(), |c| c.logging);
    if ostena_common::logging::init(&logging).is_err() {
        let _ = ostena_common::logging::init(&LoggingConfig::default());
    }
    let loaded = match config::load_with(config_path, ostena_platform::permission_checker()) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(event = "agent.config_refused", codes = ?e.codes(), "{e}");
            return 1;
        }
    };
    loaded.log_weakenings();
    let Some(agent) = loaded.config.agent.clone() else {
        tracing::error!(
            event = "agent.config_refused",
            "section [agent] absente de {}",
            config_path.display()
        );
        return 1;
    };
    if cfg!(not(feature = "ssh")) && agent.ssh.is_some() {
        tracing::error!(
            event = "agent.config_refused",
            "[agent.ssh] présent, mais ce binaire est construit sans le serveur SSH (mesure \
             d'empreinte seulement) : utilisez le binaire de release"
        );
        return 1;
    }
    let journal = match FileReplayStore::open(&agent.replay_journal) {
        Ok(j) => Arc::new(j),
        Err(e) => {
            tracing::error!(event = "agent.replay_store_refused", "{e}");
            return 1;
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(agent.worker_threads())
        .thread_name("ostena-agent")
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(event = "agent.runtime_failed", "{e}");
            return 1;
        }
    };
    let endpoint = agent
        .control_endpoint
        .clone()
        .unwrap_or_else(|| DEFAULT_ENDPOINT.to_owned());
    let info = Arc::new(control::AgentInfo {
        started,
        gateway_group: agent.gateway_group.clone(),
        config_fingerprint: fingerprint(config_path),
        sessions: Arc::new(Sessions::new()),
        link: Arc::default(),
        gateway: Arc::default(),
        #[cfg(feature = "ssh")]
        ssh: std::sync::OnceLock::new(),
    });
    let grace = Duration::from_secs(agent.shutdown_grace_secs);
    let mode = loaded.config.mode;
    let served = runtime.block_on(serve_until_stopped(
        &agent,
        mode,
        &endpoint,
        Running {
            info,
            journal: journal.clone(),
        },
        grace,
        stop,
        ready,
    ));
    if !served {
        return 1;
    }
    let code = match journal.sync() {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!(event = "agent.replay_store_sync_failed", "{e}");
            1
        }
    };
    drop(journal);
    runtime.shutdown_timeout(Duration::from_secs(5));
    tracing::info!(
        event = "agent.stopped",
        uptime_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
    );
    code
}

/// Starts the link to the core and what it pushes; `false` refuses the
/// start (unreadable key set state: the rollback protection could not be
/// guaranteed). Without a core CA, the agent runs without link.
async fn start_core_link(
    agent: &AgentConfig,
    mode: config::Mode,
    infrastructure: core_link::Infrastructure,
    info: &control::AgentInfo,
) -> bool {
    match core_link::start(agent, &info.config_fingerprint) {
        Ok(link) => {
            let link = Arc::new(link);
            // What the core pushes; an unreadable key set state refuses the
            // start: the rollback protection could not be guaranteed.
            match core_link::start_gateway(agent, mode, infrastructure, link.clone()) {
                Ok(gateway) => {
                    let _ = info.gateway.set(gateway);
                }
                Err(e) => {
                    tracing::error!(event = "agent.config_refused", code = "TUN-E015", "{e}");
                    link.stop().await;
                    return false;
                }
            }
            let _ = info.link.set(link);
        }
        Err(e) => tracing::warn!(event = "agent.core_link_disabled", "{e}"),
    }
    true
}

/// Starts the native SSH server when configured (ADR-0010): its keys and its
/// addresses must be usable, or the agent does not start (`Err`).
#[cfg(feature = "ssh")]
async fn start_ssh(
    agent: &AgentConfig,
    info: &control::AgentInfo,
    journal: Arc<FileReplayStore>,
) -> Result<Option<crate::ssh::SshService>, ()> {
    let side = crate::ssh::CoreSide {
        link: info.link.clone(),
        gateway: info.gateway.clone(),
    };
    match crate::ssh::start(agent, side, journal).await {
        Ok(ssh) => {
            if let Some(ssh) = &ssh {
                let _ = info.ssh.set(ssh.report());
            }
            Ok(ssh)
        }
        Err((e, code)) => {
            tracing::error!(event = "agent.ssh_unavailable", code, "{e}");
            if let Some(link) = info.link.get() {
                link.stop().await;
            }
            Err(())
        }
    }
}

/// Control plane and idle footprint until the stop request, then the bounded
/// shutdown of the sessions. Returns `false` when the control plane cannot
/// start (`AGT-E006`: another agent or a squat).
async fn serve_until_stopped(
    agent: &AgentConfig,
    mode: config::Mode,
    endpoint: &str,
    running: Running,
    grace: Duration,
    stop: StopSource,
    ready: Box<dyn FnOnce() + Send>,
) -> bool {
    let Running { info, journal } = running;
    #[cfg(not(feature = "ssh"))]
    let _ = journal;
    let listener = match ControlListener::bind(endpoint) {
        Ok(l) => Arc::new(l),
        Err(e) => {
            tracing::error!(event = "agent.control_unavailable", code = e.code.as_str(), endpoint = %endpoint, "{e}");
            return false;
        }
    };
    // The Ostena components must be known before anything else (CFG-P010).
    let infrastructure = match core_link::resolve_infrastructure(agent, mode).await {
        Ok(i) => i,
        Err(e) => {
            tracing::error!(event = "agent.config_refused", code = "CFG-P010", "{e}");
            return false;
        }
    };
    let refresher = core_link::refresh_infrastructure(agent, infrastructure.clone());
    if !start_core_link(agent, mode, infrastructure, &info).await {
        refresher.abort();
        return false;
    }
    #[cfg(feature = "ssh")]
    let Ok(ssh) = start_ssh(agent, &info, journal).await else {
        refresher.abort();
        return false;
    };
    let server = tokio::spawn(control::serve(Arc::clone(&listener), Arc::clone(&info)));
    let footprint = tokio::spawn(async {
        tokio::time::sleep(IDLE_FOOTPRINT_DELAY).await;
        tracing::info!(
            event = "agent.idle_footprint",
            resident_bytes = ostena_platform::memory::resident_bytes()
        );
    });
    let stopped = stop.arm();
    ready();
    tracing::info!(
        event = "agent.started",
        version = ostena_common::VERSION,
        gateway_group = %agent.gateway_group,
        worker_threads = agent.worker_threads(),
        control_endpoint = %endpoint,
        pid = std::process::id(),
    );
    stopped.await;
    #[cfg(target_os = "linux")]
    ostena_platform::service::notify("STOPPING=1");
    tracing::info!(
        event = "agent.stopping",
        sessions = info.sessions.active(),
        grace_secs = grace.as_secs()
    );
    // One grace for every session, SSH or not: both stop at once, and the
    // SSH reports are sent before the link closes.
    #[cfg(feature = "ssh")]
    let report = {
        let deadline = Instant::now() + grace;
        let ssh = async {
            if let Some(ssh) = ssh {
                ssh.stop(deadline).await;
            }
        };
        tokio::join!(ssh, info.sessions.shutdown(grace)).1
    };
    #[cfg(not(feature = "ssh"))]
    let report = info.sessions.shutdown(grace).await;
    tracing::info!(
        event = "agent.sessions_closed",
        finished = report.finished,
        aborted = report.aborted
    );
    if let Some(link) = info.link.get() {
        link.stop().await;
    }
    refresher.abort();
    footprint.abort();
    server.abort();
    let _ = server.await;
    // Dropping the listener removes the Unix socket.
    drop(listener);
    true
}
