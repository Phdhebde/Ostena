//! The native SSH server of the agent (ADR-0010), bound to the tunnel:
//! keys created at the first start, identity built from what the core
//! pushes, accesses decided by the core (grant, jti consumed on both
//! sides, scope control), revocations, bounded shutdown.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ostena_common::config::{AgentConfig, SshPaths};
use ostena_common::secret::SecretBytes;
use ostena_crypto::p256::SigningKey;
use ostena_grant::FileReplayStore;
use ostena_platform::private_file::{self, Reader};
use ostena_ssh::cert;
use ostena_ssh::keys;
use ostena_ssh::server::{
    AccessRequest, Authorized, Authorizer, Refusal, ServerSettings, SessionSummary, SshIdentity,
    SshServer,
};
use ostena_tunnel::Uuid;
use ostena_tunnel::control::AgentMessage;
use ostena_tunnel::gateway::{Gateway, SshAccess};
use ostena_tunnel::link::AgentLink;
use serde_json::{Value, json};
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;

/// Code of a listen address that cannot be bound.
const LISTEN_FAILED: &str = "AGT-E010";
/// Code of revocations lost by the agent.
const REVOCATIONS_LOST: &str = "SSH-E020";
/// Code of an identity the agent cannot build from the pushed trust.
const IDENTITY_REFUSED: &str = "SSH-E018";

/// The agent's link to the core, as the SSH server needs it.
#[derive(Clone)]
pub(crate) struct CoreSide {
    pub link: Arc<OnceLock<Arc<AgentLink>>>,
    pub gateway: Arc<OnceLock<Gateway>>,
}

/// Decides through the core: grant, jti consumed here (persistent journal)
/// and by the core, scope control, pinned host key of the target.
struct TunnelAuthorizer {
    core: CoreSide,
    journal: Arc<FileReplayStore>,
    reports: Reports,
}

/// Session reports (`SessionClosed`) being sent to the core by detached
/// tasks, counted so that a stop waits for them before closing the link.
#[derive(Debug, Default, Clone)]
struct Reports(Arc<AtomicUsize>);

/// One report being sent; counted until dropped.
struct Sending(Arc<AtomicUsize>);

impl Drop for Sending {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Reports {
    fn sending(&self) -> Sending {
        self.0.fetch_add(1, Ordering::SeqCst);
        Sending(self.0.clone())
    }

    fn pending(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

/// Waits while `busy`, until `deadline` at most; returns whether it ended
/// idle.
async fn wait_idle(deadline: Instant, busy: impl Fn() -> bool) -> bool {
    loop {
        if !busy() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn refusal(code: &str, message: &str) -> Refusal {
    Refusal {
        code: code.to_owned(),
        message: message.to_owned(),
    }
}

impl Authorizer for TunnelAuthorizer {
    async fn authorize(&self, request: AccessRequest) -> Result<Authorized, Refusal> {
        let Some(gateway) = self.core.gateway.get() else {
            return Err(refusal("TUN-E026", "pas de lien avec le core"));
        };
        let access = SshAccess {
            subject: Uuid::from_bytes(request.identity.subject),
            login_session: Uuid::from_bytes(request.identity.login_session),
            certificate_sha256: request.identity.certificate_sha256,
            account: request.account,
            resource: request.resource,
            client_address: request.client_address,
        };
        match gateway
            .open_ssh_session(&access, ostena_grant::unix_now(), self.journal.as_ref())
            .await
        {
            Ok(session) => Ok(Authorized {
                session_id: session.session.session_id.to_bytes(),
                target: session.session.target,
                target_host_key: session.target_host_key,
                account: session.account,
                max_session: Duration::from_secs(session.session.max_session_secs.into()),
            }),
            Err(e) => Err(Refusal {
                code: e.code(),
                message: e.to_string(),
            }),
        }
    }

    fn closed(&self, summary: SessionSummary) {
        let Some(link) = self.core.link.get().cloned() else {
            return;
        };
        let session_id = Uuid::from_bytes(summary.session_id).to_string();
        let message = AgentMessage::SessionClosed {
            session_id: session_id.clone(),
            reason: summary.reason.to_owned(),
            bytes_to_target: summary.bytes_to_target,
            bytes_from_target: summary.bytes_from_target,
        };
        let sending = self.reports.sending();
        tokio::spawn(async move {
            let _sending = sending;
            if let Err(e) = link.send(&message).await {
                tracing::warn!(
                    event = "agent.session_report_lost",
                    session_id = %session_id,
                    code = e.code(),
                    "bilan de session non transmis au core : {e}"
                );
            }
        });
    }
}

/// The comment of the keys the agent creates: `ostena-agent-<host name>`.
fn key_comment() -> String {
    let name = if cfg!(windows) {
        std::env::var("COMPUTERNAME").unwrap_or_default()
    } else {
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .or_else(|_| std::fs::read_to_string("/etc/hostname"))
            .unwrap_or_default()
    };
    let name: String = name
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '.')
        .take(63)
        .collect::<String>()
        .to_ascii_lowercase();
    if name.is_empty() {
        "ostena-agent".to_owned()
    } else {
        format!("ostena-agent-{name}")
    }
}

/// The key at `path`, created with private rights if it does not exist
/// (`agent.ssh_key_created`), and checked: readable by `ostena-crypto` and
/// by the SSH library.
///
/// # Errors
///
/// The message, with `SSH-E007`–`SSH-E009` for a key problem.
pub(crate) fn ensure_key(path: &Path, role: &str) -> Result<SecretBytes, String> {
    let file = match std::fs::read(path) {
        Ok(bytes) => SecretBytes::from(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = keys::generate(&key_comment()).map_err(|e| e.to_string())?;
            // SECRET-EXPOSURE: written once, to a file created with its final rights.
            #[expect(clippy::disallowed_methods)]
            private_file::create(path, key.private.expose_secret(), Reader::CurrentProcess)
                .map_err(|e| {
                    format!("[SSH-E009] {} : création impossible : {e}", path.display())
                })?;
            tracing::info!(
                event = "agent.ssh_key_created",
                role,
                path = %path.display(),
                public_key = %key.public,
                "clé SSH créée"
            );
            key.private
        }
        Err(e) => return Err(format!("{} : {e}", path.display())),
    };
    keys::decode(&file).map_err(|e| format!("{} : {e}", path.display()))?;
    keys::load(&file).map_err(|e| format!("{} : {e}", path.display()))?;
    Ok(file)
}

/// Writes the host certificate next to the keys, for the operators
/// (`ssh-keygen -L -f`): a public file, replaced atomically.
fn write_host_certificate(path: &Path, certificate: &[u8]) -> std::io::Result<()> {
    let line = format!(
        "{} {} ostena-agent\n",
        cert::CERT_TYPE,
        STANDARD.encode(certificate)
    );
    if std::fs::read_to_string(path).is_ok_and(|current| current == line) {
        return Ok(());
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".new");
    std::fs::write(&tmp, line)?;
    std::fs::rename(&tmp, path)
}

/// Builds the identity of the server from the pushed trust.
///
/// # Errors
///
/// No host certificate in the trust, or an identity that cannot be built
/// (`SSH-E018`): certificate refused, no user authority…
fn identity_of(
    host_key: &SecretBytes,
    trust: &ostena_tunnel::ssh::SshTrust,
    now: u64,
) -> Result<SshIdentity, String> {
    let certificate = trust
        .host_certificate
        .as_deref()
        .ok_or_else(|| "pas de certificat d'hôte dans la confiance poussée".to_owned())?;
    let key = keys::load(host_key).map_err(|e| e.to_string())?;
    SshIdentity::new(
        key,
        certificate,
        &trust.host_cas,
        trust.user_cas.clone(),
        now,
    )
    .map_err(|e| e.to_string())
}

/// The identity of the server as the status shows it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct IdentityState {
    /// Version of the trust whose identity is in effect.
    applied: Option<u64>,
    /// End of validity of the host certificate in effect.
    valid_before: Option<u64>,
    /// Why there is no identity since the last push.
    refusal: Option<String>,
}

/// Where the identity of the server is published.
struct IdentitySink {
    host_key: SecretBytes,
    certificate_path: std::path::PathBuf,
    identity: watch::Sender<Option<Arc<SshIdentity>>>,
    state: Arc<std::sync::Mutex<IdentityState>>,
}

impl IdentitySink {
    fn set_state(&self, state: IdentityState) {
        if let Ok(mut slot) = self.state.lock() {
            *slot = state;
        }
    }

    /// Applies `trust` at `now`. Fail closed: a push the agent cannot apply
    /// (no host certificate, certificate refused, no user authority)
    /// withdraws the previous identity, with its user authorities; the
    /// server then refuses every connection before the banner, as without
    /// identity.
    fn apply(&self, trust: &ostena_tunnel::ssh::SshTrust, now: u64) {
        match identity_of(&self.host_key, trust, now) {
            Ok(built) => {
                let certificate = trust.host_certificate.as_deref().unwrap_or_default();
                let end = cert::parse(certificate).ok().map(|c| c.valid_before);
                self.identity.send_replace(Some(Arc::new(built)));
                self.set_state(IdentityState {
                    applied: Some(trust.version),
                    valid_before: end,
                    refusal: None,
                });
                tracing::info!(
                    event = "agent.ssh_identity_ready",
                    trust_version = trust.version,
                    authorities = trust.user_cas.len(),
                    host_authorities = trust.host_cas.len(),
                    valid_before = end,
                );
                if let Err(e) = write_host_certificate(&self.certificate_path, certificate) {
                    tracing::warn!(
                        event = "agent.ssh_host_certificate_unwritten",
                        path = %self.certificate_path.display(),
                        "certificat d'hôte non écrit : {e}"
                    );
                }
            }
            Err(reason) => {
                let withdrawn = self.identity.send_replace(None).is_some();
                self.set_state(IdentityState {
                    applied: None,
                    valid_before: None,
                    refusal: Some(reason.clone()),
                });
                // A trust pushed before the host certificate is issued is
                // the normal start: nothing to report.
                if withdrawn || trust.host_certificate.is_some() {
                    tracing::warn!(
                        event = "agent.ssh_identity_refused",
                        code = IDENTITY_REFUSED,
                        trust_version = trust.version,
                        withdrawn,
                        "[{IDENTITY_REFUSED}] {reason} ; aucune connexion SSH acceptée jusqu'à \
                         une confiance applicable"
                    );
                }
            }
        }
    }
}

/// Follows the trust pushed by the core and publishes the identity of the
/// server (see [`IdentitySink::apply`]).
fn follow_trust(
    mut trust: watch::Receiver<Option<Arc<ostena_tunnel::ssh::SshTrust>>>,
    sink: IdentitySink,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let current = trust.borrow_and_update().clone();
            if let Some(trust) = current {
                sink.apply(&trust, ostena_grant::unix_now());
            }
            if trust.changed().await.is_err() {
                return;
            }
        }
    })
}

/// Sends the host key with its proof of possession on each connection to
/// the core: the proof is bound to the certificate of the tunnel, which a
/// renewal changes.
fn send_host_key(link: Arc<AgentLink>, host_key: SigningKey) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut connected = link.subscribe_connected();
        loop {
            let connection = *connected.borrow_and_update();
            if let Some(connection) = connection {
                let sent = match ostena_tunnel::ssh::host_key_message(
                    &host_key,
                    &connection.certificate_sha256,
                ) {
                    Ok(message) => link.send(&message).await,
                    Err(e) => Err(e),
                };
                match sent {
                    Ok(()) => tracing::info!(
                        event = "agent.ssh_host_key_sent",
                        connection = connection.count
                    ),
                    Err(e) => tracing::warn!(
                        event = "agent.ssh_host_key_unsent",
                        code = e.code(),
                        "clé d'hôte SSH non transmise au core : {e}"
                    ),
                }
            }
            if connected.changed().await.is_err() {
                return;
            }
        }
    })
}

/// What a revocation acts on (the server; a counter in the tests).
pub(crate) trait Revoke {
    /// Cuts the sessions of `login_session`; returns how many.
    fn revoke_login(&self, login_session: [u8; 16]) -> usize;
    /// Cuts every session; returns how many.
    fn revoke_all(&self) -> usize;
}

impl<A: Authorizer> Revoke for SshServer<A> {
    fn revoke_login(&self, login_session: [u8; 16]) -> usize {
        SshServer::revoke_login(self, login_session)
    }
    fn revoke_all(&self) -> usize {
        SshServer::revoke_all(self)
    }
}

/// Applies the revocations of `ostena login` sessions. A revocation of an
/// unknown session cuts nothing (the core may push one again at a
/// reconnection). Lost revocations (the channel lagged) cut every session:
/// one of them may have been revoked (`ssh.revocations_lost`, `SSH-E020`).
pub(crate) async fn follow_revocations(
    mut revocations: broadcast::Receiver<Uuid>,
    server: impl Revoke,
) {
    loop {
        match revocations.recv().await {
            Ok(login) => {
                let cut = server.revoke_login(login.to_bytes());
                if cut > 0 {
                    tracing::info!(
                        event = "agent.login_revocation_applied",
                        login_session = %login,
                        sessions = cut
                    );
                }
            }
            Err(broadcast::error::RecvError::Lagged(lost)) => {
                let cut = server.revoke_all();
                tracing::warn!(
                    event = "ssh.revocations_lost",
                    code = REVOCATIONS_LOST,
                    lost,
                    sessions = cut,
                    "[{REVOCATIONS_LOST}] {lost} révocation(s) de session de connexion perdue(s) : \
                     toutes les sessions SSH en cours sont coupées"
                );
            }
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}

/// The running SSH server of the agent.
pub(crate) struct SshService {
    report: Arc<Report>,
    reports: Reports,
    stop: watch::Sender<bool>,
    listeners: Vec<JoinHandle<()>>,
    helpers: Vec<JoinHandle<()>>,
}

/// What `ostena agent status` shows of the SSH server.
pub(crate) struct Report {
    server: SshServer<TunnelAuthorizer>,
    listen: Vec<SocketAddr>,
    identity: watch::Receiver<Option<Arc<SshIdentity>>>,
    state: Arc<std::sync::Mutex<IdentityState>>,
    gateway: Arc<OnceLock<Gateway>>,
}

impl Report {
    /// Authenticated sessions now.
    pub(crate) fn sessions(&self) -> usize {
        self.server.sessions()
    }

    /// The `ssh` block of the status.
    pub(crate) fn status(&self) -> Value {
        let state = self.state.lock().map(|s| s.clone()).unwrap_or_default();
        json!({
            "listen": self.listen.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "sessions": self.server.sessions(),
            "identity": self.identity.borrow().is_some(),
            "host_certificate_valid_before": state.valid_before,
            "identity_refusal": state.refusal,
            "trust_version": state.applied,
            "trust_version_received": self
                .gateway
                .get()
                .and_then(|g| g.state().versions().ssh_trust),
        })
    }
}

/// Bounds of the server from `[agent.ssh]`.
fn settings(ssh: &ostena_common::config::AgentSshConfig) -> ServerSettings {
    let size = |v: u32| usize::try_from(v).unwrap_or(usize::MAX);
    ServerSettings {
        max_sessions: size(ssh.max_sessions),
        max_unauthenticated: size(ssh.max_unauthenticated),
        max_unauthenticated_per_source: size(ssh.max_unauthenticated_per_source),
        login_grace: Duration::from_secs(ssh.login_grace_secs),
        target_connect_timeout: Duration::from_secs(ssh.target_connect_timeout_secs),
        ..ServerSettings::default()
    }
}

/// Starts the SSH server when `[agent.ssh]` is configured: keys, listeners,
/// identity, host key sent to the core, revocations.
///
/// # Errors
///
/// A key cannot be created or read (`SSH-E007`–`SSH-E009`), or an address
/// cannot be listened on (`AGT-E010`): the agent refuses to start.
pub(crate) async fn start(
    agent: &AgentConfig,
    core: CoreSide,
    journal: Arc<FileReplayStore>,
) -> Result<Option<SshService>, (String, &'static str)> {
    let (
        Some(ssh),
        Some(SshPaths {
            host_key,
            target_key,
            host_certificate,
        }),
    ) = (&agent.ssh, agent.ssh_paths())
    else {
        return Ok(None);
    };
    let key_error = |e: String| {
        let found = ["SSH-E007", "SSH-E008", "SSH-E009"]
            .into_iter()
            .find(|c| e.contains(c))
            .unwrap_or("SSH-E008");
        (e, found)
    };
    let host = ensure_key(&host_key, "host").map_err(key_error)?;
    let target = ensure_key(&target_key, "target").map_err(key_error)?;
    let target = Arc::new(keys::load(&target).map_err(|e| key_error(e.to_string()))?);
    let (signing, _) = keys::decode(&host).map_err(|e| key_error(e.to_string()))?;

    let mut bound = Vec::with_capacity(ssh.listen.len());
    for address in &ssh.listen {
        let listener = tokio::net::TcpListener::bind(address.as_str())
            .await
            .map_err(|e| {
                (
                    format!("[{LISTEN_FAILED}] agent.ssh.listen « {address} » : {e}"),
                    LISTEN_FAILED,
                )
            })?;
        bound.push(listener);
    }

    let (identity_tx, identity) = watch::channel(None);
    let reports = Reports::default();
    let server = SshServer::new(
        settings(ssh),
        identity.clone(),
        target,
        Arc::new(TunnelAuthorizer {
            core: core.clone(),
            journal,
            reports: reports.clone(),
        }),
    );
    let (stop, stop_rx) = watch::channel(false);
    let mut listen = Vec::with_capacity(bound.len());
    let mut listeners = Vec::with_capacity(bound.len());
    for listener in bound {
        if let Ok(addr) = listener.local_addr() {
            listen.push(addr);
        }
        let server = server.clone();
        let stop = stop_rx.clone();
        listeners.push(tokio::spawn(async move {
            let _ = server.serve(listener, stop).await;
        }));
    }

    let state = Arc::new(std::sync::Mutex::new(IdentityState::default()));
    let mut helpers = Vec::new();
    if let Some(gateway) = core.gateway.get() {
        helpers.push(follow_trust(
            gateway.state().subscribe_ssh_trust(),
            IdentitySink {
                host_key: host,
                certificate_path: host_certificate,
                identity: identity_tx,
                state: state.clone(),
            },
        ));
        helpers.push(tokio::spawn(follow_revocations(
            gateway.subscribe_login_revocations(),
            server.clone(),
        )));
    }
    if let Some(link) = core.link.get() {
        helpers.push(send_host_key(link.clone(), signing));
    }
    tracing::info!(
        event = "agent.ssh_started",
        listen = ?listen,
        max_sessions = ssh.max_sessions,
        "serveur SSH natif à l'écoute"
    );
    Ok(Some(SshService {
        report: Arc::new(Report {
            server,
            listen,
            identity,
            state,
            gateway: core.gateway,
        }),
        reports,
        stop,
        listeners,
        helpers,
    }))
}

impl SshService {
    /// What the status shows, shared with the control plane.
    pub(crate) fn report(&self) -> Arc<Report> {
        self.report.clone()
    }

    /// Stops listening, disconnects the sessions, and waits until
    /// `deadline` for the sessions, those being authorised included, to end
    /// and for their reports to be sent to the core (the link is closed
    /// after); returns how many were in progress at the stop.
    pub(crate) async fn stop(self, deadline: Instant) -> usize {
        let server = &self.report.server;
        let open = server.in_progress();
        self.stop.send_replace(true);
        for listener in self.listeners {
            let _ = listener.await;
        }
        let reports = &self.reports;
        wait_idle(deadline, || {
            server.in_progress() > 0 || reports.pending() > 0
        })
        .await;
        for helper in self.helpers {
            helper.abort();
        }
        tracing::info!(
            event = "agent.ssh_stopped",
            sessions = open,
            remaining = server.in_progress(),
            reports_unsent = reports.pending()
        );
        open
    }
}

/// One `from=` entry: an IP address or a CIDR network, nothing that could
/// alter the `authorized_keys` line.
fn valid_source(entry: &str) -> bool {
    let (address, prefix) = entry
        .split_once('/')
        .map_or((entry, None), |(a, p)| (a, Some(p)));
    let Ok(ip) = address.parse::<std::net::IpAddr>() else {
        return false;
    };
    let max = if ip.is_ipv4() { 32 } else { 128 };
    prefix.is_none_or(|p| p.parse::<u8>().is_ok_and(|p| p <= max) && !p.starts_with('+'))
}

/// The `authorized_keys` line of `public` (ADR-0010): `restrict`, `pty`
/// only when asked, `from=` the agent addresses.
///
/// # Errors
///
/// An entry of `from` is not an address or a network.
pub(crate) fn authorized_keys_line(
    public: &str,
    from: &[String],
    pty: bool,
) -> Result<String, String> {
    if let Some(bad) = from.iter().find(|f| !valid_source(f)) {
        return Err(format!(
            "--from « {bad} » : adresse IP ou réseau CIDR attendu"
        ));
    }
    let sources = if from.is_empty() {
        "ADRESSES_DES_AGENTS".to_owned()
    } else {
        from.join(",")
    };
    let pty = if pty { ",pty" } else { "" };
    Ok(format!("restrict{pty},from=\"{sources}\" {public}"))
}

/// The public line of the key file at `path`.
fn public_line(path: &Path) -> Result<String, String> {
    let file = std::fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            format!(
                "{} absente : l'agent la crée à son premier démarrage. Démarrez le service, puis \
                 relancez cette commande.",
                path.display()
            )
        } else {
            format!("{} : {e}", path.display())
        }
    })?;
    let (key, comment) =
        keys::decode(&SecretBytes::from(file)).map_err(|e| format!("{} : {e}", path.display()))?;
    keys::encode(&key, &comment)
        .map(|k| k.public)
        .map_err(|e| e.to_string())
}

/// `ostena agent ssh-key`: the agent key on the targets and the
/// `authorized_keys` line to deposit (ADR-0010); `line_only` prints the
/// line alone, for configuration management.
pub(crate) fn show_key(
    agent: &AgentConfig,
    from: &[String],
    pty: bool,
    line_only: bool,
) -> Result<String, String> {
    let paths = agent
        .ssh_paths()
        .ok_or("section [agent.ssh] absente : le serveur SSH natif n'est pas configuré")?;
    let public = public_line(&paths.target_key)?;
    let line = authorized_keys_line(&public, from, pty)?;
    if line_only {
        return Ok(line);
    }
    let mut out = format!(
        "Clé de l'agent sur les cibles ({}) :\n{public}\n\nLigne authorized_keys recommandée \
         (compte cible) :\n{line}\n",
        paths.target_key.display()
    );
    if from.is_empty() {
        out.push_str(
            "\nRemplacez ADRESSES_DES_AGENTS par les adresses de tous les agents du groupe, telles \
             que les cibles les voient (après une éventuelle traduction d'adresses), ou passez \
             --from.\n",
        );
    }
    if let Ok(host) = public_line(&paths.host_key) {
        let _ = writeln!(out, "\nClé d'hôte du serveur SSH de l'agent :\n{host}");
    }
    let certificate = std::fs::read_to_string(&paths.host_certificate)
        .ok()
        .and_then(|text| STANDARD.decode(text.split_whitespace().nth(1)?).ok());
    let now = ostena_grant::unix_now();
    let _ = match certificate.as_deref().map(cert::parse) {
        Some(Ok(c)) if c.valid_before > now => writeln!(
            out,
            "Certificat d'hôte : valide encore {} h",
            (c.valid_before - now) / 3600
        ),
        Some(Ok(_)) => writeln!(out, "Certificat d'hôte : EXPIRÉ"),
        Some(Err(e)) => writeln!(out, "Certificat d'hôte : illisible ({e})"),
        None => writeln!(out, "Certificat d'hôte : pas encore reçu du core"),
    };
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default, Clone)]
    struct Counter(Arc<(AtomicUsize, AtomicUsize)>);

    impl Revoke for Counter {
        fn revoke_login(&self, _: [u8; 16]) -> usize {
            self.0.0.fetch_add(1, Ordering::SeqCst);
            0
        }
        fn revoke_all(&self) -> usize {
            self.0.1.fetch_add(1, Ordering::SeqCst);
            3
        }
    }

    fn block_on<F: Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn lost_revocations_cut_every_session() {
        block_on(async {
            let (tx, rx) = broadcast::channel(4);
            let login = Uuid::parse("7a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d").unwrap();
            // More than the channel holds before the consumer reads: lagged.
            for _ in 0..6 {
                tx.send(login).unwrap();
            }
            drop(tx);
            let counter = Counter::default();
            follow_revocations(rx, counter.clone()).await;
            assert_eq!(
                counter.0.1.load(Ordering::SeqCst),
                1,
                "one cut for the loss"
            );
            assert_eq!(counter.0.0.load(Ordering::SeqCst), 4, "then the kept ones");
        });
    }

    #[test]
    fn revocations_are_applied_one_by_one_without_loss() {
        block_on(async {
            let (tx, rx) = broadcast::channel(64);
            let counter = Counter::default();
            let task = tokio::spawn(follow_revocations(rx, counter.clone()));
            for _ in 0..3 {
                tx.send(Uuid::parse("7a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d").unwrap())
                    .unwrap();
            }
            drop(tx);
            task.await.unwrap();
            assert_eq!(counter.0.0.load(Ordering::SeqCst), 3);
            assert_eq!(counter.0.1.load(Ordering::SeqCst), 0);
        });
    }

    struct Dir(std::path::PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn dir(name: &str) -> Dir {
        let d = std::env::temp_dir().join(format!("ostena-cli-ssh-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Dir(d)
    }

    #[test]
    fn keys_are_created_private_then_read_back() {
        let d = dir("keys");
        let path = d.0.join("ssh_target_key");
        let created = ensure_key(&path, "target").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let again = ensure_key(&path, "target").unwrap();
        assert_eq!(
            keys::decode(&created).unwrap().0.verifying_key(),
            keys::decode(&again).unwrap().0.verifying_key()
        );
        let (_, comment) = keys::decode(&again).unwrap();
        assert!(comment.starts_with("ostena-agent"), "{comment}");
    }

    #[test]
    fn an_invalid_key_file_is_refused() {
        let d = dir("bad-key");
        let path = d.0.join("ssh_host_key");
        std::fs::write(&path, b"not a key").unwrap();
        assert!(
            ensure_key(&path, "host")
                .err()
                .unwrap()
                .contains("SSH-E008")
        );
    }

    #[test]
    fn authorized_keys_line_is_restricted() {
        let public = "ecdsa-sha2-nistp256 AAAA ostena-agent-gw01";
        let from = vec!["10.20.0.11".to_owned(), "10.20.0.0/24".to_owned()];
        assert_eq!(
            authorized_keys_line(public, &from, false).unwrap(),
            "restrict,from=\"10.20.0.11,10.20.0.0/24\" ecdsa-sha2-nistp256 AAAA ostena-agent-gw01"
        );
        assert!(
            authorized_keys_line(public, &["fd00::1".into()], true)
                .unwrap()
                .starts_with("restrict,pty,from=\"fd00::1\" ")
        );
        assert!(
            authorized_keys_line(public, &[], false)
                .unwrap()
                .contains("from=\"ADRESSES_DES_AGENTS\"")
        );
        for bad in [
            "10.0.0.1\",command=\"sh",
            "host.example",
            "10.0.0.0/33",
            "10.0.0.0/+8",
            "",
        ] {
            assert!(
                authorized_keys_line(public, &[bad.to_owned()], false).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn comment_is_a_plain_name() {
        let comment = key_comment();
        assert!(comment.starts_with("ostena-agent"));
        assert!(
            comment
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        );
    }

    #[test]
    fn host_certificate_is_written_as_an_openssh_line() {
        let d = dir("host-cert");
        let path = d.0.join("ssh_host_certificate");
        write_host_certificate(&path, b"blob").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            text,
            format!(
                "{} {} ostena-agent\n",
                cert::CERT_TYPE,
                STANDARD.encode(b"blob")
            )
        );
        write_host_certificate(&path, b"other").unwrap();
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains(&STANDARD.encode(b"other"))
        );
    }

    /// A host key, its host authority, and what applying a trust publishes.
    struct Trusted {
        sink: IdentitySink,
        identity: watch::Receiver<Option<Arc<SshIdentity>>>,
        host: ostena_crypto::p256::VerifyingKey,
        host_ca: SigningKey,
        _dir: Dir,
    }

    impl Trusted {
        fn new(name: &str) -> Self {
            let dir = dir(name);
            let host_key = ensure_key(&dir.0.join("ssh_host_key"), "host").unwrap();
            let host = keys::decode(&host_key).unwrap().0.verifying_key();
            let (tx, identity) = watch::channel(None);
            Self {
                sink: IdentitySink {
                    host_key,
                    certificate_path: dir.0.join("ssh_host_certificate"),
                    identity: tx,
                    state: Arc::default(),
                },
                identity,
                host,
                host_ca: SigningKey::generate().unwrap().0,
                _dir: dir,
            }
        }

        fn certificate(&self, by: &SigningKey, valid_after: u64, valid_before: u64) -> Vec<u8> {
            cert::issue(
                &cert::Template {
                    kind: cert::Kind::Host,
                    public: self.host,
                    serial: 1,
                    key_id: "agent".into(),
                    principals: vec!["gw01".into()],
                    valid_after,
                    valid_before,
                    critical_options: vec![],
                    extensions: vec![],
                },
                by,
            )
            .unwrap()
        }

        fn trust(
            &self,
            version: u64,
            certificate: Option<Vec<u8>>,
            user_cas: &[&SigningKey],
        ) -> ostena_tunnel::ssh::SshTrust {
            ostena_tunnel::ssh::SshTrust {
                version,
                user_cas: user_cas.iter().map(|k| k.verifying_key()).collect(),
                host_cas: vec![self.host_ca.verifying_key()],
                host_certificate: certificate,
            }
        }

        fn user_cas(&self) -> Option<Vec<ostena_crypto::p256::VerifyingKey>> {
            self.identity
                .borrow()
                .as_ref()
                .map(|i| i.user_authorities().to_vec())
        }

        fn state(&self) -> IdentityState {
            self.sink.state.lock().unwrap().clone()
        }
    }

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn a_trust_the_agent_cannot_apply_withdraws_the_identity() {
        let t = Trusted::new("trust-withdrawn");
        let old_ca = SigningKey::generate().unwrap().0;
        let new_ca = SigningKey::generate().unwrap().0;
        let valid = t.certificate(&t.host_ca, NOW - 60, NOW + 86_400);

        // Before the host certificate is issued: no identity, nothing to
        // withdraw.
        t.sink.apply(&t.trust(1, None, &[&old_ca]), NOW);
        assert_eq!(t.user_cas(), None);
        assert_eq!(t.state().applied, None);

        t.sink
            .apply(&t.trust(2, Some(valid.clone()), &[&old_ca]), NOW);
        assert_eq!(t.user_cas(), Some(vec![old_ca.verifying_key()]));
        assert_eq!(
            t.state(),
            IdentityState {
                applied: Some(2),
                valid_before: Some(NOW + 86_400),
                refusal: None
            }
        );

        // The same certificate with other user authorities: the new ones
        // apply.
        t.sink
            .apply(&t.trust(3, Some(valid.clone()), &[&new_ca]), NOW);
        assert_eq!(t.user_cas(), Some(vec![new_ca.verifying_key()]));
        assert_eq!(t.state().applied, Some(3));

        // Without a host certificate: the old authorities do not stay.
        t.sink.apply(&t.trust(4, None, &[&new_ca]), NOW);
        assert_eq!(t.user_cas(), None);
        let state = t.state();
        assert_eq!(state.applied, None, "the status shows no applied version");
        assert!(state.refusal.unwrap().contains("certificat d'hôte"));

        t.sink
            .apply(&t.trust(5, Some(valid.clone()), &[&new_ca]), NOW);
        assert!(t.user_cas().is_some());
        // A certificate signed by another authority: withdrawn as well.
        let stranger = SigningKey::generate().unwrap().0;
        let foreign = t.certificate(&stranger, NOW - 60, NOW + 86_400);
        t.sink.apply(&t.trust(6, Some(foreign), &[&new_ca]), NOW);
        assert_eq!(t.user_cas(), None);
        assert!(t.state().refusal.unwrap().contains("SSH-E018"));

        // No user authority: withdrawn too.
        t.sink
            .apply(&t.trust(7, Some(valid.clone()), &[&new_ca]), NOW);
        assert!(t.user_cas().is_some());
        t.sink.apply(&t.trust(8, Some(valid), &[]), NOW);
        assert_eq!(t.user_cas(), None);
        assert_eq!(t.state().applied, None);
    }

    #[test]
    fn a_stop_waits_for_the_reports_being_sent_within_the_grace() {
        block_on(async {
            let reports = Reports::default();
            assert!(wait_idle(Instant::now(), || reports.pending() > 0).await);
            let sending = reports.sending();
            let task = tokio::spawn(async move {
                let _sending = sending;
                tokio::time::sleep(Duration::from_millis(200)).await;
            });
            assert_eq!(reports.pending(), 1);
            let started = Instant::now();
            assert!(
                wait_idle(started + Duration::from_secs(5), || reports.pending() > 0).await,
                "sent before the deadline"
            );
            assert!(started.elapsed() >= Duration::from_millis(150));
            task.await.unwrap();

            // A report that never ends: the wait stops at the deadline.
            let _stuck = reports.sending();
            let started = Instant::now();
            assert!(
                !wait_idle(started + Duration::from_millis(100), || reports.pending()
                    > 0)
                .await
            );
            assert!(started.elapsed() < Duration::from_secs(2));
        });
    }
}
