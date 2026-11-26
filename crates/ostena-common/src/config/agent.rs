//! `[agent]` section: the gateway agent (ADR-0007).

use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::scope::{InfrastructureRole, PolicySpec};
use super::validation::{Code, Violation, parse_host_port};
use crate::secret::SecretBytes;

/// Default bounded wait for sessions to end on shutdown, in seconds.
pub const DEFAULT_SHUTDOWN_GRACE_SECS: u64 = 30;
/// Default upper bound of runtime worker threads.
pub const DEFAULT_MAX_WORKER_THREADS: usize = 4;

/// Default port of the core enrolment listener.
pub const DEFAULT_ENROLLMENT_PORT: u16 = 8444;

const fn default_grace() -> u64 {
    DEFAULT_SHUTDOWN_GRACE_SECS
}

/// Gateway agent settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    /// Gateway group (UUID), also the grant audience.
    pub gateway_group: String,
    /// Core address, `host:port`.
    pub core_address: String,
    /// Transport of the tunnel to the core (ADR-0008): `auto` (default,
    /// QUIC, and TLS 1.3 over TCP on the same port if QUIC does not answer
    /// within 1 s), `quic` or `tcp`.
    #[serde(default)]
    pub transport: TunnelTransport,
    /// Core enrolment address, `host:port`; default: the host of
    /// `core_address` on port 8444 (ADR-0008).
    #[serde(default)]
    pub enrollment_address: Option<String>,
    /// Agent certificate for mTLS (public).
    pub tls_certificate: PathBuf,
    /// Agent private key for mTLS, loaded into a `Secret`.
    pub tls_private_key: PathBuf,
    /// CA that signs the core certificate. Required in production: the
    /// system roots are never trusted for the core.
    #[serde(default)]
    pub tls_core_ca: Option<PathBuf>,
    /// Anti-replay journal.
    pub replay_journal: PathBuf,
    /// Bounded wait for sessions to end on shutdown, 1 to 300 s.
    #[serde(default = "default_grace")]
    pub shutdown_grace_secs: u64,
    /// Runtime worker threads, 1 to 64; default min(4, cores).
    #[serde(default)]
    pub worker_threads: Option<usize>,
    /// Local control plane: a socket path (Linux, default
    /// `/run/ostena/agent.sock`) or a pipe name (Windows, default
    /// `\\.\pipe\ostena-agent`).
    #[serde(default)]
    pub control_endpoint: Option<String>,
    /// Scope policy of the gateway group.
    #[serde(default)]
    pub scope: PolicySpec,
    /// Ostena components, refused as targets (`SCP-E016`); names are resolved
    /// at startup and refreshed.
    #[serde(default)]
    pub infrastructure: Vec<InfrastructureEndpoint>,
    /// Native SSH server of the agent (ADR-0010); absent: no SSH server.
    #[serde(default)]
    pub ssh: Option<AgentSshConfig>,
    /// Quotas and delays of the sessions, every protocol (ADR-0018).
    #[serde(default)]
    pub sessions: AgentSessionsConfig,
}

/// Default bound of the sessions of an agent, every protocol.
pub const DEFAULT_MAX_SESSIONS: u32 = 64;
/// Default bound of the sessions of one user at once (ADR-0018).
pub const DEFAULT_MAX_SESSIONS_PER_USER: u32 = 8;
/// Default bound of the sessions towards one resource at once (ADR-0018).
pub const DEFAULT_MAX_SESSIONS_PER_TARGET: u32 = 8;
/// Default idle delay of a session, in seconds (ADR-0018).
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 900;

const fn default_max_sessions_per_user() -> u32 {
    DEFAULT_MAX_SESSIONS_PER_USER
}
const fn default_max_sessions_per_target() -> u32 {
    DEFAULT_MAX_SESSIONS_PER_TARGET
}
const fn default_idle_timeout() -> u64 {
    DEFAULT_IDLE_TIMEOUT_SECS
}

/// `[agent.sessions]`: the quotas and delays of the session manager of the
/// agent, common to every protocol (SSH, RDP, web; ADR-0018).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSessionsConfig {
    /// Sessions of the agent at once, every protocol, 1 to 1 024; default
    /// `agent.ssh.max_sessions` if set (jalon M1), else 64.
    #[serde(default)]
    pub max_sessions: Option<u32>,
    /// Sessions of one user at once, 1 to 256.
    #[serde(default = "default_max_sessions_per_user")]
    pub max_sessions_per_user: u32,
    /// Sessions towards one resource at once, 1 to 256.
    #[serde(default = "default_max_sessions_per_target")]
    pub max_sessions_per_target: u32,
    /// A session without activity of the user for this long is cut, 60 to
    /// 86 400 s; 0: never (`CFG-P017` in production).
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
}

impl Default for AgentSessionsConfig {
    fn default() -> Self {
        Self {
            max_sessions: None,
            max_sessions_per_user: DEFAULT_MAX_SESSIONS_PER_USER,
            max_sessions_per_target: DEFAULT_MAX_SESSIONS_PER_TARGET,
            idle_timeout_secs: DEFAULT_IDLE_TIMEOUT_SECS,
        }
    }
}

/// The bounds of the session manager, defaults applied (the agent builds
/// its `ostena_session::Limits` from them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionBounds {
    /// Sessions of the agent at once.
    pub max_sessions: u32,
    /// Sessions of one user at once.
    pub max_sessions_per_user: u32,
    /// Sessions towards one resource at once.
    pub max_sessions_per_target: u32,
    /// Idle delay; `None`: never (development only).
    pub idle_timeout_secs: Option<u64>,
}

/// Transport of the tunnel to the core (ADR-0008). TCP is a performance
/// downgrade, not a security one: TLS and its algorithms are the same.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelTransport {
    /// QUIC first, TLS 1.3 over TCP in parallel after 1 s without answer.
    #[default]
    Auto,
    /// QUIC only.
    Quic,
    /// TLS 1.3 over TCP only (UDP blocked on the path).
    Tcp,
}

/// Default bound of the SSH connections not yet authenticated.
pub const DEFAULT_SSH_MAX_UNAUTHENTICATED: u32 = 16;
/// Default bound of the SSH connections not yet authenticated from one
/// source address.
pub const DEFAULT_SSH_MAX_UNAUTHENTICATED_PER_SOURCE: u32 = 4;
/// Default delay to authenticate, in seconds.
pub const DEFAULT_SSH_LOGIN_GRACE_SECS: u64 = 30;
/// Default delay to reach a target, in seconds.
pub const DEFAULT_SSH_TARGET_CONNECT_TIMEOUT_SECS: u64 = 5;
/// Default file names of the SSH identity, in the state directory (the
/// directory of `agent.replay_journal`).
pub const DEFAULT_SSH_HOST_KEY: &str = "ssh_host_key";
/// See [`DEFAULT_SSH_HOST_KEY`].
pub const DEFAULT_SSH_TARGET_KEY: &str = "ssh_target_key";
/// See [`DEFAULT_SSH_HOST_KEY`].
pub const DEFAULT_SSH_HOST_CERTIFICATE: &str = "ssh_host_certificate";

const fn default_ssh_max_unauthenticated() -> u32 {
    DEFAULT_SSH_MAX_UNAUTHENTICATED
}
const fn default_ssh_max_unauthenticated_per_source() -> u32 {
    DEFAULT_SSH_MAX_UNAUTHENTICATED_PER_SOURCE
}
const fn default_ssh_login_grace() -> u64 {
    DEFAULT_SSH_LOGIN_GRACE_SECS
}
const fn default_ssh_connect_timeout() -> u64 {
    DEFAULT_SSH_TARGET_CONNECT_TIMEOUT_SECS
}

/// `[agent.ssh]`: the native SSH server of the agent and its driver to the
/// targets (ADR-0010).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSshConfig {
    /// Addresses to listen on, `host:port` (at least one).
    pub listen: Vec<String>,
    /// Host key of the server (private); default: `ssh_host_key` in the
    /// state directory.
    #[serde(default)]
    pub host_key: Option<PathBuf>,
    /// Key of the agent on the targets (private); default: `ssh_target_key`
    /// in the state directory. Never the host key.
    #[serde(default)]
    pub target_key: Option<PathBuf>,
    /// Host certificate issued by the core; default:
    /// `ssh_host_certificate` in the state directory.
    #[serde(default)]
    pub host_certificate: Option<PathBuf>,
    /// Obsolete (jalon M1): the bound of the agent sessions when
    /// `[agent.sessions] max_sessions` is not set, 1 to 256.
    #[serde(default)]
    pub max_sessions: Option<u32>,
    /// Connections not yet authenticated, 1 to 256.
    #[serde(default = "default_ssh_max_unauthenticated")]
    pub max_unauthenticated: u32,
    /// Connections not yet authenticated from one source address, 1 to 256
    /// (within `max_unauthenticated` anyway).
    #[serde(default = "default_ssh_max_unauthenticated_per_source")]
    pub max_unauthenticated_per_source: u32,
    /// Delay to authenticate, 5 to 120 s.
    #[serde(default = "default_ssh_login_grace")]
    pub login_grace_secs: u64,
    /// Delay to reach a target, 1 to 30 s.
    #[serde(default = "default_ssh_connect_timeout")]
    pub target_connect_timeout_secs: u64,
}

/// The paths of the SSH identity, defaults applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshPaths {
    /// Host key.
    pub host_key: PathBuf,
    /// Key on the targets.
    pub target_key: PathBuf,
    /// Host certificate.
    pub host_certificate: PathBuf,
}

/// Addresses of an Ostena component: names, IP addresses or CIDR networks.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfrastructureEndpoint {
    /// Component.
    pub role: InfrastructureRole,
    /// Names, addresses or networks.
    pub addresses: Vec<String>,
}

impl AgentConfig {
    /// Worker threads to start.
    pub fn worker_threads(&self) -> usize {
        self.worker_threads.unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map_or(1, std::num::NonZero::get)
                .min(DEFAULT_MAX_WORKER_THREADS)
        })
    }

    /// The scope policy, with the gateway group filled in.
    pub fn scope_policy(&self) -> PolicySpec {
        PolicySpec {
            gateway_group: self.gateway_group.clone(),
            ..self.scope.clone()
        }
    }

    /// The enrolment address: `enrollment_address`, or the host of
    /// `core_address` on [`DEFAULT_ENROLLMENT_PORT`].
    pub fn enrollment_address(&self) -> String {
        self.enrollment_address.clone().unwrap_or_else(|| {
            let host = self
                .core_address
                .rsplit_once(':')
                .map_or(self.core_address.as_str(), |(host, _)| host);
            format!("{host}:{DEFAULT_ENROLLMENT_PORT}")
        })
    }

    /// Reads the private key into a secret.
    ///
    /// # Errors
    ///
    /// The file cannot be read.
    pub fn read_private_key(&self) -> std::io::Result<SecretBytes> {
        std::fs::read(&self.tls_private_key).map(SecretBytes::from)
    }

    /// The bounds of the session manager, defaults applied.
    pub fn session_bounds(&self) -> SessionBounds {
        let sessions = &self.sessions;
        SessionBounds {
            max_sessions: sessions
                .max_sessions
                .or_else(|| self.ssh.as_ref().and_then(|s| s.max_sessions))
                .unwrap_or(DEFAULT_MAX_SESSIONS),
            max_sessions_per_user: sessions.max_sessions_per_user,
            max_sessions_per_target: sessions.max_sessions_per_target,
            idle_timeout_secs: (sessions.idle_timeout_secs != 0)
                .then_some(sessions.idle_timeout_secs),
        }
    }

    /// The state directory: the directory of the replay journal.
    pub fn state_dir(&self) -> &Path {
        self.replay_journal
            .parent()
            .unwrap_or(self.replay_journal.as_path())
    }

    /// The SSH identity paths, defaults in [`AgentConfig::state_dir`];
    /// `None` without `[agent.ssh]`.
    pub fn ssh_paths(&self) -> Option<SshPaths> {
        let ssh = self.ssh.as_ref()?;
        let dir = self.state_dir();
        let or = |path: &Option<PathBuf>, name| path.clone().unwrap_or_else(|| dir.join(name));
        Some(SshPaths {
            host_key: or(&ssh.host_key, DEFAULT_SSH_HOST_KEY),
            target_key: or(&ssh.target_key, DEFAULT_SSH_TARGET_KEY),
            host_certificate: or(&ssh.host_certificate, DEFAULT_SSH_HOST_CERTIFICATE),
        })
    }
}

/// Rules of `[agent.ssh]` (`CFG-V015`, `CFG-V008` for relative paths).
fn ssh_consistency(agent: &AgentConfig, out: &mut Vec<Violation>) {
    let (Some(ssh), Some(paths)) = (&agent.ssh, agent.ssh_paths()) else {
        return;
    };
    if ssh.listen.is_empty() {
        out.push(Violation::new(
            Code::AgentSsh,
            "agent.ssh.listen est vide : au moins une adresse hôte:port est requise.",
        ));
    }
    for (i, address) in ssh.listen.iter().enumerate() {
        if parse_host_port(address).is_none() {
            out.push(Violation::new(
                Code::AgentSsh,
                format!(
                    "agent.ssh.listen[{i}] = « {address} » : attendu hôte:port, ipv4:port ou \
                     [ipv6]:port."
                ),
            ));
        }
    }
    let optional = ssh
        .max_sessions
        .map(|v| ("max_sessions", u64::from(v), 1..=256));
    let bounds: [(&str, u64, std::ops::RangeInclusive<u64>); 4] = [
        (
            "max_unauthenticated",
            u64::from(ssh.max_unauthenticated),
            1..=256,
        ),
        (
            "max_unauthenticated_per_source",
            u64::from(ssh.max_unauthenticated_per_source),
            1..=256,
        ),
        ("login_grace_secs", ssh.login_grace_secs, 5..=120),
        (
            "target_connect_timeout_secs",
            ssh.target_connect_timeout_secs,
            1..=30,
        ),
    ];
    for (field, value, range) in bounds.into_iter().chain(optional) {
        if !range.contains(&value) {
            out.push(Violation::new(
                Code::AgentSsh,
                format!(
                    "agent.ssh.{field} = {value} : attendu de {} à {}.",
                    range.start(),
                    range.end()
                ),
            ));
        }
    }
    for (field, path) in [
        ("agent.ssh.host_key", &ssh.host_key),
        ("agent.ssh.target_key", &ssh.target_key),
        ("agent.ssh.host_certificate", &ssh.host_certificate),
    ] {
        if let Some(path) = path {
            path_rule(out, field, path);
        }
    }
    if paths.host_key == paths.target_key {
        out.push(Violation::new(
            Code::AgentSsh,
            "agent.ssh.host_key et agent.ssh.target_key désignent le même fichier : la clé \
             d'hôte de l'agent ne doit jamais servir à se connecter aux cibles.",
        ));
    }
}

/// Rules of `[agent.sessions]` (`CFG-V018`).
fn sessions_consistency(sessions: &AgentSessionsConfig, out: &mut Vec<Violation>) {
    let bounds = [
        (
            "max_sessions",
            sessions.max_sessions.map(u64::from),
            1..=1024,
        ),
        (
            "max_sessions_per_user",
            Some(u64::from(sessions.max_sessions_per_user)),
            1..=256,
        ),
        (
            "max_sessions_per_target",
            Some(u64::from(sessions.max_sessions_per_target)),
            1..=256,
        ),
    ];
    for (field, value, range) in bounds {
        if let Some(value) = value
            && !range.contains(&value)
        {
            out.push(Violation::new(
                Code::AgentSessions,
                format!(
                    "agent.sessions.{field} = {value} : attendu de {} à {}.",
                    range.start(),
                    range.end()
                ),
            ));
        }
    }
    let idle = sessions.idle_timeout_secs;
    if idle != 0 && !(60..=86_400).contains(&idle) {
        out.push(Violation::new(
            Code::AgentSessions,
            format!(
                "agent.sessions.idle_timeout_secs = {idle} : attendu 0 (jamais) ou de 60 à 86 400."
            ),
        ));
    }
}

/// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, hexadecimal.
fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// Name, IP address or `address/prefix`: a syntax check only, the scope
/// crate validates the networks strictly when compiling the policy.
fn is_address_like(s: &str) -> bool {
    let (addr, prefix) = s.split_once('/').map_or((s, None), |(a, p)| (a, Some(p)));
    let prefix_ok = prefix
        .is_none_or(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()));
    let addr_ok = if addr.contains(':') {
        addr.parse::<std::net::Ipv6Addr>().is_ok()
    } else {
        !addr.is_empty()
            && addr.len() <= 253
            && addr
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
    };
    prefix_ok && addr_ok
}

pub(crate) fn path_rule(out: &mut Vec<Violation>, field: &str, path: &Path) {
    if path.as_os_str().is_empty() {
        out.push(Violation::new(
            Code::EmptyPath,
            format!("{field} est un chemin vide."),
        ));
    } else if !path.has_root() {
        out.push(Violation::new(
            Code::RelativePath,
            format!(
                "{field} = « {} » doit être un chemin absolu.",
                path.display()
            ),
        ));
    }
}

/// Consistency rules of the agent section (`CFG-V006` to `CFG-V010`,
/// `CFG-V015`).
pub(crate) fn consistency(agent: &AgentConfig, out: &mut Vec<Violation>) {
    if !is_uuid(&agent.gateway_group) {
        out.push(Violation::new(
            Code::AgentGatewayGroup,
            format!(
                "agent.gateway_group = « {} » n'est pas un UUID.",
                agent.gateway_group
            ),
        ));
    }
    if parse_host_port(&agent.core_address).is_none() {
        out.push(Violation::new(
            Code::AgentCoreAddress,
            format!(
                "agent.core_address = « {} » : attendu hôte:port, ipv4:port ou [ipv6]:port.",
                agent.core_address
            ),
        ));
    }
    if let Some(address) = &agent.enrollment_address
        && parse_host_port(address).is_none()
    {
        out.push(Violation::new(
            Code::AgentCoreAddress,
            format!(
                "agent.enrollment_address = « {address} » : attendu hôte:port, ipv4:port ou [ipv6]:port."
            ),
        ));
    }
    path_rule(out, "agent.tls_certificate", &agent.tls_certificate);
    path_rule(out, "agent.tls_private_key", &agent.tls_private_key);
    if let Some(ca) = &agent.tls_core_ca {
        path_rule(out, "agent.tls_core_ca", ca);
    }
    path_rule(out, "agent.replay_journal", &agent.replay_journal);
    if !(1..=300).contains(&agent.shutdown_grace_secs) {
        out.push(Violation::new(
            Code::AgentBounds,
            format!(
                "agent.shutdown_grace_secs = {} : attendu de 1 à 300.",
                agent.shutdown_grace_secs
            ),
        ));
    }
    if let Some(n) = agent.worker_threads
        && !(1..=64).contains(&n)
    {
        out.push(Violation::new(
            Code::AgentBounds,
            format!("agent.worker_threads = {n} : attendu de 1 à 64."),
        ));
    }
    if let Some(endpoint) = &agent.control_endpoint {
        let pipe = endpoint
            .strip_prefix(r"\\.\pipe\")
            .is_some_and(|name| !name.is_empty() && !name.contains('\\'));
        // sun_path holds 108 bytes, terminator included.
        let socket = endpoint.starts_with('/') && endpoint.len() < 108;
        if !(pipe || socket) {
            out.push(Violation::new(
                Code::ControlEndpoint,
                format!(
                    "agent.control_endpoint = « {endpoint} » : chemin de socket absolu ou nom de pipe \
                     \\\\.\\pipe\\… attendu."
                ),
            ));
        }
    }
    if !agent.scope.infrastructure.is_empty() {
        out.push(Violation::new(
            Code::AgentInfrastructure,
            "agent.scope.infrastructure : déclarez les composants Ostena dans [[agent.infrastructure]] \
             (les noms y sont résolus et rafraîchis).",
        ));
    }
    if !agent.scope.gateway_group.is_empty() && agent.scope.gateway_group != agent.gateway_group {
        out.push(Violation::new(
            Code::AgentInfrastructure,
            "agent.scope.gateway_group diffère de agent.gateway_group : retirez-le, il est repris \
             automatiquement.",
        ));
    }
    ssh_consistency(agent, out);
    sessions_consistency(&agent.sessions, out);
    for (i, endpoint) in agent.infrastructure.iter().enumerate() {
        if endpoint.addresses.is_empty() {
            out.push(Violation::new(
                Code::AgentInfrastructure,
                format!("agent.infrastructure[{i}].addresses est vide."),
            ));
        }
        for (j, a) in endpoint.addresses.iter().enumerate() {
            if !is_address_like(a) {
                out.push(Violation::new(
                    Code::AgentInfrastructure,
                    format!("agent.infrastructure[{i}].addresses[{j}] = « {a} » : nom, adresse IP ou réseau CIDR attendu."),
                ));
            }
        }
    }
}

/// Production refusals of the agent section that do not need the file
/// system (`CFG-P007`).
pub(crate) fn weakenings(agent: &AgentConfig, out: &mut Vec<Violation>) {
    if agent.tls_core_ca.is_none() {
        out.push(Violation::new(
            Code::CoreCaMissing,
            "agent.tls_core_ca absent : le certificat du core doit être validé par une CA dédiée, \
             jamais par les racines du système.",
        ));
    }
    if agent.sessions.idle_timeout_secs == 0 {
        out.push(Violation::new(
            Code::IdleTimeoutDisabled,
            "agent.sessions.idle_timeout_secs = 0 : une session laissée ouverte sans activité \
             n'est jamais coupée ; choisissez un délai de 60 à 86 400 s en production.",
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuids() {
        assert!(is_uuid("2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6"));
        assert!(is_uuid("2F6C9A4E-1B2C-4D5E-8F90-A1B2C3D4E5F6"));
        for bad in [
            "",
            "2f6c9a4e1b2c4d5e8f90a1b2c3d4e5f6",
            "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5fg",
            "{2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6}",
        ] {
            assert!(!is_uuid(bad), "{bad}");
        }
    }

    #[test]
    fn address_like() {
        for ok in [
            "core.corp.example",
            "10.0.0.5",
            "10.0.0.0/24",
            "2001:db8::5",
            "2001:db8::/64",
        ] {
            assert!(is_address_like(ok), "{ok}");
        }
        for bad in ["", "a b", "core_1.example", "http://core", "bücher.example"] {
            assert!(!is_address_like(bad), "{bad}");
        }
    }
}
