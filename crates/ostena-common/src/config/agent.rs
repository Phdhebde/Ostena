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

fn path_rule(out: &mut Vec<Violation>, field: &str, path: &Path) {
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

/// Consistency rules of the agent section (`CFG-V006` to `CFG-V010`).
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
