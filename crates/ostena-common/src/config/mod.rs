//! Configuration: one strict TOML file, safe defaults, two validation levels.
//!
//! - Parsing rejects unknown fields everywhere (`deny_unknown_fields`).
//! - Every default is the safest value; the default mode is production.
//! - [`Config::validate`] checks consistency and applies in every mode.
//! - [`Config::weakenings`] lists options that lower security. In production
//!   they are refused ([`Config::validate_for_production`]); in development
//!   they are only logged ([`LoadedConfig::log_weakenings`]).
//! - [`load`] also checks the file permissions (`CFG-P006`).
//!
//! All violations are reported at once, each with a stable [`Code`]. The file
//! never holds secrets: they are referenced by path and loaded into a
//! [`Secret`](crate::secret::Secret) where they are used. See ADR-0003.

pub mod agent;
pub mod core;
mod permissions;
pub mod scope;
mod validation;

use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub use self::core::{
    CoreAuditConfig, CoreConfig, CoreLoginConfig, CoreSshConfig, DatabaseConfig, DatabaseTcp,
    KeySource, TotpAlgorithmSetting,
};
pub use agent::{AgentConfig, AgentSshConfig, InfrastructureEndpoint, SshPaths};
pub use permissions::{DefaultPermissions, PermissionChecker};
pub use validation::{
    Code, GRANT_SIGNATURE_ALGORITHM, KNOWN_SIGNATURE_ALGORITHMS, Violation, Violations,
};

/// The whole configuration file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Production (default) or development.
    pub mode: Mode,
    /// Native and proxied SSH sessions.
    pub ssh: SshConfig,
    /// RDP sessions.
    pub rdp: RdpConfig,
    /// Session grants.
    pub grant: GrantConfig,
    /// Technical logs.
    pub logging: LoggingConfig,
    /// Audit export.
    pub audit: AuditConfig,
    /// Gateway agent (only on gateway hosts).
    pub agent: Option<AgentConfig>,
    /// The core (only on the core host).
    pub core: Option<CoreConfig>,
}

/// Run mode. Production refuses every weakening option.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// Weakening options are refused at startup.
    #[default]
    Production,
    /// Weakening options are accepted and logged.
    Development,
}

/// SSH settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SshConfig {
    /// How target host keys are checked.
    pub host_key_verification: HostKeyVerification,
}

/// Target host key verification. There is no way to disable it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostKeyVerification {
    /// The key must already be known.
    #[default]
    Strict,
    /// An unknown key is trusted on first use (`CFG-P001` in production).
    AcceptNew,
}

/// RDP settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RdpConfig {
    /// How target certificates are validated.
    pub certificate_validation: CertificateValidation,
    /// CA bundle used when `certificate_validation = "pki"`.
    pub pki_ca_bundle: Option<PathBuf>,
    /// The gateway injects a stored password into the session.
    pub password_delegation: bool,
    /// Falling back to NTLM is allowed when Kerberos fails.
    pub ntlm_fallback: bool,
}

/// Target RDP certificate validation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CertificateValidation {
    /// Each target certificate is pinned in the inventory.
    #[default]
    Pinned,
    /// Certificates are validated against `pki_ca_bundle`.
    Pki,
    /// No validation (`CFG-P002` in production).
    #[serde(rename = "none")]
    Disabled,
}

/// Grant settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GrantConfig {
    /// Signature algorithm. Only `ecdsa-p256-sha256` is accepted in production.
    pub signature_algorithm: String,
}

impl Default for GrantConfig {
    fn default() -> Self {
        Self {
            signature_algorithm: GRANT_SIGNATURE_ALGORITHM.to_owned(),
        }
    }
}

/// Technical log settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    /// Minimum level written.
    pub level: LogLevel,
    /// Destinations, all receiving the same JSON lines.
    pub outputs: Vec<Output>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::default(),
            outputs: vec![Output::Stdout {}],
        }
    }
}

/// Audit export settings. The sealed local chain does not depend on them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuditConfig {
    /// Export destinations (none by default).
    pub outputs: Vec<Output>,
}

/// Log level.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[expect(missing_docs, reason = "standard level names")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

/// A log or audit destination.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Output {
    /// Standard output (journald under systemd).
    // A struct variant, not a unit one: serde ignores unknown fields on unit
    // variants of internally tagged enums, even with deny_unknown_fields.
    Stdout {},
    /// A local file, opened in append mode.
    File {
        /// File path.
        path: PathBuf,
    },
    /// A syslog collector over the network.
    Syslog {
        /// `host:port`, `ipv4:port` or `[ipv6]:port`.
        address: String,
        /// Transport, TLS by default.
        #[serde(default)]
        transport: Transport,
    },
    /// The local syslog Unix socket.
    SyslogUnix {
        /// Socket path, usually `/dev/log`.
        path: PathBuf,
    },
}

/// Network transport of a syslog destination.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Transport {
    /// RFC 5425, encrypted.
    #[default]
    Tls,
    /// RFC 6587, clear text.
    Tcp,
    /// RFC 5426, clear text.
    Udp,
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tls => "tls",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        })
    }
}

/// Errors returned while loading the configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file cannot be read.
    #[error("[{}] impossible de lire le fichier de configuration {} : {source}", Code::Read, path.display())]
    Read {
        /// File path.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },
    /// The file is not valid TOML or does not match the expected structure.
    #[error("[{}] fichier de configuration invalide : {message}", Code::Parse)]
    Parse {
        /// Parser message, with line and column.
        message: String,
    },
    /// The configuration breaks one or more rules.
    #[error("{0}")]
    Invalid(Violations),
}

impl ConfigError {
    /// Stable codes of every problem carried by this error.
    pub fn codes(&self) -> Vec<Code> {
        match self {
            Self::Read { .. } => vec![Code::Read],
            Self::Parse { .. } => vec![Code::Parse],
            Self::Invalid(v) => v.codes(),
        }
    }
}

impl Config {
    /// Parses a TOML document. Does not validate.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Parse`] on invalid TOML, unknown fields or bad values.
    pub fn from_toml_str(text: &str) -> Result<Self, ConfigError> {
        toml::from_str(text).map_err(|e| ConfigError::Parse {
            message: e.to_string(),
        })
    }

    /// Consistency rules (`CFG-V…`), applied in every mode.
    ///
    /// # Errors
    ///
    /// Every rule broken, at once.
    pub fn validate(&self) -> Result<(), Violations> {
        Violations::into_result(validation::consistency(self))
    }

    /// Options that lower security (`CFG-P…`), refused in production.
    ///
    /// The rules on files (`CFG-P006`, `CFG-P008`, `CFG-P009`, `CFG-P011`)
    /// depend on the file system and are checked by [`load`].
    pub fn weakenings(&self) -> Vec<Violation> {
        self.weakenings_at(unix_now())
    }

    /// [`Config::weakenings`] at `now` (Unix seconds).
    pub fn weakenings_at(&self, now: u64) -> Vec<Violation> {
        validation::weakenings(self, now)
    }

    /// Weakenings tolerated in production until a date (`CFG-P012` until
    /// 2027-04-30), logged at every start.
    pub fn tolerated(&self) -> Vec<Violation> {
        self.tolerated_at(unix_now())
    }

    /// [`Config::tolerated`] at `now` (Unix seconds).
    pub fn tolerated_at(&self, now: u64) -> Vec<Violation> {
        validation::tolerated(self, now)
    }

    /// Consistency rules plus refusal of every weakening option.
    ///
    /// # Errors
    ///
    /// Every rule broken, at once.
    pub fn validate_for_production(&self) -> Result<(), Violations> {
        let mut all = validation::consistency(self);
        all.extend(validation::weakenings(self, unix_now()));
        Violations::into_result(all)
    }
}

/// The wall clock, Unix seconds (0 before 1970).
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A configuration ready for startup.
#[derive(Debug)]
pub struct LoadedConfig {
    /// Validated configuration.
    pub config: Config,
    /// File it was read from.
    pub path: PathBuf,
    /// Weakening options accepted because the mode is development.
    pub weakenings: Vec<Violation>,
    /// Weakenings tolerated in production until a date.
    pub tolerated: Vec<Violation>,
}

impl LoadedConfig {
    /// Logs one `config.weakening` warning per accepted weakening option.
    /// Call it once logging is initialised.
    pub fn log_weakenings(&self) {
        for w in &self.weakenings {
            tracing::warn!(
                event = "config.weakening",
                code = w.code.as_str(),
                "{}",
                w.message
            );
        }
        for w in &self.tolerated {
            tracing::warn!(
                event = "config.waiver",
                code = w.code.as_str(),
                "{}",
                w.message
            );
        }
    }
}

/// Reads, parses and validates the configuration file for startup, with the
/// default permission checks (Unix permissions; refused on Windows).
///
/// In production every weakening option, including `CFG-P006` (file or
/// directory writable by another account), is refused. In development they
/// are returned in [`LoadedConfig::weakenings`].
///
/// # Errors
///
/// [`ConfigError`] with every problem found.
pub fn load(path: &Path) -> Result<LoadedConfig, ConfigError> {
    load_with(path, &DefaultPermissions)
}

/// [`load`] with a platform permission checker (`ostena-platform` on Windows).
///
/// # Errors
///
/// [`ConfigError`] with every problem found.
pub fn load_with(
    path: &Path,
    checker: &dyn PermissionChecker,
) -> Result<LoadedConfig, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let config = Config::from_toml_str(&text)?;

    let mut weakenings = config.weakenings();
    weakenings.extend(file_rules(&config, path, checker));
    let mut errors = validation::consistency(&config);
    if config.mode == Mode::Production {
        errors.append(&mut weakenings);
    }
    let tolerated = config.tolerated();
    Violations::into_result(errors).map_err(ConfigError::Invalid)?;

    Ok(LoadedConfig {
        config,
        path: path.to_path_buf(),
        weakenings,
        tolerated,
    })
}

/// Reads, parses and checks the consistency of the configuration for
/// `ostena agent enroll`, which creates the agent key and certificate: the
/// rules on those files (`CFG-P008`) and the other weakening rules do not
/// apply yet; `agent install` and the service startup check them.
///
/// # Errors
///
/// [`ConfigError`] with every consistency problem found.
pub fn load_for_enrollment(path: &Path) -> Result<Config, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let config = Config::from_toml_str(&text)?;
    Violations::into_result(validation::consistency(&config)).map_err(ConfigError::Invalid)?;
    Ok(config)
}

/// Rules that need the file system: `CFG-P006`, for an agent `CFG-P008` and
/// `CFG-P009`, for the core `CFG-P011`.
fn file_rules(config: &Config, path: &Path, checker: &dyn PermissionChecker) -> Vec<Violation> {
    let mut out = Vec::new();
    if let Err(reason) = checker.not_writable_by_others(path) {
        out.push(Violation::new(
            Code::ConfigFileWritableByOthers,
            format!("{} : {reason}", path.display()),
        ));
    }
    if let Some(agent) = &config.agent {
        if let Err(reason) = checker.private(&agent.tls_private_key) {
            out.push(Violation::new(
                Code::PrivateKeyExposed,
                format!(
                    "agent.tls_private_key {} : {reason}",
                    agent.tls_private_key.display()
                ),
            ));
        }
        // The SSH keys are created by the agent with private rights at its
        // first start (ADR-0010): checked once they exist; before, their
        // directory is, as `private` checks the directory of a key.
        if let Some(paths) = agent.ssh_paths() {
            for (field, key) in [
                ("agent.ssh.host_key", &paths.host_key),
                ("agent.ssh.target_key", &paths.target_key),
            ] {
                let verdict = if key.exists() {
                    checker.private(key)
                } else {
                    let dir = key.parent().filter(|d| !d.as_os_str().is_empty());
                    checker.not_writable_by_others(dir.unwrap_or(key))
                };
                if let Err(reason) = verdict {
                    out.push(Violation::new(
                        Code::PrivateKeyExposed,
                        format!("{field} {} : {reason}", key.display()),
                    ));
                }
            }
        }
        // The journal may not exist yet: its directory must.
        let dir = agent
            .replay_journal
            .parent()
            .unwrap_or(&agent.replay_journal);
        if let Err(reason) = checker.not_writable_by_others(dir) {
            out.push(Violation::new(
                Code::ReplayJournalExposed,
                format!(
                    "agent.replay_journal {} : {reason}",
                    agent.replay_journal.display()
                ),
            ));
        }
    }
    if let Some(core) = &config.core {
        for (field, key) in core::key_paths(core) {
            if let Err(reason) = checker.private(key) {
                out.push(Violation::new(
                    Code::CoreKeyExposed,
                    format!("{field} {} : {reason}", key.display()),
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests;
