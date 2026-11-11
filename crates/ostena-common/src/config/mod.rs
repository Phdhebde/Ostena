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

mod permissions;
mod validation;

use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub use validation::{Code, KNOWN_SIGNATURE_ALGORITHMS, Violation, Violations};

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
    /// Signature algorithm. Only `ed25519` is accepted in production.
    pub signature_algorithm: String,
}

impl Default for GrantConfig {
    fn default() -> Self {
        Self {
            signature_algorithm: "ed25519".to_owned(),
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

    /// Options that lower security (`CFG-P001` to `CFG-P005`).
    ///
    /// `CFG-P006` depends on the file system and is checked by [`load`].
    pub fn weakenings(&self) -> Vec<Violation> {
        validation::weakenings(self)
    }

    /// Consistency rules plus refusal of every weakening option.
    ///
    /// # Errors
    ///
    /// Every rule broken, at once.
    pub fn validate_for_production(&self) -> Result<(), Violations> {
        let mut all = validation::consistency(self);
        all.extend(validation::weakenings(self));
        Violations::into_result(all)
    }
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
    }
}

/// Reads, parses and validates the configuration file for startup.
///
/// In production every weakening option, including `CFG-P006` (file or
/// directory writable by another account), is refused. In development they
/// are returned in [`LoadedConfig::weakenings`].
///
/// # Errors
///
/// [`ConfigError`] with every problem found.
pub fn load(path: &Path) -> Result<LoadedConfig, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let config = Config::from_toml_str(&text)?;

    let mut weakenings = config.weakenings();
    weakenings.extend(permissions::check(path));
    let mut errors = validation::consistency(&config);
    if config.mode == Mode::Production {
        errors.append(&mut weakenings);
    }
    Violations::into_result(errors).map_err(ConfigError::Invalid)?;

    Ok(LoadedConfig {
        config,
        path: path.to_path_buf(),
        weakenings,
    })
}

#[cfg(test)]
mod tests;
