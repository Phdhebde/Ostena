//! Validation rules and their stable codes.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use super::{
    CertificateValidation, Config, DisconnectedSessions, HostKeyVerification, Output, SyslogTls,
    Transport,
};

/// The only grant signature algorithm accepted in production (ADR-0004).
pub const GRANT_SIGNATURE_ALGORITHM: &str = "ecdsa-p256-sha256";

/// Signature algorithm names that are recognised, so that the other ones are
/// refused in production with a clear message rather than as unknown.
pub const KNOWN_SIGNATURE_ALGORITHMS: &[&str] = &[
    "ed25519",
    "ecdsa-p256-sha256",
    "rsa-pss-sha256",
    "hmac-sha256",
];

/// Stable error codes. They are part of the product interface: never renumber
/// or reuse one, only add new ones (ADR-0003).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Code {
    /// The configuration file cannot be read.
    Read,
    /// The configuration file cannot be parsed.
    Parse,
    /// `pki` validation without a CA bundle.
    PkiWithoutCaBundle,
    /// CA bundle set while validation is not `pki`.
    CaBundleUnused,
    /// Empty path.
    EmptyPath,
    /// Unknown grant signature algorithm.
    UnknownSignatureAlgorithm,
    /// Invalid syslog address.
    InvalidSyslogAddress,
    /// SSH host key verification is not strict.
    SshHostKeyNotStrict,
    /// RDP target certificates are neither pinned nor validated by a PKI.
    RdpCertificateNotValidated,
    /// NTLM allowed while a password is delegated.
    NtlmWithPasswordDelegation,
    /// Grant signature algorithm other than ECDSA P-256 / SHA-256.
    GrantAlgorithmNotEcdsaP256,
    /// Logs or audit sent unencrypted to another machine.
    UnencryptedRemoteOutput,
    /// Configuration file or directory writable by another account.
    ConfigFileWritableByOthers,
    /// Agent: gateway group is not a UUID.
    AgentGatewayGroup,
    /// Agent: invalid core address.
    AgentCoreAddress,
    /// Agent: relative path.
    RelativePath,
    /// Agent: value out of bounds (shutdown delay, worker threads).
    AgentBounds,
    /// Agent: invalid infrastructure declaration.
    AgentInfrastructure,
    /// Agent: no CA configured for the core certificate.
    CoreCaMissing,
    /// Agent: private key readable or writable by another account.
    PrivateKeyExposed,
    /// Agent: replay journal directory writable by another account.
    ReplayJournalExposed,
    /// Agent: an infrastructure name cannot be resolved.
    InfrastructureUnresolved,
    /// Agent: invalid control endpoint.
    ControlEndpoint,
    /// Core: value out of bounds or conflicting addresses.
    CoreBounds,
    /// Core: invalid database identifier or host.
    DatabaseIdentifier,
    /// Core: invalid key source.
    CoreKeySource,
    /// Core: CA or server key readable beyond the service account, or its
    /// directory writable by another account.
    CoreKeyExposed,
    /// Core: CA or server key read in clear from a file instead of an
    /// encrypted systemd credential (tolerated until 2027-04-30).
    CoreKeyInFile,
    /// Core: PostgreSQL reached over TCP instead of the local Unix socket.
    DatabaseOverTcp,
    /// Agent: invalid `[agent.ssh]` (address, bound, host key used as the
    /// target key).
    AgentSsh,
    /// Core: the same key source named for two keys.
    CoreKeyReused,
    /// Core: invalid `[core.login]` (bound, address, host pattern).
    CoreLogin,
    /// Core: TOTP with HMAC-SHA-1, the default; an accepted deviation
    /// (ADR-0009), logged at every start and never refused.
    TotpSha1,
    /// Core: transcript directory readable beyond the service account, or
    /// its parent writable by another account (ADR-0016).
    TranscriptsExposed,
    /// Agent: invalid `[agent.sessions]` (bound out of range).
    AgentSessions,
    /// Agent: sessions never cut for inactivity
    /// (`agent.sessions.idle_timeout_secs = 0`).
    IdleTimeoutDisabled,
    /// Core: invalid `[core.web]` (bound, address, origin).
    CoreWeb,
    /// Core: a browser session is not bound to its source.
    WebSourceNotBound,
    /// Core: the web listener accepts a classical key exchange.
    WebTlsClassic,
    /// Core: invalid `[core.identity]` (plain LDAP or another scheme than
    /// `ldaps://`, name, DN, bound, suffix routed twice).
    CoreIdentity,
    /// Core: password file of an identity source readable beyond the
    /// service account, or its directory writable by another account.
    IdentitySecretExposed,
    /// Core: an identity source admits TLS 1.2 towards its directories; an
    /// accepted deviation (ADR-0009), logged at every start and never
    /// refused.
    DirectoryTls12,
    /// Agent: Windows sessions of the target account left disconnected
    /// (`rdp.disconnected_sessions = "keep"`, ADR-0026).
    RdpSessionsKept,
    /// Core: sealed files (transcripts, recordings) written without the
    /// append-only then immutable attributes (`core.audit.worm = "disabled"`).
    WormDisabled,
    /// Invalid TLS settings of a syslog output (`tls` with a clear-text
    /// transport, certificate without its key or the reverse, key in a
    /// file instead of a systemd credential, empty path, invalid server
    /// name).
    SyslogTls,
    /// Core: one account may hold the audit role and a role that widens
    /// accesses (`core.admin.allow_role_cumulation`, ADR-0022).
    RoleCumulation,
}

impl Code {
    /// Every code, in numbering order.
    pub const ALL: [Self; 46] = [
        Self::Read,
        Self::Parse,
        Self::PkiWithoutCaBundle,
        Self::CaBundleUnused,
        Self::EmptyPath,
        Self::UnknownSignatureAlgorithm,
        Self::InvalidSyslogAddress,
        Self::SshHostKeyNotStrict,
        Self::RdpCertificateNotValidated,
        Self::NtlmWithPasswordDelegation,
        Self::GrantAlgorithmNotEcdsaP256,
        Self::UnencryptedRemoteOutput,
        Self::ConfigFileWritableByOthers,
        Self::AgentGatewayGroup,
        Self::AgentCoreAddress,
        Self::RelativePath,
        Self::AgentBounds,
        Self::AgentInfrastructure,
        Self::CoreCaMissing,
        Self::PrivateKeyExposed,
        Self::ReplayJournalExposed,
        Self::InfrastructureUnresolved,
        Self::ControlEndpoint,
        Self::CoreBounds,
        Self::DatabaseIdentifier,
        Self::CoreKeySource,
        Self::CoreKeyExposed,
        Self::CoreKeyInFile,
        Self::DatabaseOverTcp,
        Self::AgentSsh,
        Self::CoreKeyReused,
        Self::CoreLogin,
        Self::TotpSha1,
        Self::TranscriptsExposed,
        Self::AgentSessions,
        Self::IdleTimeoutDisabled,
        Self::CoreWeb,
        Self::WebSourceNotBound,
        Self::WebTlsClassic,
        Self::CoreIdentity,
        Self::IdentitySecretExposed,
        Self::DirectoryTls12,
        Self::RdpSessionsKept,
        Self::WormDisabled,
        Self::SyslogTls,
        Self::RoleCumulation,
    ];

    /// The code as written in messages and logs, e.g. `CFG-P001`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "CFG-E001",
            Self::Parse => "CFG-E002",
            Self::PkiWithoutCaBundle => "CFG-V001",
            Self::CaBundleUnused => "CFG-V002",
            Self::EmptyPath => "CFG-V003",
            Self::UnknownSignatureAlgorithm => "CFG-V004",
            Self::InvalidSyslogAddress => "CFG-V005",
            Self::SshHostKeyNotStrict => "CFG-P001",
            Self::RdpCertificateNotValidated => "CFG-P002",
            Self::NtlmWithPasswordDelegation => "CFG-P003",
            Self::GrantAlgorithmNotEcdsaP256 => "CFG-P004",
            Self::UnencryptedRemoteOutput => "CFG-P005",
            Self::ConfigFileWritableByOthers => "CFG-P006",
            Self::AgentGatewayGroup => "CFG-V006",
            Self::AgentCoreAddress => "CFG-V007",
            Self::RelativePath => "CFG-V008",
            Self::AgentBounds => "CFG-V009",
            Self::AgentInfrastructure => "CFG-V010",
            Self::CoreCaMissing => "CFG-P007",
            Self::PrivateKeyExposed => "CFG-P008",
            Self::ReplayJournalExposed => "CFG-P009",
            Self::InfrastructureUnresolved => "CFG-P010",
            Self::ControlEndpoint => "CFG-V011",
            Self::CoreBounds => "CFG-V012",
            Self::DatabaseIdentifier => "CFG-V013",
            Self::CoreKeySource => "CFG-V014",
            Self::CoreKeyExposed => "CFG-P011",
            Self::CoreKeyInFile => "CFG-P012",
            Self::DatabaseOverTcp => "CFG-P014",
            Self::AgentSsh => "CFG-V015",
            Self::CoreKeyReused => "CFG-V016",
            Self::CoreLogin => "CFG-V017",
            Self::TotpSha1 => "CFG-P015",
            Self::TranscriptsExposed => "CFG-P016",
            Self::AgentSessions => "CFG-V018",
            Self::IdleTimeoutDisabled => "CFG-P017",
            Self::CoreWeb => "CFG-V019",
            Self::WebSourceNotBound => "CFG-P018",
            Self::WebTlsClassic => "CFG-P019",
            Self::CoreIdentity => "CFG-V020",
            Self::IdentitySecretExposed => "CFG-P020",
            Self::DirectoryTls12 => "CFG-P021",
            Self::RdpSessionsKept => "CFG-P022",
            Self::WormDisabled => "CFG-P024",
            Self::SyslogTls => "CFG-V021",
            Self::RoleCumulation => "CFG-P023",
        }
    }

    /// Whether the code is a production refusal (`CFG-P…`).
    pub const fn is_weakening(self) -> bool {
        matches!(
            self,
            Self::SshHostKeyNotStrict
                | Self::CoreKeyExposed
                | Self::CoreKeyInFile
                | Self::DatabaseOverTcp
                | Self::RdpCertificateNotValidated
                | Self::NtlmWithPasswordDelegation
                | Self::GrantAlgorithmNotEcdsaP256
                | Self::UnencryptedRemoteOutput
                | Self::ConfigFileWritableByOthers
                | Self::CoreCaMissing
                | Self::PrivateKeyExposed
                | Self::ReplayJournalExposed
                | Self::InfrastructureUnresolved
                | Self::TotpSha1
                | Self::TranscriptsExposed
                | Self::IdleTimeoutDisabled
                | Self::WebSourceNotBound
                | Self::WebTlsClassic
                | Self::IdentitySecretExposed
                | Self::DirectoryTls12
                | Self::RdpSessionsKept
                | Self::WormDisabled
                | Self::RoleCumulation
        )
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One broken rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// Stable code.
    pub code: Code,
    /// Explanation in French, naming the offending field.
    pub message: String,
}

impl Violation {
    pub(crate) fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

/// All the rules broken by a configuration (never empty).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violations(Vec<Violation>);

impl Violations {
    pub(crate) fn into_result(list: Vec<Violation>) -> Result<(), Self> {
        if list.is_empty() {
            Ok(())
        } else {
            Err(Self(list))
        }
    }

    /// The violations, in rule order.
    pub fn as_slice(&self) -> &[Violation] {
        &self.0
    }

    /// Their codes, in rule order.
    pub fn codes(&self) -> Vec<Code> {
        self.0.iter().map(|v| v.code).collect()
    }
}

impl fmt::Display for Violations {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "configuration refusée ({} problème(s)) :", self.0.len())?;
        for v in &self.0 {
            write!(f, "\n  - {v}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Violations {}

/// Consistency rules (`CFG-V…`).
pub(crate) fn consistency(config: &Config) -> Vec<Violation> {
    let mut out = Vec::new();
    if let Some(agent) = &config.agent {
        super::agent::consistency(agent, &mut out);
    }
    if let Some(core) = &config.core {
        super::core::consistency(core, &mut out);
    }
    let rdp = &config.rdp;

    match (rdp.certificate_validation, &rdp.pki_ca_bundle) {
        (CertificateValidation::Pki, None) => out.push(Violation::new(
            Code::PkiWithoutCaBundle,
            "rdp.certificate_validation = \"pki\" exige rdp.pki_ca_bundle (chemin du \
             bundle des autorités de certification).",
        )),
        (CertificateValidation::Pki, Some(path)) => {
            check_path(&mut out, "rdp.pki_ca_bundle", path);
        }
        (_, Some(_)) => out.push(Violation::new(
            Code::CaBundleUnused,
            "rdp.pki_ca_bundle est renseigné mais n'est utilisé que si \
             rdp.certificate_validation = \"pki\" : supprimez-le ou changez le mode de \
             validation.",
        )),
        (_, None) => {}
    }

    let algorithm = config.grant.signature_algorithm.as_str();
    if !KNOWN_SIGNATURE_ALGORITHMS.contains(&algorithm) {
        out.push(Violation::new(
            Code::UnknownSignatureAlgorithm,
            format!(
                "grant.signature_algorithm = \"{algorithm}\" est inconnu ; seule la valeur \
                 \"{GRANT_SIGNATURE_ALGORITHM}\" est prise en charge."
            ),
        ));
    }

    for (field, output) in outputs(config) {
        match output {
            Output::Stdout {} => {}
            Output::File { path } | Output::SyslogUnix { path } => {
                check_path(&mut out, &format!("{field}.path"), path);
            }
            Output::Syslog {
                address,
                transport,
                tls,
            } => {
                if let Some(tls) = tls {
                    check_syslog_tls(&mut out, &field, *transport, tls);
                }
                if parse_host_port(address).is_none() {
                    out.push(Violation::new(
                        Code::InvalidSyslogAddress,
                        format!(
                            "{field}.address = \"{address}\" n'est pas une adresse valide ; \
                             formats attendus : hôte:port, ipv4:port ou [ipv6]:port."
                        ),
                    ));
                }
            }
        }
    }
    out
}

/// Production refusals that do not depend on the file system, at `now`
/// (Unix seconds) for the dated waivers.
pub(crate) fn weakenings(config: &Config, now: u64) -> Vec<Violation> {
    let mut out = Vec::new();
    if let Some(agent) = &config.agent {
        super::agent::weakenings(agent, &mut out);
    }
    if let Some(core) = &config.core {
        super::core::weakenings(core, now, &mut out);
    }

    if config.ssh.host_key_verification != HostKeyVerification::Strict {
        out.push(Violation::new(
            Code::SshHostKeyNotStrict,
            "ssh.host_key_verification = \"accept-new\" fait confiance à une clé hôte \
             inconnue à la première connexion ; seul \"strict\" est accepté en production.",
        ));
    }

    if config.rdp.certificate_validation == CertificateValidation::Disabled {
        out.push(Violation::new(
            Code::RdpCertificateNotValidated,
            "rdp.certificate_validation = \"none\" : les certificats des cibles RDP ne sont \
             ni épinglés ni validés par une PKI ; utilisez \"pinned\" ou \"pki\" en production.",
        ));
    }

    if config.rdp.password_delegation && config.rdp.ntlm_fallback {
        out.push(Violation::new(
            Code::NtlmWithPasswordDelegation,
            "rdp.ntlm_fallback = true alors que rdp.password_delegation = true : un repli \
             NTLM exposerait le mot de passe délégué ; désactivez ntlm_fallback en production.",
        ));
    }

    if config.rdp.disconnected_sessions == DisconnectedSessions::Keep {
        out.push(Violation::new(
            Code::RdpSessionsKept,
            "rdp.disconnected_sessions = \"keep\" : les sessions Windows du compte cible restent \
             déconnectées et une connexion suivante peut s'y rattacher (mot de passe délégué \
             en mémoire, fenêtres d'un autre administrateur) ; seul \"logoff\" est accepté \
             en production.",
        ));
    }

    let algorithm = config.grant.signature_algorithm.as_str();
    if algorithm != GRANT_SIGNATURE_ALGORITHM && KNOWN_SIGNATURE_ALGORITHMS.contains(&algorithm) {
        out.push(Violation::new(
            Code::GrantAlgorithmNotEcdsaP256,
            format!(
                "grant.signature_algorithm = \"{algorithm}\" : seuls les grants signés en \
                 ECDSA P-256 / SHA-256 sont acceptés en production."
            ),
        ));
    }

    for (field, output) in outputs(config) {
        if let Output::Syslog {
            address, transport, ..
        } = output
            && *transport != Transport::Tls
            && !is_local_address(address)
        {
            out.push(Violation::new(
                Code::UnencryptedRemoteOutput,
                format!(
                    "{field} : syslog en {transport} vers {address} envoie les journaux \
                     en clair hors de la machine ; utilisez transport = \"tls\" en \
                     production."
                ),
            ));
        }
    }
    out
}

/// Every output, with its field name for messages (`logging.outputs[0]`…).
fn outputs(config: &Config) -> impl Iterator<Item = (String, &Output)> {
    let logging = config.logging.outputs.iter().enumerate();
    let audit = config.audit.outputs.iter().enumerate();
    logging
        .map(|(i, o)| (format!("logging.outputs[{i}]"), o))
        .chain(audit.map(|(i, o)| (format!("audit.outputs[{i}]"), o)))
}

fn check_syslog_tls(out: &mut Vec<Violation>, field: &str, transport: Transport, tls: &SyslogTls) {
    let mut refuse = |why: String| {
        out.push(Violation::new(
            Code::SyslogTls,
            format!("{field}.tls : {why}"),
        ));
    };
    if transport != Transport::Tls {
        refuse(format!(
            "réglages TLS avec transport = \"{transport}\" ; retirez-les ou passez à \"tls\"."
        ));
    }
    if tls.ca.as_os_str().is_empty()
        || tls
            .certificate
            .as_ref()
            .is_some_and(|p| p.as_os_str().is_empty())
    {
        refuse("chemin vide.".into());
    }
    if matches!(tls.private_key, Some(super::KeySource::File(_))) {
        refuse(
            "private_key en clair dans un fichier : credential systemd chiffré seulement.".into(),
        );
    }
    if tls.certificate.is_some() != tls.private_key.is_some() {
        refuse("certificate et private_key vont ensemble (authentification mutuelle).".into());
    }
    if let Some(name) = &tls.server_name
        && parse_host_port(&format!("{name}:1")).is_none()
    {
        refuse(format!(
            "server_name = \"{name}\" n'est pas un nom d'hôte ni une adresse IP."
        ));
    }
}

fn check_path(out: &mut Vec<Violation>, field: &str, path: &Path) {
    if path.as_os_str().is_empty() {
        out.push(Violation::new(
            Code::EmptyPath,
            format!("{field} est un chemin vide."),
        ));
    }
}

/// Host part of a `host:port` address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Host {
    Ip(IpAddr),
    Name(String),
}

/// Parses `host:port`, `ipv4:port` or `[ipv6]:port`. No DNS resolution.
pub(crate) fn parse_host_port(address: &str) -> Option<(Host, u16)> {
    if let Ok(socket) = address.parse::<SocketAddr>() {
        return (socket.port() != 0).then_some((Host::Ip(socket.ip()), socket.port()));
    }
    let (host, port) = address.rsplit_once(':')?;
    let port = port.parse::<u16>().ok().filter(|p| *p != 0)?;
    let valid_name = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    valid_name.then(|| (Host::Name(host.to_owned()), port))
}

/// Only a literal loopback address counts as local: names are never resolved,
/// so `localhost` is treated as remote.
pub(crate) fn is_local_address(address: &str) -> bool {
    matches!(
        parse_host_port(address),
        Some((Host::Ip(ip), _)) if ip.to_canonical().is_loopback()
    )
}

/// Weakenings tolerated in production until a date, at `now` (Unix
/// seconds): accepted, and logged at every start.
pub(crate) fn tolerated(config: &Config, now: u64) -> Vec<Violation> {
    let mut out = Vec::new();
    if let Some(core) = &config.core {
        super::core::tolerated(core, now, &mut out);
    }
    out
}
