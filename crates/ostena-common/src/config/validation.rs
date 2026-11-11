//! Validation rules and their stable codes.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use super::{CertificateValidation, Config, HostKeyVerification, Output, Transport};

/// Signature algorithm names that are recognised, so that the non-EdDSA ones
/// are refused in production with a clear message rather than as unknown.
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
    /// Grant signature algorithm other than Ed25519.
    GrantAlgorithmNotEd25519,
    /// Logs or audit sent unencrypted to another machine.
    UnencryptedRemoteOutput,
    /// Configuration file or directory writable by another account.
    ConfigFileWritableByOthers,
}

impl Code {
    /// Every code, in numbering order.
    pub const ALL: [Self; 13] = [
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
        Self::GrantAlgorithmNotEd25519,
        Self::UnencryptedRemoteOutput,
        Self::ConfigFileWritableByOthers,
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
            Self::GrantAlgorithmNotEd25519 => "CFG-P004",
            Self::UnencryptedRemoteOutput => "CFG-P005",
            Self::ConfigFileWritableByOthers => "CFG-P006",
        }
    }

    /// Whether the code is a production refusal (`CFG-P…`).
    pub const fn is_weakening(self) -> bool {
        matches!(
            self,
            Self::SshHostKeyNotStrict
                | Self::RdpCertificateNotValidated
                | Self::NtlmWithPasswordDelegation
                | Self::GrantAlgorithmNotEd25519
                | Self::UnencryptedRemoteOutput
                | Self::ConfigFileWritableByOthers
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
                 \"ed25519\" est prise en charge."
            ),
        ));
    }

    for (field, output) in outputs(config) {
        match output {
            Output::Stdout {} => {}
            Output::File { path } | Output::SyslogUnix { path } => {
                check_path(&mut out, &format!("{field}.path"), path);
            }
            Output::Syslog { address, .. } => {
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

/// Production refusals that do not depend on the file system (`CFG-P001` to `CFG-P005`).
pub(crate) fn weakenings(config: &Config) -> Vec<Violation> {
    let mut out = Vec::new();

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

    let algorithm = config.grant.signature_algorithm.as_str();
    if algorithm != "ed25519" && KNOWN_SIGNATURE_ALGORITHMS.contains(&algorithm) {
        out.push(Violation::new(
            Code::GrantAlgorithmNotEd25519,
            format!(
                "grant.signature_algorithm = \"{algorithm}\" : seuls les grants signés en \
                 Ed25519 (EdDSA) sont acceptés en production."
            ),
        ));
    }

    for (field, output) in outputs(config) {
        if let Output::Syslog { address, transport } = output
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
