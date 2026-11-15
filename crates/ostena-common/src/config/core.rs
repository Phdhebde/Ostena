//! `[core]` section: the core (ADR-0011).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::agent::path_rule;
use super::validation::{Code, Violation};

/// Default validity of an agent certificate, in days.
pub const DEFAULT_AGENT_CERTIFICATE_DAYS: u32 = 30;
/// Default directory of the PostgreSQL Unix socket (Debian).
pub const DEFAULT_SOCKET_DIR: &str = "/var/run/postgresql";
/// Default size of the connection pool.
pub const DEFAULT_MAX_CONNECTIONS: u32 = 8;

/// Core keys in plain files are tolerated until this instant (exclusive,
/// 2027-05-01T00:00:00Z): a dated waiver for M1, refused afterwards
/// (`CFG-P012`, ADR-0011).
pub const KEY_FILE_WAIVER_END: u64 = 1_809_129_600;
/// The last day of the waiver, for messages.
pub const KEY_FILE_WAIVER_LAST_DAY: &str = "2027-04-30";

const fn default_certificate_days() -> u32 {
    DEFAULT_AGENT_CERTIFICATE_DAYS
}

/// Core settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreConfig {
    /// Address of the tunnel listener (QUIC), e.g. `0.0.0.0:8443`.
    pub tunnel_listen: SocketAddr,
    /// Address of the enrolment listener (QUIC, bound only while a token is
    /// valid); default: the address of `tunnel_listen` on port 8444.
    #[serde(default)]
    pub enrollment_listen: Option<SocketAddr>,
    /// The offline root (`root.pem`), which signs the server certificate
    /// and the issuing CA.
    pub tls_root_ca: PathBuf,
    /// Server certificate presented to the agents (`server.pem`).
    pub tls_certificate: PathBuf,
    /// Its private key.
    pub tls_private_key: KeySource,
    /// Issuing CA certificate (`issuing.pem`), agent certificates only.
    pub issuing_certificate: PathBuf,
    /// Its private key.
    pub issuing_private_key: KeySource,
    /// Validity of agent certificates, 1 to 90 days.
    #[serde(default = "default_certificate_days")]
    pub agent_certificate_days: u32,
    /// Runtime worker threads, 1 to 64; default min(4, cores).
    #[serde(default)]
    pub worker_threads: Option<usize>,
    /// The PostgreSQL database.
    #[serde(default)]
    pub database: DatabaseConfig,
}

/// Where a private key of the core is read.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum KeySource {
    /// A systemd credential (`LoadCredentialEncrypted=`), read from
    /// `$CREDENTIALS_DIRECTORY/<name>`.
    Credential(String),
    /// A plain PKCS#8 file (`CFG-P012`: tolerated until 2027-04-30).
    File(PathBuf),
}

/// PostgreSQL settings. Production goes through the local Unix socket with
/// `peer` authentication only: no password, no network.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DatabaseConfig {
    /// Directory of the Unix socket.
    pub socket_dir: PathBuf,
    /// Server port (it names the socket file, `.s.PGSQL.<port>`).
    pub port: u16,
    /// Database name.
    pub name: String,
    /// Role, which owns the schema; with `peer`, the service account name.
    pub user: String,
    /// Connection pool size, 1 to 64.
    pub max_connections: u32,
    /// Connection timeout, 1 to 60 s.
    pub connect_timeout_secs: u64,
    /// TCP instead of the socket: development only (`CFG-P014`).
    pub tcp: Option<DatabaseTcp>,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            socket_dir: PathBuf::from(DEFAULT_SOCKET_DIR),
            port: 5432,
            name: "ostena".into(),
            user: "ostena".into(),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            connect_timeout_secs: 5,
            tcp: None,
        }
    }
}

/// A TCP connection to PostgreSQL, in clear text: development only.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseTcp {
    /// Host name or IP address.
    pub host: String,
    /// File holding the password (SCRAM), if the server asks for one.
    #[serde(default)]
    pub password_file: Option<PathBuf>,
}

impl CoreConfig {
    /// The enrolment address: `enrollment_listen`, or the address of
    /// `tunnel_listen` on port 8444.
    pub fn enrollment_listen(&self) -> SocketAddr {
        self.enrollment_listen.unwrap_or_else(|| {
            SocketAddr::new(
                self.tunnel_listen.ip(),
                super::agent::DEFAULT_ENROLLMENT_PORT,
            )
        })
    }

    /// Worker threads to start.
    pub fn worker_threads(&self) -> usize {
        self.worker_threads.unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map_or(1, std::num::NonZero::get)
                .min(super::agent::DEFAULT_MAX_WORKER_THREADS)
        })
    }

    /// The two private keys, with their field names.
    pub fn keys(&self) -> [(&'static str, &KeySource); 2] {
        [
            ("core.tls_private_key", &self.tls_private_key),
            ("core.issuing_private_key", &self.issuing_private_key),
        ]
    }
}

/// A PostgreSQL identifier we accept unquoted: lower case, digits and `_`,
/// not starting with a digit, at most 63 bytes.
fn is_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && !s.starts_with(|c: char| c.is_ascii_digit())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// A systemd credential name: no path separator, not empty.
fn is_credential_name(s: &str) -> bool {
    !s.is_empty() && s != "." && s != ".." && !s.contains(['/', '\\', '\0'])
}

fn bounds(out: &mut Vec<Violation>, field: &str, value: u64, min: u64, max: u64) {
    if !(min..=max).contains(&value) {
        out.push(Violation::new(
            Code::CoreBounds,
            format!("{field} = {value} : attendu de {min} à {max}."),
        ));
    }
}

/// Consistency rules of the core section (`CFG-V008`, `CFG-V012` to
/// `CFG-V014`).
pub(crate) fn consistency(core: &CoreConfig, out: &mut Vec<Violation>) {
    path_rule(out, "core.tls_root_ca", &core.tls_root_ca);
    path_rule(out, "core.tls_certificate", &core.tls_certificate);
    path_rule(out, "core.issuing_certificate", &core.issuing_certificate);
    for (field, key) in core.keys() {
        match key {
            KeySource::File(path) => path_rule(out, field, path),
            KeySource::Credential(name) if !is_credential_name(name) => {
                out.push(Violation::new(
                    Code::CoreKeySource,
                    format!(
                        "{field} = {{ credential = « {name} » }} : nom de credential systemd \
                         sans séparateur attendu."
                    ),
                ));
            }
            KeySource::Credential(_) => {}
        }
    }
    if core.enrollment_listen() == core.tunnel_listen {
        out.push(Violation::new(
            Code::CoreBounds,
            "core.enrollment_listen doit différer de core.tunnel_listen.",
        ));
    }
    bounds(
        out,
        "core.agent_certificate_days",
        u64::from(core.agent_certificate_days),
        1,
        90,
    );
    if let Some(n) = core.worker_threads {
        bounds(
            out,
            "core.worker_threads",
            u64::try_from(n).unwrap_or(u64::MAX),
            1,
            64,
        );
    }
    let db = &core.database;
    path_rule(out, "core.database.socket_dir", &db.socket_dir);
    for (field, value) in [
        ("core.database.name", &db.name),
        ("core.database.user", &db.user),
    ] {
        if !is_identifier(value) {
            out.push(Violation::new(
                Code::DatabaseIdentifier,
                format!(
                    "{field} = « {value} » : minuscules, chiffres et « _ » attendus \
                     (63 octets au plus, sans chiffre en tête)."
                ),
            ));
        }
    }
    bounds(
        out,
        "core.database.max_connections",
        u64::from(db.max_connections),
        1,
        64,
    );
    bounds(
        out,
        "core.database.connect_timeout_secs",
        db.connect_timeout_secs,
        1,
        60,
    );
    if db.port == 0 {
        out.push(Violation::new(
            Code::CoreBounds,
            "core.database.port = 0 : port attendu.",
        ));
    }
    if let Some(tcp) = &db.tcp {
        if tcp.host.is_empty() {
            out.push(Violation::new(
                Code::DatabaseIdentifier,
                "core.database.tcp.host est vide.",
            ));
        }
        if let Some(file) = &tcp.password_file {
            path_rule(out, "core.database.tcp.password_file", file);
        }
    }
}

/// Production refusals of the core section that do not need the file
/// system: `CFG-P014`, and `CFG-P012` once the waiver has ended (`now`, Unix
/// seconds).
pub(crate) fn weakenings(core: &CoreConfig, now: u64, out: &mut Vec<Violation>) {
    if core.database.tcp.is_some() {
        out.push(Violation::new(
            Code::DatabaseOverTcp,
            "core.database.tcp : en production, le core joint PostgreSQL par le socket Unix \
             local avec l'authentification peer uniquement (ni réseau, ni mot de passe).",
        ));
    }
    if now >= KEY_FILE_WAIVER_END {
        key_files(core, out);
    }
}

/// Weakenings tolerated in production until a date, and logged at every
/// start: `CFG-P012` until 2027-04-30.
pub(crate) fn tolerated(core: &CoreConfig, now: u64, out: &mut Vec<Violation>) {
    if now < KEY_FILE_WAIVER_END {
        key_files(core, out);
    }
}

fn key_files(core: &CoreConfig, out: &mut Vec<Violation>) {
    for (field, key) in core.keys() {
        if let KeySource::File(path) = key {
            out.push(Violation::new(
                Code::CoreKeyInFile,
                format!(
                    "{field} = {{ file = « {} » }} : clé en clair dans un fichier au lieu d'un \
                     credential systemd chiffré ; dérogation jusqu'au {KEY_FILE_WAIVER_LAST_DAY} \
                     inclus, refusée ensuite.",
                    path.display()
                ),
            ));
        }
    }
}

/// Paths of the key files, for the permission rule (`CFG-P011`).
pub(crate) fn key_paths(core: &CoreConfig) -> impl Iterator<Item = (&'static str, &Path)> {
    core.keys()
        .into_iter()
        .filter_map(|(field, key)| match key {
            KeySource::File(path) => Some((field, path.as_path())),
            KeySource::Credential(_) => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers() {
        for ok in ["ostena", "ostena_core", "o2", "_x"] {
            assert!(is_identifier(ok), "{ok}");
        }
        let long = "a".repeat(64);
        for bad in ["", "Ostena", "2db", "a-b", "a b", "a\"b", long.as_str()] {
            assert!(!is_identifier(bad), "{bad}");
        }
    }

    #[test]
    fn credential_names() {
        assert!(is_credential_name("issuing.key"));
        for bad in ["", ".", "..", "a/b", "a\\b", "a\0b"] {
            assert!(!is_credential_name(bad), "{bad:?}");
        }
    }
}
