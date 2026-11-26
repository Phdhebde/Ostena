//! `[core.identity]`: the identity sources of the core (ADR-0021): LDAPS
//! directories read in read-only mode, besides the local accounts.
//!
//! Plain LDAP and StartTLS do not exist: a server address must be
//! `ldaps://` (`CFG-V020` otherwise, in every mode). The search filters are
//! read by the core at start (their syntax belongs to the LDAP client).

use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::agent::path_rule;
use super::core::KeySource;
use super::validation::{Code, Violation};

/// Name of the source of the local accounts, reserved.
pub const LOCAL_SOURCE: &str = "local";
/// Default interval of the check of the users with an open session, s.
pub const DEFAULT_CHECK_INTERVAL_SECS: u32 = 20;
/// Default interval of the full synchronisation of a source, s.
pub const DEFAULT_SYNC_INTERVAL_SECS: u32 = 900;
/// Default TCP and TLS connection timeout towards a directory, s.
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u32 = 5;
/// Default timeout of one LDAP operation, s.
pub const DEFAULT_OPERATION_TIMEOUT_SECS: u32 = 10;
/// Default LDAPS port.
pub const LDAPS_PORT: u16 = 636;

const fn default_check() -> u32 {
    DEFAULT_CHECK_INTERVAL_SECS
}

const fn default_sync() -> u32 {
    DEFAULT_SYNC_INTERVAL_SECS
}

const fn default_connect() -> u32 {
    DEFAULT_CONNECT_TIMEOUT_SECS
}

const fn default_operation() -> u32 {
    DEFAULT_OPERATION_TIMEOUT_SECS
}

const fn yes() -> bool {
    true
}

/// `[core.identity]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreIdentityConfig {
    /// Source of a login name without `source/` nor `@suffix`; absent, such
    /// a name is a local account.
    #[serde(default)]
    pub default_source: Option<String>,
    /// Interval of the check of the users that hold an open login session
    /// (disabled, deleted, password changed, out of the allowed groups),
    /// 5 to 50 s: a user disabled in a directory loses their sessions within
    /// this interval and the time of one search.
    #[serde(default = "default_check")]
    pub check_interval_secs: u32,
    /// Interval of the full synchronisation of each source, 60 to 86 400 s.
    #[serde(default = "default_sync")]
    pub sync_interval_secs: u32,
    /// The LDAPS directories, 0 to 16.
    #[serde(default)]
    pub ldap: Vec<LdapSourceConfig>,
}

/// The kind of a directory: the attributes the core reads depend on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DirectoryKind {
    /// Active Directory (a forest per source).
    ActiveDirectory,
    /// OpenLDAP (with the `ppolicy` overlay for locked accounts).
    Openldap,
    /// FreeIPA (389 Directory Server).
    Freeipa,
}

/// `[[core.identity.ldap]]`: one LDAPS directory.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LdapSourceConfig {
    /// Name of the source, `[a-z0-9][a-z0-9-]{0,31}`, not `local`: the
    /// prefix of its users (`corp/jdupont`).
    pub name: String,
    /// Kind of directory.
    pub kind: DirectoryKind,
    /// Its servers, `ldaps://host[:port]`, tried in order (1 to 8).
    pub servers: Vec<String>,
    /// The CA bundle (PEM) that issues the certificates of the servers:
    /// the only trust anchors of this source.
    pub ca_bundle: PathBuf,
    /// DN of the read-only service account.
    pub bind_dn: String,
    /// Its password: a systemd credential, or a file readable by the
    /// service account only.
    pub bind_password: KeySource,
    /// Base DN of the users.
    pub user_base: String,
    /// Filter of the users (RFC 4515); default by kind.
    #[serde(default)]
    pub user_filter: Option<String>,
    /// Attribute of the login name; default by kind (`sAMAccountName`,
    /// `uid`).
    #[serde(default)]
    pub login_attribute: Option<String>,
    /// Base DN of the groups; default: `user_base`.
    #[serde(default)]
    pub group_base: Option<String>,
    /// Suffixes routed to this source: `jdupont@corp.example` (0 to 16).
    #[serde(default)]
    pub suffixes: Vec<String>,
    /// Only the users of a group named by a rule are created and may log
    /// in (default); `false` takes every user of the filter.
    #[serde(default = "yes")]
    pub require_group: bool,
    /// TCP and TLS connection timeout, 1 to 30 s.
    #[serde(default = "default_connect")]
    pub connect_timeout_secs: u32,
    /// Timeout of one LDAP operation, 1 to 120 s.
    #[serde(default = "default_operation")]
    pub operation_timeout_secs: u32,
    /// Group rules: a group of the directory (nested groups included)
    /// gives a group of users of the core (0 to 256).
    #[serde(default)]
    pub groups: Vec<GroupRule>,
}

/// `[[core.identity.ldap.groups]]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupRule {
    /// DN of the group in the directory.
    pub directory: String,
    /// Group of users of the core, `[a-z0-9][a-z0-9._-]{0,62}`.
    pub group: String,
}

/// A server address of a source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapsServer {
    /// Host name or IP address (without brackets).
    pub host: String,
    /// Port.
    pub port: u16,
}

impl LdapsServer {
    /// Reads `ldaps://host[:port][/]`.
    ///
    /// # Errors
    ///
    /// A message in French: another scheme (`ldap://`: plain LDAP and
    /// StartTLS are refused), no host, a bad port, a path or a query.
    pub fn parse(url: &str) -> Result<Self, String> {
        let lower = url.to_ascii_lowercase();
        let Some(rest) = lower.strip_prefix("ldaps://").map(|_| &url[8..]) else {
            return Err(if lower.starts_with("ldap://") {
                "LDAP en clair refusé (StartTLS non plus) : ldaps:// attendu".into()
            } else {
                "ldaps://hôte[:port] attendu".into()
            });
        };
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        if rest.contains(['/', '?', '#', '@']) || rest.is_empty() {
            return Err("ldaps://hôte[:port] attendu, sans chemin ni identifiant".into());
        }
        let (host, port) = if let Some(v6) = rest.strip_prefix('[') {
            let (host, after) = v6
                .split_once(']')
                .ok_or_else(|| "adresse IPv6 sans « ] »".to_owned())?;
            (host, after.strip_prefix(':'))
        } else {
            match rest.rsplit_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (rest, None),
            }
        };
        let port = match port {
            None => LDAPS_PORT,
            Some(p) => p
                .parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| format!("port « {p} » invalide"))?,
        };
        let ok_host = !host.is_empty()
            && host.len() <= 253
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'));
        if !ok_host {
            return Err(format!("hôte « {} » invalide", host.escape_debug()));
        }
        Ok(Self {
            host: host.to_ascii_lowercase(),
            port,
        })
    }
}

/// A source name: `[a-z0-9][a-z0-9-]{0,31}`.
pub fn is_source_name(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=32).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// A group of users: `[a-z0-9][a-z0-9._-]{0,62}`.
pub fn is_user_group_name(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=63).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        })
}

fn violation(out: &mut Vec<Violation>, message: String) {
    out.push(Violation::new(Code::CoreIdentity, message));
}

fn dn_rule(out: &mut Vec<Violation>, field: &str, dn: &str) {
    if dn.trim().is_empty() || dn.len() > 1024 || dn.chars().any(char::is_control) {
        violation(
            out,
            format!("{field} : DN de 1 à 1 024 octets sans caractère de contrôle attendu."),
        );
    }
}

fn bounds(out: &mut Vec<Violation>, field: &str, value: u32, min: u32, max: u32) {
    if !(min..=max).contains(&value) {
        violation(
            out,
            format!("{field} = {value} : attendu de {min} à {max}."),
        );
    }
}

/// Rules of `[core.identity]` (`CFG-V020`).
pub(crate) fn rules(identity: &CoreIdentityConfig, out: &mut Vec<Violation>) {
    bounds(
        out,
        "core.identity.check_interval_secs",
        identity.check_interval_secs,
        5,
        50,
    );
    bounds(
        out,
        "core.identity.sync_interval_secs",
        identity.sync_interval_secs,
        60,
        86_400,
    );
    if identity.ldap.len() > 16 {
        violation(out, "core.identity.ldap : 16 sources au plus.".into());
    }
    if let Some(default) = &identity.default_source
        && default != LOCAL_SOURCE
        && !identity.ldap.iter().any(|s| &s.name == default)
    {
        violation(
            out,
            format!(
                "core.identity.default_source = « {} » : source inconnue.",
                default.escape_debug()
            ),
        );
    }
    let mut suffixes: Vec<String> = Vec::new();
    for i in 0..identity.ldap.len() {
        source_rules(identity, i, &mut suffixes, out);
    }
}

/// Rules of one source.
fn source_rules(
    identity: &CoreIdentityConfig,
    i: usize,
    suffixes: &mut Vec<String>,
    out: &mut Vec<Violation>,
) {
    let source = &identity.ldap[i];
    let at = format!("core.identity.ldap[{i}]");
    if !is_source_name(&source.name) || source.name == LOCAL_SOURCE {
        violation(
            out,
            format!(
                "{at}.name = « {} » : [a-z0-9][a-z0-9-]{{0,31}} attendu, « local » réservé.",
                source.name.escape_debug()
            ),
        );
    }
    if identity.ldap[..i].iter().any(|s| s.name == source.name) {
        violation(
            out,
            format!("{at}.name = « {} » : déjà utilisé.", source.name),
        );
    }
    if source.servers.is_empty() || source.servers.len() > 8 {
        violation(out, format!("{at}.servers : de 1 à 8 serveurs attendus."));
    }
    for server in &source.servers {
        if let Err(reason) = LdapsServer::parse(server) {
            violation(
                out,
                format!("{at}.servers : « {} » : {reason}.", server.escape_debug()),
            );
        }
    }
    path_rule(out, &format!("{at}.ca_bundle"), &source.ca_bundle);
    if let KeySource::File(path) = &source.bind_password {
        path_rule(out, &format!("{at}.bind_password"), path);
    }
    dn_rule(out, &format!("{at}.bind_dn"), &source.bind_dn);
    dn_rule(out, &format!("{at}.user_base"), &source.user_base);
    if let Some(base) = &source.group_base {
        dn_rule(out, &format!("{at}.group_base"), base);
    }
    if let Some(attr) = &source.login_attribute {
        let ok = !attr.is_empty()
            && attr.len() <= 64
            && attr.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !ok {
            violation(
                out,
                format!("{at}.login_attribute : nom d'attribut attendu."),
            );
        }
    }
    suffix_rules(source, &at, suffixes, out);
    bounds(
        out,
        &format!("{at}.connect_timeout_secs"),
        source.connect_timeout_secs,
        1,
        30,
    );
    bounds(
        out,
        &format!("{at}.operation_timeout_secs"),
        source.operation_timeout_secs,
        1,
        120,
    );
    group_rules(source, &at, out);
}

/// Suffixes of one source: domain names, each routed to one source.
fn suffix_rules(
    source: &LdapSourceConfig,
    at: &str,
    suffixes: &mut Vec<String>,
    out: &mut Vec<Violation>,
) {
    if source.suffixes.len() > 16 {
        violation(out, format!("{at}.suffixes : 16 au plus."));
    }
    for suffix in &source.suffixes {
        let lower = suffix.to_ascii_lowercase();
        let ok = !lower.is_empty()
            && lower.len() <= 253
            && lower
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'));
        if !ok {
            violation(
                out,
                format!(
                    "{at}.suffixes : « {} » n'est pas un nom de domaine.",
                    suffix.escape_debug()
                ),
            );
        } else if suffixes.contains(&lower) {
            violation(
                out,
                format!("{at}.suffixes : « {lower} » routé vers deux sources."),
            );
        } else {
            suffixes.push(lower);
        }
    }
}

/// Group rules of one source.
fn group_rules(source: &LdapSourceConfig, at: &str, out: &mut Vec<Violation>) {
    if source.groups.len() > 256 {
        violation(out, format!("{at}.groups : 256 règles au plus."));
    }
    if source.require_group && source.groups.is_empty() {
        violation(
            out,
            format!(
                "{at} : require_group sans règle de groupe : aucun utilisateur ne serait admis \
                 (ajoutez [[…groups]] ou require_group = false)."
            ),
        );
    }
    for (j, rule) in source.groups.iter().enumerate() {
        dn_rule(out, &format!("{at}.groups[{j}].directory"), &rule.directory);
        if !is_user_group_name(&rule.group) {
            violation(
                out,
                format!(
                    "{at}.groups[{j}].group = « {} » : [a-z0-9][a-z0-9._-]{{0,62}} attendu.",
                    rule.group.escape_debug()
                ),
            );
        }
    }
}

/// The password files of the sources, for the permission rule (`CFG-P020`).
pub(crate) fn secret_paths(identity: &CoreIdentityConfig) -> Vec<(String, &Path)> {
    identity
        .ldap
        .iter()
        .enumerate()
        .filter_map(|(i, s)| match &s.bind_password {
            KeySource::File(path) => Some((
                format!("core.identity.ldap[{i}].bind_password"),
                path.as_path(),
            )),
            KeySource::Credential(_) => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_addresses() {
        let ok = |url: &str, host: &str, port: u16| {
            assert_eq!(
                LdapsServer::parse(url),
                Ok(LdapsServer {
                    host: host.into(),
                    port
                }),
                "{url}"
            );
        };
        ok("ldaps://dc01.corp.example", "dc01.corp.example", 636);
        ok("LDAPS://DC01.corp.example:3269/", "dc01.corp.example", 3269);
        ok("ldaps://10.0.0.5:636", "10.0.0.5", 636);
        ok("ldaps://[fd00::5]:1636", "fd00::5", 1636);
        for bad in [
            "ldap://dc01.corp.example",
            "LDAP://dc01",
            "dc01.corp.example",
            "ldaps://",
            "ldaps://dc01:0",
            "ldaps://dc01:70000",
            "ldaps://dc01/dc=corp",
            "ldaps://user@dc01",
            "ldaps://dc 01",
            "ldapi:///",
        ] {
            assert!(LdapsServer::parse(bad).is_err(), "{bad}");
        }
        assert!(
            LdapsServer::parse("ldap://dc01")
                .unwrap_err()
                .contains("en clair")
        );
    }

    #[test]
    fn names() {
        assert!(is_source_name("corp-fr"));
        assert!(!is_source_name("Corp"));
        assert!(!is_source_name("-corp"));
        assert!(!is_source_name(&"a".repeat(33)));
        assert!(is_user_group_name("rdp.admins_1"));
        assert!(!is_user_group_name("RDP"));
    }
}
