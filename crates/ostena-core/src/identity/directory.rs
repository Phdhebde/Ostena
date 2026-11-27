//! One LDAPS directory, read in read-only mode (ADR-0021). No database
//! here: the lab test drives this module against the domain controller of
//! the lab alone.
//!
//! - **Transport**: TCP then TLS with the directory profile of
//!   `ostena-crypto` (TLS 1.3, CA bundle of the source only, name of the
//!   server in its certificate). There is no plain mode and no StartTLS.
//! - **Failover**: the servers are tried in order, starting with the last
//!   one that answered; a server that fails its connection, its TLS or a
//!   transient LDAP error hands over to the next one.
//! - **Reading**: the service account binds, then paged searches. Values
//!   typed by a user (a login name) only ever go into filter leaves.
//! - **Groups**: Active Directory resolves nested groups itself
//!   (`LDAP_MATCHING_RULE_IN_CHAIN`, one search per group rule); for
//!   OpenLDAP and FreeIPA the core reads the groups under `group_base` and
//!   follows `member` / `uniqueMember` itself, cycles included.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use ostena_common::config::{DirectoryKind, DirectoryTlsVersion, LdapSourceConfig, LdapsServer};
use ostena_common::secret::SecretString;
use ostena_crypto::tls::directory::{DirectoryTls, anchors_from_pem, directory_client_config};
use ostena_crypto::tls::{self, ClientConfig, HandshakeFailure, ServerName};
use ostena_ldap::{Connection, Entry, Filter, LdapError, Limits, Scope, SearchRequest};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::ProtocolVersion;

/// Users whose state is read in one search.
pub const LOOKUP_BATCH: usize = 50;
/// Largest depth followed in the groups of OpenLDAP and FreeIPA.
const MAX_GROUP_DEPTH: usize = 32;

/// Why a source cannot be read. Codes are stable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    /// No server of the source answered.
    #[error("[IDN-E001] aucun serveur de la source « {source_name} » ne répond : {detail}")]
    Unavailable {
        /// The source.
        source_name: String,
        /// What the last server said.
        detail: String,
    },
    /// A server is refused: its TLS handshake failed (certificate not
    /// issued by the CA bundle, other name, TLS 1.2 only without the
    /// option, suite or group outside the profile), or its name resolves to
    /// a cloud metadata address.
    #[error("[IDN-E002] serveur {server} refusé (source « {source_name} ») : {detail}")]
    Tls {
        /// The source.
        source_name: String,
        /// The server, `host:port`.
        server: String,
        /// The failure.
        detail: String,
    },
    /// The directory refused the service account.
    #[error(
        "[IDN-E003] liaison du compte de service de la source « {source_name} » refusée : {detail}"
    )]
    ServiceBind {
        /// The source.
        source_name: String,
        /// The LDAP error.
        detail: String,
    },
    /// A search failed.
    #[error("[IDN-E004] recherche en échec dans la source « {source_name} » : {detail}")]
    Search {
        /// The source.
        source_name: String,
        /// The LDAP error.
        detail: String,
    },
    /// The configuration of the source cannot be used (CA bundle, filter,
    /// password).
    #[error("[IDN-E005] source « {source_name} » inutilisable : {detail}")]
    Config {
        /// The source.
        source_name: String,
        /// The fault.
        detail: String,
    },
}

impl IdentityError {
    /// The stable code, e.g. `IDN-E002`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unavailable { .. } => "IDN-E001",
            Self::Tls { .. } => "IDN-E002",
            Self::ServiceBind { .. } => "IDN-E003",
            Self::Search { .. } => "IDN-E004",
            Self::Config { .. } => "IDN-E005",
        }
    }
}

/// Why a directory entry gives no user. Not an error of the source: the
/// entry is skipped and counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    /// No identifier, or one longer than 128 bytes.
    NoIdentifier,
    /// No login name, or one outside `[a-z0-9][a-z0-9._-]{0,63}` once in
    /// lower case.
    LoginName,
}

/// A user as the directory sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirUser {
    /// DN of the entry.
    pub dn: String,
    /// Stable identifier of the entry (objectGUID in hex, entryUUID,
    /// ipaUniqueID).
    pub external_id: String,
    /// Login name, lower case.
    pub login: String,
    /// Display name, 1 to 128 characters without control characters.
    pub display_name: String,
    /// Why the directory refuses the account, if it does.
    pub disabled: Option<&'static str>,
    /// Last password change, Unix seconds, if the directory tells it.
    pub password_changed_at: Option<u64>,
    /// Groups of users of the core given by the rules of the source.
    pub groups: Vec<String>,
}

/// What a full listing returned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Listing {
    /// The users.
    pub users: Vec<DirUser>,
    /// Entries skipped (no identifier, login name outside the rules).
    pub skipped: usize,
}

/// The attributes of a kind of directory.
#[derive(Debug, Clone, Copy)]
struct Schema {
    id: &'static str,
    login: &'static str,
    filter: &'static str,
    state: &'static [&'static str],
}

const fn schema(kind: DirectoryKind) -> Schema {
    match kind {
        DirectoryKind::ActiveDirectory => Schema {
            id: "objectGUID",
            login: "sAMAccountName",
            filter: "(&(objectCategory=person)(objectClass=user))",
            state: &["userAccountControl", "accountExpires", "pwdLastSet"],
        },
        DirectoryKind::Openldap => Schema {
            id: "entryUUID",
            login: "uid",
            filter: "(objectClass=inetOrgPerson)",
            state: &["pwdAccountLockedTime", "pwdChangedTime"],
        },
        DirectoryKind::Freeipa => Schema {
            id: "ipaUniqueID",
            login: "uid",
            filter: "(objectClass=person)",
            state: &["nsAccountLock", "krbLastPwdChange"],
        },
    }
}

/// A DN compared without case and spaces around separators.
pub fn norm_dn(dn: &str) -> String {
    let mut out = String::with_capacity(dn.len());
    for part in dn.split(',') {
        if !out.is_empty() {
            out.push(',');
        }
        let (attr, value) = part.split_once('=').unwrap_or((part, ""));
        out.push_str(&attr.trim().to_ascii_lowercase());
        out.push('=');
        out.push_str(&value.trim().to_lowercase());
    }
    out
}

fn is_login(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=64).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        })
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Windows FILETIME (100 ns since 1601) to Unix seconds; 0 and the largest
/// value mean never.
fn filetime(value: &str) -> Option<u64> {
    let v: i64 = value.trim().parse().ok()?;
    if v <= 0 || v == i64::MAX {
        return None;
    }
    u64::try_from(v / 10_000_000 - 11_644_473_600).ok()
}

/// `YYYYMMDDHHMMSS[.f]Z` to Unix seconds.
fn generalized_time(value: &str) -> Option<u64> {
    let digits = value.get(..14)?;
    if !digits.bytes().all(|b| b.is_ascii_digit()) || !value.ends_with('Z') {
        return None;
    }
    let n = |r: std::ops::Range<usize>| digits[r].parse::<i64>().ok();
    let (y, m, d) = (n(0..4)?, n(4..6)?, n(6..8)?);
    let (hh, mm, ss) = (n(8..10)?, n(10..12)?, n(12..14)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // Days from the civil date (H. Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + hh * 3600 + mm * 60 + ss).ok()
}

fn clean_display(value: &str) -> Option<String> {
    let s: String = value
        .chars()
        .filter(|c| !c.is_control())
        .take(128)
        .collect::<String>()
        .trim()
        .to_owned();
    (!s.is_empty()).then_some(s)
}

type Stream = TlsStream<TcpStream>;

/// One LDAPS directory of the configuration.
pub struct DirectorySource {
    /// Name of the source, prefix of its users.
    pub name: String,
    /// Kind of directory.
    pub kind: DirectoryKind,
    /// Suffixes routed to this source, lower case.
    pub suffixes: Vec<String>,
    /// Whether only the users of a ruled group are admitted.
    pub require_group: bool,
    servers: Vec<LdapsServer>,
    tls: Arc<ClientConfig>,
    bind_dn: String,
    bind_password: SecretString,
    user_base: String,
    user_filter: Filter,
    login_attr: String,
    group_base: String,
    /// (normalized DN of the directory group, DN as written, group of
    /// users).
    rules: Vec<(String, String, String)>,
    connect_timeout: Duration,
    operation_timeout: Duration,
    /// Whether TLS 1.2 is admitted (`tls_min_version = "1.2"`).
    tls12: bool,
    preferred: AtomicUsize,
    available: AtomicBool,
}

impl fmt::Debug for DirectorySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectorySource")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("servers", &self.servers)
            .field("bind_dn", &self.bind_dn)
            .finish_non_exhaustive()
    }
}

fn ldap_detail(e: &LdapError) -> String {
    e.to_string()
}

impl DirectorySource {
    /// The source of `config`, trusting the CA bundle `ca_pem`, binding
    /// with `bind_password`.
    ///
    /// # Errors
    ///
    /// [`IdentityError::Config`] for an unreadable bundle, a bad filter or
    /// server address.
    pub fn new(
        config: &LdapSourceConfig,
        ca_pem: &[u8],
        bind_password: SecretString,
    ) -> Result<Self, IdentityError> {
        let bad = |detail: String| IdentityError::Config {
            source_name: config.name.clone(),
            detail,
        };
        let anchors = anchors_from_pem(ca_pem).map_err(|e| bad(format!("ca_bundle : {e}")))?;
        let tls12 = config.tls_min_version == DirectoryTlsVersion::Tls12;
        let mode = if tls12 {
            DirectoryTls::AllowTls12
        } else {
            DirectoryTls::Tls13
        };
        let tls = directory_client_config(&anchors, mode).map_err(|e| bad(e.to_string()))?;
        let servers = config
            .servers
            .iter()
            .map(|s| LdapsServer::parse(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(bad)?;
        for s in &servers {
            server_name(&s.host).map_err(|_| bad(format!("hôte « {} » invalide", s.host)))?;
        }
        let schema = schema(config.kind);
        let filter_text = config.user_filter.as_deref().unwrap_or(schema.filter);
        let user_filter =
            Filter::parse(filter_text).map_err(|e| bad(format!("user_filter : {e}")))?;
        Ok(Self {
            name: config.name.clone(),
            kind: config.kind,
            suffixes: config
                .suffixes
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
            require_group: config.require_group,
            servers,
            tls,
            bind_dn: config.bind_dn.clone(),
            bind_password,
            user_base: config.user_base.clone(),
            user_filter,
            login_attr: config
                .login_attribute
                .clone()
                .unwrap_or_else(|| schema.login.to_owned()),
            group_base: config
                .group_base
                .clone()
                .unwrap_or_else(|| config.user_base.clone()),
            rules: config
                .groups
                .iter()
                .map(|r| (norm_dn(&r.directory), r.directory.clone(), r.group.clone()))
                .collect(),
            connect_timeout: Duration::from_secs(u64::from(config.connect_timeout_secs)),
            operation_timeout: Duration::from_secs(u64::from(config.operation_timeout_secs)),
            tls12,
            preferred: AtomicUsize::new(0),
            available: AtomicBool::new(true),
        })
    }

    /// Records whether the source answers; `true` if that changed.
    pub fn set_available(&self, available: bool) -> bool {
        self.available.swap(available, Ordering::Relaxed) != available
    }

    /// The groups of users that the rules of this source can give.
    pub fn ruled_groups(&self) -> impl Iterator<Item = &str> {
        self.rules.iter().map(|(_, _, g)| g.as_str())
    }

    /// Whether a user of this source with `groups` may exist in the core.
    pub fn admits(&self, user: &DirUser) -> bool {
        !self.require_group || !user.groups.is_empty()
    }

    fn search_error(&self, e: &LdapError) -> IdentityError {
        IdentityError::Search {
            source_name: self.name.clone(),
            detail: ldap_detail(e),
        }
    }

    async fn timed<T>(
        &self,
        work: impl Future<Output = Result<T, LdapError>>,
    ) -> Result<T, LdapError> {
        tokio::time::timeout(self.operation_timeout, work)
            .await
            .unwrap_or_else(|_| Err(LdapError::Io("délai dépassé".into())))
    }

    /// TCP, TLS, then the bind of the service account on server `index`.
    async fn connect_to(&self, index: usize) -> Result<Connection<Stream>, IdentityError> {
        let server = &self.servers[index];
        let label = format!("{}:{}", server.host, server.port);
        let unavailable = |detail: String| IdentityError::Unavailable {
            source_name: self.name.clone(),
            detail: format!("{label} : {detail}"),
        };
        let name = server_name(&server.host).map_err(|e| unavailable(e.clone()))?;
        let connect = async {
            let addrs = self.resolve(server, &label).await?;
            let tcp = TcpStream::connect(&addrs[..])
                .await
                .map_err(|e| unavailable(e.kind().to_string()))?;
            let _ = tcp.set_nodelay(true);
            TlsConnector::from(self.tls.clone())
                .connect(name, tcp)
                .await
                .map_err(|e| match tls::classify_io(&e) {
                    Some(failure) => IdentityError::Tls {
                        source_name: self.name.clone(),
                        server: label.clone(),
                        detail: match failure {
                            HandshakeFailure::ProtocolVersion if self.tls12 => {
                                "TLS : ni TLS 1.3 ni TLS 1.2 proposés par le serveur".into()
                            }
                            _ => format!("TLS : {}", describe(failure)),
                        },
                    },
                    None => unavailable(e.kind().to_string()),
                })
        };
        let stream = tokio::time::timeout(self.connect_timeout, connect)
            .await
            .unwrap_or_else(|_| Err(unavailable("délai de connexion dépassé".into())))?;
        if self.tls12 && stream.get_ref().1.protocol_version() == Some(ProtocolVersion::TLSv1_2) {
            tracing::warn!(
                event = "identity.tls12",
                source = %self.name,
                server = %label,
                "connexion à l'annuaire en TLS 1.2 (écart accepté, ADR-0009, CFG-P021)"
            );
        }
        let mut conn = Connection::new(stream, Limits::default());
        match self
            .timed(conn.bind(&self.bind_dn, &self.bind_password))
            .await
        {
            Ok(()) => Ok(conn),
            Err(e) if e.is_transient() => Err(unavailable(ldap_detail(&e))),
            Err(e) => Err(IdentityError::ServiceBind {
                source_name: self.name.clone(),
                detail: ldap_detail(&e),
            }),
        }
    }

    /// The addresses of `server`, resolved here so that a name pointing at
    /// a cloud metadata service is refused before any connection (the
    /// floor of ADR-0005; the rest of the scope policy does not apply to
    /// the directories of the configuration).
    async fn resolve(
        &self,
        server: &LdapsServer,
        label: &str,
    ) -> Result<Vec<std::net::SocketAddr>, IdentityError> {
        let addrs: Vec<_> = tokio::net::lookup_host((server.host.as_str(), server.port))
            .await
            .map_err(|e| IdentityError::Unavailable {
                source_name: self.name.clone(),
                detail: format!("{label} : résolution : {}", e.kind()),
            })?
            .collect();
        if let Some(bad) = addrs.iter().find(|a| {
            ostena_scope::floor_cause(a.ip()) == Some(ostena_scope::FloorCause::CloudMetadata)
        }) {
            return Err(IdentityError::Tls {
                source_name: self.name.clone(),
                server: label.to_owned(),
                detail: format!(
                    "adresse {} : {} (ADR-0005)",
                    bad.ip(),
                    ostena_scope::FloorCause::CloudMetadata.description()
                ),
            });
        }
        if addrs.is_empty() {
            return Err(IdentityError::Unavailable {
                source_name: self.name.clone(),
                detail: format!("{label} : aucune adresse"),
            });
        }
        Ok(addrs)
    }

    /// A connection bound as the service account, on the first server that
    /// answers, starting with the last one that did.
    ///
    /// # Errors
    ///
    /// [`IdentityError::ServiceBind`] at once if the account is refused
    /// (the same account is used on every server); otherwise the error of
    /// the last server, once every server has failed.
    pub async fn open(&self) -> Result<Connection<Stream>, IdentityError> {
        let n = self.servers.len();
        let start = self.preferred.load(Ordering::Relaxed) % n.max(1);
        let mut last = None;
        for k in 0..n {
            let index = (start + k) % n;
            match self.connect_to(index).await {
                Ok(conn) => {
                    if index != start {
                        tracing::warn!(
                            event = "identity.server_failover",
                            source = %self.name,
                            server = %self.servers[index].host,
                            "serveur d'annuaire de repli"
                        );
                    }
                    self.preferred.store(index, Ordering::Relaxed);
                    return Ok(conn);
                }
                Err(e @ IdentityError::ServiceBind { .. }) => return Err(e),
                Err(e) => {
                    tracing::warn!(
                        event = "identity.server_unavailable",
                        source = %self.name,
                        code = e.code(),
                        "{e}"
                    );
                    last = Some(e);
                }
            }
        }
        Err(match last {
            Some(IdentityError::Tls { detail, server, .. }) => IdentityError::Unavailable {
                source_name: self.name.clone(),
                detail: format!("{server} refusé : {detail}"),
            },
            Some(e) => e,
            None => IdentityError::Config {
                source_name: self.name.clone(),
                detail: "aucun serveur".into(),
            },
        })
    }

    fn attributes(&self) -> Vec<String> {
        let schema = schema(self.kind);
        let mut attrs = vec![
            schema.id.to_owned(),
            self.login_attr.clone(),
            "displayName".to_owned(),
            "cn".to_owned(),
        ];
        attrs.extend(schema.state.iter().map(|s| (*s).to_owned()));
        attrs
    }

    fn users_request(&self, filter: Filter, attributes: Vec<String>) -> SearchRequest {
        SearchRequest {
            base: self.user_base.clone(),
            scope: Scope::Subtree,
            size_limit: 0,
            time_limit: u32::try_from(self.operation_timeout.as_secs()).unwrap_or(0),
            filter: Filter::And(vec![self.user_filter.clone(), filter]),
            attributes,
        }
    }

    /// The user of an entry, without groups.
    fn user_of(&self, entry: &Entry, now: u64) -> Result<DirUser, Skip> {
        let schema = schema(self.kind);
        let external_id = match self.kind {
            DirectoryKind::ActiveDirectory => entry
                .values(schema.id)
                .next()
                .filter(|v| v.len() == 16)
                .map(hex),
            _ => entry.first(schema.id).map(str::to_owned),
        }
        .filter(|id| !id.is_empty() && id.len() <= 128 && !id.chars().any(char::is_control))
        .ok_or(Skip::NoIdentifier)?;
        let login = entry
            .first(&self.login_attr)
            .map(str::to_lowercase)
            .filter(|l| is_login(l))
            .ok_or(Skip::LoginName)?;
        let display_name = entry
            .first("displayName")
            .and_then(clean_display)
            .or_else(|| entry.first("cn").and_then(clean_display))
            .unwrap_or_else(|| login.clone());
        let (disabled, password_changed_at) = match self.kind {
            DirectoryKind::ActiveDirectory => {
                let uac: u64 = entry
                    .first("userAccountControl")
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                let expired = entry
                    .first("accountExpires")
                    .and_then(filetime)
                    .is_some_and(|t| t <= now);
                let disabled = if uac & 0x2 != 0 {
                    Some("compte désactivé dans l'annuaire")
                } else if expired {
                    Some("compte expiré dans l'annuaire")
                } else {
                    None
                };
                (disabled, entry.first("pwdLastSet").and_then(filetime))
            }
            DirectoryKind::Openldap => (
                entry
                    .has("pwdAccountLockedTime")
                    .then_some("compte verrouillé dans l'annuaire"),
                entry.first("pwdChangedTime").and_then(generalized_time),
            ),
            DirectoryKind::Freeipa => (
                entry
                    .first("nsAccountLock")
                    .is_some_and(|v| v.eq_ignore_ascii_case("true"))
                    .then_some("compte désactivé dans l'annuaire"),
                entry.first("krbLastPwdChange").and_then(generalized_time),
            ),
        };
        Ok(DirUser {
            dn: entry.dn.clone(),
            external_id,
            login,
            display_name,
            disabled,
            password_changed_at,
            groups: Vec::new(),
        })
    }

    fn users_of(&self, entries: &[Entry], now: u64) -> (Vec<DirUser>, usize) {
        let mut users = Vec::with_capacity(entries.len());
        let mut skipped = 0;
        for entry in entries {
            match self.user_of(entry, now) {
                Ok(u) => users.push(u),
                Err(skip) => {
                    skipped += 1;
                    tracing::debug!(
                        event = "identity.entry_skipped",
                        source = %self.name,
                        dn = %entry.dn.escape_debug(),
                        reason = ?skip,
                        "entrée d'annuaire ignorée"
                    );
                }
            }
        }
        (users, skipped)
    }

    /// The filter that selects the users of `ids`.
    fn ids_filter(&self, ids: &[&str]) -> Filter {
        let id_attr = schema(self.kind).id;
        Filter::Or(
            ids.iter()
                .map(|id| match self.kind {
                    DirectoryKind::ActiveDirectory => {
                        Filter::equal(id_attr, unhex(id).unwrap_or_default())
                    }
                    _ => Filter::equal(id_attr, id.as_bytes()),
                })
                .collect(),
        )
    }

    /// Fills the groups of `users`, read through `conn`; `subset` limits
    /// the searches of Active Directory to these users.
    async fn fill_groups(
        &self,
        conn: &mut Connection<Stream>,
        users: &mut [DirUser],
        subset: Option<Filter>,
    ) -> Result<(), IdentityError> {
        if self.rules.is_empty() || users.is_empty() {
            return Ok(());
        }
        let index: HashMap<String, usize> = users
            .iter()
            .enumerate()
            .map(|(i, u)| (norm_dn(&u.dn), i))
            .collect();
        match self.kind {
            DirectoryKind::ActiveDirectory => {
                for (_, dn, group) in &self.rules {
                    let mut filter = vec![Filter::in_chain("memberOf", dn)];
                    filter.extend(subset.clone());
                    let request = self.users_request(Filter::And(filter), vec!["1.1".into()]);
                    let found = self
                        .timed(conn.search(&request))
                        .await
                        .map_err(|e| self.search_error(&e))?;
                    for entry in &found.entries {
                        if let Some(&i) = index.get(&norm_dn(&entry.dn)) {
                            users[i].groups.push(group.clone());
                        }
                    }
                }
            }
            DirectoryKind::Openldap | DirectoryKind::Freeipa => {
                let request = SearchRequest {
                    base: self.group_base.clone(),
                    scope: Scope::Subtree,
                    size_limit: 0,
                    time_limit: u32::try_from(self.operation_timeout.as_secs()).unwrap_or(0),
                    filter: Filter::Or(vec![
                        Filter::Present("member".into()),
                        Filter::Present("uniqueMember".into()),
                    ]),
                    attributes: vec!["member".into(), "uniqueMember".into()],
                };
                let found = self
                    .timed(conn.search(&request))
                    .await
                    .map_err(|e| self.search_error(&e))?;
                let graph: HashMap<String, Vec<String>> = found
                    .entries
                    .iter()
                    .map(|e| {
                        let members = e
                            .values("member")
                            .chain(e.values("uniqueMember"))
                            .filter_map(|v| std::str::from_utf8(v).ok())
                            .map(norm_dn)
                            .collect();
                        (norm_dn(&e.dn), members)
                    })
                    .collect();
                for (rule, _, group) in &self.rules {
                    for member in closure(&graph, rule) {
                        if let Some(&i) = index.get(&member) {
                            users[i].groups.push(group.clone());
                        }
                    }
                }
            }
        }
        for u in users.iter_mut() {
            u.groups.sort();
            u.groups.dedup();
        }
        Ok(())
    }

    /// Finds the user `login` and, if `password` is given and the account
    /// is not refused by the directory, checks it by a bind as the user
    /// (on the same connection, after the service account's searches).
    /// `None` if the directory has no such user.
    ///
    /// # Errors
    ///
    /// [`IdentityError`] if the source cannot be read.
    pub async fn authenticate(
        &self,
        login: &str,
        password: Option<&SecretString>,
        now: u64,
    ) -> Result<Option<(DirUser, bool)>, IdentityError> {
        let mut conn = self.open().await?;
        let request = self.users_request(Filter::equal(&self.login_attr, login), self.attributes());
        let found = self
            .timed(conn.search(&request))
            .await
            .map_err(|e| self.search_error(&e))?;
        let (mut users, _) = self.users_of(&found.entries, now);
        // Exactly one entry, whose login is the one asked (a filter of the
        // directory may match more loosely).
        users.retain(|u| u.login == login);
        if users.len() != 1 {
            if users.len() > 1 {
                tracing::warn!(
                    event = "identity.login_ambiguous",
                    source = %self.name,
                    "plusieurs entrées pour un même identifiant : connexion refusée"
                );
            }
            let _ = conn.unbind().await;
            return Ok(None);
        }
        let subset = Some(self.ids_filter(&[users[0].external_id.as_str()]));
        self.fill_groups(&mut conn, &mut users, subset).await?;
        let Some(user) = users.pop() else {
            return Ok(None);
        };
        let password_ok = match password {
            Some(password) if user.disabled.is_none() => {
                match self.timed(conn.bind(&user.dn, password)).await {
                    Ok(()) => true,
                    Err(e) if e.is_invalid_credentials() || e == LdapError::EmptyCredentials => {
                        false
                    }
                    Err(e) => return Err(self.search_error(&e)),
                }
            }
            _ => false,
        };
        let _ = conn.unbind().await;
        Ok(Some((user, password_ok)))
    }

    /// Every user of the filter, with their groups.
    ///
    /// # Errors
    ///
    /// [`IdentityError`] if the source cannot be read.
    pub async fn list(&self, now: u64) -> Result<Listing, IdentityError> {
        let mut conn = self.open().await?;
        let request = self.users_request(Filter::Present("objectClass".into()), self.attributes());
        let found = self
            .timed(conn.search(&request))
            .await
            .map_err(|e| self.search_error(&e))?;
        let (mut users, skipped) = self.users_of(&found.entries, now);
        self.fill_groups(&mut conn, &mut users, None).await?;
        let _ = conn.unbind().await;
        Ok(Listing { users, skipped })
    }

    /// The users of `ids` still in the directory, with their groups; a
    /// missing identifier was deleted (or left the filter).
    ///
    /// # Errors
    ///
    /// [`IdentityError`] if the source cannot be read.
    pub async fn lookup(&self, ids: &[String], now: u64) -> Result<Vec<DirUser>, IdentityError> {
        let mut out = Vec::with_capacity(ids.len());
        if ids.is_empty() {
            return Ok(out);
        }
        let mut conn = self.open().await?;
        for batch in ids.chunks(LOOKUP_BATCH) {
            let refs: Vec<&str> = batch.iter().map(String::as_str).collect();
            let subset = self.ids_filter(&refs);
            let request = self.users_request(subset.clone(), self.attributes());
            let found = self
                .timed(conn.search(&request))
                .await
                .map_err(|e| self.search_error(&e))?;
            let (mut users, _) = self.users_of(&found.entries, now);
            self.fill_groups(&mut conn, &mut users, Some(subset))
                .await?;
            out.extend(users);
        }
        let _ = conn.unbind().await;
        Ok(out)
    }
}

/// Every DN reachable from `start` through `graph`, `start` excluded.
fn closure(graph: &HashMap<String, Vec<String>>, start: &str) -> HashSet<String> {
    let mut seen = HashSet::new();
    let mut frontier = vec![start.to_owned()];
    for _ in 0..MAX_GROUP_DEPTH {
        let mut next = Vec::new();
        for dn in frontier {
            for m in graph.get(&dn).into_iter().flatten() {
                if seen.insert(m.clone()) {
                    next.push(m.clone());
                }
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    seen
}

fn server_name(host: &str) -> Result<ServerName<'static>, String> {
    match host.parse::<IpAddr>() {
        Ok(ip) => Ok(ServerName::IpAddress(ip.into())),
        Err(_) => ServerName::try_from(host.to_owned()).map_err(|e| e.to_string()),
    }
}

fn describe(failure: HandshakeFailure) -> &'static str {
    match failure {
        HandshakeFailure::UnknownIssuer => "certificat non émis par l'autorité de la source",
        HandshakeFailure::Expired => "certificat expiré",
        HandshakeFailure::NotYetValid => "certificat pas encore valide",
        HandshakeFailure::NameMismatch => "certificat d'un autre nom",
        HandshakeFailure::ProtocolVersion => "TLS 1.3 non proposé par le serveur",
        HandshakeFailure::NoCommonCipherSuite => "aucune suite commune (AES-256-GCM attendue)",
        HandshakeFailure::NoCommonGroup => "aucun groupe commun (P-256, P-384)",
        _ => "poignée de main refusée (certificat ou paramètres hors profil)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dn_normalization() {
        assert_eq!(
            norm_dn("CN=Alice Martin , OU=Users,DC=Corp, DC=Example"),
            "cn=alice martin,ou=users,dc=corp,dc=example"
        );
    }

    #[test]
    fn times() {
        // 2026-01-01T00:00:00Z.
        assert_eq!(generalized_time("20260101000000Z"), Some(1_767_225_600));
        assert_eq!(generalized_time("20260101000000.5Z"), Some(1_767_225_600));
        assert_eq!(generalized_time("2026010100000Z"), None);
        assert_eq!(generalized_time("20261301000000Z"), None);
        assert_eq!(filetime("134116992000000000"), Some(1_767_225_600));
        assert_eq!(filetime("0"), None);
        assert_eq!(filetime("9223372036854775807"), None);
        assert_eq!(filetime("x"), None);
    }

    #[test]
    fn hex_round_trip() {
        let id = [0u8, 1, 0xab, 0xff];
        assert_eq!(hex(&id), "0001abff");
        assert_eq!(unhex("0001abff"), Some(id.to_vec()));
        assert_eq!(unhex("0g"), None);
        assert_eq!(unhex("abc"), None);
    }

    #[test]
    fn closure_follows_nesting_and_cycles() {
        let mut g = HashMap::new();
        g.insert(
            "cn=a".to_owned(),
            vec!["cn=b".to_owned(), "uid=x".to_owned()],
        );
        g.insert(
            "cn=b".to_owned(),
            vec!["cn=a".to_owned(), "uid=y".to_owned()],
        );
        let c = closure(&g, "cn=a");
        assert!(c.contains("uid=x") && c.contains("uid=y") && c.contains("cn=b"));
        assert!(closure(&g, "cn=none").is_empty());
    }

    #[test]
    fn login_rule() {
        assert!(is_login("jdupont"));
        assert!(is_login("j.dupont-2"));
        assert!(!is_login("j dupont"));
        assert!(!is_login("jdupont$"));
        assert!(!is_login(""));
    }
}
