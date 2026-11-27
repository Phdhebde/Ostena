//! The running core (ADR-0011): tunnel listener, enrolment listener,
//! certificate renewal, revocation that closes live tunnels.
//!
//! The copy of the registry is reloaded every [`RELOAD_INTERVAL`], and every
//! [`RETRY_INTERVAL`] while it cannot be read. Notifications from the
//! administration commands (token issued, agent revoked, login session
//! revoked, group changed) apply at once. Notifications sent while the
//! listening connection is lost are lost: once it listens again, the core
//! replays from the database what they would have applied, until it
//! succeeds; so does a notification it fails to apply.
//!
//! Native SSH access (ADR-0014): when an agent connects, the core pushes
//! the grant key set, the scope policy of its group, its SSH trust and the
//! revoked login sessions it received grants for; then it answers its host
//! key, grant and session requests.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ostena_audit::{ActorKind, Event, EventKind, Outcome, field};
use ostena_common::config::{CoreConfig, KeySource, Output};
use ostena_common::secret::SecretBytes;
use ostena_crypto::p256::SigningKey;
use ostena_crypto::pki::{IssuingAuthority, Validity};
use ostena_crypto::tls::{self, ClientAuth, Identity, TrustAnchor, WebGroups};
use ostena_grant::Issuer;
use ostena_tunnel::control::{AgentMessage, CoreMessage, PROTOCOL_VERSION};
use ostena_tunnel::enroll::{AgentRegistry, EnrollmentService};
use ostena_tunnel::{ALPN, CoreListener, CoreTunnel, Limits, TunnelError, Uuid, renewal};
use sqlx::postgres::PgListener;
use tokio::task::JoinHandle;

use crate::access::{self, Refusal, SshRequest};
use crate::api::{Attempts, Limits as LoginLimits, LoginListener};
use crate::audit::{self, Cadence, HeadSigner, Recorder, SystemClock};
use crate::authn::PgAuthenticator;
use crate::cache::AgentCache;
use crate::credential::TotpKey;
use crate::error::CoreError;
use crate::forwarding::Forwarder;
use crate::grant_keys::GrantAuthority;
use crate::identity::Directories;
use crate::ssh_ca::SshAuthorities;
use crate::store::{CHANNEL, Notice, PgStore, agent_event, truncate};
use crate::timestamping::Timestamper;
use crate::transcripts::{self, Transcripts};
use crate::web::gateway::Relays;
use crate::web::pg::{Agents, PgWebBackend, WebAccess};
use crate::web::{WebListener, WebSettings};
use crate::{login, pushes, rate};
use ostena_crypto::hmac::HmacKey;

/// Full reload of the registry copy.
pub const RELOAD_INTERVAL: Duration = Duration::from_secs(60);
/// Reload attempts while the copy is unavailable.
pub const RETRY_INTERVAL: Duration = Duration::from_secs(5);
/// Tolerated clock difference at the start of an agent certificate.
const SKEW: u64 = 300;
const DAY: u64 = 86_400;
/// Time allowed for the enrolment handshake and exchange.
const ENROLL_TIMEOUT: Duration = Duration::from_secs(10);
/// Interval between two looks for host certificates due for renewal.
pub const HOST_RENEWAL_INTERVAL: Duration = Duration::from_hours(1);

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The keys and certificates of the core.
pub struct Keys {
    /// The root the agents pin (signs the server certificate).
    pub root: TrustAnchor,
    /// The server certificate and its key.
    pub server: Identity,
    /// The issuing CA (agent certificates).
    pub issuing: Arc<IssuingAuthority>,
    /// The key that signs the heads of the audit chain (ADR-0012).
    pub audit: Arc<SigningKey>,
    /// The key that signs the session grants (ADR-0004).
    pub grant: Arc<Issuer>,
    /// The SSH certificate authorities, if `[core.ssh]` is set (ADR-0014).
    pub ssh: Option<Arc<SshAuthorities>>,
    /// The key of the TOTP secrets, if `[core.login]` is set (ADR-0010).
    pub totp: Option<Arc<TotpKey>>,
    /// The transcript directory and the command key, with `[core.ssh]`
    /// (ADR-0016): no SSH without them.
    pub transcripts: Option<Arc<Transcripts>>,
    /// The LDAPS identity sources of `[core.identity]` (ADR-0021).
    pub directories: Option<Arc<Directories>>,
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys")
            .field("issuing", &self.issuing.common_name())
            .finish_non_exhaustive()
    }
}

fn read(path: &Path) -> Result<Vec<u8>, CoreError> {
    std::fs::read(path).map_err(|e| CoreError::Keys(format!("{} : {e}", path.display())))
}

/// Reads a private key: a plain file (`CFG-P012`), or a systemd credential
/// from `credentials` (`$CREDENTIALS_DIRECTORY`).
/// The transcript directory and the command key of `[core.ssh]`
/// (ADR-0016): no SSH without them.
fn load_transcripts(
    config: &CoreConfig,
    credentials: Option<&Path>,
) -> Result<Option<Arc<Transcripts>>, CoreError> {
    let Some(ssh) = &config.ssh else {
        return Ok(None);
    };
    let field = "core.ssh.command_mac_key";
    let mac = HmacKey::new(&read_key(field, &ssh.command_mac_key, credentials)?).map_err(|e| {
        CoreError::Keys(format!(
            "{field} : {e} (32 octets aléatoires attendus : ostena ca key new-mac)"
        ))
    })?;
    Ok(Some(Arc::new(Transcripts::open(
        &ssh.transcripts_dir,
        mac,
        config.audit.worm,
    )?)))
}

pub(crate) fn read_key(
    field: &str,
    source: &KeySource,
    credentials: Option<&Path>,
) -> Result<SecretBytes, CoreError> {
    let path = match source {
        KeySource::File(path) => path.clone(),
        KeySource::Credential(name) => credentials
            .ok_or_else(|| {
                CoreError::Keys(format!(
                    "{field} : credential « {name} » demandé, mais CREDENTIALS_DIRECTORY n'est pas \
                     défini (LoadCredentialEncrypted= dans l'unité systemd)"
                ))
            })?
            .join(name),
    };
    std::fs::read(&path)
        .map(SecretBytes::from)
        .map_err(|e| CoreError::Keys(format!("{field} {} : {e}", path.display())))
}

impl Keys {
    /// Loads the keys and certificates named by `config`; credentials are
    /// read from `credentials`.
    ///
    /// # Errors
    ///
    /// [`CoreError::Keys`] naming the file at fault.
    pub fn load(config: &CoreConfig, credentials: Option<&Path>) -> Result<Self, CoreError> {
        let keys = |what: &str, e: &dyn std::fmt::Display| CoreError::Keys(format!("{what} : {e}"));
        let root = TrustAnchor::from_pem(&read(&config.tls_root_ca)?)
            .map_err(|e| keys("core.tls_root_ca", &e))?;
        let server_key = read_key("core.tls_private_key", &config.tls_private_key, credentials)?;
        let server = Identity::from_pem(&read(&config.tls_certificate)?, &server_key)
            .map_err(|e| keys("core.tls_certificate / core.tls_private_key", &e))?;
        let issuing_key = ostena_crypto::pki::pkcs8_from_pem(&read_key(
            "core.issuing_private_key",
            &config.issuing_private_key,
            credentials,
        )?)
        .map_err(|e| keys("core.issuing_private_key", &e))?;
        let issuing_certificate = TrustAnchor::from_pem(&read(&config.issuing_certificate)?)
            .map_err(|e| keys("core.issuing_certificate", &e))?
            .certificate()
            .clone();
        let issuing_scalar = SigningKey::from_pkcs8(&issuing_key).and_then(|k| k.scalar());
        let issuing = IssuingAuthority::from_certificate(&issuing_key, issuing_certificate)
            .map_err(|e| {
                keys(
                    "core.issuing_certificate / core.issuing_private_key",
                    &format!("{e} (la clé n'est pas celle du certificat ?)"),
                )
            })?;
        let audit = ostena_crypto::pki::signing_key_from_pem(&read_key(
            "core.audit.signing_key",
            &config.audit.signing_key,
            credentials,
        )?)
        .map_err(|e| keys("core.audit.signing_key", &e))?;
        let signing = |field: &str, source: &KeySource| -> Result<SigningKey, CoreError> {
            ostena_crypto::pki::signing_key_from_pem(&read_key(field, source, credentials)?)
                .map_err(|e| keys(field, &e))
        };
        let grant = signing("core.grant_signing_key", &config.grant_signing_key)?;
        let ssh = match &config.ssh {
            Some(ssh) => Some(SshAuthorities::new(
                signing("core.ssh.user_ca_key", &ssh.user_ca_key)?,
                signing("core.ssh.host_ca_key", &ssh.host_ca_key)?,
                ssh.host_certificate_days,
            )?),
            None => None,
        };
        let transcripts = load_transcripts(config, credentials)?;
        // One key, one use, whatever the files (CFG-V016 compares sources).
        let issuing_public = SigningKey::from_pkcs8(&issuing_key)
            .map_err(|e| keys("core.issuing_private_key", &e))?
            .verifying_key();
        let tls_public = ostena_crypto::pki::signing_key_from_pem(&server_key)
            .map_err(|e| keys("core.tls_private_key", &e))?
            .verifying_key();
        let mut publics = vec![
            ("core.tls_private_key", tls_public),
            ("core.issuing_private_key", issuing_public),
            ("core.audit.signing_key", audit.verifying_key()),
            ("core.grant_signing_key", grant.verifying_key()),
        ];
        if let Some(ssh) = &ssh {
            publics.push(("core.ssh.user_ca_key", ssh.user_ca_public()));
            publics.push(("core.ssh.host_ca_key", ssh.host_ca_public()));
        }
        distinct_keys(&publics)?;
        let totp = match &config.login {
            Some(login) => {
                // A key of its own: never the bytes of another key.
                let mut others = Vec::new();
                let scalar =
                    |field: &'static str, key: &SigningKey| key.scalar().ok().map(|s| (field, s));
                others.extend(scalar("core.audit.signing_key", &audit));
                others.extend(scalar("core.grant_signing_key", &grant));
                if let Ok(s) = issuing_scalar {
                    others.push(("core.issuing_private_key", s));
                }
                if let Some(s) = ostena_crypto::pki::pkcs8_from_pem(&server_key)
                    .ok()
                    .and_then(|p| SigningKey::from_pkcs8(&p).ok())
                    .and_then(|k| k.scalar().ok())
                {
                    others.push(("core.tls_private_key", s));
                }
                if let Some(ssh) = &ssh {
                    others.extend(ssh.scalars());
                }
                let bytes = read_key("core.login.totp_key", &login.totp_key, credentials)?;
                Some(Arc::new(TotpKey::from_bytes(&bytes, &others)?))
            }
            None => None,
        };
        let directories = load_directories(config, credentials)?;
        Ok(Self {
            root,
            server,
            issuing: Arc::new(issuing),
            audit: Arc::new(audit),
            grant: Arc::new(Issuer::new(grant)),
            ssh: ssh.map(Arc::new),
            totp,
            transcripts,
            directories,
        })
    }
}

/// Each key of the core has one use: two fields with the same public key
/// are refused, whatever their sources.
fn distinct_keys(publics: &[(&str, ostena_crypto::p256::VerifyingKey)]) -> Result<(), CoreError> {
    for (i, (field, key)) in publics.iter().enumerate() {
        if let Some((other, _)) = publics[..i].iter().find(|(_, k)| k == key) {
            return Err(CoreError::Keys(format!(
                "{field} : même clé que {other} ; chaque clé du core a un seul usage"
            )));
        }
    }
    Ok(())
}

/// The key of the TOTP secrets alone, for `ostena core user totp-enroll`:
/// its format is checked, not its distinctness from the other keys (the
/// core checks it at startup).
///
/// # Errors
///
/// [`CoreError::Keys`], also when `[core.login]` is absent.
pub fn load_totp_key(
    config: &CoreConfig,
    credentials: Option<&Path>,
) -> Result<TotpKey, CoreError> {
    let login = config
        .login
        .as_ref()
        .ok_or_else(|| CoreError::Keys("section [core.login] absente".into()))?;
    let bytes = read_key("core.login.totp_key", &login.totp_key, credentials)?;
    TotpKey::from_bytes(&bytes, &[])
}

/// `$CREDENTIALS_DIRECTORY`, set by systemd for the credentials of the unit.
pub fn credentials_directory() -> Option<PathBuf> {
    std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from)
}

/// Open tunnels, by certificate fingerprint.
#[derive(Debug, Default)]
struct Tunnels(Mutex<HashMap<[u8; 32], Vec<Arc<CoreTunnel>>>>);

impl Tunnels {
    fn add(&self, fingerprint: [u8; 32], tunnel: Arc<CoreTunnel>) {
        if let Ok(mut map) = self.0.lock() {
            let list = map.entry(fingerprint).or_default();
            list.retain(|t| !t.is_closed());
            list.push(tunnel);
        }
    }

    /// Closes the tunnels of `fingerprints` with `error`.
    fn close(&self, fingerprints: &[[u8; 32]], error: &TunnelError) -> usize {
        let Ok(mut map) = self.0.lock() else {
            return 0;
        };
        let mut closed = 0;
        for fp in fingerprints {
            for tunnel in map.remove(fp).unwrap_or_default() {
                if !tunnel.is_closed() {
                    tunnel.close(error.clone());
                    closed += 1;
                }
            }
        }
        closed
    }

    /// Closes the tunnels whose certificate `keep` refuses.
    fn sweep(&self, keep: impl Fn(&[u8; 32]) -> bool) -> usize {
        let doomed: Vec<[u8; 32]> = self
            .0
            .lock()
            .map(|map| map.keys().filter(|fp| !keep(fp)).copied().collect())
            .unwrap_or_default();
        self.close(&doomed, &TunnelError::Revoked)
    }

    /// The open tunnels, with their certificate fingerprint.
    fn live(&self) -> Vec<([u8; 32], Arc<CoreTunnel>)> {
        self.0.lock().map_or_else(
            |_| Vec::new(),
            |map| {
                map.iter()
                    .flat_map(|(fp, list)| {
                        list.iter()
                            .filter(|t| !t.is_closed())
                            .map(|t| (*fp, t.clone()))
                    })
                    .collect()
            },
        )
    }

    fn open(&self) -> usize {
        self.0.lock().map_or(0, |map| {
            map.values().flatten().filter(|t| !t.is_closed()).count()
        })
    }

    fn close_all(&self, error: &TunnelError) {
        let all = self
            .0
            .lock()
            .map(|mut map| std::mem::take(&mut *map))
            .unwrap_or_default();
        for tunnel in all.into_values().flatten() {
            tunnel.close(error.clone());
        }
    }
}

/// The connected agents by gateway group, for the web listener.
struct Directory {
    tunnels: Arc<Tunnels>,
    cache: Arc<AgentCache>,
}

impl Agents for Directory {
    fn pick(&self, group: Uuid) -> Option<Uuid> {
        self.tunnels
            .live()
            .into_iter()
            .filter_map(|(fp, tunnel)| {
                let entry = self.cache.active(&fp)?;
                (entry.group == group).then(|| (tunnel.open_channels(), entry.agent))
            })
            .min()
            .map(|(_, agent)| agent)
    }

    fn tunnel(&self, agent: Uuid) -> Option<Arc<CoreTunnel>> {
        self.tunnels
            .live()
            .into_iter()
            .find_map(|(fp, tunnel)| (self.cache.active(&fp)?.agent == agent).then_some(tunnel))
    }
}

struct Shared {
    store: PgStore,
    cache: Arc<AgentCache>,
    issuer: Arc<IssuingAuthority>,
    enrollment: EnrollmentService,
    tunnels: Arc<Tunnels>,
    /// The gateway sessions of the portal (ADR-0020).
    relays: Arc<Relays>,
    certificate_lifetime: u64,
    limits: Limits,
    recorder: Arc<Recorder>,
    grants: Arc<GrantAuthority>,
    ssh: Option<Arc<SshAuthorities>>,
    transcripts: Option<Arc<Transcripts>>,
    /// Asks for a replay of what lost notices would have applied.
    resync: tokio::sync::Notify,
    /// Per-agent limits of `ssh_grant_request` and `ssh_host_key`.
    grant_requests: rate::Limiter,
    host_keys: rate::Limiter,
    stream_refusals: rate::Limiter,
}

/// What the start of the core writes to the audit chain besides
/// `core.started`: the weakenings in effect. The core no longer migrates:
/// `ostena core migrate` writes `core.migrated` itself (ADR-0011).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StartInfo {
    /// Weakening options and dated waivers in effect: (code, message).
    pub waivers: Vec<(String, String)>,
    /// `[[audit.outputs]]`: the syslog collectors of the audit export.
    pub audit_outputs: Vec<Output>,
}

/// What leaves the core besides the chain itself: the time-stamps of the
/// heads and the SIEM export (ADR-0012).
struct Exports {
    timestamper: Option<Timestamper>,
    forwarders: Vec<Forwarder>,
}

impl Exports {
    /// Reads the anchors, bundles and keys of both.
    fn load(config: &CoreConfig, info: &StartInfo) -> Result<Self, CoreError> {
        Ok(Self {
            timestamper: Timestamper::of(&config.audit)?,
            forwarders: Forwarder::load_all(
                &info.audit_outputs,
                credentials_directory().as_deref(),
            )?,
        })
    }

    fn spawn(self, pool: &sqlx::PgPool, recorder: &Arc<Recorder>) -> Vec<JoinHandle<()>> {
        let mut tasks: Vec<_> = self
            .forwarders
            .into_iter()
            .map(|f| f.spawn(pool.clone(), recorder.clone()))
            .collect();
        tasks.extend(
            self.timestamper
                .map(|t| t.spawn(pool.clone(), recorder.clone())),
        );
        tasks
    }
}

/// Time allowed at stop for the queue, `core.stopped` and the final head.
const STOP_TIMEOUT: Duration = Duration::from_secs(2);

/// Writes granting events in one transaction and tells the signer.
async fn write_granting(store: &PgStore, events: Vec<Event>) -> Result<(), CoreError> {
    let mut tx = store
        .pool()
        .begin()
        .await
        .map_err(|e| CoreError::AuditWrite(e.to_string()))?;
    let appended = audit::append_many(&mut tx, events).await?;
    tx.commit()
        .await
        .map_err(|e| CoreError::AuditWrite(e.to_string()))?;
    store.recorder().critical(&appended);
    Ok(())
}

fn core_event(kind: EventKind) -> Event {
    Event::new(kind, Outcome::Success, ActorKind::Core, audit::CORE_ACTOR)
}

/// The start records besides `core.started`.
fn start_events(signer: &HeadSigner, info: &StartInfo) -> Vec<Event> {
    let mut events = vec![signer.signing_started()];
    for (code, message) in &info.waivers {
        events.push(
            core_event(EventKind::ConfigWaiver)
                .text(field::CODE, truncate(code))
                .text(field::REASON, truncate(message)),
        );
    }
    events
}

/// The identity sources of `[core.identity]` (ADR-0021).
fn load_directories(
    config: &CoreConfig,
    credentials: Option<&Path>,
) -> Result<Option<Arc<Directories>>, CoreError> {
    let Some(identity) = &config.identity else {
        return Ok(None);
    };
    Directories::load(identity, credentials).map(|d| Some(Arc::new(d)))
}

/// The synchronisation of the identity sources of `keys`, if any.
fn identity_of(
    keys: &Keys,
    store: &PgStore,
    recorder: &Arc<Recorder>,
) -> Option<Arc<crate::identity::Identity>> {
    let directories = keys.directories.clone()?;
    Some(Arc::new(crate::identity::Identity::new(
        directories,
        store.pool().clone(),
        recorder.clone(),
    )))
}

/// The background tasks of a started core.
fn background(
    listener: &Arc<CoreListener>,
    notices: PgListener,
    shared: &Arc<Shared>,
    signer: &Arc<HeadSigner>,
    identity: Option<&Arc<crate::identity::Identity>>,
) -> Vec<JoinHandle<()>> {
    let mut tasks = vec![
        tokio::spawn(accept(listener.clone(), shared.clone())),
        tokio::spawn(follow_notices(notices, shared.clone())),
        tokio::spawn(resync_on_request(shared.clone())),
        tokio::spawn(reload_periodically(shared.clone())),
        tokio::spawn(signer.clone().run()),
        tokio::spawn(renew_host_certificates(shared.clone())),
    ];
    // The synchronisation of the identity sources (ADR-0021).
    if let Some(identity) = identity {
        tasks.extend(identity.spawn());
    }
    tasks
}

/// The listeners of `[core.login]` (ADR-0010, ADR-0015) and of
/// `[core.web]` (ADR-0020): one authenticator and one attempt limiter for
/// both.
async fn start_login(
    config: &CoreConfig,
    keys: &Keys,
    shared: &Arc<Shared>,
    recorder: &Arc<Recorder>,
    identity: Option<Arc<crate::identity::Identity>>,
) -> Result<(Option<LoginListener>, Option<WebListener>), CoreError> {
    let store = &shared.store;
    let Some(settings) = &config.login else {
        return Ok((None, None));
    };
    let (Some(ssh), Some(totp)) = (keys.ssh.clone(), keys.totp.clone()) else {
        return Err(CoreError::Startup(
            "[core.login] exige [core.ssh] et core.login.totp_key".into(),
        ));
    };
    let tls = tls::server_config(&keys.server, ClientAuth::None, &[b"http/1.1"])
        .map_err(|e| CoreError::Startup(e.to_string()))?;
    let mut authenticator =
        PgAuthenticator::new(store.pool().clone(), recorder.clone(), ssh, totp, settings);
    if let Some(identity) = identity {
        authenticator = authenticator.with_identity(identity);
    }
    let authenticator = Arc::new(authenticator);
    let limits = LoginLimits::from_config(settings);
    let attempts = Arc::new(Attempts::new(limits.attempts_per_minute));
    let login = LoginListener::bind_sharing(
        settings.listen,
        tls,
        limits,
        authenticator.clone(),
        attempts.clone(),
    )
    .await?;
    let Some(web) = &config.web else {
        return Ok((Some(login), None));
    };
    let groups = if web.tls_classic_fallback {
        WebGroups::HybridThenClassic
    } else {
        WebGroups::Hybrid
    };
    let tls = tls::web_server_config(&keys.server, groups)
        .map_err(|e| CoreError::Startup(e.to_string()))?;
    let listener = WebListener::bind(
        web.listen,
        tls,
        WebSettings::from_config(web),
        Arc::new(PgWebBackend::new(authenticator).with_access(web_access(shared))),
        attempts,
    )
    .await?;
    tracing::info!(
        event = "web.tls_groups",
        groups = ?groups.names(),
        origin = %web.origin,
        "groupes TLS de l'écouteur web (X25519MLKEM768 : écart admis, ADR-0009)"
    );
    Ok((Some(login), Some(listener)))
}

/// A started core. Dropping it does not stop it: call [`RunningCore::stop`].
pub struct RunningCore {
    shared: Arc<Shared>,
    listener: Arc<CoreListener>,
    tunnel_addr: SocketAddr,
    tasks: Vec<JoinHandle<()>>,
    writer: JoinHandle<()>,
    signer: Arc<HeadSigner>,
    login: Option<LoginListener>,
    web: Option<WebListener>,
}

impl std::fmt::Debug for RunningCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunningCore")
            .field("tunnel_addr", &self.tunnel_addr)
            .finish_non_exhaustive()
    }
}

/// What the access decisions of the portal need: the grant key and the
/// connected agents.
fn web_access(shared: &Shared) -> WebAccess {
    WebAccess {
        grants: shared.grants.clone(),
        agents: Arc::new(Directory {
            tunnels: shared.tunnels.clone(),
            cache: shared.cache.clone(),
        }),
        relays: shared.relays.clone(),
    }
}

impl RunningCore {
    /// Loads the registry, checks the audit chain and signs a head, writes
    /// the start records, binds the tunnel listener, prepares the enrolment
    /// listener (opened if a token is valid) and starts the background
    /// tasks.
    ///
    /// # Errors
    ///
    /// [`CoreError`] if the registry cannot be read, a listener cannot be
    /// bound, the audit chain is inconsistent (`CORE-E011`) or a start
    /// record cannot be written (`CORE-E010`).
    ///
    /// # Panics
    ///
    /// Outside a Tokio runtime.
    pub async fn start(
        config: &CoreConfig,
        store: PgStore,
        keys: &Keys,
        info: &StartInfo,
    ) -> Result<Self, CoreError> {
        // Unreadable anchors, bundles or keys refuse the start before
        // anything is written.
        let exports = Exports::load(config, info)?;
        let cache = store.cache();
        store.reload().await?;
        let recorder = store.recorder();
        let chain = audit::ensure_genesis(store.pool()).await?;
        let signer = Arc::new(HeadSigner::new(
            store.pool().clone(),
            keys.audit.clone(),
            Cadence::from(&config.audit),
            Arc::new(SystemClock),
            recorder.clone(),
        ));
        // A broken segment refuses the start (CORE-E011).
        signer.sign_now().await?;
        write_granting(&store, start_events(&signer, info)).await?;
        recover_transcripts(keys, &store, &recorder).await?;
        // The grant key: activated (granting record) if new.
        let (grants, activated) = GrantAuthority::load(store.pool(), keys.grant.clone()).await?;
        if let Some(appended) = activated {
            recorder.critical(&[appended]);
        }
        let startup = |e: TunnelError| CoreError::Startup(e.to_string());
        let limits = Limits::default();
        let (listener, tunnel_addr) = bind_tunnel(config, keys, &cache, limits)?;
        let certificate_lifetime = u64::from(config.agent_certificate_days) * DAY;
        let enrollment = EnrollmentService::new(
            config.enrollment_listen(),
            &keys.server,
            keys.issuing.clone(),
            Arc::new(store.clone()),
            Arc::new(store.clone()),
            Duration::from_secs(certificate_lifetime),
            ENROLL_TIMEOUT,
        )
        .map_err(startup)?;
        let shared = Arc::new(Shared {
            store,
            cache,
            issuer: keys.issuing.clone(),
            enrollment,
            tunnels: Arc::default(),
            relays: Arc::default(),
            certificate_lifetime,
            limits,
            recorder: recorder.clone(),
            grants: Arc::new(grants),
            ssh: keys.ssh.clone(),
            transcripts: keys.transcripts.clone(),
            resync: tokio::sync::Notify::new(),
            grant_requests: rate::Limiter::new(rate::GRANT_REQUESTS),
            host_keys: rate::Limiter::new(rate::HOST_KEYS),
            stream_refusals: rate::Limiter::new(rate::STREAM_REFUSALS),
        });
        write_granting(
            &shared.store,
            vec![
                core_event(EventKind::CoreStarted)
                    .text(field::VERSION, env!("CARGO_PKG_VERSION"))
                    .text(field::PEER_ADDR, tunnel_addr.to_string()),
            ],
        )
        .await?;
        let identity = identity_of(keys, &shared.store, &recorder);
        let (login, web) = start_login(config, keys, &shared, &recorder, identity.clone()).await?;
        // Tokens issued while the core was stopped.
        shared.enrollment.wake().await.map_err(startup)?;
        let notices = listen(shared.store.pool()).await?;
        let exporting = exports.spawn(shared.store.pool(), &recorder);
        let writer = tokio::spawn(audit::run_writer(shared.store.pool().clone(), recorder));
        let mut tasks = background(&listener, notices, &shared, &signer, identity.as_ref());
        tasks.extend(exporting);
        tracing::info!(
            event = "core.started",
            tunnel = %tunnel_addr,
            tunnel_tcp = %listener.tcp_local_addr(),
            enrollment = %shared.enrollment.addr(),
            chain = %chain,
            kid = %signer.kid(),
            grant_kid = %shared.grants.kid(),
            ssh = shared.ssh.is_some(),
            login = ?login.as_ref().map(LoginListener::local_addr),
            web = ?web.as_ref().map(WebListener::local_addr),
            "core démarré"
        );
        Ok(Self {
            shared,
            listener,
            tunnel_addr,
            tasks,
            writer,
            signer,
            login,
            web,
        })
    }

    /// The bound address of the web listener, if `[core.web]` is set.
    pub fn web_addr(&self) -> Option<SocketAddr> {
        self.web.as_ref().map(WebListener::local_addr)
    }

    /// The bound address of the login listener, if `[core.login]` is set.
    pub fn login_addr(&self) -> Option<SocketAddr> {
        self.login.as_ref().map(LoginListener::local_addr)
    }

    /// The bound tunnel address.
    pub fn tunnel_addr(&self) -> SocketAddr {
        self.tunnel_addr
    }

    /// The enrolment address.
    pub fn enrollment_addr(&self) -> SocketAddr {
        self.shared.enrollment.addr()
    }

    /// Whether the enrolment listener is bound.
    pub fn enrollment_open(&self) -> bool {
        self.shared.enrollment.is_open()
    }

    /// Open tunnels.
    pub fn open_tunnels(&self) -> usize {
        self.shared.tunnels.open()
    }

    /// Whether the copy of the registry can be used.
    pub fn registry_available(&self) -> bool {
        self.shared.cache.is_available()
    }

    /// The head signer.
    pub fn signer(&self) -> &Arc<HeadSigner> {
        &self.signer
    }

    /// Stops: closes both listeners and every tunnel, writes the queued
    /// audit events and `core.stopped`, then signs a last head; each step
    /// gets at most two seconds.
    pub async fn stop(self) {
        for task in &self.tasks {
            task.abort();
        }
        if let Some(login) = &self.login {
            login.close();
        }
        if let Some(web) = &self.web {
            web.close();
        }
        self.listener.close();
        self.shared.enrollment.close();
        self.shared
            .tunnels
            .close_all(&TunnelError::ConnectionLost("arrêt du core".into()));
        if !self.shared.recorder.flush(STOP_TIMEOUT).await {
            tracing::warn!(
                event = "audit.append_failed",
                pending = self.shared.recorder.pending(),
                "file d'audit non vidée à l'arrêt"
            );
        }
        let stopped = tokio::time::timeout(
            STOP_TIMEOUT,
            write_granting(&self.shared.store, vec![core_event(EventKind::CoreStopped)]),
        )
        .await;
        match stopped {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(event = "audit.append_failed", code = e.code(), "{e}"),
            Err(_) => tracing::warn!(
                event = "audit.append_failed",
                code = "CORE-E010",
                "core.stopped non écrit en 2 s"
            ),
        }
        match tokio::time::timeout(STOP_TIMEOUT, self.signer.sign_now()).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => tracing::warn!(event = "audit.head_failed", code = e.code(), "{e}"),
            Err(_) => tracing::warn!(
                event = "audit.head_failed",
                "dernière tête non signée en 2 s"
            ),
        }
        self.writer.abort();
        tracing::info!(event = "core.stopped", "core arrêté");
    }
}

async fn accept(listener: Arc<CoreListener>, shared: Arc<Shared>) {
    while let Some(accepted) = listener.accept().await {
        let accepted = match accepted {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(event = "tunnel.refused", code = e.code(), "{e}");
                continue;
            }
        };
        let fingerprint = accepted.fingerprint;
        let Some(entry) = shared.cache.active(&fingerprint) else {
            accepted.tunnel.close(TunnelError::UnknownAgent);
            continue;
        };
        if entry.group != accepted.hello.gateway_group {
            let e = TunnelError::Protocol("groupe annoncé différent du certificat".into());
            tracing::warn!(
                event = "tunnel.refused",
                agent = %entry.agent,
                code = e.code(),
                "{e}"
            );
            shared.recorder.emit(
                agent_event(EventKind::TunnelRefused, Outcome::Refused, entry.agent)
                    .uuid(field::GROUP_ID, entry.group.to_bytes())
                    .text(field::CODE, e.code()),
            );
            accepted.tunnel.close(e);
            continue;
        }
        let heartbeat_secs =
            u16::try_from(shared.limits.heartbeat_interval.as_secs().clamp(1, 60)).unwrap_or(10);
        let ack = CoreMessage::HelloAck {
            protocol: PROTOCOL_VERSION,
            core_version: env!("CARGO_PKG_VERSION").into(),
            heartbeat_secs,
        };
        if accepted.tunnel.send(&ack).await.is_err() {
            continue;
        }
        let tunnel = Arc::new(accepted.tunnel);
        shared.tunnels.add(fingerprint, tunnel.clone());
        // A revocation committed during the handshake: the notice may have
        // been handled before the tunnel was listed.
        if shared.cache.active(&fingerprint).is_none() {
            shared.tunnels.close(&[fingerprint], &TunnelError::Revoked);
            continue;
        }
        tracing::info!(
            event = "tunnel.agent_connected",
            agent = %entry.agent,
            group = %entry.group,
            agent_version = %accepted.hello.agent_version,
        );
        shared.recorder.emit(
            agent_event(
                EventKind::TunnelAgentConnected,
                Outcome::Success,
                entry.agent,
            )
            .uuid(field::GROUP_ID, entry.group.to_bytes())
            .text(
                field::AGENT_VERSION,
                truncate(&accepted.hello.agent_version),
            ),
        );
        tokio::spawn(streams(tunnel.clone(), entry.agent, shared.clone()));
        tokio::spawn(control(
            tunnel,
            fingerprint,
            entry.agent,
            entry.group,
            shared.clone(),
        ));
    }
}

/// Refuses SSH without its transcripts (ADR-0016), then seals as
/// incomplete the transcripts left unsealed by the previous stop.
async fn recover_transcripts(
    keys: &Keys,
    store: &PgStore,
    recorder: &Recorder,
) -> Result<(), CoreError> {
    if keys.ssh.is_some() && keys.transcripts.is_none() {
        return Err(CoreError::Startup(format!(
            "[{}] [core.ssh] sans répertoire de transcripts ni clé d'empreinte des commandes",
            transcripts::REFUSED
        )));
    }
    if let Some(transcripts) = &keys.transcripts {
        let recovered =
            transcripts::recover(store.pool(), recorder, transcripts, unix_now()).await?;
        if recovered > 0 {
            tracing::warn!(
                event = "transcript.recovered",
                count = recovered,
                code = transcripts::INCOMPLETE,
                "transcripts interrompus par l'arrêt précédent, scellés incomplets"
            );
        }
    }
    Ok(())
}

/// Counts a refused session stream of `agent`: `true` if it is within the
/// limit and is reported on its own. Beyond it, the tunnel of the agent is
/// closed, and one aggregated line is logged per minute at most
/// (`tunnel.streams_limited`) instead of one event per refusal.
fn refusal_allowed(shared: &Shared, tunnel: &CoreTunnel, agent: Uuid) -> bool {
    match shared
        .stream_refusals
        .check(agent, std::time::Instant::now())
    {
        rate::Decision::Allowed => true,
        rate::Decision::Refused { log } => {
            if let Some(refused) = log {
                tracing::warn!(
                    event = "tunnel.streams_limited",
                    agent = %agent,
                    refused,
                    code = transcripts::REFUSED,
                    "flux de session refusés au-delà de la limite : tunnel de l'agent fermé"
                );
            }
            tunnel.close(TunnelError::Protocol(
                "trop de flux de session refusés".into(),
            ));
            false
        }
    }
}

/// The session streams an agent opens: transcripts (ADR-0016) are received
/// and sealed; any other class is refused, the core relays no session data
/// yet.
async fn streams(tunnel: Arc<CoreTunnel>, agent: Uuid, shared: Arc<Shared>) {
    loop {
        let (session, class, mut channel) = match tunnel.accept_channel().await {
            Ok(accepted) => accepted,
            // A bad stream header: the stream is refused, the tunnel stays
            // up. Once the tunnel is closed, nothing more comes.
            Err(TunnelError::Protocol(e)) if !tunnel.is_closed() => {
                tracing::warn!(event = "tunnel.channel_refused", agent = %agent, "{e}");
                continue;
            }
            Err(TunnelError::Version(v)) if !tunnel.is_closed() => {
                tracing::warn!(event = "tunnel.channel_refused", agent = %agent, version = v);
                continue;
            }
            Err(_) => return,
        };
        if let (Some(store), ostena_tunnel::StreamClass::Recording) = (&shared.transcripts, class) {
            let shared = shared.clone();
            let store = store.clone();
            let tunnel = tunnel.clone();
            tokio::spawn(async move {
                transcripts::receive(
                    shared.store.pool(),
                    &shared.recorder,
                    &store,
                    agent,
                    session,
                    channel,
                    unix_now,
                    || refusal_allowed(&shared, &tunnel, agent),
                )
                .await;
            });
        } else {
            if refusal_allowed(&shared, &tunnel, agent) {
                tracing::warn!(
                    event = "tunnel.channel_refused",
                    agent = %agent,
                    session = %session,
                    class = ?class,
                    "flux de session refusé par le core"
                );
            }
            ostena_tunnel::recording::refuse(&mut channel);
        }
    }
}

/// Sends `message` on `tunnel`; a failure is logged (the tunnel is closing).
async fn send(tunnel: &CoreTunnel, agent: Uuid, message: &CoreMessage) -> bool {
    match tunnel.send(message).await {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(event = "core.push_failed", agent = %agent, code = e.code(), "{e}");
            false
        }
    }
}

/// What the core pushes to an agent that connects: the grant key set, the
/// policy of its group, its SSH trust, and the revoked login sessions it
/// received grants for (it may have missed their revocation while
/// disconnected; it applies them again without harm).
async fn push_on_connect(tunnel: &CoreTunnel, agent: Uuid, group: Uuid, shared: &Shared) {
    let pool = shared.store.pool();
    if !send(tunnel, agent, &shared.grants.key_set_message()).await {
        return;
    }
    match pushes::policy_message(pool, group).await {
        Ok(Some(policy)) => {
            send(tunnel, agent, &policy).await;
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!(event = "core.push_failed", agent = %agent, code = e.code(), "{e}");
        }
    }
    push_ssh_trust(tunnel, agent, group, shared).await;
    if !repeat_revocations(tunnel, agent, shared).await {
        // Not lost: the replay retries until it can read them.
        shared.resync.notify_one();
    }
}

/// Sends `agent` the revoked login sessions, not yet expired, it received
/// grants for or opened sessions with; it applies them again without harm.
/// `false` if they cannot be read.
async fn repeat_revocations(tunnel: &CoreTunnel, agent: Uuid, shared: &Shared) -> bool {
    match login::revoked_for_agent(shared.store.pool(), agent).await {
        Ok(sessions) => {
            for login_session in sessions {
                let message = CoreMessage::LoginRevoked {
                    login_session: login_session.to_string(),
                };
                send(tunnel, agent, &message).await;
            }
            true
        }
        Err(e) => {
            tracing::warn!(event = "core.push_failed", agent = %agent, code = e.code(), "{e}");
            false
        }
    }
}

async fn push_ssh_trust(tunnel: &CoreTunnel, agent: Uuid, group: Uuid, shared: &Shared) {
    let Some(ssh) = &shared.ssh else {
        return;
    };
    match pushes::ssh_trust_message(shared.store.pool(), ssh, agent, group, unix_now()).await {
        Ok(trust) => {
            send(tunnel, agent, &trust).await;
        }
        Err(e) => {
            tracing::warn!(event = "core.push_failed", agent = %agent, code = e.code(), "{e}");
        }
    }
}

/// Certifies the host key of `agent` (unless current: same key, current
/// host names of the group, not due), then pushes its SSH trust if the
/// certificate changed.
async fn certify_host(
    tunnel: &CoreTunnel,
    agent: Uuid,
    group: Uuid,
    key: &ostena_crypto::p256::VerifyingKey,
    shared: &Shared,
) {
    let Some(ssh) = &shared.ssh else {
        let refusal = Refusal {
            code: access::SSH_DISABLED,
            reason: "clé d'hôte SSH reçue, mais [core.ssh] n'est pas configuré".into(),
        };
        shared
            .recorder
            .emit(pushes::host_key_refused_event(agent, &refusal));
        return;
    };
    match pushes::certify_host(shared.store.pool(), ssh, agent, group, key, unix_now()).await {
        Ok(Some(appended)) => {
            shared.recorder.critical(&[appended]);
            push_ssh_trust(tunnel, agent, group, shared).await;
        }
        Ok(None) => {}
        Err(refusal) => {
            tracing::warn!(
                event = "ssh.host_key_refused",
                agent = %agent,
                code = refusal.code,
                "{}",
                refusal.reason
            );
            shared
                .recorder
                .emit(pushes::host_key_refused_event(agent, &refusal));
        }
    }
}

fn parse_hex32(text: &str) -> Option<[u8; 32]> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in bytes.chunks(2).enumerate() {
        let digit = |c: u8| char::from(c).to_digit(16);
        let value = digit(pair[0])? * 16 + digit(pair[1])?;
        out[i] = u8::try_from(value).ok()?;
    }
    Some(out)
}

/// An `ssh_grant_request` (already validated by the tunnel).
fn ssh_request(message: &AgentMessage) -> Option<(u64, SshRequest)> {
    let AgentMessage::SshGrantRequest {
        request_id,
        subject,
        login_session,
        certificate_sha256,
        account,
        resource,
        client_address,
    } = message
    else {
        return None;
    };
    Some((
        *request_id,
        SshRequest {
            subject: Uuid::parse(subject)?,
            login_session: Uuid::parse(login_session)?,
            certificate_sha256: parse_hex32(certificate_sha256)?,
            account: account.clone(),
            resource: resource.clone(),
            client_address: client_address.clone(),
        },
    ))
}

async fn answer_ssh_grant(
    tunnel: &CoreTunnel,
    agent: Uuid,
    group: Uuid,
    message: &AgentMessage,
    shared: &Shared,
) {
    let Some((request_id, request)) = ssh_request(message) else {
        return;
    };
    let decided = if shared.ssh.is_none() {
        Err(Refusal {
            code: access::SSH_DISABLED,
            reason: "[core.ssh] n'est pas configuré".into(),
        })
    } else {
        access::ssh_grant(
            shared.store.pool(),
            &shared.grants,
            agent,
            group,
            &request,
            unix_now(),
        )
        .await
    };
    let reply = match decided {
        Ok(issued) => {
            shared.recorder.critical(&[issued.appended]);
            tracing::info!(
                event = "access.ssh_granted",
                agent = %agent,
                jti = %issued.content.jti,
                user = %request.subject,
            );
            CoreMessage::SshGrant {
                request_id,
                grant: issued.grant,
            }
        }
        Err(refusal) => {
            tracing::warn!(
                event = "access.ssh_refused",
                agent = %agent,
                code = refusal.code,
                "{}",
                refusal.reason
            );
            shared
                .recorder
                .emit(access::ssh_refused_event(agent, &request, &refusal));
            refusal.to_message(request_id)
        }
    };
    send(tunnel, agent, &reply).await;
}

async fn answer_session(
    tunnel: &CoreTunnel,
    agent: Uuid,
    group: Uuid,
    request_id: u64,
    grant: &str,
    shared: &Shared,
) {
    let opened = access::open_session(
        shared.store.pool(),
        &shared.grants,
        agent,
        group,
        request_id,
        grant,
        unix_now(),
    )
    .await;
    let reply = match opened {
        Ok(opened) => {
            shared.recorder.critical(&[opened.appended]);
            tracing::info!(event = "access.session_opened", agent = %agent, session = %opened.session);
            opened.params
        }
        Err(refusal) => {
            tracing::warn!(
                event = "access.session_refused",
                agent = %agent,
                code = refusal.code,
                "{}",
                refusal.reason
            );
            shared.recorder.emit(access::session_refused_event(
                agent,
                access::jti_of(grant),
                &refusal,
            ));
            refusal.to_message(request_id)
        }
    };
    send(tunnel, agent, &reply).await;
}

/// Records a session report of the agent, then acknowledges it so that
/// the agent drops it from its queue (ADR-0012). A report already applied
/// (sent again after a lost link) is acknowledged without a second record;
/// one that cannot be written is not acknowledged, and comes back.
async fn close_session(tunnel: &CoreTunnel, agent: Uuid, message: AgentMessage, shared: &Shared) {
    let AgentMessage::SessionClosed {
        report_id,
        session_id,
        reason,
        bytes_to_target,
        bytes_from_target,
        closed_at,
    } = message
    else {
        return;
    };
    let Some(session) = Uuid::parse(&session_id) else {
        return;
    };
    match access::close_session(
        shared.store.pool(),
        agent,
        session,
        &reason,
        bytes_to_target,
        bytes_from_target,
        closed_at.min(unix_now()),
    )
    .await
    {
        Ok(event) => {
            if let Some(event) = event {
                shared.recorder.emit(event);
            }
            send(tunnel, agent, &CoreMessage::ReportAck { report_id }).await;
        }
        Err(e) => tracing::warn!(
            event = "access.session_close_failed",
            agent = %agent,
            code = e.code(),
            "{e}"
        ),
    }
}

/// Records the reports an agent dropped (full or unreadable queue), then
/// acknowledges the notice.
async fn reports_lost(tunnel: &CoreTunnel, agent: Uuid, message: &AgentMessage, shared: &Shared) {
    let &AgentMessage::ReportsLost {
        report_id,
        count,
        first_at,
        last_at,
        unreadable,
    } = message
    else {
        return;
    };
    tracing::error!(
        event = "agent.reports_lost",
        agent = %agent,
        count,
        unreadable,
        "bilans de session perdus par l'agent (file pleine ou illisible)"
    );
    let event = Event::new(
        EventKind::AgentReportsLost,
        Outcome::Failure,
        ActorKind::Agent,
        agent.to_string(),
    )
    .uuid(field::AGENT_ID, agent.to_bytes())
    .u64(field::LOST_COUNT, count)
    .u64(field::FIRST_MS, first_at.saturating_mul(1000))
    .u64(field::LAST_MS, last_at.saturating_mul(1000))
    .bool(field::COMPLETE, !unreadable);
    let mut tx = match shared.store.pool().begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::warn!(event = "agent.reports_lost", agent = %agent, "{e}");
            return;
        }
    };
    // Written before the acknowledgement: a notice is never dropped unseen.
    let appended = match audit::append(&mut tx, event).await {
        Ok(appended) => appended,
        Err(e) => {
            tracing::warn!(event = "agent.reports_lost", agent = %agent, code = e.code(), "{e}");
            return;
        }
    };
    if let Err(e) = tx.commit().await {
        tracing::warn!(event = "agent.reports_lost", agent = %agent, "{e}");
        return;
    }
    shared.recorder.critical(&[appended]);
    send(tunnel, agent, &CoreMessage::ReportAck { report_id }).await;
}

/// Binds the tunnel listener: agents authenticated by a certificate of the
/// issuing CA, checked against the registry cache.
fn bind_tunnel(
    config: &CoreConfig,
    keys: &Keys,
    cache: &Arc<AgentCache>,
    limits: Limits,
) -> Result<(Arc<CoreListener>, SocketAddr), CoreError> {
    let startup = |e: TunnelError| CoreError::Startup(e.to_string());
    let tls = tls::server_config(
        &keys.server,
        ClientAuth::Required {
            issuing_cas: vec![keys.issuing.trust_anchor()],
            authorizer: cache.clone(),
        },
        &[ALPN],
    )
    .map_err(|e| CoreError::Startup(e.to_string()))?;
    let listener =
        Arc::new(CoreListener::bind(config.tunnel_listen, tls, limits).map_err(startup)?);
    let tunnel_addr = listener.local_addr().map_err(startup)?;
    Ok((listener, tunnel_addr))
}

/// Control messages of one agent: the pushes when it connects, then
/// certificate renewal, SSH host key, grant and session requests.
async fn control(
    tunnel: Arc<CoreTunnel>,
    fingerprint: [u8; 32],
    agent: Uuid,
    group: Uuid,
    shared: Arc<Shared>,
) {
    push_on_connect(&tunnel, agent, group, &shared).await;
    while let Some(message) = tunnel.recv().await {
        match message {
            AgentMessage::Renew { request } => match renew(&shared, &fingerprint, &request).await {
                Ok(reply) => {
                    let _ = tunnel.send(&reply).await;
                }
                Err(e) => {
                    tracing::warn!(
                        event = "agent.renewal_refused",
                        agent = %agent,
                        code = e.code(),
                        "{e}"
                    );
                    shared.recorder.emit(
                        agent_event(EventKind::AgentRenewalRefused, Outcome::Refused, agent)
                            .text(field::CODE, e.code()),
                    );
                    tunnel.close(e);
                    break;
                }
            },
            AgentMessage::SshHostKey { .. }
                if !within_limit(&shared.host_keys, agent, "ssh_host_key") =>
            {
                // Ignored: the agent keeps its certificate, if any.
            }
            AgentMessage::SshGrantRequest { request_id, .. }
                if !within_limit(&shared.grant_requests, agent, "ssh_grant_request") =>
            {
                let refusal = Refusal {
                    code: access::RATE_LIMITED,
                    reason: String::new(),
                };
                send(&tunnel, agent, &refusal.to_message(request_id)).await;
            }
            AgentMessage::SshHostKey { p256_public, proof } => {
                match ostena_tunnel::ssh::verify_host_key(&p256_public, &proof, &fingerprint) {
                    Ok(key) => certify_host(&tunnel, agent, group, &key, &shared).await,
                    Err(e) => {
                        let refusal = Refusal {
                            code: e.code(),
                            reason: e.to_string(),
                        };
                        shared
                            .recorder
                            .emit(pushes::host_key_refused_event(agent, &refusal));
                        tunnel.close(e);
                        break;
                    }
                }
            }
            message @ AgentMessage::SshGrantRequest { .. } => {
                answer_ssh_grant(&tunnel, agent, group, &message, &shared).await;
            }
            AgentMessage::SessionRequest { request_id, grant } => {
                answer_session(&tunnel, agent, group, request_id, &grant, &shared).await;
            }
            message @ AgentMessage::SessionClosed { .. } => {
                close_session(&tunnel, agent, message, &shared).await;
            }
            message @ AgentMessage::ReportsLost { .. } => {
                reports_lost(&tunnel, agent, &message, &shared).await;
            }
            _ => {}
        }
    }
}

/// Whether a request `kind` of `agent` is within `limiter`; the refusals
/// are logged in aggregate (no audit record each: they would flood it).
fn within_limit(limiter: &rate::Limiter, agent: Uuid, kind: &str) -> bool {
    match limiter.check(agent, std::time::Instant::now()) {
        rate::Decision::Allowed => true,
        rate::Decision::Refused { log } => {
            if let Some(refused) = log {
                tracing::warn!(
                    event = "access.rate_limited",
                    agent = %agent,
                    request = kind,
                    refused,
                    code = access::RATE_LIMITED,
                    "demandes de l'agent au-delà de la limite, refusées"
                );
            }
            false
        }
    }
}

async fn renew(
    shared: &Shared,
    fingerprint: &[u8; 32],
    request: &str,
) -> Result<CoreMessage, TunnelError> {
    let key = renewal::verify(request, fingerprint)?;
    let entry = shared
        .cache
        .active(fingerprint)
        .ok_or(TunnelError::UnknownAgent)?;
    let now = unix_now();
    let validity = Validity {
        not_before: now.saturating_sub(SKEW),
        not_after: now + shared.certificate_lifetime,
    };
    let cert = shared
        .issuer
        .issue_agent(
            &key,
            &entry.group.to_string(),
            &entry.agent.to_string(),
            validity,
        )
        .map_err(|e| TunnelError::Io(e.to_string()))?;
    let new_fingerprint = tls::fingerprint(&cert);
    shared
        .store
        .register(new_fingerprint, entry.group, entry.agent)
        .await?;
    tracing::info!(
        event = "agent.certificate_renewed",
        agent = %entry.agent,
        fingerprint = %hex(&new_fingerprint),
        not_after = validity.not_after,
    );
    Ok(CoreMessage::Certificate {
        certificate: ostena_crypto::pki::pem_certificate(&cert),
        not_before: validity.not_before,
        not_after: validity.not_after,
    })
}

/// Opens a connection that listens to [`CHANNEL`].
async fn listen(pool: &sqlx::PgPool) -> Result<PgListener, sqlx::Error> {
    let mut notices = PgListener::connect_with(pool).await?;
    notices.listen(CHANNEL).await?;
    Ok(notices)
}

/// Applies the notices. A notice sent while the connection is lost is lost:
/// once it listens again, the core replays what such notices would have
/// applied ([`replay`]).
async fn follow_notices(mut notices: PgListener, shared: Arc<Shared>) {
    let mut last_error: Option<tokio::time::Instant> = None;
    loop {
        match notices.try_recv().await {
            Ok(Some(notice)) => apply_notice(&shared, notice.payload()).await,
            Ok(None) => {
                // Lost, then opened again and listening (sqlx reconnects).
                tracing::warn!(
                    event = "core.notices_interrupted",
                    "connexion de notification perdue, puis rouverte"
                );
                shared.resync.notify_one();
            }
            Err(e) => {
                tracing::warn!(event = "core.notices_interrupted", "{e}");
                // An error that comes back at once does not spin the loop.
                if last_error.is_some_and(|t| t.elapsed() < RETRY_INTERVAL) {
                    tokio::time::sleep(RETRY_INTERVAL).await;
                }
                last_error = Some(tokio::time::Instant::now());
                notices = listen_again(&shared).await;
                shared.resync.notify_one();
            }
        }
    }
}

/// A new listening connection, attempted every [`RETRY_INTERVAL`]; the copy
/// of the registry is reloaded meanwhile (a lost agent revocation).
async fn listen_again(shared: &Shared) -> PgListener {
    loop {
        match listen(shared.store.pool()).await {
            Ok(notices) => return notices,
            Err(e) => {
                tracing::warn!(event = "core.notices_interrupted", "{e}");
                reload(shared).await;
                tokio::time::sleep(RETRY_INTERVAL).await;
            }
        }
    }
}

async fn apply_notice(shared: &Arc<Shared>, payload: &str) {
    // Any change may have appended to the chain (administration commands
    // notify in the transaction of their record).
    shared.recorder.wake();
    match Notice::parse(payload) {
        Some(Notice::Token) => {
            if let Err(e) = shared.enrollment.wake().await {
                tracing::warn!(event = "enroll.wake_failed", code = e.code(), "{e}");
            }
        }
        Some(Notice::Revoked(agent)) => {
            let fingerprints = shared.cache.revoke_agent(agent);
            let closed = shared.tunnels.close(&fingerprints, &TunnelError::Revoked);
            tracing::warn!(
                event = "agent.revocation_applied",
                agent = %agent,
                tunnels_closed = closed,
            );
            shared.recorder.emit(
                agent_event(EventKind::AgentRevocationApplied, Outcome::Success, agent)
                    .u64(field::CLOSED_TUNNELS, closed as u64),
            );
        }
        Some(Notice::LoginRevoked(session)) => {
            tokio::spawn(apply_login_revocation(shared.clone(), session));
        }
        Some(Notice::Group(group)) => {
            let shared = shared.clone();
            tokio::spawn(async move {
                if !apply_group_change(&shared, group).await {
                    shared.resync.notify_one();
                }
            });
        }
        Some(Notice::Registered | Notice::Audit) | None => {}
    }
}

/// Replays, each time it is asked, until it succeeds (every
/// [`RETRY_INTERVAL`]). A request made during a replay starts another.
async fn resync_on_request(shared: Arc<Shared>) {
    loop {
        shared.resync.notified().await;
        while !replay(&shared).await {
            tokio::time::sleep(RETRY_INTERVAL).await;
        }
    }
}

/// What lost notices would have applied, from the database: the copy of the
/// registry reloaded (revoked agents), the enrolment listener woken (tokens),
/// the policy and host certificates of the groups of the connected agents,
/// and the revoked login sessions repeated to them. `false` if any part
/// failed: the whole is replayed again, each part being idempotent.
async fn replay(shared: &Shared) -> bool {
    let mut done = reload(shared).await;
    if let Err(e) = shared.enrollment.wake().await {
        tracing::warn!(event = "enroll.wake_failed", code = e.code(), "{e}");
        done = false;
    }
    let agents = connected(shared);
    let groups: std::collections::HashSet<Uuid> = agents.iter().map(|(_, g, _)| *g).collect();
    for group in groups {
        done &= apply_group_change(shared, group).await;
    }
    for (agent, _, tunnel) in &agents {
        done &= repeat_revocations(tunnel, *agent, shared).await;
    }
    tracing::info!(
        event = "core.notices_replayed",
        agents = agents.len(),
        complete = done,
    );
    done
}

/// Reloads the copy; then closes the tunnels it no longer accepts (a lost
/// revocation notice). While the copy is unavailable, open tunnels are kept
/// and new agents refused.
async fn reload(shared: &Shared) -> bool {
    if shared.store.reload().await.is_err() {
        return false;
    }
    let closed = shared.tunnels.sweep(|fp| shared.cache.active(fp).is_some());
    if closed > 0 {
        tracing::warn!(event = "agent.revocation_applied", tunnels_closed = closed);
        shared.recorder.emit(
            Event::new(
                EventKind::AgentRevocationApplied,
                Outcome::Success,
                ActorKind::Core,
                audit::CORE_ACTOR,
            )
            .u64(field::CLOSED_TUNNELS, closed as u64),
        );
    }
    true
}

async fn reload_periodically(shared: Arc<Shared>) {
    let mut wait = RELOAD_INTERVAL;
    loop {
        tokio::time::sleep(wait).await;
        wait = if reload(&shared).await {
            RELOAD_INTERVAL
        } else {
            RETRY_INTERVAL
        };
    }
}

/// The connected agents, by tunnel, with their group.
fn connected(shared: &Shared) -> Vec<(Uuid, Uuid, Arc<CoreTunnel>)> {
    shared
        .tunnels
        .live()
        .into_iter()
        .filter_map(|(fp, tunnel)| {
            let entry = shared.cache.active(&fp)?;
            Some((entry.agent, entry.group, tunnel))
        })
        .collect()
}

/// Tells the connected agents that received a grant for `session` that it
/// is revoked; those not connected are told when they connect.
async fn apply_login_revocation(shared: Arc<Shared>, session: Uuid) {
    // The gateway sessions of the portal end at once (ADR-0020).
    let cut = shared.relays.cut(session);
    if cut > 0 {
        tracing::warn!(event = "gateway.cut", login_session = %session, sessions = cut);
    }
    let agents = match login::agents_to_notify(shared.store.pool(), session).await {
        Ok(agents) => agents,
        Err(e) => {
            // Not dropped: the replay repeats every revoked login session to
            // the connected agents concerned, until it can read them.
            tracing::warn!(
                event = "login_session.revocation_failed",
                login_session = %session,
                code = e.code(),
                "{e}"
            );
            shared.resync.notify_one();
            return;
        }
    };
    let message = CoreMessage::LoginRevoked {
        login_session: session.to_string(),
    };
    let mut notified = std::collections::HashSet::new();
    for (agent, _, tunnel) in connected(&shared) {
        if agents.contains(&agent) && send(&tunnel, agent, &message).await {
            notified.insert(agent);
        }
    }
    tracing::warn!(
        event = "login_session.revocation_applied",
        login_session = %session,
        notified_agents = notified.len(),
    );
    shared.recorder.emit(
        Event::new(
            EventKind::LoginSessionRevocationApplied,
            Outcome::Success,
            ActorKind::Core,
            audit::CORE_ACTOR,
        )
        .uuid(field::LOGIN_SESSION, session.to_bytes())
        .u64(field::NOTIFIED_AGENTS, notified.len() as u64),
    );
}

/// Pushes the policy of `group` again to its connected agents and
/// certifies their host keys again if the SSH host names changed. `false`
/// if the policy or a host key could not be read (a replay retries).
async fn apply_group_change(shared: &Shared, group: Uuid) -> bool {
    let pool = shared.store.pool();
    let mut done = true;
    let policy = match pushes::policy_message(pool, group).await {
        Ok(policy) => policy,
        Err(e) => {
            tracing::warn!(event = "core.push_failed", group = %group, code = e.code(), "{e}");
            done = false;
            None
        }
    };
    for (agent, agent_group, tunnel) in connected(shared) {
        if agent_group != group {
            continue;
        }
        if let Some(policy) = &policy {
            send(&tunnel, agent, policy).await;
        }
        if shared.ssh.is_none() {
            continue;
        }
        match pushes::stored_host_key(pool, agent).await {
            Ok(Some(key)) => certify_host(&tunnel, agent, group, &key, shared).await,
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(event = "core.push_failed", agent = %agent, code = e.code(), "{e}");
                done = false;
            }
        }
    }
    done
}

/// Renews the host certificates due (two thirds of their life) of the
/// connected agents, every [`HOST_RENEWAL_INTERVAL`].
async fn renew_host_certificates(shared: Arc<Shared>) {
    if shared.ssh.is_none() {
        return;
    }
    loop {
        tokio::time::sleep(HOST_RENEWAL_INTERVAL).await;
        let due = match pushes::renewals_due(shared.store.pool(), unix_now()).await {
            Ok(due) => due,
            Err(e) => {
                tracing::warn!(event = "ssh.host_renewal_failed", code = e.code(), "{e}");
                continue;
            }
        };
        for (agent, group, tunnel) in connected(&shared) {
            if let Some((_, key)) = due.iter().find(|(a, _)| *a == agent) {
                certify_host(&tunnel, agent, group, key, &shared).await;
            }
        }
    }
}
