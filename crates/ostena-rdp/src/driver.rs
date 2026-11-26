//! The RDP [`Driver`] of the session manager (ADR-0018, ADR-0019).
//!
//! The core sends the RDP part of `session_params` ([`RdpSessionParams`]):
//! account, DNS name of the target for the SPN, pinned fingerprint, mode,
//! profile and licence. The agent adds what it alone holds
//! ([`RdpPolicy`]): the `[rdp]` bounds, the KDCs pinned by the scope
//! control, the key of the client identity, and the secret of the account
//! ([`SecretSource`]). The authentication is decided here, by rule:
//!
//! | Mode | Kerberos possible | NTLM |
//! |---|---|---|
//! | Restricted Admin | Kerberos, then NTLM if `ntlm_fallback` | only if `ntlm_fallback` |
//! | Delegation | Kerberos only | never in production (REG-SEC-02) |
//!
//! A dependency that panics is contained to the task of the connection:
//! the session is cut (`RDP-E099`), the agent goes on.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ironrdp_connector::DesktopSize;
use ostena_common::secret::SecretString;
use ostena_crypto::hmac::HmacKey;
use ostena_crypto::tls::target::TargetTrust;
use ostena_scope::PinnedTarget;
use ostena_session::{Activity, Driver, DriverConnection, Protocol};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, mpsc, watch};
use tokio::task::JoinHandle;

use crate::connect::{ConnectParams, ConnectReport, establish};
use crate::credssp::{Authentication, Kdcs, Mechanism};
use crate::error::RdpError;
use crate::profile::{StoredLicense, TargetProfile, client_identity, from_hex};
use crate::session::{Counters, SessionEnd, SessionLoop};

/// Bounds of the desktop size requested.
const DESKTOP_MIN: u16 = 200;
const DESKTOP_MAX: u16 = 8192;
/// Input frames queued towards the target at most.
const INPUT_QUEUE: usize = 256;
/// Delay of a clean close.
const CLOSE_DELAY: Duration = Duration::from_secs(2);

/// Delegation of the password or Restricted Admin, chosen per target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RdpMode {
    /// CredSSP `WithCredentials`: the password is delegated to the target.
    Delegation,
    /// CredSSP `CredentialLess` with `RESTRICTED_ADMIN_MODE_REQUIRED`.
    RestrictedAdmin,
}

/// The RDP part of `session_params`, sent by the core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RdpSessionParams {
    /// Account on the target: `user`, `DOMAIN\user` or `user@realm`.
    pub account: String,
    /// DNS name of the target in the inventory (SNI, SPN `TERMSRV/…`);
    /// absent for a target known by its address only (no Kerberos).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_name: Option<String>,
    /// SHA-256 of the DER certificate of the target, hexadecimal (`pinned`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_sha256: Option<String>,
    /// Mode of the target.
    pub mode: RdpMode,
    /// Desktop width requested.
    pub width: u16,
    /// Desktop height requested.
    pub height: u16,
    /// Profile remembered by the core.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<TargetProfile>,
    /// Licence kept by the core for this agent and target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<StoredLicense>,
}

impl RdpSessionParams {
    /// Checks the fields on their own.
    ///
    /// # Errors
    ///
    /// [`RdpError::Params`] naming the field.
    pub fn validate(&self) -> Result<(), RdpError> {
        let bad = |m: &str| Err(RdpError::Params(m.to_owned()));
        if self.account.is_empty()
            || self.account.len() > 256
            || self.account.chars().any(char::is_control)
        {
            return bad("account");
        }
        if let Some(name) = &self.target_name
            && ostena_scope::parse_host(name).is_err()
        {
            return bad("target_name");
        }
        if let Some(fp) = &self.certificate_sha256
            && (fp.len() != 64 || from_hex(fp).is_none())
        {
            return bad("certificate_sha256");
        }
        for side in [self.width, self.height] {
            if !(DESKTOP_MIN..=DESKTOP_MAX).contains(&side) {
                return bad("width/height");
            }
        }
        Ok(())
    }
}

/// How the agent validates target certificates (`[rdp]
/// certificate_validation`).
#[derive(Debug, Clone)]
pub enum Validation {
    /// Fingerprint sent by the core, compared exactly.
    Pinned,
    /// Chain to the customer authority (`pki_ca_bundle`).
    Pki(Vec<ostena_crypto::tls::TrustAnchor>),
}

/// What the agent alone holds, for every RDP session.
pub struct RdpPolicy {
    /// Production mode: the weakening options are refused.
    pub production: bool,
    /// Certificate validation.
    pub validation: Validation,
    /// `[rdp] password_delegation`.
    pub password_delegation: bool,
    /// `[rdp] ntlm_fallback`.
    pub ntlm_fallback: bool,
    /// The configured realms and their KDCs, pinned.
    pub realms: Vec<Kdcs>,
    /// Key of the client identity (licences).
    pub identity_key: HmacKey,
    /// Name of the agent as a workstation (NTLM, Kerberos).
    pub workstation: String,
}

impl std::fmt::Debug for RdpPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RdpPolicy")
            .field("production", &self.production)
            .field("validation", &self.validation)
            .field("password_delegation", &self.password_delegation)
            .field("ntlm_fallback", &self.ntlm_fallback)
            .field("realms", &self.realms)
            .finish_non_exhaustive()
    }
}

/// Where the secrets of the accounts are read.
pub trait SecretSource: Send + Sync + 'static {
    /// The password of `account`.
    ///
    /// # Errors
    ///
    /// [`RdpError::Secret`] when it cannot be read.
    fn password(&self, account: &str) -> Result<SecretString, RdpError>;
}

/// The realm of `account`, in upper case, if it names one.
fn realm_of(account: &str) -> Option<String> {
    if let Some((_, realm)) = account.rsplit_once('@') {
        return Some(realm.to_ascii_uppercase());
    }
    account
        .split_once('\\')
        .map(|(domain, _)| domain.to_ascii_uppercase())
}

/// Decides the mechanism (table of the module documentation).
///
/// # Errors
///
/// [`RdpError::Params`] for delegation not admitted, [`RdpError::NtlmRefused`]
/// when only NTLM would remain and it is not admitted.
pub fn mechanism(policy: &RdpPolicy, params: &RdpSessionParams) -> Result<Mechanism, RdpError> {
    let kdcs = params.target_name.as_ref().and_then(|_| {
        let realm = realm_of(&params.account)?;
        policy
            .realms
            .iter()
            .find(|k| {
                // The realm itself, or its NetBIOS name (`CORP\user`).
                let configured = k.realm.to_ascii_uppercase();
                configured == realm || configured.starts_with(&format!("{realm}."))
            })
            .cloned()
    });
    let ntlm = match params.mode {
        RdpMode::RestrictedAdmin => policy.ntlm_fallback,
        RdpMode::Delegation => {
            if !policy.password_delegation {
                return Err(RdpError::Params(
                    "délégation du mot de passe non admise par [rdp] password_delegation".into(),
                ));
            }
            // Never with a delegated password in production (REG-SEC-02);
            // the development mode admits it for the tests.
            !policy.production && policy.ntlm_fallback
        }
    };
    match (kdcs, ntlm) {
        (Some(k), false) => Ok(Mechanism::Kerberos(k)),
        (Some(k), true) => Ok(Mechanism::KerberosThenNtlm(k)),
        (None, true) => Ok(Mechanism::Ntlm),
        (None, false) => Err(RdpError::NtlmRefused(
            "Kerberos impossible pour cette cible (nom DNS ou domaine sans KDC configuré) \
             et repli NTLM non admis",
        )),
    }
}

/// What a session needs besides the target.
pub struct TargetParams {
    /// From the core.
    pub session: RdpSessionParams,
    /// Names the target in events (`account@resource`, sanitised).
    pub label: String,
}

impl std::fmt::Debug for TargetParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TargetParams")
            .field("session", &self.session)
            .field("label", &self.label)
            .finish()
    }
}

/// The RDP driver.
#[derive(Clone)]
pub struct RdpDriver {
    policy: Arc<RdpPolicy>,
    secrets: Arc<dyn SecretSource>,
}

impl std::fmt::Debug for RdpDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RdpDriver")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl RdpDriver {
    /// A driver applying `policy`, reading secrets from `secrets`.
    pub fn new(policy: Arc<RdpPolicy>, secrets: Arc<dyn SecretSource>) -> Self {
        Self { policy, secrets }
    }

    /// Everything [`establish`] needs, decided from the policy.
    ///
    /// # Errors
    ///
    /// [`RdpError::Params`], [`RdpError::NtlmRefused`], [`RdpError::Secret`].
    pub fn plan(
        &self,
        target: &PinnedTarget,
        params: TargetParams,
    ) -> Result<ConnectParams, RdpError> {
        let session = params.session;
        session.validate()?;
        let trust = match &self.policy.validation {
            Validation::Pinned => {
                let fp = session
                    .certificate_sha256
                    .as_deref()
                    .and_then(from_hex)
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .ok_or_else(|| {
                        RdpError::Params("empreinte du certificat de la cible absente".into())
                    })?;
                TargetTrust::Pinned(fp)
            }
            Validation::Pki(anchors) => {
                if session.target_name.is_none() {
                    return Err(RdpError::Params(
                        "mode pki : la cible doit être inscrite par son nom DNS".into(),
                    ));
                }
                TargetTrust::Pki(anchors.clone())
            }
        };
        let mechanism = mechanism(&self.policy, &session)?;
        let server_name = session
            .target_name
            .clone()
            .or_else(|| target.name().map(ToString::to_string))
            .or_else(|| target.addrs().first().map(|a| a.ip().to_string()))
            .ok_or_else(|| RdpError::Params("cible sans nom ni adresse".into()))?;
        let spn = format!("TERMSRV/{server_name}");
        let password = self.secrets.password(&session.account)?;
        let (client_name, hardware_id) = client_identity(&self.policy.identity_key, &server_name);
        Ok(ConnectParams {
            server_name,
            trust,
            auth: Authentication {
                username: session.account,
                password,
                spn,
                mechanism,
                restricted_admin: session.mode == RdpMode::RestrictedAdmin,
                workstation: self.policy.workstation.clone(),
            },
            desktop: DesktopSize {
                width: session.width,
                height: session.height,
            },
            client_name,
            hardware_id,
            profile: session.profile,
            license: session.license,
            label: params.label,
        })
    }
}

/// Emits the event of a failed connection.
fn log_failure(label: &str, error: &RdpError) {
    tracing::warn!(
        event = error.event(),
        code = error.code(),
        target = label,
        "{error}"
    );
}

/// Tries the addresses of `target` in order within `timeout`.
async fn connect_any(
    target: &PinnedTarget,
    params: ConnectParams,
) -> Result<crate::connect::Established, RdpError> {
    // One address only: the parameters (and the secret) are consumed by
    // the attempt, and a second attempt would play CredSSP again.
    let addr = *target
        .addrs()
        .first()
        .ok_or_else(|| RdpError::Unreachable("aucune adresse".into()))?;
    establish(addr, params).await
}

impl Driver for RdpDriver {
    type Params = TargetParams;
    type Connection = RdpConnection;
    type Error = RdpError;

    const PROTOCOL: Protocol = Protocol::Rdp;

    fn connect(
        &self,
        target: &PinnedTarget,
        params: TargetParams,
        timeout: Duration,
    ) -> impl Future<Output = Result<RdpConnection, RdpError>> + Send {
        let label = params.label.clone();
        let planned = self.plan(target, params);
        let target = target.clone();
        async move {
            let planned = match planned {
                Ok(p) => p,
                Err(e) => {
                    log_failure(&label, &e);
                    return Err(e);
                }
            };
            // A panic in a dependency stays in this task (RDP-E099).
            let task = tokio::spawn(async move {
                tokio::time::timeout(timeout, connect_any(&target, planned)).await
            });
            let outcome = match task.await {
                Ok(Ok(result)) => result,
                Ok(Err(_)) => Err(RdpError::Timeout),
                Err(_) => Err(RdpError::Internal),
            };
            match outcome {
                Ok(established) => Ok(RdpConnection::start(established, label)),
                Err(e) => {
                    log_failure(&label, &e);
                    Err(e)
                }
            }
        }
    }
}

/// How a connection ended, with what the loop counted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ended {
    /// Why.
    pub end: SessionEnd,
    /// Counters of the loop.
    pub counters: Counters,
}

/// An established RDP connection, its session loop running.
pub struct RdpConnection {
    report: ConnectReport,
    inputs: mpsc::Sender<Vec<u8>>,
    stop: watch::Sender<bool>,
    closed: Arc<AtomicBool>,
    activity: watch::Sender<Option<Activity>>,
    task: Mutex<Option<JoinHandle<Ended>>>,
    label: String,
}

impl std::fmt::Debug for RdpConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RdpConnection")
            .field("label", &self.label)
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

impl RdpConnection {
    fn start(established: crate::connect::Established, label: String) -> Self {
        let crate::connect::Established {
            transport,
            result,
            report,
        } = established;
        let (inputs, input_rx) = mpsc::channel(INPUT_QUEUE);
        let (stop, stop_rx) = watch::channel(false);
        let (activity, mut activity_rx) = watch::channel::<Option<Activity>>(None);
        let closed = Arc::new(AtomicBool::new(false));
        let flag = closed.clone();
        let task_label = label.clone();
        let task = tokio::spawn(async move {
            // The activity handle arrives once the session is open.
            let activity = activity_rx.borrow_and_update().clone();
            let looped =
                tokio::spawn(SessionLoop::new(transport, result).run(input_rx, stop_rx, activity));
            let (end, counters) = match looped.await {
                Ok(done) => done,
                Err(_) => (SessionEnd::Failed(RdpError::Internal), Counters::default()),
            };
            flag.store(true, Ordering::Release);
            if let SessionEnd::Failed(e) = &end {
                log_failure(&task_label, e);
            }
            Ended { end, counters }
        });
        Self {
            report,
            inputs,
            stop,
            closed,
            activity,
            task: Mutex::new(Some(task)),
            label,
        }
    }

    /// What the sequence reported (profile, licence, phases), for the
    /// report of the session to the core.
    pub fn report(&self) -> &ConnectReport {
        &self.report
    }

    /// A sender of input frames towards the target.
    pub fn inputs(&self) -> mpsc::Sender<Vec<u8>> {
        self.inputs.clone()
    }

    /// Gives the activity handle of the session (idle delay).
    pub fn set_activity(&self, activity: Activity) {
        let _ = self.activity.send(Some(activity));
    }

    /// Waits for the end of the session loop, once.
    pub async fn ended(&self) -> Option<Ended> {
        let task = self.task.lock().await.take()?;
        task.await.ok()
    }
}

impl DriverConnection for RdpConnection {
    #[allow(clippy::manual_async_fn, reason = "the trait asks for a Send future")]
    fn close(&self) -> impl Future<Output = ()> + Send {
        async move {
            let _ = self.stop.send(true);
            if let Some(task) = self.task.lock().await.take() {
                let _ = tokio::time::timeout(CLOSE_DELAY, task).await;
            }
            self.closed.store(true, Ordering::Release);
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(production: bool, delegation: bool, ntlm: bool, realms: Vec<Kdcs>) -> RdpPolicy {
        RdpPolicy {
            production,
            validation: Validation::Pinned,
            password_delegation: delegation,
            ntlm_fallback: ntlm,
            realms,
            identity_key: HmacKey::new(&HmacKey::generate().unwrap()).unwrap(),
            workstation: "OST-AGENT".into(),
        }
    }

    fn params(account: &str, name: Option<&str>, mode: RdpMode) -> RdpSessionParams {
        RdpSessionParams {
            account: account.into(),
            target_name: name.map(Into::into),
            certificate_sha256: Some("ab".repeat(32)),
            mode,
            width: 1280,
            height: 720,
            profile: None,
            license: None,
        }
    }

    fn corp() -> Vec<Kdcs> {
        vec![Kdcs {
            realm: "CORP.EXAMPLE.TEST".into(),
            servers: Vec::new(),
        }]
    }

    #[test]
    fn delegation_never_falls_back_to_ntlm_in_production() {
        // REG-SEC-02: a password delegated without Kerberos is refused,
        // even with ntlm_fallback (which the configuration refuses too).
        let p = policy(true, true, true, corp());
        let local = params("admin", Some("srv.example.test"), RdpMode::Delegation);
        assert!(matches!(
            mechanism(&p, &local),
            Err(RdpError::NtlmRefused(_))
        ));
        let domain = params(
            "admin@corp.example.test",
            Some("srv.corp.example.test"),
            RdpMode::Delegation,
        );
        assert!(matches!(mechanism(&p, &domain), Ok(Mechanism::Kerberos(_))));
        // By address only: no Kerberos, so no delegation.
        let by_ip = params("admin@corp.example.test", None, RdpMode::Delegation);
        assert!(matches!(
            mechanism(&p, &by_ip),
            Err(RdpError::NtlmRefused(_))
        ));
        // Development: admitted for the tests.
        let dev = policy(false, true, true, Vec::new());
        assert!(matches!(mechanism(&dev, &local), Ok(Mechanism::Ntlm)));
        // Delegation not admitted by [rdp].
        let off = policy(false, false, true, corp());
        assert!(matches!(mechanism(&off, &domain), Err(RdpError::Params(_))));
    }

    #[test]
    fn restricted_admin_admits_ntlm_only_with_the_fallback() {
        let local = params("admin", Some("srv.example.test"), RdpMode::RestrictedAdmin);
        assert!(matches!(
            mechanism(&policy(true, false, true, Vec::new()), &local),
            Ok(Mechanism::Ntlm)
        ));
        assert!(matches!(
            mechanism(&policy(true, false, false, Vec::new()), &local),
            Err(RdpError::NtlmRefused(_))
        ));
        let domain = params(
            "CORP\\admin",
            Some("srv.corp.example.test"),
            RdpMode::RestrictedAdmin,
        );
        let p = policy(
            true,
            false,
            true,
            vec![Kdcs {
                realm: "CORP".into(),
                servers: Vec::new(),
            }],
        );
        assert!(matches!(
            mechanism(&p, &domain),
            Ok(Mechanism::KerberosThenNtlm(_))
        ));
    }

    #[test]
    fn params_are_bounded() {
        let ok = params("admin", Some("srv.example.test"), RdpMode::RestrictedAdmin);
        assert!(ok.validate().is_ok());
        let mut bad = ok.clone();
        bad.width = 10;
        assert!(bad.validate().is_err());
        let mut bad = ok.clone();
        bad.certificate_sha256 = Some("zz".into());
        assert!(bad.validate().is_err());
        let mut bad = ok.clone();
        bad.account = "a\nb".into();
        assert!(bad.validate().is_err());
        let json = serde_json::to_string(&ok).unwrap();
        assert_eq!(serde_json::from_str::<RdpSessionParams>(&json).unwrap(), ok);
        assert!(
            serde_json::from_str::<RdpSessionParams>(&json.replace('}', r#","x":1}"#)).is_err()
        );
    }
}
