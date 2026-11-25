//! The decision of a native SSH access and the consumption of its grant
//! (ADR-0014).
//!
//! 1. `ssh_grant_request`: the agent relays what the user certificate
//!    says. In one transaction, the user, the login session, the resource,
//!    the account and a right are read and locked (`FOR SHARE`: a
//!    revocation waits for the grant to be recorded, then finds it); a grant
//!    is signed and recorded by jti with its granting audit record.
//! 2. `session_request`: the grant is verified again, its jti consumed once
//!    for the whole group (`FOR UPDATE`), everything it depends on read
//!    again; the session is recorded with its granting audit record.
//! 3. `session_closed`: the end is recorded.
//!
//! A refusal carries a precise code for the agent and its full reason for
//! the audit chain; nothing goes back to the SSH client.
//!
//! Lock order, everywhere (ADR-0014): `access_grant`, `app_user`,
//! `login_session`, `resource`, `target_account`, `access_right`. A
//! transaction that locks two of them takes them in this order, or two
//! transactions could wait for each other.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ostena_audit::{ActorKind, Event, EventKind, Outcome, field};
use ostena_grant::{
    Binding, Claims, GatewayGroupId, Grant, Protocol, ResourceId, Rights, SignedGrant, SubjectId,
    Verifier,
};
use ostena_tunnel::Uuid;
use ostena_tunnel::control::{CoreMessage, SessionProtocol};
use sqlx::PgPool;

use crate::audit::{self, Appended, Tx};
use crate::error::CoreError;
use crate::grant_keys::GrantAuthority;
use crate::store::{i64_of, truncate, uuid};

/// Why an access is refused: a stable code for the agent, the reason for
/// the audit chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// Stable code, e.g. `ACC-E006`.
    pub code: &'static str,
    /// Full reason (audit only).
    pub reason: String,
}

impl Refusal {
    fn new(code: &'static str, reason: impl Into<String>) -> Self {
        Self {
            code,
            reason: reason.into(),
        }
    }

    /// The message sent to the agent: the code and its generic label, not
    /// the reason.
    pub fn to_message(&self, request_id: u64) -> CoreMessage {
        CoreMessage::SessionRefused {
            request_id,
            code: self.code.to_owned(),
            message: label(self.code).to_owned(),
        }
    }
}

impl From<sqlx::Error> for Refusal {
    fn from(e: sqlx::Error) -> Self {
        Self::new("CORE-E001", e.to_string())
    }
}

impl From<CoreError> for Refusal {
    fn from(e: CoreError) -> Self {
        Self::new(e.code(), e.to_string())
    }
}

/// The generic label of a refusal code.
pub fn label(code: &str) -> &'static str {
    match code {
        LOGIN_UNKNOWN => "session de connexion inconnue",
        LOGIN_EXPIRED => "session de connexion expirée",
        LOGIN_REVOKED => "session de connexion révoquée",
        LOGIN_MISMATCH => "certificat différent de la session de connexion",
        USER_INACTIVE => "utilisateur inconnu ou désactivé",
        NO_RIGHT => "aucun droit valide",
        SSH_DISABLED => "accès SSH non configuré sur le core",
        GRANT_UNKNOWN => "grant inconnu du core",
        RESOURCE_UNKNOWN => "ressource inconnue de l'inventaire",
        OTHER_GROUP => "ressource d'un autre groupe de passerelles",
        ACCOUNT_UNKNOWN => "compte inconnu sur la ressource",
        HOST_KEY_MISSING => "clé d'hôte de la cible non épinglée",
        NO_HOST_NAME => "aucun nom d'hôte SSH pour le groupe",
        _ => "accès refusé",
    }
}

/// `ACC-E001`: login session unknown.
pub const LOGIN_UNKNOWN: &str = "ACC-E001";
/// `ACC-E002`: login session expired.
pub const LOGIN_EXPIRED: &str = "ACC-E002";
/// `ACC-E003`: login session revoked.
pub const LOGIN_REVOKED: &str = "ACC-E003";
/// `ACC-E004`: subject or certificate other than the login session's.
pub const LOGIN_MISMATCH: &str = "ACC-E004";
/// `ACC-E005`: user unknown or disabled.
pub const USER_INACTIVE: &str = "ACC-E005";
/// `ACC-E006`: no valid right.
pub const NO_RIGHT: &str = "ACC-E006";
/// `ACC-E007`: SSH not configured on the core (`[core.ssh]`).
pub const SSH_DISABLED: &str = "ACC-E007";
/// `ACC-E008`: grant unknown to the core.
pub const GRANT_UNKNOWN: &str = "ACC-E008";
/// `INV-E001`: resource unknown (or disabled).
pub const RESOURCE_UNKNOWN: &str = "INV-E001";
/// `INV-E002`: resource of another gateway group.
pub const OTHER_GROUP: &str = "INV-E002";
/// `INV-E003`: account unknown on the resource (or disabled).
pub const ACCOUNT_UNKNOWN: &str = "INV-E003";
/// `INV-E004`: host key of the target not pinned.
pub const HOST_KEY_MISSING: &str = "INV-E004";
/// `INV-E005`: no SSH host name for the group (no host certificate).
pub const NO_HOST_NAME: &str = "INV-E005";

/// What an agent asks for a native SSH user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshRequest {
    /// The user, principal of the certificate.
    pub subject: Uuid,
    /// The login session, key identifier of the certificate.
    pub login_session: Uuid,
    /// SHA-256 of the certificate.
    pub certificate_sha256: [u8; 32],
    /// Account on the target.
    pub account: String,
    /// Resource name.
    pub resource: String,
    /// Address of the SSH client.
    pub client_address: String,
}

/// What a right allows, after every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowed {
    /// The right used.
    pub right: Uuid,
    /// The resource.
    pub resource: Uuid,
    /// Its gateway group.
    pub group: Uuid,
    /// The account.
    pub account: Uuid,
    /// Target host.
    pub host: String,
    /// Target port.
    pub port: u16,
    /// Pinned host key of the target.
    pub target_p256_public: [u8; 65],
    /// Longest session the right allows now: its maximum, and no later
    /// than its end.
    pub max_session_secs: u32,
}

fn secs_until(end: i64, now: u64) -> u64 {
    u64::try_from(end).unwrap_or(0).saturating_sub(now)
}

/// The user, read with `FOR SHARE` before the login session (the lock
/// order of ADR-0014); checked by [`UserLock::active`].
struct UserLock {
    user: Uuid,
    active: bool,
}

impl UserLock {
    async fn take(tx: &mut Tx<'_>, user: Uuid) -> Result<Self, Refusal> {
        let active = sqlx::query_scalar!(
            "SELECT state = 'active' FROM app_user WHERE id = $1::text::uuid FOR SHARE",
            user.to_string(),
        )
        .fetch_optional(&mut **tx)
        .await?
        .flatten();
        Ok(Self {
            user,
            active: active == Some(true),
        })
    }

    /// The user must exist and be active.
    fn active(&self) -> Result<(), Refusal> {
        if self.active {
            Ok(())
        } else {
            Err(Refusal::new(
                USER_INACTIVE,
                format!("utilisateur {} inconnu ou désactivé", self.user),
            ))
        }
    }
}

/// The resource, the account and a valid right of `user` (already locked
/// and checked), read with `FOR SHARE` in `tx`. `group` is the group of the
/// asking agent (`None`: any, for the dry run).
async fn allowed(
    tx: &mut Tx<'_>,
    user: Uuid,
    resource: &str,
    account: &str,
    group: Option<Uuid>,
    now: u64,
) -> Result<Allowed, Refusal> {
    let Some(r) = sqlx::query!(
        r#"SELECT id::text AS "id!", gateway_group::text AS "group!", host, port,
                  ssh_host_p256_public
           FROM resource WHERE name = $1 AND disabled_at IS NULL FOR SHARE"#,
        resource,
    )
    .fetch_optional(&mut **tx)
    .await?
    else {
        return Err(Refusal::new(
            RESOURCE_UNKNOWN,
            format!(
                "ressource « {} » inconnue ou désactivée",
                truncate(resource)
            ),
        ));
    };
    let resource_group = uuid(&r.group)?;
    if let Some(group) = group
        && group != resource_group
    {
        return Err(Refusal::new(
            OTHER_GROUP,
            format!(
                "ressource « {resource} » du groupe {resource_group}, demandée par le groupe {group}"
            ),
        ));
    }
    let Some(target_p256_public) = r
        .ssh_host_p256_public
        .and_then(|k| <[u8; 65]>::try_from(k.as_slice()).ok())
    else {
        return Err(Refusal::new(
            HOST_KEY_MISSING,
            format!("clé d'hôte de « {resource} » non épinglée"),
        ));
    };
    let Some(account_id) = sqlx::query_scalar!(
        r#"SELECT id::text AS "id!" FROM target_account
           WHERE resource_id = $1::text::uuid AND name = $2 AND disabled_at IS NULL FOR SHARE"#,
        r.id,
        account,
    )
    .fetch_optional(&mut **tx)
    .await?
    else {
        return Err(Refusal::new(
            ACCOUNT_UNKNOWN,
            format!(
                "compte « {} » inconnu ou désactivé sur « {resource} »",
                truncate(account)
            ),
        ));
    };
    // The right that lasts longest, if several.
    let Some(right) = sqlx::query!(
        r#"SELECT id::text AS "id!", valid_until, max_session_secs FROM access_right
           WHERE user_id = $1::text::uuid AND account_id = $2::text::uuid AND protocol = 'ssh'
             AND revoked_at IS NULL AND valid_from <= $3 AND valid_until > $3
           ORDER BY valid_until DESC, max_session_secs DESC LIMIT 1 FOR SHARE"#,
        user.to_string(),
        account_id,
        i64_of(now),
    )
    .fetch_optional(&mut **tx)
    .await?
    else {
        return Err(Refusal::new(
            NO_RIGHT,
            format!(
                "aucun droit SSH valide de {user} sur « {}@{resource} »",
                truncate(account)
            ),
        ));
    };
    let max = u64::try_from(right.max_session_secs)
        .unwrap_or(0)
        .min(secs_until(right.valid_until, now))
        .max(1);
    Ok(Allowed {
        right: uuid(&right.id)?,
        resource: uuid(&r.id)?,
        group: resource_group,
        account: uuid(&account_id)?,
        host: r.host,
        port: u16::try_from(r.port).unwrap_or(0),
        target_p256_public,
        max_session_secs: u32::try_from(max).unwrap_or(u32::MAX),
    })
}

/// The login session, read with `FOR SHARE`: it must exist, name the
/// subject and the certificate (when given), and be neither revoked nor
/// expired. Returns its expiry.
async fn login_session(
    tx: &mut Tx<'_>,
    session: Uuid,
    subject: Uuid,
    certificate_sha256: Option<&[u8; 32]>,
    now: u64,
) -> Result<u64, Refusal> {
    let Some(s) = sqlx::query!(
        r#"SELECT user_id::text AS "user!", certificate_sha256, expires_at,
                  revoked_at IS NOT NULL AS "revoked!"
           FROM login_session WHERE id = $1::text::uuid FOR SHARE"#,
        session.to_string(),
    )
    .fetch_optional(&mut **tx)
    .await?
    else {
        return Err(Refusal::new(
            LOGIN_UNKNOWN,
            format!("session de connexion {session} inconnue"),
        ));
    };
    if uuid(&s.user)? != subject
        || certificate_sha256.is_some_and(|c| s.certificate_sha256.as_slice() != c)
    {
        return Err(Refusal::new(
            LOGIN_MISMATCH,
            format!("sujet {subject} ou certificat différent de la session de connexion {session}"),
        ));
    }
    if s.revoked {
        return Err(Refusal::new(
            LOGIN_REVOKED,
            format!("session de connexion {session} révoquée"),
        ));
    }
    let expires_at = u64::try_from(s.expires_at).unwrap_or(0);
    if expires_at <= now {
        return Err(Refusal::new(
            LOGIN_EXPIRED,
            format!("session de connexion {session} expirée"),
        ));
    }
    Ok(expires_at)
}

/// What a dry run finds: the right that would be used, or the refusal.
/// Nothing is written, not even to the audit chain.
///
/// # Errors
///
/// The refusal.
pub async fn check(
    pool: &PgPool,
    user: &str,
    resource: &str,
    account: &str,
    now: u64,
) -> Result<Allowed, Refusal> {
    let mut tx = pool.begin().await?;
    let user = sqlx::query_scalar!(
        r#"SELECT id::text AS "id!" FROM app_user WHERE name = $1"#,
        user
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| {
        Refusal::new(
            USER_INACTIVE,
            format!("utilisateur « {} » inconnu", truncate(user)),
        )
    })?;
    let user = uuid(&user)?;
    let found = match UserLock::take(&mut tx, user).await?.active() {
        Ok(()) => allowed(&mut tx, user, resource, account, None, now).await,
        Err(refusal) => Err(refusal),
    };
    tx.rollback().await?;
    found
}

/// A grant issued for an SSH request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issued {
    /// The grant, text form.
    pub grant: String,
    /// Its content.
    pub content: Grant,
    /// The audit record, for the head signer.
    pub appended: Appended,
}

fn access_event(kind: EventKind, outcome: Outcome, agent: Uuid, request: &SshRequest) -> Event {
    Event::new(kind, outcome, ActorKind::Agent, agent.to_string())
        .uuid(field::AGENT_ID, agent.to_bytes())
        .uuid(field::USER_ID, request.subject.to_bytes())
        .uuid(field::LOGIN_SESSION, request.login_session.to_bytes())
        .bytes(field::CERTIFICATE_SHA256, request.certificate_sha256)
        .text(field::RESOURCE, truncate(&request.resource))
        .text(field::ACCOUNT, truncate(&request.account))
        .text(field::CLIENT_ADDR, truncate(&request.client_address))
}

/// The `access.ssh_refused` record of a refused request.
pub fn ssh_refused_event(agent: Uuid, request: &SshRequest, refusal: &Refusal) -> Event {
    access_event(
        EventKind::AccessSshRefused,
        Outcome::Refused,
        agent,
        request,
    )
    .text(field::CODE, refusal.code)
    .text(field::REASON, truncate(&refusal.reason))
}

/// Decides `request` from `agent` of `group` at `now`; on success, a grant
/// for the group, bound to the login session and the account, recorded
/// with its granting `access.ssh_granted` record.
///
/// # Errors
///
/// The refusal; the caller records `access.ssh_refused`
/// ([`ssh_refused_event`]).
pub async fn ssh_grant(
    pool: &PgPool,
    authority: &GrantAuthority,
    agent: Uuid,
    group: Uuid,
    request: &SshRequest,
    now: u64,
) -> Result<Issued, Refusal> {
    let mut tx = pool.begin().await?;
    // Lock order (ADR-0014): the user, then the login session.
    let user = UserLock::take(&mut tx, request.subject).await?;
    let login_expires = login_session(
        &mut tx,
        request.login_session,
        request.subject,
        Some(&request.certificate_sha256),
        now,
    )
    .await?;
    user.active()?;
    let allowed = allowed(
        &mut tx,
        request.subject,
        &request.resource,
        &request.account,
        Some(group),
        now,
    )
    .await?;
    // Nor later than the login session.
    let max_session_secs = session_secs(
        &[u64::from(allowed.max_session_secs)],
        login_expires.saturating_sub(now),
    );
    let claims = Claims {
        subject: SubjectId::from_bytes(request.subject.to_bytes()),
        resource: ResourceId::from_bytes(allowed.resource.to_bytes()),
        audience: GatewayGroupId::from_bytes(group.to_bytes()),
        protocol: Protocol::Ssh,
        rights: Rights::NONE,
        max_session_secs,
        binding: Binding::of(request.login_session.to_bytes(), &request.account),
    };
    let (content, signed) = authority
        .issuer()
        .issue_grant(&claims, now)
        .map_err(|e| Refusal::new("CORE-E006", format!("signature du grant : {e}")))?;
    sqlx::query!(
        "INSERT INTO access_grant (jti, login_session_id, right_id, agent_id, gateway_group,
                                   resource_id, account, protocol, max_session_secs,
                                   issued_at, expires_at)
         VALUES ($1, $2::text::uuid, $3::text::uuid, $4::text::uuid, $5::text::uuid,
                 $6::text::uuid, $7, 'ssh', $8, $9, $10)",
        &content.jti.to_bytes()[..],
        request.login_session.to_string(),
        allowed.right.to_string(),
        agent.to_string(),
        group.to_string(),
        allowed.resource.to_string(),
        request.account,
        i32::try_from(max_session_secs).unwrap_or(i32::MAX),
        i64_of(content.issued_at),
        i64_of(content.expires_at),
    )
    .execute(&mut *tx)
    .await?;
    let event = access_event(
        EventKind::AccessSshGranted,
        Outcome::Success,
        agent,
        request,
    )
    .bytes(field::JTI, content.jti.to_bytes())
    .uuid(field::RIGHT_ID, allowed.right.to_bytes())
    .uuid(field::RESOURCE_ID, allowed.resource.to_bytes())
    .uuid(field::GROUP_ID, group.to_bytes())
    .u64(field::MAX_SESSION_SECS, u64::from(max_session_secs))
    .u64(field::EXPIRES_AT, content.expires_at);
    // Granting, last statement before the commit.
    let appended = audit::append(&mut tx, event).await?;
    tx.commit()
        .await
        .map_err(|e| Refusal::new("CORE-E010", e.to_string()))?;
    Ok(Issued {
        grant: signed.to_text(),
        content,
        appended,
    })
}

/// The parameters of an opened session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    /// The session.
    pub session: Uuid,
    /// The answer to the agent.
    pub params: CoreMessage,
    /// The audit record, for the head signer.
    pub appended: Appended,
}

/// The `access.session_refused` record of a refused session request.
pub fn session_refused_event(agent: Uuid, jti: Option<[u8; 16]>, refusal: &Refusal) -> Event {
    let event = Event::new(
        EventKind::AccessSessionRefused,
        Outcome::Refused,
        ActorKind::Agent,
        agent.to_string(),
    )
    .uuid(field::AGENT_ID, agent.to_bytes())
    .text(field::CODE, refusal.code)
    .text(field::REASON, truncate(&refusal.reason));
    match jti {
        Some(jti) => event.bytes(field::JTI, jti),
        None => event,
    }
}

/// The jti of a grant (bytes 16 to 32, ADR-0004), if it can be read: for
/// the refusal record only, the grant is not verified.
pub fn jti_of(grant: &str) -> Option<[u8; 16]> {
    SignedGrant::from_text(grant)
        .ok()
        .and_then(|g| g.as_bytes().get(16..32)?.try_into().ok())
}

/// Every check of `grant` but the jti, with the keys of the core.
fn verify(
    authority: &GrantAuthority,
    group: Uuid,
    grant: &str,
    now: u64,
) -> Result<Grant, Refusal> {
    let verifier = Verifier::new(
        authority.keys().clone(),
        GatewayGroupId::from_bytes(group.to_bytes()),
        ostena_grant::Policy::default(),
    );
    SignedGrant::from_text(grant)
        .and_then(|signed| verifier.check(signed.as_bytes(), now))
        .map_err(|e| Refusal::new(e.code(), e.to_string()))
}

/// The longest session allowed: the smallest of `limits` and of
/// `login_left`, at least one second.
fn session_secs(limits: &[u64], login_left: u64) -> u32 {
    let max = limits.iter().copied().fold(login_left, u64::min).max(1);
    u32::try_from(max).unwrap_or(u32::MAX)
}

/// Consumes the jti for `agent` and records a new session; returns it.
async fn consume(tx: &mut Tx<'_>, jti: [u8; 16], agent: Uuid, now: u64) -> Result<Uuid, Refusal> {
    let session = Uuid::random().map_err(|e| Refusal::new("CORE-E006", e.to_string()))?;
    sqlx::query!(
        "UPDATE access_grant SET consumed_at = $2, consumed_by = $3::text::uuid WHERE jti = $1",
        &jti[..],
        i64_of(now),
        agent.to_string(),
    )
    .execute(&mut **tx)
    .await?;
    sqlx::query!(
        "INSERT INTO access_session (id, jti, agent_id, opened_at)
         VALUES ($1::text::uuid, $2, $3::text::uuid, $4)",
        session.to_string(),
        &jti[..],
        agent.to_string(),
        i64_of(now),
    )
    .execute(&mut **tx)
    .await?;
    Ok(session)
}

/// Opens the session of `grant` presented by `agent` of `group` at `now`:
/// verified with the keys of the core, its jti consumed once for the whole
/// group, its login session, user, resource and account checked again, and
/// a valid right of the user on the account looked for again (not
/// necessarily the one of the grant); recorded with its granting
/// `access.session_opened` record, which names the right used.
///
/// # Errors
///
/// The refusal; the caller records `access.session_refused`
/// ([`session_refused_event`]).
pub async fn open_session(
    pool: &PgPool,
    authority: &GrantAuthority,
    agent: Uuid,
    group: Uuid,
    request_id: u64,
    grant: &str,
    now: u64,
) -> Result<Opened, Refusal> {
    let checked = verify(authority, group, grant, now)?;
    let jti = checked.jti.to_bytes();
    let mut tx = pool.begin().await?;
    let Some(row) = sqlx::query!(
        r#"SELECT login_session_id::text AS "login!",
                  resource_id::text AS "resource!", account, protocol, max_session_secs,
                  consumed_at IS NOT NULL AS "consumed!"
           FROM access_grant WHERE jti = $1 AND gateway_group = $2::text::uuid FOR UPDATE"#,
        &jti[..],
        group.to_string(),
    )
    .fetch_optional(&mut *tx)
    .await?
    else {
        return Err(Refusal::new(
            GRANT_UNKNOWN,
            format!("grant {} non émis par le core pour ce groupe", checked.jti),
        ));
    };
    if row.consumed {
        return Err(Refusal::new(
            "GRT-E010",
            format!("grant {} déjà consommé", checked.jti),
        ));
    }
    if row.protocol != "ssh" {
        return Err(Refusal::new(
            GRANT_UNKNOWN,
            format!("grant {} d'un protocole non servi", checked.jti),
        ));
    }
    let subject = Uuid::from_bytes(checked.claims.subject.to_bytes());
    let login = uuid(&row.login)?;
    // Lock order (ADR-0014): the grant, the user, then the login session.
    let user = UserLock::take(&mut tx, subject).await?;
    let login_expires = login_session(&mut tx, login, subject, None, now).await?;
    user.active()?;
    let resource_name = sqlx::query_scalar!(
        "SELECT name FROM resource WHERE id = $1::text::uuid",
        row.resource
    )
    .fetch_one(&mut *tx)
    .await?;
    let allowed = allowed(
        &mut tx,
        subject,
        &resource_name,
        &row.account,
        Some(group),
        now,
    )
    .await?;
    // Any valid right of the user on the account will do: the one of the
    // grant may have been replaced by another since (a longer one, for
    // example); without any, `allowed` refuses (`ACC-E006`).
    let session = consume(&mut tx, jti, agent, now).await?;
    // Computed again now: no longer than the grant (its row and its
    // claims), than the right used (its maximum and its end), nor than the
    // login session.
    let max_session_secs = session_secs(
        &[
            u64::try_from(row.max_session_secs).unwrap_or(0),
            u64::from(checked.claims.max_session_secs),
            u64::from(allowed.max_session_secs),
        ],
        login_expires.saturating_sub(now),
    );
    let event = Event::new(
        EventKind::AccessSessionOpened,
        Outcome::Success,
        ActorKind::Agent,
        agent.to_string(),
    )
    .uuid(field::AGENT_ID, agent.to_bytes())
    .uuid(field::ACCESS_SESSION, session.to_bytes())
    .bytes(field::JTI, jti)
    .uuid(field::USER_ID, subject.to_bytes())
    .uuid(field::LOGIN_SESSION, login.to_bytes())
    .uuid(field::RESOURCE_ID, allowed.resource.to_bytes())
    .uuid(field::RIGHT_ID, allowed.right.to_bytes())
    .text(field::ACCOUNT, truncate(&row.account))
    .text(field::HOST, truncate(&allowed.host))
    .u64(field::PORT, u64::from(allowed.port))
    .u64(field::MAX_SESSION_SECS, u64::from(max_session_secs));
    // Granting, last statement before the commit.
    let appended = audit::append(&mut tx, event).await?;
    tx.commit()
        .await
        .map_err(|e| Refusal::new("CORE-E010", e.to_string()))?;
    Ok(Opened {
        session,
        params: CoreMessage::SessionParams {
            request_id,
            session_id: session.to_string(),
            protocol: SessionProtocol::Ssh,
            host: allowed.host,
            port: allowed.port,
            max_session_secs,
            account: Some(row.account),
            target_p256_public: Some(URL_SAFE_NO_PAD.encode(allowed.target_p256_public)),
        },
        appended,
    })
}

/// Records the end of `session` of `agent`; returns its
/// `access.session_closed` record, or `None` for a session unknown to this
/// agent or already closed.
///
/// # Errors
///
/// [`CoreError::Database`].
pub async fn close_session(
    pool: &PgPool,
    agent: Uuid,
    session: Uuid,
    reason: &str,
    bytes_to_target: u64,
    bytes_from_target: u64,
    now: u64,
) -> Result<Option<Event>, CoreError> {
    let reason: String = truncate(reason).chars().take(128).collect();
    let found = sqlx::query!(
        "UPDATE access_session SET closed_at = $3, close_reason = $4,
                bytes_to_target = $5, bytes_from_target = $6
         WHERE id = $1::text::uuid AND agent_id = $2::text::uuid AND closed_at IS NULL",
        session.to_string(),
        agent.to_string(),
        i64_of(now),
        reason,
        i64_of(bytes_to_target),
        i64_of(bytes_from_target),
    )
    .execute(pool)
    .await?
    .rows_affected();
    if found == 0 {
        return Ok(None);
    }
    Ok(Some(
        Event::new(
            EventKind::AccessSessionClosed,
            Outcome::Success,
            ActorKind::Agent,
            agent.to_string(),
        )
        .uuid(field::AGENT_ID, agent.to_bytes())
        .uuid(field::ACCESS_SESSION, session.to_bytes())
        .text(field::REASON, reason)
        .u64(field::BYTES_TO_TARGET, bytes_to_target)
        .u64(field::BYTES_FROM_TARGET, bytes_from_target),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_has_a_label_and_the_message_hides_the_reason() {
        for code in [
            LOGIN_UNKNOWN,
            LOGIN_EXPIRED,
            LOGIN_REVOKED,
            LOGIN_MISMATCH,
            USER_INACTIVE,
            NO_RIGHT,
            SSH_DISABLED,
            GRANT_UNKNOWN,
            RESOURCE_UNKNOWN,
            OTHER_GROUP,
            ACCOUNT_UNKNOWN,
            HOST_KEY_MISSING,
            NO_HOST_NAME,
        ] {
            assert_ne!(label(code), "accès refusé", "{code}");
        }
        let refusal = Refusal::new(NO_RIGHT, "aucun droit de 1234 sur root@srv");
        let message = refusal.to_message(7);
        message.validate().unwrap();
        let CoreMessage::SessionRefused {
            request_id,
            code,
            message,
        } = message
        else {
            panic!("pas un refus");
        };
        assert_eq!((request_id, code.as_str()), (7, NO_RIGHT));
        assert!(!message.contains("root@srv"));
    }

    #[test]
    fn the_session_length_is_the_smallest_limit() {
        assert_eq!(session_secs(&[3600, 1800, 900], 7200), 900);
        assert_eq!(session_secs(&[3600], 120), 120);
        assert_eq!(session_secs(&[3600, 0], 120), 1);
        assert_eq!(session_secs(&[u64::MAX], u64::MAX), u32::MAX);
    }

    #[test]
    fn jti_is_read_from_the_grant() {
        let (key, _) = ostena_crypto::p256::SigningKey::generate().unwrap();
        let issuer = ostena_grant::Issuer::new(key);
        let claims = Claims {
            subject: SubjectId::from_bytes([1; 16]),
            resource: ResourceId::from_bytes([2; 16]),
            audience: GatewayGroupId::from_bytes([3; 16]),
            protocol: Protocol::Ssh,
            rights: Rights::NONE,
            max_session_secs: 60,
            binding: Binding::of([4; 16], "root"),
        };
        let (content, signed) = issuer.issue_grant(&claims, 1_800_000_000).unwrap();
        assert_eq!(jti_of(&signed.to_text()), Some(content.jti.to_bytes()));
        assert_eq!(jti_of("pas un grant"), None);
    }
}
