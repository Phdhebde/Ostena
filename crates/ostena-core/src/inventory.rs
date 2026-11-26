//! The minimal inventory (ADR-0014): gateway groups, users, resources,
//! target accounts and rights, administered by `ostena core …`.
//!
//! Every change is one transaction with its audit record: a change that
//! grants (a user, a resource, a right, a policy) is refused if its record
//! cannot be written; a change that only takes away (a user disabled, a
//! right revoked) commits anyway (ADR-0012). The actor is the database
//! user, as for the agent commands.

use ostena_audit::{ActorKind, Event, EventKind, Outcome, field};
use ostena_common::api::web::Role;
use ostena_common::config::Mode;
use ostena_common::config::scope::PolicySpec;
use ostena_crypto::p256::VerifyingKey;
use ostena_tunnel::Uuid;
use sqlx::PgPool;

use crate::audit::{self, Tx};
use crate::error::CoreError;
use crate::store::{Notice, i64_of, notify_audit, notify_notice, truncate, unix_now, uuid};

/// Longest validity of a right, seconds (366 days).
pub const MAX_RIGHT_SECS: u64 = 366 * 86_400;
/// Bounds of the session length of a right, seconds.
pub const SESSION_SECS: std::ops::RangeInclusive<u32> = 60..=43_200;
/// Most SSH host names of a group (principals of a host certificate).
pub const MAX_HOST_NAMES: usize = 16;

fn invalid(message: impl Into<String>) -> CoreError {
    CoreError::Invalid(message.into())
}

fn admin_event(kind: EventKind, actor: String) -> Event {
    Event::new(kind, Outcome::Success, ActorKind::Admin, actor)
}

fn new_id() -> Result<Uuid, CoreError> {
    Uuid::random().map_err(|e| CoreError::Keys(format!("aléa : {e}")))
}

/// A unique violation (`23505`) becomes a readable refusal.
fn unique(what: &str) -> impl Fn(sqlx::Error) -> CoreError + '_ {
    move |e| match &e {
        sqlx::Error::Database(d) if d.code().as_deref() == Some("23505") => {
            invalid(format!("{what} existe déjà"))
        }
        _ => CoreError::from(e),
    }
}

/// Writes a granting record and commits; the record is the last statement.
async fn commit_granting(mut tx: Tx<'_>, event: Event) -> Result<(), CoreError> {
    notify_audit(&mut tx).await?;
    audit::append(&mut tx, event).await?;
    tx.commit()
        .await
        .map_err(|e| CoreError::AuditWrite(e.to_string()))
}

fn is_name(value: &str, max: usize, extra: &[u8]) -> bool {
    let b = value.as_bytes();
    b.first()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && b.len() <= max
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || extra.contains(c))
}

/// A user name: `[a-z0-9][a-z0-9._-]{0,63}`.
pub fn is_user_name(value: &str) -> bool {
    is_name(value, 64, b"._-")
}

/// A gateway group name: `[a-z0-9][a-z0-9._-]{0,62}`.
pub fn is_group_name(value: &str) -> bool {
    is_name(value, 63, b"._-")
}

/// A resource name, as in the tunnel messages: `[a-z0-9][a-z0-9.-]{0,62}`.
pub fn is_resource_name(value: &str) -> bool {
    is_name(value, 63, b".-")
}

/// An account on a target, as in the tunnel messages: 1 to 256 bytes, no
/// control character, no leading or trailing space.
pub fn is_account(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.chars().any(char::is_control)
        && !value.starts_with(char::is_whitespace)
        && !value.ends_with(char::is_whitespace)
}

fn check_host_names(names: &[String]) -> Result<(), CoreError> {
    if names.len() > MAX_HOST_NAMES {
        return Err(invalid(format!(
            "au plus {MAX_HOST_NAMES} noms d'hôte SSH par groupe"
        )));
    }
    for name in names {
        let lower = name.bytes().all(|c| !c.is_ascii_uppercase());
        if !lower || ostena_scope::parse_host(name).is_err() || name.contains(',') {
            return Err(invalid(format!(
                "nom d'hôte SSH invalide : {}",
                truncate(name)
            )));
        }
    }
    let mut sorted = names.to_vec();
    sorted.sort();
    sorted.dedup();
    if sorted.len() != names.len() {
        return Err(invalid("nom d'hôte SSH en double"));
    }
    Ok(())
}

// ---------------------------------------------------------------- groups

/// One gateway group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRow {
    /// Identifier, the audience of its grants.
    pub id: Uuid,
    /// Name.
    pub name: String,
    /// SSH host names (principals of the host certificates).
    pub ssh_host_names: Vec<String>,
    /// Version of the stored scope policy, if any.
    pub policy_version: Option<u64>,
}

/// Creates a gateway group. `id` is the UUID its agents were enrolled
/// with, if any; otherwise a new one.
///
/// # Errors
///
/// [`CoreError::Invalid`] for an invalid or taken name or id,
/// [`CoreError::AuditWrite`] if the record cannot be written.
pub async fn create_group(
    pool: &PgPool,
    id: Option<Uuid>,
    name: &str,
    ssh_host_names: &[String],
) -> Result<Uuid, CoreError> {
    if !is_group_name(name) {
        return Err(invalid("nom de groupe : [a-z0-9][a-z0-9._-]{0,62} attendu"));
    }
    check_host_names(ssh_host_names)?;
    let id = match id {
        Some(id) => id,
        None => new_id()?,
    };
    let mut tx = pool.begin().await?;
    let actor = audit::admin_actor(&mut tx).await?;
    sqlx::query!(
        "INSERT INTO gateway_group (id, name, ssh_host_names) VALUES ($1::text::uuid, $2, $3)",
        id.to_string(),
        name,
        ssh_host_names,
    )
    .execute(&mut *tx)
    .await
    .map_err(unique("ce groupe (nom ou identifiant)"))?;
    notify_notice(&mut tx, &Notice::Group(id)).await?;
    let event = admin_event(EventKind::GatewayGroupUpdated, actor)
        .uuid(field::GROUP_ID, id.to_bytes())
        .text(field::NAME, name)
        .text(field::HOST_NAMES, truncate(&ssh_host_names.join(",")));
    commit_granting(tx, event).await?;
    tracing::info!(event = "gateway_group.updated", group = %id, "groupe créé");
    Ok(id)
}

async fn group_id(tx: &mut Tx<'_>, name: &str) -> Result<Uuid, CoreError> {
    let id = sqlx::query_scalar!(
        r#"SELECT id::text AS "id!" FROM gateway_group WHERE name = $1 FOR UPDATE"#,
        name
    )
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| CoreError::NotFound(format!("groupe {name}")))?;
    uuid(&id)
}

/// Replaces the SSH host names of the group `name`; the running core
/// certifies the host keys of its agents again.
///
/// # Errors
///
/// [`CoreError::NotFound`], [`CoreError::Invalid`],
/// [`CoreError::AuditWrite`].
pub async fn set_group_host_names(
    pool: &PgPool,
    name: &str,
    ssh_host_names: &[String],
) -> Result<(), CoreError> {
    check_host_names(ssh_host_names)?;
    let mut tx = pool.begin().await?;
    let actor = audit::admin_actor(&mut tx).await?;
    let id = group_id(&mut tx, name).await?;
    sqlx::query!(
        "UPDATE gateway_group SET ssh_host_names = $2, updated_at = now()
         WHERE id = $1::text::uuid",
        id.to_string(),
        ssh_host_names,
    )
    .execute(&mut *tx)
    .await?;
    notify_notice(&mut tx, &Notice::Group(id)).await?;
    let event = admin_event(EventKind::GatewayGroupUpdated, actor)
        .uuid(field::GROUP_ID, id.to_bytes())
        .text(field::NAME, name)
        .text(field::HOST_NAMES, truncate(&ssh_host_names.join(",")));
    commit_granting(tx, event).await
}

/// Checks a scope policy as the agents will: compiled in production mode,
/// no floor exception.
///
/// # Errors
///
/// [`CoreError::Invalid`] with every problem found.
pub fn check_policy(spec: &PolicySpec) -> Result<(), CoreError> {
    if !spec.floor_exceptions.is_empty() {
        return Err(invalid(
            "une politique poussée aux agents ne peut pas lever le plancher (floor_exceptions)",
        ));
    }
    ostena_scope::CompiledPolicy::compile(spec, Mode::Production)
        .map(|_| ())
        .map_err(|e| invalid(format!("politique : {e}")))
}

/// Stores the scope policy of the group `name`, compiled in production
/// mode first, with a new version; the running core pushes it to the
/// agents of the group. Returns the version.
///
/// # Errors
///
/// [`CoreError::NotFound`], [`CoreError::Invalid`] for a policy the agents
/// would refuse, [`CoreError::AuditWrite`].
pub async fn set_group_policy(
    pool: &PgPool,
    name: &str,
    spec: &PolicySpec,
) -> Result<u64, CoreError> {
    let mut tx = pool.begin().await?;
    let actor = audit::admin_actor(&mut tx).await?;
    let id = group_id(&mut tx, name).await?;
    let mut spec = spec.clone();
    spec.gateway_group = id.to_string();
    check_policy(&spec)?;
    let json = serde_json::to_string(&spec).map_err(|e| invalid(format!("politique : {e}")))?;
    let version = sqlx::query_scalar!(
        r#"UPDATE gateway_group
           SET policy = $2, policy_version = nextval('push_version'), updated_at = now()
           WHERE id = $1::text::uuid RETURNING policy_version AS "version!""#,
        id.to_string(),
        json,
    )
    .fetch_one(&mut *tx)
    .await?;
    let version = u64::try_from(version).unwrap_or(0);
    notify_notice(&mut tx, &Notice::Group(id)).await?;
    let event = admin_event(EventKind::GatewayGroupUpdated, actor)
        .uuid(field::GROUP_ID, id.to_bytes())
        .text(field::NAME, name)
        .u64(field::POLICY_VERSION, version);
    commit_granting(tx, event).await?;
    tracing::info!(event = "gateway_group.updated", group = %id, policy_version = version);
    Ok(version)
}

/// Every group, by name.
///
/// # Errors
///
/// [`CoreError::Database`].
pub async fn list_groups(pool: &PgPool) -> Result<Vec<GroupRow>, CoreError> {
    let rows = sqlx::query!(
        r#"SELECT id::text AS "id!", name, ssh_host_names, policy_version
           FROM gateway_group ORDER BY name"#
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(GroupRow {
                id: uuid(&r.id)?,
                name: r.name,
                ssh_host_names: r.ssh_host_names,
                policy_version: r.policy_version.and_then(|v| u64::try_from(v).ok()),
            })
        })
        .collect()
}

// ----------------------------------------------------------------- users

/// One user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRow {
    /// Identifier, the principal of their SSH certificates.
    pub id: Uuid,
    /// Login name.
    pub name: String,
    /// Display name.
    pub display_name: String,
    /// `active` or `disabled`.
    pub state: String,
}

/// Creates an active user.
///
/// # Errors
///
/// [`CoreError::Invalid`] for an invalid or taken name,
/// [`CoreError::AuditWrite`].
pub async fn add_user(pool: &PgPool, name: &str, display_name: &str) -> Result<Uuid, CoreError> {
    if !is_user_name(name) {
        return Err(invalid(
            "nom d'utilisateur : [a-z0-9][a-z0-9._-]{0,63} attendu",
        ));
    }
    let chars = display_name.chars().count();
    if !(1..=128).contains(&chars) || display_name.chars().any(char::is_control) {
        return Err(invalid(
            "nom affiché : 1 à 128 caractères, sans caractère de contrôle",
        ));
    }
    let id = new_id()?;
    let mut tx = pool.begin().await?;
    let actor = audit::admin_actor(&mut tx).await?;
    sqlx::query!(
        "INSERT INTO app_user (id, name, display_name) VALUES ($1::text::uuid, $2, $3)",
        id.to_string(),
        name,
        display_name,
    )
    .execute(&mut *tx)
    .await
    .map_err(unique("cet utilisateur"))?;
    let event = admin_event(EventKind::UserCreated, actor)
        .uuid(field::USER_ID, id.to_bytes())
        .text(field::NAME, name)
        .text(field::DISPLAY_NAME, truncate(display_name));
    commit_granting(tx, event).await?;
    tracing::info!(event = "user.created", user = %id, name);
    Ok(id)
}

/// Every user, by name.
///
/// # Errors
///
/// [`CoreError::Database`].
pub async fn list_users(pool: &PgPool) -> Result<Vec<UserRow>, CoreError> {
    let rows = sqlx::query!(
        r#"SELECT id::text AS "id!", name, display_name, state FROM app_user ORDER BY name"#
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(UserRow {
                id: uuid(&r.id)?,
                name: r.name,
                display_name: r.display_name,
                state: r.state,
            })
        })
        .collect()
}

/// Disables the user `name` and revokes their login sessions still valid;
/// the running core tells the agents concerned. Returns how many sessions
/// were revoked. Disabling a disabled user revokes what is left, if
/// anything, and audits only that: `user.disabled` is written once.
///
/// # Errors
///
/// [`CoreError::NotFound`], [`CoreError::Database`].
pub async fn disable_user(pool: &PgPool, name: &str) -> Result<usize, CoreError> {
    let mut tx = pool.begin().await?;
    let actor = audit::admin_actor(&mut tx).await?;
    // Lock order (ADR-0014): the user, then their login sessions.
    let user = sqlx::query!(
        r#"SELECT id::text AS "id!", state = 'active' AS "active!"
           FROM app_user WHERE name = $1 FOR UPDATE"#,
        name,
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| CoreError::NotFound(format!("utilisateur {name}")))?;
    let id = uuid(&user.id)?;
    if user.active {
        sqlx::query!(
            "UPDATE app_user SET state = 'disabled', disabled_at = now()
             WHERE id = $1::text::uuid",
            id.to_string(),
        )
        .execute(&mut *tx)
        .await?;
    }
    let sessions = sqlx::query_scalar!(
        r#"UPDATE login_session
           SET revoked_at = now(), revoked_by = $2, revocation_reason = 'utilisateur désactivé'
           WHERE user_id = $1::text::uuid AND revoked_at IS NULL AND expires_at > $3
           RETURNING id::text AS "id!""#,
        id.to_string(),
        actor,
        i64_of(unix_now()),
    )
    .fetch_all(&mut *tx)
    .await?;
    let sessions = sessions
        .iter()
        .map(|s| uuid(s))
        .collect::<Result<Vec<_>, _>>()?;
    if !user.active && sessions.is_empty() {
        // Already disabled, nothing left: nothing changes.
        tx.rollback().await?;
        return Ok(0);
    }
    for session in &sessions {
        notify_notice(&mut tx, &Notice::LoginRevoked(*session)).await?;
    }
    notify_audit(&mut tx).await?;
    // Protective, last statements before the commit.
    for session in &sessions {
        audit::append_protective(
            &mut tx,
            admin_event(EventKind::LoginSessionRevoked, actor.clone())
                .uuid(field::LOGIN_SESSION, session.to_bytes())
                .uuid(field::USER_ID, id.to_bytes())
                .text(field::REASON, "utilisateur désactivé"),
        )
        .await;
    }
    if user.active {
        audit::append_protective(
            &mut tx,
            admin_event(EventKind::UserDisabled, actor)
                .uuid(field::USER_ID, id.to_bytes())
                .text(field::NAME, name)
                .u64(field::REVOKED_SESSIONS, sessions.len() as u64),
        )
        .await;
    }
    tx.commit().await?;
    tracing::warn!(event = "user.disabled", user = %id, revoked_sessions = sessions.len());
    Ok(sessions.len())
}

/// Gives `role` to the user `name` (portal, ADR-0020). Giving a role the
/// user has changes nothing. Returns whether it was given now.
///
/// # Errors
///
/// [`CoreError::NotFound`], [`CoreError::AuditWrite`], [`CoreError::Database`].
pub async fn grant_role(pool: &PgPool, name: &str, role: Role) -> Result<bool, CoreError> {
    let mut tx = pool.begin().await?;
    let actor = audit::admin_actor(&mut tx).await?;
    let id = user_id(&mut tx, name).await?;
    let granted = sqlx::query!(
        "INSERT INTO user_role (user_id, role, granted_by) VALUES ($1::text::uuid, $2, $3)
         ON CONFLICT DO NOTHING",
        id.to_string(),
        role.as_str(),
        actor,
    )
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    if !granted {
        tx.rollback().await?;
        return Ok(false);
    }
    let event = admin_event(EventKind::UserRoleGranted, actor)
        .uuid(field::USER_ID, id.to_bytes())
        .text(field::NAME, name)
        .text(field::ROLE, role.as_str());
    commit_granting(tx, event).await?;
    tracing::info!(event = "user.role_granted", user = %id, role = role.as_str());
    Ok(true)
}

/// Takes `role` from the user `name`; the browser sessions open see it at
/// their next request. Returns whether the user had it.
///
/// # Errors
///
/// [`CoreError::NotFound`], [`CoreError::Database`].
pub async fn revoke_role(pool: &PgPool, name: &str, role: Role) -> Result<bool, CoreError> {
    let mut tx = pool.begin().await?;
    let actor = audit::admin_actor(&mut tx).await?;
    let id = user_id(&mut tx, name).await?;
    let removed = sqlx::query!(
        "DELETE FROM user_role WHERE user_id = $1::text::uuid AND role = $2",
        id.to_string(),
        role.as_str(),
    )
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    if !removed {
        tx.rollback().await?;
        return Ok(false);
    }
    notify_audit(&mut tx).await?;
    // Protective, last statement before the commit.
    audit::append_protective(
        &mut tx,
        admin_event(EventKind::UserRoleRevoked, actor)
            .uuid(field::USER_ID, id.to_bytes())
            .text(field::NAME, name)
            .text(field::ROLE, role.as_str()),
    )
    .await;
    tx.commit().await?;
    tracing::warn!(event = "user.role_revoked", user = %id, role = role.as_str());
    Ok(true)
}

/// The roles of the user `name`, sorted.
///
/// # Errors
///
/// [`CoreError::Database`].
pub async fn user_roles(pool: &PgPool, name: &str) -> Result<Vec<Role>, CoreError> {
    let rows = sqlx::query_scalar!(
        "SELECT r.role FROM user_role r JOIN app_user u ON u.id = r.user_id
         WHERE u.name = $1 ORDER BY r.role",
        name,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.iter().filter_map(|r| Role::parse(r)).collect())
}

async fn user_id(tx: &mut Tx<'_>, name: &str) -> Result<Uuid, CoreError> {
    let id = sqlx::query_scalar!(
        r#"SELECT id::text AS "id!" FROM app_user WHERE name = $1"#,
        name
    )
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| CoreError::NotFound(format!("utilisateur {name}")))?;
    uuid(&id)
}

// ------------------------------------------------------------- resources

/// The pinned host key of a target, from its OpenSSH public key line (the
/// content of `ssh_host_ecdsa_key.pub`): ECDSA P-256 only.
///
/// # Errors
///
/// [`CoreError::Invalid`].
pub fn parse_host_key(line: &str) -> Result<VerifyingKey, CoreError> {
    ostena_ssh::keys::parse_public_line(line.trim()).ok_or_else(|| {
        invalid("clé d'hôte : une ligne « ecdsa-sha2-nistp256 AAAA… » (ssh_host_ecdsa_key.pub) attendue")
    })
}

/// One resource and its accounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRow {
    /// Identifier.
    pub id: Uuid,
    /// Name, as users type it.
    pub name: String,
    /// Target host.
    pub host: String,
    /// Target port.
    pub port: u16,
    /// Name of its gateway group.
    pub group: String,
    /// Its SSH host key is pinned.
    pub host_key_pinned: bool,
    /// Its accounts, by name.
    pub accounts: Vec<String>,
}

/// Adds a resource reached through the agents of the group `group`, with
/// the pinned SSH host key of the target.
///
/// # Errors
///
/// [`CoreError::Invalid`] for an invalid or taken name, an invalid host or
/// port; [`CoreError::NotFound`] for an unknown group;
/// [`CoreError::AuditWrite`].
pub async fn add_resource(
    pool: &PgPool,
    name: &str,
    host: &str,
    port: u16,
    group: &str,
    ssh_host_key: &VerifyingKey,
) -> Result<Uuid, CoreError> {
    if !is_resource_name(name) {
        return Err(invalid(
            "nom de ressource : [a-z0-9][a-z0-9.-]{0,62} attendu",
        ));
    }
    ostena_scope::parse_host(host).map_err(|e| invalid(format!("hôte : {e}")))?;
    if port == 0 {
        return Err(invalid("port nul"));
    }
    let id = new_id()?;
    let mut tx = pool.begin().await?;
    let actor = audit::admin_actor(&mut tx).await?;
    let group_id = group_id(&mut tx, group).await?;
    sqlx::query!(
        "INSERT INTO resource (id, name, host, port, ssh_host_p256_public, gateway_group)
         VALUES ($1::text::uuid, $2, $3, $4, $5, $6::text::uuid)",
        id.to_string(),
        name,
        host,
        i32::from(port),
        &ssh_host_key.to_bytes()[..],
        group_id.to_string(),
    )
    .execute(&mut *tx)
    .await
    .map_err(unique("cette ressource"))?;
    let event = admin_event(EventKind::ResourceCreated, actor)
        .uuid(field::RESOURCE_ID, id.to_bytes())
        .text(field::NAME, name)
        .text(field::HOST, truncate(host))
        .u64(field::PORT, u64::from(port))
        .uuid(field::GROUP_ID, group_id.to_bytes());
    commit_granting(tx, event).await?;
    tracing::info!(event = "resource.created", resource = %id, name);
    Ok(id)
}

/// Adds the account `account` to the resource `resource`.
///
/// # Errors
///
/// [`CoreError::Invalid`], [`CoreError::NotFound`],
/// [`CoreError::AuditWrite`].
pub async fn add_account(pool: &PgPool, resource: &str, account: &str) -> Result<Uuid, CoreError> {
    if !is_account(account) {
        return Err(invalid(
            "compte : 1 à 256 octets, sans caractère de contrôle ni espace au bord",
        ));
    }
    let id = new_id()?;
    let mut tx = pool.begin().await?;
    let actor = audit::admin_actor(&mut tx).await?;
    let resource_id = sqlx::query_scalar!(
        r#"SELECT id::text AS "id!" FROM resource WHERE name = $1 AND disabled_at IS NULL"#,
        resource
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| CoreError::NotFound(format!("ressource {resource}")))?;
    sqlx::query!(
        "INSERT INTO target_account (id, resource_id, name)
         VALUES ($1::text::uuid, $2::text::uuid, $3)",
        id.to_string(),
        resource_id,
        account,
    )
    .execute(&mut *tx)
    .await
    .map_err(unique("ce compte"))?;
    let event = admin_event(EventKind::TargetAccountCreated, actor)
        .uuid(field::ACCOUNT_ID, id.to_bytes())
        .uuid(field::RESOURCE_ID, uuid(&resource_id)?.to_bytes())
        .text(field::ACCOUNT, truncate(account));
    commit_granting(tx, event).await?;
    Ok(id)
}

/// Every resource and its accounts, by name.
///
/// # Errors
///
/// [`CoreError::Database`].
pub async fn list_resources(pool: &PgPool) -> Result<Vec<ResourceRow>, CoreError> {
    let rows = sqlx::query!(
        r#"SELECT r.id::text AS "id!", r.name, r.host, r.port, g.name AS "group!",
                  r.ssh_host_p256_public IS NOT NULL AS "pinned!",
                  coalesce(array_agg(a.name ORDER BY a.name)
                           FILTER (WHERE a.id IS NOT NULL AND a.disabled_at IS NULL),
                           '{}') AS "accounts!"
           FROM resource r JOIN gateway_group g ON g.id = r.gateway_group
           LEFT JOIN target_account a ON a.resource_id = r.id
           WHERE r.disabled_at IS NULL
           GROUP BY r.id, g.name ORDER BY r.name"#
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(ResourceRow {
                id: uuid(&r.id)?,
                name: r.name,
                host: r.host,
                port: u16::try_from(r.port).unwrap_or(0),
                group: r.group,
                host_key_pinned: r.pinned,
                accounts: r.accounts,
            })
        })
        .collect()
}

// ---------------------------------------------------------------- rights

/// One right.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RightRow {
    /// Identifier.
    pub id: Uuid,
    /// User name.
    pub user: String,
    /// Resource name.
    pub resource: String,
    /// Account name.
    pub account: String,
    /// Protocol.
    pub protocol: String,
    /// End of validity, Unix seconds.
    pub valid_until: u64,
    /// Longest session, seconds.
    pub max_session_secs: u32,
    /// Revoked.
    pub revoked: bool,
}

/// Grants `user` SSH access to `account@resource` until `valid_until`
/// (Unix seconds, at most 366 days ahead), sessions of at most
/// `max_session_secs` (60 to 43 200).
///
/// # Errors
///
/// [`CoreError::Invalid`] for bounds, [`CoreError::NotFound`] for an
/// unknown user, resource or account, [`CoreError::AuditWrite`].
pub async fn grant_right(
    pool: &PgPool,
    user: &str,
    resource: &str,
    account: &str,
    valid_until: u64,
    max_session_secs: u32,
) -> Result<Uuid, CoreError> {
    let now = unix_now();
    if valid_until <= now || valid_until > now + MAX_RIGHT_SECS {
        return Err(invalid(
            "fin du droit obligatoire, dans le futur et à 366 jours au plus",
        ));
    }
    if !SESSION_SECS.contains(&max_session_secs) {
        return Err(invalid("durée de session : 60 à 43 200 secondes"));
    }
    let id = new_id()?;
    let mut tx = pool.begin().await?;
    let actor = audit::admin_actor(&mut tx).await?;
    let user_id = sqlx::query_scalar!(
        r#"SELECT id::text AS "id!" FROM app_user WHERE name = $1 AND state = 'active'"#,
        user
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| CoreError::NotFound(format!("utilisateur actif {user}")))?;
    let account_id = sqlx::query_scalar!(
        r#"SELECT a.id::text AS "id!" FROM target_account a JOIN resource r ON r.id = a.resource_id
           WHERE r.name = $1 AND a.name = $2 AND r.disabled_at IS NULL AND a.disabled_at IS NULL"#,
        resource,
        account,
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| CoreError::NotFound(format!("compte {account}@{resource}")))?;
    sqlx::query!(
        "INSERT INTO access_right (id, user_id, account_id, protocol, valid_from, valid_until,
                                   max_session_secs, created_by)
         VALUES ($1::text::uuid, $2::text::uuid, $3::text::uuid, 'ssh', $4, $5, $6, $7)",
        id.to_string(),
        user_id,
        account_id,
        i64_of(now),
        i64_of(valid_until),
        i32::try_from(max_session_secs).unwrap_or(i32::MAX),
        actor,
    )
    .execute(&mut *tx)
    .await?;
    let event = admin_event(EventKind::RightGranted, actor)
        .uuid(field::RIGHT_ID, id.to_bytes())
        .uuid(field::USER_ID, uuid(&user_id)?.to_bytes())
        .uuid(field::ACCOUNT_ID, uuid(&account_id)?.to_bytes())
        .text(field::PROTOCOL, "ssh")
        .u64(field::VALID_UNTIL, valid_until)
        .u64(field::MAX_SESSION_SECS, u64::from(max_session_secs));
    commit_granting(tx, event).await?;
    tracing::info!(event = "right.granted", right = %id, user, resource, account);
    Ok(id)
}

/// Revokes the right `right`: no new grant under it. Sessions already
/// open end at their maximum length (or with their login session).
/// Revoking a revoked right changes nothing, and is not audited again.
///
/// # Errors
///
/// [`CoreError::NotFound`], [`CoreError::Database`].
pub async fn revoke_right(pool: &PgPool, right: Uuid) -> Result<(), CoreError> {
    let mut tx = pool.begin().await?;
    let actor = audit::admin_actor(&mut tx).await?;
    let revoked = sqlx::query!(
        "UPDATE access_right SET revoked_at = now(), revoked_by = $2
         WHERE id = $1::text::uuid AND revoked_at IS NULL",
        right.to_string(),
        actor,
    )
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if revoked == 0 {
        let known = sqlx::query_scalar!(
            r#"SELECT true AS "known!" FROM access_right WHERE id = $1::text::uuid"#,
            right.to_string(),
        )
        .fetch_optional(&mut *tx)
        .await?;
        tx.rollback().await?;
        return match known {
            // Already revoked: nothing changes.
            Some(_) => Ok(()),
            None => Err(CoreError::NotFound(format!("droit {right}"))),
        };
    }
    notify_audit(&mut tx).await?;
    // Protective, last statement before the commit.
    audit::append_protective(
        &mut tx,
        admin_event(EventKind::RightRevoked, actor).uuid(field::RIGHT_ID, right.to_bytes()),
    )
    .await;
    tx.commit().await?;
    tracing::warn!(event = "right.revoked", right = %right);
    Ok(())
}

/// Every right, newest first.
///
/// # Errors
///
/// [`CoreError::Database`].
pub async fn list_rights(pool: &PgPool) -> Result<Vec<RightRow>, CoreError> {
    let rows = sqlx::query!(
        r#"SELECT ar.id::text AS "id!", u.name AS "user!", r.name AS "resource!",
                  a.name AS "account!", ar.protocol, ar.valid_until, ar.max_session_secs,
                  ar.revoked_at IS NOT NULL AS "revoked!"
           FROM access_right ar JOIN app_user u ON u.id = ar.user_id
           JOIN target_account a ON a.id = ar.account_id JOIN resource r ON r.id = a.resource_id
           ORDER BY ar.created_at DESC, ar.id"#
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(RightRow {
                id: uuid(&r.id)?,
                user: r.user,
                resource: r.resource,
                account: r.account,
                protocol: r.protocol,
                valid_until: u64::try_from(r.valid_until).unwrap_or(0),
                max_session_secs: u32::try_from(r.max_session_secs).unwrap_or(0),
                revoked: r.revoked,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_follow_the_rules() {
        assert!(is_user_name("alice.martin-2"));
        assert!(!is_user_name("Alice"));
        assert!(!is_user_name("-alice"));
        assert!(!is_user_name(&"a".repeat(65)));
        assert!(is_user_name(&"a".repeat(64)));
        assert!(is_resource_name("srv-lab01.example"));
        assert!(!is_resource_name("srv_lab01"));
        assert!(!is_resource_name(&"a".repeat(64)));
        assert!(is_group_name("dc-paris_1"));
        assert!(is_account("root"));
        assert!(is_account("DOMAIN\\admin user"));
        for bad in ["", " root", "root ", "ro\not", &"a".repeat(257)] {
            assert!(!is_account(bad), "{bad:?}");
        }
    }

    #[test]
    fn host_names_are_checked() {
        let ok =
            |n: &[&str]| check_host_names(&n.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>());
        assert!(ok(&[]).is_ok());
        assert!(ok(&["bastion.example", "bastion", "192.0.2.10"]).is_ok());
        for bad in [
            &["Bastion"][..],
            &["a,b"],
            &["bastion", "bastion"],
            &["has space"],
            &[""],
        ] {
            assert_eq!(ok(bad).unwrap_err().code(), "CORE-E012", "{bad:?}");
        }
        let many: Vec<String> = (0..17).map(|i| format!("h{i}")).collect();
        assert!(check_host_names(&many).is_err());
    }

    #[test]
    fn policies_are_compiled_for_production() {
        let lab = PolicySpec {
            gateway_group: "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6".into(),
            allow: vec![ostena_common::config::scope::AllowRuleSpec {
                label: None,
                networks: vec!["10.20.0.0/16".into()],
                ports: vec!["22".into()],
            }],
            ..PolicySpec::default()
        };
        check_policy(&lab).unwrap();
        let spec = PolicySpec {
            allow_short_names: true,
            ..lab.clone()
        };
        assert_eq!(check_policy(&spec).unwrap_err().code(), "CORE-E012");
        let spec = PolicySpec {
            floor_exceptions: vec![ostena_common::config::scope::FloorExceptionSpec {
                network: "10.0.0.0/8".into(),
                reason: "laboratoire".into(),
            }],
            ..PolicySpec::default()
        };
        assert_eq!(check_policy(&spec).unwrap_err().code(), "CORE-E012");
    }
}
