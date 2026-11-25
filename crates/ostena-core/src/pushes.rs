//! What the core pushes to an agent (ADR-0008, ADR-0014): the scope policy
//! of its group, the SSH trust (authorities and host certificate), and the
//! certification of the SSH host key it sends.
//!
//! Every version comes from one sequence (`push_version`), so that it never
//! goes back. The SSH trust of an agent keeps its version while its content
//! (digest) does not change: the agent refuses another content under a
//! version it already applied (`TUN-E030`).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ostena_audit::{ActorKind, Event, EventKind, Outcome, field};
use ostena_common::config::scope::PolicySpec;
use ostena_crypto::p256::VerifyingKey;
use ostena_tunnel::Uuid;
use ostena_tunnel::control::CoreMessage;
use sqlx::PgPool;

use crate::access::{NO_HOST_NAME, Refusal};
use crate::audit::{self, Appended, CORE_ACTOR, Tx};
use crate::error::CoreError;
use crate::ssh_ca::SshAuthorities;
use crate::store::{i64_of, truncate, uuid};

/// The scope policy of `group`, if one is stored.
///
/// # Errors
///
/// [`CoreError::Database`], also for a stored policy that no longer
/// parses.
pub async fn policy_message(pool: &PgPool, group: Uuid) -> Result<Option<CoreMessage>, CoreError> {
    let row = sqlx::query!(
        "SELECT policy, policy_version FROM gateway_group WHERE id = $1::text::uuid",
        group.to_string(),
    )
    .fetch_optional(pool)
    .await?;
    let Some((Some(policy), Some(version))) = row.map(|r| (r.policy, r.policy_version)) else {
        return Ok(None);
    };
    let policy: PolicySpec = serde_json::from_str(&policy)
        .map_err(|e| CoreError::Database(format!("politique du groupe {group} : {e}")))?;
    Ok(Some(CoreMessage::Policy {
        version: u64::try_from(version).unwrap_or(0),
        policy,
    }))
}

/// A stored host certificate still usable: valid at `now`, for the stored
/// key, signed by the current host authority, and for the current SSH host
/// names of the group (`names`, in any order): a certificate for names the
/// group no longer has is not pushed, and is replaced.
fn usable_certificate(
    ssh: &SshAuthorities,
    key: Option<&[u8]>,
    blob: Option<&[u8]>,
    names: &[String],
    now: u64,
) -> Option<Vec<u8>> {
    let key = VerifyingKey::from_bytes(key?.try_into().ok()?).ok()?;
    let blob = blob?;
    let parsed = ostena_ssh::cert::parse(blob).ok()?;
    parsed.verify(&[ssh.host_ca_public()]).ok()?;
    ostena_ssh::cert::check_host(&parsed, &key, now).ok()?;
    let mut principals = parsed.principals.clone();
    principals.sort_unstable();
    let mut current: Vec<&str> = names.iter().map(String::as_str).collect();
    current.sort_unstable();
    if current.is_empty() || principals != current {
        return None;
    }
    Some(blob.to_vec())
}

/// The SSH host names of `group` (none for an unknown group).
async fn host_names(tx: &mut Tx<'_>, group: Uuid) -> Result<Vec<String>, sqlx::Error> {
    Ok(sqlx::query_scalar!(
        "SELECT ssh_host_names FROM gateway_group WHERE id = $1::text::uuid",
        group.to_string(),
    )
    .fetch_optional(&mut **tx)
    .await?
    .unwrap_or_default())
}

/// The SSH trust of `agent` of `group`: the two authorities and its host
/// certificate if one is usable; its version changes only with its
/// content.
///
/// # Errors
///
/// [`CoreError::Database`].
pub async fn ssh_trust_message(
    pool: &PgPool,
    ssh: &SshAuthorities,
    agent: Uuid,
    group: Uuid,
    now: u64,
) -> Result<CoreMessage, CoreError> {
    let mut tx = pool.begin().await?;
    let row = sqlx::query!(
        "SELECT host_p256_public, host_certificate, trust_version, trust_digest
         FROM agent_ssh WHERE agent_id = $1::text::uuid FOR UPDATE",
        agent.to_string(),
    )
    .fetch_optional(&mut *tx)
    .await?;
    let names = host_names(&mut tx, group).await?;
    let user_ca = ssh.user_ca_public().to_bytes();
    let host_ca = ssh.host_ca_public().to_bytes();
    let certificate = row.as_ref().and_then(|r| {
        usable_certificate(
            ssh,
            r.host_p256_public.as_deref(),
            r.host_certificate.as_deref(),
            &names,
            now,
        )
    });
    // Fixed-size authorities, then the certificate: unambiguous.
    let digest = ostena_crypto::sha256::digest_concat(&[
        &user_ca,
        &host_ca,
        certificate.as_deref().unwrap_or_default(),
    ]);
    let version = match &row {
        Some(r) if r.trust_digest.as_slice() == digest => r.trust_version,
        _ => {
            sqlx::query_scalar!(
                r#"INSERT INTO agent_ssh (agent_id, trust_version, trust_digest)
                   VALUES ($1::text::uuid, nextval('push_version'), $2)
                   ON CONFLICT (agent_id) DO UPDATE
                   SET trust_version = nextval('push_version'), trust_digest = $2,
                       updated_at = now()
                   RETURNING trust_version"#,
                agent.to_string(),
                &digest[..],
            )
            .fetch_one(&mut *tx)
            .await?
        }
    };
    tx.commit().await?;
    Ok(CoreMessage::SshTrust {
        version: u64::try_from(version).unwrap_or(0),
        user_ca_p256_public: vec![URL_SAFE_NO_PAD.encode(user_ca)],
        host_ca_p256_public: vec![URL_SAFE_NO_PAD.encode(host_ca)],
        host_certificate: certificate.map(|c| URL_SAFE_NO_PAD.encode(c)),
    })
}

/// The SSH host key last sent by `agent`, if any.
///
/// # Errors
///
/// [`CoreError::Database`].
pub async fn stored_host_key(
    pool: &PgPool,
    agent: Uuid,
) -> Result<Option<VerifyingKey>, CoreError> {
    let key = sqlx::query_scalar!(
        "SELECT host_p256_public FROM agent_ssh WHERE agent_id = $1::text::uuid",
        agent.to_string(),
    )
    .fetch_optional(pool)
    .await?
    .flatten();
    Ok(key
        .and_then(|k| <[u8; 65]>::try_from(k.as_slice()).ok())
        .and_then(|k| VerifyingKey::from_bytes(&k).ok()))
}

/// The agents whose host certificate is due for renewal at `now` (two
/// thirds of its life), with their host key.
///
/// # Errors
///
/// [`CoreError::Database`].
pub async fn renewals_due(pool: &PgPool, now: u64) -> Result<Vec<(Uuid, VerifyingKey)>, CoreError> {
    let rows = sqlx::query!(
        r#"SELECT agent_id::text AS "agent!", host_p256_public AS "key!",
                  certificate_issued_at AS "issued!", certificate_valid_before AS "before!"
           FROM agent_ssh
           WHERE host_certificate IS NOT NULL AND host_p256_public IS NOT NULL"#
    )
    .fetch_all(pool)
    .await?;
    let mut due = Vec::new();
    for r in rows {
        let issued = u64::try_from(r.issued).unwrap_or(0);
        let before = u64::try_from(r.before).unwrap_or(0);
        if !SshAuthorities::host_renewal_due(issued, before, now) {
            continue;
        }
        let key = <[u8; 65]>::try_from(r.key.as_slice())
            .ok()
            .and_then(|k| VerifyingKey::from_bytes(&k).ok());
        if let Some(key) = key {
            due.push((uuid(&r.agent)?, key));
        }
    }
    Ok(due)
}

/// The `ssh.host_key_refused` record.
pub fn host_key_refused_event(agent: Uuid, refusal: &Refusal) -> Event {
    Event::new(
        EventKind::SshHostKeyRefused,
        Outcome::Refused,
        ActorKind::Agent,
        agent.to_string(),
    )
    .uuid(field::AGENT_ID, agent.to_bytes())
    .text(field::CODE, refusal.code)
    .text(field::REASON, truncate(&refusal.reason))
}

/// Stores the host key of `agent` without certificate; a new key drops the
/// certificate of the old one.
async fn keep_host_key(tx: &mut Tx<'_>, agent: Uuid, public: &[u8; 65]) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO agent_ssh (agent_id, host_p256_public, trust_version, trust_digest)
         VALUES ($1::text::uuid, $2, nextval('push_version'), $3)
         ON CONFLICT (agent_id) DO UPDATE SET host_p256_public = $2,
             host_certificate = CASE WHEN agent_ssh.host_p256_public = $2
                                     THEN agent_ssh.host_certificate END,
             certificate_issued_at = CASE WHEN agent_ssh.host_p256_public = $2
                                          THEN agent_ssh.certificate_issued_at END,
             certificate_valid_before = CASE WHEN agent_ssh.host_p256_public = $2
                                             THEN agent_ssh.certificate_valid_before END,
             updated_at = now()",
        agent.to_string(),
        &public[..],
        &[0u8; 32][..],
    )
    .execute(&mut **tx)
    .await
    .map(|_| ())
}

/// Certifies the SSH host key `key` of `agent` of `group` with the SSH
/// host names of the group, unless its certificate is current (same key,
/// signed by the current authority, for the current host names of the
/// group, not due).
/// Returns the granting `ssh.host_certified` record of a new certificate,
/// `None` if nothing changed. The key is stored even when it cannot be
/// certified yet (a group without host names), for a later change of the
/// group.
///
/// # Errors
///
/// The refusal (`INV-E005` for a group without SSH host name); the caller
/// records `ssh.host_key_refused` ([`host_key_refused_event`]).
pub async fn certify_host(
    pool: &PgPool,
    ssh: &SshAuthorities,
    agent: Uuid,
    group: Uuid,
    key: &VerifyingKey,
    now: u64,
) -> Result<Option<Appended>, Refusal> {
    let public = key.to_bytes();
    let mut tx = pool.begin().await?;
    let row = sqlx::query!(
        "SELECT host_p256_public, host_certificate, certificate_issued_at,
                certificate_valid_before
         FROM agent_ssh WHERE agent_id = $1::text::uuid FOR UPDATE",
        agent.to_string(),
    )
    .fetch_optional(&mut *tx)
    .await?;
    let names = host_names(&mut tx, group).await?;
    let same_key = row
        .as_ref()
        .is_some_and(|r| r.host_p256_public.as_deref() == Some(&public[..]));
    if same_key
        && let Some(r) = &row
        && usable_certificate(
            ssh,
            r.host_p256_public.as_deref(),
            r.host_certificate.as_deref(),
            &names,
            now,
        )
        .is_some()
        && !SshAuthorities::host_renewal_due(
            u64::try_from(r.certificate_issued_at.unwrap_or(0)).unwrap_or(0),
            u64::try_from(r.certificate_valid_before.unwrap_or(0)).unwrap_or(0),
            now,
        )
    {
        return Ok(None);
    }
    if names.is_empty() {
        keep_host_key(&mut tx, agent, &public).await?;
        tx.commit().await?;
        return Err(Refusal {
            code: NO_HOST_NAME,
            reason: format!(
                "groupe {group} inconnu ou sans nom d'hôte SSH : clé d'hôte gardée, non certifiée"
            ),
        });
    }
    let issued = ssh.issue_host(key, agent.to_bytes(), &names, now)?;
    sqlx::query!(
        "INSERT INTO agent_ssh (agent_id, host_p256_public, host_certificate,
                                certificate_issued_at, certificate_valid_before,
                                trust_version, trust_digest)
         VALUES ($1::text::uuid, $2, $3, $4, $5, nextval('push_version'), $6)
         ON CONFLICT (agent_id) DO UPDATE SET host_p256_public = $2, host_certificate = $3,
             certificate_issued_at = $4, certificate_valid_before = $5, updated_at = now()",
        agent.to_string(),
        &public[..],
        issued.blob,
        i64_of(now),
        i64_of(issued.valid_before),
        &[0u8; 32][..],
    )
    .execute(&mut *tx)
    .await?;
    let event = Event::new(
        EventKind::SshHostCertified,
        Outcome::Success,
        ActorKind::Core,
        CORE_ACTOR,
    )
    .uuid(field::AGENT_ID, agent.to_bytes())
    .uuid(field::GROUP_ID, group.to_bytes())
    .bytes(field::P256_PUBLIC, public)
    .text(field::HOST_NAMES, truncate(&names.join(",")))
    .u64(field::NOT_AFTER, issued.valid_before);
    // Granting, last statement before the commit.
    let appended = audit::append(&mut tx, event).await?;
    tx.commit()
        .await
        .map_err(|e| Refusal::from(CoreError::AuditWrite(e.to_string())))?;
    tracing::info!(
        event = "ssh.host_certified",
        agent = %agent,
        not_after = issued.valid_before,
        "certificat d'hôte SSH émis"
    );
    Ok(Some(appended))
}
