//! Login sessions (ADR-0014): an `ostena login` session is the key
//! identifier of the user certificate; revoking it cuts the SSH sessions
//! that depend on it.
//!
//! The login itself (credentials, certificate issuance) belongs to the
//! login service; it opens the session with [`open_session`] in its own
//! transaction. A revocation is protective: it commits even if its audit
//! record cannot be written, and the running core tells the agents that
//! received a grant for that session or consumed one ([`agents_to_notify`]);
//! an agent that was disconnected is told again when it connects
//! ([`revoked_for_agent`]).

use ostena_audit::{ActorKind, Event, EventKind, Outcome, field};
use ostena_tunnel::Uuid;
use sqlx::PgPool;

use crate::audit::{self, Tx};
use crate::error::CoreError;
use crate::store::{Notice, i64_of, notify_notice, truncate, unix_now, uuid};

/// Longest login session, seconds (ADR-0010).
pub const MAX_LOGIN_SECS: u64 = 8 * 3600;

/// A fresh login session identifier.
///
/// # Errors
///
/// [`CoreError::Keys`] if the random generator fails.
pub fn new_session_id() -> Result<Uuid, CoreError> {
    Uuid::random().map_err(|e| CoreError::Keys(format!("aléa : {e}")))
}

/// Opens the login session `session` of `user` for the certificate whose
/// SHA-256 is `certificate_sha256`, until `expires_at` (at most eight
/// hours from now), in the transaction of the login.
///
/// # Errors
///
/// [`CoreError::Invalid`] for an expiry in the past or too far,
/// [`CoreError::Database`] otherwise (unknown user, certificate reused).
pub async fn open_session(
    tx: &mut Tx<'_>,
    session: Uuid,
    user: Uuid,
    certificate_sha256: [u8; 32],
    expires_at: u64,
) -> Result<(), CoreError> {
    let now = unix_now();
    if expires_at <= now || expires_at > now + MAX_LOGIN_SECS {
        return Err(CoreError::Invalid(
            "fin de session de connexion passée ou à plus de 8 heures".into(),
        ));
    }
    sqlx::query!(
        "INSERT INTO login_session (id, user_id, certificate_sha256, started_at, expires_at)
         VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5)",
        session.to_string(),
        user.to_string(),
        &certificate_sha256[..],
        i64_of(now),
        i64_of(expires_at),
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Revokes `session` for `reason`; the actor is the database user. The
/// running core tells the agents concerned. Revoking a revoked session
/// changes nothing.
///
/// # Errors
///
/// [`CoreError::NotFound`] for an unknown session, [`CoreError::Database`]
/// otherwise.
pub async fn revoke_session(pool: &PgPool, session: Uuid, reason: &str) -> Result<(), CoreError> {
    let mut tx = pool.begin().await?;
    let actor = audit::admin_actor(&mut tx).await?;
    let row = sqlx::query!(
        r#"UPDATE login_session
           SET revoked_at = now(), revoked_by = $2, revocation_reason = $3
           WHERE id = $1::text::uuid AND revoked_at IS NULL
           RETURNING user_id::text AS "user!""#,
        session.to_string(),
        actor,
        truncate_reason(reason),
    )
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        let known = sqlx::query_scalar!(
            r#"SELECT true AS "known!" FROM login_session WHERE id = $1::text::uuid"#,
            session.to_string(),
        )
        .fetch_optional(&mut *tx)
        .await?;
        return match known {
            // Already revoked: nothing changes.
            Some(_) => Ok(()),
            None => Err(CoreError::NotFound(format!(
                "session de connexion {session}"
            ))),
        };
    };
    notify_notice(&mut tx, &Notice::LoginRevoked(session)).await?;
    // Protective, last statement before the commit.
    audit::append_protective(
        &mut tx,
        Event::new(
            EventKind::LoginSessionRevoked,
            Outcome::Success,
            ActorKind::Admin,
            actor,
        )
        .uuid(field::LOGIN_SESSION, session.to_bytes())
        .uuid(field::USER_ID, uuid(&row.user)?.to_bytes())
        .text(field::REASON, truncate(reason)),
    )
    .await;
    tx.commit().await?;
    tracing::warn!(event = "login_session.revoked", login_session = %session, "session de connexion révoquée");
    Ok(())
}

fn truncate_reason(reason: &str) -> String {
    let clean = truncate(reason);
    clean.chars().take(256).collect()
}

/// The agents that received a grant for `session` or opened a session with
/// one (any agent of the group may consume a grant): the running core sends
/// them `login_revoked`.
///
/// # Errors
///
/// [`CoreError::Database`].
pub async fn agents_to_notify(pool: &PgPool, session: Uuid) -> Result<Vec<Uuid>, CoreError> {
    let rows = sqlx::query_scalar!(
        r#"SELECT agent_id::text AS "agent!" FROM access_grant
           WHERE login_session_id = $1::text::uuid
           UNION
           SELECT consumed_by::text AS "agent!" FROM access_grant
           WHERE login_session_id = $1::text::uuid AND consumed_by IS NOT NULL"#,
        session.to_string(),
    )
    .fetch_all(pool)
    .await?;
    rows.iter().map(|a| uuid(a)).collect()
}

/// The revoked login sessions, not yet expired, for which `agent` received
/// a grant or opened a session: repeated to the agent when it connects (it may have missed the
/// revocation while disconnected).
///
/// # Errors
///
/// [`CoreError::Database`].
pub async fn revoked_for_agent(pool: &PgPool, agent: Uuid) -> Result<Vec<Uuid>, CoreError> {
    let rows = sqlx::query_scalar!(
        r#"SELECT DISTINCT s.id::text AS "id!" FROM login_session s
           JOIN access_grant g ON g.login_session_id = s.id
           WHERE (g.agent_id = $1::text::uuid OR g.consumed_by = $1::text::uuid)
             AND s.revoked_at IS NOT NULL
             AND s.expires_at > $2"#,
        agent.to_string(),
        i64_of(unix_now()),
    )
    .fetch_all(pool)
    .await?;
    rows.iter().map(|s| uuid(s)).collect()
}
