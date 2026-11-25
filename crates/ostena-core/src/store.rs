//! The agent registry and the enrolment tokens in PostgreSQL (ADR-0011).
//!
//! Every change is committed with a notification on [`CHANNEL`]: the core
//! that did not make it (an administration command runs in another process)
//! updates its copy of the registry or opens its enrolment listener.
//!
//! Every change is also written to the audit chain (ADR-0012), in the same
//! transaction: enrolment, renewal, token issuance and consumption are
//! refused if their record cannot be written (granting); a revocation and a
//! refused token commit anyway (protective).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ostena_audit::{ActorKind, Event, EventKind, Outcome, field};
use ostena_tunnel::enroll::{
    AgentRegistry, EnrollmentService, EnrollmentToken, StoreFuture, TokenDecision, TokenRecord,
    TokenStore,
};
use ostena_tunnel::{TunnelError, Uuid};
use sqlx::PgPool;

use crate::audit::{self, Appended, Recorder};
use crate::cache::{AgentCache, CertEntry};
use crate::error::CoreError;

/// Notification channel of the registry.
pub const CHANNEL: &str = "ostena_registry";

/// What a notification on [`CHANNEL`] says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    /// A token was issued: open the enrolment listener.
    Token,
    /// A certificate was registered.
    Registered,
    /// An agent was revoked: close its tunnels.
    Revoked(Uuid),
    /// The audit chain changed (an administration command appended to it):
    /// the head signer looks at the tip.
    Audit,
    /// A login session was revoked: tell the agents concerned (ADR-0014).
    LoginRevoked(Uuid),
    /// A gateway group changed (SSH host names, scope policy): push again
    /// to its agents.
    Group(Uuid),
}

impl Notice {
    /// The payload sent.
    pub fn payload(&self) -> String {
        match self {
            Self::Token => "token".into(),
            Self::Registered => "registered".into(),
            Self::Revoked(agent) => format!("revoked:{agent}"),
            Self::Audit => "audit".into(),
            Self::LoginRevoked(session) => format!("login_revoked:{session}"),
            Self::Group(group) => format!("group:{group}"),
        }
    }

    /// Parses a payload; anything else is ignored by the caller.
    pub fn parse(payload: &str) -> Option<Self> {
        match payload {
            "token" => Some(Self::Token),
            "registered" => Some(Self::Registered),
            "audit" => Some(Self::Audit),
            _ => {
                let (kind, id) = payload.split_once(':')?;
                let id = Uuid::parse(id)?;
                match kind {
                    "revoked" => Some(Self::Revoked(id)),
                    "login_revoked" => Some(Self::LoginRevoked(id)),
                    "group" => Some(Self::Group(id)),
                    _ => None,
                }
            }
        }
    }
}

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "used as map_err(store_error)"
)]
fn store_error(e: sqlx::Error) -> TunnelError {
    tracing::warn!(event = "core.registry_error", "{e}");
    TunnelError::RegistryUnavailable
}

fn fingerprint(bytes: &[u8]) -> Result<[u8; 32], CoreError> {
    bytes
        .try_into()
        .map_err(|_| CoreError::Database("empreinte de certificat de taille invalide".into()))
}

pub(crate) fn uuid(text: &str) -> Result<Uuid, CoreError> {
    Uuid::parse(text).ok_or_else(|| CoreError::Database(format!("UUID invalide : {text}")))
}

pub(crate) fn i64_of(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// A granting audit record could not be written: the operation is refused
/// with the registry error (`TUN-E029`).
#[expect(
    clippy::needless_pass_by_value,
    reason = "used as map_err(audit_error)"
)]
fn audit_error(e: CoreError) -> TunnelError {
    tracing::error!(
        event = "audit.append_failed",
        code = e.code(),
        "enregistrement d'audit impossible : opération refusée ; {e}"
    );
    TunnelError::RegistryUnavailable
}

pub(crate) fn agent_event(kind: EventKind, outcome: Outcome, agent: Uuid) -> Event {
    Event::new(kind, outcome, ActorKind::Agent, agent.to_string())
        .uuid(field::AGENT_ID, agent.to_bytes())
}

/// The registry and the tokens of one core.
#[derive(Debug, Clone)]
pub struct PgStore {
    pool: PgPool,
    cache: Arc<AgentCache>,
    recorder: Arc<Recorder>,
    /// The copy of the registry could not be reloaded last time.
    registry_down: Arc<AtomicBool>,
}

impl PgStore {
    /// A store on `pool`, keeping `cache` in step with what it commits.
    pub fn new(pool: PgPool, cache: Arc<AgentCache>) -> Self {
        Self {
            pool,
            cache,
            recorder: Arc::new(Recorder::new()),
            registry_down: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// The copy of the registry it keeps in step.
    pub fn cache(&self) -> Arc<AgentCache> {
        self.cache.clone()
    }

    /// What links its audit records to the head signer.
    pub fn recorder(&self) -> Arc<Recorder> {
        self.recorder.clone()
    }

    /// Reads every agent certificate, for a full reload of the copy.
    ///
    /// # Errors
    ///
    /// [`CoreError::Database`].
    pub async fn certificates(&self) -> Result<HashMap<[u8; 32], CertEntry>, CoreError> {
        let rows = sqlx::query!(
            r#"SELECT c.fingerprint, a.id::text AS "agent!", a.gateway_group::text AS "group!",
                      (c.revoked_at IS NOT NULL OR a.revoked_at IS NOT NULL) AS "revoked!"
               FROM agent_certificate c JOIN agent a ON a.id = c.agent_id"#
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok((
                    fingerprint(&r.fingerprint)?,
                    CertEntry {
                        group: uuid(&r.group)?,
                        agent: uuid(&r.agent)?,
                        revoked: r.revoked,
                    },
                ))
            })
            .collect()
    }

    /// Reloads the copy in full; on failure the copy becomes unavailable
    /// (new agents refused) until a reload succeeds.
    ///
    /// # Errors
    ///
    /// [`CoreError::Database`].
    pub async fn reload(&self) -> Result<(), CoreError> {
        match self.certificates().await {
            Ok(entries) => {
                self.cache.replace(entries);
                if self.registry_down.swap(false, Ordering::AcqRel) {
                    tracing::info!(
                        event = "core.registry_restored",
                        "registre de nouveau lisible"
                    );
                    self.recorder.emit(Event::new(
                        EventKind::CoreRegistryRestored,
                        Outcome::Success,
                        ActorKind::Core,
                        audit::CORE_ACTOR,
                    ));
                }
                Ok(())
            }
            Err(e) => {
                if !self.registry_down.swap(true, Ordering::AcqRel) {
                    tracing::error!(
                        event = "core.registry_unavailable",
                        code = e.code(),
                        "registre illisible : nouveaux agents refusés (TUN-E029) jusqu'au prochain rechargement réussi ; {e}"
                    );
                    self.recorder.emit(
                        Event::new(
                            EventKind::CoreRegistryUnavailable,
                            Outcome::Failure,
                            ActorKind::Core,
                            audit::CORE_ACTOR,
                        )
                        .text(field::CODE, e.code())
                        .text(field::REASON, truncate(&e.to_string())),
                    );
                }
                self.cache.invalidate();
                Err(e)
            }
        }
    }
}

impl AgentRegistry for PgStore {
    fn register(&self, fingerprint: [u8; 32], group: Uuid, agent: Uuid) -> StoreFuture<'_, ()> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await.map_err(store_error)?;
            // A new row: an enrolment; none: a renewal of a known agent.
            let enrolled = sqlx::query!(
                "INSERT INTO agent (id, gateway_group) VALUES ($1::text::uuid, $2::text::uuid)
                 ON CONFLICT (id) DO NOTHING",
                agent.to_string(),
                group.to_string(),
            )
            .execute(&mut *tx)
            .await
            .map_err(store_error)?
            .rows_affected()
                == 1;
            // A renewal adds a certificate to a known agent: only if the group
            // matches and the agent is not revoked.
            let inserted = sqlx::query!(
                "INSERT INTO agent_certificate (fingerprint, agent_id)
                 SELECT $1, id FROM agent
                 WHERE id = $2::text::uuid AND gateway_group = $3::text::uuid
                   AND revoked_at IS NULL",
                &fingerprint[..],
                agent.to_string(),
                group.to_string(),
            )
            .execute(&mut *tx)
            .await
            .map_err(store_error)?
            .rows_affected();
            if inserted != 1 {
                return Err(TunnelError::Revoked);
            }
            notify(&mut tx, &Notice::Registered)
                .await
                .map_err(store_error)?;
            let kind = if enrolled {
                EventKind::AgentEnrolled
            } else {
                EventKind::AgentCertificateRenewed
            };
            let event = agent_event(kind, Outcome::Success, agent)
                .uuid(field::GROUP_ID, group.to_bytes())
                .bytes(field::FINGERPRINT, fingerprint);
            // Granting, last statement before the commit.
            let appended = audit::append(&mut tx, event).await.map_err(audit_error)?;
            tx.commit().await.map_err(store_error)?;
            self.recorder.critical(&[appended]);
            self.cache.insert(
                fingerprint,
                CertEntry {
                    group,
                    agent,
                    revoked: false,
                },
            );
            Ok(())
        })
    }
}

impl TokenStore for PgStore {
    fn insert(&self, id: [u8; 16], record: TokenRecord) -> StoreFuture<'_, ()> {
        Box::pin(async move {
            let appended = insert_token(&self.pool, id, &record)
                .await
                .map_err(audit_error)?;
            self.recorder.critical(&[appended]);
            Ok(())
        })
    }

    fn decide(&self, id: [u8; 16], decide: TokenDecision) -> StoreFuture<'_, ()> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await.map_err(store_error)?;
            // The row stays locked until the commit: two attempts with the same
            // token are decided one after the other.
            let Some(row) = sqlx::query!(
                r#"SELECT digest, gateway_group::text AS "group!", expires_at, used, failures, burned
                   FROM enrollment_token WHERE id = $1 FOR UPDATE"#,
                &id[..],
            )
            .fetch_optional(&mut *tx)
            .await
            .map_err(store_error)?
            else {
                return Err(TunnelError::TokenUnknown);
            };
            let mut record = TokenRecord {
                digest: row
                    .digest
                    .as_slice()
                    .try_into()
                    .map_err(|_| TunnelError::RegistryUnavailable)?,
                group: Uuid::parse(&row.group).ok_or(TunnelError::RegistryUnavailable)?,
                expires_at: u64::try_from(row.expires_at).unwrap_or(0),
                used: row.used,
                failures: u8::try_from(row.failures).unwrap_or(u8::MAX),
                burned: row.burned,
            };
            let decided = decide(&mut record);
            sqlx::query!(
                "UPDATE enrollment_token SET used = $2, failures = $3, burned = $4 WHERE id = $1",
                &id[..],
                record.used,
                i16::from(record.failures),
                record.burned,
            )
            .execute(&mut *tx)
            .await
            .map_err(store_error)?;
            let event = |kind, outcome| {
                Event::new(kind, outcome, ActorKind::Peer, "")
                    .bytes(field::ENROLLMENT_ID, id)
                    .uuid(field::GROUP_ID, record.group.to_bytes())
            };
            // Last statement before the commit in both cases.
            let appended = match &decided {
                // Granting: the token is spent only if its record is written.
                Ok(()) => Some(
                    audit::append(
                        &mut tx,
                        event(EventKind::EnrollTokenConsumed, Outcome::Success),
                    )
                    .await
                    .map_err(audit_error)?,
                ),
                // Protective: the failure counter is kept whatever happens.
                Err(e) => {
                    audit::append_protective(
                        &mut tx,
                        event(EventKind::EnrollTokenRejected, Outcome::Refused)
                            .u64(field::FAILURES, u64::from(record.failures))
                            .bool(field::BURNED, record.burned)
                            .text(field::CODE, e.code()),
                    )
                    .await
                }
            };
            tx.commit().await.map_err(store_error)?;
            if let Some(appended) = appended {
                self.recorder.critical(&[appended]);
            }
            decided
        })
    }

    fn next_expiry(&self, now: u64) -> StoreFuture<'_, Option<u64>> {
        Box::pin(async move {
            let next = sqlx::query_scalar!(
                "SELECT min(expires_at) FROM enrollment_token
                 WHERE NOT used AND NOT burned AND expires_at > $1",
                i64_of(now),
            )
            .fetch_one(&self.pool)
            .await
            .map_err(store_error)?;
            Ok(next.and_then(|n| u64::try_from(n).ok()))
        })
    }
}

/// Stores a token and its granting `enroll.token_issued` record, in one
/// transaction; the actor is the database user (`system_user`).
async fn insert_token(
    pool: &PgPool,
    id: [u8; 16],
    record: &TokenRecord,
) -> Result<Appended, CoreError> {
    let mut tx = pool.begin().await?;
    let actor = audit::admin_actor(&mut tx).await?;
    sqlx::query!(
        "INSERT INTO enrollment_token (id, digest, gateway_group, expires_at)
         VALUES ($1, $2, $3::text::uuid, $4)",
        &id[..],
        &record.digest[..],
        record.group.to_string(),
        i64_of(record.expires_at),
    )
    .execute(&mut *tx)
    .await?;
    notify(&mut tx, &Notice::Token).await?;
    let event = Event::new(
        EventKind::EnrollTokenIssued,
        Outcome::Success,
        ActorKind::Admin,
        actor,
    )
    .bytes(field::ENROLLMENT_ID, id)
    .uuid(field::GROUP_ID, record.group.to_bytes())
    .u64(field::EXPIRES_AT, record.expires_at);
    let appended = audit::append(&mut tx, event).await?;
    tx.commit()
        .await
        .map_err(|e| CoreError::AuditWrite(e.to_string()))?;
    Ok(appended)
}

async fn notify(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    notice: &Notice,
) -> Result<(), sqlx::Error> {
    sqlx::query!("SELECT pg_notify($1, $2)", CHANNEL, notice.payload())
        .execute(&mut **tx)
        .await
        .map(|_| ())
}

/// Sends `notice` on [`CHANNEL`], delivered at the commit of `tx`.
///
/// # Errors
///
/// [`CoreError::Database`].
pub(crate) async fn notify_notice(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    notice: &Notice,
) -> Result<(), CoreError> {
    notify(tx, notice).await.map_err(CoreError::from)
}

/// Notifies the running core that the audit chain changed (an
/// administration command appended to it).
///
/// # Errors
///
/// [`CoreError::Database`].
pub(crate) async fn notify_audit(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), CoreError> {
    notify(tx, &Notice::Audit).await.map_err(CoreError::from)
}

/// Text of at most 1024 bytes (an audit text field), cut on a character
/// boundary, without control characters.
pub(crate) fn truncate(text: &str) -> String {
    let mut out: String = text.chars().filter(|c| !c.is_control()).collect();
    let mut end = out.len().min(ostena_audit::record::MAX_TEXT_LEN);
    while !out.is_char_boundary(end) {
        end -= 1;
    }
    out.truncate(end);
    out
}

// ------------------------------------------------------------ administration

/// One agent, for `ostena core agent list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRow {
    /// Agent identifier.
    pub id: Uuid,
    /// Gateway group.
    pub group: Uuid,
    /// Enrolment time, ISO 8601 UTC.
    pub enrolled_at: String,
    /// Revocation time, if revoked.
    pub revoked_at: Option<String>,
    /// Certificates issued so far (enrolment and renewals).
    pub certificates: i64,
}

/// Issues an enrolment token for `group`, valid `ttl`: the running core
/// opens its listener when notified. Returns the token, to hand to the agent
/// operator once.
///
/// # Errors
///
/// [`CoreError::Startup`] for a lifetime out of bounds,
/// [`CoreError::AuditWrite`] if its audit record cannot be written (the
/// token is then not issued), [`CoreError::Database`] otherwise.
pub async fn issue_token(
    pool: &PgPool,
    group: Uuid,
    ttl: Duration,
) -> Result<EnrollmentToken, CoreError> {
    let (token, record) = EnrollmentService::new_token(group, ttl, unix_now())
        .map_err(|e| CoreError::Startup(e.to_string()))?;
    insert_token(pool, token.id(), &record).await?;
    tracing::info!(event = "enroll.token_issued", group = %group, ttl_secs = ttl.as_secs());
    Ok(token)
}

/// Every agent, oldest first.
///
/// # Errors
///
/// [`CoreError::Database`].
pub async fn list_agents(pool: &PgPool) -> Result<Vec<AgentRow>, CoreError> {
    let rows = sqlx::query!(
        r#"SELECT a.id::text AS "id!", a.gateway_group::text AS "group!",
                  to_char(a.enrolled_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS "enrolled_at!",
                  to_char(a.revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS revoked_at,
                  (SELECT count(*) FROM agent_certificate c WHERE c.agent_id = a.id) AS "certificates!"
           FROM agent a ORDER BY a.enrolled_at, a.id"#
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(AgentRow {
                id: uuid(&r.id)?,
                group: uuid(&r.group)?,
                enrolled_at: r.enrolled_at,
                revoked_at: r.revoked_at,
                certificates: r.certificates,
            })
        })
        .collect()
}

/// Revokes `agent` and all its certificates; the running core closes its
/// tunnels when notified. Revoking a revoked agent changes nothing.
///
/// # Errors
///
/// [`CoreError::NotFound`] for an unknown agent, [`CoreError::Database`]
/// otherwise.
pub async fn revoke_agent(pool: &PgPool, agent: Uuid) -> Result<(), CoreError> {
    let mut tx = pool.begin().await?;
    let actor = audit::admin_actor(&mut tx).await?;
    let found = sqlx::query!(
        "UPDATE agent SET revoked_at = coalesce(revoked_at, now()) WHERE id = $1::text::uuid",
        agent.to_string(),
    )
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if found == 0 {
        return Err(CoreError::NotFound(format!("agent {agent}")));
    }
    sqlx::query!(
        "UPDATE agent_certificate SET revoked_at = coalesce(revoked_at, now())
         WHERE agent_id = $1::text::uuid",
        agent.to_string(),
    )
    .execute(&mut *tx)
    .await?;
    notify(&mut tx, &Notice::Revoked(agent)).await?;
    // Protective, last statement before the commit: the revocation stands
    // even if its record cannot be written.
    audit::append_protective(
        &mut tx,
        Event::new(
            EventKind::AgentRevoked,
            Outcome::Success,
            ActorKind::Admin,
            actor,
        )
        .uuid(field::AGENT_ID, agent.to_bytes()),
    )
    .await;
    tx.commit().await?;
    tracing::warn!(event = "agent.revoked", agent = %agent, "agent révoqué");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notices_round_trip() {
        let agent = Uuid::from_bytes([7; 16]);
        for n in [
            Notice::Token,
            Notice::Registered,
            Notice::Revoked(agent),
            Notice::Audit,
            Notice::LoginRevoked(agent),
            Notice::Group(agent),
        ] {
            assert_eq!(Notice::parse(&n.payload()), Some(n));
        }
        for bad in [
            "",
            "revoked:",
            "revoked:x",
            "token ",
            "other",
            "group:",
            "login_revoked:x",
            "other:07070707-0707-0707-0707-070707070707",
        ] {
            assert_eq!(Notice::parse(bad), None, "{bad}");
        }
    }
}
