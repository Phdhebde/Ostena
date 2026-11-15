//! The agent registry and the enrolment tokens in PostgreSQL (ADR-0011).
//!
//! Every change is committed with a notification on [`CHANNEL`]: the core
//! that did not make it (an administration command runs in another process)
//! updates its copy of the registry or opens its enrolment listener.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ostena_tunnel::enroll::{
    AgentRegistry, EnrollmentService, EnrollmentToken, StoreFuture, TokenDecision, TokenRecord,
    TokenStore,
};
use ostena_tunnel::{TunnelError, Uuid};
use sqlx::PgPool;

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
}

impl Notice {
    /// The payload sent.
    pub fn payload(&self) -> String {
        match self {
            Self::Token => "token".into(),
            Self::Registered => "registered".into(),
            Self::Revoked(agent) => format!("revoked:{agent}"),
        }
    }

    /// Parses a payload; anything else is ignored by the caller.
    pub fn parse(payload: &str) -> Option<Self> {
        match payload {
            "token" => Some(Self::Token),
            "registered" => Some(Self::Registered),
            _ => payload
                .strip_prefix("revoked:")
                .and_then(Uuid::parse)
                .map(Self::Revoked),
        }
    }
}

fn unix_now() -> u64 {
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

fn uuid(text: &str) -> Result<Uuid, CoreError> {
    Uuid::parse(text).ok_or_else(|| CoreError::Database(format!("UUID invalide : {text}")))
}

fn i64_of(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// The registry and the tokens of one core.
#[derive(Debug, Clone)]
pub struct PgStore {
    pool: PgPool,
    cache: Arc<AgentCache>,
}

impl PgStore {
    /// A store on `pool`, keeping `cache` in step with what it commits.
    pub fn new(pool: PgPool, cache: Arc<AgentCache>) -> Self {
        Self { pool, cache }
    }

    /// The pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// The copy of the registry it keeps in step.
    pub fn cache(&self) -> Arc<AgentCache> {
        self.cache.clone()
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
                Ok(())
            }
            Err(e) => {
                if self.cache.is_available() {
                    tracing::error!(
                        event = "core.registry_unavailable",
                        code = e.code(),
                        "registre illisible : nouveaux agents refusés (TUN-E029) jusqu'au prochain rechargement réussi ; {e}"
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
            sqlx::query!(
                "INSERT INTO agent (id, gateway_group) VALUES ($1::text::uuid, $2::text::uuid)
                 ON CONFLICT (id) DO NOTHING",
                agent.to_string(),
                group.to_string(),
            )
            .execute(&mut *tx)
            .await
            .map_err(store_error)?;
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
            tx.commit().await.map_err(store_error)?;
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
            insert_token(&self.pool, id, &record)
                .await
                .map_err(store_error)
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
            tx.commit().await.map_err(store_error)?;
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

async fn insert_token(
    pool: &PgPool,
    id: [u8; 16],
    record: &TokenRecord,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
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
    tx.commit().await
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
/// [`CoreError::Database`] otherwise.
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
        for n in [Notice::Token, Notice::Registered, Notice::Revoked(agent)] {
            assert_eq!(Notice::parse(&n.payload()), Some(n));
        }
        for bad in ["", "revoked:", "revoked:x", "token ", "other"] {
            assert_eq!(Notice::parse(bad), None, "{bad}");
        }
    }
}
