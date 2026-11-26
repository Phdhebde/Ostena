//! The PostgreSQL store of the browser sessions (ADR-0020), on top of the
//! authenticator of `ostena login` (same passwords, TOTP, lockout and
//! audit records, channel `web`).
//!
//! Every revocation (logout, idle time, source change, administrator) is
//! protective: it commits even if its audit record cannot be written, and
//! the running core tells the agents concerned, as for `ostena login`.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use ostena_audit::{ActorKind, Event, EventKind, Outcome, field};
use ostena_common::api::web::{
    Channel, LoginSessionItem, LoginSessionList, MAX_LISTED_SESSIONS, ReauthenticateRequest, Role,
    SessionRequest,
};
use ostena_tunnel::Uuid;

use super::session::{SessionEnd, SessionRecord, WebBackend};
use crate::api::ApiError;
use crate::audit::{self, CORE_ACTOR};
use crate::authn::{Opening, PgAuthenticator};
use crate::error::CoreError;
use crate::store::{Notice, i64_of, notify_notice, truncate, unix_now, uuid};

/// The browser sessions in PostgreSQL.
#[derive(Debug)]
pub struct PgWebBackend {
    auth: Arc<PgAuthenticator>,
}

impl PgWebBackend {
    /// The store behind `auth`, the authenticator of `[core.login]`.
    pub fn new(auth: Arc<PgAuthenticator>) -> Self {
        Self { auth }
    }
}

fn broken(e: &CoreError) -> ApiError {
    tracing::error!(event = "web.unavailable", code = e.code(), "{e}");
    ApiError::unavailable()
}

fn u64_of(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

/// Who revokes, and how it is recorded.
struct Revocation<'a> {
    revoked_by: String,
    reason: &'a str,
    event: Event,
    log: &'static str,
}

impl PgWebBackend {
    /// Revokes `session` if it is still open, with its protective record.
    /// `false` if the session does not exist.
    async fn revoke_with(&self, session: Uuid, r: Revocation<'_>) -> Result<bool, CoreError> {
        let pool = self.auth.pool();
        let mut tx = pool.begin().await?;
        let row = sqlx::query!(
            r#"UPDATE login_session
               SET revoked_at = now(), revoked_by = $2, revocation_reason = $3
               WHERE id = $1::text::uuid AND revoked_at IS NULL
               RETURNING user_id::text AS "user!""#,
            session.to_string(),
            r.revoked_by,
            truncate(r.reason).chars().take(256).collect::<String>(),
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
            // Already revoked: nothing changes.
            return Ok(known.is_some());
        };
        notify_notice(&mut tx, &Notice::LoginRevoked(session)).await?;
        let event = r
            .event
            .uuid(field::LOGIN_SESSION, session.to_bytes())
            .uuid(field::USER_ID, uuid(&row.user)?.to_bytes())
            .text(field::REASON, truncate(r.reason));
        // Protective, last statement before the commit.
        let appended = audit::append_protective(&mut tx, event).await;
        tx.commit().await?;
        if let Some(appended) = appended {
            self.auth.recorder().critical(&[appended]);
        }
        tracing::warn!(
            event = r.log,
            login_session = %session,
            reason = r.reason,
            "session du portail révoquée"
        );
        Ok(true)
    }

    async fn find_record(
        &self,
        cookie_sha256: [u8; 32],
    ) -> Result<Option<SessionRecord>, CoreError> {
        let row = sqlx::query!(
            r#"SELECT s.id::text AS "id!", s.user_id::text AS "user!", u.name, u.display_name,
                      u.state = 'active' AS "active!", s.expires_at,
                      s.revoked_at IS NOT NULL AS "revoked!",
                      w.source, w.authenticated_at, w.last_activity_at,
                      ARRAY(SELECT role FROM user_role r WHERE r.user_id = s.user_id
                            ORDER BY role) AS "roles!"
               FROM web_session w
               JOIN login_session s ON s.id = w.login_session_id
               JOIN app_user u ON u.id = s.user_id
               WHERE w.cookie_sha256 = $1"#,
            &cookie_sha256[..],
        )
        .fetch_optional(self.auth.pool())
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let source: IpAddr = row
            .source
            .parse()
            .map_err(|_| CoreError::Database(format!("source invalide : {}", row.source)))?;
        let mut roles: Vec<Role> = row.roles.iter().filter_map(|r| Role::parse(r)).collect();
        roles.sort();
        Ok(Some(SessionRecord {
            login_session: uuid(&row.id)?,
            user: uuid(&row.user)?,
            username: row.name,
            display_name: row.display_name,
            roles,
            source,
            expires_at: u64_of(row.expires_at),
            authenticated_at: u64_of(row.authenticated_at),
            last_activity_at: u64_of(row.last_activity_at),
            revoked: row.revoked,
            user_active: row.active,
        }))
    }

    /// The session just opened or renewed under `cookie_sha256`.
    async fn opened(&self, cookie_sha256: [u8; 32]) -> Result<SessionRecord, ApiError> {
        match self.find_record(cookie_sha256).await {
            Ok(Some(record)) => Ok(record),
            Ok(None) => Err(broken(&CoreError::Database(
                "session du portail introuvable après son ouverture".into(),
            ))),
            Err(e) => Err(broken(&e)),
        }
    }
}

impl WebBackend for PgWebBackend {
    async fn open(
        &self,
        request: SessionRequest,
        cookie_sha256: [u8; 32],
        source: IpAddr,
        session_secs: u64,
        peer: SocketAddr,
    ) -> Result<SessionRecord, ApiError> {
        let start = tokio::time::Instant::now();
        let SessionRequest {
            username,
            password,
            totp,
        } = request;
        let opening = Opening::Web {
            cookie_sha256,
            source,
            session_secs,
        };
        self.auth
            .authenticate(&username, password, &totp, opening, peer, start)
            .await?;
        self.opened(cookie_sha256).await
    }

    async fn reauthenticate(
        &self,
        session: &SessionRecord,
        request: ReauthenticateRequest,
        cookie_sha256: [u8; 32],
        peer: SocketAddr,
    ) -> Result<SessionRecord, ApiError> {
        let start = tokio::time::Instant::now();
        let opening = Opening::Reauthenticate {
            session: session.login_session,
            user: session.user,
            cookie_sha256,
        };
        self.auth
            .authenticate(
                &session.username,
                request.password,
                &request.totp,
                opening,
                peer,
                start,
            )
            .await?;
        self.opened(cookie_sha256).await
    }

    async fn find(&self, cookie_sha256: [u8; 32]) -> Result<Option<SessionRecord>, ApiError> {
        self.find_record(cookie_sha256)
            .await
            .map_err(|e| broken(&e))
    }

    async fn touch(&self, session: Uuid, now: u64) -> Result<(), ApiError> {
        sqlx::query!(
            "UPDATE web_session SET last_activity_at = $2
             WHERE login_session_id = $1::text::uuid AND last_activity_at < $2",
            session.to_string(),
            i64_of(now),
        )
        .execute(self.auth.pool())
        .await
        .map(|_| ())
        .map_err(|e| broken(&e.into()))
    }

    async fn end(
        &self,
        session: &SessionRecord,
        end: SessionEnd,
        peer: SocketAddr,
    ) -> Result<(), ApiError> {
        let user = session.user;
        let core_event = |kind| Event::new(kind, Outcome::Success, ActorKind::Core, CORE_ACTOR);
        let revocation = match end {
            SessionEnd::Logout => Revocation {
                revoked_by: format!("user:{user}"),
                reason: "déconnexion du portail",
                event: Event::new(
                    EventKind::LoginSessionRevoked,
                    Outcome::Success,
                    ActorKind::User,
                    user.to_string(),
                )
                .text(field::CHANNEL, Channel::Web.as_str())
                .text(field::CLIENT_ADDR, peer.to_string()),
                log: "login_session.revoked",
            },
            SessionEnd::Idle => Revocation {
                revoked_by: CORE_ACTOR.into(),
                reason: "inactivité du portail",
                event: core_event(EventKind::WebSessionExpired)
                    .u64(field::EXPIRES_AT, session.last_activity_at)
                    .text(field::CLIENT_ADDR, peer.to_string()),
                log: "web_session.expired",
            },
            SessionEnd::SourceChanged => Revocation {
                revoked_by: CORE_ACTOR.into(),
                reason: "session du portail présentée depuis une autre source",
                event: core_event(EventKind::WebSessionSourceChanged)
                    .text(field::SOURCE, session.source.to_string())
                    .text(field::CLIENT_ADDR, peer.to_string()),
                log: "web_session.source_changed",
            },
        };
        self.revoke_with(session.login_session, revocation)
            .await
            .map(|_| ())
            .map_err(|e| broken(&e))
    }

    async fn login_sessions(&self) -> Result<LoginSessionList, ApiError> {
        let rows = sqlx::query!(
            r#"SELECT s.id::text AS "id!", s.user_id::text AS "user!", u.name, s.channel,
                      s.started_at, s.expires_at
               FROM login_session s JOIN app_user u ON u.id = s.user_id
               WHERE s.revoked_at IS NULL AND s.expires_at > $1
               ORDER BY s.started_at DESC, s.id
               LIMIT $2"#,
            i64_of(unix_now()),
            i64_of(MAX_LISTED_SESSIONS as u64),
        )
        .fetch_all(self.auth.pool())
        .await
        .map_err(|e| broken(&e.into()))?;
        let sessions = rows
            .into_iter()
            .map(|r| {
                Ok(LoginSessionItem {
                    id: uuid(&r.id)?.to_string(),
                    user: uuid(&r.user)?.to_string(),
                    username: r.name,
                    channel: Channel::parse(&r.channel).unwrap_or(Channel::Cli),
                    started_at: u64_of(r.started_at),
                    expires_at: u64_of(r.expires_at),
                })
            })
            .collect::<Result<Vec<_>, CoreError>>()
            .map_err(|e| broken(&e))?;
        Ok(LoginSessionList { sessions })
    }

    async fn revoke(&self, by: &SessionRecord, id: Uuid, reason: &str) -> Result<bool, ApiError> {
        let revocation = Revocation {
            revoked_by: format!("user:{}", by.user),
            reason,
            event: Event::new(
                EventKind::LoginSessionRevoked,
                Outcome::Success,
                ActorKind::User,
                by.user.to_string(),
            )
            .text(field::CHANNEL, Channel::Web.as_str()),
            log: "login_session.revoked",
        };
        self.revoke_with(id, revocation)
            .await
            .map_err(|e| broken(&e))
    }
}
