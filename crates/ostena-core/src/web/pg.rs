//! The PostgreSQL store of the browser sessions (ADR-0020), on top of the
//! authenticator of `ostena login` (same passwords, TOTP, lockout and
//! audit records, channel `web`).
//!
//! Every revocation (logout, idle time, source change, administrator) is
//! protective: it commits even if its audit record cannot be written, and
//! the running core tells the agents concerned, as for `ostena login`.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use hyper::StatusCode;
use ostena_audit::{ActorKind, Event, EventKind, Outcome, field};
use ostena_common::api::web::{
    AccessGrant, AccessProtocol, AccessRequest, Channel, LoginSessionItem, LoginSessionList,
    MAX_LISTED_SESSIONS, ReauthenticateRequest, Role, SessionRequest,
};
use ostena_tunnel::{CoreTunnel, Uuid};

use super::WebError;
use super::gateway::{self, GatewayStream, Opening as StreamOpening, Relayed, Relays};
use super::session::{SessionEnd, SessionRecord, WebBackend};
use crate::access::{self, Refusal, WebRequest};
use crate::api::ApiError;
use crate::audit::{self, CORE_ACTOR};
use crate::authn::{Opening, PgAuthenticator};
use crate::error::CoreError;
use crate::grant_keys::GrantAuthority;
use crate::policy::Policies;
use crate::rate;
use crate::store::{Notice, i64_of, notify_notice, truncate, unix_now, uuid};

/// The agents connected to the core, as the web listener sees them; the
/// running core implements it on its tunnels.
pub trait Agents: Send + Sync + 'static {
    /// A connected agent of `group`, the least busy; `None` if none is.
    fn pick(&self, group: Uuid) -> Option<Uuid>;

    /// The tunnel of `agent`, if it is connected.
    fn tunnel(&self, agent: Uuid) -> Option<Arc<CoreTunnel>>;
}

/// What the access decisions of the portal need (ADR-0020, § 4).
pub struct WebAccess {
    /// The grant signing key of the core.
    pub grants: Arc<GrantAuthority>,
    /// The access decision point (ADR-0022).
    pub policies: Arc<Policies>,
    /// The connected agents.
    pub agents: Arc<dyn Agents>,
    /// The gateway sessions, cut by the revocation of their login session.
    pub relays: Arc<Relays>,
}

impl std::fmt::Debug for WebAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebAccess").finish_non_exhaustive()
    }
}

/// Access requests of one browser session: 10 at once, then one every
/// six seconds.
pub const ACCESS_REQUESTS: rate::Rate = rate::Rate {
    burst: 10,
    refill: std::time::Duration::from_secs(6),
};

/// The browser sessions in PostgreSQL.
#[derive(Debug)]
pub struct PgWebBackend {
    auth: Arc<PgAuthenticator>,
    access: Option<WebAccess>,
    requests: rate::Limiter,
}

impl PgWebBackend {
    /// The store behind `auth`, the authenticator of `[core.login]`,
    /// without access decision (`POST /api/v1/access` answers `GTW-E003`).
    pub fn new(auth: Arc<PgAuthenticator>) -> Self {
        Self {
            auth,
            access: None,
            requests: rate::Limiter::new(ACCESS_REQUESTS),
        }
    }

    /// The same store, deciding the accesses of the portal with `access`.
    #[must_use]
    pub fn with_access(mut self, access: WebAccess) -> Self {
        self.access = Some(access);
        self
    }
}

/// The answer to a refused gateway session: the code and its generic
/// label, the cause in the audit chain only.
fn gateway_refused(code: &'static str) -> WebError {
    let (status, label) = match code {
        access::NO_AGENT => (StatusCode::SERVICE_UNAVAILABLE, access::label(code)),
        "GTW-E006" => (
            StatusCode::FORBIDDEN,
            "protocole non servi dans le navigateur",
        ),
        c if c.starts_with("GTW-") => (StatusCode::FORBIDDEN, "grant refusé"),
        _ => (StatusCode::SERVICE_UNAVAILABLE, "service indisponible"),
    };
    WebError::refused(status, code, label)
}

/// The answer to a refused access: the stable code and its generic label;
/// the reason goes to the audit chain only.
fn access_refused(refusal: &Refusal) -> WebError {
    let status = match refusal.code {
        access::NO_AGENT => StatusCode::SERVICE_UNAVAILABLE,
        access::RATE_LIMITED => StatusCode::TOO_MANY_REQUESTS,
        code if code.starts_with("ACC-") || code.starts_with("INV-") => StatusCode::FORBIDDEN,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };
    WebError::refused(status, refusal.code, access::label(refusal.code))
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

    async fn sweep(&self, now: u64, idle_secs: u64) -> Result<usize, ApiError> {
        let idle = sqlx::query!(
            r#"SELECT w.login_session_id::text AS "id!", w.last_activity_at
               FROM web_session w JOIN login_session l ON l.id = w.login_session_id
               WHERE l.revoked_at IS NULL AND w.last_activity_at < $1
               ORDER BY w.last_activity_at LIMIT 256"#,
            i64_of(now.saturating_sub(idle_secs)),
        )
        .fetch_all(self.auth.pool())
        .await
        .map_err(|e| broken(&e.into()))?;
        let mut revoked = 0;
        for row in idle {
            let id = uuid(&row.id).map_err(|e| broken(&e))?;
            let revocation = Revocation {
                revoked_by: CORE_ACTOR.into(),
                reason: "inactivité du portail",
                event: Event::new(
                    EventKind::WebSessionExpired,
                    Outcome::Success,
                    ActorKind::Core,
                    CORE_ACTOR,
                )
                .u64(field::EXPIRES_AT, u64_of(row.last_activity_at)),
                log: "web_session.expired",
            };
            if self
                .revoke_with(id, revocation)
                .await
                .map_err(|e| broken(&e))?
            {
                revoked += 1;
            }
        }
        Ok(revoked)
    }

    async fn open_gateway(
        &self,
        session: &SessionRecord,
        grant: &str,
        peer: SocketAddr,
    ) -> Result<GatewayStream, WebError> {
        let Some(web) = &self.access else {
            return Err(gateway_refused(access::NO_AGENT));
        };
        let client = peer.to_string();
        let by = access::Presenter {
            subject: session.user,
            login_session: session.login_session,
            client_address: &client,
        };
        let refuse = |refusal: Refusal| {
            tracing::warn!(
                event = "gateway.refused",
                login_session = %session.login_session,
                code = refusal.code,
                "{}",
                refusal.reason
            );
            self.auth
                .recorder()
                .emit(access::gateway_refused_event(&by, &refusal));
            gateway_refused(refusal.code)
        };
        // Watched before the grant is presented: a revocation in between
        // still cuts the session.
        let cut = web.relays.watch(session.login_session);
        let presented =
            match access::present_web_grant(self.auth.pool(), &web.grants, &by, grant, unix_now())
                .await
            {
                Ok(presented) => presented,
                Err(refusal) => return Err(refuse(refusal)),
            };
        self.auth.recorder().critical(&[presented.appended]);
        // The agent chosen at issue, or another agent of the group.
        let tunnel = web
            .agents
            .tunnel(presented.agent)
            .map(|t| (presented.agent, t))
            .or_else(|| {
                let agent = web.agents.pick(presented.group)?;
                web.agents.tunnel(agent).map(|t| (agent, t))
            });
        let Some((agent, tunnel)) = tunnel else {
            return Err(refuse(Refusal {
                code: access::NO_AGENT,
                reason: format!("aucun agent du groupe {} connecté", presented.group),
                pdp_version: None,
            }));
        };
        match gateway::open_stream(&tunnel, presented.jti, grant).await {
            Ok(StreamOpening::Opened(id, channel)) => {
                tracing::info!(
                    event = "gateway.opened",
                    login_session = %session.login_session,
                    session = %id,
                    jti = %presented.jti,
                    agent = %agent,
                );
                Ok(GatewayStream {
                    session: id,
                    jti: presented.jti,
                    agent,
                    channel,
                    cut,
                })
            }
            Ok(StreamOpening::Refused(code)) => {
                let known = if code == "GTW-E006" {
                    "GTW-E006"
                } else {
                    access::GATEWAY_GRANT
                };
                Err(refuse(Refusal {
                    code: known,
                    reason: format!("refus de l'agent {agent} : {code}"),
                    pdp_version: None,
                }))
            }
            Err(e) => Err(refuse(Refusal {
                code: access::NO_AGENT,
                reason: format!("flux navigateur vers l'agent {agent} : {e}"),
                pdp_version: None,
            })),
        }
    }

    async fn gateway_closed(
        &self,
        session: &SessionRecord,
        peer: SocketAddr,
        opened: (Uuid, Uuid),
        ended: &Relayed,
    ) {
        let client = peer.to_string();
        let by = access::Presenter {
            subject: session.user,
            login_session: session.login_session,
            client_address: &client,
        };
        tracing::info!(
            event = "gateway.closed",
            login_session = %session.login_session,
            session = %opened.0,
            code = ended.code,
            bytes_from_browser = ended.from_browser,
            bytes_to_browser = ended.to_browser,
            "{}",
            ended.reason
        );
        self.auth.recorder().emit(access::gateway_closed_event(
            &by,
            opened.0,
            opened.1,
            ended.code.unwrap_or(ended.reason),
            ended.from_browser,
            ended.to_browser,
        ));
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

    async fn grant_access(
        &self,
        session: &SessionRecord,
        request: AccessRequest,
        peer: SocketAddr,
    ) -> Result<AccessGrant, WebError> {
        let request_of = WebRequest {
            subject: session.user,
            login_session: session.login_session,
            account: request.account,
            resource: request.resource,
            client_address: peer.to_string(),
        };
        let decided = match &self.access {
            None => Err(Refusal {
                code: access::NO_AGENT,
                reason: "décision d'accès du portail non configurée".into(),
                pdp_version: None,
            }),
            Some(_)
                if self
                    .requests
                    .check(session.login_session, std::time::Instant::now())
                    != rate::Decision::Allowed =>
            {
                Err(Refusal {
                    code: access::RATE_LIMITED,
                    reason: "demandes d'accès de la session au-delà de la limite".into(),
                    pdp_version: None,
                })
            }
            Some(web) => {
                access::web_grant(
                    self.auth.pool(),
                    &web.policies,
                    &web.grants,
                    &request_of,
                    |group| web.agents.pick(group),
                    unix_now(),
                )
                .await
            }
        };
        match decided {
            Ok(issued) => {
                self.auth.recorder().critical(&[issued.appended]);
                tracing::info!(
                    event = "access.web_granted",
                    login_session = %session.login_session,
                    jti = %issued.content.jti,
                    agent = %issued.agent,
                );
                Ok(AccessGrant {
                    grant: issued.grant,
                    resource: request_of.resource,
                    account: request_of.account,
                    protocol: AccessProtocol::Ssh,
                    expires_at: issued.content.expires_at,
                    max_session_secs: issued.content.claims.max_session_secs,
                })
            }
            Err(refusal) => {
                tracing::warn!(
                    event = "access.web_refused",
                    login_session = %session.login_session,
                    code = refusal.code,
                    "{}",
                    refusal.reason
                );
                if refusal.code != access::RATE_LIMITED {
                    self.auth
                        .recorder()
                        .emit(access::web_refused_event(&request_of, &refusal));
                }
                Err(access_refused(&refusal))
            }
        }
    }
}
