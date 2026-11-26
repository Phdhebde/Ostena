//! The PostgreSQL [`Authenticator`] of the login API (ADR-0010, step 1).
//!
//! A login runs in two phases, so that no row lock and no hashing slot is
//! held while another attempt waits:
//!
//! 1. the password digest is read without a lock, and PBKDF2 runs off the
//!    runtime threads, outside any transaction, holding one of the
//!    [`HASHING_SLOTS`] only while it derives; an unknown name or an
//!    account without a digest gets a dummy derivation of the same cost;
//! 2. one transaction then locks, in the canonical order of ADR-0014, the
//!    user row (`FOR SHARE`: a concurrent `disable_user` either waits for
//!    the session to be opened and revokes it, or is seen) and the
//!    credential row (`FOR UPDATE`: concurrent attempts count failures and
//!    consume TOTP steps one after the other). It checks again that the
//!    account is active, not locked, fully enrolled and that its digest is
//!    the one derived against (else refused, not counted), then the TOTP
//!    code (one step of tolerance, a step never accepted twice).
//!
//! A failure counts; at `max_failures` failures, each within
//! `lockout_minutes` of the previous one, the account is locked for
//! `lockout_minutes` (`login.locked`, protective); an older count starts
//! again. A success clears the counters, keeps the step, issues the user
//! certificate, opens the login session and writes `login.succeeded`
//! (granting), all in the same transaction.
//!
//! Every refusal leaves no earlier than [`REFUSAL_FLOOR`] after the request
//! came in: an unknown name, a locked account, a wrong password or code
//! take the same time seen from the client, whatever the work done (a
//! dummy COMMIT would not cover the audit writes and the lock waits).
//!
//! The client always gets `AUTH-E001`; the cause goes to `login.refused`:
//! protective, in the transaction that counts the failure or reads the
//! account, for a known account; best effort for an unknown name, which
//! has no row to lock. A logout is a revocation by the user of their own
//! session, signed by the session key (`login_session.revoked`). A listing
//! of the SSH accesses (`ostena config ssh`) is signed the same way, under
//! another domain, and reads only.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ostena_audit::{ActorKind, Event, EventKind, Outcome, field};
use ostena_common::api::login::{
    self, LoginRequest, LoginResponse, LogoutRequest, SshAccess, SshHostsRequest, SshHostsResponse,
};
use ostena_common::api::web::Channel;
use ostena_common::config::CoreLoginConfig;
use ostena_common::secret::SecretString;
use ostena_crypto::p256::{Signature, VerifyingKey};
use ostena_crypto::password::{self, PasswordHash};
use ostena_crypto::totp::{TotpAlgorithm, TotpError};
use ostena_ssh::cert;
use ostena_tunnel::Uuid;
use sqlx::PgPool;
use tokio::sync::Semaphore;

use crate::api::{ApiCode, ApiError, Authenticator};
use crate::audit::{self, Recorder, Tx};
use crate::credential::TotpKey;
use crate::error::CoreError;
use crate::login as sessions;
use crate::ssh_ca::SshAuthorities;
use crate::store::{Notice, i64_of, notify_notice, truncate, unix_now, uuid};

/// PBKDF2 derivations run at the same time; the others wait. A slot is
/// held only while deriving, never with a transaction open.
pub const HASHING_SLOTS: usize = 4;
/// Least time before any `AUTH-E001` answer, from the arrival of the
/// request: above the cost of PBKDF2, a transaction and an audit write.
pub const REFUSAL_FLOOR: Duration = Duration::from_secs(1);
/// Clock tolerance at the start of a user certificate, seconds.
const CERTIFICATE_SKEW: u64 = 60;

/// Why a login is refused: told to the audit chain only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cause {
    UnknownUser,
    Locked,
    Disabled,
    NotEnrolled,
    Password,
    Code,
    Replayed,
    /// The account changed between the derivation and the transaction.
    Changed,
    /// The stored TOTP secret cannot be opened (another key, altered row).
    Unreadable,
}

impl Cause {
    fn as_str(self) -> &'static str {
        match self {
            Self::UnknownUser => "utilisateur inconnu ou sans identifiants",
            Self::Locked => "compte verrouillé",
            Self::Disabled => "compte désactivé",
            Self::NotEnrolled => "mot de passe ou TOTP non enrôlé",
            Self::Password => "mot de passe faux",
            Self::Code => "code TOTP faux",
            Self::Replayed => "code TOTP déjà utilisé",
            Self::Changed => "compte modifié pendant la vérification du mot de passe",
            Self::Unreadable => "secret TOTP illisible",
        }
    }
}

enum Failure {
    /// Refused; `login.refused` still to be written (best effort).
    Refused(Cause, Option<Uuid>),
    /// Refused; `login.refused` written in the transaction (protective).
    Recorded(Cause, Uuid),
    Broken(CoreError),
}

/// The attempt on a known account, for its refusal records.
struct Attempt<'a> {
    user: Uuid,
    name: &'a str,
    peer: SocketAddr,
    channel: Channel,
}

/// What a successful authentication opens.
pub(crate) enum Opening {
    /// `ostena login`: a login session and its user certificate.
    Cli {
        public: VerifyingKey,
        ttl_secs: Option<u64>,
    },
    /// The portal: a login session of channel `web` and its cookie
    /// (ADR-0020).
    Web {
        cookie_sha256: [u8; 32],
        source: IpAddr,
        session_secs: u64,
    },
    /// The portal, again for an open browser session: a new cookie value.
    Reauthenticate {
        session: Uuid,
        user: Uuid,
        cookie_sha256: [u8; 32],
    },
}

impl Opening {
    fn channel(&self) -> Channel {
        match self {
            Self::Cli { .. } => Channel::Cli,
            Self::Web { .. } | Self::Reauthenticate { .. } => Channel::Web,
        }
    }
}

/// What a successful authentication opened.
pub(crate) enum Opened {
    Cli(LoginResponse),
    /// A browser session opened or authenticated again.
    Web,
}

/// `login.refused` with its cause, for the audit chain only.
fn refusal_event(
    cause: Cause,
    user: Option<Uuid>,
    name: &str,
    peer: SocketAddr,
    channel: Channel,
) -> Event {
    let actor = user.map_or_else(|| peer.ip().to_string(), |u| u.to_string());
    let kind = if user.is_some() {
        ActorKind::User
    } else {
        ActorKind::Peer
    };
    let mut event = Event::new(EventKind::LoginRefused, Outcome::Failure, kind, actor)
        .text(field::NAME, truncate(name))
        .text(field::CODE, ApiCode::InvalidCredentials.as_str())
        .text(field::REASON, cause.as_str())
        .text(field::CLIENT_ADDR, peer.to_string())
        .text(field::CHANNEL, channel.as_str());
    if let Some(user) = user {
        event = event.uuid(field::USER_ID, user.to_bytes());
    }
    event
}

impl From<CoreError> for Failure {
    fn from(e: CoreError) -> Self {
        Self::Broken(e)
    }
}

impl From<sqlx::Error> for Failure {
    fn from(e: sqlx::Error) -> Self {
        Self::Broken(CoreError::from(e))
    }
}

/// The settings of `[core.login]` the decision uses.
#[derive(Debug, Clone)]
struct Settings {
    session_secs: u64,
    max_failures: u32,
    lockout_secs: u64,
    ssh_hosts: Vec<String>,
    ssh_port: u16,
}

/// The authenticator of the running core.
pub struct PgAuthenticator {
    pool: PgPool,
    recorder: Arc<Recorder>,
    ssh: Arc<SshAuthorities>,
    totp: Arc<TotpKey>,
    settings: Settings,
    hashing: Semaphore,
    refusal_floor: Duration,
}

impl std::fmt::Debug for PgAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgAuthenticator")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

fn user_event(kind: EventKind, outcome: Outcome, user: Uuid) -> Event {
    Event::new(kind, outcome, ActorKind::User, user.to_string())
}

/// Runs a derivation off the runtime threads.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Failure> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| Failure::Broken(CoreError::Keys(format!("vérification interrompue : {e}"))))
}

/// Locks the row of the user `name`, shared, before anything else
/// (ADR-0014: `app_user` before `login_session`): a disabling waits for
/// this transaction, and this one sees a disabling committed before it.
/// Returns the user and whether they are active.
async fn lock_user(tx: &mut Tx<'_>, name: &str) -> Result<Option<(Uuid, bool)>, Failure> {
    let row = sqlx::query!(
        r#"SELECT id::text AS "id!", state FROM app_user WHERE name = $1 FOR SHARE"#,
        name,
    )
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|r| Ok((uuid(&r.id)?, r.state == "active")))
        .transpose()
}

/// The stored password digest, sealed TOTP secret and its HMAC, if the
/// user is fully enrolled.
fn enrolled(
    user: Uuid,
    digest: Option<String>,
    sealed: Option<Vec<u8>>,
    algorithm: Option<String>,
    pending: bool,
) -> Option<(PasswordHash, Vec<u8>, TotpAlgorithm)> {
    let (Some(digest), Some(sealed), Some(algorithm), false) = (digest, sealed, algorithm, pending)
    else {
        return None;
    };
    let (Ok(digest), Some(algorithm)) = (
        PasswordHash::parse(&digest),
        TotpAlgorithm::parse(&algorithm),
    ) else {
        tracing::error!(
            event = "login.credential_invalid",
            user = %user,
            "empreinte de mot de passe ou algorithme TOTP illisible"
        );
        return None;
    };
    Some((digest, sealed, algorithm))
}

fn decode_public(text: &str) -> Option<VerifyingKey> {
    let bytes: [u8; 65] = URL_SAFE_NO_PAD.decode(text).ok()?.try_into().ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

impl PgAuthenticator {
    /// The authenticator of `config`, signing with the user authority of
    /// `ssh` and opening the TOTP secrets with `totp`.
    pub fn new(
        pool: PgPool,
        recorder: Arc<Recorder>,
        ssh: Arc<SshAuthorities>,
        totp: Arc<TotpKey>,
        config: &CoreLoginConfig,
    ) -> Self {
        Self {
            pool,
            recorder,
            ssh,
            totp,
            settings: Settings {
                session_secs: u64::from(config.session_max_hours.clamp(1, 8)) * 3600,
                max_failures: config.max_failures.max(1),
                lockout_secs: u64::from(config.lockout_minutes.max(1)) * 60,
                ssh_hosts: config.ssh_hosts.clone(),
                ssh_port: config.ssh_port,
            },
            hashing: Semaphore::new(HASHING_SLOTS),
            refusal_floor: REFUSAL_FLOOR,
        }
    }

    /// Another floor for the refusals than [`REFUSAL_FLOOR`] (tests).
    #[must_use]
    pub fn with_refusal_floor(mut self, floor: Duration) -> Self {
        self.refusal_floor = floor;
        self
    }

    /// `AUTH-E001`, once `refusal_floor` has passed since `start`.
    async fn invalid_credentials(&self, start: tokio::time::Instant) -> ApiError {
        tokio::time::sleep_until(start + self.refusal_floor).await;
        ApiError::invalid_credentials()
    }

    /// Phase 1: PBKDF2 against the digest read without a lock, outside any
    /// transaction, holding a hashing slot only while it derives. Returns
    /// whether the password matches and, if its iterations are too few,
    /// a new digest.
    async fn derive(
        &self,
        password: SecretString,
        stored: Option<PasswordHash>,
    ) -> Result<(bool, Option<String>), Failure> {
        let _slot = self.hashing.acquire().await.map_err(|e| {
            Failure::Broken(CoreError::Keys(format!("vérification indisponible : {e}")))
        })?;
        blocking(move || {
            let Some(stored) = stored else {
                password::dummy_verify(&password);
                return (false, None);
            };
            let ok = password::verify(&password, &stored).is_ok();
            let rehash = (ok && stored.needs_rehash())
                .then(|| password::hash(&password).ok())
                .flatten()
                .map(|p| p.encode());
            (ok, rehash)
        })
        .await
    }

    /// Phase 1: the user and their password digest, read without a lock.
    async fn read_digest(&self, name: &str) -> Result<(Option<Uuid>, Option<String>), Failure> {
        let row = sqlx::query!(
            r#"SELECT u.id::text AS "id!", c.password_hash AS "password_hash?"
               FROM app_user u LEFT JOIN user_credential c ON c.user_id = u.id
               WHERE u.name = $1"#,
            name,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            Some(row) => (Some(uuid(&row.id)?), row.password_hash),
            None => (None, None),
        })
    }

    async fn decide(
        &self,
        username: &str,
        password: SecretString,
        totp: &SecretString,
        opening: Opening,
        peer: SocketAddr,
    ) -> Result<Opened, Failure> {
        let channel = opening.channel();
        // Phase 1, no lock.
        let (user, digest) = self.read_digest(username).await?;
        let stored = digest.as_deref().and_then(|d| PasswordHash::parse(d).ok());
        let (password_ok, rehash) = self.derive(password, stored).await?;
        let Some(user) = user else {
            return Err(Failure::Refused(Cause::UnknownUser, None));
        };
        let attempt = Attempt {
            user,
            name: username,
            peer,
            channel,
        };
        if let Opening::Reauthenticate { user: owner, .. } = &opening
            && *owner != user
        {
            return Err(Failure::Refused(Cause::Changed, Some(user)));
        }

        // Phase 2, the locks in the canonical order, everything checked again.
        let mut tx = self.pool.begin().await?;
        let (locked_user, active) = lock_user(&mut tx, username).await?.unwrap_or((user, false));
        if locked_user != user {
            return Err(self.refuse(tx, Cause::Changed, &attempt).await);
        }
        let row = sqlx::query!(
            r#"SELECT password_hash, totp_secret, totp_algorithm, totp_pending,
                      totp_last_step, failed_attempts, last_failure_at, locked_until
               FROM user_credential WHERE user_id = $1::text::uuid
               FOR UPDATE"#,
            user.to_string(),
        )
        .fetch_optional(&mut *tx)
        .await?;
        let now = unix_now();
        let Some(row) = row else {
            return Err(self.refuse(tx, Cause::NotEnrolled, &attempt).await);
        };
        let locked = row
            .locked_until
            .is_some_and(|t| u64::try_from(t).unwrap_or(0) > now);
        let unchanged = row.password_hash == digest;
        let enrolled = enrolled(
            user,
            row.password_hash,
            row.totp_secret,
            row.totp_algorithm,
            row.totp_pending,
        );
        let early = if locked {
            Some(Cause::Locked)
        } else if !active {
            Some(Cause::Disabled)
        } else if enrolled.is_none() {
            Some(Cause::NotEnrolled)
        } else if !unchanged {
            Some(Cause::Changed)
        } else {
            None
        };
        let (Some((_, sealed, algorithm)), None) = (enrolled, early) else {
            let cause = early.unwrap_or(Cause::NotEnrolled);
            return Err(self.refuse(tx, cause, &attempt).await);
        };
        let last_step = u64::try_from(row.totp_last_step).unwrap_or(0);
        let checked = if password_ok {
            self.check_code(user, algorithm, &sealed, totp, now, last_step)
        } else {
            Err(Cause::Password)
        };
        let step = match checked {
            Ok(step) => step,
            Err(cause) => {
                let failures = self.failures_after(row.failed_attempts, row.last_failure_at, now);
                self.count_failure(tx, &attempt, cause, failures, now)
                    .await?;
                return Err(Failure::Recorded(cause, user));
            }
        };
        self.succeed(
            tx,
            Success {
                user,
                opening,
                step,
                rehash,
                peer,
                now,
            },
        )
        .await
    }

    /// The TOTP code against the sealed secret of `user`: the accepted step.
    fn check_code(
        &self,
        user: Uuid,
        algorithm: TotpAlgorithm,
        sealed: &[u8],
        code: &SecretString,
        now: u64,
        last_step: u64,
    ) -> Result<u64, Cause> {
        match self.totp.open(user, algorithm, sealed) {
            Ok(secret) => secret.verify(code, now, last_step).map_err(|e| match e {
                TotpError::Replayed => Cause::Replayed,
                _ => Cause::Code,
            }),
            // A refusal like the others, counted: never a 503 that would
            // tell this account apart.
            Err(e) => {
                tracing::error!(
                    event = "login.credential_invalid",
                    user = %user,
                    error = %e,
                    "secret TOTP illisible : autre clé des secrets ou ligne altérée"
                );
                Err(Cause::Unreadable)
            }
        }
    }

    /// The count of consecutive failures with one more at `now`: the
    /// previous ones count only within the lockout of the last one.
    fn failures_after(&self, previous: i32, last: Option<i64>, now: u64) -> u32 {
        let recent = last
            .and_then(|t| u64::try_from(t).ok())
            .is_some_and(|t| now < t.saturating_add(self.settings.lockout_secs));
        let previous = if recent {
            u32::try_from(previous).unwrap_or(0)
        } else {
            0
        };
        previous.saturating_add(1)
    }

    /// Refuses a known account without counting a failure: `login.refused`
    /// is written in `tx` (protective), then committed.
    async fn refuse(&self, mut tx: Tx<'_>, cause: Cause, a: &Attempt<'_>) -> Failure {
        let appended = audit::append_protective(
            &mut tx,
            refusal_event(cause, Some(a.user), a.name, a.peer, a.channel),
        )
        .await;
        if let Err(e) = tx.commit().await {
            return Failure::Broken(e.into());
        }
        if let Some(appended) = appended {
            self.recorder.critical(&[appended]);
        }
        Failure::Recorded(cause, a.user)
    }

    /// Counts a failure, and writes `login.refused` in the same
    /// transaction (protective); at the limit, locks the account.
    async fn count_failure(
        &self,
        mut tx: Tx<'_>,
        a: &Attempt<'_>,
        cause: Cause,
        failures: u32,
        now: u64,
    ) -> Result<(), Failure> {
        let (user, name) = (a.user, a.name);
        if failures < self.settings.max_failures {
            sqlx::query!(
                "UPDATE user_credential SET failed_attempts = $2, last_failure_at = $3
                 WHERE user_id = $1::text::uuid",
                user.to_string(),
                i32::try_from(failures).unwrap_or(i32::MAX),
                i64_of(now),
            )
            .execute(&mut *tx)
            .await?;
            let appended = audit::append_protective(
                &mut tx,
                refusal_event(cause, Some(user), name, a.peer, a.channel),
            )
            .await;
            tx.commit().await?;
            if let Some(appended) = appended {
                self.recorder.critical(&[appended]);
            }
            return Ok(());
        }
        let until = now + self.settings.lockout_secs;
        sqlx::query!(
            "UPDATE user_credential
             SET failed_attempts = 0, last_failure_at = NULL, locked_until = $2
             WHERE user_id = $1::text::uuid",
            user.to_string(),
            i64_of(until),
        )
        .execute(&mut *tx)
        .await?;
        // Protective, last statements before the commit.
        let refused = audit::append_protective(
            &mut tx,
            refusal_event(cause, Some(user), name, a.peer, a.channel),
        )
        .await;
        let locked = audit::append_protective(
            &mut tx,
            user_event(EventKind::LoginLocked, Outcome::Failure, user)
                .uuid(field::USER_ID, user.to_bytes())
                .text(field::NAME, name)
                .u64(field::FAILURES, u64::from(failures))
                .u64(field::LOCKED_UNTIL, until)
                .text(field::CHANNEL, a.channel.as_str()),
        )
        .await;
        tx.commit().await?;
        let appended: Vec<_> = refused.into_iter().chain(locked).collect();
        if !appended.is_empty() {
            self.recorder.critical(&appended);
        }
        tracing::warn!(
            event = "login.locked",
            user = %user,
            name,
            locked_until = until,
            "compte verrouillé après trop d'échecs"
        );
        Ok(())
    }

    async fn succeed(&self, mut tx: Tx<'_>, s: Success) -> Result<Opened, Failure> {
        sqlx::query!(
            "UPDATE user_credential
             SET failed_attempts = 0, last_failure_at = NULL, locked_until = NULL,
                 totp_last_step = $2,
                 last_success_at = now(),
                 password_hash = coalesce($3, password_hash),
                 password_changed_at = CASE WHEN $3::text IS NULL THEN password_changed_at
                                            ELSE now() END
             WHERE user_id = $1::text::uuid",
            s.user.to_string(),
            i64_of(s.step),
            s.rehash,
        )
        .execute(&mut *tx)
        .await?;
        let rehashed = s.rehash.is_some();
        match s.opening {
            Opening::Cli { public, ttl_secs } => {
                let granted = Granted {
                    user: s.user,
                    peer: s.peer,
                    now: s.now,
                    rehashed,
                };
                self.open_cli(tx, granted, &public, ttl_secs)
                    .await
                    .map(Opened::Cli)
            }
            Opening::Web {
                cookie_sha256,
                source,
                session_secs,
            } => {
                let web = WebOpening {
                    cookie_sha256,
                    source,
                    session_secs,
                };
                self.open_web(tx, s.user, s.peer, s.now, web, rehashed)
                    .await
            }
            Opening::Reauthenticate {
                session,
                cookie_sha256,
                ..
            } => {
                self.renew_web(tx, s.user, s.peer, s.now, session, cookie_sha256)
                    .await
            }
        }
    }

    /// The browser: opens a login session of channel `web` and its cookie.
    async fn open_web(
        &self,
        mut tx: Tx<'_>,
        user: Uuid,
        peer: SocketAddr,
        now: u64,
        web: WebOpening,
        rehashed: bool,
    ) -> Result<Opened, Failure> {
        let WebOpening {
            cookie_sha256,
            source,
            session_secs,
        } = web;
        let session = sessions::new_session_id()?;
        let expires_at = now + session_secs.clamp(60, sessions::MAX_LOGIN_SECS);
        sessions::open_web_session(&mut tx, session, user, now, expires_at).await?;
        sqlx::query!(
            "INSERT INTO web_session
                 (login_session_id, cookie_sha256, source, authenticated_at,
                  last_activity_at)
             VALUES ($1::text::uuid, $2, $3, $4, $4)",
            session.to_string(),
            &cookie_sha256[..],
            source.to_string(),
            i64_of(now),
        )
        .execute(&mut *tx)
        .await?;
        let event = user_event(EventKind::LoginSucceeded, Outcome::Success, user)
            .uuid(field::USER_ID, user.to_bytes())
            .uuid(field::LOGIN_SESSION, session.to_bytes())
            .u64(field::EXPIRES_AT, expires_at)
            .text(field::CLIENT_ADDR, peer.to_string())
            .text(field::SOURCE, source.to_string())
            .text(field::CHANNEL, Channel::Web.as_str());
        self.commit_granting(tx, event).await?;
        tracing::info!(
            event = "login.succeeded",
            channel = "web",
            user = %user,
            login_session = %session,
            expires_at,
            client_addr = %peer,
            rehashed,
            "session du portail ouverte"
        );
        Ok(Opened::Web)
    }

    /// Re-authentication: a new cookie digest for a live web session.
    async fn renew_web(
        &self,
        mut tx: Tx<'_>,
        user: Uuid,
        peer: SocketAddr,
        now: u64,
        session: Uuid,
        cookie_sha256: [u8; 32],
    ) -> Result<Opened, Failure> {
        let renewed = sqlx::query_scalar!(
            r#"UPDATE web_session w
               SET cookie_sha256 = $2, authenticated_at = $3, last_activity_at = $3
               FROM login_session s
               WHERE w.login_session_id = $1::text::uuid AND s.id = w.login_session_id
                 AND user_id = $4::text::uuid
                 AND s.revoked_at IS NULL AND s.expires_at > $3
               RETURNING true AS "renewed!""#,
            session.to_string(),
            &cookie_sha256[..],
            i64_of(now),
            user.to_string(),
        )
        .fetch_optional(&mut *tx)
        .await?;
        if renewed.is_none() {
            // Revoked or expired meanwhile: nothing is renewed.
            return Err(Failure::Refused(Cause::Changed, Some(user)));
        }
        let event = user_event(EventKind::WebSessionReauthenticated, Outcome::Success, user)
            .uuid(field::USER_ID, user.to_bytes())
            .uuid(field::LOGIN_SESSION, session.to_bytes())
            .text(field::CLIENT_ADDR, peer.to_string());
        self.commit_granting(tx, event).await?;
        tracing::info!(
            event = "web_session.reauthenticated",
            user = %user,
            login_session = %session,
            client_addr = %peer,
            "session du portail authentifiée de nouveau"
        );
        Ok(Opened::Web)
    }

    /// Appends the granting `event` and commits; a failed commit is an audit
    /// failure (nothing is opened).
    async fn commit_granting(&self, mut tx: Tx<'_>, event: Event) -> Result<(), Failure> {
        let appended = audit::append(&mut tx, event).await?;
        tx.commit()
            .await
            .map_err(|e| CoreError::AuditWrite(e.to_string()))?;
        self.recorder.critical(&[appended]);
        Ok(())
    }

    /// `ostena login`: issues the user certificate and opens its session.
    async fn open_cli(
        &self,
        mut tx: Tx<'_>,
        s: Granted,
        public: &VerifyingKey,
        ttl_secs: Option<u64>,
    ) -> Result<LoginResponse, Failure> {
        let session = sessions::new_session_id()?;
        let ttl = ttl_secs
            .unwrap_or(self.settings.session_secs)
            .clamp(60, self.settings.session_secs);
        let valid_after = s.now.saturating_sub(CERTIFICATE_SKEW);
        let valid_before = s.now + ttl;
        let issued = self.ssh.issue_user(
            public,
            s.user.to_bytes(),
            session.to_bytes(),
            valid_after,
            valid_before,
            true,
        )?;
        sessions::open_session(&mut tx, session, s.user, issued.sha256, valid_before).await?;
        let event = user_event(EventKind::LoginSucceeded, Outcome::Success, s.user)
            .uuid(field::USER_ID, s.user.to_bytes())
            .uuid(field::LOGIN_SESSION, session.to_bytes())
            .bytes(field::CERTIFICATE_SHA256, issued.sha256)
            .bytes(field::P256_PUBLIC, public.to_bytes())
            .u64(field::EXPIRES_AT, valid_before)
            .text(field::CLIENT_ADDR, s.peer.to_string())
            .text(field::CHANNEL, Channel::Cli.as_str());
        self.commit_granting(tx, event).await?;
        tracing::info!(
            event = "login.succeeded",
            channel = "cli",
            user = %s.user,
            login_session = %session,
            expires_at = valid_before,
            client_addr = %s.peer,
            rehashed = s.rehashed,
            "session de connexion ouverte"
        );
        Ok(LoginResponse {
            protocol: login::PROTOCOL,
            login_session: session.to_string(),
            user: s.user.to_string(),
            certificate: format!(
                "ecdsa-sha2-nistp256-cert-v01@openssh.com {} {session}",
                STANDARD.encode(&issued.blob)
            ),
            valid_after,
            valid_before,
            host_ca: ostena_ssh::keys::public_line(&self.ssh.host_ca_public(), "ostena-host-ca"),
            ssh_hosts: self.settings.ssh_hosts.clone(),
            ssh_port: self.settings.ssh_port,
        })
    }

    /// Checks a request signed by a session key over `message`: the
    /// certificate of the user authority, the session it names, the
    /// signature, the time. Returns the session, its user and the SHA-256
    /// of the certificate.
    fn signed(
        &self,
        request: &LogoutRequest,
        message: &[u8],
    ) -> Result<(Uuid, Uuid, [u8; 32]), Failure> {
        let refused = || Failure::Refused(Cause::UnknownUser, None);
        let blob = request
            .certificate
            .split(' ')
            .nth(1)
            .and_then(|b| STANDARD.decode(b).ok())
            .ok_or_else(refused)?;
        let parsed = cert::parse(&blob).map_err(|_| refused())?;
        parsed
            .verify(&[self.ssh.user_ca_public()])
            .map_err(|_| refused())?;
        let session = Uuid::parse(&request.login_session).ok_or_else(refused)?;
        let subject = parsed
            .principals
            .first()
            .and_then(|p| Uuid::parse(p))
            .ok_or_else(refused)?;
        if parsed.key_id != request.login_session {
            return Err(Failure::Refused(Cause::UnknownUser, Some(subject)));
        }
        let signature: [u8; 64] = URL_SAFE_NO_PAD
            .decode(&request.signature)
            .ok()
            .and_then(|s| s.try_into().ok())
            .ok_or_else(refused)?;
        parsed
            .public
            .verify(message, &Signature::from_bytes(&signature))
            .map_err(|_| Failure::Refused(Cause::Code, Some(subject)))?;
        if request.issued_at.abs_diff(unix_now()) > login::LOGOUT_SKEW_SECS {
            return Err(Failure::Refused(Cause::Replayed, Some(subject)));
        }
        Ok((session, subject, ostena_crypto::sha256::digest(&blob)))
    }

    async fn revoke(&self, request: &LogoutRequest) -> Result<(), Failure> {
        let (session, subject, sha256) = self.signed(
            request,
            &login::logout_message(&request.login_session, request.issued_at),
        )?;
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query!(
            r#"UPDATE login_session
               SET revoked_at = now(), revoked_by = $3, revocation_reason = 'ostena logout'
               WHERE id = $1::text::uuid AND certificate_sha256 = $2 AND revoked_at IS NULL
               RETURNING user_id::text AS "user!""#,
            session.to_string(),
            &sha256[..],
            format!("user:{subject}"),
        )
        .fetch_optional(&mut *tx)
        .await?;
        if row.is_none() {
            let known = sqlx::query_scalar!(
                r#"SELECT true AS "known!" FROM login_session
                   WHERE id = $1::text::uuid AND certificate_sha256 = $2"#,
                session.to_string(),
                &sha256[..],
            )
            .fetch_optional(&mut *tx)
            .await?;
            // Already revoked: nothing changes.
            return known
                .map(|_| ())
                .ok_or(Failure::Refused(Cause::UnknownUser, Some(subject)));
        }
        notify_notice(&mut tx, &Notice::LoginRevoked(session)).await?;
        // Protective, last statement before the commit.
        let appended = audit::append_protective(
            &mut tx,
            user_event(EventKind::LoginSessionRevoked, Outcome::Success, subject)
                .uuid(field::LOGIN_SESSION, session.to_bytes())
                .uuid(field::USER_ID, subject.to_bytes())
                .text(field::REASON, "ostena logout"),
        )
        .await;
        tx.commit().await?;
        if let Some(appended) = appended {
            self.recorder.critical(&[appended]);
        }
        tracing::info!(
            event = "login_session.revoked",
            login_session = %session,
            user = %subject,
            reason = "ostena logout",
            "session de connexion fermée par l'utilisateur"
        );
        Ok(())
    }

    /// The SSH accesses of the user of a signed listing request: every
    /// valid right of an active user, on an enabled account of an enabled
    /// resource, while the session is valid. Reads only.
    async fn list_hosts(&self, request: &SshHostsRequest) -> Result<SshHostsResponse, Failure> {
        let (session, subject, sha256) = self.signed(
            request,
            &login::ssh_hosts_message(&request.login_session, request.issued_at),
        )?;
        let now = unix_now();
        let mut tx = self.pool.begin().await?;
        let valid = sqlx::query_scalar!(
            r#"SELECT true AS "valid!" FROM login_session s JOIN app_user u ON u.id = s.user_id
               WHERE s.id = $1::text::uuid AND s.certificate_sha256 = $2
                 AND s.user_id = $3::text::uuid AND s.revoked_at IS NULL
                 AND s.expires_at > $4 AND u.state = 'active'"#,
            session.to_string(),
            &sha256[..],
            subject.to_string(),
            i64_of(now),
        )
        .fetch_optional(&mut *tx)
        .await?;
        if valid.is_none() {
            return Err(Failure::Refused(Cause::UnknownUser, Some(subject)));
        }
        let rows = sqlx::query!(
            r#"SELECT r.name AS "resource!", a.name AS "account!",
                      g.ssh_host_names AS "hosts!", max(ar.valid_until) AS "valid_until!"
               FROM access_right ar
               JOIN target_account a ON a.id = ar.account_id
               JOIN resource r ON r.id = a.resource_id
               JOIN gateway_group g ON g.id = r.gateway_group
               WHERE ar.user_id = $1::text::uuid AND ar.protocol = 'ssh'
                 AND ar.revoked_at IS NULL AND ar.valid_from <= $2 AND ar.valid_until > $2
                 AND a.disabled_at IS NULL AND r.disabled_at IS NULL
               GROUP BY r.name, a.name, g.ssh_host_names
               ORDER BY r.name COLLATE "C", a.name COLLATE "C"
               LIMIT $3"#,
            subject.to_string(),
            i64_of(now),
            i64::try_from(login::MAX_SSH_ACCESSES).unwrap_or(i64::MAX) + 1,
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        let total = rows.len();
        let accesses: Vec<SshAccess> = rows
            .into_iter()
            .take(login::MAX_SSH_ACCESSES)
            .filter_map(|row| {
                let host = bastion_host(&row.hosts, &self.settings.ssh_hosts)?;
                (login::is_resource(&row.resource) && login::is_account(&row.account)).then(|| {
                    SshAccess {
                        resource: row.resource,
                        account: row.account,
                        host: host.to_owned(),
                        valid_until: u64::try_from(row.valid_until).unwrap_or(0),
                    }
                })
            })
            .collect();
        tracing::info!(
            event = "login.ssh_hosts_listed",
            login_session = %session,
            user = %subject,
            accesses = accesses.len(),
            omitted = total - accesses.len(),
            "accès SSH listés pour ostena config ssh"
        );
        Ok(SshHostsResponse {
            protocol: login::PROTOCOL,
            ssh_port: self.settings.ssh_port,
            accesses,
        })
    }

    /// Logs a refusal; writes `login.refused` (best effort) unless the
    /// transaction already did.
    fn refused(
        &self,
        cause: Cause,
        user: Option<Uuid>,
        (name, peer, channel): (&str, SocketAddr, Channel),
        recorded: bool,
    ) {
        if !recorded {
            self.recorder
                .emit(refusal_event(cause, user, name, peer, channel));
        }
        tracing::info!(
            event = "login.refused",
            channel = channel.as_str(),
            name = %truncate(name).escape_debug(),
            reason = cause.as_str(),
            client_addr = %peer,
            "connexion refusée"
        );
    }
}

struct Success {
    user: Uuid,
    opening: Opening,
    step: u64,
    rehash: Option<String>,
    peer: SocketAddr,
    now: u64,
}

/// What a browser login opens.
struct WebOpening {
    cookie_sha256: [u8; 32],
    source: IpAddr,
    session_secs: u64,
}

/// A granted `ostena login`, for its certificate.
struct Granted {
    user: Uuid,
    peer: SocketAddr,
    now: u64,
    rehashed: bool,
}

fn broken(e: &CoreError) -> ApiError {
    tracing::error!(event = "login.unavailable", code = e.code(), "{e}");
    ApiError::unavailable()
}

/// Whether `name` matches the `ssh_config` `pattern` (`*` any run, `?` one
/// character), as OpenSSH compares host names: ASCII, case-insensitive.
fn host_matches(pattern: &[u8], name: &[u8]) -> bool {
    match pattern.split_first() {
        None => name.is_empty(),
        Some((b'*', rest)) => (0..=name.len()).any(|i| host_matches(rest, &name[i..])),
        Some((p, rest)) => name.split_first().is_some_and(|(n, tail)| {
            (*p == b'?' || p.eq_ignore_ascii_case(n)) && host_matches(rest, tail)
        }),
    }
}

/// The bastion host to reach a resource through: the first host name of
/// its group, without wildcard, that the patterns of `[core.login]` cover
/// (the `known_hosts` line written by `ostena login` trusts only those).
fn bastion_host<'a>(group_names: &'a [String], patterns: &[String]) -> Option<&'a str> {
    group_names
        .iter()
        .filter(|n| login::is_host_pattern(n) && !n.contains(['*', '?']))
        .find(|n| {
            patterns
                .iter()
                .any(|p| host_matches(p.as_bytes(), n.as_bytes()))
        })
        .map(String::as_str)
}

impl PgAuthenticator {
    /// Checks the password and the TOTP code of `username` and, on
    /// success, opens what `opening` asks for. Every refusal is
    /// `AUTH-E001` after the refusal floor, its cause in the audit chain.
    pub(crate) async fn authenticate(
        &self,
        username: &str,
        password: SecretString,
        totp: &SecretString,
        opening: Opening,
        peer: SocketAddr,
        start: tokio::time::Instant,
    ) -> Result<Opened, ApiError> {
        let channel = opening.channel();
        match self.decide(username, password, totp, opening, peer).await {
            Ok(opened) => Ok(opened),
            Err(Failure::Refused(cause, user)) => {
                self.refused(cause, user, (username, peer, channel), false);
                Err(self.invalid_credentials(start).await)
            }
            Err(Failure::Recorded(cause, user)) => {
                self.refused(cause, Some(user), (username, peer, channel), true);
                Err(self.invalid_credentials(start).await)
            }
            Err(Failure::Broken(e)) => Err(broken(&e)),
        }
    }

    /// The pool of the store.
    pub(crate) fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// The recorder of the audit chain.
    pub(crate) fn recorder(&self) -> &Arc<Recorder> {
        &self.recorder
    }
}

impl Authenticator for PgAuthenticator {
    async fn login(
        &self,
        request: LoginRequest,
        peer: SocketAddr,
    ) -> Result<LoginResponse, ApiError> {
        let start = tokio::time::Instant::now();
        let Some(public) = decode_public(&request.p256_public) else {
            return Err(ApiError::new(
                ApiCode::PublicKey,
                "clé publique refusée : point P-256 non compressé attendu",
            ));
        };
        let LoginRequest {
            username,
            password,
            totp,
            ttl_secs,
            ..
        } = request;
        let opening = Opening::Cli { public, ttl_secs };
        match self
            .authenticate(&username, password, &totp, opening, peer, start)
            .await?
        {
            Opened::Cli(response) => Ok(response),
            Opened::Web => Err(ApiError::unavailable()),
        }
    }

    async fn logout(&self, request: LogoutRequest, peer: SocketAddr) -> Result<(), ApiError> {
        let start = tokio::time::Instant::now();
        let (cause, user) = match self.revoke(&request).await {
            Ok(()) => return Ok(()),
            Err(Failure::Broken(e)) => return Err(broken(&e)),
            Err(Failure::Refused(cause, user)) => (cause, user),
            Err(Failure::Recorded(cause, user)) => (cause, Some(user)),
        };
        tracing::info!(
            event = "login.logout_refused",
            user = ?user.map(|u| u.to_string()),
            reason = cause.as_str(),
            client_addr = %peer,
            "déconnexion refusée"
        );
        Err(self.invalid_credentials(start).await)
    }

    async fn ssh_hosts(
        &self,
        request: SshHostsRequest,
        peer: SocketAddr,
    ) -> Result<SshHostsResponse, ApiError> {
        let start = tokio::time::Instant::now();
        let (cause, user) = match self.list_hosts(&request).await {
            Ok(response) => return Ok(response),
            Err(Failure::Broken(e)) => return Err(broken(&e)),
            Err(Failure::Refused(cause, user)) => (cause, user),
            Err(Failure::Recorded(cause, user)) => (cause, Some(user)),
        };
        tracing::info!(
            event = "login.ssh_hosts_refused",
            user = ?user.map(|u| u.to_string()),
            reason = cause.as_str(),
            client_addr = %peer,
            "liste des accès SSH refusée"
        );
        Err(self.invalid_credentials(start).await)
    }
}

#[cfg(test)]
mod host_tests {
    use super::{bastion_host, host_matches};

    #[test]
    fn host_patterns_match_as_openssh() {
        for (pattern, name, expected) in [
            ("bastion.corp", "bastion.corp", true),
            ("bastion.corp", "BASTION.corp", true),
            ("*.corp", "bastion.corp", true),
            ("*.corp", "corp", false),
            ("bastion?.corp", "bastion1.corp", true),
            ("bastion?.corp", "bastion.corp", false),
            ("b*n*.corp", "bastion.corp", true),
            ("bastion", "bastion.corp", false),
        ] {
            assert_eq!(
                host_matches(pattern.as_bytes(), name.as_bytes()),
                expected,
                "{pattern} {name}"
            );
        }
    }

    #[test]
    fn the_bastion_host_is_a_covered_name_of_the_group() {
        let names = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let group = names(&["gw*.corp", "gw1.other", "gw1.corp"]);
        assert_eq!(bastion_host(&group, &names(&["*.corp"])), Some("gw1.corp"));
        assert_eq!(
            bastion_host(&group, &names(&["gw1.other"])),
            Some("gw1.other")
        );
        assert_eq!(bastion_host(&group, &names(&["*.example"])), None);
        assert_eq!(bastion_host(&[], &names(&["*.corp"])), None);
    }
}
