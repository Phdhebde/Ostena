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
//! The client always gets `AUTH-E001`; the cause goes to `login.refused`
//! (best effort). A logout is a revocation by the user of their own
//! session, signed by the session key (`login_session.revoked`).

use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ostena_audit::{ActorKind, Event, EventKind, Outcome, field};
use ostena_common::api::login::{self, LoginRequest, LoginResponse, LogoutRequest};
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
/// Clock tolerance at the start of a user certificate, seconds.
const CERTIFICATE_SKEW: u64 = 60;
/// Tolerance on the time of a logout request, seconds.
const LOGOUT_SKEW: u64 = 300;

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
    Refused(Cause, Option<Uuid>),
    Broken(CoreError),
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
        }
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
        request: LoginRequest,
        public: VerifyingKey,
        peer: SocketAddr,
    ) -> Result<LoginResponse, Failure> {
        let LoginRequest {
            username,
            password,
            totp,
            ttl_secs,
            ..
        } = request;
        // Phase 1, no lock.
        let (user, digest) = self.read_digest(&username).await?;
        let stored = digest.as_deref().and_then(|d| PasswordHash::parse(d).ok());
        let (password_ok, rehash) = self.derive(password, stored).await?;
        let Some(user) = user else {
            return Err(Failure::Refused(Cause::UnknownUser, None));
        };

        // Phase 2, the locks in the canonical order, everything checked again.
        let mut tx = self.pool.begin().await?;
        let Some((locked_user, active)) = lock_user(&mut tx, &username).await? else {
            return Err(Failure::Refused(Cause::Changed, Some(user)));
        };
        if locked_user != user {
            return Err(Failure::Refused(Cause::Changed, Some(user)));
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
            return Err(Failure::Refused(Cause::NotEnrolled, Some(user)));
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
            return Err(Failure::Refused(
                early.unwrap_or(Cause::NotEnrolled),
                Some(user),
            ));
        };
        let last_step = u64::try_from(row.totp_last_step).unwrap_or(0);
        let checked = if password_ok {
            self.check_code(user, algorithm, &sealed, &totp, now, last_step)
        } else {
            Err(Cause::Password)
        };
        let step = match checked {
            Ok(step) => step,
            Err(cause) => {
                let failures = self.failures_after(row.failed_attempts, row.last_failure_at, now);
                self.count_failure(tx, user, &username, failures, now)
                    .await?;
                return Err(Failure::Refused(cause, Some(user)));
            }
        };
        self.succeed(
            tx,
            Success {
                user,
                public,
                step,
                rehash,
                ttl_secs,
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

    /// Counts a failure; at the limit, locks the account.
    async fn count_failure(
        &self,
        mut tx: Tx<'_>,
        user: Uuid,
        name: &str,
        failures: u32,
        now: u64,
    ) -> Result<(), Failure> {
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
            tx.commit().await?;
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
        let appended = audit::append_protective(
            &mut tx,
            user_event(EventKind::LoginLocked, Outcome::Failure, user)
                .uuid(field::USER_ID, user.to_bytes())
                .text(field::NAME, name)
                .u64(field::FAILURES, u64::from(failures))
                .u64(field::LOCKED_UNTIL, until),
        )
        .await;
        tx.commit().await?;
        if let Some(appended) = appended {
            self.recorder.critical(&[appended]);
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

    async fn succeed(&self, mut tx: Tx<'_>, s: Success) -> Result<LoginResponse, Failure> {
        let session = sessions::new_session_id()?;
        let ttl = s
            .ttl_secs
            .unwrap_or(self.settings.session_secs)
            .clamp(60, self.settings.session_secs);
        let valid_after = s.now.saturating_sub(CERTIFICATE_SKEW);
        let valid_before = s.now + ttl;
        let issued = self.ssh.issue_user(
            &s.public,
            s.user.to_bytes(),
            session.to_bytes(),
            valid_after,
            valid_before,
            true,
        )?;
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
        sessions::open_session(&mut tx, session, s.user, issued.sha256, valid_before).await?;
        let appended = audit::append(
            &mut tx,
            user_event(EventKind::LoginSucceeded, Outcome::Success, s.user)
                .uuid(field::USER_ID, s.user.to_bytes())
                .uuid(field::LOGIN_SESSION, session.to_bytes())
                .bytes(field::CERTIFICATE_SHA256, issued.sha256)
                .bytes(field::P256_PUBLIC, s.public.to_bytes())
                .u64(field::EXPIRES_AT, valid_before)
                .text(field::CLIENT_ADDR, s.peer.to_string()),
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| CoreError::AuditWrite(e.to_string()))?;
        self.recorder.critical(&[appended]);
        tracing::info!(
            event = "login.succeeded",
            user = %s.user,
            login_session = %session,
            expires_at = valid_before,
            client_addr = %s.peer,
            rehashed = s.rehash.is_some(),
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

    async fn revoke(&self, request: &LogoutRequest) -> Result<(), Failure> {
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
            .verify(
                &login::logout_message(&request.login_session, request.issued_at),
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| Failure::Refused(Cause::Code, Some(subject)))?;
        if request.issued_at.abs_diff(unix_now()) > LOGOUT_SKEW {
            return Err(Failure::Refused(Cause::Replayed, Some(subject)));
        }
        let sha256 = ostena_crypto::sha256::digest(&blob);
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

    fn refused(&self, cause: Cause, user: Option<Uuid>, name: &str, peer: SocketAddr) {
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
            .text(field::CLIENT_ADDR, peer.to_string());
        if let Some(user) = user {
            event = event.uuid(field::USER_ID, user.to_bytes());
        }
        self.recorder.emit(event);
        tracing::info!(
            event = "login.refused",
            name = %truncate(name).escape_debug(),
            reason = cause.as_str(),
            client_addr = %peer,
            "connexion refusée"
        );
    }
}

struct Success {
    user: Uuid,
    public: VerifyingKey,
    step: u64,
    rehash: Option<String>,
    ttl_secs: Option<u64>,
    peer: SocketAddr,
    now: u64,
}

fn broken(e: &CoreError) -> ApiError {
    tracing::error!(event = "login.unavailable", code = e.code(), "{e}");
    ApiError::unavailable()
}

impl Authenticator for PgAuthenticator {
    async fn login(
        &self,
        request: LoginRequest,
        peer: SocketAddr,
    ) -> Result<LoginResponse, ApiError> {
        let Some(public) = decode_public(&request.p256_public) else {
            return Err(ApiError::new(
                ApiCode::PublicKey,
                "clé publique refusée : point P-256 non compressé attendu",
            ));
        };
        let name = request.username.clone();
        match self.decide(request, public, peer).await {
            Ok(response) => Ok(response),
            Err(Failure::Refused(cause, user)) => {
                self.refused(cause, user, &name, peer);
                Err(ApiError::invalid_credentials())
            }
            Err(Failure::Broken(e)) => Err(broken(&e)),
        }
    }

    async fn logout(&self, request: LogoutRequest, peer: SocketAddr) -> Result<(), ApiError> {
        match self.revoke(&request).await {
            Ok(()) => Ok(()),
            Err(Failure::Refused(cause, user)) => {
                tracing::info!(
                    event = "login.logout_refused",
                    user = ?user.map(|u| u.to_string()),
                    reason = cause.as_str(),
                    client_addr = %peer,
                    "déconnexion refusée"
                );
                Err(ApiError::invalid_credentials())
            }
            Err(Failure::Broken(e)) => Err(broken(&e)),
        }
    }
}
