//! Local credentials of the users (ADR-0009, amendment of 2026-11-25;
//! ADR-0010): password digest, TOTP secret encrypted at rest, lockout.
//!
//! Administered by `ostena core user …`, in one transaction with the audit
//! record. What gives access (a password, a confirmed enrolment, an
//! unlock) is refused if its record cannot be written; what takes it away
//! (a TOTP secret removed or replaced) commits anyway (ADR-0012).

use ostena_audit::{ActorKind, Event, EventKind, Outcome, field};
use ostena_common::config::TotpAlgorithmSetting;
use ostena_common::secret::{SecretBytes, SecretString};
use ostena_crypto::aead::AeadKey;
use ostena_crypto::password;
use ostena_crypto::totp::{TotpAlgorithm, TotpError, TotpSecret};
use ostena_tunnel::Uuid;
use sqlx::PgPool;

use crate::audit::{self, Tx};
use crate::error::CoreError;
use crate::store::{i64_of, notify_audit, unix_now, uuid};

/// Shortest password, in characters. The TOTP code is the second factor;
/// the lockout bounds online guessing.
pub const MIN_PASSWORD_CHARS: usize = 12;
/// Length of `core.login.totp_key`: 32 random bytes (AES-256).
pub const TOTP_KEY_LEN: usize = 32;

fn invalid(message: impl Into<String>) -> CoreError {
    CoreError::Invalid(message.into())
}

fn admin_event(kind: EventKind, actor: String) -> Event {
    Event::new(kind, Outcome::Success, ActorKind::Admin, actor)
}

/// The HMAC of new enrolments.
pub fn algorithm_of(setting: TotpAlgorithmSetting) -> TotpAlgorithm {
    match setting {
        TotpAlgorithmSetting::Sha1 => TotpAlgorithm::Sha1,
        TotpAlgorithmSetting::Sha256 => TotpAlgorithm::Sha256,
    }
}

fn same(a: &SecretBytes, b: &SecretBytes) -> bool {
    // SECRET-EXPOSURE: two keys compared once at startup, never kept.
    #[expect(clippy::disallowed_methods)]
    let equal = a.expose_secret() == b.expose_secret();
    equal
}

/// `core.login.totp_key`: the AES-256-GCM key of the TOTP secrets in the
/// database. A key of its own: never the bytes of another key of the core.
pub struct TotpKey(AeadKey);

impl std::fmt::Debug for TotpKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpKey")
    }
}

impl TotpKey {
    /// The key from the content of its file or credential: exactly 32
    /// bytes, not one byte repeated, and different from each of `others`
    /// (the private scalars of the other keys of the core: field, bytes).
    ///
    /// # Errors
    ///
    /// [`CoreError::Keys`].
    pub fn from_bytes(
        bytes: &SecretBytes,
        others: &[(&str, SecretBytes)],
    ) -> Result<Self, CoreError> {
        // SECRET-EXPOSURE: length and repetition of the key, checked once.
        #[expect(clippy::disallowed_methods)]
        let raw = bytes.expose_secret();
        if raw.len() != TOTP_KEY_LEN {
            return Err(CoreError::Keys(format!(
                "core.login.totp_key : {TOTP_KEY_LEN} octets aléatoires attendus, {} lus \
                 (head -c 32 /dev/urandom)",
                raw.len()
            )));
        }
        if raw.iter().all(|b| *b == raw[0]) {
            return Err(CoreError::Keys(
                "core.login.totp_key : un seul octet répété, ce n'est pas une clé aléatoire".into(),
            ));
        }
        if let Some((field, _)) = others.iter().find(|(_, other)| same(bytes, other)) {
            return Err(CoreError::Keys(format!(
                "core.login.totp_key : mêmes octets que {field} ; chaque clé du core a un seul usage"
            )));
        }
        AeadKey::from_bytes(bytes)
            .map(Self)
            .map_err(|e| CoreError::Keys(format!("core.login.totp_key : {e}")))
    }

    fn seal(&self, user: Uuid, secret: &TotpSecret) -> Result<Vec<u8>, CoreError> {
        self.0
            .seal(secret.bytes(), &user.to_bytes())
            .map_err(|e| CoreError::Keys(format!("chiffrement du secret TOTP : {e}")))
    }

    /// The TOTP secret of `user`, stored as `sealed`.
    pub(crate) fn open(
        &self,
        user: Uuid,
        algorithm: TotpAlgorithm,
        sealed: &[u8],
    ) -> Result<TotpSecret, CoreError> {
        let bytes = self.0.open(sealed, &user.to_bytes()).map_err(|_| {
            CoreError::Keys(format!(
                "secret TOTP de {user} indéchiffrable : core.login.totp_key a changé ?"
            ))
        })?;
        TotpSecret::from_bytes(algorithm, bytes)
            .map_err(|e| CoreError::Keys(format!("secret TOTP de {user} : {e}")))
    }
}

/// Checks the rules of a new password.
///
/// # Errors
///
/// [`CoreError::Invalid`].
pub fn check_password(password: &SecretString) -> Result<(), CoreError> {
    // SECRET-EXPOSURE: only its length and characters are looked at.
    #[expect(clippy::disallowed_methods)]
    let text = password.expose_secret();
    let chars = text.chars().count();
    if chars < MIN_PASSWORD_CHARS || text.len() > password::MAX_PASSWORD_LEN {
        return Err(invalid(format!(
            "mot de passe : de {MIN_PASSWORD_CHARS} caractères à {} octets",
            password::MAX_PASSWORD_LEN
        )));
    }
    if text.chars().any(char::is_control) {
        return Err(invalid("mot de passe : caractère de contrôle refusé"));
    }
    Ok(())
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

async fn commit_granting(mut tx: Tx<'_>, event: Event) -> Result<(), CoreError> {
    notify_audit(&mut tx).await?;
    audit::append(&mut tx, event).await?;
    tx.commit()
        .await
        .map_err(|e| CoreError::AuditWrite(e.to_string()))
}

async fn commit_protective(mut tx: Tx<'_>, event: Event) -> Result<(), CoreError> {
    notify_audit(&mut tx).await?;
    audit::append_protective(&mut tx, event).await;
    tx.commit().await?;
    Ok(())
}

/// Sets the password of `name` (digest of [`password::hash`]) and clears
/// its failed attempts and lockout.
///
/// # Errors
///
/// [`CoreError::Invalid`] for a password outside the rules,
/// [`CoreError::NotFound`], [`CoreError::AuditWrite`].
pub async fn set_password(
    pool: &PgPool,
    name: &str,
    password: SecretString,
) -> Result<(), CoreError> {
    // A user of a directory (`source/identifier`, ADR-0021) has the
    // password of the directory, checked by a bind.
    if name.contains('/') {
        return Err(CoreError::Invalid(
            "utilisateur d'annuaire : son mot de passe est celui de l'annuaire".into(),
        ));
    }
    check_password(&password)?;
    let digest = tokio::task::spawn_blocking(move || password::hash(&password))
        .await
        .map_err(|e| CoreError::Keys(e.to_string()))?
        .map_err(|e| CoreError::Keys(e.to_string()))?
        .encode();
    let mut tx = pool.begin().await?;
    let actor = audit::admin_actor(&mut tx).await?;
    let id = user_id(&mut tx, name).await?;
    sqlx::query!(
        "INSERT INTO user_credential (user_id, password_hash, password_changed_at)
         VALUES ($1::text::uuid, $2, now())
         ON CONFLICT (user_id) DO UPDATE
         SET password_hash = EXCLUDED.password_hash, password_changed_at = now(),
             failed_attempts = 0, last_failure_at = NULL, locked_until = NULL",
        id.to_string(),
        digest,
    )
    .execute(&mut *tx)
    .await?;
    let event = admin_event(EventKind::UserPasswordSet, actor)
        .uuid(field::USER_ID, id.to_bytes())
        .text(field::NAME, name);
    commit_granting(tx, event).await?;
    tracing::info!(event = "user.password_set", user = %id, name);
    Ok(())
}

/// Generates a new TOTP secret for `name`, pending until
/// [`confirm_totp`]: the login is refused meanwhile. Any previous secret is
/// replaced. Returns the secret, to show once to the administrator.
///
/// # Errors
///
/// [`CoreError::NotFound`], [`CoreError::Keys`], [`CoreError::Database`].
pub async fn enroll_totp(
    pool: &PgPool,
    key: &TotpKey,
    name: &str,
    algorithm: TotpAlgorithm,
) -> Result<TotpSecret, CoreError> {
    let secret = TotpSecret::generate(algorithm).map_err(|e| CoreError::Keys(e.to_string()))?;
    let mut tx = pool.begin().await?;
    let actor = audit::admin_actor(&mut tx).await?;
    let id = user_id(&mut tx, name).await?;
    let sealed = key.seal(id, &secret)?;
    sqlx::query!(
        "INSERT INTO user_credential (user_id, totp_secret, totp_algorithm, totp_pending)
         VALUES ($1::text::uuid, $2, $3, true)
         ON CONFLICT (user_id) DO UPDATE
         SET totp_secret = EXCLUDED.totp_secret, totp_algorithm = EXCLUDED.totp_algorithm,
             totp_pending = true, totp_enrolled_at = NULL, totp_last_step = 0",
        id.to_string(),
        sealed,
        algorithm.as_str(),
    )
    .execute(&mut *tx)
    .await?;
    let event = admin_event(EventKind::UserTotpReset, actor)
        .uuid(field::USER_ID, id.to_bytes())
        .text(field::NAME, name)
        .text(field::HMAC, algorithm.as_str())
        .text(field::REASON, "nouveau secret en attente de confirmation");
    commit_protective(tx, event).await?;
    tracing::warn!(event = "user.totp_reset", user = %id, name, pending = true);
    Ok(secret)
}

/// Confirms the pending TOTP secret of `name` with a `code` of the
/// authenticator application.
///
/// # Errors
///
/// [`CoreError::Invalid`] if no secret is pending or the code is refused,
/// [`CoreError::NotFound`], [`CoreError::AuditWrite`].
pub async fn confirm_totp(
    pool: &PgPool,
    key: &TotpKey,
    name: &str,
    code: &SecretString,
) -> Result<(), CoreError> {
    let mut tx = pool.begin().await?;
    let actor = audit::admin_actor(&mut tx).await?;
    let id = user_id(&mut tx, name).await?;
    let row = sqlx::query!(
        r#"SELECT totp_secret, totp_algorithm, totp_pending FROM user_credential
           WHERE user_id = $1::text::uuid FOR UPDATE"#,
        id.to_string(),
    )
    .fetch_optional(&mut *tx)
    .await?;
    let (Some(sealed), Some(algorithm), true) = row
        .map(|r| (r.totp_secret, r.totp_algorithm, r.totp_pending))
        .unwrap_or_default()
    else {
        return Err(invalid(format!(
            "aucun secret TOTP en attente pour {name} : lancez d'abord totp-enroll"
        )));
    };
    let algorithm = TotpAlgorithm::parse(&algorithm)
        .ok_or_else(|| CoreError::Database(format!("algorithme TOTP inconnu : {algorithm}")))?;
    let secret = key.open(id, algorithm, &sealed)?;
    let step = secret.verify(code, unix_now(), 0).map_err(|e| match e {
        TotpError::Format => invalid("code TOTP : 6 chiffres attendus"),
        _ => invalid("code TOTP refusé : vérifiez l'heure du téléphone et réessayez"),
    })?;
    sqlx::query!(
        "UPDATE user_credential
         SET totp_pending = false, totp_enrolled_at = now(), totp_last_step = $2
         WHERE user_id = $1::text::uuid",
        id.to_string(),
        i64_of(step),
    )
    .execute(&mut *tx)
    .await?;
    let event = admin_event(EventKind::UserTotpEnrolled, actor)
        .uuid(field::USER_ID, id.to_bytes())
        .text(field::NAME, name)
        .text(field::HMAC, algorithm.as_str());
    commit_granting(tx, event).await?;
    tracing::info!(event = "user.totp_enrolled", user = %id, name);
    Ok(())
}

/// Removes the TOTP secret of `name`: the login is refused until a new
/// enrolment is confirmed.
///
/// # Errors
///
/// [`CoreError::NotFound`], [`CoreError::Database`].
pub async fn reset_totp(pool: &PgPool, name: &str) -> Result<(), CoreError> {
    let mut tx = pool.begin().await?;
    let actor = audit::admin_actor(&mut tx).await?;
    let id = user_id(&mut tx, name).await?;
    sqlx::query!(
        "UPDATE user_credential
         SET totp_secret = NULL, totp_algorithm = NULL, totp_pending = false,
             totp_enrolled_at = NULL, totp_last_step = 0
         WHERE user_id = $1::text::uuid",
        id.to_string(),
    )
    .execute(&mut *tx)
    .await?;
    let event = admin_event(EventKind::UserTotpReset, actor)
        .uuid(field::USER_ID, id.to_bytes())
        .text(field::NAME, name)
        .text(field::REASON, "secret retiré");
    commit_protective(tx, event).await?;
    tracing::warn!(event = "user.totp_reset", user = %id, name, pending = false);
    Ok(())
}

/// Clears the failed attempts and the lockout of `name`.
///
/// # Errors
///
/// [`CoreError::NotFound`], [`CoreError::AuditWrite`].
pub async fn unlock(pool: &PgPool, name: &str) -> Result<(), CoreError> {
    let mut tx = pool.begin().await?;
    let actor = audit::admin_actor(&mut tx).await?;
    let id = user_id(&mut tx, name).await?;
    sqlx::query!(
        "UPDATE user_credential SET failed_attempts = 0, last_failure_at = NULL, locked_until = NULL
         WHERE user_id = $1::text::uuid",
        id.to_string(),
    )
    .execute(&mut *tx)
    .await?;
    let event = admin_event(EventKind::UserUnlocked, actor)
        .uuid(field::USER_ID, id.to_bytes())
        .text(field::NAME, name);
    commit_granting(tx, event).await?;
    tracing::info!(event = "user.unlocked", user = %id, name);
    Ok(())
}

/// The credential state of a user, for `ostena core user list`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CredentialState {
    /// A password is set.
    pub password: bool,
    /// A TOTP secret is confirmed.
    pub totp: bool,
    /// A TOTP secret waits for its confirmation.
    pub totp_pending: bool,
    /// End of the lockout, Unix seconds, if locked now.
    pub locked_until: Option<u64>,
}

/// The credential state of `user`.
///
/// # Errors
///
/// [`CoreError::Database`].
pub async fn state(pool: &PgPool, user: Uuid) -> Result<CredentialState, CoreError> {
    let row = sqlx::query!(
        r#"SELECT password_hash IS NOT NULL AS "password!",
                  totp_secret IS NOT NULL AND NOT totp_pending AS "totp!",
                  totp_pending, locked_until
           FROM user_credential WHERE user_id = $1::text::uuid"#,
        user.to_string(),
    )
    .fetch_optional(pool)
    .await?;
    let now = unix_now();
    Ok(
        row.map_or_else(CredentialState::default, |r| CredentialState {
            password: r.password,
            totp: r.totp,
            totp_pending: r.totp_pending,
            locked_until: r
                .locked_until
                .and_then(|t| u64::try_from(t).ok())
                .filter(|t| *t > now),
        }),
    )
}
