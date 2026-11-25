//! The grant signing keys (ADR-0004, ADR-0014): the key named by
//! `core.grant_signing_key` signs; the key set pushed to the agents holds it
//! and the keys it replaced until the grants they signed have expired.
//!
//! At start, a key not yet active is activated: the previous active key is
//! retired after the longest grant lifetime plus the clock skew, and the key
//! set gets a new version (`grant.key_activated`, granting). The set pushed
//! changes only then, so that one version always has one content.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ostena_audit::{ActorKind, Event, EventKind, Outcome, field};
use ostena_crypto::p256::VerifyingKey;
use ostena_grant::{Issuer, KeySet, Kid};
use ostena_tunnel::control::{CoreMessage, GrantKey, MAX_KEYS};
use sqlx::PgPool;

use crate::audit::{self, Appended};
use crate::error::CoreError;
use crate::store::{i64_of, unix_now};

/// The signing side and the key set of the core.
pub struct GrantAuthority {
    issuer: Arc<Issuer>,
    keys: KeySet,
    version: u64,
    pushed: Vec<GrantKey>,
}

impl std::fmt::Debug for GrantAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrantAuthority")
            .field("kid", &self.issuer.kid())
            .field("version", &self.version)
            .field("keys", &self.pushed.len())
            .finish_non_exhaustive()
    }
}

/// After this delay, a replaced key no longer verifies: the longest grant
/// lifetime accepted by the agents plus the clock skew.
pub fn retirement_delay() -> u64 {
    let policy = ostena_grant::Policy::default();
    policy.max_ttl_secs + policy.clock_skew_secs
}

impl GrantAuthority {
    /// Activates the key of `issuer` if needed and loads the key set.
    /// Returns the authority and the audit record of an activation, for the
    /// head signer.
    ///
    /// # Errors
    ///
    /// [`CoreError::AuditWrite`] if the activation record cannot be
    /// written (nothing changes), [`CoreError::Database`] otherwise.
    pub async fn load(
        pool: &PgPool,
        issuer: Arc<Issuer>,
    ) -> Result<(Self, Option<Appended>), CoreError> {
        let now = unix_now();
        let public = issuer.verifying_key().to_bytes();
        let kid = issuer.kid().to_bytes();
        let mut tx = pool.begin().await?;
        // One core at a time decides an activation.
        sqlx::query!("LOCK TABLE grant_key IN SHARE ROW EXCLUSIVE MODE")
            .execute(&mut *tx)
            .await?;
        let active = sqlx::query_scalar!(
            r#"SELECT retire_at IS NULL AS "active!" FROM grant_key WHERE kid = $1"#,
            &kid[..]
        )
        .fetch_optional(&mut *tx)
        .await?;
        let mut appended = None;
        if active != Some(true) {
            sqlx::query!(
                "UPDATE grant_key SET retire_at = $2 WHERE retire_at IS NULL AND kid <> $1",
                &kid[..],
                i64_of(now + retirement_delay()),
            )
            .execute(&mut *tx)
            .await?;
            sqlx::query!(
                "INSERT INTO grant_key (kid, p256_public, activated_at) VALUES ($1, $2, $3)
                 ON CONFLICT (kid) DO UPDATE SET activated_at = $3, retire_at = NULL",
                &kid[..],
                &public[..],
                i64_of(now),
            )
            .execute(&mut *tx)
            .await?;
            let version = sqlx::query_scalar!(
                r#"INSERT INTO grant_key_set (id, version) VALUES (true, nextval('push_version'))
                   ON CONFLICT (id) DO UPDATE SET version = nextval('push_version')
                   RETURNING version"#
            )
            .fetch_one(&mut *tx)
            .await?;
            let event = Event::new(
                EventKind::GrantKeyActivated,
                Outcome::Success,
                ActorKind::Core,
                audit::CORE_ACTOR,
            )
            .bytes(field::KID, kid)
            .u64(field::VERSION, u64::try_from(version).unwrap_or(0));
            appended = Some(audit::append(&mut tx, event).await?);
            tracing::info!(event = "grant.key_activated", kid = %issuer.kid(), version);
        }
        let version = sqlx::query_scalar!("SELECT version FROM grant_key_set")
            .fetch_one(&mut *tx)
            .await?;
        // The active key and those it replaced, still verifying.
        let rows = sqlx::query!(
            "SELECT p256_public, retire_at FROM grant_key
             WHERE retire_at IS NULL
                OR retire_at > (SELECT activated_at FROM grant_key WHERE kid = $1)
             ORDER BY retire_at IS NULL DESC, activated_at DESC, kid LIMIT $2",
            &kid[..],
            i64_of(MAX_KEYS as u64),
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit()
            .await
            .map_err(|e| CoreError::AuditWrite(e.to_string()))?;
        let mut keys = KeySet::new();
        let mut pushed = Vec::with_capacity(rows.len());
        for row in rows {
            let bytes: [u8; 65] = row
                .p256_public
                .as_slice()
                .try_into()
                .map_err(|_| CoreError::Database("clé de grant de taille invalide".into()))?;
            let key = VerifyingKey::from_bytes(&bytes)
                .map_err(|_| CoreError::Database("clé de grant hors de la courbe".into()))?;
            let kid = keys.insert(key);
            let retire_at = row.retire_at.and_then(|r| u64::try_from(r).ok());
            if let Some(at) = retire_at {
                keys.retire_at(kid, at)
                    .map_err(|e| CoreError::Database(e.to_string()))?;
            }
            pushed.push(GrantKey {
                kid: kid.to_string(),
                public_key: URL_SAFE_NO_PAD.encode(bytes),
                retire_at,
            });
        }
        Ok((
            Self {
                issuer,
                keys,
                version: u64::try_from(version).unwrap_or(0),
                pushed,
            },
            appended,
        ))
    }

    /// The signing side.
    pub fn issuer(&self) -> &Issuer {
        &self.issuer
    }

    /// The keys that verify grants (with their retirement dates).
    pub fn keys(&self) -> &KeySet {
        &self.keys
    }

    /// The identifier of the signing key.
    pub fn kid(&self) -> Kid {
        self.issuer.kid()
    }

    /// The `key_set` message pushed to every agent.
    pub fn key_set_message(&self) -> CoreMessage {
        CoreMessage::KeySet {
            version: self.version,
            keys: self.pushed.clone(),
        }
    }
}
