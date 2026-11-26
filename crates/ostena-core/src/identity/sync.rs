//! What the directories say, applied to the users of the core (ADR-0021).
//!
//! Each change of a user is one transaction with its audit records, in the
//! lock order of ADR-0014 (the user, then their login sessions):
//!
//! - **created** (`identity.user_provisioned`, granting): an entry of the
//!   filter, admitted by the group rules, not yet known;
//! - **updated**: rename, display name, DN (no record: the next
//!   `identity.sync_completed` counts it);
//! - **disabled** (`user.disabled`, protective): disabled, expired or
//!   locked in the directory, deleted from it (or out of its filter), or out
//!   of every ruled group when `require_group` is set; their open login
//!   sessions are revoked (`login_session.revoked`, protective) and the
//!   running core tells the agents, which cut the sessions;
//! - **enabled again** (`identity.user_reenabled`, granting): only a user
//!   that the source itself disabled (`directory_disabled`); a disabling by
//!   an administrator stays;
//! - **password changed** in the directory after a login session opened:
//!   that session is revoked (`login_session.revoked`).
//!
//! Group memberships given by the rules are kept apart, in their own
//! transaction (`user_group.member_added` granting, `user_group.member_removed`
//! protective).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use ostena_audit::{ActorKind, Event, EventKind, Outcome, field};
use ostena_common::secret::SecretString;
use ostena_tunnel::Uuid;
use sqlx::PgPool;
use tokio::task::JoinHandle;

use super::Directories;
use super::directory::{DirUser, DirectorySource, IdentityError};
use crate::audit::{self, Appended, Recorder, Tx};
use crate::error::CoreError;
use crate::store::{Notice, i64_of, notify_audit, notify_notice, truncate, unix_now, uuid};

/// What a login learnt from its directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryLogin {
    /// The user in the core, if the directory has them and admits them.
    pub user: Option<Uuid>,
    /// Whether the password was accepted by a bind as the user.
    pub password_ok: bool,
}

/// Counts of one pass over a source.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Report {
    /// Users read from the directory.
    pub seen: usize,
    /// Users created.
    pub created: usize,
    /// Users updated or enabled again.
    pub updated: usize,
    /// Users disabled.
    pub disabled: usize,
    /// Login sessions revoked.
    pub revoked_sessions: usize,
    /// Entries skipped (identifier, login name, name taken).
    pub skipped: usize,
}

/// What [`Identity::apply`] did to one user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Change {
    /// Not admitted and unknown: nothing done.
    Ignored,
    /// Its name is taken by another user of the source.
    Conflict,
    Created(Uuid),
    Unchanged(Uuid),
    Updated(Uuid),
    Disabled(Uuid, usize),
    Reenabled(Uuid),
    /// Sessions revoked after a password change.
    Revoked(Uuid, usize),
}

impl Change {
    fn user(self) -> Option<Uuid> {
        match self {
            Self::Ignored | Self::Conflict => None,
            Self::Created(u)
            | Self::Unchanged(u)
            | Self::Updated(u)
            | Self::Disabled(u, _)
            | Self::Reenabled(u)
            | Self::Revoked(u, _) => Some(u),
        }
    }

    fn count(self, report: &mut Report) {
        match self {
            Self::Ignored | Self::Unchanged(_) => {}
            Self::Conflict => report.skipped += 1,
            Self::Created(_) => report.created += 1,
            Self::Updated(_) | Self::Reenabled(_) => report.updated += 1,
            Self::Disabled(_, n) => {
                report.disabled += 1;
                report.revoked_sessions += n;
            }
            Self::Revoked(_, n) => report.revoked_sessions += n,
        }
    }
}

fn core_event(kind: EventKind, outcome: Outcome, source: &str) -> Event {
    Event::new(kind, outcome, ActorKind::Core, audit::CORE_ACTOR)
        .text(field::IDENTITY_SOURCE, source)
}

/// The reason written when the source no longer has an entry.
const ABSENT: &str = "absent de l'annuaire";
/// The reason written when no ruled group admits the user any more.
const OUT_OF_GROUPS: &str = "hors des groupes autorisés de la source";
/// The reason of the revocations after a password change.
const PASSWORD_CHANGED: &str = "mot de passe changé dans l'annuaire";

/// The identity sources and the database they feed.
#[derive(Debug)]
pub struct Identity {
    directories: Arc<Directories>,
    pool: PgPool,
    recorder: Arc<Recorder>,
}

impl Identity {
    /// The sources of `directories`, applied to `pool`.
    pub fn new(directories: Arc<Directories>, pool: PgPool, recorder: Arc<Recorder>) -> Self {
        Self {
            directories,
            pool,
            recorder,
        }
    }

    /// The sources and the routing of login names.
    pub fn directories(&self) -> &Directories {
        &self.directories
    }

    /// Records that `source` answered or not (`identity.source_restored`,
    /// `identity.source_unavailable` on a change only).
    fn reached<T>(
        &self,
        source: &DirectorySource,
        result: Result<T, IdentityError>,
    ) -> Result<T, CoreError> {
        match result {
            Ok(value) => {
                if source.set_available(true) {
                    self.recorder.emit(core_event(
                        EventKind::IdentitySourceRestored,
                        Outcome::Success,
                        &source.name,
                    ));
                    tracing::info!(event = "identity.source_restored", source = %source.name, "source d'identités de nouveau joignable");
                }
                Ok(value)
            }
            Err(e) => {
                if source.set_available(false) {
                    self.recorder.emit(
                        core_event(
                            EventKind::IdentitySourceUnavailable,
                            Outcome::Failure,
                            &source.name,
                        )
                        .text(field::CODE, e.code())
                        .text(field::REASON, truncate(&e.to_string())),
                    );
                }
                tracing::error!(event = "identity.source_unavailable", source = %source.name, code = e.code(), "{e}");
                Err(CoreError::Directory(e.to_string()))
            }
        }
    }

    /// The directory part of a login on `source`: the user is read (and
    /// created, updated or disabled in the core as the directory says),
    /// then the password is checked by a bind as the user.
    ///
    /// # Errors
    ///
    /// [`CoreError::Directory`] if the source cannot be read,
    /// [`CoreError::Database`], [`CoreError::AuditWrite`].
    pub async fn authenticate(
        &self,
        source: &DirectorySource,
        login: &str,
        password: &SecretString,
    ) -> Result<DirectoryLogin, CoreError> {
        let now = unix_now();
        let found = self.reached(
            source,
            source.authenticate(login, Some(password), now).await,
        )?;
        let Some((user, password_ok)) = found else {
            return Ok(DirectoryLogin {
                user: None,
                password_ok: false,
            });
        };
        let change = self.apply(source, &user, now).await?;
        if let Some(id) = change.user() {
            self.set_groups(source, id, &user.groups).await?;
        }
        Ok(DirectoryLogin {
            user: change.user(),
            password_ok,
        })
    }

    /// A full pass over `source`: every user of its filter, then the users
    /// of the core it no longer has.
    ///
    /// # Errors
    ///
    /// [`CoreError::Directory`] if the source cannot be read (nothing is
    /// disabled then), [`CoreError::Database`].
    pub async fn sync(&self, source: &DirectorySource) -> Result<Report, CoreError> {
        let started = Instant::now();
        let now = unix_now();
        let listing = self.reached(source, source.list(now).await)?;
        let mut report = Report {
            seen: listing.users.len(),
            skipped: listing.skipped,
            ..Report::default()
        };
        let mut seen = HashSet::with_capacity(listing.users.len());
        for user in &listing.users {
            seen.insert(user.external_id.as_str());
            let change = self.apply(source, user, now).await?;
            change.count(&mut report);
            if let Some(id) = change.user() {
                self.set_groups(source, id, &user.groups).await?;
            }
        }
        let known = sqlx::query!(
            r#"SELECT external_id AS "external_id!" FROM app_user
               WHERE source = $1 AND state = 'active' AND external_id IS NOT NULL"#,
            source.name,
        )
        .fetch_all(&self.pool)
        .await?;
        for row in known {
            if !seen.contains(row.external_id.as_str()) {
                self.absent(source, &row.external_id)
                    .await?
                    .count(&mut report);
            }
        }
        let elapsed = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.recorder.emit(
            core_event(
                EventKind::IdentitySyncCompleted,
                Outcome::Success,
                &source.name,
            )
            .u64(field::USERS_SEEN, report.seen as u64)
            .u64(field::USERS_CREATED, report.created as u64)
            .u64(field::USERS_UPDATED, report.updated as u64)
            .u64(field::USERS_DISABLED, report.disabled as u64)
            .u64(field::REVOKED_SESSIONS, report.revoked_sessions as u64)
            .u64(field::DURATION_MS, elapsed),
        );
        tracing::info!(
            event = "identity.sync_completed",
            source = %source.name,
            seen = report.seen,
            created = report.created,
            updated = report.updated,
            disabled = report.disabled,
            skipped = report.skipped,
            duration_ms = elapsed,
            "source d'identités synchronisée"
        );
        Ok(report)
    }

    /// The check of the users of `source` that hold an open login session:
    /// disabled, deleted, password changed, out of the allowed groups.
    ///
    /// # Errors
    ///
    /// [`CoreError::Directory`] if the source cannot be read,
    /// [`CoreError::Database`].
    pub async fn check(&self, source: &DirectorySource) -> Result<Report, CoreError> {
        let now = unix_now();
        let ids = sqlx::query_scalar!(
            r#"SELECT DISTINCT u.external_id AS "external_id!" FROM app_user u
               JOIN login_session s ON s.user_id = u.id
               WHERE u.source = $1 AND u.state = 'active' AND u.external_id IS NOT NULL
                 AND s.revoked_at IS NULL AND s.expires_at > $2"#,
            source.name,
            i64_of(now),
        )
        .fetch_all(&self.pool)
        .await?;
        let mut report = Report::default();
        if ids.is_empty() {
            return Ok(report);
        }
        let users = self.reached(source, source.lookup(&ids, now).await)?;
        report.seen = users.len();
        let mut seen = HashSet::with_capacity(users.len());
        for user in &users {
            seen.insert(user.external_id.as_str());
            let change = self.apply(source, user, now).await?;
            change.count(&mut report);
            if let Some(id) = change.user() {
                self.set_groups(source, id, &user.groups).await?;
            }
        }
        for id in &ids {
            if !seen.contains(id.as_str()) {
                self.absent(source, id).await?.count(&mut report);
            }
        }
        Ok(report)
    }

    /// Applies what the directory says of `user` to the core.
    async fn apply(
        &self,
        source: &DirectorySource,
        user: &DirUser,
        now: u64,
    ) -> Result<Change, CoreError> {
        let name = format!("{}/{}", source.name, user.login);
        let admitted = source.admits(user);
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query!(
            r#"SELECT id::text AS "id!", name, display_name, directory_dn AS "dn!", state,
                      directory_disabled
               FROM app_user WHERE source = $1 AND external_id = $2 FOR UPDATE"#,
            source.name,
            user.external_id,
        )
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            if !admitted || user.disabled.is_some() {
                return Ok(Change::Ignored);
            }
            return self.create(tx, source, user, &name, now).await;
        };
        let id = uuid(&row.id)?;
        let renamed = row.name != name;
        let changed = renamed || row.display_name != user.display_name || row.dn != user.dn;
        let updated = sqlx::query!(
            "UPDATE app_user SET name = $2, display_name = $3, directory_dn = $4, synced_at = $5
             WHERE id = $1::text::uuid",
            id.to_string(),
            name,
            user.display_name,
            user.dn,
            i64_of(now),
        )
        .execute(&mut *tx)
        .await;
        if let Err(e) = updated {
            if is_unique_violation(&e) {
                tracing::warn!(
                    event = "identity.name_conflict",
                    source = %source.name,
                    user = %id,
                    name = %name,
                    "nom déjà pris par un autre utilisateur de la source : renommage différé"
                );
                return Ok(Change::Conflict);
            }
            return Err(e.into());
        }
        let refused = user.disabled.or((!admitted).then_some(OUT_OF_GROUPS));
        let active = row.state == "active";
        let mut appended = Vec::new();
        let change = match (active, refused) {
            (true, Some(reason)) => {
                let revoked =
                    disable(&mut tx, id, &name, &source.name, reason, &mut appended).await?;
                Change::Disabled(id, revoked)
            }
            (false, None) if row.directory_disabled => {
                appended.push(reenable(&mut tx, id, &name, &source.name).await?);
                Change::Reenabled(id)
            }
            (true, None) => match user.password_changed_at {
                Some(changed_at) => {
                    let revoked = revoke(
                        &mut tx,
                        id,
                        &source.name,
                        PASSWORD_CHANGED,
                        Some(changed_at),
                        now,
                        &mut appended,
                    )
                    .await?;
                    if revoked > 0 {
                        Change::Revoked(id, revoked)
                    } else if changed {
                        Change::Updated(id)
                    } else {
                        Change::Unchanged(id)
                    }
                }
                None if changed => Change::Updated(id),
                None => Change::Unchanged(id),
            },
            (false, _) => Change::Unchanged(id),
        };
        tx.commit().await?;
        if !appended.is_empty() {
            self.recorder.critical(&appended);
        }
        if let Change::Disabled(_, revoked) = change {
            tracing::warn!(
                event = "user.disabled",
                user = %id,
                source = %source.name,
                reason = refused.unwrap_or_default(),
                revoked_sessions = revoked,
                "utilisateur désactivé par sa source d'identités"
            );
        }
        Ok(change)
    }

    async fn create(
        &self,
        mut tx: Tx<'_>,
        source: &DirectorySource,
        user: &DirUser,
        name: &str,
        now: u64,
    ) -> Result<Change, CoreError> {
        let id = Uuid::random().map_err(|e| CoreError::Keys(format!("aléa : {e}")))?;
        let inserted = sqlx::query!(
            "INSERT INTO app_user (id, name, display_name, source, external_id, directory_dn,
                                   synced_at)
             VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7)",
            id.to_string(),
            name,
            user.display_name,
            source.name,
            user.external_id,
            user.dn,
            i64_of(now),
        )
        .execute(&mut *tx)
        .await;
        if let Err(e) = inserted {
            if is_unique_violation(&e) {
                tracing::warn!(
                    event = "identity.name_conflict",
                    source = %source.name,
                    name = %name,
                    "nom déjà pris par un autre utilisateur de la source : utilisateur non créé"
                );
                return Ok(Change::Conflict);
            }
            return Err(e.into());
        }
        notify_audit(&mut tx).await?;
        let appended = audit::append(
            &mut tx,
            core_event(
                EventKind::IdentityUserProvisioned,
                Outcome::Success,
                &source.name,
            )
            .uuid(field::USER_ID, id.to_bytes())
            .text(field::NAME, name)
            .text(field::DISPLAY_NAME, truncate(&user.display_name))
            .text(field::DIRECTORY_DN, truncate(&user.dn)),
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| CoreError::AuditWrite(e.to_string()))?;
        self.recorder.critical(&[appended]);
        tracing::info!(event = "identity.user_provisioned", user = %id, name, "utilisateur créé depuis sa source d'identités");
        Ok(Change::Created(id))
    }

    /// Disables the active user of `source` whose entry is gone.
    async fn absent(
        &self,
        source: &DirectorySource,
        external_id: &str,
    ) -> Result<Change, CoreError> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query!(
            r#"SELECT id::text AS "id!", name FROM app_user
               WHERE source = $1 AND external_id = $2 AND state = 'active' FOR UPDATE"#,
            source.name,
            external_id,
        )
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            return Ok(Change::Ignored);
        };
        let id = uuid(&row.id)?;
        let mut appended = Vec::new();
        let revoked = disable(&mut tx, id, &row.name, &source.name, ABSENT, &mut appended).await?;
        tx.commit().await?;
        if !appended.is_empty() {
            self.recorder.critical(&appended);
        }
        tracing::warn!(event = "user.disabled", user = %id, source = %source.name, reason = ABSENT, revoked_sessions = revoked, "utilisateur désactivé par sa source d'identités");
        Ok(Change::Disabled(id, revoked))
    }

    /// Makes the memberships given by `source` to `user` exactly `groups`.
    async fn set_groups(
        &self,
        source: &DirectorySource,
        user: Uuid,
        groups: &[String],
    ) -> Result<(), CoreError> {
        let mut tx = self.pool.begin().await?;
        let current = sqlx::query_scalar!(
            r#"SELECT g.name FROM user_group_member m JOIN user_group g ON g.id = m.group_id
               WHERE m.user_id = $1::text::uuid AND m.source = $2"#,
            user.to_string(),
            source.name,
        )
        .fetch_all(&mut *tx)
        .await?;
        let added: Vec<&String> = groups.iter().filter(|g| !current.contains(g)).collect();
        let removed: Vec<&String> = current.iter().filter(|g| !groups.contains(g)).collect();
        if added.is_empty() && removed.is_empty() {
            tx.rollback().await?;
            return Ok(());
        }
        notify_audit(&mut tx).await?;
        let mut appended = Vec::new();
        for group in &added {
            let id = Uuid::random().map_err(|e| CoreError::Keys(format!("aléa : {e}")))?;
            let created = sqlx::query_scalar!(
                r#"INSERT INTO user_group (id, name) VALUES ($1::text::uuid, $2)
                   ON CONFLICT (name) DO NOTHING RETURNING id::text AS "id!""#,
                id.to_string(),
                group.as_str(),
            )
            .fetch_optional(&mut *tx)
            .await?;
            if created.is_some() {
                appended.push(
                    audit::append(
                        &mut tx,
                        core_event(EventKind::UserGroupCreated, Outcome::Success, &source.name)
                            .text(field::USER_GROUP, group.as_str()),
                    )
                    .await?,
                );
            }
            sqlx::query!(
                "INSERT INTO user_group_member (group_id, user_id, source)
                 SELECT id, $2::text::uuid, $3 FROM user_group WHERE name = $1
                 ON CONFLICT DO NOTHING",
                group.as_str(),
                user.to_string(),
                source.name,
            )
            .execute(&mut *tx)
            .await?;
            appended.push(
                audit::append(
                    &mut tx,
                    core_event(
                        EventKind::UserGroupMemberAdded,
                        Outcome::Success,
                        &source.name,
                    )
                    .uuid(field::USER_ID, user.to_bytes())
                    .text(field::USER_GROUP, group.as_str()),
                )
                .await?,
            );
        }
        for group in &removed {
            sqlx::query!(
                "DELETE FROM user_group_member m USING user_group g
                 WHERE g.id = m.group_id AND m.user_id = $1::text::uuid AND m.source = $2
                   AND g.name = $3",
                user.to_string(),
                source.name,
                group.as_str(),
            )
            .execute(&mut *tx)
            .await?;
        }
        // Protective, last statements before the commit.
        for group in &removed {
            appended.extend(
                audit::append_protective(
                    &mut tx,
                    core_event(
                        EventKind::UserGroupMemberRemoved,
                        Outcome::Success,
                        &source.name,
                    )
                    .uuid(field::USER_ID, user.to_bytes())
                    .text(field::USER_GROUP, group.as_str()),
                )
                .await,
            );
        }
        tx.commit()
            .await
            .map_err(|e| CoreError::AuditWrite(e.to_string()))?;
        self.recorder.critical(&appended);
        Ok(())
    }

    /// One task per source: a full pass at start and every
    /// `sync_interval`, a check every `check_interval` in between.
    pub fn spawn(self: &Arc<Self>) -> Vec<JoinHandle<()>> {
        self.directories
            .sources()
            .iter()
            .map(|source| tokio::spawn(self.clone().run(source.clone())))
            .collect()
    }

    async fn run(self: Arc<Self>, source: Arc<DirectorySource>) {
        let check = self.directories.check_interval;
        let full = self.directories.sync_interval;
        let mut next_full = tokio::time::Instant::now();
        loop {
            let now = tokio::time::Instant::now();
            let result = if now >= next_full {
                next_full = now + full;
                self.sync(&source).await
            } else {
                self.check(&source).await
            };
            if let Err(e) = result {
                if !matches!(e, CoreError::Directory(_)) {
                    tracing::error!(event = "identity.sync_failed", source = %source.name, code = e.code(), "{e}");
                }
                // A failed full pass is tried again at the next tick.
                if next_full > now {
                    next_full = now;
                }
            }
            tokio::time::sleep(check).await;
        }
    }
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(d) if d.code().as_deref() == Some("23505"))
}

/// Enables again `id`, disabled by its source `source`
/// (`identity.user_reenabled`, granting).
async fn reenable(
    tx: &mut Tx<'_>,
    id: Uuid,
    name: &str,
    source: &str,
) -> Result<Appended, CoreError> {
    sqlx::query!(
        "UPDATE app_user SET state = 'active', disabled_at = NULL, directory_disabled = false
         WHERE id = $1::text::uuid",
        id.to_string(),
    )
    .execute(&mut **tx)
    .await?;
    notify_audit(tx).await?;
    audit::append(
        tx,
        core_event(EventKind::IdentityUserReenabled, Outcome::Success, source)
            .uuid(field::USER_ID, id.to_bytes())
            .text(field::NAME, name),
    )
    .await
}

/// Disables `id` (locked by the caller) for `reason` given by its source
/// and revokes its open login sessions. Returns how many.
async fn disable(
    tx: &mut Tx<'_>,
    id: Uuid,
    name: &str,
    source: &str,
    reason: &str,
    appended: &mut Vec<Appended>,
) -> Result<usize, CoreError> {
    sqlx::query!(
        "UPDATE app_user SET state = 'disabled', disabled_at = now(), directory_disabled = true
         WHERE id = $1::text::uuid",
        id.to_string(),
    )
    .execute(&mut **tx)
    .await?;
    let revoked = revoke(tx, id, source, reason, None, unix_now(), appended).await?;
    appended.extend(
        audit::append_protective(
            tx,
            core_event(EventKind::UserDisabled, Outcome::Success, source)
                .uuid(field::USER_ID, id.to_bytes())
                .text(field::NAME, name)
                .text(field::REASON, reason)
                .u64(field::REVOKED_SESSIONS, revoked as u64),
        )
        .await,
    );
    Ok(revoked)
}

/// Revokes the open login sessions of `id` (only those opened before
/// `before`, if given) and tells the running core. Returns how many.
async fn revoke(
    tx: &mut Tx<'_>,
    id: Uuid,
    source: &str,
    reason: &str,
    before: Option<u64>,
    now: u64,
    appended: &mut Vec<Appended>,
) -> Result<usize, CoreError> {
    let sessions = sqlx::query_scalar!(
        r#"UPDATE login_session
           SET revoked_at = now(), revoked_by = $2, revocation_reason = $3
           WHERE user_id = $1::text::uuid AND revoked_at IS NULL AND expires_at > $4
             AND ($5::bigint IS NULL OR started_at < $5)
           RETURNING id::text AS "id!""#,
        id.to_string(),
        format!("core:identity/{source}"),
        reason,
        i64_of(now),
        before.map(i64_of),
    )
    .fetch_all(&mut **tx)
    .await?;
    if sessions.is_empty() {
        return Ok(0);
    }
    let sessions = sessions
        .iter()
        .map(|s| uuid(s))
        .collect::<Result<Vec<_>, _>>()?;
    for session in &sessions {
        notify_notice(tx, &Notice::LoginRevoked(*session)).await?;
    }
    notify_audit(tx).await?;
    // Protective.
    for session in &sessions {
        appended.extend(
            audit::append_protective(
                tx,
                core_event(EventKind::LoginSessionRevoked, Outcome::Success, source)
                    .uuid(field::LOGIN_SESSION, session.to_bytes())
                    .uuid(field::USER_ID, id.to_bytes())
                    .text(field::REASON, reason),
            )
            .await,
        );
    }
    Ok(sessions.len())
}
