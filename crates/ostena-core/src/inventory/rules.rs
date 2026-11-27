//! Access rules and groups of target accounts (ADR-0022, PR 10c),
//! administered in the database like the rights. Every change raises the
//! version of the policy (trigger of migration 11), which notifies the
//! core; every change is written to the audit chain: a rule that allows
//! and a membership added are granting, a refusal, a revocation and a
//! membership removed are protective.

use ostena_audit::{EventKind, field};
use ostena_policy::Protocol;
use ostena_tunnel::Uuid;
use sqlx::PgPool;

use super::{
    MAX_RIGHT_SECS, SESSION_SECS, admin_event, commit_granting, invalid, is_name, new_id, unique,
};
use crate::audit::{self, Tx};
use crate::error::CoreError;
use crate::functions::Functions;
use crate::store::{i64_of, notify_audit, unix_now, uuid};

/// Who a rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSubject<'a> {
    /// One user, by name.
    User(&'a str),
    /// The members of a group of users, by name.
    Group(&'a str),
}

/// What a rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleTarget<'a> {
    /// One account on a resource.
    Account {
        /// Resource name.
        resource: &'a str,
        /// Account name.
        account: &'a str,
    },
    /// Every account of a group of accounts, by name.
    Group(&'a str),
}

/// What a rule does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleEffect {
    /// Allows, with these functions, sessions of at most `max_session_secs`.
    Allow {
        /// Functions beyond the terminal and the commands.
        functions: Functions,
        /// Longest session, 60 to 43 200 seconds.
        max_session_secs: u32,
    },
    /// Refuses, whatever the allowing rules.
    Deny,
    /// Takes these functions away (at least one).
    DenyFunctions(Functions),
}

impl RuleEffect {
    /// The name stored, e.g. `deny_functions`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Allow { .. } => "allow",
            Self::Deny => "deny",
            Self::DenyFunctions(_) => "deny_functions",
        }
    }

    fn functions(self) -> Functions {
        match self {
            Self::Allow { functions, .. } | Self::DenyFunctions(functions) => functions,
            Self::Deny => Functions::NONE,
        }
    }
}

/// A rule to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRule<'a> {
    /// Who.
    pub subject: RuleSubject<'a>,
    /// On what.
    pub target: RuleTarget<'a>,
    /// With which protocols (at least one).
    pub protocols: Vec<Protocol>,
    /// What it does.
    pub effect: RuleEffect,
    /// End, Unix seconds: mandatory for an allowing rule (366 days at
    /// most), optional for a refusal.
    pub valid_until: Option<u64>,
}

/// A rule, as listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleRow {
    /// Identifier.
    pub id: Uuid,
    /// `user:name` or `group:name`.
    pub subject: String,
    /// `account@resource` or `group:name`.
    pub target: String,
    /// Protocols.
    pub protocols: Vec<String>,
    /// `allow`, `deny` or `deny_functions`.
    pub effect: String,
    /// Functions granted or taken away.
    pub functions: Functions,
    /// Longest session of an allowing rule.
    pub max_session_secs: Option<u32>,
    /// End, if any.
    pub valid_until: Option<u64>,
    /// Revoked.
    pub revoked: bool,
}

fn protocols_text(protocols: &[Protocol]) -> String {
    protocols
        .iter()
        .map(|p| p.name())
        .collect::<Vec<_>>()
        .join(",")
}

/// The checks of a rule before it is written: bounds of the window and of
/// the session, functions of a refusal.
fn check_rule(rule: &NewRule<'_>, now: u64) -> Result<(), CoreError> {
    if rule.protocols.is_empty() {
        return Err(invalid("au moins un protocole"));
    }
    match (rule.effect, rule.valid_until) {
        (RuleEffect::Allow { .. }, None) => {
            return Err(invalid("fin d'une règle d'autorisation obligatoire"));
        }
        (RuleEffect::Allow { .. }, Some(until)) if until > now + MAX_RIGHT_SECS => {
            return Err(invalid(
                "fin d'une règle d'autorisation à 366 jours au plus",
            ));
        }
        (_, Some(until)) if until <= now => {
            return Err(invalid("fin de la règle dans le futur"));
        }
        _ => {}
    }
    match rule.effect {
        RuleEffect::Allow {
            max_session_secs, ..
        } if !SESSION_SECS.contains(&max_session_secs) => {
            Err(invalid("durée de session : 60 à 43 200 secondes"))
        }
        RuleEffect::DenyFunctions(f) if f == Functions::NONE => Err(invalid(
            "une interdiction de fonctions en nomme au moins une",
        )),
        _ => Ok(()),
    }
}

async fn active_user(tx: &mut Tx<'_>, name: &str) -> Result<Uuid, CoreError> {
    let id = sqlx::query_scalar!(
        r#"SELECT id::text AS "id!" FROM app_user WHERE name = $1 AND state = 'active'"#,
        name
    )
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| CoreError::NotFound(format!("utilisateur actif {name}")))?;
    uuid(&id)
}

async fn user_group(tx: &mut Tx<'_>, name: &str) -> Result<Uuid, CoreError> {
    let id = sqlx::query_scalar!(
        r#"SELECT id::text AS "id!" FROM user_group WHERE name = $1"#,
        name
    )
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| CoreError::NotFound(format!("groupe d'utilisateurs {name}")))?;
    uuid(&id)
}

async fn account(tx: &mut Tx<'_>, resource: &str, account: &str) -> Result<Uuid, CoreError> {
    let id = sqlx::query_scalar!(
        r#"SELECT a.id::text AS "id!" FROM target_account a JOIN resource r ON r.id = a.resource_id
           WHERE r.name = $1 AND a.name = $2 AND r.disabled_at IS NULL AND a.disabled_at IS NULL"#,
        resource,
        account,
    )
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| CoreError::NotFound(format!("compte {account}@{resource}")))?;
    uuid(&id)
}

async fn account_group(tx: &mut Tx<'_>, name: &str) -> Result<Uuid, CoreError> {
    let id = sqlx::query_scalar!(
        r#"SELECT id::text AS "id!" FROM account_group WHERE name = $1"#,
        name
    )
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| CoreError::NotFound(format!("groupe de comptes {name}")))?;
    uuid(&id)
}

/// Creates the group of accounts `name`; prints its identifier.
///
/// # Errors
///
/// [`CoreError::Invalid`] for a bad or taken name, [`CoreError::AuditWrite`].
pub async fn create_account_group(pool: &PgPool, name: &str) -> Result<Uuid, CoreError> {
    if !is_name(name, 63, b"._-") {
        return Err(invalid(
            "nom de groupe de comptes : minuscules, chiffres, « . _ - », 63 au plus",
        ));
    }
    let id = new_id()?;
    let mut tx = pool.begin().await?;
    let actor = audit::admin_actor(&mut tx).await?;
    sqlx::query!(
        "INSERT INTO account_group (id, name, created_by) VALUES ($1::text::uuid, $2, $3)",
        id.to_string(),
        name,
        actor,
    )
    .execute(&mut *tx)
    .await
    .map_err(unique(&format!("le groupe de comptes {name}")))?;
    let event = admin_event(EventKind::AccountGroupCreated, actor)
        .uuid(field::ACCOUNT_GROUP_ID, id.to_bytes())
        .text(field::ACCOUNT_GROUP, name);
    commit_granting(tx, event).await?;
    tracing::info!(event = "account_group.created", account_group = %id, name);
    Ok(id)
}

/// Adds `account@resource` to the group of accounts `group`. Returns
/// whether it was not already a member.
///
/// # Errors
///
/// [`CoreError::NotFound`], [`CoreError::AuditWrite`].
pub async fn add_account_group_member(
    pool: &PgPool,
    group: &str,
    resource: &str,
    account_name: &str,
) -> Result<bool, CoreError> {
    let mut tx = pool.begin().await?;
    let actor = audit::admin_actor(&mut tx).await?;
    let group_id = account_group(&mut tx, group).await?;
    let account_id = account(&mut tx, resource, account_name).await?;
    let added = sqlx::query!(
        "INSERT INTO account_group_member (group_id, account_id, added_by)
         VALUES ($1::text::uuid, $2::text::uuid, $3) ON CONFLICT DO NOTHING",
        group_id.to_string(),
        account_id.to_string(),
        actor,
    )
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    if !added {
        tx.rollback().await?;
        return Ok(false);
    }
    let event = admin_event(EventKind::AccountGroupMemberAdded, actor)
        .uuid(field::ACCOUNT_GROUP_ID, group_id.to_bytes())
        .text(field::ACCOUNT_GROUP, group)
        .uuid(field::ACCOUNT_ID, account_id.to_bytes());
    commit_granting(tx, event).await?;
    tracing::info!(
        event = "account_group.member_added",
        account_group = group,
        account = %account_id
    );
    Ok(true)
}

/// Removes `account@resource` from the group of accounts `group`. Returns
/// whether it was a member. Sessions already open end at their maximum.
///
/// # Errors
///
/// [`CoreError::NotFound`], [`CoreError::Database`].
pub async fn remove_account_group_member(
    pool: &PgPool,
    group: &str,
    resource: &str,
    account_name: &str,
) -> Result<bool, CoreError> {
    let mut tx = pool.begin().await?;
    let actor = audit::admin_actor(&mut tx).await?;
    let group_id = account_group(&mut tx, group).await?;
    let account_id = account(&mut tx, resource, account_name).await?;
    let removed = sqlx::query!(
        "DELETE FROM account_group_member
         WHERE group_id = $1::text::uuid AND account_id = $2::text::uuid",
        group_id.to_string(),
        account_id.to_string(),
    )
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    if !removed {
        tx.rollback().await?;
        return Ok(false);
    }
    notify_audit(&mut tx).await?;
    // Protective, last statement before the commit.
    audit::append_protective(
        &mut tx,
        admin_event(EventKind::AccountGroupMemberRemoved, actor)
            .uuid(field::ACCOUNT_GROUP_ID, group_id.to_bytes())
            .text(field::ACCOUNT_GROUP, group)
            .uuid(field::ACCOUNT_ID, account_id.to_bytes()),
    )
    .await;
    tx.commit().await?;
    tracing::warn!(
        event = "account_group.member_removed",
        account_group = group,
        account = %account_id
    );
    Ok(true)
}

/// Every group of accounts and its members (`account@resource`), by name.
///
/// # Errors
///
/// [`CoreError::Database`].
pub async fn list_account_groups(pool: &PgPool) -> Result<Vec<(String, Vec<String>)>, CoreError> {
    let rows = sqlx::query!(
        r#"SELECT g.name AS "name!",
                  coalesce(array_agg(a.name || '@' || r.name ORDER BY r.name, a.name)
                           FILTER (WHERE a.id IS NOT NULL), '{}') AS "members!"
           FROM account_group g
           LEFT JOIN account_group_member m ON m.group_id = g.id
           LEFT JOIN target_account a ON a.id = m.account_id
           LEFT JOIN resource r ON r.id = a.resource_id
           GROUP BY g.name ORDER BY g.name"#
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| (r.name, r.members)).collect())
}

/// Creates `rule`; returns its identifier.
///
/// # Errors
///
/// [`CoreError::Invalid`] for bounds, [`CoreError::NotFound`] for an
/// unknown user, group, resource or account, [`CoreError::AuditWrite`].
pub async fn create_rule(pool: &PgPool, rule: &NewRule<'_>) -> Result<Uuid, CoreError> {
    let now = unix_now();
    check_rule(rule, now)?;
    let id = new_id()?;
    let mut tx = pool.begin().await?;
    let actor = audit::admin_actor(&mut tx).await?;
    let mut event = admin_event(EventKind::AccessRuleCreated, actor.clone())
        .uuid(field::RULE_ID, id.to_bytes());
    let (user, user_group_id) = match rule.subject {
        RuleSubject::User(name) => {
            let user = active_user(&mut tx, name).await?;
            event = event.uuid(field::USER_ID, user.to_bytes());
            (Some(user.to_string()), None)
        }
        RuleSubject::Group(name) => {
            let group = user_group(&mut tx, name).await?;
            event = event
                .uuid(field::USER_GROUP_ID, group.to_bytes())
                .text(field::USER_GROUP, name);
            (None, Some(group.to_string()))
        }
    };
    let (account_id, account_group_id) = match rule.target {
        RuleTarget::Account {
            resource,
            account: name,
        } => {
            let target = account(&mut tx, resource, name).await?;
            event = event.uuid(field::ACCOUNT_ID, target.to_bytes());
            (Some(target.to_string()), None)
        }
        RuleTarget::Group(name) => {
            let group = account_group(&mut tx, name).await?;
            event = event
                .uuid(field::ACCOUNT_GROUP_ID, group.to_bytes())
                .text(field::ACCOUNT_GROUP, name);
            (None, Some(group.to_string()))
        }
    };
    let protocols: Vec<String> = rule.protocols.iter().map(|p| p.name().to_owned()).collect();
    let max_session_secs = match rule.effect {
        RuleEffect::Allow {
            max_session_secs, ..
        } => Some(i32::try_from(max_session_secs).unwrap_or(i32::MAX)),
        RuleEffect::Deny | RuleEffect::DenyFunctions(_) => None,
    };
    sqlx::query!(
        "INSERT INTO access_rule (id, user_id, user_group_id, account_id, account_group_id,
                                  protocols, effect, functions, max_session_secs, valid_from,
                                  valid_until, created_by)
         VALUES ($1::text::uuid, $2::text::uuid, $3::text::uuid, $4::text::uuid,
                 $5::text::uuid, $6, $7, $8, $9, $10, $11, $12)",
        id.to_string(),
        user,
        user_group_id,
        account_id,
        account_group_id,
        &protocols,
        rule.effect.name(),
        &rule.effect.functions().names(),
        max_session_secs,
        i64_of(now),
        rule.valid_until.map(i64_of),
        actor,
    )
    .execute(&mut *tx)
    .await?;
    event = event
        .text(field::PROTOCOLS, protocols_text(&rule.protocols))
        .text(field::EFFECT, rule.effect.name())
        .text(field::FUNCTIONS, rule.effect.functions().label());
    if let Some(secs) = max_session_secs {
        event = event.u64(field::MAX_SESSION_SECS, u64::try_from(secs).unwrap_or(0));
    }
    if let Some(until) = rule.valid_until {
        event = event.u64(field::VALID_UNTIL, until);
    }
    if matches!(rule.effect, RuleEffect::Allow { .. }) {
        commit_granting(tx, event).await?;
    } else {
        // A refusal only narrows: protective.
        notify_audit(&mut tx).await?;
        audit::append_protective(&mut tx, event).await;
        tx.commit().await?;
    }
    tracing::info!(event = "access_rule.created", rule = %id, effect = rule.effect.name());
    Ok(id)
}

/// Revokes the rule `rule`: no new grant under it. Sessions already open
/// end at their maximum length (or with their login session).
///
/// # Errors
///
/// [`CoreError::NotFound`] for an unknown rule, [`CoreError::Database`].
pub async fn revoke_rule(pool: &PgPool, rule: Uuid) -> Result<(), CoreError> {
    let mut tx = pool.begin().await?;
    let actor = audit::admin_actor(&mut tx).await?;
    let revoked = sqlx::query!(
        "UPDATE access_rule SET revoked_at = now(), revoked_by = $2
         WHERE id = $1::text::uuid AND revoked_at IS NULL",
        rule.to_string(),
        actor,
    )
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if revoked == 0 {
        let known = sqlx::query_scalar!(
            r#"SELECT true AS "known!" FROM access_rule WHERE id = $1::text::uuid"#,
            rule.to_string(),
        )
        .fetch_optional(&mut *tx)
        .await?;
        tx.rollback().await?;
        return match known {
            Some(_) => Ok(()),
            None => Err(CoreError::NotFound(format!("règle {rule}"))),
        };
    }
    notify_audit(&mut tx).await?;
    // Protective, last statement before the commit.
    audit::append_protective(
        &mut tx,
        admin_event(EventKind::AccessRuleRevoked, actor).uuid(field::RULE_ID, rule.to_bytes()),
    )
    .await;
    tx.commit().await?;
    tracing::warn!(event = "access_rule.revoked", rule = %rule);
    Ok(())
}

/// Every rule, newest first.
///
/// # Errors
///
/// [`CoreError::Database`].
pub async fn list_rules(pool: &PgPool) -> Result<Vec<RuleRow>, CoreError> {
    let rows = sqlx::query!(
        r#"SELECT ar.id::text AS "id!",
                  coalesce('user:' || u.name, 'group:' || ug.name) AS "subject!",
                  coalesce(a.name || '@' || r.name, 'group:' || ag.name) AS "target!",
                  ar.protocols, ar.effect, ar.functions, ar.max_session_secs, ar.valid_until,
                  ar.revoked_at IS NOT NULL AS "revoked!"
           FROM access_rule ar
           LEFT JOIN app_user u ON u.id = ar.user_id
           LEFT JOIN user_group ug ON ug.id = ar.user_group_id
           LEFT JOIN target_account a ON a.id = ar.account_id
           LEFT JOIN resource r ON r.id = a.resource_id
           LEFT JOIN account_group ag ON ag.id = ar.account_group_id
           ORDER BY ar.created_at DESC, ar.id"#
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(RuleRow {
                id: uuid(&r.id)?,
                subject: r.subject,
                target: r.target,
                protocols: r.protocols,
                effect: r.effect,
                functions: Functions::from_stored(&r.functions),
                max_session_secs: r.max_session_secs.and_then(|s| u32::try_from(s).ok()),
                valid_until: r.valid_until.and_then(|u| u64::try_from(u).ok()),
                revoked: r.revoked,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::functions::Function;

    fn rule(effect: RuleEffect, valid_until: Option<u64>) -> NewRule<'static> {
        NewRule {
            subject: RuleSubject::Group("ops"),
            target: RuleTarget::Group("linux"),
            protocols: vec![Protocol::Ssh],
            effect,
            valid_until,
        }
    }

    #[test]
    fn rules_are_checked_before_they_are_written() {
        let now = 1_000_000;
        let allow = RuleEffect::Allow {
            functions: Functions::NONE,
            max_session_secs: 3600,
        };
        assert!(check_rule(&rule(allow, Some(now + 86_400)), now).is_ok());
        // An allowing rule ends, within 366 days.
        assert!(check_rule(&rule(allow, None), now).is_err());
        assert!(check_rule(&rule(allow, Some(now + MAX_RIGHT_SECS + 1)), now).is_err());
        assert!(check_rule(&rule(allow, Some(now)), now).is_err());
        let long = RuleEffect::Allow {
            functions: Functions::NONE,
            max_session_secs: 43_201,
        };
        assert!(check_rule(&rule(long, Some(now + 60)), now).is_err());
        // A refusal may last forever, but not end in the past.
        assert!(check_rule(&rule(RuleEffect::Deny, None), now).is_ok());
        assert!(check_rule(&rule(RuleEffect::Deny, Some(now - 1)), now).is_err());
        assert!(check_rule(&rule(RuleEffect::DenyFunctions(Functions::NONE), None), now).is_err());
        let transfer = Functions::NONE.with(Function::Transfer);
        assert!(check_rule(&rule(RuleEffect::DenyFunctions(transfer), None), now).is_ok());
        let mut none = rule(RuleEffect::Deny, None);
        none.protocols.clear();
        assert!(check_rule(&none, now).is_err());
    }
}
