//! The access policy of the core in its decision point (ADR-0022).
//!
//! The policy is read from PostgreSQL as a whole, compiled and installed in
//! a [`Pdp`]. Its rules are the rights of ADR-0014 (one user, one account,
//! SSH, functions, until a date) and the access rules (users or groups of
//! users, accounts or groups of accounts, protocols, allowing or refusing).
//! Its version is the one of the database (`policy_version`), raised by
//! every change of what it reads. A reload is asked after each change
//! (notice `policy`), when lost notices are replayed, and when a decision
//! finds the policy behind the database ([`crate::access`]).
//! Reloads are serialized and merged: a reload asked while another one
//! reads the database runs once more after it, never in parallel, so a
//! slower reload never installs older rules.
//!
//! A reload that fails leaves the policy invalidated: every access is
//! refused (`POL-E003`) until the next reload succeeds.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use ostena_audit::{ActorKind, Event, EventKind, Outcome, field};
use ostena_policy::roles::{self, AdminRole, Separation};
use ostena_policy::{
    AccountGroupId, AccountId, CompiledPolicy, Decision, Effect, Functions, Installed, Pdp,
    Protocol, Protocols, Request, Rule, RuleId, Snapshot, Stats, Subject, Target, UserGroupId,
    UserId,
};
use ostena_tunnel::Uuid;
use sqlx::PgPool;

use crate::audit::{self, Recorder};
use crate::error::CoreError;
use crate::store::{truncate, uuid};

/// The 128 bits of a UUID, as the decision point names it.
pub const fn id128(id: Uuid) -> u128 {
    u128::from_be_bytes(id.to_bytes())
}

/// The UUID of an identifier of the decision point.
pub const fn uuid_of(id: u128) -> Uuid {
    Uuid::from_bytes(id.to_be_bytes())
}

/// The functions of the decision point carried by the functions of a right.
pub fn functions(right: crate::functions::Functions) -> Functions {
    // Same bits (ADR-0004); an unknown bit cannot come from a right, and
    // would give no function.
    Functions::from_bits(right.rights().bits()).unwrap_or(Functions::NONE)
}

/// The version of the policy in the database (`policy_version`).
///
/// # Errors
///
/// [`CoreError::Database`].
pub async fn stored_version(conn: &mut sqlx::PgConnection) -> Result<u64, CoreError> {
    let version = sqlx::query_scalar!("SELECT version FROM policy_version")
        .fetch_one(&mut *conn)
        .await?;
    Ok(u64::try_from(version).unwrap_or(0))
}

/// The protocols named by a rule; an unknown name is left out.
fn protocols(names: &[String]) -> Protocols {
    names.iter().filter_map(|n| Protocol::parse(n)).collect()
}

/// The policy valid at `now` or later and its version, read in one
/// repeatable-read transaction: the rights neither revoked nor ended, the
/// access rules likewise, and the members of the groups.
///
/// # Errors
///
/// [`CoreError::Database`].
pub async fn snapshot(pool: &PgPool, now: u64) -> Result<Snapshot, CoreError> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    let version = stored_version(&mut tx).await?;
    let mut rules = rights(&mut tx, now).await?;
    rules.extend(access_rules(&mut tx, now).await?);
    let user_groups = sqlx::query!(
        r#"SELECT group_id::text AS "group!", user_id::text AS "user!" FROM user_group_member"#
    )
    .fetch_all(&mut *tx)
    .await?
    .into_iter()
    .map(|r| {
        Ok((
            UserGroupId(id128(uuid(&r.group)?)),
            UserId(id128(uuid(&r.user)?)),
        ))
    })
    .collect::<Result<Vec<_>, CoreError>>()?;
    let account_groups = sqlx::query!(
        r#"SELECT group_id::text AS "group!", account_id::text AS "account!"
           FROM account_group_member"#
    )
    .fetch_all(&mut *tx)
    .await?
    .into_iter()
    .map(|r| {
        Ok((
            AccountGroupId(id128(uuid(&r.group)?)),
            AccountId(id128(uuid(&r.account)?)),
        ))
    })
    .collect::<Result<Vec<_>, CoreError>>()?;
    tx.commit().await?;
    Ok(Snapshot {
        version,
        user_groups,
        account_groups,
        rules,
    })
}

/// The rights valid at `now` or later, as rules.
async fn rights(conn: &mut sqlx::PgConnection, now: u64) -> Result<Vec<Rule>, CoreError> {
    let rows = sqlx::query!(
        r#"SELECT id::text AS "id!", user_id::text AS "user!", account_id::text AS "account!",
                  protocol, valid_from, valid_until, max_session_secs, functions
           FROM access_right WHERE revoked_at IS NULL AND valid_until > $1"#,
        crate::store::i64_of(now),
    )
    .fetch_all(&mut *conn)
    .await?;
    let mut rules = Vec::with_capacity(rows.len());
    for r in rows {
        // The CHECK constraints keep these in range; a row that is not is
        // left out, never widened.
        let Some(protocol) = Protocol::parse(&r.protocol) else {
            continue;
        };
        let (Ok(valid_from), Ok(valid_until), Ok(max_session_secs)) = (
            u64::try_from(r.valid_from),
            u64::try_from(r.valid_until),
            u32::try_from(r.max_session_secs),
        ) else {
            continue;
        };
        rules.push(Rule {
            id: RuleId(id128(uuid(&r.id)?)),
            subject: Subject::User(UserId(id128(uuid(&r.user)?))),
            target: Target::Account(AccountId(id128(uuid(&r.account)?))),
            protocols: Protocols::NONE.with(protocol),
            effect: Effect::Allow {
                functions: functions(crate::functions::Functions::from_stored(&r.functions)),
                max_session_secs,
            },
            valid_from,
            valid_until,
        });
    }
    Ok(rules)
}

/// The access rules valid at `now` or later. A refusal without an end
/// lasts until `u64::MAX`.
async fn access_rules(conn: &mut sqlx::PgConnection, now: u64) -> Result<Vec<Rule>, CoreError> {
    let rows = sqlx::query!(
        r#"SELECT id::text AS "id!", user_id::text AS "user?", user_group_id::text AS "user_group?",
                  account_id::text AS "account?", account_group_id::text AS "account_group?",
                  protocols, effect, functions, max_session_secs, valid_from, valid_until
           FROM access_rule
           WHERE revoked_at IS NULL AND (valid_until IS NULL OR valid_until > $1)"#,
        crate::store::i64_of(now),
    )
    .fetch_all(&mut *conn)
    .await?;
    let mut rules = Vec::with_capacity(rows.len());
    for r in rows {
        let subject = match (&r.user, &r.user_group) {
            (Some(u), None) => Subject::User(UserId(id128(uuid(u)?))),
            (None, Some(g)) => Subject::Group(UserGroupId(id128(uuid(g)?))),
            _ => continue,
        };
        let target = match (&r.account, &r.account_group) {
            (Some(a), None) => Target::Account(AccountId(id128(uuid(a)?))),
            (None, Some(g)) => Target::AccountGroup(AccountGroupId(id128(uuid(g)?))),
            _ => continue,
        };
        let named = functions(crate::functions::Functions::from_stored(&r.functions));
        let effect = match (r.effect.as_str(), r.max_session_secs) {
            ("allow", Some(secs)) => {
                let Ok(max_session_secs) = u32::try_from(secs) else {
                    continue;
                };
                Effect::Allow {
                    functions: named,
                    max_session_secs,
                }
            }
            ("deny_functions", None) => Effect::DenyFunctions(named),
            // Out of the CHECK constraints: an allowing rule is left out.
            ("allow", None) | ("deny" | "deny_functions", Some(_)) => continue,
            // `deny`, and a refusal of an unknown kind: refuses everything.
            _ => Effect::Deny,
        };
        let Ok(valid_from) = u64::try_from(r.valid_from) else {
            continue;
        };
        let valid_until = match r.valid_until {
            None => u64::MAX,
            Some(until) => u64::try_from(until).unwrap_or(0),
        };
        rules.push(Rule {
            id: RuleId(id128(uuid(&r.id)?)),
            subject,
            target,
            protocols: protocols(&r.protocols),
            effect,
            valid_from,
            valid_until,
        });
    }
    Ok(rules)
}

/// What a reload installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reloaded {
    /// The version installed and the one it replaced.
    pub installed: Installed,
    /// What the policy holds.
    pub stats: Stats,
    /// Compilation time, microseconds.
    pub compile_micros: u64,
}

/// The decision point of the core and its reloads.
#[derive(Debug, Default)]
pub struct Policies {
    pdp: Pdp,
    /// Reloads asked so far.
    asked: AtomicU64,
    /// Under the lock: the last reload asked that a finished reload covers.
    state: tokio::sync::Mutex<u64>,
    /// Where the installations and invalidations are recorded (the core);
    /// none for a dry run.
    recorder: Option<Arc<Recorder>>,
}

impl Policies {
    /// No policy yet: every access is refused until the first reload.
    /// Reloads are not audited (a dry run).
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// [`Policies::new`] for the core: each installation is recorded
    /// (`policy.installed`), each failed reload too (`policy.invalidated`),
    /// at best.
    pub fn recorded(recorder: Arc<Recorder>) -> Arc<Self> {
        Arc::new(Self {
            recorder: Some(recorder),
            ..Self::default()
        })
    }

    /// Decides with the policy in place.
    pub fn decide(&self, request: &Request) -> Decision {
        self.pdp.decide(request)
    }

    /// The version in place, if any.
    pub fn version(&self) -> Option<u64> {
        self.pdp.current().map(|p| p.version())
    }

    /// Reads, compiles and installs the policy, unless a reload that
    /// started after this call already did. Returns what was installed
    /// (`None`: done by another reload). On failure, the policy is
    /// invalidated.
    ///
    /// # Errors
    ///
    /// [`CoreError::Database`], [`CoreError::Policy`] (`POL-E004`).
    pub async fn reload(&self, pool: &PgPool, now: u64) -> Result<Option<Reloaded>, CoreError> {
        let ticket = self.asked.fetch_add(1, Ordering::AcqRel) + 1;
        let mut state = self.state.lock().await;
        if *state >= ticket {
            return Ok(None);
        }
        // Every reload asked until now is covered by this one: they asked
        // before it reads.
        let covers = self.asked.load(Ordering::Acquire);
        let result = self.read_and_install(pool, now).await;
        match result {
            Ok(reloaded) => {
                *state = covers;
                tracing::info!(
                    event = "policy.installed",
                    pdp_version = reloaded.installed.version,
                    rules = reloaded.stats.rules,
                    compile_micros = reloaded.compile_micros,
                );
                if let Some(recorder) = &self.recorder {
                    recorder.emit(installed_event(&reloaded));
                }
                Ok(Some(reloaded))
            }
            Err(e) => {
                let dropped = self.pdp.invalidate();
                tracing::error!(
                    event = "policy.invalidated",
                    code = e.code(),
                    dropped = ?dropped,
                    "{e}"
                );
                if let Some(recorder) = &self.recorder {
                    recorder.emit(invalidated_event(&e));
                }
                Err(e)
            }
        }
    }

    async fn read_and_install(&self, pool: &PgPool, now: u64) -> Result<Reloaded, CoreError> {
        let snapshot = snapshot(pool, now).await?;
        let start = Instant::now();
        let compiled = CompiledPolicy::compile(&snapshot)?;
        let compile_micros = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
        let stats = compiled.stats();
        let installed = self.pdp.install(Arc::new(compiled))?;
        Ok(Reloaded {
            installed,
            stats,
            compile_micros,
        })
    }
}

/// Whether the configuration lets one account hold incompatible
/// administration roles (`core.admin.allow_role_cumulation`, ADR-0022).
/// In production the option only passes the validation with its
/// justification (`CFG-P023`).
pub fn separation(admin: &ostena_common::config::CoreAdminConfig) -> Separation {
    if admin.allow_role_cumulation {
        Separation::CumulationAllowed
    } else {
        Separation::Strict
    }
}

/// The administration roles of `user`, as the decision point names them
/// (a stored name it does not know is left out).
async fn admin_roles(
    conn: &mut sqlx::PgConnection,
    user: Uuid,
) -> Result<Vec<AdminRole>, CoreError> {
    let names: Vec<String> =
        sqlx::query_scalar("SELECT role FROM user_role WHERE user_id = $1::text::uuid")
            .bind(user.to_string())
            .fetch_all(&mut *conn)
            .await?;
    Ok(names.iter().filter_map(|n| AdminRole::parse(n)).collect())
}

/// Checks that `user`, who holds the roles stored, may also receive `role`
/// under `separation`.
///
/// # Errors
///
/// [`CoreError::Policy`] (`POL-E006`), [`CoreError::Database`].
pub async fn check_role_grant(
    conn: &mut sqlx::PgConnection,
    user: Uuid,
    role: &str,
    separation: Separation,
) -> Result<(), CoreError> {
    let Some(asked) = AdminRole::parse(role) else {
        return Ok(());
    };
    let held = admin_roles(conn, user).await?;
    roles::check_grant(&held, asked, separation).map_err(|c| CoreError::Policy {
        code: c.code().as_str(),
        message: format!("utilisateur {user} : {c}"),
    })
}

/// The accounts that hold incompatible administration roles, with the
/// first conflicting pair: checked at every start.
///
/// # Errors
///
/// [`CoreError::Database`].
pub async fn role_cumulations(
    pool: &PgPool,
) -> Result<Vec<(String, roles::Cumulation)>, CoreError> {
    let rows: Vec<(String, Vec<String>)> = sqlx::query_as(
        "SELECT u.name, array_agg(r.role ORDER BY r.role) FROM user_role r
         JOIN app_user u ON u.id = r.user_id GROUP BY u.name ORDER BY u.name",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(name, names)| {
            let held: Vec<AdminRole> = names.iter().filter_map(|n| AdminRole::parse(n)).collect();
            roles::cumulation(&held).map(|c| (name, c))
        })
        .collect())
}

/// The start check of the separate administration roles: an account that
/// holds incompatible roles stops the core in production unless the
/// cumulation is allowed by `core.admin.allow_role_cumulation`; otherwise
/// each one is logged (`admin.role_cumulation`).
///
/// # Errors
///
/// [`CoreError::Policy`] (`POL-E006`), [`CoreError::Database`].
pub async fn enforce_role_separation(
    pool: &PgPool,
    separation: Separation,
    mode: ostena_common::config::Mode,
) -> Result<(), CoreError> {
    let found = role_cumulations(pool).await?;
    for (name, cumulation) in &found {
        tracing::warn!(
            event = "admin.role_cumulation",
            user = %truncate(name),
            held = cumulation.held.name(),
            other = cumulation.asked.name(),
            allowed = separation == Separation::CumulationAllowed,
            "{cumulation}"
        );
    }
    match found.first() {
        Some((name, cumulation))
            if separation == Separation::Strict
                && mode == ostena_common::config::Mode::Production =>
        {
            Err(CoreError::Policy {
                code: cumulation.code().as_str(),
                message: format!(
                    "{cumulation} (utilisateur {}, {} compte(s) en tout) ; retirez un rôle ou \
                     voir core.admin.allow_role_cumulation (ADR-0022)",
                    truncate(name),
                    found.len()
                ),
            })
        }
        _ => Ok(()),
    }
}

/// The `policy.installed` record of a reload (best effort).
pub fn installed_event(reloaded: &Reloaded) -> Event {
    let event = Event::new(
        EventKind::PolicyInstalled,
        Outcome::Success,
        ActorKind::Core,
        audit::CORE_ACTOR,
    )
    .u64(field::PDP_VERSION, reloaded.installed.version)
    .u64(field::RULES, reloaded.stats.rules as u64)
    .u64(field::COMPILE_MICROS, reloaded.compile_micros);
    match reloaded.installed.previous {
        Some(previous) => event.u64(field::PREVIOUS_VERSION, previous),
        None => event,
    }
}

/// The `policy.invalidated` record of a failed reload (best effort).
pub fn invalidated_event(error: &CoreError) -> Event {
    Event::new(
        EventKind::PolicyInvalidated,
        Outcome::Failure,
        ActorKind::Core,
        audit::CORE_ACTOR,
    )
    .text(field::CODE, error.code())
    .text(field::REASON, truncate(&error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::functions::{Function, Functions as RightFunctions};

    #[test]
    fn identifiers_and_functions_map_one_to_one() {
        let id = Uuid::from_bytes([7; 16]);
        assert_eq!(uuid_of(id128(id)), id);
        assert_eq!(functions(RightFunctions::NONE), Functions::NONE);
        assert_eq!(
            functions(RightFunctions::NONE.with(Function::Transfer)),
            Functions::TRANSFER
        );
        for f in Function::ALL {
            let one = RightFunctions::NONE.with(f);
            assert_eq!(functions(one).bits(), one.rights().bits(), "{f:?}");
        }
    }
}
