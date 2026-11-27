//! `ostena core group|user|resource|account|right|login|access`: the
//! minimal inventory and the SSH authorisation (ADR-0014), administered in
//! the database while the core runs; it is notified of what concerns the
//! agents (policy, SSH host names, login revocations) and applies it at
//! once. Every change is written to the audit chain.

use std::fmt::Write as _;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use ostena_common::api::web::Role;
use ostena_common::config::scope::PolicySpec;
use ostena_core::functions::Functions;
use ostena_core::{access, credential, inventory, login};
use ostena_tunnel::Uuid;

use crate::core::{admin, admin_core, fail, init_admin_logging};

const DAY: u64 = 86_400;

fn now() -> u64 {
    ostena_grant::unix_now()
}

fn done(outcome: Result<String, String>) -> ExitCode {
    match outcome {
        Ok(line) => {
            if !line.is_empty() {
                let _ = writeln!(io::stdout(), "{line}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}

/// `ostena core group add`: prints the group identifier.
pub(crate) fn group_add(
    path: &Path,
    name: &str,
    id: Option<&str>,
    host_names: &[String],
) -> ExitCode {
    init_admin_logging(path);
    let id = match id.map(Uuid::parse) {
        None => None,
        Some(Some(id)) => Some(id),
        Some(None) => return fail("--id : UUID attendu (minuscules, forme canonique)"),
    };
    done(admin(path, async move |pool| {
        inventory::create_group(&pool, id, name, host_names)
            .await
            .map(|id| id.to_string())
    }))
}

/// `ostena core group host-names`.
pub(crate) fn group_host_names(path: &Path, name: &str, host_names: &[String]) -> ExitCode {
    init_admin_logging(path);
    done(admin(path, async move |pool| {
        inventory::set_group_host_names(&pool, name, host_names)
            .await
            .map(|()| String::new())
    }))
}

/// `ostena core group policy`: the scope policy of the group, from a TOML
/// file with the fields of a `[[scope.policies]]` entry of the agent
/// configuration; prints its version.
pub(crate) fn group_policy(path: &Path, name: &str, file: &Path) -> ExitCode {
    init_admin_logging(path);
    let spec: PolicySpec = match std::fs::read_to_string(file)
        .map_err(|e| e.to_string())
        .and_then(|text| toml::from_str(&text).map_err(|e| e.to_string()))
    {
        Ok(spec) => spec,
        Err(e) => return fail(&format!("{} : {e}", file.display())),
    };
    done(admin(path, async move |pool| {
        inventory::set_group_policy(&pool, name, &spec)
            .await
            .map(|v| format!("politique du groupe {name} : version {v}"))
    }))
}

/// `ostena core group list`.
pub(crate) fn group_list(path: &Path) -> ExitCode {
    init_admin_logging(path);
    done(
        admin(path, async |pool| inventory::list_groups(&pool).await).map(|groups| {
            let mut out = String::from("groupe\tnom\tnoms d'hôte SSH\tpolitique");
            for g in groups {
                let _ = write!(
                    out,
                    "\n{}\t{}\t{}\t{}",
                    g.id,
                    g.name,
                    if g.ssh_host_names.is_empty() {
                        "-".to_owned()
                    } else {
                        g.ssh_host_names.join(",")
                    },
                    g.policy_version
                        .map_or_else(|| "-".to_owned(), |v| format!("v{v}"))
                );
            }
            out
        }),
    )
}

/// `ostena core user add`: prints the user identifier.
pub(crate) fn user_add(path: &Path, name: &str, display_name: &str) -> ExitCode {
    init_admin_logging(path);
    done(admin(path, async move |pool| {
        inventory::add_user(&pool, name, display_name)
            .await
            .map(|id| id.to_string())
    }))
}

/// `ostena core user list`.
pub(crate) fn user_list(path: &Path) -> ExitCode {
    init_admin_logging(path);
    done(
        admin(path, async |pool| {
            let users = inventory::list_users(&pool).await?;
            let mut rows = Vec::with_capacity(users.len());
            for u in users {
                let state = credential::state(&pool, u.id).await?;
                rows.push((u, state));
            }
            Ok(rows)
        })
        .map(|rows| {
            let mut out =
                String::from("utilisateur\tnom\tnom affiché\tétat\tmot de passe\ttotp\tverrouillé");
            for (u, c) in rows {
                let yes = |b: bool| if b { "oui" } else { "non" };
                let totp = if c.totp_pending {
                    "en attente"
                } else {
                    yes(c.totp)
                };
                let locked = c
                    .locked_until
                    .map_or_else(|| "-".to_owned(), ostena_common::logging::utc_text);
                let _ = write!(
                    out,
                    "\n{}\t{}\t{}\t{}\t{}\t{totp}\t{locked}",
                    u.id,
                    u.name,
                    u.display_name,
                    u.state,
                    yes(c.password)
                );
            }
            out
        }),
    )
}

/// `ostena core user disable`: also revokes their login sessions.
pub(crate) fn user_disable(path: &Path, name: &str) -> ExitCode {
    init_admin_logging(path);
    done(admin(path, async move |pool| {
        inventory::disable_user(&pool, name)
            .await
            .map(|n| format!("{name} désactivé, {n} session(s) de connexion révoquée(s)"))
    }))
}

/// `ostena core user role-grant|role-revoke`: a role of the portal
/// (ADR-0020).
pub(crate) fn user_role(path: &Path, name: &str, role: &str, grant: bool) -> ExitCode {
    init_admin_logging(path);
    let Some(role) = Role::parse(role) else {
        return fail(&format!(
            "rôle « {} » inconnu : admin attendu",
            role.escape_debug()
        ));
    };
    done(admin_core(path, async move |pool, core| {
        let changed = if grant {
            let separation = ostena_core::policy::separation(&core.admin);
            inventory::grant_role(&pool, name, role, separation).await?
        } else {
            inventory::revoke_role(&pool, name, role).await?
        };
        let roles = inventory::user_roles(&pool, name).await?;
        let list: Vec<_> = roles.iter().map(|r| r.as_str()).collect();
        let what = match (grant, changed) {
            (true, true) => "rôle accordé",
            (true, false) => "rôle déjà accordé",
            (false, true) => "rôle retiré",
            (false, false) => "rôle déjà absent",
        };
        Ok(format!("{name} : {what} ; rôles : {}", list.join(", ")))
    }))
}

/// `ostena core resource add`: the pinned host key comes from the
/// `ssh_host_ecdsa_key.pub` file of the target; prints the identifier.
pub(crate) fn resource_add(
    path: &Path,
    name: &str,
    host: &str,
    port: u16,
    group: &str,
    host_key: &Path,
) -> ExitCode {
    init_admin_logging(path);
    let key = match std::fs::read_to_string(host_key)
        .map_err(|e| e.to_string())
        .and_then(|line| inventory::parse_host_key(&line).map_err(|e| e.to_string()))
    {
        Ok(key) => key,
        Err(e) => return fail(&format!("{} : {e}", host_key.display())),
    };
    done(admin(path, async move |pool| {
        inventory::add_resource(&pool, name, host, port, group, &key)
            .await
            .map(|id| id.to_string())
    }))
}

/// `ostena core resource list`.
pub(crate) fn resource_list(path: &Path) -> ExitCode {
    init_admin_logging(path);
    done(
        admin(path, async |pool| inventory::list_resources(&pool).await).map(|resources| {
            let mut out = String::from("ressource\tnom\tcible\tgroupe\tclé épinglée\tcomptes");
            for r in resources {
                let _ = write!(
                    out,
                    "\n{}\t{}\t{}:{}\t{}\t{}\t{}",
                    r.id,
                    r.name,
                    r.host,
                    r.port,
                    r.group,
                    if r.host_key_pinned { "oui" } else { "non" },
                    if r.accounts.is_empty() {
                        "-".to_owned()
                    } else {
                        r.accounts.join(",")
                    }
                );
            }
            out
        }),
    )
}

/// `ostena core account add`.
pub(crate) fn account_add(path: &Path, resource: &str, account: &str) -> ExitCode {
    init_admin_logging(path);
    done(admin(path, async move |pool| {
        inventory::add_account(&pool, resource, account)
            .await
            .map(|id| id.to_string())
    }))
}

/// `ostena core right grant`: SSH, for `days` (1 to 366), sessions of at
/// most `max_session_mins`, with the functions of `allow` (none by
/// default); prints the right identifier.
pub(crate) fn right_grant(
    path: &Path,
    user: &str,
    resource: &str,
    account: &str,
    days: u64,
    max_session_mins: u32,
    allow: &[String],
) -> ExitCode {
    init_admin_logging(path);
    if !(1..=366).contains(&days) {
        return fail("--days : 1 à 366 jours (la fin d'un droit est obligatoire)");
    }
    let functions = match Functions::parse(allow) {
        Ok(functions) => functions,
        Err(e) => return fail(&format!("--allow : {e}")),
    };
    let until = now() + days * DAY;
    let max = max_session_mins.saturating_mul(60);
    done(admin(path, async move |pool| {
        inventory::grant_right(&pool, user, resource, account, until, max, functions)
            .await
            .map(|id| id.to_string())
    }))
}

/// `ostena core right list`.
pub(crate) fn right_list(path: &Path) -> ExitCode {
    init_admin_logging(path);
    done(
        admin(path, async |pool| inventory::list_rights(&pool).await).map(|rights| {
            let mut out = String::from(
                "droit\tutilisateur\tcompte\tprotocole\tfin\tsession max (s)\tfonctions\trévoqué",
            );
            for r in rights {
                let _ = write!(
                    out,
                    "\n{}\t{}\t{}@{}\t{}\t{}\t{}\t{}\t{}",
                    r.id,
                    r.user,
                    r.account,
                    r.resource,
                    r.protocol,
                    r.valid_until,
                    r.max_session_secs,
                    r.functions.label(),
                    if r.revoked { "oui" } else { "non" }
                );
            }
            out
        }),
    )
}

/// `ostena core right revoke`.
pub(crate) fn right_revoke(path: &Path, right: &str) -> ExitCode {
    init_admin_logging(path);
    let Some(right) = Uuid::parse(right) else {
        return fail("identifiant de droit : UUID attendu (minuscules, forme canonique)");
    };
    done(admin(path, async move |pool| {
        inventory::revoke_right(&pool, right)
            .await
            .map(|()| String::new())
    }))
}

/// `account@resource`, split at its last `@`.
fn account_at(value: &str) -> Result<(&str, &str), String> {
    value
        .rsplit_once('@')
        .filter(|(a, r)| !a.is_empty() && !r.is_empty())
        .map(|(account, resource)| (resource, account))
        .ok_or_else(|| format!("compte « {value} » : account@resource attendu"))
}

/// The arguments of `ostena core rule create`.
pub(crate) struct RuleArgs<'a> {
    pub(crate) config: &'a Path,
    pub(crate) user: Option<&'a str>,
    pub(crate) user_group: Option<&'a str>,
    pub(crate) account: Option<&'a str>,
    pub(crate) account_group: Option<&'a str>,
    pub(crate) protocols: &'a [String],
    pub(crate) deny: bool,
    pub(crate) deny_functions: &'a [String],
    pub(crate) days: Option<u64>,
    pub(crate) max_session_mins: u32,
    pub(crate) allow: &'a [String],
}

/// The rule asked by `args`, checked as far as the command line can.
fn new_rule<'a>(args: &RuleArgs<'a>, now: u64) -> Result<inventory::NewRule<'a>, String> {
    let subject = match (args.user, args.user_group) {
        (Some(user), None) => inventory::RuleSubject::User(user),
        (None, Some(group)) => inventory::RuleSubject::Group(group),
        _ => return Err("--user ou --user-group, l'un des deux".into()),
    };
    let target = match (args.account, args.account_group) {
        (Some(account), None) => {
            let (resource, account) = account_at(account)?;
            inventory::RuleTarget::Account { resource, account }
        }
        (None, Some(group)) => inventory::RuleTarget::Group(group),
        _ => return Err("--account ou --account-group, l'un des deux".into()),
    };
    let protocols = if args.protocols.is_empty() {
        vec![ostena_policy::Protocol::Ssh]
    } else {
        args.protocols
            .iter()
            .map(|p| {
                ostena_policy::Protocol::parse(p)
                    .ok_or_else(|| format!("--protocol « {p} » : ssh, rdp, vnc ou web"))
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    let effect = if args.deny {
        inventory::RuleEffect::Deny
    } else if !args.deny_functions.is_empty() {
        inventory::RuleEffect::DenyFunctions(
            Functions::parse(args.deny_functions).map_err(|e| format!("--deny-function : {e}"))?,
        )
    } else {
        inventory::RuleEffect::Allow {
            functions: Functions::parse(args.allow).map_err(|e| format!("--allow : {e}"))?,
            max_session_secs: args.max_session_mins.saturating_mul(60),
        }
    };
    let valid_until = match args.days {
        Some(days) if (1..=366).contains(&days) => Some(now + days * DAY),
        Some(_) => return Err("--days : 1 à 366 jours".into()),
        None => None,
    };
    Ok(inventory::NewRule {
        subject,
        target,
        protocols,
        effect,
        valid_until,
    })
}

/// `ostena core rule create`: prints the rule identifier.
pub(crate) fn rule_create(args: &RuleArgs<'_>) -> ExitCode {
    init_admin_logging(args.config);
    let rule = match new_rule(args, now()) {
        Ok(rule) => rule,
        Err(e) => return fail(&e),
    };
    done(admin(args.config, async move |pool| {
        inventory::create_rule(&pool, &rule)
            .await
            .map(|id| id.to_string())
    }))
}

/// `ostena core rule list`.
pub(crate) fn rule_list(path: &Path) -> ExitCode {
    init_admin_logging(path);
    done(
        admin(path, async |pool| inventory::list_rules(&pool).await).map(|rules| {
            let mut out = String::from(
                "règle	sujet	cible	protocoles	effet	fonctions	session max (s)	fin	révoquée",
            );
            for r in rules {
                let _ = write!(
                    out,
                    "\n{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    r.id,
                    r.subject,
                    r.target,
                    r.protocols.join(","),
                    r.effect,
                    r.functions.label(),
                    r.max_session_secs
                        .map_or_else(|| "-".into(), |s| s.to_string()),
                    r.valid_until.map_or_else(|| "-".into(), |u| u.to_string()),
                    if r.revoked { "oui" } else { "non" }
                );
            }
            out
        }),
    )
}

/// `ostena core rule revoke`.
pub(crate) fn rule_revoke(path: &Path, rule: &str) -> ExitCode {
    init_admin_logging(path);
    let Some(rule) = Uuid::parse(rule) else {
        return fail("identifiant de règle : UUID attendu (minuscules, forme canonique)");
    };
    done(admin(path, async move |pool| {
        inventory::revoke_rule(&pool, rule)
            .await
            .map(|()| String::new())
    }))
}

/// `ostena core account-group create`: prints the group identifier.
pub(crate) fn account_group_create(path: &Path, name: &str) -> ExitCode {
    init_admin_logging(path);
    done(admin(path, async move |pool| {
        inventory::create_account_group(&pool, name)
            .await
            .map(|id| id.to_string())
    }))
}

/// `ostena core account-group add|remove`.
pub(crate) fn account_group_member(path: &Path, group: &str, account: &str, add: bool) -> ExitCode {
    init_admin_logging(path);
    let (resource, account) = match account_at(account) {
        Ok(parts) => parts,
        Err(e) => return fail(&e),
    };
    done(admin(path, async move |pool| {
        let changed = if add {
            inventory::add_account_group_member(&pool, group, resource, account).await?
        } else {
            inventory::remove_account_group_member(&pool, group, resource, account).await?
        };
        Ok(if changed {
            String::new()
        } else if add {
            "déjà membre".into()
        } else {
            "pas membre".into()
        })
    }))
}

/// `ostena core account-group list`.
pub(crate) fn account_group_list(path: &Path) -> ExitCode {
    init_admin_logging(path);
    done(
        admin(path, async |pool| {
            inventory::list_account_groups(&pool).await
        })
        .map(|groups| {
            let mut out = String::from("groupe	comptes");
            for (name, members) in groups {
                let _ = write!(out, "\n{name}\t{}", members.join(","));
            }
            out
        }),
    )
}

/// `ostena core login revoke`: the agents concerned cut its SSH sessions.
pub(crate) fn login_revoke(path: &Path, session: &str, reason: &str) -> ExitCode {
    init_admin_logging(path);
    let Some(session) = Uuid::parse(session) else {
        return fail("session de connexion : UUID attendu (minuscules, forme canonique)");
    };
    done(admin(path, async move |pool| {
        login::revoke_session(&pool, session, reason)
            .await
            .map(|()| String::new())
    }))
}

/// `ostena core access check`: a dry run of the decision, without login
/// session; nothing is written, not even to the audit chain. Exit code 1
/// if the access would be refused.
pub(crate) fn access_check(path: &Path, user: &str, resource: &str, account: &str) -> ExitCode {
    init_admin_logging(path);
    let outcome = admin(path, async move |pool| {
        Ok(access::check(&pool, user, resource, account, now()).await)
    });
    match outcome {
        Ok(Ok(allowed)) => {
            let _ = writeln!(
                io::stdout(),
                "autorisé\trègle {}\tgroupe {}\tcible {}:{}\tsession max {} s\tfonctions {}",
                allowed.rule,
                allowed.group,
                allowed.host,
                allowed.port,
                allowed.max_session_secs,
                allowed.functions.label()
            );
            ExitCode::SUCCESS
        }
        Ok(Err(refusal)) => fail(&format!("refusé\t{}\t{}", refusal.code, refusal.reason)),
        Err(e) => fail(&e),
    }
}
