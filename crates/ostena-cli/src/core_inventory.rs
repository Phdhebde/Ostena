//! `ostena core group|user|resource|account|right|login|access`: the
//! minimal inventory and the SSH authorisation (ADR-0014), administered in
//! the database while the core runs; it is notified of what concerns the
//! agents (policy, SSH host names, login revocations) and applies it at
//! once. Every change is written to the audit chain.

use std::fmt::Write as _;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use ostena_common::config::scope::PolicySpec;
use ostena_core::{access, inventory, login};
use ostena_tunnel::Uuid;

use crate::core::{admin, fail, init_admin_logging};

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
        admin(path, async |pool| inventory::list_users(&pool).await).map(|users| {
            let mut out = String::from("utilisateur\tnom\tnom affiché\tétat");
            for u in users {
                let _ = write!(
                    out,
                    "\n{}\t{}\t{}\t{}",
                    u.id, u.name, u.display_name, u.state
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
/// most `max_session_mins`; prints the right identifier.
pub(crate) fn right_grant(
    path: &Path,
    user: &str,
    resource: &str,
    account: &str,
    days: u64,
    max_session_mins: u32,
) -> ExitCode {
    init_admin_logging(path);
    if !(1..=366).contains(&days) {
        return fail("--days : 1 à 366 jours (la fin d'un droit est obligatoire)");
    }
    let until = now() + days * DAY;
    let max = max_session_mins.saturating_mul(60);
    done(admin(path, async move |pool| {
        inventory::grant_right(&pool, user, resource, account, until, max)
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
                "droit\tutilisateur\tcompte\tprotocole\tfin\tsession max (s)\trévoqué",
            );
            for r in rights {
                let _ = write!(
                    out,
                    "\n{}\t{}\t{}@{}\t{}\t{}\t{}\t{}",
                    r.id,
                    r.user,
                    r.account,
                    r.resource,
                    r.protocol,
                    r.valid_until,
                    r.max_session_secs,
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
                "autorisé\tdroit {}\tgroupe {}\tcible {}:{}\tsession max {} s",
                allowed.right,
                allowed.group,
                allowed.host,
                allowed.port,
                allowed.max_session_secs
            );
            ExitCode::SUCCESS
        }
        Ok(Err(refusal)) => fail(&format!("refusé\t{}\t{}", refusal.code, refusal.reason)),
        Err(e) => fail(&e),
    }
}
