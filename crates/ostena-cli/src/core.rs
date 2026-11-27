//! `ostena core`: the core, a Linux component (ADR-0011).
//!
//! - `run` connects to PostgreSQL (Unix socket, `peer`) as the service
//!   role, checks the schema and the roles, and serves the tunnel and
//!   enrolment listeners;
//! - `migrate` applies, checks or reverts the migrations, as the owner of
//!   the schema;
//! - `db init` creates the roles and the database (ADR-0011);
//! - `agent token|list|revoke` administer the registry, in the database,
//!   while the core runs: it is notified and applies the change at once;
//! - `audit export|head|verify|acknowledge-break` read the audit chain in
//!   the database, or record an acknowledged break (ADR-0012).

use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use ostena_common::config::{self, Config, CoreConfig, DatabaseConfig, LoggingConfig};
use ostena_core::audit::{self as core_audit, ExportSummary};
use ostena_core::cache::AgentCache;
use ostena_core::db::Role;
use ostena_core::roles::{self, Logins};
use ostena_core::schema::{self, SchemaState};
use ostena_core::server::{self, Keys, RunningCore, StartInfo};
use ostena_core::store::{self, PgStore};
use ostena_core::{CoreError, db};
use ostena_platform::private_file::{self, Reader};
use ostena_tunnel::Uuid;

pub(crate) fn fail(text: &str) -> ExitCode {
    let _ = writeln!(io::stderr(), "{text}");
    ExitCode::FAILURE
}

fn runtime(threads: usize) -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()
        .map_err(|e| format!("runtime Tokio : {e}"))
}

/// A configuration loaded for the core.
struct Loaded {
    config: Config,
    core: CoreConfig,
    /// Weakenings and waivers in effect: (code, message).
    waivers: Vec<(String, String)>,
}

/// The validated configuration and its `[core]` section; weakenings and
/// waivers are logged.
fn load(path: &Path) -> Result<Loaded, String> {
    loaded(config::load_with(
        path,
        ostena_platform::permission_checker(),
    ))
}

/// [`load`] for `db init` and `migrate`, run under other accounts than the
/// service: its keys and transcripts, private to it, are not checked.
fn load_for_database(path: &Path) -> Result<Loaded, String> {
    loaded(config::load_for_database(
        path,
        ostena_platform::permission_checker(),
    ))
}

fn loaded(result: Result<config::LoadedConfig, config::ConfigError>) -> Result<Loaded, String> {
    let loaded = result.map_err(|e| e.to_string())?;
    loaded.log_weakenings();
    let core = loaded
        .config
        .core
        .clone()
        .ok_or_else(|| format!("section [core] absente de {}", loaded.path.display()))?;
    let waivers = loaded
        .weakenings
        .iter()
        .chain(&loaded.tolerated)
        .map(|v| (v.code.as_str().to_owned(), v.message.clone()))
        .collect();
    Ok(Loaded {
        config: loaded.config,
        core,
        waivers,
    })
}

/// Logging from the raw configuration if it parses, as the agent does.
fn init_logging(path: &Path) {
    let logging = crate::agent::read(path).map_or_else(|_| LoggingConfig::default(), |c| c.logging);
    if ostena_common::logging::init(&logging).is_err() {
        let _ = ostena_common::logging::init(&LoggingConfig::default());
    }
}

/// Logging of an administration command: the configured destinations but
/// standard output, which carries the result (a token, a listing); the
/// operator reads errors on standard error.
pub(crate) fn init_admin_logging(path: &Path) {
    let mut logging =
        crate::agent::read(path).map_or_else(|_| LoggingConfig::default(), |c| c.logging);
    logging
        .outputs
        .retain(|o| !matches!(o, config::Output::Stdout {}));
    if !logging.outputs.is_empty() {
        let _ = ostena_common::logging::init(&logging);
    }
}

/// `ostena core run`.
pub(crate) fn run(path: &Path) -> ExitCode {
    init_logging(path);
    let loaded = match load(path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(event = "core.config_refused", "{e}");
            return ExitCode::FAILURE;
        }
    };
    let rt = match runtime(loaded.core.worker_threads()) {
        Ok(rt) => rt,
        Err(e) => return fail(&e),
    };
    match rt.block_on(serve(loaded)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(event = "core.start_failed", code = e.code(), "{e}");
            ExitCode::FAILURE
        }
    }
}

async fn serve(loaded: Loaded) -> Result<(), CoreError> {
    let Loaded {
        config,
        core,
        waivers,
    } = loaded;
    let keys = Keys::load(&core, server::credentials_directory().as_deref())?;
    let pool = db::connect(&core.database, config.mode, Role::App).await?;
    // The core never migrates (ADR-0011): `ostena core migrate`, under the
    // administration account, does.
    schema::require_up_to_date(&pool).await?;
    roles::check_service(&pool).await?;
    enforce_roles(&pool, &core.database, config.mode).await?;
    let store = PgStore::new(pool, Arc::new(AgentCache::default()));
    let info = StartInfo { waivers };
    let stopped = crate::agent::wait_for_signals();
    let running = RunningCore::start(&core, store, &keys, &info).await?;
    ostena_platform::service::notify("READY=1");
    stopped.await;
    ostena_platform::service::notify("STOPPING=1");
    running.stop().await;
    Ok(())
}

/// Logs what weakens the separation of the roles (`core.database_role_weak`)
/// and refuses it in production (`CORE-E014`): the login role of the
/// service is a superuser, could take the owner role or create roles, or is
/// also the migration role.
async fn enforce_roles(
    pool: &db::Pool,
    database: &DatabaseConfig,
    mode: config::Mode,
) -> Result<(), CoreError> {
    let logins = Logins {
        service: &database.user,
        migration: &database.migration_user,
    };
    roles::enforce(pool, logins, mode).await
}

/// Runs an administration task against the database of `path`, on a small
/// runtime; the schema must be the one of this binary.
pub(crate) fn admin<T>(
    path: &Path,
    task: impl AsyncFnOnce(db::Pool) -> Result<T, CoreError>,
) -> Result<T, String> {
    let loaded = load(path)?;
    let rt = runtime(1)?;
    rt.block_on(async {
        let pool = db::connect(&loaded.core.database, loaded.config.mode, Role::App).await?;
        enforce_roles(&pool, &loaded.core.database, loaded.config.mode).await?;
        schema::require_up_to_date(&pool).await?;
        task(pool).await
    })
    .map_err(|e| e.to_string())
}

/// As [`admin`], with the `[core]` section of `path`.
pub(crate) fn admin_core<T>(
    path: &Path,
    task: impl AsyncFnOnce(db::Pool, CoreConfig) -> Result<T, CoreError>,
) -> Result<T, String> {
    let loaded = load(path)?;
    let rt = runtime(1)?;
    rt.block_on(async {
        let pool = db::connect(&loaded.core.database, loaded.config.mode, Role::App).await?;
        enforce_roles(&pool, &loaded.core.database, loaded.config.mode).await?;
        schema::require_up_to_date(&pool).await?;
        task(pool, loaded.core).await
    })
    .map_err(|e| e.to_string())
}

/// `ostena core migrate [--check | --revert-to <version>]`: as the owner
/// of the schema; what changed is written to the audit chain
/// (`core.migrated`, `core.migration_reverted`).
pub(crate) fn migrate(path: &Path, check: bool, revert_to: Option<i64>) -> ExitCode {
    init_admin_logging(path);
    let outcome = load_for_database(path).and_then(|loaded| {
        runtime(1)?
            .block_on(async {
                let pool =
                    db::connect(&loaded.core.database, loaded.config.mode, Role::Owner).await?;
                if check {
                    return schema::state(&pool).await;
                }
                let (versions, version, reverted) = match revert_to {
                    None => {
                        let applied = schema::migrate(&pool).await?;
                        (applied, schema::latest_version(), false)
                    }
                    Some(target) => (schema::revert(&pool, target).await?, target, true),
                };
                if !versions.is_empty() {
                    ostena_core::audit::record_migration(&pool, &versions, version, reverted)
                        .await?;
                }
                let _ = writeln!(
                    io::stdout(),
                    "schéma à la version {version}{}",
                    if versions.is_empty() {
                        String::new()
                    } else {
                        format!(
                            " ({} : {versions:?})",
                            if reverted { "retirées" } else { "appliquées" }
                        )
                    }
                );
                Ok(if reverted {
                    SchemaState::UpToDate
                } else {
                    schema::state(&pool).await?
                })
            })
            .map_err(|e| e.to_string())
    });
    match outcome {
        Ok(SchemaState::UpToDate) => ExitCode::SUCCESS,
        Ok(SchemaState::Pending(versions)) => {
            fail(&format!("migrations en attente : {versions:?}"))
        }
        Err(e) => fail(&e),
    }
}

/// `ostena core db init`: the roles, the database, and the objects an M1
/// installation left to the service account, as `superuser`.
pub(crate) fn db_init(path: &Path, superuser: &str) -> ExitCode {
    init_admin_logging(path);
    let outcome = load_for_database(path).and_then(|loaded| {
        runtime(1)?
            .block_on(async {
                let database = &loaded.core.database;
                let logins = Logins {
                    service: &database.user,
                    migration: &database.migration_user,
                };
                if loaded.config.mode == config::Mode::Production
                    && database.user == database.migration_user
                {
                    return Err(CoreError::RolesWeak(format!(
                        "{} sert au service et aux migrations : core.database.user et \
                         migration_user doivent désigner deux comptes distincts",
                        database.user
                    )));
                }
                let cluster = DatabaseConfig {
                    name: "postgres".into(),
                    user: superuser.into(),
                    max_connections: 1,
                    ..database.clone()
                };
                let pool = db::connect(&cluster, loaded.config.mode, Role::Login).await?;
                let mut changes = roles::init_cluster(&pool, logins).await?;
                changes.extend(roles::init_database(&pool, &database.name, logins).await?);
                pool.close().await;
                let target = DatabaseConfig {
                    name: database.name.clone(),
                    ..cluster
                };
                let pool = db::connect(&target, loaded.config.mode, Role::Login).await?;
                changes.extend(roles::adopt_m1_objects(&pool, &database.user).await?);
                let weak = roles::weaknesses(&pool, logins).await?;
                pool.close().await;
                Ok::<_, CoreError>((changes, weak, loaded.config.mode))
            })
            .map_err(|e| e.to_string())
    });
    match outcome {
        Ok((changes, weak, mode)) => {
            let mut stdout = io::stdout().lock();
            if changes.is_empty() {
                let _ = writeln!(stdout, "rôles et base déjà en place : rien à faire");
            }
            for change in &changes {
                tracing::info!(event = "core.database_initialized", change = %change);
                let _ = writeln!(stdout, "{change}");
            }
            for reason in &weak {
                tracing::warn!(event = "core.database_role_weak", reason = %reason);
                let _ = writeln!(io::stderr(), "attention : {reason}");
            }
            drop(stdout);
            if mode == config::Mode::Production && !weak.is_empty() {
                // The core would refuse to start on these roles.
                return fail(&CoreError::RolesWeak(weak.join(" ; ")).to_string());
            }
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}

/// `ostena core agent token`: the token goes to `out` (created with mode
/// 0600, never overwritten) or, with `-`, to standard output.
pub(crate) fn agent_token(path: &Path, group: &str, ttl_mins: u64, out: &Path) -> ExitCode {
    init_admin_logging(path);
    let Some(group) = Uuid::parse(group) else {
        return fail("--group : UUID attendu (minuscules, forme canonique)");
    };
    if out != Path::new("-") && out.exists() {
        return fail(&format!("{} existe déjà : jamais écrasé", out.display()));
    }
    let ttl = Duration::from_secs(ttl_mins.saturating_mul(60));
    let token = match admin(path, async move |pool| {
        store::issue_token(&pool, group, ttl).await
    }) {
        Ok(t) => t,
        Err(e) => return fail(&e),
    };
    let text = token.to_text();
    // SECRET-EXPOSURE: the token is handed to the operator once, to a private file or a pipe.
    #[expect(clippy::disallowed_methods)]
    let bytes = text.expose_secret();
    let written = if out == Path::new("-") {
        let mut stdout = io::stdout();
        stdout
            .write_all(bytes)
            .and_then(|()| stdout.write_all(b"\n"))
            .map_err(|e| e.to_string())
    } else {
        private_file::create(out, bytes, Reader::CurrentProcess)
            .map_err(|e| format!("{} : {e}", out.display()))
    };
    match written {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(&e),
    }
}

/// `ostena core agent list`: one line per agent.
pub(crate) fn agent_list(path: &Path) -> ExitCode {
    init_admin_logging(path);
    let agents = match admin(path, async |pool| store::list_agents(&pool).await) {
        Ok(a) => a,
        Err(e) => return fail(&e),
    };
    let mut stdout = io::stdout().lock();
    let _ = writeln!(stdout, "agent\tgroupe\tenrôlé\tcertificats\trévoqué");
    for a in agents {
        let _ = writeln!(
            stdout,
            "{}\t{}\t{}\t{}\t{}",
            a.id,
            a.group,
            a.enrolled_at,
            a.certificates,
            a.revoked_at.as_deref().unwrap_or("-")
        );
    }
    ExitCode::SUCCESS
}

/// `ostena core agent revoke`.
pub(crate) fn agent_revoke(path: &Path, agent: &str) -> ExitCode {
    init_admin_logging(path);
    let Some(agent) = Uuid::parse(agent) else {
        return fail("identifiant d'agent : UUID attendu (minuscules, forme canonique)");
    };
    match admin(path, async move |pool| {
        store::revoke_agent(&pool, agent).await
    }) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(&e),
    }
}

/// `ostena core audit export`: the chain, or its part after head
/// `from_head`, to `out` (created with mode 0600, never overwritten); then
/// records `audit.exported`.
pub(crate) fn audit_export(path: &Path, out: &Path, from_head: Option<u64>) -> ExitCode {
    init_admin_logging(path);
    if out.exists() {
        return fail(&format!("{} existe déjà : jamais écrasé", out.display()));
    }
    let target = out.to_path_buf();
    let outcome = admin(path, async move |pool| {
        let file = private_file::create_new(&target, Reader::CurrentProcess)
            .map_err(|e| CoreError::AuditWrite(format!("{} : {e}", target.display())))?;
        let written = core_audit::export(&pool, BufWriter::new(file), from_head).await;
        let summary = match written.and_then(|(writer, summary)| {
            let file = writer
                .into_inner()
                .map_err(|e| CoreError::AuditWrite(format!("{} : {e}", target.display())))?;
            file.sync_all()
                .map_err(|e| CoreError::AuditWrite(format!("{} : {e}", target.display())))?;
            Ok(summary)
        }) {
            Ok(summary) => summary,
            Err(e) => {
                // A partial export is of no use: never leave one behind.
                let _ = std::fs::remove_file(&target);
                return Err(e);
            }
        };
        core_audit::record_export(&pool, &summary).await?;
        Ok(summary)
    });
    match outcome {
        Ok(summary) => {
            let _ = writeln!(io::stdout(), "{}", export_line(out, &summary));
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}

fn export_line(out: &Path, summary: &ExportSummary) -> String {
    format!(
        "{}\tchaîne {}\tenregistrements {} (n° {} à {})\ttêtes {}",
        out.display(),
        summary.chain_id,
        summary.records,
        summary.first_seq,
        summary
            .last_seq
            .map_or_else(|| "-".to_owned(), |s| s.to_string()),
        summary.heads
    )
}

/// `ostena core audit head`: the last signed head, in text form, to keep
/// outside the bastion.
pub(crate) fn audit_head(path: &Path) -> ExitCode {
    init_admin_logging(path);
    match admin(path, async |pool| core_audit::last_head(&pool).await) {
        Ok(Some(head)) => {
            let _ = writeln!(io::stdout(), "{}", head.to_text());
            ExitCode::SUCCESS
        }
        Ok(None) => fail("aucune tête signée : le core n'a pas encore démarré"),
        Err(e) => fail(&e),
    }
}

/// `ostena core audit verify`: the whole chain in the database, with the
/// public keys of the signer. Exit codes of `ostena audit verify`.
pub(crate) fn audit_verify(
    path: &Path,
    keys: &[PathBuf],
    tsa_ca: &[PathBuf],
    json: bool,
) -> ExitCode {
    init_admin_logging(path);
    let trusted =
        crate::audit::read_keys(keys).and_then(|k| Ok((k, crate::audit::read_tsa(tsa_ca)?)));
    let (trusted, tsa) = match trusted {
        Ok(t) => t,
        Err(e) => {
            let _ = writeln!(io::stderr(), "ostena core audit : {e}");
            return ExitCode::from(crate::audit::USAGE_ERROR);
        }
    };
    match admin(path, async move |pool| {
        core_audit::verify_online(&pool, trusted, tsa).await
    }) {
        Ok(report) => {
            let label = Path::new("(base PostgreSQL du core)");
            let text = if json {
                crate::audit::json(label, &report)
            } else {
                crate::audit::summary(label, &report)
            };
            let _ = io::stdout().write_all(text.as_bytes());
            ExitCode::from(report.exit_code())
        }
        Err(e) => {
            let _ = writeln!(io::stderr(), "ostena core audit : {e}");
            ExitCode::from(crate::audit::USAGE_ERROR)
        }
    }
}

/// `ostena core audit acknowledge-break`: records that an administrator
/// acknowledged a break of the chain from record `seq`; the core then
/// resumes signing (see the break procedure).
pub(crate) fn audit_acknowledge_break(path: &Path, seq: u64) -> ExitCode {
    init_admin_logging(path);
    match admin(path, async move |pool| {
        core_audit::acknowledge_break(&pool, seq).await
    }) {
        Ok(appended) => {
            let _ = writeln!(
                io::stdout(),
                "rupture à partir de l'enregistrement n° {seq} reconnue (enregistrement n° {})",
                appended.seq
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}
