//! `ostena core`: the core, a Linux component (ADR-0011).
//!
//! - `run` connects to PostgreSQL (Unix socket, `peer`), applies the
//!   embedded migrations and serves the tunnel and enrolment listeners;
//! - `migrate` applies or checks the migrations;
//! - `agent token|list|revoke` administer the registry, in the database,
//!   while the core runs: it is notified and applies the change at once.

use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use ostena_common::config::{self, Config, CoreConfig, LoggingConfig};
use ostena_core::cache::AgentCache;
use ostena_core::schema::{self, SchemaState};
use ostena_core::server::{self, Keys, RunningCore};
use ostena_core::store::{self, PgStore};
use ostena_core::{CoreError, db};
use ostena_platform::private_file::{self, Reader};
use ostena_tunnel::Uuid;

fn fail(text: &str) -> ExitCode {
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

/// The validated configuration and its `[core]` section; weakenings and
/// waivers are logged.
fn load(path: &Path) -> Result<(Config, CoreConfig), String> {
    let loaded = config::load_with(path, ostena_platform::permission_checker())
        .map_err(|e| e.to_string())?;
    loaded.log_weakenings();
    let core = loaded
        .config
        .core
        .clone()
        .ok_or_else(|| format!("section [core] absente de {}", path.display()))?;
    Ok((loaded.config, core))
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
fn init_admin_logging(path: &Path) {
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
    let (config, core) = match load(path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(event = "core.config_refused", "{e}");
            return ExitCode::FAILURE;
        }
    };
    let rt = match runtime(core.worker_threads()) {
        Ok(rt) => rt,
        Err(e) => return fail(&e),
    };
    match rt.block_on(serve(&config, &core)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(event = "core.start_failed", code = e.code(), "{e}");
            ExitCode::FAILURE
        }
    }
}

async fn serve(config: &Config, core: &CoreConfig) -> Result<(), CoreError> {
    let keys = Keys::load(core, server::credentials_directory().as_deref())?;
    let pool = db::connect(&core.database, config.mode).await?;
    schema::migrate(&pool).await?;
    let store = PgStore::new(pool, Arc::new(AgentCache::default()));
    let running = RunningCore::start(core, store, &keys).await?;
    ostena_platform::service::notify("READY=1");
    crate::agent::wait_for_signals().await;
    ostena_platform::service::notify("STOPPING=1");
    running.stop();
    Ok(())
}

/// Runs an administration task against the database of `path`, on a small
/// runtime; the schema must be the one of this binary.
fn admin<T>(
    path: &Path,
    task: impl AsyncFnOnce(db::Pool) -> Result<T, CoreError>,
) -> Result<T, String> {
    let (config, core) = load(path)?;
    let rt = runtime(1)?;
    rt.block_on(async {
        let pool = db::connect(&core.database, config.mode).await?;
        schema::require_up_to_date(&pool).await?;
        task(pool).await
    })
    .map_err(|e| e.to_string())
}

/// `ostena core migrate [--check]`.
pub(crate) fn migrate(path: &Path, check: bool) -> ExitCode {
    init_admin_logging(path);
    let outcome = load(path).and_then(|(config, core)| {
        runtime(1)?
            .block_on(async {
                let pool = db::connect(&core.database, config.mode).await?;
                if check {
                    schema::state(&pool).await
                } else {
                    schema::migrate(&pool).await?;
                    Ok(SchemaState::UpToDate)
                }
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
