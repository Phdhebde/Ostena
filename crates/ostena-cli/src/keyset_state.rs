//! `ostena agent keyset-state repair`: resets an unreadable key set state
//! file (ADR-0008), after confirmation, the agent stopped.
//!
//! The damaged file is kept as `<file>.corrupt-<time>`, never modified. The
//! agent then accepts the key set version the core pushes at the next
//! connection, and none lower afterwards: the rollback protection resumes
//! from there. The operation is logged (`keyset_state.repaired`).

use std::io::{self, BufRead, Write};
use std::path::Path;
use std::process::ExitCode;

use ostena_common::config::{self, LoggingConfig};
use ostena_platform::control::{ControlListener, DEFAULT_ENDPOINT};
use ostena_tunnel::gateway::read_floor;

use crate::core_link::keyset_state;

/// What the operator types to confirm.
const CONFIRMATION: &str = "réinitialiser";

fn say(text: &str) {
    let _ = writeln!(io::stderr(), "{text}");
}

/// Asks for [`CONFIRMATION`] on standard input.
fn confirmed(path: &Path) -> bool {
    say(&format!(
        "{} est illisible.\nLe réinitialiser fait accepter à l'agent la version des clés de grant \
         que le core poussera à la prochaine connexion, quelle qu'elle soit ; la protection contre \
         le retour en arrière reprend ensuite à partir de cette version.\nVérifiez d'abord la \
         version courante côté core. Tapez « {CONFIRMATION} » pour confirmer :",
        path.display()
    ));
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line).is_ok() && line.trim() == CONFIRMATION
}

/// `ostena agent keyset-state repair`.
pub(crate) fn repair(config_path: &Path, yes: bool) -> ExitCode {
    if ostena_common::logging::init(&LoggingConfig::default()).is_err() {
        return ExitCode::FAILURE;
    }
    let failed = |e: &str| {
        tracing::error!(event = "keyset_state.repair_failed", "{e}");
        ExitCode::FAILURE
    };
    let config = match config::load_for_enrollment(config_path) {
        Ok(c) => c,
        Err(e) => return failed(&e.to_string()),
    };
    let Some(agent) = config.agent else {
        return failed("la configuration n'a pas de section [agent]");
    };
    let path = keyset_state(&agent);
    let endpoint = agent
        .control_endpoint
        .clone()
        .unwrap_or_else(|| DEFAULT_ENDPOINT.to_owned());
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => return failed(&e.to_string()),
    };
    // Holding the control endpoint proves the agent is stopped, and keeps it
    // from starting during the repair.
    let _guard = runtime.enter();
    let _control = match ControlListener::bind(&endpoint) {
        Ok(l) => l,
        Err(e) => {
            return failed(&format!(
                "l'agent semble en marche ({e}) : arrêtez-le avant la reprise"
            ));
        }
    };
    match read_floor(&path) {
        Ok(None) => {
            say(&format!(
                "{} n'existe pas : rien à réparer.",
                path.display()
            ));
            return ExitCode::SUCCESS;
        }
        Ok(Some(version)) => {
            return failed(&format!(
                "{} est lisible (version {version}) : rien à réparer, et il ne doit pas être \
                 réinitialisé",
                path.display()
            ));
        }
        Err(_) => {}
    }
    if !yes && !confirmed(&path) {
        return failed("reprise abandonnée : confirmation absente");
    }
    let now = ostena_grant::unix_now();
    let mut backup = path.as_os_str().to_owned();
    backup.push(format!(".corrupt-{now}"));
    let size = std::fs::metadata(&path).map_or(0, |m| m.len());
    if let Err(e) = std::fs::rename(&path, &backup) {
        return failed(&format!("{} : {e}", path.display()));
    }
    tracing::warn!(
        event = "keyset_state.repaired",
        path = %path.display(),
        backup = %Path::new(&backup).display(),
        size,
        "état des clés de grant réinitialisé ; l'original est conservé. L'agent acceptera la \
         version que le core poussera à la prochaine connexion"
    );
    ExitCode::SUCCESS
}
