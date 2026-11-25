//! `ostena core user set-password|totp-enroll|totp-reset|unlock`: the local
//! credentials of `ostena login` (ADR-0009, amendment of 2026-11-25;
//! ADR-0010), administered in the database while the core runs. Every
//! change is written to the audit chain.

use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use ostena_common::secret::SecretString;
use ostena_core::credential;
use ostena_core::server;

use crate::core::{admin, admin_core, fail, init_admin_logging};

fn done(outcome: Result<String, String>) -> ExitCode {
    match outcome {
        Ok(text) => {
            let _ = writeln!(io::stdout(), "{text}");
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}

fn input(e: &io::Error) -> String {
    format!("saisie : {e}")
}

/// The new password: from standard input with `stdin`, else typed twice
/// without echo.
fn new_password(stdin: bool) -> Result<SecretString, String> {
    if stdin {
        return ostena_platform::tty::read_stdin_line().map_err(|e| input(&e));
    }
    let first =
        ostena_platform::tty::read_hidden("Nouveau mot de passe : ").map_err(|e| input(&e))?;
    let second = ostena_platform::tty::read_hidden("Confirmation : ").map_err(|e| input(&e))?;
    // SECRET-EXPOSURE: both entries compared, never kept.
    #[expect(clippy::disallowed_methods)]
    let same = first.expose_secret() == second.expose_secret();
    if same {
        Ok(first)
    } else {
        Err("les deux saisies diffèrent".into())
    }
}

/// `ostena core user set-password`.
pub(crate) fn set_password(path: &Path, name: &str, stdin: bool) -> ExitCode {
    init_admin_logging(path);
    let password = match new_password(stdin).and_then(|p| {
        credential::check_password(&p)
            .map(|()| p)
            .map_err(|e| e.to_string())
    }) {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    done(admin(path, async move |pool| {
        credential::set_password(&pool, name, password)
            .await
            .map(|()| format!("mot de passe de {name} enregistré"))
    }))
}

/// `ostena core user totp-enroll`: a new pending secret, shown once; with
/// `confirm`, the code of the application activates it.
pub(crate) fn totp_enroll(path: &Path, name: &str, confirm: bool, stdin: bool) -> ExitCode {
    init_admin_logging(path);
    let code = if confirm {
        let read = if stdin {
            ostena_platform::tty::read_stdin_line()
        } else {
            ostena_platform::tty::read_visible("Code affiché par l'application : ")
        };
        match read {
            Ok(code) => Some(code),
            Err(e) => return fail(&input(&e)),
        }
    } else {
        None
    };
    done(admin_core(path, async move |pool, core| {
        let key = server::load_totp_key(&core, server::credentials_directory().as_deref())?;
        if let Some(code) = code {
            credential::confirm_totp(&pool, &key, name, &code).await?;
            return Ok(format!("TOTP de {name} activé"));
        }
        let login = core
            .login
            .as_ref()
            .ok_or_else(|| ostena_core::CoreError::Keys("section [core.login] absente".into()))?;
        let algorithm = credential::algorithm_of(login.totp_algorithm);
        let secret = credential::enroll_totp(&pool, &key, name, algorithm).await?;
        let uri = secret
            .provisioning_uri(&login.totp_issuer, name)
            .map_err(|e| ostena_core::CoreError::Invalid(e.to_string()))?;
        let base32 = secret.base32();
        // SECRET-EXPOSURE: shown once to the administrator, who hands it to
        // the user for their authenticator application.
        #[expect(clippy::disallowed_methods)]
        let shown = format!(
            "Secret TOTP de {name} ({}, 6 chiffres, 30 s), à saisir une seule fois dans \
             l'application d'authentification, puis à effacer de l'écran :\n  {}\n  clé : {}\n\
             Ensuite : ostena core user totp-enroll {name} --confirm",
            algorithm.as_str(),
            uri.expose_secret(),
            base32.expose_secret()
        );
        Ok(shown)
    }))
}

/// `ostena core user totp-reset`.
pub(crate) fn totp_reset(path: &Path, name: &str) -> ExitCode {
    init_admin_logging(path);
    done(admin(path, async move |pool| {
        credential::reset_totp(&pool, name).await.map(|()| {
            format!("TOTP de {name} retiré : connexion refusée jusqu'à un nouvel enrôlement")
        })
    }))
}

/// `ostena core user unlock`.
pub(crate) fn unlock(path: &Path, name: &str) -> ExitCode {
    init_admin_logging(path);
    done(admin(path, async move |pool| {
        credential::unlock(&pool, name)
            .await
            .map(|()| format!("{name} déverrouillé"))
    }))
}
