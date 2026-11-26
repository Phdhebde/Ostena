//! `ostena config ssh`: `Host` aliases for the SSH accesses the user holds
//! now, so that `ssh srv-lab01` stands for `ssh root@srv-lab01@bastion`.
//!
//! The list comes from the core (`POST /v1/ssh-hosts`), signed by the key
//! of the session like a logout. It is written to `~/.ostena/ssh_hosts`,
//! which the `ssh_config` fragment of `ostena login` includes. Each access
//! gets the alias `<account>.<resource>`, and `<resource>` too when it is
//! the only account of the resource. Each alias repeats the options of the
//! fragment (key, `known_hosts`, frozen algorithms, no forwarding by
//! default), since OpenSSH applies a `Host` block by the name typed, not by
//! the `HostName` it leads to.

use std::fmt::Write as _;
use std::path::Path;
use std::process::ExitCode;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hyper::StatusCode;
use hyper::body::Bytes;
use ostena_common::api::login::{self, SSH_HOSTS_PATH, SshHostsRequest, SshHostsResponse};
use ostena_common::logging::utc_text;
use ostena_common::secret::SecretBytes;
use ostena_ssh::cert;

use super::{
    CERTIFICATE, KEY, LoginError, ROOT, SSH_HOSTS, directory, fail, files, options, post,
    read_root, read_settings, refusal, runtime, say, unix_now, write_private,
};

/// An account usable in an alias and as the `User` of `ssh_config`: no
/// character OpenSSH would read as a separator, a quote, a comment or a
/// `%` token.
fn plain_account(account: &str) -> bool {
    !account.is_empty()
        && account
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// The `ssh_hosts` file for `response`, and the accesses left out (their
/// account cannot be written in `ssh_config`).
pub(crate) fn hosts_file(
    dir: &Path,
    response: &SshHostsResponse,
    now: u64,
) -> Result<(String, Vec<String>), LoginError> {
    let options = options(dir, response.ssh_port)?;
    let mut out = format!(
        "# Écrit par ostena config ssh le {}, réécrit à chaque appel.\n\
         # Les droits peuvent changer : relancez ostena config ssh.\n",
        utc_text(now)
    );
    let mut skipped = Vec::new();
    for access in &response.accesses {
        if !plain_account(&access.account) {
            skipped.push(format!("{}@{}", access.account, access.resource));
            continue;
        }
        let alone = response
            .accesses
            .iter()
            .filter(|a| a.resource == access.resource)
            .count()
            == 1;
        let mut aliases = format!("{}.{}", access.account, access.resource);
        if alone {
            aliases = format!("{} {aliases}", access.resource);
        }
        let _ = write!(
            out,
            "\n# Droit valable jusqu'au {until}.\n\
             Host {aliases}\n\
             \x20   HostName {host}\n\
             \x20   User {account}@{resource}\n\
             {options}",
            until = utc_text(access.valid_until),
            host = access.host,
            account = access.account,
            resource = access.resource,
        );
    }
    Ok((out, skipped))
}

/// What `ostena config ssh` wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Written {
    /// Accesses written.
    pub(crate) written: usize,
    /// Accesses left out, `account@resource`.
    pub(crate) skipped: Vec<String>,
}

/// Asks the core for the accesses of the session of `dir` and writes
/// `ssh_hosts`.
///
/// # Errors
///
/// [`LoginError`].
pub(crate) async fn config_ssh_in(dir: &Path) -> Result<Written, LoginError> {
    let settings = read_settings(dir)?
        .ok_or_else(|| LoginError::Usage("aucune session : lancez d'abord ostena login".into()))?;
    let (root, _) = read_root(&dir.join(ROOT))?;
    let certificate_path = dir.join(CERTIFICATE);
    let line = std::fs::read_to_string(&certificate_path)
        .map_err(|e| files(&certificate_path, &e))?
        .trim()
        .to_owned();
    let blob = line
        .split(' ')
        .nth(1)
        .and_then(|b| STANDARD.decode(b).ok())
        .ok_or_else(|| LoginError::Certificate("ligne OpenSSH illisible".into()))?;
    let parsed = cert::parse(&blob).map_err(|e| LoginError::Certificate(e.to_string()))?;
    let now = unix_now();
    if parsed.valid_before <= now {
        return Err(LoginError::Usage(
            "session expirée : relancez ostena login".into(),
        ));
    }
    let session = parsed.key_id.to_owned();
    let key_path = dir.join(KEY);
    let key_file = SecretBytes::from(std::fs::read(&key_path).map_err(|e| files(&key_path, &e))?);
    let (key, _) = ostena_ssh::keys::decode(&key_file)
        .map_err(|e| LoginError::Files(format!("{} : {e}", key_path.display())))?;
    if key.verifying_key() != parsed.public {
        return Err(LoginError::Certificate(
            "le certificat ne correspond pas à la clé".into(),
        ));
    }
    let signature = key
        .sign(&login::ssh_hosts_message(&session, now))
        .map_err(|e| LoginError::Usage(e.to_string()))?;
    let request = SshHostsRequest {
        protocol: login::PROTOCOL,
        login_session: session,
        certificate: line,
        issued_at: now,
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    };
    let body = serde_json::to_vec(&request).map_err(|e| LoginError::Usage(e.to_string()))?;
    // No secret: signed, bound to its session and its time.
    let (status, answer) = post(
        &settings.core,
        &root,
        SSH_HOSTS_PATH,
        Bytes::from(body),
        login::MAX_HOSTS_BODY,
    )
    .await?;
    if status != StatusCode::OK {
        return Err(refusal(status, &answer));
    }
    let response =
        SshHostsResponse::parse(&answer).map_err(|e| LoginError::Response(e.to_string()))?;
    let (text, skipped) = hosts_file(dir, &response, now)?;
    write_private(dir, SSH_HOSTS, text.as_bytes())?;
    Ok(Written {
        written: response.accesses.len() - skipped.len(),
        skipped,
    })
}

/// `ostena config ssh`.
pub(crate) fn config_ssh(dir: Option<&Path>) -> ExitCode {
    let run = || -> Result<(Written, std::path::PathBuf), LoginError> {
        let dir = directory(dir)?;
        let written = runtime()
            .map_err(|e| LoginError::Usage(e.to_string()))?
            .block_on(config_ssh_in(&dir))?;
        Ok((written, dir))
    };
    match run() {
        Ok((written, dir)) => {
            say(&format!(
                "{} accès écrits dans {} (inclus par le fragment d'ostena login).",
                written.written,
                dir.join(SSH_HOSTS).display()
            ));
            for access in &written.skipped {
                say(&format!(
                    "Non écrit (compte inutilisable dans ssh_config) : {access} ; utilisez \
                     ssh compte@ressource@bastion."
                ));
            }
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}
