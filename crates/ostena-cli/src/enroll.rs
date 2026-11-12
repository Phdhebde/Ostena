//! `ostena agent enroll`: first contact of the agent with the core
//! (ADR-0008).
//!
//! The key is generated here and written (mode 0600 on Unix) before any
//! network exchange; only its public half and a proof of possession leave the
//! machine. The token is read from a file or standard input, never from the
//! command line. A certificate is never overwritten; a key without a
//! certificate, left by a failed attempt, is reused.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use ostena_common::config::{self, AgentConfig};
use ostena_common::secret::SecretBytes;
use ostena_crypto::p256::SigningKey;
use ostena_crypto::pki::pem_private_key;
use ostena_crypto::tls::TrustAnchor;
use ostena_platform::private_file::{self, Reader};
use ostena_tunnel::Uuid;
use ostena_tunnel::enroll::{EnrollParams, EnrollmentToken, enroll};

fn fail(text: &str) -> ExitCode {
    let _ = writeln!(io::stderr(), "{text}");
    ExitCode::FAILURE
}

/// Creates a new file; the key is created with its final rights before any
/// byte is written (`ostena_platform::private_file`). A missing directory
/// (the state directory before `install`) is created, private.
fn create(path: &Path, bytes: &[u8], secret: bool) -> Result<(), String> {
    let failed = |e: io::Error| format!("{} : {e}", path.display());
    if let Some(dir) = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty() && !d.exists())
    {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(dir).map_err(failed)?;
    }
    if secret {
        return private_file::create(path, bytes, Reader::Service).map_err(failed);
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(failed)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(failed)
}

fn read_token(source: &Path) -> Result<EnrollmentToken, String> {
    let mut bytes = Vec::new();
    if source == Path::new("-") {
        io::stdin()
            .lock()
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
    } else {
        bytes = fs::read(source).map_err(|e| format!("{} : {e}", source.display()))?;
    }
    EnrollmentToken::parse(&SecretBytes::from(bytes)).map_err(|e| e.to_string())
}

/// `host:port` → (host for the certificate name, resolved address).
async fn resolve(address: &str) -> Result<(String, std::net::SocketAddr), String> {
    let host = address
        .rsplit_once(':')
        .map_or(address, |(h, _)| h)
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let resolved = tokio::net::lookup_host(address)
        .await
        .map_err(|e| format!("{address} : {e}"))?
        .next()
        .ok_or_else(|| format!("{address} : aucune adresse"))?;
    Ok((host, resolved))
}

/// `ostena agent enroll`.
pub(crate) fn enroll_agent(config_path: &Path, token: &Path, timeout_secs: u64) -> ExitCode {
    let config = match config::load_for_enrollment(config_path) {
        Ok(c) => c,
        Err(e) => return fail(&e.to_string()),
    };
    let Some(agent) = config.agent else {
        return fail("la configuration n'a pas de section [agent]");
    };
    match run(&agent, token, Duration::from_secs(timeout_secs.max(1))) {
        Ok(text) => {
            let _ = writeln!(io::stdout(), "{text}");
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}

fn run(agent: &AgentConfig, token: &Path, timeout: Duration) -> Result<String, String> {
    let root_path = agent
        .tls_core_ca
        .as_ref()
        .ok_or("agent.tls_core_ca absent : le certificat de la racine est nécessaire")?;
    let root = TrustAnchor::from_pem(
        &fs::read(root_path).map_err(|e| format!("{} : {e}", root_path.display()))?,
    )
    .map_err(|e| e.to_string())?;
    if agent.tls_certificate.exists() {
        return Err(format!(
            "{} existe déjà : l'agent est déjà enrôlé. Pour le ré-enrôler, retirez la clé et le \
             certificat après avoir révoqué l'ancien sur le core.",
            agent.tls_certificate.display()
        ));
    }
    let group = Uuid::parse(&agent.gateway_group).ok_or("agent.gateway_group invalide")?;
    let token = read_token(token)?;

    // The key exists on disk, protected, before anything is sent. A key
    // without a certificate is left by an attempt that failed: it is reused
    // (or recreated if unreadable), so that a new attempt is never blocked.
    let key = if let Some(key) = reuse_key(&agent.tls_private_key) {
        key
    } else {
        let (key, pkcs8) = SigningKey::generate().map_err(|e| e.to_string())?;
        // SECRET-EXPOSURE: written once, to a file created with its final rights.
        #[expect(clippy::disallowed_methods)]
        create(
            &agent.tls_private_key,
            pem_private_key(&pkcs8).expose_secret(),
            true,
        )?;
        key
    };

    let address = agent.enrollment_address();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let result = runtime.block_on(async {
        let (server_name, resolved) = resolve(&address).await?;
        enroll(&EnrollParams {
            address: resolved,
            server_name,
            root: &root,
            token: &token,
            gateway_group: group,
            key: &key,
            timeout,
        })
        .await
        .map_err(|e| e.to_string())
    });
    // On failure the key stays: the next attempt reuses it.
    let enrolled = result?;
    create(
        &agent.tls_certificate,
        enrolled.certificate.as_bytes(),
        false,
    )?;
    tracing::info!(
        event = "agent.enrolled",
        agent = %enrolled.agent_id,
        group = %group,
        not_after = enrolled.not_after,
    );
    Ok(format!(
        "Agent enrôlé : identifiant {}, groupe {group}.\nCertificat : {} (valide {} jours, renouvelé \
         automatiquement aux 2/3 de sa validité).\nClé privée : {} (ne quitte pas cette machine).",
        enrolled.agent_id,
        agent.tls_certificate.display(),
        enrolled.not_after.saturating_sub(enrolled.not_before) / 86_400,
        agent.tls_private_key.display()
    ))
}

/// A key left without a certificate by a failed attempt, if readable. An
/// unreadable one is removed, to be recreated.
fn reuse_key(path: &Path) -> Option<SigningKey> {
    let text = fs::read(path).ok()?;
    if let Ok(key) = ostena_crypto::pki::signing_key_from_pem(&SecretBytes::from(text)) {
        Some(key)
    } else {
        tracing::warn!(
            event = "agent.enroll_key_recreated",
            path = %path.display(),
            "clé sans certificat illisible : recréée"
        );
        let _ = fs::remove_file(path);
        None
    }
}
