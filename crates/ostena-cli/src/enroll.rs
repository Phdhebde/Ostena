//! `ostena agent enroll`: first contact of the agent with the core
//! (ADR-0008).
//!
//! The key is generated here and written (mode 0600 on Unix) before any
//! network exchange; only its public half and a proof of possession leave the
//! machine. The token is read from a file or standard input, never from the
//! command line. Existing key or certificate files are never overwritten.

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
use ostena_tunnel::Uuid;
use ostena_tunnel::enroll::{EnrollParams, EnrollmentToken, enroll};

fn fail(text: &str) -> ExitCode {
    let _ = writeln!(io::stderr(), "{text}");
    ExitCode::FAILURE
}

fn create(path: &Path, bytes: &[u8], secret: bool) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = secret;
    let mut file = options
        .open(path)
        .map_err(|e| format!("{} : {e}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("{} : {e}", path.display()))
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
    for path in [&agent.tls_certificate, &agent.tls_private_key] {
        if path.exists() {
            return Err(format!(
                "{} existe déjà : l'agent est déjà enrôlé. Pour le ré-enrôler, retirez la clé et le \
                 certificat après avoir révoqué l'ancien sur le core.",
                path.display()
            ));
        }
    }
    let group = Uuid::parse(&agent.gateway_group).ok_or("agent.gateway_group invalide")?;
    let token = read_token(token)?;

    // The key exists on disk, protected, before anything is sent.
    let (key, pkcs8) = SigningKey::generate().map_err(|e| e.to_string())?;
    // SECRET-EXPOSURE: written once to a new 0600 file.
    #[expect(clippy::disallowed_methods)]
    create(
        &agent.tls_private_key,
        pem_private_key(&pkcs8).expose_secret(),
        true,
    )?;

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
    let enrolled = match result {
        Ok(e) => e,
        Err(e) => {
            // Unused key: removed so that a new attempt starts clean.
            let _ = fs::remove_file(&agent.tls_private_key);
            return Err(e);
        }
    };
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
