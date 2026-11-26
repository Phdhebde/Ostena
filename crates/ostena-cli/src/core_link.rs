//! The agent's link to the core at startup (ADR-0008): resolution of the
//! Ostena component names (`CFG-P010`), then the tunnel kept up for the life
//! of the agent.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ostena_common::config::{AgentConfig, Mode, TunnelTransport};
use ostena_crypto::tls::TrustAnchor;
use ostena_platform::private_file::{self, Reader};
use ostena_scope::infrastructure::{self, Unresolved};
use ostena_scope::{InfrastructureSpec, LocalAddresses, SharedLocalAddresses, SystemResolver};
use ostena_tunnel::gateway::{Gateway, GatewayParams, GatewayState};
use ostena_tunnel::link::{AgentLink, Backoff, LinkParams, SystemClock};
use ostena_tunnel::{Hello, Limits, TransportMode, Uuid};

/// How often the component names are resolved again.
const INFRASTRUCTURE_REFRESH: Duration = Duration::from_mins(5);

/// Resolved Ostena components, shared with the scope control.
pub(crate) type Infrastructure = Arc<Mutex<Vec<InfrastructureSpec>>>;

fn resolver() -> SystemResolver {
    SystemResolver::new(Duration::from_secs(5), 8)
}

fn refused(e: &Unresolved) -> String {
    format!(
        "[CFG-P010] agent.infrastructure : {:?} « {} » non résolu ({}) ; le plancher ne peut pas \
         protéger ce composant",
        e.role, e.address, e.reason
    )
}

/// Resolves the component names. In production an unresolved name refuses
/// the start (`CFG-P010`); in development it is logged and skipped.
///
/// # Errors
///
/// The `CFG-P010` message, in production.
pub(crate) async fn resolve_infrastructure(
    agent: &AgentConfig,
    mode: Mode,
) -> Result<Infrastructure, String> {
    match infrastructure::resolve(&agent.infrastructure, &resolver()).await {
        Ok(specs) => Ok(Arc::new(Mutex::new(specs))),
        Err(e) if mode == Mode::Production => Err(refused(&e)),
        Err(e) => {
            tracing::warn!(
                event = "config.weakening",
                code = "CFG-P010",
                "{}",
                refused(&e)
            );
            Ok(Arc::new(Mutex::new(Vec::new())))
        }
    }
}

/// Resolves the names again every five minutes; a failed refresh keeps the
/// previous addresses, and the union keeps the old ones one more period.
pub(crate) fn refresh_infrastructure(
    agent: &AgentConfig,
    current: Infrastructure,
) -> tokio::task::JoinHandle<()> {
    let endpoints = agent.infrastructure.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(INFRASTRUCTURE_REFRESH).await;
            match infrastructure::resolve(&endpoints, &resolver()).await {
                Ok(fresh) => {
                    if let Ok(mut specs) = current.lock() {
                        let merged = infrastructure::union(&specs, &fresh);
                        if merged != *specs {
                            tracing::info!(event = "agent.infrastructure_refreshed");
                        }
                        *specs = merged;
                    }
                }
                Err(e) => tracing::warn!(
                    event = "agent.infrastructure_unresolved",
                    code = "CFG-P010",
                    "{} ; les adresses précédentes sont gardées",
                    refused(&e)
                ),
            }
        }
    })
}

/// The renewal writes next to the key and the certificate: their directory
/// must be writable by the agent account (the state directory). Says so at
/// startup rather than at the renewal, twenty days later.
fn check_renewable(agent: &AgentConfig) {
    for file in [&agent.tls_private_key, &agent.tls_certificate] {
        let Some(dir) = file.parent() else { continue };
        let probe = dir.join(".ostena-renewal-probe");
        let writable = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe)
            .is_ok();
        let _ = std::fs::remove_file(&probe);
        if !writable {
            tracing::warn!(
                event = "agent.renewal_impossible",
                path = %dir.display(),
                "le compte de l'agent ne peut pas écrire dans ce dossier : le certificat ne pourra \
                 pas être renouvelé. Placez la clé et le certificat dans le dossier d'état."
            );
        }
    }
}

/// Starts the link to the core, or explains why it cannot start (no core CA
/// configured, unreadable CA, invalid group).
///
/// # Errors
///
/// Why the link is not started.
pub(crate) fn start(agent: &AgentConfig, config_fingerprint: &str) -> Result<AgentLink, String> {
    let ca = agent
        .tls_core_ca
        .as_ref()
        .ok_or("agent.tls_core_ca absent : pas de lien avec le core")?;
    let pem = std::fs::read(ca).map_err(|e| format!("{} : {e}", ca.display()))?;
    let root = TrustAnchor::from_pem(&pem).map_err(|e| e.to_string())?;
    let gateway_group = Uuid::parse(&agent.gateway_group).ok_or("agent.gateway_group invalide")?;
    check_renewable(agent);
    Ok(AgentLink::spawn(LinkParams {
        core_address: agent.core_address.clone(),
        certificate: agent.tls_certificate.clone(),
        private_key: agent.tls_private_key.clone(),
        root,
        hello: Hello {
            agent_version: ostena_common::VERSION.to_owned(),
            gateway_group,
            config_fingerprint: config_fingerprint.to_owned(),
        },
        transport: match agent.transport {
            TunnelTransport::Auto => TransportMode::Auto,
            TunnelTransport::Quic => TransportMode::Quic,
            TunnelTransport::Tcp => TransportMode::Tcp,
        },
        limits: Limits::default(),
        backoff: Backoff::default(),
        clock: Arc::new(SystemClock),
        // The agent account reads its renewed key (the service, in
        // production).
        write_key: |path, bytes| private_file::create(path, bytes, Reader::CurrentProcess),
    }))
}

/// The state file of the key set version, next to the replay journal.
pub(crate) fn keyset_state(agent: &AgentConfig) -> PathBuf {
    agent
        .replay_journal
        .parent()
        .map_or_else(|| PathBuf::from(KEYSET_STATE), |d| d.join(KEYSET_STATE))
}

const KEYSET_STATE: &str = "keyset.version";

/// Applies what the core pushes on `link`: the policy, intersected with the
/// local one, and the grant keys, whose version never goes back.
///
/// # Errors
///
/// The key set state cannot be read, or the agent addresses cannot be
/// listed.
pub(crate) fn start_gateway(
    agent: &AgentConfig,
    mode: Mode,
    infrastructure: Infrastructure,
    link: Arc<AgentLink>,
) -> Result<Gateway, String> {
    let gateway_group = Uuid::parse(&agent.gateway_group).ok_or("agent.gateway_group invalide")?;
    let addresses = LocalAddresses::system().map_err(|e| format!("adresses de l'agent : {e}"))?;
    let state = GatewayState::open(GatewayParams {
        gateway_group,
        mode,
        local_policy: agent.scope_policy(),
        infrastructure,
        local_addresses: SharedLocalAddresses::new(addresses),
        keyset_state: keyset_state(agent),
        write_private: |path, bytes| private_file::create(path, bytes, Reader::CurrentProcess),
        grant_policy: ostena_grant::Policy::default(),
    })
    .map_err(|e| e.to_string())?;
    Gateway::start(Arc::new(state), link).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use ostena_common::config::Config;
    use std::future::Future;

    use super::*;

    fn agent(addresses: &str) -> AgentConfig {
        let text = format!(
            "[agent]\ngateway_group = \"2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6\"\n\
             core_address = \"core.invalid:8443\"\ntls_certificate = \"/a.crt\"\n\
             tls_private_key = \"/a.key\"\nreplay_journal = \"/j\"\n\
             [[agent.infrastructure]]\nrole = \"core\"\naddresses = [{addresses}]\n"
        );
        Config::from_toml_str(&text).unwrap().agent.unwrap()
    }

    fn block_on<F: Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn unresolved_component_refuses_production_only() {
        let unresolved = agent("\"core.example.invalid\"");
        let refused = block_on(resolve_infrastructure(&unresolved, Mode::Production));
        assert!(refused.unwrap_err().starts_with("[CFG-P010]"));
        let accepted = block_on(resolve_infrastructure(&unresolved, Mode::Development)).unwrap();
        assert!(accepted.lock().unwrap().is_empty());
    }

    #[test]
    fn addresses_and_networks_need_no_resolution() {
        let literal = agent("\"10.0.0.5\", \"10.1.0.0/16\"");
        let specs = block_on(resolve_infrastructure(&literal, Mode::Production)).unwrap();
        let specs = specs.lock().unwrap();
        assert_eq!(specs[0].networks, vec!["10.0.0.5", "10.1.0.0/16"]);
    }
}
