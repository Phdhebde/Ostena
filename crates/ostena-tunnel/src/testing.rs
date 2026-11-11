//! In-process test core (feature `testing`). Never in a release binary:
//! `cargo xtask check-release` refuses the feature and [`MARKER`].
//!
//! It plays the core side of the tunnel: its own CA, a registry of agent
//! certificates, hello checks, heartbeat answers and echo of every session
//! channel. Enrolment, policy and key pushes come with the next lots.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ostena_crypto::p256;
use ostena_crypto::pki::{CertificateAuthority, Validity};
use ostena_crypto::tls::{
    self, ClientAuth, ClientAuthorizer, ClientRefusal, Identity, TrustAnchor,
};
use tokio::task::JoinHandle;

use crate::control::{CoreMessage, PROTOCOL_VERSION};
use crate::error::TunnelError;
use crate::ids::Uuid;
use crate::limits::Limits;
use crate::tunnel::{ALPN, AgentConfig, CoreListener, CoreTunnel, Hello};

/// Text present in any binary that links the test core.
pub const MARKER: &str = "ostena-testing-core: never in a release build";

const DAY: u64 = 86_400;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Valid from yesterday for 30 days.
pub fn valid() -> Validity {
    Validity {
        not_before: now() - DAY,
        not_after: now() + 30 * DAY,
    }
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    group: Uuid,
    revoked: bool,
}

/// The test core registry of agent certificates.
#[derive(Debug, Default)]
pub struct Registry(Mutex<HashMap<[u8; 32], Entry>>);

impl ClientAuthorizer for Registry {
    fn authorize(&self, fingerprint: &[u8; 32]) -> Result<(), ClientRefusal> {
        match self.0.lock().ok().and_then(|r| r.get(fingerprint).copied()) {
            Some(Entry { revoked: false, .. }) => Ok(()),
            Some(_) => Err(ClientRefusal::Revoked),
            None => Err(ClientRefusal::Unknown),
        }
    }
}

impl Registry {
    fn group(&self, fingerprint: &[u8; 32]) -> Option<Uuid> {
        self.0.lock().ok()?.get(fingerprint).map(|e| e.group)
    }
}

/// How the test core behaves.
#[derive(Debug, Clone, Copy, Default)]
pub struct Behaviour {
    /// Stop answering heartbeats once connected (QUIC stays up).
    pub mute: bool,
}

#[derive(Debug, Default)]
struct State {
    errors: Mutex<Vec<TunnelError>>,
    tunnels: Mutex<Vec<Arc<CoreTunnel>>>,
}

/// A core listening on 127.0.0.1, for tests and benchmarks.
pub struct TestCore {
    ca: Arc<CertificateAuthority>,
    registry: Arc<Registry>,
    listener: Arc<CoreListener>,
    addr: SocketAddr,
    state: Arc<State>,
    task: JoinHandle<()>,
}

impl std::fmt::Debug for TestCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestCore")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl TestCore {
    /// Starts a test core with `limits`.
    ///
    /// # Errors
    ///
    /// If the certificates or the listener cannot be created.
    ///
    /// # Panics
    ///
    /// Outside a Tokio runtime (it spawns the accept loop).
    pub fn start(limits: Limits, behaviour: Behaviour) -> Result<Self, TunnelError> {
        tracing::debug!(marker = MARKER);
        let config = |e: ostena_crypto::pki::PkiError| TunnelError::Config(e.to_string());
        let ca = Arc::new(
            CertificateAuthority::generate("Ostena test core CA", valid()).map_err(config)?,
        );
        let server = ca
            .issue_server(&["localhost", "127.0.0.1"], valid())
            .map_err(config)?;
        let registry = Arc::new(Registry::default());
        let tls = tls::server_config(
            &server,
            ClientAuth::Required {
                ca: ca.trust_anchor(),
                authorizer: registry.clone(),
            },
            &[ALPN],
        )
        .map_err(|e| TunnelError::Config(e.to_string()))?;
        let listener = Arc::new(CoreListener::bind(
            (Ipv4Addr::LOCALHOST, 0).into(),
            tls,
            limits,
        )?);
        let addr = listener.local_addr()?;
        let state = Arc::new(State::default());
        let task = tokio::spawn(serve(
            listener.clone(),
            registry.clone(),
            state.clone(),
            behaviour,
            limits,
        ));
        Ok(Self {
            ca,
            registry,
            listener,
            addr,
            state,
            task,
        })
    }

    /// The listening address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The CA the agents must pin.
    pub fn trust_anchor(&self) -> TrustAnchor {
        self.ca.trust_anchor()
    }

    /// Issues an agent certificate for `group` with `validity` and, if
    /// `register`, records it in the registry.
    ///
    /// # Errors
    ///
    /// If the key or the certificate cannot be created.
    pub fn agent_identity(
        &self,
        group: Uuid,
        validity: Validity,
        register: bool,
    ) -> Result<Identity, TunnelError> {
        let (key, pkcs8) =
            p256::SigningKey::generate().map_err(|e| TunnelError::Config(e.to_string()))?;
        let cert = self
            .ca
            .issue_agent(
                &key.verifying_key(),
                &group.to_string(),
                "test-agent",
                validity,
            )
            .map_err(|e| TunnelError::Config(e.to_string()))?;
        if register && let Ok(mut r) = self.registry.0.lock() {
            r.insert(
                tls::fingerprint(&cert),
                Entry {
                    group,
                    revoked: false,
                },
            );
        }
        Identity::new(vec![cert], pkcs8).map_err(|e| TunnelError::Config(e.to_string()))
    }

    /// Revokes an agent certificate.
    pub fn revoke(&self, identity: &Identity) {
        if let Ok(mut r) = self.registry.0.lock()
            && let Some(e) = r.get_mut(&tls::fingerprint(identity.certificate()))
        {
            e.revoked = true;
        }
    }

    /// A ready agent configuration for `identity` and `group`.
    ///
    /// # Errors
    ///
    /// If the TLS configuration is refused.
    pub fn agent_config(
        &self,
        identity: &Identity,
        group: Uuid,
        limits: Limits,
    ) -> Result<AgentConfig, TunnelError> {
        Ok(AgentConfig {
            core: self.addr,
            server_name: "localhost".into(),
            tls: tls::client_config(&self.trust_anchor(), Some(identity), &[ALPN])
                .map_err(|e| TunnelError::Config(e.to_string()))?,
            limits,
            hello: Hello {
                agent_version: "test".into(),
                gateway_group: group,
                config_fingerprint: format!("sha256:{}", "0".repeat(64)),
            },
        })
    }

    /// Errors seen while accepting connections, oldest first.
    pub fn errors(&self) -> Vec<TunnelError> {
        self.state
            .errors
            .lock()
            .map(|e| e.clone())
            .unwrap_or_default()
    }

    /// Waits up to `limit` for an accept error and returns it.
    pub async fn wait_error(&self, limit: Duration) -> Option<TunnelError> {
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            if let Some(e) = self.errors().into_iter().next() {
                return Some(e);
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Open tunnels.
    pub fn tunnels(&self) -> usize {
        self.state
            .tunnels
            .lock()
            .map_or(0, |t| t.iter().filter(|t| !t.is_closed()).count())
    }

    /// Sends `message` on every open tunnel.
    pub async fn broadcast(&self, message: &CoreMessage) {
        let tunnels: Vec<_> = self
            .state
            .tunnels
            .lock()
            .map(|t| t.clone())
            .unwrap_or_default();
        for t in tunnels {
            let _ = t.send(message).await;
        }
    }

    /// Stops the core: closes the listener and every tunnel.
    pub fn stop(&self) {
        self.task.abort();
        self.listener.close();
    }
}

impl Drop for TestCore {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn serve(
    listener: Arc<CoreListener>,
    registry: Arc<Registry>,
    state: Arc<State>,
    behaviour: Behaviour,
    limits: Limits,
) {
    while let Some(accepted) = listener.accept().await {
        let accepted = match accepted {
            Ok(a) => a,
            Err(e) => {
                if let Ok(mut errors) = state.errors.lock() {
                    errors.push(e);
                }
                continue;
            }
        };
        if registry.group(&accepted.fingerprint) != Some(accepted.hello.gateway_group) {
            let e = TunnelError::Protocol("groupe annoncé différent du certificat".into());
            accepted.tunnel.close(e.clone());
            if let Ok(mut errors) = state.errors.lock() {
                errors.push(e);
            }
            continue;
        }
        let heartbeat_secs =
            u16::try_from(limits.heartbeat_interval.as_secs().clamp(1, 60)).unwrap_or(10);
        let ack = CoreMessage::HelloAck {
            protocol: PROTOCOL_VERSION,
            core_version: "test".into(),
            heartbeat_secs,
        };
        if accepted.tunnel.send(&ack).await.is_err() {
            continue;
        }
        let tunnel = Arc::new(accepted.tunnel);
        if behaviour.mute {
            // Keep QUIC alive but stop reading the control stream: pings
            // pile up unanswered.
            tunnel.mute_for_tests();
        }
        if let Ok(mut t) = state.tunnels.lock() {
            t.push(tunnel.clone());
        }
        tokio::spawn(echo_channels(tunnel));
    }
}

async fn echo_channels(tunnel: Arc<CoreTunnel>) {
    while let Ok((_, _, mut channel)) = tunnel.accept_channel().await {
        tokio::spawn(async move {
            let mut buf = vec![0u8; 16 * 1024];
            while let Ok(Some(n)) = channel.recv.read(&mut buf).await {
                if channel.send.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
            let _ = channel.send.finish();
        });
    }
}
