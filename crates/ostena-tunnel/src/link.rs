//! The agent side of the tunnel, kept up for the life of the agent
//! (ADR-0008): connection, reconnection with exponential backoff and full
//! jitter, shared status for `ostena agent status`, and automatic certificate
//! renewal at two thirds of its validity.
//!
//! The identity is read from disk at every connection, so that a renewed
//! certificate is used from the next one. A renewal writes the new key and
//! certificate next to the old ones (`.new`), then renames the key and the
//! certificate; a renewal interrupted between the two renames is completed at
//! the next connection.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ostena_common::secret::SecretBytes;
use ostena_crypto::p256::SigningKey;
use ostena_crypto::pki::{certificate_validity, pem_private_key};
use ostena_crypto::tls::{self, Identity, TrustAnchor};
use serde::Serialize;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::control::CoreMessage;
use crate::error::TunnelError;
use crate::limits::Limits;
use crate::renewal;
use crate::tunnel::{ALPN, AgentConfig, AgentTunnel, Hello, connect};

/// Reconnection delays: full jitter (a random delay between zero and the
/// exponential bound), so that agents cut off together do not come back
/// together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    /// Bound of the first retry.
    pub base: Duration,
    /// Largest bound.
    pub max: Duration,
    /// A connection that lasted this long resets the sequence.
    pub stable_after: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            base: Duration::from_secs(1),
            max: Duration::from_mins(1),
            stable_after: Duration::from_mins(1),
        }
    }
}

impl Backoff {
    /// Upper bound of the delay before retry number `attempt` (from 0).
    pub fn bound(&self, attempt: u32) -> Duration {
        let factor = 1u32.checked_shl(attempt.min(31)).unwrap_or(u32::MAX);
        self.base.saturating_mul(factor).min(self.max)
    }

    /// A random delay in `[0, bound(attempt)]`.
    pub fn delay(&self, attempt: u32) -> Duration {
        let bound = u64::try_from(self.bound(attempt).as_millis()).unwrap_or(u64::MAX);
        let random = ostena_crypto::rand::array::<8>().map_or(u64::MAX, u64::from_le_bytes);
        Duration::from_millis(random % bound.saturating_add(1))
    }
}

/// State of the link, as `ostena agent status` shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LinkState {
    /// Dialling the core.
    Connecting,
    /// Connected.
    Connected {
        /// Since (Unix seconds).
        since: u64,
        /// Transport.
        transport: &'static str,
    },
    /// Waiting before the next attempt.
    Reconnecting {
        /// Next attempt (Unix seconds).
        retry_at: u64,
        /// Stable code of the last failure.
        code: &'static str,
        /// Last failure.
        error: String,
    },
    /// Stopped.
    Stopped,
}

/// Status of the link, shared with the control plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinkStatus {
    /// Connection state.
    #[serde(flatten)]
    pub state: LinkState,
    /// Smoothed round-trip time, in microseconds, while connected.
    pub rtt_micros: Option<u64>,
    /// End of validity of the current certificate (Unix seconds).
    pub certificate_not_after: Option<u64>,
    /// When it will be renewed (Unix seconds).
    pub renewal_due: Option<u64>,
    /// Connections established since the start.
    pub connections: u64,
}

impl LinkStatus {
    /// One line in French for `ostena agent status`.
    pub fn summary(&self, now: u64) -> String {
        match &self.state {
            LinkState::Connecting => "connexion en cours".into(),
            LinkState::Connected { since, transport } => {
                let rtt = self.rtt_micros.map_or_else(String::new, |r| {
                    format!(", RTT {}.{} ms", r / 1000, r % 1000 / 100)
                });
                format!(
                    "connecté ({}) depuis {} s{rtt}",
                    transport.to_uppercase(),
                    now.saturating_sub(*since)
                )
            }
            LinkState::Reconnecting {
                retry_at,
                code,
                error,
            } => format!(
                "non connecté, nouvelle tentative dans {} s ({code} : {error})",
                retry_at.saturating_sub(now)
            ),
            LinkState::Stopped => "arrêté".into(),
        }
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// What the link needs.
#[derive(Debug, Clone)]
pub struct LinkParams {
    /// Core address, `host:port` (resolved at every attempt).
    pub core_address: String,
    /// Agent certificate (PEM).
    pub certificate: PathBuf,
    /// Agent private key (PEM PKCS#8).
    pub private_key: PathBuf,
    /// The root the agent pins.
    pub root: TrustAnchor,
    /// Hello content.
    pub hello: Hello,
    /// Bounds.
    pub limits: Limits,
    /// Reconnection delays.
    pub backoff: Backoff,
}

/// The link to the core. Dropping it stops it.
#[derive(Debug)]
pub struct AgentLink {
    status: Arc<Mutex<LinkStatus>>,
    stop: watch::Sender<bool>,
    task: Mutex<Option<JoinHandle<()>>>,
    pushes: Mutex<Option<mpsc::Receiver<CoreMessage>>>,
}

impl AgentLink {
    /// Starts the link.
    ///
    /// # Panics
    ///
    /// Outside a Tokio runtime.
    pub fn spawn(params: LinkParams) -> Self {
        let status = Arc::new(Mutex::new(LinkStatus {
            state: LinkState::Connecting,
            rtt_micros: None,
            certificate_not_after: None,
            renewal_due: None,
            connections: 0,
        }));
        let (stop, stop_rx) = watch::channel(false);
        let (push_tx, push_rx) = mpsc::channel(64);
        let task = tokio::spawn(run(params, status.clone(), stop_rx, push_tx));
        Self {
            status,
            stop,
            task: Mutex::new(Some(task)),
            pushes: Mutex::new(Some(push_rx)),
        }
    }

    /// The current status.
    pub fn status(&self) -> LinkStatus {
        self.status.lock().map_or_else(
            |_| LinkStatus {
                state: LinkState::Stopped,
                rtt_micros: None,
                certificate_not_after: None,
                renewal_due: None,
                connections: 0,
            },
            |s| s.clone(),
        )
    }

    /// The control messages pushed by the core (policy, keys, session
    /// answers…), once.
    pub fn take_pushes(&self) -> Option<mpsc::Receiver<CoreMessage>> {
        self.pushes.lock().ok()?.take()
    }

    /// Stops the link and waits for it.
    pub async fn stop(&self) {
        let _ = self.stop.send(true);
        let task = self.task.lock().ok().and_then(|mut t| t.take());
        if let Some(task) = task {
            let _ = task.await;
        }
    }
}

impl Drop for AgentLink {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

fn set(status: &Mutex<LinkStatus>, edit: impl FnOnce(&mut LinkStatus)) {
    if let Ok(mut s) = status.lock() {
        edit(&mut s);
    }
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Completes a renewal interrupted between the two renames.
fn complete_pending_renewal(params: &LinkParams) {
    let pending = with_suffix(&params.certificate, ".new");
    if pending.exists() && !with_suffix(&params.private_key, ".new").exists() {
        // The key was renamed, not the certificate yet.
        let _ = std::fs::rename(&pending, &params.certificate);
    }
}

fn load_identity(params: &LinkParams) -> Result<Identity, TunnelError> {
    complete_pending_renewal(params);
    let read = |p: &Path| {
        std::fs::read(p).map_err(|e| TunnelError::Config(format!("{} : {e}", p.display())))
    };
    let chain = read(&params.certificate)?;
    let key = SecretBytes::from(read(&params.private_key)?);
    Identity::from_pem(&chain, &key).map_err(|e| TunnelError::Config(e.to_string()))
}

async fn resolve(address: &str) -> Result<(String, std::net::SocketAddr), TunnelError> {
    let host = address
        .rsplit_once(':')
        .map_or(address, |(h, _)| h)
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let resolved = tokio::net::lookup_host(address)
        .await
        .map_err(|e| TunnelError::ConnectionLost(format!("{address} : {e}")))?
        .next()
        .ok_or_else(|| TunnelError::ConnectionLost(format!("{address} : aucune adresse")))?;
    Ok((host, resolved))
}

async fn run(
    params: LinkParams,
    status: Arc<Mutex<LinkStatus>>,
    mut stop: watch::Receiver<bool>,
    pushes: mpsc::Sender<CoreMessage>,
) {
    let mut attempt = 0u32;
    loop {
        if *stop.borrow() {
            break;
        }
        set(&status, |s| s.state = LinkState::Connecting);
        let started = Instant::now();
        let failure = match open(&params).await {
            Ok((tunnel, identity)) => {
                set(&status, |s| {
                    s.state = LinkState::Connected {
                        since: now(),
                        transport: "quic",
                    };
                    s.connections += 1;
                });
                tracing::info!(event = "agent.core_connected", core = %params.core_address);
                let why = serve(&params, &tunnel, &identity, &status, &stop, &pushes).await;
                drop(tunnel);
                why
            }
            Err(e) => e,
        };
        set(&status, |s| s.rtt_micros = None);
        if *stop.borrow() {
            break;
        }
        if started.elapsed() >= params.backoff.stable_after {
            attempt = 0;
        }
        let delay = params.backoff.delay(attempt);
        attempt = attempt.saturating_add(1);
        tracing::warn!(
            event = "agent.core_disconnected",
            code = failure.code(),
            retry_in_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            "{failure}"
        );
        set(&status, |s| {
            s.state = LinkState::Reconnecting {
                retry_at: now() + delay.as_secs(),
                code: failure.code(),
                error: failure.to_string(),
            };
        });
        // Wait for the delay, or for the stop request.
        let _ = tokio::time::timeout(delay, stop.changed()).await;
    }
    set(&status, |s| s.state = LinkState::Stopped);
}

async fn open(params: &LinkParams) -> Result<(Arc<AgentTunnel>, Identity), TunnelError> {
    let identity = load_identity(params)?;
    let (server_name, core) = resolve(&params.core_address).await?;
    let config = AgentConfig {
        core,
        server_name,
        tls: tls::client_config(&params.root, Some(&identity), &[ALPN])
            .map_err(|e| TunnelError::Config(e.to_string()))?,
        limits: params.limits,
        hello: params.hello.clone(),
    };
    let (tunnel, _) = connect(&config).await?;
    Ok((Arc::new(tunnel), identity))
}

enum Event {
    Message(CoreMessage),
    Closed(TunnelError),
    RenewalDue,
    Stop,
}

/// Runs one connection until it closes or the agent stops; returns why it
/// ended.
async fn serve(
    params: &LinkParams,
    tunnel: &Arc<AgentTunnel>,
    identity: &Identity,
    status: &Mutex<LinkStatus>,
    stop: &watch::Receiver<bool>,
    pushes: &mpsc::Sender<CoreMessage>,
) -> TunnelError {
    let (tx, mut events) = mpsc::channel::<Event>(16);
    let mut pending: Option<(SigningKey, SecretBytes)> = None;
    let mut renewal_timer = schedule_renewal(identity, status, tx.clone());
    let forwarder = {
        let tx = tx.clone();
        let tunnel = tunnel.clone();
        tokio::spawn(async move {
            while let Some(message) = tunnel.recv().await {
                if tx.send(Event::Message(message)).await.is_err() {
                    return;
                }
            }
            let _ = tx.send(Event::Closed(tunnel.closed().await)).await;
        })
    };
    let stopper = {
        let tx = tx.clone();
        let mut stop = stop.clone();
        tokio::spawn(async move {
            while stop.changed().await.is_ok() {
                if *stop.borrow() {
                    let _ = tx.send(Event::Stop).await;
                    break;
                }
            }
        })
    };
    let why = loop {
        set(status, |s| {
            s.rtt_micros = Some(u64::try_from(tunnel.rtt().as_micros()).unwrap_or(u64::MAX));
        });
        // Wake up at least every second to refresh the round-trip time.
        let event = match tokio::time::timeout(Duration::from_secs(1), events.recv()).await {
            Ok(Some(event)) => event,
            Ok(None) => break TunnelError::Io("canal interne fermé".into()),
            Err(_) => continue,
        };
        match event {
            Event::Stop => break TunnelError::ConnectionLost("arrêt de l'agent".into()),
            Event::Closed(e) => break e,
            Event::RenewalDue => match start_renewal(tunnel, identity).await {
                Ok(next) => pending = Some(next),
                Err(e) => tracing::warn!(event = "agent.renewal_failed", code = e.code(), "{e}"),
            },
            Event::Message(CoreMessage::Certificate {
                certificate,
                not_before,
                not_after,
            }) => {
                let Some((key, pkcs8)) = pending.take() else {
                    tracing::warn!(
                        event = "agent.renewal_failed",
                        "certificat non demandé, ignoré"
                    );
                    continue;
                };
                match install(params, &key, &pkcs8, &certificate) {
                    Ok(()) => {
                        let due = renewal::due_at(not_before, not_after);
                        tracing::info!(
                            event = "agent.certificate_renewed",
                            not_after,
                            renewal_due = due
                        );
                        set(status, |s| {
                            s.certificate_not_after = Some(not_after);
                            s.renewal_due = Some(due);
                        });
                        renewal_timer.abort();
                        renewal_timer = timer_until(due, tx.clone());
                    }
                    Err(e) => {
                        tracing::warn!(event = "agent.renewal_failed", code = e.code(), "{e}");
                    }
                }
            }
            Event::Message(other) => {
                // Pushes for the agent (policy, keys, session answers).
                let _ = pushes.try_send(other);
            }
        }
    };
    renewal_timer.abort();
    forwarder.abort();
    stopper.abort();
    why
}

fn timer_until(due: u64, tx: mpsc::Sender<Event>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let wait = due.saturating_sub(now());
        tokio::time::sleep(Duration::from_secs(wait)).await;
        let _ = tx.send(Event::RenewalDue).await;
    })
}

/// Reads the validity of the current certificate and arms the timer.
fn schedule_renewal(
    identity: &Identity,
    status: &Mutex<LinkStatus>,
    tx: mpsc::Sender<Event>,
) -> JoinHandle<()> {
    if let Some((not_before, not_after)) = certificate_validity(identity.certificate()) {
        let due = renewal::due_at(not_before, not_after);
        set(status, |s| {
            s.certificate_not_after = Some(not_after);
            s.renewal_due = Some(due);
        });
        timer_until(due, tx)
    } else {
        tracing::warn!(
            event = "agent.renewal_failed",
            "validité du certificat illisible"
        );
        tokio::spawn(async {})
    }
}

async fn start_renewal(
    tunnel: &AgentTunnel,
    identity: &Identity,
) -> Result<(SigningKey, SecretBytes), TunnelError> {
    let (key, pkcs8) = SigningKey::generate().map_err(|e| TunnelError::Io(e.to_string()))?;
    let current = tls::fingerprint(identity.certificate());
    tunnel.send(&renewal::request(&key, &current)?).await?;
    tracing::info!(event = "agent.renewal_requested");
    Ok((key, pkcs8))
}

/// Writes the renewed key and certificate next to the current ones, then
/// renames the key, then the certificate.
fn install(
    params: &LinkParams,
    key: &SigningKey,
    pkcs8: &SecretBytes,
    certificate: &str,
) -> Result<(), TunnelError> {
    let public = key.verifying_key().to_bytes();
    let der = TrustAnchor::from_pem(certificate.as_bytes())
        .map_err(|e| TunnelError::Protocol(e.to_string()))?;
    if !der.certificate().windows(public.len()).any(|w| w == public) {
        return Err(TunnelError::Protocol(
            "certificat renouvelé pour une autre clé".into(),
        ));
    }
    let io = |e: std::io::Error| TunnelError::Io(e.to_string());
    let key_new = with_suffix(&params.private_key, ".new");
    let cert_new = with_suffix(&params.certificate, ".new");
    // SECRET-EXPOSURE: written once to a new 0600 file.
    #[expect(clippy::disallowed_methods)]
    write_file(&key_new, pem_private_key(pkcs8).expose_secret(), true).map_err(io)?;
    write_file(&cert_new, certificate.as_bytes(), false).map_err(io)?;
    std::fs::rename(&key_new, &params.private_key).map_err(io)?;
    std::fs::rename(&cert_new, &params.certificate).map_err(io)
}

fn write_file(path: &Path, bytes: &[u8], secret: bool) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = secret;
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_bounds_grow_to_the_cap() {
        let b = Backoff::default();
        assert_eq!(b.bound(0), Duration::from_secs(1));
        assert_eq!(b.bound(1), Duration::from_secs(2));
        assert_eq!(b.bound(5), Duration::from_secs(32));
        assert_eq!(b.bound(6), Duration::from_mins(1));
        assert_eq!(b.bound(100), Duration::from_mins(1));
    }

    #[test]
    fn backoff_delay_is_jittered_within_the_bound() {
        let b = Backoff::default();
        let delays: Vec<Duration> = (0..200).map(|_| b.delay(4)).collect();
        assert!(delays.iter().all(|d| *d <= b.bound(4)));
        let distinct: std::collections::BTreeSet<_> = delays.iter().collect();
        assert!(distinct.len() > 50, "full jitter spreads the retries");
    }

    #[test]
    fn summary_in_french() {
        let mut s = LinkStatus {
            state: LinkState::Connected {
                since: 100,
                transport: "quic",
            },
            rtt_micros: Some(420),
            certificate_not_after: None,
            renewal_due: None,
            connections: 1,
        };
        assert_eq!(s.summary(112), "connecté (QUIC) depuis 12 s, RTT 0.4 ms");
        s.state = LinkState::Reconnecting {
            retry_at: 120,
            code: "TUN-E013",
            error: "perdu".into(),
        };
        assert!(
            s.summary(112)
                .starts_with("non connecté, nouvelle tentative dans 8 s (TUN-E013")
        );
    }
}
