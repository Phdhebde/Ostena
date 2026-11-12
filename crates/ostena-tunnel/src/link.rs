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
use ostena_crypto::tls::{self, CertificateDer, Identity, TrustAnchor};
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
    /// 90 % of the validity are past without a successful renewal.
    pub renewal_overdue: bool,
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

/// Wall clock in Unix seconds, injectable so that the tests that depend on
/// time do not rely on tolerance margins.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Now, in Unix seconds.
    fn now(&self) -> u64;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}

/// Creates a private file with its final rights before writing it, and
/// refuses an existing file (`ostena_platform::private_file::create` in the
/// agent).
pub type KeyWriter = fn(&Path, &[u8]) -> std::io::Result<()>;

/// How often an overdue renewal is checked and reported.
pub const OVERDUE_CHECK: Duration = Duration::from_hours(1);

/// From when, without a successful renewal, it is overdue: 90 % of the
/// validity.
pub fn overdue_at(not_before: u64, not_after: u64) -> u64 {
    not_before.saturating_add(not_after.saturating_sub(not_before) / 10 * 9)
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
    /// Wall clock.
    pub clock: Arc<dyn Clock>,
    /// Writes the renewed key.
    pub write_key: KeyWriter,
}

/// The link to the core. Dropping it stops it.
#[derive(Debug)]
pub struct AgentLink {
    status: Arc<Mutex<LinkStatus>>,
    stop: watch::Sender<bool>,
    task: Mutex<Option<JoinHandle<()>>>,
    pushes: Mutex<Option<mpsc::Receiver<CoreMessage>>>,
}

fn initial_status() -> LinkStatus {
    LinkStatus {
        state: LinkState::Connecting,
        rtt_micros: None,
        certificate_not_after: None,
        renewal_due: None,
        renewal_overdue: false,
        connections: 0,
    }
}

impl AgentLink {
    /// Starts the link.
    ///
    /// # Panics
    ///
    /// Outside a Tokio runtime.
    pub fn spawn(params: LinkParams) -> Self {
        let status = Arc::new(Mutex::new(initial_status()));
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
                ..initial_status()
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

/// Completes or discards a renewal interrupted by a stop.
///
/// - The new key is still next to the current one: the renames had not
///   started and the current pair is consistent; the new files are removed.
/// - Only the new certificate is left: the key was renamed, the
///   certificate is renamed now.
fn complete_pending_renewal(params: &LinkParams) {
    let key_new = with_suffix(&params.private_key, ".new");
    let cert_new = with_suffix(&params.certificate, ".new");
    if key_new.exists() {
        let _ = std::fs::remove_file(&key_new);
        let _ = std::fs::remove_file(&cert_new);
    } else if cert_new.exists() {
        let _ = std::fs::rename(&cert_new, &params.certificate);
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

/// Validity of the certificate on disk.
fn validity_on_disk(certificate: &Path) -> Option<(u64, u64)> {
    let pem = std::fs::read(certificate).ok()?;
    let der = TrustAnchor::from_pem(&pem).ok()?;
    certificate_validity(der.certificate())
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

/// Checks every `every` whether the renewal is overdue (90 % of the validity
/// without a successful renewal): sets the status and calls `report` each
/// time it is. Runs whether the core is reachable or not.
async fn watch_overdue(
    validity: impl Fn() -> Option<(u64, u64)>,
    clock: Arc<dyn Clock>,
    status: Arc<Mutex<LinkStatus>>,
    every: Duration,
    report: impl Fn(u64, u64),
) {
    loop {
        if let Some((not_before, not_after)) = validity() {
            let now = clock.now();
            let overdue = now >= overdue_at(not_before, not_after);
            set(&status, |s| {
                s.certificate_not_after = Some(not_after);
                s.renewal_due = Some(renewal::due_at(not_before, not_after));
                s.renewal_overdue = overdue;
            });
            if overdue {
                report(not_after, now);
            }
        }
        tokio::time::sleep(every).await;
    }
}

fn report_overdue(not_after: u64, now: u64) {
    tracing::warn!(
        event = "tunnel.renewal_overdue",
        not_after,
        remaining_secs = not_after.saturating_sub(now),
        "certificat de l'agent non renouvelé à 90 % de sa validité ; vérifier le lien avec le core"
    );
}

/// Why one connection ended.
enum Ended {
    /// Lost or refused.
    Failed(TunnelError),
    /// Renewed: reconnect now with the new identity, so that the old key
    /// leaves memory.
    Renewed,
}

async fn run(
    params: LinkParams,
    status: Arc<Mutex<LinkStatus>>,
    mut stop: watch::Receiver<bool>,
    pushes: mpsc::Sender<CoreMessage>,
) {
    let overdue = {
        let certificate = params.certificate.clone();
        tokio::spawn(watch_overdue(
            move || validity_on_disk(&certificate),
            params.clock.clone(),
            status.clone(),
            OVERDUE_CHECK,
            report_overdue,
        ))
    };
    let mut attempt = 0u32;
    loop {
        if *stop.borrow() {
            break;
        }
        set(&status, |s| s.state = LinkState::Connecting);
        let started = Instant::now();
        let ended = match open(&params).await {
            Ok((tunnel, certificate)) => {
                set(&status, |s| {
                    s.state = LinkState::Connected {
                        since: params.clock.now(),
                        transport: "quic",
                    };
                    s.connections += 1;
                });
                tracing::info!(event = "agent.core_connected", core = %params.core_address);
                let ended = serve(&params, &tunnel, &certificate, &status, &stop, &pushes).await;
                drop(tunnel);
                ended
            }
            Err(e) => Ended::Failed(e),
        };
        set(&status, |s| s.rtt_micros = None);
        if *stop.borrow() {
            break;
        }
        let failure = match ended {
            Ended::Renewed => {
                tracing::info!(event = "agent.identity_rotated");
                attempt = 0;
                continue;
            }
            Ended::Failed(e) => e,
        };
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
                retry_at: params.clock.now() + delay.as_secs(),
                code: failure.code(),
                error: failure.to_string(),
            };
        });
        // Wait for the delay, or for the stop request.
        let _ = tokio::time::timeout(delay, stop.changed()).await;
    }
    overdue.abort();
    set(&status, |s| s.state = LinkState::Stopped);
}

/// Connects; returns the tunnel and the certificate in use. The identity
/// read from disk is dropped (and its key erased) once the TLS configuration
/// is built: the key then lives only in the TLS state of this connection.
async fn open(
    params: &LinkParams,
) -> Result<(Arc<AgentTunnel>, CertificateDer<'static>), TunnelError> {
    let identity = load_identity(params)?;
    let certificate = identity.certificate().clone();
    let (server_name, core) = resolve(&params.core_address).await?;
    let config = AgentConfig {
        core,
        server_name,
        tls: tls::client_config(&params.root, Some(&identity), &[ALPN])
            .map_err(|e| TunnelError::Config(e.to_string()))?,
        limits: params.limits,
        hello: params.hello.clone(),
    };
    drop(identity);
    let (tunnel, _) = connect(&config).await?;
    Ok((Arc::new(tunnel), certificate))
}

enum Event {
    Message(CoreMessage),
    Closed(TunnelError),
    RenewalDue,
    Stop,
}

/// Runs one connection until it closes, the agent stops, or a renewal asks
/// for a new connection.
async fn serve(
    params: &LinkParams,
    tunnel: &Arc<AgentTunnel>,
    certificate: &CertificateDer<'static>,
    status: &Mutex<LinkStatus>,
    stop: &watch::Receiver<bool>,
    pushes: &mpsc::Sender<CoreMessage>,
) -> Ended {
    let (tx, mut events) = mpsc::channel::<Event>(16);
    let mut pending: Option<(SigningKey, SecretBytes)> = None;
    let mut renewed = false;
    let renewal_timer = schedule_renewal(certificate, params, status, tx.clone());
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
    let ended = loop {
        set(status, |s| {
            s.rtt_micros = Some(u64::try_from(tunnel.rtt().as_micros()).unwrap_or(u64::MAX));
        });
        // Renewed: reconnect with the new identity as soon as no session
        // channel is open, never cutting a session.
        if renewed && tunnel.open_channels() == 0 {
            tunnel.close(TunnelError::ConnectionLost(
                "reconnexion avec le certificat renouvelé".into(),
            ));
            break Ended::Renewed;
        }
        // Wake up at least every second to refresh the round-trip time.
        let event = match tokio::time::timeout(Duration::from_secs(1), events.recv()).await {
            Ok(Some(event)) => event,
            Ok(None) => break Ended::Failed(TunnelError::Io("canal interne fermé".into())),
            Err(_) => continue,
        };
        match event {
            Event::Stop => {
                break Ended::Failed(TunnelError::ConnectionLost("arrêt de l'agent".into()));
            }
            Event::Closed(e) => break Ended::Failed(e),
            Event::RenewalDue => match start_renewal(tunnel, certificate).await {
                Ok(next) => pending = Some(next),
                Err(e) => tracing::warn!(event = "agent.renewal_failed", code = e.code(), "{e}"),
            },
            Event::Message(CoreMessage::Certificate {
                certificate,
                not_before,
                not_after,
            }) => {
                // The new key leaves memory when this pair is dropped.
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
                            s.renewal_overdue = false;
                        });
                        renewal_timer.abort();
                        renewed = true;
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
    ended
}

fn timer_until(due: u64, clock: Arc<dyn Clock>, tx: mpsc::Sender<Event>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let wait = due.saturating_sub(clock.now());
        tokio::time::sleep(Duration::from_secs(wait)).await;
        let _ = tx.send(Event::RenewalDue).await;
    })
}

/// Reads the validity of the certificate in use and arms the timer.
fn schedule_renewal(
    certificate: &CertificateDer<'static>,
    params: &LinkParams,
    status: &Mutex<LinkStatus>,
    tx: mpsc::Sender<Event>,
) -> JoinHandle<()> {
    if let Some((not_before, not_after)) = certificate_validity(certificate) {
        let due = renewal::due_at(not_before, not_after);
        set(status, |s| {
            s.certificate_not_after = Some(not_after);
            s.renewal_due = Some(due);
        });
        timer_until(due, params.clock.clone(), tx)
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
    certificate: &CertificateDer<'static>,
) -> Result<(SigningKey, SecretBytes), TunnelError> {
    let (key, pkcs8) = SigningKey::generate().map_err(|e| TunnelError::Io(e.to_string()))?;
    let current = tls::fingerprint(certificate);
    tunnel.send(&renewal::request(&key, &current)?).await?;
    tracing::info!(event = "agent.renewal_requested");
    Ok((key, pkcs8))
}

/// Writes the renewed key (created with its final rights by
/// [`LinkParams::write_key`]) and certificate next to the current ones, then
/// renames the key over the old one, which removes it, then the
/// certificate.
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
    // Leftovers of an attempt that failed before the renames.
    let _ = std::fs::remove_file(&key_new);
    let _ = std::fs::remove_file(&cert_new);
    // SECRET-EXPOSURE: written once, to a file created with its final rights.
    #[expect(clippy::disallowed_methods)]
    (params.write_key)(&key_new, pem_private_key(pkcs8).expose_secret()).map_err(io)?;
    write_file(&cert_new, certificate.as_bytes()).map_err(io)?;
    std::fs::rename(&key_new, &params.private_key).map_err(io)?;
    std::fs::rename(&cert_new, &params.certificate).map_err(io)
}

fn write_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::File::create(path)?;
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
            renewal_overdue: false,
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

    /// A clock the test sets by hand.
    #[derive(Debug, Default)]
    struct ManualClock(std::sync::atomic::AtomicU64);

    impl Clock for ManualClock {
        fn now(&self) -> u64 {
            self.0.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[test]
    fn overdue_from_ninety_percent() {
        assert_eq!(overdue_at(1_000, 2_000), 1_900);
        assert_eq!(overdue_at(0, 30 * 86_400), 27 * 86_400);
        assert_eq!(
            overdue_at(2_000, 1_000),
            2_000,
            "inverted validity never panics"
        );
    }

    /// Simulated wall clock and paused Tokio time: no margin. Before 90 %:
    /// nothing; from 90 %: the status says so and the event is repeated at
    /// every check (each hour).
    #[test]
    fn renewal_overdue_is_reported_every_hour() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()
            .unwrap();
        runtime.block_on(async {
            let clock = Arc::new(ManualClock::default());
            // Valid from 0 to 1000: overdue from 900.
            clock.0.store(899, std::sync::atomic::Ordering::SeqCst);
            let status = Arc::new(Mutex::new(initial_status()));
            let reports = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let watcher = tokio::spawn(watch_overdue(
                || Some((0, 1_000)),
                clock.clone(),
                status.clone(),
                OVERDUE_CHECK,
                {
                    let reports = reports.clone();
                    move |not_after, _| {
                        assert_eq!(not_after, 1_000);
                        reports.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                },
            ));
            let count = || reports.load(std::sync::atomic::Ordering::SeqCst);
            tokio::task::yield_now().await;
            assert_eq!(count(), 0);
            assert!(!status.lock().unwrap().renewal_overdue);
            assert_eq!(
                status.lock().unwrap().renewal_due,
                Some(renewal::due_at(0, 1_000))
            );

            // 90 % reached: reported at the next check, then every hour.
            clock.0.store(900, std::sync::atomic::Ordering::SeqCst);
            tokio::time::sleep(OVERDUE_CHECK).await;
            tokio::task::yield_now().await;
            assert_eq!(count(), 1);
            assert!(status.lock().unwrap().renewal_overdue);
            tokio::time::sleep(OVERDUE_CHECK * 2).await;
            tokio::task::yield_now().await;
            assert_eq!(count(), 3);
            watcher.abort();
        });
    }
}
