//! RFC 3161 time-stamps of the heads (ADR-0012, « Horodatage RFC 3161 des
//! têtes »): at most every `interval_secs`, the hash of the last head is
//! sent to the time-stamping authority of the site, over HTTP (RFC 3161
//! section 3.4); the token is fully verified (nonce, imprint, signature,
//! certificate chain to the configured anchors at `genTime`) before it is
//! written to the chain as `audit.head_timestamped`.
//!
//! The transport carries a hash and a signed answer: a man in the middle
//! can only make a time-stamp fail, which is logged and recorded once per
//! run of failures (`audit.timestamp_failed`), never accepted.

use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use ostena_audit::{ActorKind, Event, EventKind, Outcome, field, timestamp};
use ostena_common::config::{CoreAuditConfig, HttpTarget, TimestampingConfig};
use ostena_crypto::tsp::{self, TimeStamp, TsaTrust};
use sqlx::PgPool;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

use crate::audit::{self, Recorder};
use crate::error::CoreError;

/// Code of an authority that cannot be reached or answers out of the
/// protocol (connection, timeout, HTTP status, size).
pub const UNREACHABLE: &str = "TSP-E007";

/// Why a time-stamp failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StampError {
    /// The authority cannot be reached, or does not answer as RFC 3161
    /// over HTTP says.
    #[error("[{UNREACHABLE}] autorité d'horodatage injoignable : {0}")]
    Unreachable(String),
    /// The answer is refused (`TSP-E001` to `TSP-E006`).
    #[error("{0}")]
    Token(#[from] tsp::TspError),
    /// The last head cannot be read.
    #[error("{0}")]
    Chain(String),
}

impl StampError {
    /// The stable code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unreachable(_) => UNREACHABLE,
            Self::Token(e) => e.code(),
            Self::Chain(_) => "CORE-E011",
        }
    }
}

/// The time-stamping authority of the core.
#[derive(Debug, Clone)]
pub struct Timestamper {
    target: HttpTarget,
    trust: TsaTrust,
    interval: Duration,
    timeout: Duration,
}

impl Timestamper {
    /// The authority of `[core.audit.timestamping]`, its anchors read.
    ///
    /// # Errors
    ///
    /// [`CoreError::Startup`] for an invalid URL or unreadable anchors.
    pub fn load(config: &TimestampingConfig) -> Result<Self, CoreError> {
        let target = config.target().ok_or_else(|| {
            CoreError::Startup(format!(
                "core.audit.timestamping.url « {} » invalide",
                config.url
            ))
        })?;
        let pem = std::fs::read(&config.ca).map_err(|e| {
            CoreError::Startup(format!(
                "core.audit.timestamping.ca {} : {e}",
                config.ca.display()
            ))
        })?;
        let trust = TsaTrust::from_pem(&pem).map_err(|e| {
            CoreError::Startup(format!(
                "core.audit.timestamping.ca {} : {e}",
                config.ca.display()
            ))
        })?;
        Ok(Self::new(
            target,
            trust,
            Duration::from_secs(config.interval_secs.into()),
            Duration::from_secs(config.timeout_secs.into()),
        ))
    }

    /// The authority of `[core.audit.timestamping]`, if set.
    ///
    /// # Errors
    ///
    /// As [`Self::load`].
    pub fn of(config: &CoreAuditConfig) -> Result<Option<Self>, CoreError> {
        config.timestamping.as_ref().map(Self::load).transpose()
    }

    /// An authority at `target`, trusted per `trust`.
    pub fn new(target: HttpTarget, trust: TsaTrust, interval: Duration, timeout: Duration) -> Self {
        Self {
            target,
            trust,
            interval,
            timeout,
        }
    }

    /// Stamps `hash`: the token (DER) and what it says, verified.
    ///
    /// # Errors
    ///
    /// [`StampError::Unreachable`] or [`StampError::Token`].
    pub async fn stamp(&self, hash: &[u8; 32]) -> Result<(Vec<u8>, TimeStamp), StampError> {
        let request = tsp::Request::new(*hash)?;
        let response = tokio::time::timeout(self.timeout, self.post(request.der()))
            .await
            .map_err(|_| StampError::Unreachable("délai dépassé".into()))??;
        Ok(request.check(&response, &self.trust)?)
    }

    /// One POST of `application/timestamp-query`; the body of a 200 answer.
    async fn post(&self, body: &[u8]) -> Result<Vec<u8>, StampError> {
        let unreachable = |e: &dyn std::fmt::Display| StampError::Unreachable(e.to_string());
        let HttpTarget { host, port, path } = &self.target;
        let tcp = TcpStream::connect((host.as_str(), *port))
            .await
            .map_err(|e| unreachable(&e))?;
        let _ = tcp.set_nodelay(true);
        let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(tcp))
            .await
            .map_err(|e| unreachable(&e))?;
        let driver = tokio::spawn(connection);
        let host_header = match (host.contains(':'), *port) {
            (true, port) => format!("[{host}]:{port}"),
            (false, 80) => host.clone(),
            (false, port) => format!("{host}:{port}"),
        };
        let request = hyper::Request::post(path.as_str())
            .header("host", host_header)
            .header("content-type", "application/timestamp-query")
            .header("accept", "application/timestamp-reply")
            .body(Full::new(Bytes::copy_from_slice(body)))
            .map_err(|e| unreachable(&e))?;
        let answer = async {
            let response = sender
                .send_request(request)
                .await
                .map_err(|e| unreachable(&e))?;
            if response.status() != hyper::StatusCode::OK {
                return Err(StampError::Unreachable(format!(
                    "statut HTTP {}",
                    response.status()
                )));
            }
            let mut out = Vec::new();
            let mut incoming = response.into_body();
            while let Some(frame) = incoming.frame().await {
                let frame = frame.map_err(|e| unreachable(&e))?;
                if let Ok(data) = frame.into_data() {
                    if out.len() + data.len() > tsp::MAX_RESPONSE {
                        return Err(StampError::Unreachable(format!(
                            "réponse de plus de {} octets",
                            tsp::MAX_RESPONSE
                        )));
                    }
                    out.extend_from_slice(&data);
                }
            }
            Ok(out)
        }
        .await;
        driver.abort();
        answer
    }

    /// The `audit.head_timestamped` event of the last head of the chain,
    /// stamped now; `None` if no head is signed yet, or if it is
    /// `already` (the head stamped last).
    ///
    /// # Errors
    ///
    /// [`StampError`].
    pub async fn stamp_last_head(
        &self,
        pool: &PgPool,
        already: Option<u64>,
    ) -> Result<Option<(u64, Event)>, StampError> {
        let head = audit::last_head(pool)
            .await
            .map_err(|e| StampError::Chain(e.to_string()))?;
        let Some(head) = head.filter(|h| Some(h.head_no()) != already) else {
            return Ok(None);
        };
        let hash = head.hash();
        let (token, stamp) = self.stamp(&hash).await?;
        let event = timestamp::event(head.head_no(), &hash, &token, &stamp)?;
        tracing::info!(
            event = "audit.head_timestamped",
            head_no = head.head_no(),
            stamped_at = stamp.gen_time_ms,
            policy = %stamp.policy,
            size = token.len(),
            "tête horodatée par l'autorité"
        );
        Ok(Some((head.head_no(), event)))
    }

    /// [`Self::run`] in a task.
    pub fn spawn(self, pool: PgPool, recorder: Arc<Recorder>) -> JoinHandle<()> {
        tokio::spawn(Arc::new(self).run(pool, recorder))
    }

    /// Stamps the last head every interval while it changes, written
    /// through the best-effort queue of `recorder`. A failure is logged at
    /// every attempt, and recorded once per run of failures.
    pub async fn run(self: Arc<Self>, pool: PgPool, recorder: Arc<Recorder>) {
        let mut ticks = tokio::time::interval(self.interval);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut stamped = None;
        let mut failing = false;
        loop {
            ticks.tick().await;
            match self.stamp_last_head(&pool, stamped).await {
                Ok(None) => {}
                Ok(Some((head_no, event))) => {
                    recorder.emit(event);
                    stamped = Some(head_no);
                    if std::mem::take(&mut failing) {
                        tracing::info!(
                            event = "audit.timestamp_restored",
                            "autorité d'horodatage de nouveau disponible"
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(
                        event = "audit.timestamp_failed",
                        code = e.code(),
                        "horodatage de la tête impossible : {e}"
                    );
                    if !std::mem::replace(&mut failing, true) {
                        recorder.emit(failed_event(&e));
                    }
                }
            }
        }
    }
}

/// The `audit.timestamp_failed` record of a failure.
pub fn failed_event(error: &StampError) -> Event {
    Event::new(
        EventKind::AuditTimestampFailed,
        Outcome::Failure,
        ActorKind::Core,
        "core",
    )
    .text(field::CODE, error.code())
    .text(field::REASON, crate::store::truncate(&error.to_string()))
}
