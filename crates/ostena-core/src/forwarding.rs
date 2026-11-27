//! Export of the audit chain to the SIEM (ADR-0012, « Export syslog TLS en
//! OCSF »): every record of the chain, in order, as an OCSF event in an
//! RFC 5424 message, over TLS 1.3 (RFC 5425) to each `[[audit.outputs]]`
//! collector.
//!
//! Delivery is at least once. The position of a collector (the last record
//! written to it and flushed) is itself recorded in the chain
//! (`audit.forwarded`), at most every [`POSITION_INTERVAL`], and the export
//! resumes after it: at start, and after every lost connection. A record
//! may thus arrive twice; its OCSF `metadata.uid` (`<chain>:<seq>`) lets
//! the collector drop the copy. Nothing is skipped: a collector that
//! cannot be reached delays the export, logged at every attempt and
//! recorded once per run of failures (`audit.forward_failed`).
//!
//! The chain stays the proof: a SIEM holds a copy, never the reference.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ostena_audit::siem::{frame, message};
use ostena_audit::{ActorKind, Event, EventKind, Outcome, Record, Value, field};
use ostena_common::config::{Output, SyslogTls, Transport};
use ostena_crypto::tls::syslog::syslog_client_config;
use ostena_crypto::tls::target::anchors_from_pem;
use ostena_crypto::tls::{ClientConfig, Identity, ServerName};
use sqlx::PgPool;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;

use crate::audit::Recorder;
use crate::error::CoreError;

/// Code of a collector that cannot be reached or refuses the TLS
/// handshake.
pub const UNREACHABLE: &str = "SYS-E001";
/// Code of a connection lost while records were sent.
pub const LOST: &str = "SYS-E002";

/// Records read and sent at once.
const BATCH: i64 = 256;
/// Delay between two reads of the chain when it does not move.
const POLL: Duration = Duration::from_secs(1);
/// Interval between two `audit.forwarded` of a collector.
pub const POSITION_INTERVAL: Duration = Duration::from_secs(60);
/// Longest delay between two connection attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// Connection and TLS handshake.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// One write of a batch.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Why an export attempt stopped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ForwardError {
    /// The collector cannot be reached or refuses the handshake.
    #[error("[{UNREACHABLE}] collecteur syslog {destination} injoignable : {detail}")]
    Unreachable {
        /// `address` of the output.
        destination: String,
        /// Why.
        detail: String,
    },
    /// The connection broke while records were sent.
    #[error("[{LOST}] connexion au collecteur syslog {destination} perdue : {detail}")]
    Lost {
        /// `address` of the output.
        destination: String,
        /// Why.
        detail: String,
    },
}

impl ForwardError {
    /// The stable code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unreachable { .. } => UNREACHABLE,
            Self::Lost { .. } => LOST,
        }
    }
}

/// One collector of `[[audit.outputs]]`.
#[derive(Debug, Clone)]
pub struct Forwarder {
    destination: String,
    host: String,
    port: u16,
    server_name: ServerName<'static>,
    tls: Arc<ClientConfig>,
    hostname: String,
    position_interval: Duration,
}

/// `host:port` or `[ipv6]:port`.
fn split_address(address: &str) -> Option<(String, u16)> {
    let (host, port) = address.rsplit_once(':')?;
    let port = port.parse::<u16>().ok().filter(|p| *p != 0)?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    (!host.is_empty()).then(|| (host.to_owned(), port))
}

fn server_name(host: &str) -> Option<ServerName<'static>> {
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => Some(ServerName::IpAddress(ip.into())),
        Err(_) => ServerName::try_from(host.to_owned()).ok(),
    }
}

/// The host name of the machine, for the `HOSTNAME` of the messages.
fn local_hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| std::fs::read_to_string("/etc/hostname"))
        .map(|h| h.trim().to_owned())
        .unwrap_or_default()
}

impl Forwarder {
    /// The collectors of `outputs` (`[[audit.outputs]]`), their bundles and
    /// keys read now; credentials from `credentials`.
    ///
    /// # Errors
    ///
    /// [`CoreError::Startup`] for an output the core cannot export to (only
    /// syslog over TLS with its `tls` settings), an unreadable bundle,
    /// certificate or key.
    pub fn load_all(
        outputs: &[Output],
        credentials: Option<&Path>,
    ) -> Result<Vec<Self>, CoreError> {
        outputs
            .iter()
            .enumerate()
            .map(|(i, output)| Self::load(&format!("audit.outputs[{i}]"), output, credentials))
            .collect()
    }

    fn load(field: &str, output: &Output, credentials: Option<&Path>) -> Result<Self, CoreError> {
        let startup = |why: String| CoreError::Startup(format!("{field} : {why}"));
        let (address, tls) = match output {
            Output::Syslog {
                address,
                transport: Transport::Tls,
                tls: Some(tls),
            } => (address, tls),
            Output::Syslog {
                transport: Transport::Tls,
                tls: None,
                ..
            } => {
                return Err(startup(
                    "syslog TLS sans réglages tls (ca au moins, RFC 5425)".into(),
                ));
            }
            _ => {
                return Err(startup(
                    "le core n'exporte l'audit que vers un collecteur syslog TLS (kind = \
                     \"syslog\", transport = \"tls\")"
                        .into(),
                ));
            }
        };
        let (host, port) =
            split_address(address).ok_or_else(|| startup(format!("adresse « {address} »")))?;
        let tls_config = client_config(field, tls, credentials)?;
        let name = tls.server_name.as_deref().unwrap_or(&host);
        let server_name =
            server_name(name).ok_or_else(|| startup(format!("nom de serveur « {name} »")))?;
        Ok(Self::new(
            address.clone(),
            host,
            port,
            server_name,
            tls_config,
            local_hostname(),
        ))
    }

    /// A collector at `host:port`, known in the chain as `destination`,
    /// whose certificate must name `server_name`.
    pub fn new(
        destination: String,
        host: String,
        port: u16,
        server_name: ServerName<'static>,
        tls: Arc<ClientConfig>,
        hostname: String,
    ) -> Self {
        Self {
            destination,
            host,
            port,
            server_name,
            tls,
            hostname,
            position_interval: POSITION_INTERVAL,
        }
    }

    /// The same, recording its position every `interval` (tests).
    #[must_use]
    pub fn with_position_interval(mut self, interval: Duration) -> Self {
        self.position_interval = interval;
        self
    }

    /// How the collector is known in the chain (`destination`).
    pub fn destination(&self) -> &str {
        &self.destination
    }

    /// The last record written to this collector per the chain: the
    /// `last_seq` of its latest `audit.forwarded`, 0 if none.
    ///
    /// # Errors
    ///
    /// [`CoreError::Database`], [`CoreError::AuditChain`] for a record that
    /// does not decode.
    pub async fn position(&self, pool: &PgPool) -> Result<u64, CoreError> {
        let mut before = i64::MAX;
        loop {
            let rows = sqlx::query!(
                "SELECT seq, body FROM audit_record WHERE event = 'audit.forwarded' AND seq < $1 \
                 ORDER BY seq DESC LIMIT 64",
                before
            )
            .fetch_all(pool)
            .await?;
            let Some(last) = rows.last() else {
                return Ok(0);
            };
            before = last.seq;
            for row in &rows {
                let record = Record::decode(&row.body).map_err(|e| {
                    CoreError::AuditChain(format!("enregistrement n° {} : {e}", row.seq))
                })?;
                if text(&record, field::DESTINATION) == Some(self.destination.as_str()) {
                    return Ok(number(&record, field::LAST_SEQ).unwrap_or(0));
                }
            }
        }
    }

    /// Connects and completes the TLS handshake.
    async fn connect(&self) -> Result<tokio_rustls::client::TlsStream<TcpStream>, ForwardError> {
        let unreachable = |detail: String| ForwardError::Unreachable {
            destination: self.destination.clone(),
            detail,
        };
        let connect = async {
            let tcp = TcpStream::connect((self.host.as_str(), self.port))
                .await
                .map_err(|e| unreachable(e.to_string()))?;
            let _ = tcp.set_nodelay(true);
            TlsConnector::from(self.tls.clone())
                .connect(self.server_name.clone(), tcp)
                .await
                .map_err(|e| unreachable(format!("TLS : {e}")))
        };
        tokio::time::timeout(CONNECT_TIMEOUT, connect)
            .await
            .map_err(|_| unreachable("délai dépassé".into()))?
    }

    /// [`Self::run`] in a task.
    pub fn spawn(self, pool: PgPool, recorder: Arc<Recorder>) -> JoinHandle<()> {
        tokio::spawn(Arc::new(self).run(pool, recorder))
    }

    /// Exports the chain to the collector, forever.
    pub async fn run(self: Arc<Self>, pool: PgPool, recorder: Arc<Recorder>) {
        let mut confirmed = loop {
            match self.position(&pool).await {
                Ok(seq) => break seq,
                Err(e) => {
                    tracing::error!(event = "audit.forward_failed", destination = %self.destination, "position du collecteur illisible : {e}");
                    tokio::time::sleep(POLL * 10).await;
                }
            }
        };
        let mut failing = false;
        let mut backoff = Duration::from_secs(1);
        loop {
            let result = match self.connect().await {
                Ok(mut stream) => {
                    if std::mem::take(&mut failing) {
                        tracing::info!(
                            event = "audit.forward_restored",
                            destination = %self.destination,
                            from_seq = confirmed + 1,
                            "collecteur syslog de nouveau joignable"
                        );
                    }
                    backoff = Duration::from_secs(1);
                    self.pump(&pool, &recorder, &mut stream, &mut confirmed)
                        .await
                }
                Err(e) => Err(e),
            };
            if let Err(e) = result {
                tracing::error!(
                    event = "audit.forward_failed",
                    code = e.code(),
                    destination = %self.destination,
                    "export de l'audit interrompu : {e}"
                );
                if !std::mem::replace(&mut failing, true) {
                    recorder.emit(failed_event(&self.destination, &e));
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }

    /// Sends the chain after `confirmed` until the connection breaks;
    /// records the position at most every position interval.
    async fn pump(
        &self,
        pool: &PgPool,
        recorder: &Recorder,
        stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
        confirmed: &mut u64,
    ) -> Result<(), ForwardError> {
        let lost = |detail: String| ForwardError::Lost {
            destination: self.destination.clone(),
            detail,
        };
        let version = env!("CARGO_PKG_VERSION");
        let mut sent = *confirmed;
        // Records other than positions sent since the last position.
        let mut unrecorded = false;
        let mut recorded_at = Instant::now();
        loop {
            let batch = match read_after(pool, sent).await {
                Ok(batch) => batch,
                Err(e) => {
                    tracing::warn!(event = "audit.forward_failed", destination = %self.destination, "lecture de la chaîne impossible : {e}");
                    tokio::time::sleep(POLL).await;
                    continue;
                }
            };
            if batch.is_empty() {
                tokio::time::sleep(POLL).await;
            } else {
                let mut bytes = Vec::with_capacity(batch.len() * 1024);
                for record in &batch {
                    bytes.extend(frame(&message(record, &self.hostname, version)));
                    unrecorded |= record.event != EventKind::AuditForwarded.name();
                }
                let write = async {
                    stream.write_all(&bytes).await?;
                    stream.flush().await
                };
                tokio::time::timeout(WRITE_TIMEOUT, write)
                    .await
                    .map_err(|_| lost("délai d'écriture dépassé".into()))?
                    .map_err(|e| lost(e.to_string()))?;
                sent = batch.last().map_or(sent, |r| r.seq);
            }
            if unrecorded && recorded_at.elapsed() >= self.position_interval {
                recorder.emit(position_event(&self.destination, sent));
                *confirmed = sent;
                unrecorded = false;
                recorded_at = Instant::now();
            }
        }
    }
}

/// The records after `seq`, at most [`BATCH`], in order.
async fn read_after(pool: &PgPool, seq: u64) -> Result<Vec<Record>, CoreError> {
    let after = i64::try_from(seq).unwrap_or(i64::MAX);
    let rows = sqlx::query!(
        "SELECT seq, body FROM audit_record WHERE seq > $1 ORDER BY seq LIMIT $2",
        after,
        BATCH
    )
    .fetch_all(pool)
    .await?;
    rows.iter()
        .map(|row| {
            Record::decode(&row.body)
                .map_err(|e| CoreError::AuditChain(format!("enregistrement n° {} : {e}", row.seq)))
        })
        .collect()
}

fn text<'a>(record: &'a Record, name: &str) -> Option<&'a str> {
    match record.field(name) {
        Some(Value::Text(t)) => Some(t),
        _ => None,
    }
}

fn number(record: &Record, name: &str) -> Option<u64> {
    match record.field(name) {
        Some(Value::U64(n)) => Some(*n),
        _ => None,
    }
}

/// The client configuration of one collector.
fn client_config(
    field: &str,
    tls: &SyslogTls,
    credentials: Option<&Path>,
) -> Result<Arc<ClientConfig>, CoreError> {
    let startup = |what: &str, e: &dyn std::fmt::Display| {
        CoreError::Startup(format!("{field}.tls.{what} : {e}"))
    };
    let pem = std::fs::read(&tls.ca).map_err(|e| startup("ca", &e))?;
    let anchors = anchors_from_pem(&pem).map_err(|e| startup("ca", &e))?;
    let identity = match (&tls.certificate, &tls.private_key) {
        (Some(certificate), Some(key)) => {
            let chain = std::fs::read(certificate).map_err(|e| startup("certificate", &e))?;
            let key =
                crate::server::read_key(&format!("{field}.tls.private_key"), key, credentials)?;
            Some(Identity::from_pem(&chain, &key).map_err(|e| startup("certificate", &e))?)
        }
        _ => None,
    };
    syslog_client_config(&anchors, identity.as_ref()).map_err(|e| startup("ca", &e))
}

/// The `audit.forwarded` record: everything up to `last_seq` was written
/// to `destination`.
pub fn position_event(destination: &str, last_seq: u64) -> Event {
    Event::new(
        EventKind::AuditForwarded,
        Outcome::Success,
        ActorKind::Core,
        "core",
    )
    .text(field::DESTINATION, crate::store::truncate(destination))
    .u64(field::LAST_SEQ, last_seq)
}

/// The `audit.forward_failed` record of a run of failures.
pub fn failed_event(destination: &str, error: &ForwardError) -> Event {
    Event::new(
        EventKind::AuditForwardFailed,
        Outcome::Failure,
        ActorKind::Core,
        "core",
    )
    .text(field::DESTINATION, crate::store::truncate(destination))
    .text(field::CODE, error.code())
    .text(field::REASON, crate::store::truncate(&error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_split() {
        assert_eq!(split_address("siem:6514"), Some(("siem".into(), 6514)));
        assert_eq!(split_address("[::1]:6514"), Some(("::1".into(), 6514)));
        assert_eq!(split_address("10.0.0.5:1"), Some(("10.0.0.5".into(), 1)));
        assert_eq!(split_address("siem:0"), None);
        assert_eq!(split_address(":6514"), None);
        assert!(matches!(server_name("::1"), Some(ServerName::IpAddress(_))));
        assert!(matches!(
            server_name("siem.example"),
            Some(ServerName::DnsName(_))
        ));
        assert!(server_name("a b").is_none());
    }

    #[test]
    fn only_syslog_over_tls_is_exported() {
        for (output, why) in [
            (Output::Stdout {}, "syslog TLS"),
            (
                Output::Syslog {
                    address: "siem:514".into(),
                    transport: Transport::Tcp,
                    tls: None,
                },
                "syslog TLS",
            ),
            (
                Output::Syslog {
                    address: "siem:6514".into(),
                    transport: Transport::Tls,
                    tls: None,
                },
                "sans réglages tls",
            ),
        ] {
            let e = Forwarder::load_all(&[output], None)
                .unwrap_err()
                .to_string();
            assert!(e.contains("audit.outputs[0]") && e.contains(why), "{e}");
        }
    }
}
