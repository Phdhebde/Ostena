//! The encrypted queue of the session reports of the agent (ADR-0012,
//! « File chiffrée de l'agent »).
//!
//! A report ([`AgentMessage::SessionClosed`]) is written to the queue
//! before it is sent, and leaves it only when the core acknowledges it
//! ([`CoreMessage::ReportAck`](crate::control::CoreMessage::ReportAck)),
//! once it is written there. A core that cannot be reached, a lost link or
//! a restart of the agent lose nothing: the queue is sent again at every
//! connection, and the core applies a report once.
//!
//! - **Encrypted**: the file is one AES-256-GCM envelope (`ostena-crypto`)
//!   under a key of its own, drawn at the first start and kept next to it
//!   with private rights (as the agent key). A copy of the queue alone,
//!   or a backup, tells nothing about the sessions.
//! - **Bounded**: [`MAX_REPORTS`] reports. A report that does not fit is
//!   dropped, counted, logged at once (`agent.report_queue_full`), and the
//!   count is sent to the core like a report
//!   ([`AgentMessage::ReportsLost`]), which records it in the chain
//!   (`agent.reports_lost`). An unreadable queue file is kept aside and
//!   reported the same way, the number lost unknown.
//! - **Atomic**: every change rewrites the file (private rights, synced,
//!   renamed over the old one).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ostena_common::secret::SecretBytes;
use ostena_crypto::aead::AeadKey;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use crate::control::AgentMessage;
use crate::link::{AgentLink, KeyWriter};
use crate::{TunnelError, Uuid};

/// Most reports kept while the core cannot be reached.
pub const MAX_REPORTS: usize = 1024;
/// Name of the queue file, next to the replay journal.
pub const QUEUE_FILE: &str = "reports.queue";
/// Name of its key file.
pub const KEY_FILE: &str = "reports.key";
/// A report not acknowledged is sent again after this delay.
pub const RESEND: Duration = Duration::from_secs(30);
/// Longest reason kept (as the core reads it).
const MAX_REASON: usize = 128;
/// Associated data of the envelope: the format of the file.
const AAD: &[u8] = b"ostena-report-queue-v1";

/// A session report waiting for the core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    /// Identifies it in the queue.
    pub id: u64,
    /// Session (UUID).
    pub session_id: String,
    /// Why it ended.
    pub reason: String,
    /// Bytes sent to the target.
    pub bytes_to_target: u64,
    /// Bytes received from the target.
    pub bytes_from_target: u64,
    /// When it ended, Unix seconds.
    pub closed_at: u64,
}

/// Reports dropped, not yet acknowledged by the core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lost {
    /// Identifies the notice in the queue.
    pub id: u64,
    /// Reports dropped (0 when unknown).
    pub count: u64,
    /// First drop, Unix seconds.
    pub first_at: u64,
    /// Last drop, Unix seconds.
    pub last_at: u64,
    /// The queue file could not be read back.
    pub unreadable: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    reports: Vec<Report>,
    lost: Option<Lost>,
}

/// What [`ReportQueue::push`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pushed {
    /// Kept until the core acknowledges it.
    Queued,
    /// Dropped: the queue is full; counted and reported.
    Dropped,
}

/// The queue: in memory, and on disk after every change.
pub struct ReportQueue {
    path: PathBuf,
    key: AeadKey,
    write: KeyWriter,
    capacity: usize,
    state: Mutex<State>,
    changed: Notify,
}

#[derive(Default)]
struct State {
    stored: Stored,
    /// When each report was last sent, on the current connection.
    sent: HashMap<u64, Instant>,
    /// The notice of dropped reports last sent, and the count it carried.
    lost_sent: Option<(u64, u64)>,
}

impl std::fmt::Debug for ReportQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReportQueue")
            .field("path", &self.path)
            .field("pending", &self.pending())
            .finish_non_exhaustive()
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn new_id() -> Result<u64, TunnelError> {
    ostena_crypto::rand::array::<8>()
        .map(u64::from_be_bytes)
        .map_err(|e| TunnelError::Config(format!("tirage d'un identifiant de bilan : {e}")))
}

fn config(path: &Path, e: impl std::fmt::Display) -> TunnelError {
    TunnelError::Config(format!("{} : {e}", path.display()))
}

impl ReportQueue {
    /// Opens the queue of `dir` with [`MAX_REPORTS`]; see
    /// [`ReportQueue::open_bounded`].
    ///
    /// # Errors
    ///
    /// As [`ReportQueue::open_bounded`].
    pub fn open(dir: &Path, write: KeyWriter) -> Result<Self, TunnelError> {
        Self::open_bounded(dir, write, MAX_REPORTS)
    }

    /// Opens the queue of `dir`, holding at most `capacity` reports: reads
    /// its key, or draws one and writes it with `write` (private rights);
    /// reads the queue file if any. A queue file that cannot be read back
    /// (another key, altered) is renamed `reports.queue.corrupt-<time>`
    /// and reported as lost.
    ///
    /// # Errors
    ///
    /// [`TunnelError::Config`] if the key file cannot be read or written,
    /// or has another length.
    pub fn open_bounded(
        dir: &Path,
        write: KeyWriter,
        capacity: usize,
    ) -> Result<Self, TunnelError> {
        let path = dir.join(QUEUE_FILE);
        let key_path = dir.join(KEY_FILE);
        let key = match std::fs::read(&key_path) {
            Ok(bytes) => AeadKey::from_bytes(&SecretBytes::from(bytes))
                .map_err(|_| config(&key_path, "clé de la file illisible (32 octets attendus)"))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let (key, bytes) = AeadKey::generate().map_err(|e| config(&key_path, e))?;
                // SECRET-EXPOSURE: the key is written once, with private rights.
                #[expect(clippy::disallowed_methods)]
                write(&key_path, bytes.expose_secret()).map_err(|e| config(&key_path, e))?;
                key
            }
            Err(e) => return Err(config(&key_path, e)),
        };
        let queue = Self {
            path,
            key,
            write,
            capacity,
            state: Mutex::new(State::default()),
            changed: Notify::new(),
        };
        let stored = match std::fs::read(&queue.path) {
            Ok(sealed) => match queue.decode(&sealed) {
                Some(stored) => stored,
                None => queue.set_aside()?,
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Stored::default(),
            Err(e) => return Err(config(&queue.path, e)),
        };
        if let Ok(mut state) = queue.state.lock() {
            state.stored = stored;
        }
        Ok(queue)
    }

    fn decode(&self, sealed: &[u8]) -> Option<Stored> {
        let plain = self.key.open(sealed, AAD).ok()?;
        // SECRET-EXPOSURE: the queue is read back after decryption.
        #[expect(clippy::disallowed_methods)]
        let stored: Stored = serde_json::from_slice(plain.expose_secret()).ok()?;
        (stored.reports.len() <= self.capacity).then_some(stored)
    }

    /// Renames an unreadable queue file and starts a queue that reports it.
    fn set_aside(&self) -> Result<Stored, TunnelError> {
        let now = now_secs();
        let mut aside = self.path.as_os_str().to_owned();
        aside.push(format!(".corrupt-{now}"));
        std::fs::rename(&self.path, &aside).map_err(|e| config(&self.path, e))?;
        tracing::error!(
            event = "agent.report_queue_unreadable",
            path = %self.path.display(),
            "file des bilans de session illisible, mise de côté ; la perte est signalée au core"
        );
        let stored = Stored {
            reports: Vec::new(),
            lost: Some(Lost {
                id: new_id()?,
                count: 0,
                first_at: now,
                last_at: now,
                unreadable: true,
            }),
        };
        self.persist(&stored);
        Ok(stored)
    }

    /// Rewrites the file. A failure is logged: the queue still lives in
    /// memory and is sent as soon as the link allows.
    fn persist(&self, stored: &Stored) {
        let result = (|| -> std::io::Result<()> {
            let json = serde_json::to_vec(stored).map_err(std::io::Error::other)?;
            let sealed = self
                .key
                .seal(&SecretBytes::from(json), AAD)
                .map_err(std::io::Error::other)?;
            let mut name = self.path.as_os_str().to_owned();
            name.push(".new");
            let next = PathBuf::from(name);
            let _ = std::fs::remove_file(&next);
            (self.write)(&next, &sealed)?;
            std::fs::rename(&next, &self.path)?;
            #[cfg(unix)]
            if let Some(dir) = self.path.parent() {
                std::fs::File::open(dir)?.sync_all()?;
            }
            Ok(())
        })();
        if let Err(e) = result {
            tracing::error!(
                event = "agent.report_queue_write_failed",
                path = %self.path.display(),
                "file des bilans de session non écrite : {e}"
            );
        }
    }

    /// Queues the report of a session that ended now.
    pub fn push(
        &self,
        session_id: Uuid,
        reason: &str,
        bytes_to_target: u64,
        bytes_from_target: u64,
    ) -> Pushed {
        let now = now_secs();
        let Ok(id) = new_id() else {
            return Pushed::Dropped;
        };
        let Ok(mut state) = self.state.lock() else {
            return Pushed::Dropped;
        };
        let pushed = if state.stored.reports.len() < self.capacity {
            state.stored.reports.push(Report {
                id,
                session_id: session_id.to_string(),
                reason: reason
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(MAX_REASON)
                    .collect(),
                bytes_to_target,
                bytes_from_target,
                closed_at: now,
            });
            Pushed::Queued
        } else {
            let lost = state.stored.lost.get_or_insert(Lost {
                id,
                count: 0,
                first_at: now,
                last_at: now,
                unreadable: false,
            });
            lost.count += 1;
            lost.last_at = now;
            tracing::error!(
                event = "agent.report_queue_full",
                session = %session_id,
                dropped = lost.count,
                capacity = self.capacity,
                "file des bilans de session pleine : bilan perdu, compté et signalé au core"
            );
            Pushed::Dropped
        };
        let stored = state.stored.clone();
        drop(state);
        self.persist(&stored);
        self.changed.notify_one();
        pushed
    }

    /// The core wrote report (or notice) `id`: it leaves the queue.
    pub fn ack(&self, id: u64) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let before = state.stored.reports.len();
        state.stored.reports.retain(|r| r.id != id);
        let lost = state.stored.lost.is_some_and(|l| l.id == id);
        if lost {
            // Drops counted after the notice was sent stay, in a new one.
            let carried = match state.lost_sent {
                Some((sent, count)) if sent == id => count,
                _ => u64::MAX,
            };
            state.stored.lost = match (state.stored.lost, new_id()) {
                (Some(l), Ok(next)) if l.count > carried => Some(Lost {
                    id: next,
                    count: l.count - carried,
                    unreadable: false,
                    ..l
                }),
                _ => None,
            };
            state.lost_sent = None;
        }
        state.sent.remove(&id);
        if state.stored.reports.len() == before && !lost {
            return;
        }
        let stored = state.stored.clone();
        drop(state);
        self.persist(&stored);
    }

    /// Reports waiting for the core.
    pub fn pending(&self) -> usize {
        self.state.lock().map_or(0, |s| s.stored.reports.len())
    }

    /// The notice of dropped reports, if any.
    pub fn lost(&self) -> Option<Lost> {
        self.state.lock().ok().and_then(|s| s.stored.lost)
    }

    /// The messages to send now: those never sent on this connection, or
    /// sent more than [`RESEND`] ago.
    fn due(&self, now: Instant) -> Vec<AgentMessage> {
        let Ok(mut state) = self.state.lock() else {
            return Vec::new();
        };
        let State {
            stored,
            sent,
            lost_sent,
        } = &mut *state;
        let mut out = Vec::new();
        let mut due = |id: u64| {
            let is_due = sent
                .get(&id)
                .is_none_or(|at| now.duration_since(*at) >= RESEND);
            if is_due {
                sent.insert(id, now);
            }
            is_due
        };
        if let Some(lost) = stored.lost
            && due(lost.id)
        {
            *lost_sent = Some((lost.id, lost.count));
            out.push(AgentMessage::ReportsLost {
                report_id: lost.id,
                count: lost.count,
                first_at: lost.first_at,
                last_at: lost.last_at,
                unreadable: lost.unreadable,
            });
        }
        for report in &stored.reports {
            if due(report.id) {
                out.push(AgentMessage::SessionClosed {
                    report_id: report.id,
                    session_id: report.session_id.clone(),
                    reason: report.reason.clone(),
                    bytes_to_target: report.bytes_to_target,
                    bytes_from_target: report.bytes_from_target,
                    closed_at: report.closed_at,
                });
            }
        }
        out
    }

    /// Sends the queue on `link`, at every connection and every change,
    /// again after [`RESEND`] for what the core did not acknowledge;
    /// forever.
    pub async fn run(self: Arc<Self>, link: Arc<AgentLink>) {
        let mut connected = link.subscribe_connected();
        loop {
            if connected.borrow_and_update().is_some() {
                for message in self.due(Instant::now()) {
                    if let Err(e) = link.send(&message).await {
                        tracing::debug!(
                            event = "agent.report_unsent",
                            code = e.code(),
                            "bilan gardé en file : {e}"
                        );
                        // Sent again on the next connection.
                        if let Ok(mut state) = self.state.lock() {
                            state.sent.clear();
                        }
                        break;
                    }
                }
            }
            tokio::select! {
                () = self.changed.notified() => {}
                changed = connected.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    if let Ok(mut state) = self.state.lock() {
                        state.sent.clear();
                    }
                }
                () = tokio::time::sleep(RESEND) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests;
