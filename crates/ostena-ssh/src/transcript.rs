//! The transcript of a session, as the agent SSH server records it
//! (ADR-0016).
//!
//! The server hands each event to a [`Transcript`]: the frame is encoded
//! (`ostena_recorder::wire`) and queued, bounded, towards the stream to the
//! core; an output of the target is queued **before** it is relayed to the
//! user. The queue is consumed by the agent (`ostena_tunnel::recording`).
//!
//! The transcript is **lost** when the queue is dropped (stream stopped by
//! the core, tunnel lost, core restarted) or when a frame waits more than
//! [`SEND_TIMEOUT`] for room (a core that no longer reads). Every call then
//! fails and [`Transcript::closed`] completes, without waiting for a call in
//! progress: the server cuts the session (`SSH-E021`).
//!
//! Times are microseconds since the start event, from the monotonic clock;
//! they never go back. Events are serialised: the time is taken and the
//! frame queued under one lock. A window change is not queued by the SSH
//! handler, which must never wait for the core: it is kept, and recorded
//! before the next output.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ostena_recorder::{EndReason, Event, Frame, wire};
use tokio::sync::{Mutex, Notify, mpsc};

use crate::error::SshError;

/// How long a frame may wait for room in the queue: past it, the core is
/// taken as gone and the session is cut.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(15);

/// The terminal of a session, as asked by the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Terminal {
    /// `TERM`: printable ASCII, 1 to 64 bytes.
    pub term: String,
    /// Columns.
    pub cols: u32,
    /// Rows.
    pub rows: u32,
}

#[derive(Debug)]
struct State {
    /// Dropped after the end frame (the stream is then finished) or when
    /// the transcript is lost.
    tx: Option<mpsc::Sender<Vec<u8>>>,
    origin: Option<Instant>,
    last_us: u64,
    output: u64,
}

/// What [`Transcript::closed`] watches, outside the lock of the state.
#[derive(Debug)]
struct Signal {
    lost: AtomicBool,
    notify: Notify,
    /// A sender kept to see the queue dropped by the agent; taken at the
    /// end or at the loss.
    probe: std::sync::Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    /// A window change not recorded yet: `cols << 32 | rows`, 0 for none.
    resize: AtomicU64,
}

/// The transcript of one session. Cheap to clone: the clones share the
/// queue and the clock.
#[derive(Debug, Clone)]
pub struct Transcript {
    state: Arc<Mutex<State>>,
    signal: Arc<Signal>,
    send_timeout: Duration,
}

fn lost(why: &str) -> SshError {
    SshError::TranscriptLost(why.to_owned())
}

fn cells(value: u32) -> u16 {
    u16::try_from(value.clamp(1, u32::from(ostena_recorder::event::MAX_CELLS))).unwrap_or(1)
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

impl Transcript {
    /// A transcript whose encoded frames go to `tx`, waiting at most
    /// [`SEND_TIMEOUT`] for room.
    pub fn new(tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self::with_timeout(tx, SEND_TIMEOUT)
    }

    /// The same, waiting at most `send_timeout` for room (tests).
    pub fn with_timeout(tx: mpsc::Sender<Vec<u8>>, send_timeout: Duration) -> Self {
        Self {
            signal: Arc::new(Signal {
                lost: AtomicBool::new(false),
                notify: Notify::new(),
                probe: std::sync::Mutex::new(Some(tx.clone())),
                resize: AtomicU64::new(0),
            }),
            state: Arc::new(Mutex::new(State {
                tx: Some(tx),
                origin: None,
                last_us: 0,
                output: 0,
            })),
            send_timeout,
        }
    }

    /// A transcript and the receiving end of its queue of `capacity`
    /// frames.
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        (Self::new(tx), rx)
    }

    /// Drops the queue and wakes [`Transcript::closed`]: the session is
    /// cut.
    fn lose(&self, state: &mut State) {
        state.tx = None;
        if let Ok(mut probe) = self.signal.probe.lock() {
            *probe = None;
        }
        self.signal.lost.store(true, Ordering::SeqCst);
        self.signal.notify.notify_waiters();
    }

    /// Queues the frame of `event` at the current time (0 for the start).
    async fn queue(&self, state: &mut State, event: Event) -> Result<(), SshError> {
        let at_us = if let Some(origin) = state.origin {
            let now = u64::try_from(origin.elapsed().as_micros()).unwrap_or(u64::MAX);
            state.last_us = state.last_us.max(now);
            state.last_us
        } else {
            state.origin = Some(Instant::now());
            0
        };
        let mut frame = Vec::new();
        match event {
            Event::Output(data) => wire::encode_output(at_us, &data, &mut frame),
            event => wire::encode(&Frame { at_us, event }, &mut frame)
                .map_err(|e| SshError::TranscriptLost(e.to_string()))?,
        }
        let tx = state
            .tx
            .as_ref()
            .ok_or_else(|| lost("transcript terminé ou perdu"))?;
        match tx.send_timeout(frame, self.send_timeout).await {
            Ok(()) => Ok(()),
            Err(mpsc::error::SendTimeoutError::Timeout(_)) => {
                self.lose(state);
                Err(lost("le core ne lit plus le transcript"))
            }
            Err(mpsc::error::SendTimeoutError::Closed(_)) => {
                self.lose(state);
                Err(lost("flux vers le core perdu"))
            }
        }
    }

    async fn start_locked(
        &self,
        state: &mut State,
        terminal: Option<&Terminal>,
        command: Option<&[u8]>,
    ) -> Result<(), SshError> {
        let (term, cols, rows) = terminal.map_or((String::new(), 0, 0), |t| {
            (t.term.clone(), cells(t.cols), cells(t.rows))
        });
        self.queue(
            state,
            Event::Start {
                cols,
                rows,
                started_ms: unix_ms(),
                term,
                command: command.map(<[u8]>::to_vec),
            },
        )
        .await
    }

    /// Records the window change kept by [`Transcript::resize`], if any.
    async fn pending_resize(&self, state: &mut State) -> Result<(), SshError> {
        let packed = self.signal.resize.swap(0, Ordering::SeqCst);
        if packed == 0 {
            return Ok(());
        }
        let cols = u32::try_from(packed >> 32).unwrap_or(1);
        let rows = u32::try_from(packed & u64::from(u32::MAX)).unwrap_or(1);
        let event = Event::Resize {
            cols: cells(cols),
            rows: cells(rows),
        };
        self.queue(state, event).await
    }

    /// Records the start of the shell or of `command`, with `terminal` if
    /// any. Once only: a second start, or one after an output, is refused,
    /// so that no command runs unrecorded.
    ///
    /// # Errors
    ///
    /// [`SshError::TranscriptLost`] (`SSH-E021`), or [`SshError::Refused`]
    /// if already started.
    pub async fn start(
        &self,
        terminal: Option<&Terminal>,
        command: Option<&[u8]>,
    ) -> Result<(), SshError> {
        let mut state = self.state.lock().await;
        if state.origin.is_some() {
            return Err(SshError::Refused("transcript déjà commencé"));
        }
        self.start_locked(&mut state, terminal, command).await
    }

    /// Records an output of the target; call it before relaying `data` to
    /// the user. An output before the start starts the transcript without
    /// terminal nor command. A window change kept since the last output is
    /// recorded first.
    ///
    /// # Errors
    ///
    /// [`SshError::TranscriptLost`]: do not relay `data`, cut the session.
    pub async fn output(&self, data: &[u8]) -> Result<(), SshError> {
        if data.is_empty() {
            return Ok(());
        }
        let mut state = self.state.lock().await;
        if state.origin.is_none() {
            self.start_locked(&mut state, None, None).await?;
        }
        self.pending_resize(&mut state).await?;
        self.queue(&mut state, Event::Output(data.to_vec())).await?;
        state.output = state.output.saturating_add(data.len() as u64);
        Ok(())
    }

    /// Keeps a window change, recorded before the next output: never
    /// waits, so the SSH handler never waits for the core. A zero size (no
    /// character grid) is ignored; a later change replaces an unrecorded
    /// one, which nothing was displayed in.
    pub fn resize(&self, cols: u32, rows: u32) {
        if cols == 0 || rows == 0 {
            return;
        }
        let packed = (u64::from(cols) << 32) | u64::from(rows);
        self.signal.resize.store(packed, Ordering::SeqCst);
    }

    /// Records the end, then closes the queue: the stream is finished. A
    /// transcript never started gets its start first. Later calls fail.
    ///
    /// # Errors
    ///
    /// [`SshError::TranscriptLost`].
    pub async fn end(&self, reason: EndReason) -> Result<(), SshError> {
        let mut state = self.state.lock().await;
        if state.tx.is_none() {
            return Err(lost("transcript déjà terminé ou perdu"));
        }
        if state.origin.is_none() {
            self.start_locked(&mut state, None, None).await?;
        }
        let output_bytes = state.output;
        let sent = self
            .queue(
                &mut state,
                Event::End {
                    reason,
                    output_bytes,
                },
            )
            .await;
        state.tx = None;
        if let Ok(mut probe) = self.signal.probe.lock() {
            *probe = None;
        }
        sent
    }

    /// Completes when the transcript is lost (queue dropped by the agent,
    /// or a frame that waited too long): the session must then be cut.
    /// Never waits for a call in progress. Pending forever once the end is
    /// recorded.
    pub async fn closed(&self) {
        let notified = self.signal.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.signal.lost.load(Ordering::SeqCst) {
            return;
        }
        let probe = self.signal.probe.lock().ok().and_then(|p| p.clone());
        match probe {
            Some(tx) => {
                tokio::select! {
                    () = tx.closed() => {}
                    () = notified => {}
                }
            }
            None => notified.await,
        }
    }
}

#[cfg(test)]
mod tests {
    use ostena_recorder::{Decoder, Limits};

    use super::*;

    fn decode(frames: Vec<Vec<u8>>) -> Vec<Frame> {
        let mut decoder = Decoder::new(Limits::default());
        let mut out = Vec::new();
        for f in frames {
            decoder.feed(&f);
            while let Some(frame) = decoder.next_frame().unwrap() {
                out.push(frame);
            }
        }
        decoder.finish().unwrap();
        out
    }

    async fn drain(mut rx: mpsc::Receiver<Vec<u8>>) -> Vec<Vec<u8>> {
        let mut all = Vec::new();
        while let Some(f) = rx.recv().await {
            all.push(f);
        }
        all
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
    }

    #[test]
    fn a_session_decodes_strictly() {
        rt().block_on(async {
            let (t, rx) = Transcript::channel(64);
            let drained = tokio::spawn(drain(rx));
            let terminal = Terminal {
                term: "xterm-256color".into(),
                cols: 120,
                rows: 40,
            };
            t.start(Some(&terminal), None).await.unwrap();
            t.output(b"hello\r\n").await.unwrap();
            t.resize(100, 30);
            t.output(&vec![b'x'; 70_000]).await.unwrap();
            assert!(t.start(None, Some(b"id")).await.is_err());
            t.end(EndReason::Closed).await.unwrap();
            assert!(t.output(b"late").await.is_err());
            let frames = decode(drained.await.unwrap());
            assert!(matches!(
                &frames[0].event,
                Event::Start { cols: 120, rows: 40, term, command: None, .. }
                    if term == "xterm-256color"
            ));
            // Start, 7 bytes, a resize, 70 000 bytes in three frames, end.
            assert_eq!(frames.len(), 7);
            assert_eq!(
                frames.last().unwrap().event,
                Event::End {
                    reason: EndReason::Closed,
                    output_bytes: 70_007
                }
            );
            assert!(frames.windows(2).all(|w| w[0].at_us <= w[1].at_us));
        });
    }

    #[test]
    fn exec_and_unstarted_sessions_are_complete() {
        rt().block_on(async {
            let (t, rx) = Transcript::channel(4);
            let drained = tokio::spawn(drain(rx));
            t.start(None, Some(b"uname -a")).await.unwrap();
            t.end(EndReason::Expired).await.unwrap();
            let frames = decode(drained.await.unwrap());
            assert!(matches!(
                &frames[0].event,
                Event::Start { command: Some(c), cols: 0, .. } if c == b"uname -a"
            ));

            // Never started: start then end. Output first: implicit start.
            let (t, rx) = Transcript::channel(4);
            let drained = tokio::spawn(drain(rx));
            t.end(EndReason::Revoked).await.unwrap();
            assert_eq!(decode(drained.await.unwrap()).len(), 2);
            let (t, rx) = Transcript::channel(4);
            let drained = tokio::spawn(drain(rx));
            t.output(b"banner").await.unwrap();
            t.end(EndReason::Closed).await.unwrap();
            assert_eq!(decode(drained.await.unwrap()).len(), 3);
        });
    }

    /// A core that no longer reads: the frame that waits too long loses
    /// the transcript, and the loss is seen while that call still waits.
    #[test]
    fn a_queue_that_is_not_read_loses_the_transcript() {
        rt().block_on(async {
            let (tx, rx) = mpsc::channel(1);
            let t = Transcript::with_timeout(tx, Duration::from_millis(200));
            t.start(None, None).await.unwrap();
            let started = Instant::now();
            let blocked = tokio::spawn({
                let t = t.clone();
                async move { t.output(b"never read").await }
            });
            tokio::time::timeout(Duration::from_secs(5), t.closed())
                .await
                .unwrap();
            assert_eq!(blocked.await.unwrap().unwrap_err().code(), "SSH-E021");
            assert!(started.elapsed() < Duration::from_secs(5));
            assert!(t.end(EndReason::Closed).await.is_err());
            // The resize kept by the handler never waits.
            t.resize(80, 24);
            drop(rx);
        });
    }

    #[test]
    fn a_lost_queue_fails_and_is_seen() {
        rt().block_on(async {
            let (t, rx) = Transcript::channel(4);
            t.start(None, None).await.unwrap();
            drop(rx);
            tokio::time::timeout(Duration::from_secs(1), t.closed())
                .await
                .unwrap();
            let e = t.output(b"secret").await.unwrap_err();
            assert_eq!(e.code(), "SSH-E021");
            assert!(t.end(EndReason::Closed).await.is_err());
        });
    }
}
