//! The transcript of a session, as the agent SSH server records it
//! (ADR-0016).
//!
//! The server hands each event to a [`Transcript`]: the frame is encoded
//! (`ostena_recorder::wire`) and queued, bounded, towards the stream to the
//! core; an output of the target is queued **before** it is relayed to the
//! user. The queue is consumed by the agent (`ostena_tunnel::recording`).
//! When it is dropped (stream stopped by the core, tunnel lost, core
//! restarted), every call fails and [`Transcript::closed`] completes: the
//! server cuts the session (`SSH-E021`).
//!
//! Times are microseconds since the start event, from the monotonic clock;
//! they never go back. Events are serialised: the time is taken and the
//! frame queued under one lock.

use std::sync::Arc;
use std::time::Instant;

use ostena_recorder::{EndReason, Event, Frame, wire};
use tokio::sync::{Mutex, mpsc};

use crate::error::SshError;

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
    /// Dropped after the end frame: the stream is then finished.
    tx: Option<mpsc::Sender<Vec<u8>>>,
    origin: Option<Instant>,
    last_us: u64,
    output: u64,
}

/// The transcript of one session. Cheap to clone: the clones share the
/// queue and the clock.
#[derive(Debug, Clone)]
pub struct Transcript {
    state: Arc<Mutex<State>>,
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
    /// A transcript whose encoded frames go to `tx`.
    pub fn new(tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                tx: Some(tx),
                origin: None,
                last_us: 0,
                output: 0,
            })),
        }
    }

    /// A transcript and the receiving end of its queue of `capacity`
    /// frames.
    pub fn channel(capacity: usize) -> (Self, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        (Self::new(tx), rx)
    }

    /// Queues the frame of `event` at the current time (0 for the start).
    async fn queue(state: &mut State, event: Event) -> Result<(), SshError> {
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
            .ok_or_else(|| lost("transcript terminé"))?;
        tx.send(frame)
            .await
            .map_err(|_| lost("flux vers le core perdu"))
    }

    async fn start_locked(
        state: &mut State,
        terminal: Option<&Terminal>,
        command: Option<&[u8]>,
    ) -> Result<(), SshError> {
        let (term, cols, rows) = terminal.map_or((String::new(), 0, 0), |t| {
            (t.term.clone(), cells(t.cols), cells(t.rows))
        });
        Self::queue(
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
        Self::start_locked(&mut state, terminal, command).await
    }

    /// Records an output of the target; call it before relaying `data` to
    /// the user. An output before the start starts the transcript without
    /// terminal nor command.
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
            Self::start_locked(&mut state, None, None).await?;
        }
        Self::queue(&mut state, Event::Output(data.to_vec())).await?;
        state.output = state.output.saturating_add(data.len() as u64);
        Ok(())
    }

    /// Records a window change; ignored before the start, or for a zero
    /// size (no character grid).
    ///
    /// # Errors
    ///
    /// [`SshError::TranscriptLost`].
    pub async fn resize(&self, cols: u32, rows: u32) -> Result<(), SshError> {
        let mut state = self.state.lock().await;
        if state.origin.is_none() || cols == 0 || rows == 0 {
            return Ok(());
        }
        let event = Event::Resize {
            cols: cells(cols),
            rows: cells(rows),
        };
        Self::queue(&mut state, event).await
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
            return Err(lost("transcript déjà terminé"));
        }
        if state.origin.is_none() {
            Self::start_locked(&mut state, None, None).await?;
        }
        let output_bytes = state.output;
        let sent = Self::queue(
            &mut state,
            Event::End {
                reason,
                output_bytes,
            },
        )
        .await;
        state.tx = None;
        sent
    }

    /// Completes when the queue can no longer reach the core: the session
    /// must then be cut. Pending forever once the end is recorded.
    pub async fn closed(&self) {
        let tx = self.state.lock().await.tx.clone();
        match tx {
            Some(tx) => tx.closed().await,
            None => std::future::pending().await,
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
            t.resize(100, 30).await.unwrap();
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

    #[test]
    fn a_lost_queue_fails_and_is_seen() {
        rt().block_on(async {
            let (t, rx) = Transcript::channel(4);
            t.start(None, None).await.unwrap();
            drop(rx);
            tokio::time::timeout(std::time::Duration::from_secs(1), t.closed())
                .await
                .unwrap();
            let e = t.output(b"secret").await.unwrap_err();
            assert_eq!(e.code(), "SSH-E021");
            assert!(t.end(EndReason::Closed).await.is_err());
        });
    }
}
