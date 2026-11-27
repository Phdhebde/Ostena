//! The transcript stream of a session (ADR-0016), agent side, and the
//! wire pieces the core side shares.
//!
//! The SSH server encodes the transcript frames and hands them over through
//! a bounded queue; [`run`] writes them on a stream of class
//! [`StreamClass::Recording`](crate::StreamClass::Recording).
//!
//! **Acknowledged by the core.** The core answers on the return direction
//! of the stream with the cumulative count of transcript bytes it has
//! written to the file ([`ACK_LEN`] bytes, big-endian). The agent keeps
//! every byte not acknowledged yet in a bounded buffer ([`BUFFER`]): what
//! the user has seen and the core has not written is at most that buffer,
//! and it is always known.
//!
//! **Grace.** When the connection is lost, the session goes on for at most
//! the grace ([`Resume::grace`]): the pump keeps taking the frames into the
//! buffer, waits for the link to come back, opens a new stream that resumes
//! the transcript ([`Preamble::Resume`]), and sends again from the offset
//! the core received. **Fail closed** otherwise: the session is cut
//! (the queue is dropped, the SSH server sees it) when
//!
//! - the grace is over before the transcript could be resumed;
//! - the buffer is full while the connection is lost;
//! - the core refuses the stream or the resumption (stopped, finished);
//! - the core, connected, acknowledges nothing for [`WRITE_TIMEOUT`];
//!
//! and the error says how many bytes the core never acknowledged. Nothing
//! is written to the agent's disk.
//!
//! Wire, after the channel header: the agent sends a preamble of
//! [`PREAMBLE_LEN`] bytes, `kind u8 ‖ 0 u8 ‖ grace in seconds u16`, then the
//! transcript frames. On a resumed stream the core first sends the offset
//! it resumes from (the bytes it received, partial frame included, which it
//! keeps), then acknowledgements.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{Notify, mpsc};
use tokio::time::Instant;

use crate::error::TunnelError;
use crate::ids::Uuid;
use crate::link::AgentLink;
use crate::transport::StreamError;
use crate::tunnel::Channel;

/// Frames queued between the SSH server and the pump: 2 frames of at most
/// 32 KiB of output.
pub const QUEUE: usize = 2;

/// Transcript bytes the agent keeps until the core acknowledges them: what
/// can be shown to the user before the core wrote it (ADR-0016).
pub const BUFFER: usize = 1024 * 1024;

/// Longest grace the core accepts (seconds); a longer one announced by an
/// agent is cut to it.
pub const MAX_GRACE_SECS: u16 = 300;

/// How long the pump waits, once the transcript is complete, for the core
/// to acknowledge all of it.
pub const FINISH_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the core, connected, may leave written bytes unacknowledged:
/// past it, it is taken as gone (the stream is reset and resumed within
/// the grace, or the session is cut). As the SSH server waits for room in
/// the queue.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(15);

/// How long the agent waits for the core to answer a resumption.
pub const RESUME_TIMEOUT: Duration = Duration::from_secs(5);

/// Application code of a stream stopped by the core on a refused
/// transcript or resumption.
pub const STOP_REFUSED: u32 = 1;
/// Application code of a stream reset by the agent: the core no longer
/// acknowledged it. The core waits for its resumption.
pub const RESET_STALLED: u32 = 2;
/// Application code of a stream the core leaves for the resumed one.
pub const STOP_REPLACED: u32 = 3;

/// Length of the preamble.
pub const PREAMBLE_LEN: usize = 4;
/// Length of an acknowledgement (and of the resumption offset).
pub const ACK_LEN: usize = 8;

/// Bytes written on the stream at once.
const WRITE_CHUNK: usize = 64 * 1024;
/// Delay between two resumption attempts when the link does not change.
const RETRY_EVERY: Duration = Duration::from_secs(1);

const KIND_NEW: u8 = 1;
const KIND_RESUME: u8 = 2;

/// What opens a transcript stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preamble {
    /// A new transcript; the core waits up to `grace_secs` (bounded by
    /// [`MAX_GRACE_SECS`]) for its resumption after a loss.
    New {
        /// Grace announced by the agent, in seconds.
        grace_secs: u16,
    },
    /// The resumption of a transcript already started.
    Resume,
}

impl Preamble {
    /// The preamble on the wire.
    pub fn encode(self) -> [u8; PREAMBLE_LEN] {
        match self {
            Self::New { grace_secs } => {
                let g = grace_secs.to_be_bytes();
                [KIND_NEW, 0, g[0], g[1]]
            }
            Self::Resume => [KIND_RESUME, 0, 0, 0],
        }
    }

    /// Decodes a preamble.
    ///
    /// # Errors
    ///
    /// [`TunnelError::Protocol`] for an unknown kind or a non-zero
    /// reserved byte.
    pub fn decode(bytes: [u8; PREAMBLE_LEN]) -> Result<Self, TunnelError> {
        match bytes {
            [KIND_NEW, 0, g0, g1] => Ok(Self::New {
                grace_secs: u16::from_be_bytes([g0, g1]).min(MAX_GRACE_SECS),
            }),
            [KIND_RESUME, 0, 0, 0] => Ok(Self::Resume),
            _ => Err(TunnelError::Protocol(
                "préambule de transcript invalide".into(),
            )),
        }
    }

    /// Reads the preamble of a transcript stream (core side), within
    /// [`RESUME_TIMEOUT`].
    ///
    /// # Errors
    ///
    /// [`TunnelError::Protocol`] if it is invalid, missing or late.
    pub async fn read(channel: &mut Channel) -> Result<Self, TunnelError> {
        let mut bytes = [0u8; PREAMBLE_LEN];
        match tokio::time::timeout(RESUME_TIMEOUT, channel.recv.read_exact(&mut bytes)).await {
            Ok(Ok(())) => Self::decode(bytes),
            Ok(Err(e)) => Err(TunnelError::Protocol(format!(
                "préambule de transcript : {e}"
            ))),
            Err(_) => Err(TunnelError::Protocol(
                "préambule de transcript non reçu à temps".into(),
            )),
        }
    }
}

/// Sends an acknowledgement, or the resumption offset (core side).
///
/// # Errors
///
/// The stream error.
pub async fn send_offset(channel: &mut Channel, offset: u64) -> Result<(), StreamError> {
    channel.send.write_all(&offset.to_be_bytes()).await
}

/// How a session survives a lost connection: the link to reopen the
/// stream on, and how long to wait for it.
#[derive(Debug, Clone)]
pub struct Resume {
    /// The link of the agent.
    pub link: Arc<AgentLink>,
    /// The session of the transcript.
    pub session: Uuid,
    /// Longest wait for the transcript to be resumed; zero cuts the session
    /// at once.
    pub grace: Duration,
}

/// How the pump runs.
#[derive(Debug, Clone)]
pub struct Options {
    /// See [`WRITE_TIMEOUT`].
    pub write_timeout: Duration,
    /// See [`BUFFER`].
    pub buffer: usize,
    /// `None`: no grace, a lost connection cuts the session.
    pub resume: Option<Resume>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            write_timeout: WRITE_TIMEOUT,
            buffer: BUFFER,
            resume: None,
        }
    }
}

/// The transcript bytes not acknowledged yet, and where the stream is.
#[derive(Debug)]
struct Buffer {
    /// Bytes from `acked` to `len`.
    bytes: VecDeque<u8>,
    /// Offset of the end of the transcript queued so far.
    len: u64,
    /// Bytes written on the current stream, from the start.
    sent: u64,
    /// Bytes the core acknowledged.
    acked: u64,
    /// Last acknowledgement, or last frame queued while none was pending.
    progress: Instant,
    /// The queue is closed: the transcript is complete.
    ended: bool,
    /// A stream is up.
    connected: bool,
}

impl Buffer {
    fn unacked(&self) -> u64 {
        self.len - self.acked
    }
}

#[derive(Debug)]
struct State {
    buffer: Mutex<Buffer>,
    changed: Notify,
    capacity: usize,
}

impl State {
    fn with<T>(&self, f: impl FnOnce(&mut Buffer) -> T) -> T {
        let mut guard = self
            .buffer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let out = f(&mut guard);
        drop(guard);
        self.changed.notify_waiters();
        out
    }

    fn peek<T>(&self, f: impl FnOnce(&Buffer) -> T) -> T {
        f(&self
            .buffer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner))
    }

    /// Waits until `ready` returns `Some`.
    async fn until<T>(&self, mut ready: impl FnMut(&mut Buffer) -> Option<T>) -> T {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let got = {
                let mut guard = self
                    .buffer
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                ready(&mut guard)
            };
            if let Some(v) = got {
                return v;
            }
            notified.await;
        }
    }
}

/// Why a stream ended.
enum Outcome {
    /// Every byte acknowledged, end included.
    Done,
    /// The connection is lost or the core stalled: resumable.
    Lost(String),
    /// The core refused the transcript: the session is cut.
    Refused(String),
}

fn lost_error(why: &str, unacked: u64) -> TunnelError {
    TunnelError::ConnectionLost(format!(
        "flux de transcript : {why} ; {unacked} octet(s) de transcript non acquitté(s) par le core"
    ))
}

/// [`run`] without grace: a lost connection cuts the session.
///
/// # Errors
///
/// As [`run`].
pub async fn pump(frames: mpsc::Receiver<Vec<u8>>, channel: Channel) -> Result<(), TunnelError> {
    run(frames, channel, Options::default()).await
}

/// [`pump`], with another write timeout (tests).
///
/// # Errors
///
/// As [`run`].
pub async fn pump_with(
    frames: mpsc::Receiver<Vec<u8>>,
    channel: Channel,
    write_timeout: Duration,
) -> Result<(), TunnelError> {
    run(
        frames,
        channel,
        Options {
            write_timeout,
            ..Options::default()
        },
    )
    .await
}

/// Writes the frames of `frames` on `channel`, freshly opened for the
/// session, until the sender side is dropped (transcript complete), then
/// finishes the stream and waits up to [`FINISH_TIMEOUT`] for the core to
/// acknowledge every byte: it wrote them to the file, which does not say
/// it sealed them. A lost connection is resumed within the grace of
/// `options` (see the module documentation).
///
/// # Errors
///
/// [`TunnelError::ConnectionLost`] when the transcript is lost (see the
/// module documentation), with the count of bytes the core did not
/// acknowledge: `frames` is dropped then, which tells the SSH server to
/// cut the session.
pub async fn run(
    mut frames: mpsc::Receiver<Vec<u8>>,
    mut channel: Channel,
    options: Options,
) -> Result<(), TunnelError> {
    let state = State {
        buffer: Mutex::new(Buffer {
            bytes: VecDeque::new(),
            len: 0,
            sent: 0,
            acked: 0,
            progress: Instant::now(),
            ended: false,
            connected: true,
        }),
        changed: Notify::new(),
        capacity: options.buffer.max(1),
    };
    let grace_secs = options.resume.as_ref().map_or(0, |r| {
        u16::try_from(r.grace.as_secs())
            .unwrap_or(u16::MAX)
            .min(MAX_GRACE_SECS)
    });
    let preamble = Preamble::New { grace_secs }.encode();
    let link = async {
        // Lost before the core has the preamble: it would refuse to resume
        // a transcript it never saw, so the session is cut at once, without
        // grace; the frames queued meanwhile are unacknowledged all the same.
        if let Err(e) = channel.send.write_all(&preamble).await {
            return Err(lost_error(&e.to_string(), state.with(|b| b.unacked())));
        }
        loop {
            match stream(&mut channel, &state, options.write_timeout).await {
                Outcome::Done => return Ok(()),
                Outcome::Refused(why) => return Err(lost_error(&why, state.with(|b| b.unacked()))),
                Outcome::Lost(why) => {
                    let Some(resume) = options.resume.as_ref().filter(|r| !r.grace.is_zero())
                    else {
                        return Err(lost_error(&why, state.with(|b| b.unacked())));
                    };
                    tracing::warn!(
                        event = "agent.transcript_interrupted",
                        session = %resume.session,
                        grace_secs = resume.grace.as_secs(),
                        unacked = state.with(|b| b.unacked()),
                        "flux de transcript interrompu ({why}) : reprise attendue pendant la grâce"
                    );
                    channel = reopen(resume, &state)
                        .await
                        .map_err(|why| lost_error(&why, state.with(|b| b.unacked())))?;
                    tracing::info!(
                        event = "agent.transcript_resumed",
                        session = %resume.session,
                        "flux de transcript repris sur la nouvelle connexion"
                    );
                }
            }
        }
    };
    tokio::pin!(link);
    let intake = intake(&mut frames, &state);
    tokio::pin!(intake);
    let mut taking = true;
    loop {
        tokio::select! {
            result = &mut link => return result,
            taken = &mut intake, if taking => {
                taking = false;
                if let Err(why) = taken {
                    return Err(lost_error(&why, state.with(|b| b.unacked())));
                }
            }
        }
    }
}

/// Takes the frames of the queue into the buffer; marks the end when the
/// queue is closed.
async fn intake(frames: &mut mpsc::Receiver<Vec<u8>>, state: &State) -> Result<(), String> {
    while let Some(frame) = frames.recv().await {
        let capacity = state.capacity;
        let room = state
            .until(|b| {
                let used = b.bytes.len();
                if used == 0 || used + frame.len() <= capacity {
                    Some(Ok(()))
                } else if !b.connected {
                    Some(Err(format!(
                        "tampon du transcript plein ({used} octets) pendant la coupure"
                    )))
                } else {
                    None
                }
            })
            .await;
        room?;
        state.with(|b| {
            if b.len == b.acked {
                b.progress = Instant::now();
            }
            b.bytes.extend(frame.iter());
            b.len += frame.len() as u64;
        });
    }
    state.with(|b| b.ended = true);
    Ok(())
}

fn classify_write(e: StreamError) -> Outcome {
    match e {
        StreamError::Stopped(code) => Outcome::Refused(format!("arrêté par le core (code {code})")),
        other => Outcome::Lost(other.to_string()),
    }
}

fn classify_read(e: StreamError) -> Outcome {
    match e {
        StreamError::Reset(code) => {
            Outcome::Refused(format!("réinitialisé par le core (code {code})"))
        }
        StreamError::FinishedEarly => Outcome::Refused("terminé par le core".into()),
        other => Outcome::Lost(other.to_string()),
    }
}

/// Runs one stream: writes from `sent`, reads the acknowledgements.
async fn stream(channel: &mut Channel, state: &State, write_timeout: Duration) -> Outcome {
    let stopped = channel.send.stopped();
    let Channel { send, recv, .. } = channel;
    let writer = async {
        loop {
            let next = state
                .until(|b| {
                    if b.sent < b.len {
                        let from = usize::try_from(b.sent - b.acked).unwrap_or(usize::MAX);
                        let n = (b.bytes.len() - from).min(WRITE_CHUNK);
                        Some(Some(
                            b.bytes.range(from..from + n).copied().collect::<Vec<_>>(),
                        ))
                    } else if b.ended {
                        Some(None)
                    } else {
                        None
                    }
                })
                .await;
            let Some(chunk) = next else { break };
            if let Err(e) = send.write_all(&chunk).await {
                return classify_write(e);
            }
            state.with(|b| b.sent += chunk.len() as u64);
        }
        if let Err(e) = send.finish() {
            return Outcome::Lost(e.to_string());
        }
        state.until(|b| (b.acked == b.len).then_some(())).await;
        Outcome::Done
    };
    let acks = async {
        let mut word = [0u8; ACK_LEN];
        loop {
            if let Err(e) = recv.read_exact(&mut word).await {
                // The core ends its side once it acknowledged everything.
                if matches!(e, StreamError::FinishedEarly)
                    && state.peek(|b| b.ended && b.acked == b.len)
                {
                    return Outcome::Done;
                }
                return classify_read(e);
            }
            let offset = u64::from_be_bytes(word);
            let valid = state.with(|b| {
                if offset < b.acked || offset > b.sent {
                    return false;
                }
                let n = usize::try_from(offset - b.acked).unwrap_or(usize::MAX);
                b.bytes.drain(..n.min(b.bytes.len()));
                b.acked = offset;
                b.progress = Instant::now();
                true
            });
            if !valid {
                return Outcome::Refused("accusé du core invalide".into());
            }
        }
    };
    let stall = async {
        loop {
            let (pending, since, finishing) =
                state.peek(|b| (b.len > b.acked, b.progress, b.ended && b.sent == b.len));
            let limit = if finishing {
                FINISH_TIMEOUT.min(write_timeout)
            } else {
                write_timeout
            };
            if pending && since.elapsed() >= limit {
                return Outcome::Lost("le core n'accuse plus le transcript".into());
            }
            tokio::time::sleep(limit / 8).await;
        }
    };
    let watch_stop = async {
        match stopped.await {
            Ok(Some(code)) => Outcome::Refused(format!("arrêté par le core (code {code})")),
            // Every byte and the end acknowledged by the transport: the
            // application acknowledgement decides.
            Ok(None) => std::future::pending().await,
            Err(e) => Outcome::Lost(e.to_string()),
        }
    };
    let outcome = tokio::select! {
        biased;
        o = watch_stop => o,
        o = acks => o,
        o = writer => o,
        o = stall => o,
    };
    if let Outcome::Lost(_) = outcome {
        // Never an implicit end: the core waits for the resumption.
        let _ = channel.send.reset(RESET_STALLED);
    }
    outcome
}

/// Counts the transcripts waiting for the link, so that it retries soon.
#[derive(Debug, Default)]
pub(crate) struct Waiting {
    count: AtomicUsize,
    wake: Notify,
}

impl Waiting {
    pub(crate) fn any(&self) -> bool {
        self.count.load(Ordering::SeqCst) > 0
    }

    pub(crate) async fn woken(&self) {
        self.wake.notified().await;
    }
}

struct WaitGuard<'a>(&'a Waiting);

impl<'a> WaitGuard<'a> {
    fn new(waiting: &'a Waiting) -> Self {
        waiting.count.fetch_add(1, Ordering::SeqCst);
        waiting.wake.notify_waiters();
        Self(waiting)
    }
}

impl Drop for WaitGuard<'_> {
    fn drop(&mut self) {
        self.0.count.fetch_sub(1, Ordering::SeqCst);
    }
}

enum Attempt {
    Retry,
    Refused(String),
}

/// Opens a stream that resumes the transcript, within the grace.
async fn reopen(resume: &Resume, state: &State) -> Result<Channel, String> {
    state.with(|b| b.connected = false);
    let deadline = Instant::now() + resume.grace;
    let _waiting = WaitGuard::new(resume.link.waiting());
    let mut connected = resume.link.subscribe_connected();
    connected.borrow_and_update();
    loop {
        match tokio::time::timeout_at(deadline, attempt(resume, state)).await {
            Ok(Ok(channel)) => return Ok(channel),
            Ok(Err(Attempt::Refused(why))) => return Err(why),
            Ok(Err(Attempt::Retry)) => {}
            Err(_) => break,
        }
        let wait = tokio::time::timeout(RETRY_EVERY, connected.changed());
        if tokio::time::timeout_at(deadline, wait).await.is_err() {
            break;
        }
    }
    Err(format!(
        "grâce de reconnexion de {} s dépassée",
        resume.grace.as_secs()
    ))
}

async fn attempt(resume: &Resume, state: &State) -> Result<Channel, Attempt> {
    let mut channel = resume
        .link
        .open_channel(resume.session, crate::StreamClass::Recording)
        .await
        .map_err(|_| Attempt::Retry)?;
    if channel
        .send
        .write_all(&Preamble::Resume.encode())
        .await
        .is_err()
    {
        return Err(Attempt::Retry);
    }
    let mut word = [0u8; ACK_LEN];
    match tokio::time::timeout(RESUME_TIMEOUT, channel.recv.read_exact(&mut word)).await {
        Ok(Ok(())) => {}
        Ok(Err(StreamError::Reset(_) | StreamError::FinishedEarly)) => {
            return Err(Attempt::Refused("reprise refusée par le core".into()));
        }
        Ok(Err(_)) => return Err(Attempt::Retry),
        Err(_) => {
            let _ = channel.send.reset(RESET_STALLED);
            return Err(Attempt::Retry);
        }
    }
    let offset = u64::from_be_bytes(word);
    let resumed = state.with(|b| {
        if offset < b.acked || offset > b.sent {
            return false;
        }
        b.sent = offset;
        b.progress = Instant::now();
        b.connected = true;
        true
    });
    if resumed {
        Ok(channel)
    } else {
        let _ = channel.send.reset(STOP_REFUSED);
        Err(Attempt::Refused("offset de reprise invalide".into()))
    }
}

/// Stops a transcript stream received by the core, with
/// [`STOP_REFUSED`]: the agent cuts the session.
pub fn refuse(channel: &mut Channel) {
    let _ = channel.recv.stop(STOP_REFUSED);
    let _ = channel.send.finish();
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// Any 4 bytes: refused, or a preamble that encodes back to the
        /// same bytes (a longer grace is cut to the bound).
        #[test]
        fn prop_preamble_is_canonical(bytes in any::<[u8; PREAMBLE_LEN]>()) {
            if let Ok(p) = Preamble::decode(bytes) {
                if let Preamble::New { grace_secs } = p {
                    prop_assert!(grace_secs <= MAX_GRACE_SECS);
                }
                prop_assert_eq!(Preamble::decode(p.encode()), Ok(p));
            }
        }
    }

    #[test]
    fn preamble_round_trip_and_refusals() {
        for p in [
            Preamble::New { grace_secs: 0 },
            Preamble::New { grace_secs: 60 },
            Preamble::Resume,
        ] {
            assert_eq!(Preamble::decode(p.encode()), Ok(p));
        }
        assert_eq!(
            Preamble::decode(Preamble::New { grace_secs: 9999 }.encode()),
            Ok(Preamble::New {
                grace_secs: MAX_GRACE_SECS
            })
        );
        for bad in [[0, 0, 0, 0], [3, 0, 0, 0], [1, 1, 0, 0], [2, 0, 0, 1]] {
            assert!(Preamble::decode(bad).is_err());
        }
    }
}
