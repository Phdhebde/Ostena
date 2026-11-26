//! The transcript stream of a session, agent side (ADR-0016).
//!
//! The SSH server encodes the transcript frames and hands them over through
//! a bounded queue; [`pump`] writes them on a stream of class
//! [`StreamClass::Recording`](crate::StreamClass::Recording) of the
//! connection in use. **Fail closed**: the stream belongs to that
//! connection. If the core stops the stream (malformed, limit, storage
//! failure) or the connection is lost, the pump drops the queue, and the
//! server, which watches it, cuts the session. Nothing is buffered beyond
//! the queue and the stream window (QUIC or TCP multiplexer), nothing is
//! written to the agent's disk.

use std::time::Duration;

use tokio::sync::mpsc;

use crate::error::TunnelError;
use crate::tunnel::Channel;

/// Frames queued between the SSH server and the stream: at most 2 frames of
/// 32 KiB of output (64 KiB), on top of the frame the pump is writing and of
/// the QUIC window of the stream. What can be shown to the user before the
/// core received it is bounded by their sum (ADR-0016). QUIC (quinn 0.11)
/// has one receive window for every stream of a connection, so the window
/// of this stream cannot be made smaller than that of the session streams.
pub const QUEUE: usize = 2;

/// How long the pump waits, once the transcript is complete, for the core
/// to acknowledge all of it.
pub const FINISH_TIMEOUT: Duration = Duration::from_secs(5);

/// How long one frame may wait for the core to give room on the stream:
/// past it, the core is taken as gone, the stream is reset and the queue
/// dropped (the session is cut). As the agent waits for room in the queue.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(15);

/// Application code of a stream stopped by the core on a refused transcript.
pub const STOP_REFUSED: u32 = 1;
/// Application code of a stream reset by the agent: the core no longer
/// read it.
pub const RESET_STALLED: u32 = 2;

/// Writes the frames of `frames` on `channel` until the sender side is
/// dropped (transcript complete), then finishes the stream and waits up to
/// [`FINISH_TIMEOUT`] for the transport acknowledgement of its end: QUIC
/// acknowledges all the data and the end, which says the core received
/// them, not that it sealed them.
///
/// # Errors
///
/// [`TunnelError::ConnectionLost`] if the stream fails, is stopped by the
/// core before the end, or a frame waits more than [`WRITE_TIMEOUT`]:
/// `frames` is dropped then, which tells the SSH server to cut the session.
pub async fn pump(frames: mpsc::Receiver<Vec<u8>>, channel: Channel) -> Result<(), TunnelError> {
    pump_with(frames, channel, WRITE_TIMEOUT).await
}

/// [`pump`], with another write timeout (tests).
///
/// # Errors
///
/// As [`pump`].
pub async fn pump_with(
    mut frames: mpsc::Receiver<Vec<u8>>,
    mut channel: Channel,
    write_timeout: Duration,
) -> Result<(), TunnelError> {
    let stopped = channel.send.stopped();
    tokio::pin!(stopped);
    let lost = |why: String| TunnelError::ConnectionLost(format!("flux de transcript : {why}"));
    loop {
        tokio::select! {
            biased;
            why = &mut stopped => {
                let why = match why {
                    Ok(Some(code)) => format!("arrêté par le core (code {code})"),
                    Ok(None) => "fermé".to_owned(),
                    Err(e) => e.to_string(),
                };
                return Err(lost(why));
            }
            frame = frames.recv() => {
                let Some(frame) = frame else { break };
                let written =
                    tokio::time::timeout(write_timeout, channel.send.write_all(&frame)).await;
                let Ok(written) = written else {
                    let _ = channel.send.reset(RESET_STALLED);
                    return Err(lost("le core ne lit plus le transcript".into()));
                };
                written.map_err(|e| lost(e.to_string()))?;
            }
        }
    }
    drop(frames);
    channel.send.finish().map_err(|e| lost(e.to_string()))?;
    match tokio::time::timeout(FINISH_TIMEOUT, stopped).await {
        Ok(Ok(None)) => Ok(()),
        Ok(Ok(Some(code))) => Err(lost(format!("arrêté par le core (code {code})"))),
        Ok(Err(e)) => Err(lost(e.to_string())),
        Err(_) => Err(lost("fin non acquittée par le core".into())),
    }
}

/// Stops a transcript stream received by the core, with
/// [`STOP_REFUSED`]: the agent cuts the session.
pub fn refuse(channel: &mut Channel) {
    let _ = channel.recv.stop(STOP_REFUSED);
    let _ = channel.send.finish();
}
