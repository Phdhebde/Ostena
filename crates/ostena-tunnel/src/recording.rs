//! The transcript stream of a session, agent side (ADR-0016).
//!
//! The SSH server encodes the transcript frames and hands them over through
//! a bounded queue; [`pump`] writes them on a stream of class
//! [`StreamClass::Recording`](crate::StreamClass::Recording) of the
//! connection in use. **Fail closed**: the stream belongs to that
//! connection. If the core stops the stream (malformed, limit, storage
//! failure) or the connection is lost, the pump drops the queue, and the
//! server, which watches it, cuts the session. Nothing is buffered beyond
//! the queue and the QUIC window, nothing is written to the agent's disk.

use std::time::Duration;

use quinn::VarInt;
use tokio::sync::mpsc;

use crate::error::TunnelError;
use crate::tunnel::Channel;

/// Frames queued between the SSH server and the stream: at most 8 frames of
/// 32 KiB of output, on top of the QUIC window of the stream.
pub const QUEUE: usize = 8;

/// How long the pump waits, once the transcript is complete, for the core
/// to acknowledge all of it.
pub const FINISH_TIMEOUT: Duration = Duration::from_secs(5);

/// Application code of a stream stopped by the core on a refused transcript.
pub const STOP_REFUSED: u32 = 1;

/// Writes the frames of `frames` on `channel` until the sender side is
/// dropped (transcript complete), then finishes the stream and waits up to
/// [`FINISH_TIMEOUT`] for the core to acknowledge it.
///
/// # Errors
///
/// [`TunnelError::ConnectionLost`] if the stream fails or is stopped by the
/// core before the end: `frames` is dropped then, which tells the SSH
/// server to cut the session.
pub async fn pump(
    mut frames: mpsc::Receiver<Vec<u8>>,
    mut channel: Channel,
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
            frame = frames.recv() => match frame {
                Some(frame) => channel
                    .send
                    .write_all(&frame)
                    .await
                    .map_err(|e| lost(e.to_string()))?,
                None => break,
            },
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
    let _ = channel.recv.stop(VarInt::from_u32(STOP_REFUSED));
    let _ = channel.send.finish();
}
