//! The pre-check applied to a connection: the peer identification line goes
//! to the SSH library once valid, its first packet is held until accepted,
//! then everything is replayed unchanged to the library, which reads it as if nothing stood in
//! between. Writes go straight through, so that our own identification line
//! and KEXINIT leave at once (both sides send theirs without waiting).
//!
//! A refusal ends the reads with an error carrying the stable code, and
//! emits `ssh.precheck_refused`.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

use super::{
    MAX_LINE, MAX_PACKET, MAX_PREFACE_LINES, PrecheckError, Progress, Role, identification, inspect,
};

/// Default deadline for the identification line and the first packet.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Most bytes held before a decision: preface lines, identification line,
/// largest first packet, and what may follow it in the same reads.
const MAX_HELD: usize = MAX_PREFACE_LINES * MAX_LINE + 4 + MAX_PACKET + 16 * 1024;

enum State {
    /// Reading until a decision; `released` bytes (the identification
    /// line, once valid) already went to the reader.
    Inspecting { held: Vec<u8>, released: usize },
    /// Accepted: replaying what was held.
    Replaying { held: Vec<u8>, at: usize },
    /// Everything replayed.
    Through,
    /// Refused.
    Refused(PrecheckError),
}

/// A connection whose peer is pre-checked before the SSH library reads it.
pub struct Prechecked<S> {
    inner: S,
    role: Role,
    peer: String,
    state: State,
    deadline: Pin<Box<Sleep>>,
}

impl<S> std::fmt::Debug for Prechecked<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prechecked")
            .field("role", &self.role)
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl<S> Prechecked<S> {
    /// Wraps `inner`, the connection to `peer` (for events), as `role`.
    ///
    /// # Panics
    ///
    /// Outside a Tokio runtime with time enabled.
    pub fn new(inner: S, role: Role, peer: impl Into<String>, timeout: Duration) -> Self {
        Self {
            inner,
            role,
            peer: peer.into(),
            state: State::Inspecting {
                held: Vec::new(),
                released: 0,
            },
            deadline: Box::pin(tokio::time::sleep(timeout)),
        }
    }

    /// The refusal, if the peer was refused.
    pub fn refusal(&self) -> Option<&PrecheckError> {
        match &self.state {
            State::Refused(e) => Some(e),
            _ => None,
        }
    }

    fn refuse(&mut self, error: PrecheckError) -> io::Error {
        tracing::warn!(
            event = "ssh.precheck_refused",
            code = error.code(),
            role = self.role.as_str(),
            peer = %self.peer,
            "{error}"
        );
        let io_error = io::Error::new(io::ErrorKind::PermissionDenied, error.to_string());
        self.state = State::Refused(error);
        io_error
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prechecked<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            match &mut this.state {
                State::Through => return Pin::new(&mut this.inner).poll_read(cx, out),
                State::Refused(e) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        e.to_string(),
                    )));
                }
                State::Replaying { held, at } => {
                    // Never answer an empty read here: it would look like the
                    // end of the stream.
                    if *at >= held.len() {
                        this.state = State::Through;
                        continue;
                    }
                    let n = (held.len() - *at).min(out.remaining());
                    out.put_slice(&held[*at..*at + n]);
                    *at += n;
                    if *at == held.len() {
                        this.state = State::Through;
                    }
                    return Poll::Ready(Ok(()));
                }
                State::Inspecting { held, released } => {
                    // The identification line goes to the reader as soon as it
                    // is valid: the library sends its KEXINIT only after reading
                    // the peer one, so holding it could block two pre-checked
                    // ends on each other. The first packet stays held.
                    match identification(held, this.role) {
                        Err(e) => return Poll::Ready(Err(this.refuse(e))),
                        Ok(Some(end)) if *released < end => {
                            let n = (end - *released).min(out.remaining());
                            out.put_slice(&held[*released..*released + n]);
                            *released += n;
                            return Poll::Ready(Ok(()));
                        }
                        Ok(_) => {}
                    }
                    match inspect(held, this.role) {
                        Ok(Progress::Accepted { .. }) => {
                            let at = *released;
                            let held = std::mem::take(held);
                            this.state = State::Replaying { held, at };
                            continue;
                        }
                        Err(e) => return Poll::Ready(Err(this.refuse(e))),
                        Ok(Progress::NeedMore) => {}
                    }
                    if this.deadline.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Err(this.refuse(PrecheckError::Timeout)));
                    }
                    let mut chunk = [0u8; 4096];
                    let mut buf = ReadBuf::new(&mut chunk);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => {
                            return Poll::Ready(Err(this.refuse(PrecheckError::Io(e.to_string()))));
                        }
                        Poll::Ready(Ok(())) if buf.filled().is_empty() => {
                            return Poll::Ready(Err(
                                this.refuse(PrecheckError::Io("fermée par le pair".into()))
                            ));
                        }
                        Poll::Ready(Ok(())) => {
                            held.extend_from_slice(buf.filled());
                            if held.len() > MAX_HELD {
                                return Poll::Ready(Err(this.refuse(PrecheckError::Packet(
                                    "trop d'octets avant la décision",
                                ))));
                            }
                        }
                    }
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prechecked<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
