//! The two transports of the tunnel behind one interface: QUIC, and TLS 1.3
//! over TCP with the multiplexer of [`crate::mux`]. Channels, the control
//! stream and the tunnel itself do not depend on which one carries them.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use ostena_crypto::tls::CertificateDer;
use quinn::VarInt;

use crate::error::TunnelError;
use crate::mux;

pub use crate::mux::StreamError;

/// The transport of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// QUIC (main transport).
    Quic,
    /// TLS 1.3 over TCP, multiplexed (fallback).
    Tcp,
}

impl Transport {
    /// `"quic"` or `"tcp"`, as logged and shown by `ostena agent status`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Quic => "quic",
            Self::Tcp => "tcp",
        }
    }
}

/// Which transport the agent dials (`agent.transport`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TransportMode {
    /// QUIC first; TCP in parallel if QUIC has not answered within
    /// [`crate::tunnel::FALLBACK_AFTER`] (default).
    #[default]
    Auto,
    /// QUIC only.
    Quic,
    /// TLS 1.3 over TCP only.
    Tcp,
}

fn code(v: VarInt) -> u32 {
    u32::try_from(v.into_inner()).unwrap_or(u32::MAX)
}

fn from_write(e: quinn::WriteError) -> StreamError {
    match e {
        quinn::WriteError::Stopped(c) => StreamError::Stopped(code(c)),
        quinn::WriteError::ClosedStream => StreamError::Closed,
        other => StreamError::ConnectionLost(other.to_string()),
    }
}

fn from_read(e: quinn::ReadError) -> StreamError {
    match e {
        quinn::ReadError::Reset(c) => StreamError::Reset(code(c)),
        quinn::ReadError::ClosedStream => StreamError::Closed,
        other => StreamError::ConnectionLost(other.to_string()),
    }
}

/// What a channel sends on.
#[derive(Debug)]
pub enum ChannelSend {
    /// A QUIC stream.
    Quic(quinn::SendStream),
    /// A stream of the TCP multiplexer.
    Tcp(mux::SendStream),
}

impl ChannelSend {
    /// Writes all of `data`, waiting for flow-control credit.
    ///
    /// # Errors
    ///
    /// The peer stopped the stream, it is finished, or the connection is
    /// lost.
    pub async fn write_all(&mut self, data: &[u8]) -> Result<(), StreamError> {
        match self {
            Self::Quic(s) => s.write_all(data).await.map_err(from_write),
            Self::Tcp(s) => s.write_all(data).await,
        }
    }

    /// Ends the stream once the bytes written are sent.
    ///
    /// # Errors
    ///
    /// [`StreamError::Closed`] if it is already finished or reset.
    pub fn finish(&mut self) -> Result<(), StreamError> {
        match self {
            Self::Quic(s) => s.finish().map_err(|_| StreamError::Closed),
            Self::Tcp(s) => s.finish(),
        }
    }

    /// Abandons the stream with an application `code`.
    ///
    /// # Errors
    ///
    /// [`StreamError::Closed`] if it is already over.
    pub fn reset(&mut self, code: u32) -> Result<(), StreamError> {
        match self {
            Self::Quic(s) => s
                .reset(VarInt::from_u32(code))
                .map_err(|_| StreamError::Closed),
            Self::Tcp(s) => s.reset(code),
        }
    }

    /// Sets the send priority (higher first).
    ///
    /// # Errors
    ///
    /// [`StreamError::Closed`] if the stream is gone.
    pub fn set_priority(&self, priority: i32) -> Result<(), StreamError> {
        match self {
            Self::Quic(s) => s.set_priority(priority).map_err(|_| StreamError::Closed),
            Self::Tcp(s) => {
                s.set_priority(priority);
                Ok(())
            }
        }
    }

    /// The send priority.
    ///
    /// # Errors
    ///
    /// [`StreamError::Closed`] if the stream is gone.
    pub fn priority(&self) -> Result<i32, StreamError> {
        match self {
            Self::Quic(s) => s.priority().map_err(|_| StreamError::Closed),
            Self::Tcp(s) => s.priority(),
        }
    }

    /// Resolves when the peer stops the stream (its code), or acknowledges
    /// every byte and the end (`None`). It does not borrow the stream, so
    /// that writes can go on while it is awaited.
    pub fn stopped(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<u32>, StreamError>> + Send + 'static>> {
        match self {
            Self::Quic(s) => {
                let stopped = s.stopped();
                Box::pin(async move {
                    match stopped.await {
                        Ok(c) => Ok(c.map(code)),
                        Err(e) => Err(StreamError::ConnectionLost(e.to_string())),
                    }
                })
            }
            Self::Tcp(s) => s.stopped(),
        }
    }
}

/// What a channel receives from.
#[derive(Debug)]
pub enum ChannelRecv {
    /// A QUIC stream.
    Quic(quinn::RecvStream),
    /// A stream of the TCP multiplexer.
    Tcp(mux::RecvStream),
}

impl ChannelRecv {
    /// Reads into `buf`; `None` at the end of the stream.
    ///
    /// # Errors
    ///
    /// Reset by the peer, stopped here, or the connection lost.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, StreamError> {
        match self {
            Self::Quic(s) => s.read(buf).await.map_err(from_read),
            Self::Tcp(s) => s.read(buf).await,
        }
    }

    /// Fills `buf` exactly.
    ///
    /// # Errors
    ///
    /// As [`ChannelRecv::read`], or [`StreamError::FinishedEarly`].
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), StreamError> {
        match self {
            Self::Quic(s) => s.read_exact(buf).await.map_err(|e| match e {
                quinn::ReadExactError::FinishedEarly(_) => StreamError::FinishedEarly,
                quinn::ReadExactError::ReadError(e) => from_read(e),
            }),
            Self::Tcp(s) => s.read_exact(buf).await,
        }
    }

    /// Asks the peer to stop sending, with an application `code`.
    ///
    /// # Errors
    ///
    /// [`StreamError::Closed`] if the direction is already over.
    pub fn stop(&mut self, code: u32) -> Result<(), StreamError> {
        match self {
            Self::Quic(s) => s
                .stop(VarInt::from_u32(code))
                .map_err(|_| StreamError::Closed),
            Self::Tcp(s) => s.stop(code),
        }
    }
}

/// A connection of either transport.
#[derive(Debug)]
pub(crate) enum Conn {
    Quic(quinn::Connection),
    Tcp {
        conn: mux::Connection,
        peer: Option<CertificateDer<'static>>,
    },
}

impl Conn {
    pub(crate) fn transport(&self) -> Transport {
        match self {
            Self::Quic(_) => Transport::Quic,
            Self::Tcp { .. } => Transport::Tcp,
        }
    }

    async fn tcp_error(conn: &mux::Connection, e: StreamError) -> TunnelError {
        if conn.is_closed() {
            conn.closed().await
        } else {
            TunnelError::ConnectionLost(e.to_string())
        }
    }

    pub(crate) async fn open_bi(&self) -> Result<(ChannelSend, ChannelRecv), TunnelError> {
        match self {
            Self::Quic(c) => {
                let (s, r) = c.open_bi().await.map_err(TunnelError::from)?;
                Ok((ChannelSend::Quic(s), ChannelRecv::Quic(r)))
            }
            Self::Tcp { conn, .. } => match conn.open().await {
                Ok((s, r)) => Ok((ChannelSend::Tcp(s), ChannelRecv::Tcp(r))),
                Err(e) => Err(Self::tcp_error(conn, e).await),
            },
        }
    }

    pub(crate) async fn accept_bi(&self) -> Result<(ChannelSend, ChannelRecv), TunnelError> {
        match self {
            Self::Quic(c) => {
                let (s, r) = c.accept_bi().await.map_err(TunnelError::from)?;
                Ok((ChannelSend::Quic(s), ChannelRecv::Quic(r)))
            }
            Self::Tcp { conn, .. } => match conn.accept().await {
                Ok((s, r)) => Ok((ChannelSend::Tcp(s), ChannelRecv::Tcp(r))),
                Err(e) => Err(Self::tcp_error(conn, e).await),
            },
        }
    }

    /// Closes on `error`, whose message (and so its code) reaches the peer.
    pub(crate) fn close(&self, code: u32, error: &TunnelError) {
        match self {
            Self::Quic(c) => {
                let reason = error.to_string();
                let reason = &reason.as_bytes()[..reason.len().min(200)];
                c.close(VarInt::from_u32(code), reason);
            }
            Self::Tcp { conn, .. } => conn.close(error.clone(), code),
        }
    }

    pub(crate) async fn closed(&self) -> TunnelError {
        match self {
            Self::Quic(c) => c.closed().await.into(),
            Self::Tcp { conn, .. } => conn.closed().await,
        }
    }

    pub(crate) fn is_closed(&self) -> bool {
        match self {
            Self::Quic(c) => c.close_reason().is_some(),
            Self::Tcp { conn, .. } => conn.is_closed(),
        }
    }

    pub(crate) fn rtt(&self) -> Duration {
        match self {
            Self::Quic(c) => c.rtt(),
            Self::Tcp { conn, .. } => conn.rtt(),
        }
    }

    pub(crate) fn peer_certificate(&self) -> Option<CertificateDer<'static>> {
        match self {
            Self::Quic(c) => crate::tunnel::peer_certificate(c),
            Self::Tcp { peer, .. } => peer.clone(),
        }
    }
}
