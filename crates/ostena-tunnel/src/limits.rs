//! Bounds of a tunnel: sessions, streams, buffers, timers (ADR-0008).

use std::sync::Arc;
use std::time::Duration;

use quinn::{IdleTimeout, TransportConfig, VarInt};

use crate::error::TunnelError;

/// One stream per traffic class.
const STREAMS_PER_SESSION: u32 = 3;

/// Tunnel bounds. Every value is checked by [`Limits::validate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Concurrent sessions (1 to 4096). Each has up to three streams, plus
    /// one control stream per tunnel.
    pub max_sessions: u32,
    /// Receive window of one stream, in bytes (16 KiB to 16 MiB).
    pub stream_window: u32,
    /// Receive and send windows of the whole connection, in bytes (at least
    /// one stream window, at most 256 MiB).
    pub connection_window: u32,
    /// QUIC keep-alive interval.
    pub keep_alive: Duration,
    /// QUIC idle timeout: the connection is declared lost after this silence.
    pub idle_timeout: Duration,
    /// Application ping interval on the control stream.
    pub heartbeat_interval: Duration,
    /// No pong for this long: the peer is declared unresponsive.
    pub heartbeat_timeout: Duration,
    /// Connection and hello exchange deadline.
    pub handshake_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_sessions: 256,
            stream_window: 256 * 1024,
            connection_window: 8 * 1024 * 1024,
            keep_alive: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(15),
            heartbeat_interval: Duration::from_secs(10),
            heartbeat_timeout: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(10),
        }
    }
}

impl Limits {
    /// Checks the bounds and their consistency.
    ///
    /// # Errors
    ///
    /// [`TunnelError::Config`] naming the offending value.
    pub fn validate(&self) -> Result<(), TunnelError> {
        let fail = |what: &str| Err(TunnelError::Config(what.to_owned()));
        if !(1..=4096).contains(&self.max_sessions) {
            return fail("max_sessions hors de 1..=4096");
        }
        if !(16 * 1024..=16 * 1024 * 1024).contains(&self.stream_window) {
            return fail("stream_window hors de 16 Kio..=16 Mio");
        }
        if self.connection_window < self.stream_window || self.connection_window > 256 * 1024 * 1024
        {
            return fail("connection_window inférieure à stream_window ou supérieure à 256 Mio");
        }
        if self.keep_alive.is_zero() || self.keep_alive >= self.idle_timeout {
            return fail("keep_alive nul ou supérieur au délai d'inactivité");
        }
        if self.heartbeat_interval.is_zero() || self.heartbeat_interval >= self.heartbeat_timeout {
            return fail("heartbeat_interval nul ou supérieur à heartbeat_timeout");
        }
        if self.handshake_timeout.is_zero() {
            return fail("handshake_timeout nul");
        }
        Ok(())
    }

    /// Streams a peer may open: three per session plus the control stream.
    pub fn max_streams(&self) -> u32 {
        self.max_sessions * STREAMS_PER_SESSION + 1
    }

    /// Upper bound of the transport buffers of one tunnel, in bytes: what
    /// the peer may send unread plus what we may keep unacknowledged.
    pub fn max_buffered_bytes(&self) -> u64 {
        2 * u64::from(self.connection_window)
    }

    /// The QUIC transport configuration.
    ///
    /// # Errors
    ///
    /// [`TunnelError::Config`] if the limits are invalid.
    pub(crate) fn transport(&self) -> Result<Arc<TransportConfig>, TunnelError> {
        self.validate()?;
        let idle = IdleTimeout::try_from(self.idle_timeout)
            .map_err(|_| TunnelError::Config("idle_timeout trop grand".into()))?;
        let mut t = TransportConfig::default();
        t.max_concurrent_bidi_streams(VarInt::from_u32(self.max_streams()))
            .max_concurrent_uni_streams(VarInt::from_u32(0))
            .stream_receive_window(VarInt::from_u32(self.stream_window))
            .receive_window(VarInt::from_u32(self.connection_window))
            .send_window(u64::from(self.connection_window))
            .keep_alive_interval(Some(self.keep_alive))
            .max_idle_timeout(Some(idle))
            .datagram_receive_buffer_size(None);
        Ok(Arc::new(t))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::StreamClass;

    #[test]
    fn defaults_are_valid_and_bounded() {
        assert_eq!(STREAMS_PER_SESSION as usize, StreamClass::ALL.len());
        let l = Limits::default();
        assert!(l.validate().is_ok());
        assert_eq!(l.max_streams(), 769);
        assert_eq!(l.max_buffered_bytes(), 16 * 1024 * 1024);
        assert!(l.transport().is_ok());
    }

    #[test]
    fn each_bound_is_checked() {
        let cases: [fn(&mut Limits); 9] = [
            |l| l.max_sessions = 0,
            |l| l.max_sessions = 4097,
            |l| l.stream_window = 1024,
            |l| l.connection_window = l.stream_window - 1,
            |l| l.connection_window = u32::MAX,
            |l| l.keep_alive = l.idle_timeout,
            |l| l.heartbeat_interval = Duration::ZERO,
            |l| l.heartbeat_timeout = l.heartbeat_interval,
            |l| l.handshake_timeout = Duration::ZERO,
        ];
        for edit in cases {
            let mut l = Limits::default();
            edit(&mut l);
            assert!(matches!(l.validate(), Err(TunnelError::Config(_))), "{l:?}");
        }
    }
}
