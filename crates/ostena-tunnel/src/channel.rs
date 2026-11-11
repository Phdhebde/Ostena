//! Session channels: one QUIC stream per session and traffic class.
//!
//! Within a session, keyboard and mouse input and a file upload travel in the
//! same direction; in one stream they would queue behind each other. A
//! session therefore opens up to three streams, one per [`StreamClass`], and
//! QUIC sends the higher priorities first. Each stream starts with an
//! 18-byte header: version, class, session identifier.

use crate::error::TunnelError;
use crate::ids::Uuid;

/// Priority of the control stream: above every session class, so that the
/// heartbeat is never starved.
pub const CONTROL_PRIORITY: i32 = 40;

/// Version of the channel header.
pub const HEADER_VERSION: u8 = 1;
/// Length of the channel header.
pub const HEADER_LEN: usize = 18;

/// Traffic class of a session stream, by decreasing priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum StreamClass {
    /// Keyboard and mouse input, SSH terminal: latency first.
    Interactive = 1,
    /// RDP and VNC graphics.
    Display = 2,
    /// Files and large clipboard transfers.
    Transfer = 3,
}

impl StreamClass {
    /// Every class.
    pub const ALL: [Self; 3] = [Self::Interactive, Self::Display, Self::Transfer];

    /// The QUIC send priority (higher goes first).
    pub const fn priority(self) -> i32 {
        match self {
            Self::Interactive => 30,
            Self::Display => 20,
            Self::Transfer => 10,
        }
    }

    fn from_u8(v: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|c| *c as u8 == v)
    }
}

/// Encodes the header that opens a session stream.
pub fn encode_header(session: Uuid, class: StreamClass) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[0] = HEADER_VERSION;
    out[1] = class as u8;
    out[2..].copy_from_slice(&session.to_bytes());
    out
}

/// Decodes a stream header.
///
/// # Errors
///
/// [`TunnelError::Version`] or [`TunnelError::Protocol`].
pub fn decode_header(bytes: &[u8; HEADER_LEN]) -> Result<(Uuid, StreamClass), TunnelError> {
    if bytes[0] != HEADER_VERSION {
        return Err(TunnelError::Version(u16::from(bytes[0])));
    }
    let class = StreamClass::from_u8(bytes[1])
        .ok_or_else(|| TunnelError::Protocol(format!("classe de flux inconnue : {}", bytes[1])))?;
    let mut id = [0u8; 16];
    id.copy_from_slice(&bytes[2..]);
    Ok((Uuid::from_bytes(id), class))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn priorities_are_strict() {
        assert!(CONTROL_PRIORITY > StreamClass::Interactive.priority());
        assert!(StreamClass::Interactive.priority() > StreamClass::Display.priority());
        assert!(StreamClass::Display.priority() > StreamClass::Transfer.priority());
    }

    #[test]
    fn header_round_trip_and_refusals() {
        let id = Uuid::from_bytes([7; 16]);
        for class in StreamClass::ALL {
            assert_eq!(decode_header(&encode_header(id, class)), Ok((id, class)));
        }
        let mut bad = encode_header(id, StreamClass::Display);
        bad[0] = 2;
        assert_eq!(decode_header(&bad), Err(TunnelError::Version(2)));
        for class in [0u8, 4, 0xff] {
            let mut bad = encode_header(id, StreamClass::Display);
            bad[1] = class;
            assert!(matches!(decode_header(&bad), Err(TunnelError::Protocol(_))));
        }
    }

    proptest! {
        #[test]
        fn prop_decode_never_panics(bytes in any::<[u8; HEADER_LEN]>()) {
            let _ = decode_header(&bytes);
        }
    }
}
