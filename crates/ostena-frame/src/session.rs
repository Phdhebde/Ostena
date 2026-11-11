//! Version negotiation and per-direction receive state.
//!
//! Sequence numbers start at 0 in each direction with the first frame (Hello
//! from the browser, HelloAck from the gateway) and grow by one per frame,
//! all channels together. They let a peer acknowledge (`Ack`) and, after a
//! reconnection, ask for the frames it missed (`Resume`); resuming itself is
//! the session layer's job.

use crate::codec::Frame;
use crate::error::{Code, FrameError};
use crate::header::{CURRENT_VERSION, FrameType, NEGOTIATION_VERSION};
use crate::payload::Payload;

/// Version bit set supported by this crate (bit `v - 1` for version `v`).
pub const SUPPORTED_VERSIONS: u32 = 1 << (CURRENT_VERSION - 1);

/// Highest version present in both bit sets.
///
/// # Errors
///
/// `FRM-E009` when the sets have no version in common.
pub fn negotiate(local: u32, remote: u32) -> Result<u8, FrameError> {
    let common = local & remote;
    if common == 0 {
        return Err(FrameError::new(
            Code::NoCommonVersion,
            "aucune version commune",
        ));
    }
    // 32 - leading zeros is the highest bit set, plus one: the version.
    u8::try_from(32 - common.leading_zeros())
        .map_err(|_| FrameError::new(Code::NoCommonVersion, "version hors bornes"))
}

/// Receive-side checks that need state: negotiation first, then the
/// negotiated version on every frame, consecutive sequence numbers, and
/// consistent fragmentation.
#[derive(Debug, Clone)]
pub struct Receiver {
    version: Option<u8>,
    next_sequence: u64,
    /// Fragmented messages in progress, by (type, channel); a few at most.
    open: [Option<(FrameType, u16)>; 8],
}

impl Default for Receiver {
    fn default() -> Self {
        Self::new()
    }
}

impl Receiver {
    /// State before any frame.
    pub const fn new() -> Self {
        Self {
            version: None,
            next_sequence: 0,
            open: [None; 8],
        }
    }

    /// The negotiated version, once known.
    pub const fn version(&self) -> Option<u8> {
        self.version
    }

    /// Sequence number expected next (also the value to send in `Ack` minus one).
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Records the version agreed by the negotiation.
    pub fn set_version(&mut self, version: u8) {
        self.version = Some(version);
    }

    /// Checks a decoded frame against the receive state. Never allocates.
    ///
    /// # Errors
    ///
    /// `FRM-E013` for a frame other than Hello, HelloAck, Error or Close
    /// before negotiation; `FRM-E003` for another version than the
    /// negotiated one; `FRM-E010` for an unexpected sequence number;
    /// `FRM-E011` for inconsistent fragments.
    pub fn accept(&mut self, frame: &Frame<'_>) -> Result<(), FrameError> {
        let h = frame.header;
        match self.version {
            None if !h.frame_type.negotiation() => {
                return Err(FrameError::new(
                    Code::NotNegotiated,
                    "trame reçue avant la négociation",
                ));
            }
            Some(_) if matches!(h.frame_type, FrameType::Hello | FrameType::HelloAck) => {
                return Err(FrameError::new(Code::Version, "négociation déjà faite"));
            }
            Some(v)
                if h.version != v
                    && !(h.version == NEGOTIATION_VERSION && h.frame_type.negotiation()) =>
            {
                return Err(FrameError::new(
                    Code::Version,
                    "version différente de la version négociée",
                ));
            }
            _ => {}
        }
        if h.sequence != self.next_sequence {
            return Err(FrameError::new(
                Code::Sequence,
                "numéro de séquence inattendu (doublon ou trou)",
            ));
        }
        if h.frame_type.fragmentable() {
            let key = (h.frame_type, h.channel);
            let slot = self.open.iter().position(|s| *s == Some(key));
            match (slot, h.flags.more()) {
                (Some(_), true) | (None, false) => {}
                (Some(i), false) => self.open[i] = None,
                (None, true) => {
                    let free =
                        self.open
                            .iter()
                            .position(Option::is_none)
                            .ok_or(FrameError::new(
                                Code::Fragmentation,
                                "trop de messages fragmentés en cours",
                            ))?;
                    self.open[free] = Some(key);
                }
            }
        }
        if let Payload::HelloAck { version, .. } = frame.payload {
            if version > CURRENT_VERSION || SUPPORTED_VERSIONS & (1 << (version - 1)) == 0 {
                return Err(FrameError::new(
                    Code::NoCommonVersion,
                    "version retenue non prise en charge",
                ));
            }
            self.version = Some(version);
        }
        self.next_sequence = self.next_sequence.wrapping_add(1);
        Ok(())
    }

    /// Moves the expected sequence number after a resume.
    pub fn resume_at(&mut self, next_sequence: u64) {
        self.next_sequence = next_sequence;
        self.open = [None; 8];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn highest_common_version() {
        assert_eq!(negotiate(0b0111, 0b0011), Ok(2));
        assert_eq!(negotiate(0b0001, 0b1111), Ok(1));
        assert_eq!(negotiate(1 << 31, u32::MAX), Ok(32));
        assert_eq!(
            negotiate(0b0100, 0b0011).unwrap_err().code,
            Code::NoCommonVersion
        );
        assert_eq!(
            negotiate(SUPPORTED_VERSIONS, SUPPORTED_VERSIONS),
            Ok(CURRENT_VERSION)
        );
    }
}
