//! The recorded events and their bounds.
//!
//! A transcript is one [`Event::Start`], then outputs and window changes,
//! at most one [`Event::Exit`], then one [`Event::End`]. Each event carries its time in microseconds
//! since the start of the session, from the monotonic clock of the agent.
//! Keystrokes are not recorded (ADR-0016).

use crate::error::RecorderError;

/// Largest output event, in bytes: the largest SSH data packet the agent
/// accepts. Larger outputs are split by the sender.
pub const MAX_OUTPUT: usize = 32 * 1024;
/// Largest recorded command (`exec`), in bytes, as accepted by the agent
/// SSH server.
pub const MAX_COMMAND: usize = 32 * 1024;
/// Longest terminal type, in bytes (printable ASCII).
pub const MAX_TERM: usize = 64;
/// Largest number of columns or rows.
pub const MAX_CELLS: u16 = 10_000;
/// Longest exit signal name, in bytes (printable ASCII, as in SSH: `KILL`,
/// not `SIGKILL`).
pub const MAX_SIGNAL: usize = 32;

/// How the shell or the command ended, as the target said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exit {
    /// Its exit status.
    Status(u32),
    /// The signal that ended it.
    Signal {
        /// Signal name, 1 to [`MAX_SIGNAL`] printable ASCII bytes.
        name: String,
        /// The target says it dumped core.
        core_dumped: bool,
    },
}

/// Why a session ended, as recorded in its end event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EndReason {
    /// The user or the target closed the session.
    Closed = 1,
    /// The session reached its maximum length.
    Expired = 2,
    /// Its login session was revoked.
    Revoked = 3,
    /// The agent stopped.
    Shutdown = 4,
    /// The target or the relay failed.
    Error = 5,
}

impl EndReason {
    /// Every reason.
    pub const ALL: [Self; 5] = [
        Self::Closed,
        Self::Expired,
        Self::Revoked,
        Self::Shutdown,
        Self::Error,
    ];

    /// The reason of a byte, if known.
    pub fn from_u8(v: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|r| *r as u8 == v)
    }

    /// Its name, as in the audit events.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Shutdown => "shutdown",
            Self::Error => "error",
        }
    }
}

/// A recorded event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The session starts: shell or command, with its terminal if any.
    Start {
        /// Columns, 0 without a terminal, else 1 to [`MAX_CELLS`].
        cols: u16,
        /// Rows, 0 without a terminal, else 1 to [`MAX_CELLS`].
        rows: u16,
        /// Wall clock time of the start, Unix milliseconds (agent clock).
        started_ms: u64,
        /// Terminal type (`TERM`), empty without a terminal; printable
        /// ASCII, at most [`MAX_TERM`] bytes.
        term: String,
        /// The command of an `exec`, at most [`MAX_COMMAND`] bytes; `None`
        /// for a shell.
        command: Option<Vec<u8>>,
    },
    /// Bytes from the target to the user (standard output and error), 1 to
    /// [`MAX_OUTPUT`].
    Output(Vec<u8>),
    /// The window changed size: 1 to [`MAX_CELLS`] each.
    Resize {
        /// Columns.
        cols: u16,
        /// Rows.
        rows: u16,
    },
    /// The shell or the command ended (`exit-status` or `exit-signal`).
    Exit(Exit),
    /// The session ended.
    End {
        /// Why.
        reason: EndReason,
        /// Bytes of output recorded, which the receiver checks.
        output_bytes: u64,
    },
}

/// An event at its time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Microseconds since the start of the session.
    pub at_us: u64,
    /// The event.
    pub event: Event,
}

fn cells(cols: u16, rows: u16) -> bool {
    (1..=MAX_CELLS).contains(&cols) && (1..=MAX_CELLS).contains(&rows)
}

impl Event {
    /// Checks the bounds of the event on its own (the order of events is
    /// checked by the decoder).
    ///
    /// # Errors
    ///
    /// [`RecorderError::Malformed`].
    pub fn check(&self) -> Result<(), RecorderError> {
        match self {
            Self::Start {
                cols,
                rows,
                term,
                command,
                ..
            } => {
                let terminal = !term.is_empty();
                if terminal != (*cols != 0 || *rows != 0) || (terminal && !cells(*cols, *rows)) {
                    return Err(RecorderError::Malformed(
                        "dimensions du terminal hors bornes ou sans type de terminal",
                    ));
                }
                if term.len() > MAX_TERM || !term.bytes().all(|b| b.is_ascii_graphic()) {
                    return Err(RecorderError::Malformed("type de terminal invalide"));
                }
                if command.as_ref().is_some_and(|c| c.len() > MAX_COMMAND) {
                    return Err(RecorderError::Malformed("commande de plus de 32 Kio"));
                }
                Ok(())
            }
            Self::Output(data) => {
                if data.is_empty() || data.len() > MAX_OUTPUT {
                    return Err(RecorderError::Malformed("sortie vide ou de plus de 32 Kio"));
                }
                Ok(())
            }
            Self::Resize { cols, rows } => {
                if !cells(*cols, *rows) {
                    return Err(RecorderError::Malformed("dimensions hors bornes"));
                }
                Ok(())
            }
            Self::Exit(Exit::Signal { name, .. }) => {
                if name.is_empty()
                    || name.len() > MAX_SIGNAL
                    || !name.bytes().all(|b| b.is_ascii_graphic())
                {
                    return Err(RecorderError::Malformed("nom de signal invalide"));
                }
                Ok(())
            }
            Self::Exit(Exit::Status(_)) | Self::End { .. } => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start(cols: u16, rows: u16, term: &str) -> Event {
        Event::Start {
            cols,
            rows,
            started_ms: 0,
            term: term.into(),
            command: None,
        }
    }

    #[test]
    fn bounds() {
        assert!(start(80, 24, "xterm-256color").check().is_ok());
        assert!(start(0, 0, "").check().is_ok());
        assert!(start(MAX_CELLS, MAX_CELLS, "x").check().is_ok());
        for bad in [
            start(80, 24, ""),
            start(0, 0, "xterm"),
            start(80, 0, "xterm"),
            start(MAX_CELLS + 1, 24, "xterm"),
            start(80, 24, "x term"),
            start(80, 24, "xtérm"),
            start(80, 24, &"x".repeat(MAX_TERM + 1)),
        ] {
            assert!(bad.check().is_err(), "{bad:?}");
        }
        let command = |n| Event::Start {
            cols: 0,
            rows: 0,
            started_ms: 0,
            term: String::new(),
            command: Some(vec![b'a'; n]),
        };
        assert!(command(0).check().is_ok());
        assert!(command(MAX_COMMAND).check().is_ok());
        assert!(command(MAX_COMMAND + 1).check().is_err());
        let signal = |name: &str| {
            Event::Exit(Exit::Signal {
                name: name.into(),
                core_dumped: false,
            })
        };
        assert!(signal("KILL").check().is_ok());
        assert!(signal(&"X".repeat(MAX_SIGNAL)).check().is_ok());
        for bad in ["", "K ILL", "KÏLL", &"X".repeat(MAX_SIGNAL + 1)] {
            assert!(signal(bad).check().is_err(), "{bad:?}");
        }
        assert!(Event::Exit(Exit::Status(u32::MAX)).check().is_ok());
        assert!(Event::Output(vec![0; MAX_OUTPUT]).check().is_ok());
        assert!(Event::Output(vec![]).check().is_err());
        assert!(Event::Output(vec![0; MAX_OUTPUT + 1]).check().is_err());
        assert!(Event::Resize { cols: 1, rows: 1 }.check().is_ok());
        assert!(Event::Resize { cols: 0, rows: 1 }.check().is_err());
    }

    #[test]
    fn reasons_round_trip() {
        for r in EndReason::ALL {
            assert_eq!(EndReason::from_u8(r as u8), Some(r));
        }
        assert_eq!(EndReason::from_u8(0), None);
        assert_eq!(EndReason::from_u8(6), None);
    }
}
