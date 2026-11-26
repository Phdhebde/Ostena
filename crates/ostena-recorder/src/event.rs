//! The recorded events and their bounds.
//!
//! A transcript is one [`Event::Start`], then outputs, window changes and
//! notes, at most one [`Event::Exit`], then one [`Event::End`]. Each event carries its time in microseconds
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
/// Longest path in a note, in bytes.
pub const MAX_PATH: usize = 4096;
/// Longest note text, in bytes: two paths and their separator.
pub const MAX_NOTE: usize = 2 * MAX_PATH + 1;
/// Longest text of a transfer or refusal note (printable ASCII and spaces).
pub const MAX_NOTE_LABEL: usize = 256;

/// What a note says (ADR-0010): a transfer started, a request refused, or
/// a file operation observed in a transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum NoteKind {
    /// A file transfer started: its protocol (`sftp`, `scp`, `rsync`).
    Transfer = 1,
    /// A request refused for lack of a function of the right: what was
    /// asked (`port-forwarding 10.0.0.5:80`, `transfer scp`…).
    Refused = 2,
    /// A file opened for reading.
    Read = 16,
    /// A file opened for writing (created, truncated or appended to).
    Write = 17,
    /// A file removed.
    Remove = 18,
    /// A file renamed: `old ‖ NUL ‖ new`.
    Rename = 19,
    /// A directory created.
    Mkdir = 20,
    /// A directory removed.
    Rmdir = 21,
    /// Attributes changed (mode, owner, times).
    Setstat = 22,
    /// A link created: `link ‖ NUL ‖ target`.
    Link = 23,
}

impl NoteKind {
    /// Every kind.
    pub const ALL: [Self; 10] = [
        Self::Transfer,
        Self::Refused,
        Self::Read,
        Self::Write,
        Self::Remove,
        Self::Rename,
        Self::Mkdir,
        Self::Rmdir,
        Self::Setstat,
        Self::Link,
    ];

    /// The kind of a byte, if known.
    pub fn from_u8(v: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|k| *k as u8 == v)
    }

    /// Its name, as in the transcript markers.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::Refused => "refused",
            Self::Read => "file-read",
            Self::Write => "file-write",
            Self::Remove => "file-remove",
            Self::Rename => "file-rename",
            Self::Mkdir => "file-mkdir",
            Self::Rmdir => "file-rmdir",
            Self::Setstat => "file-setstat",
            Self::Link => "file-link",
        }
    }

    /// Whether its text is a label (printable ASCII and spaces) rather than
    /// paths.
    pub const fn is_label(self) -> bool {
        matches!(self, Self::Transfer | Self::Refused)
    }

    /// Whether its text holds two paths separated by a NUL.
    pub const fn has_two_paths(self) -> bool {
        matches!(self, Self::Rename | Self::Link)
    }
}

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
    /// Something the agent observed or refused (ADR-0010).
    Note {
        /// What.
        kind: NoteKind,
        /// Its text: a label, a path, or two paths separated by a NUL.
        text: Vec<u8>,
    },
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
            Self::Note { kind, text } => {
                let valid = if kind.is_label() {
                    !text.is_empty()
                        && text.len() <= MAX_NOTE_LABEL
                        && text.iter().all(|b| b.is_ascii_graphic() || *b == b' ')
                } else {
                    let count = if kind.has_two_paths() { 2 } else { 1 };
                    text.split(|b| *b == 0).count() == count
                        && text
                            .split(|b| *b == 0)
                            .all(|p| !p.is_empty() && p.len() <= MAX_PATH)
                };
                if !valid {
                    return Err(RecorderError::Malformed("note invalide"));
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
    fn notes_are_bounded() {
        let note = |kind, text: &[u8]| Event::Note {
            kind,
            text: text.to_vec(),
        };
        assert!(note(NoteKind::Transfer, b"sftp").check().is_ok());
        assert!(
            note(NoteKind::Refused, b"port-forwarding 10.0.0.5:80")
                .check()
                .is_ok()
        );
        assert!(note(NoteKind::Read, b"/etc/hosts").check().is_ok());
        assert!(note(NoteKind::Write, "/tmp/é".as_bytes()).check().is_ok());
        assert!(note(NoteKind::Rename, b"/a\0/b").check().is_ok());
        assert!(note(NoteKind::Read, &[b'a'; MAX_PATH]).check().is_ok());
        for bad in [
            note(NoteKind::Transfer, b""),
            note(NoteKind::Transfer, b"sftp\n"),
            note(NoteKind::Refused, &[b'a'; MAX_NOTE_LABEL + 1]),
            note(NoteKind::Read, b""),
            note(NoteKind::Read, b"/a\0/b"),
            note(NoteKind::Read, &[b'a'; MAX_PATH + 1]),
            note(NoteKind::Rename, b"/a"),
            note(NoteKind::Rename, b"/a\0"),
            note(NoteKind::Link, b"/a\0/b\0/c"),
        ] {
            assert!(bad.check().is_err(), "{bad:?}");
        }
        for k in NoteKind::ALL {
            assert_eq!(NoteKind::from_u8(k as u8), Some(k));
        }
        assert_eq!(NoteKind::from_u8(0), None);
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
