//! File transfers through the agent SSH server (ADR-0010): which requests
//! are transfers, and the file names an SFTP stream shows.
//!
//! **Transfers** are the `sftp` subsystem and three commands: `scp -t` or
//! `scp -f` (the remote end of `scp -O`), `rsync --server` and
//! `sftp-server`. They need the transfer function of the right. A command
//! whose words name one of these tools in another way (`sh -c 'scp -f x'`,
//! `rsync` without `--server`) needs it too, but is recorded as an ordinary
//! command. The function governs these protocols, not what a shell can
//! move through its own output (`cat`, `base64`): that remains in the
//! transcript of the shell.
//!
//! **Observation.** The requests of an SFTP client are parsed as they pass,
//! never changed: the file opened (for reading or writing), removed,
//! renamed, linked, the directory created or removed, the attributes
//! changed. Each becomes a note of the transcript before the request
//! reaches the target. The parser follows the framing of the stream as
//! the server does (length, type), buffers at most the beginning of a
//! request ([`PREFIX`]) and skips the rest (file data). A message longer
//! than the server accepts (256 KiB) or shorter than its type ends the
//! observation with an error: the server would end the session too, and
//! the agent cuts it rather than let requests pass unseen.

use ostena_recorder::NoteKind;
use ostena_recorder::event::MAX_PATH;

/// Longest SFTP message, as OpenSSH's `sftp-server` accepts it (its
/// `SFTP_MAX_MSG_LENGTH`).
pub const MAX_MESSAGE: u32 = 256 * 1024;
/// Bytes of a request kept to read its names: the request identifier, two
/// paths of [`MAX_PATH`] with their lengths, an extension name.
pub const PREFIX: usize = 4 + 2 * (4 + MAX_PATH) + 4 + 64;

const OPEN: u8 = 3;
const SETSTAT: u8 = 9;
const REMOVE: u8 = 13;
const MKDIR: u8 = 14;
const RMDIR: u8 = 15;
const RENAME: u8 = 18;
const SYMLINK: u8 = 20;
const EXTENDED: u8 = 200;

/// Open flags that change the file (`SSH_FXF_WRITE`, `APPEND`, `CREAT`,
/// `TRUNC`).
const WRITE_FLAGS: u32 = 0x02 | 0x04 | 0x08 | 0x10;

/// A transfer protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// The `sftp` subsystem, or `sftp-server` run as a command.
    Sftp,
    /// `scp -t` or `scp -f`: the legacy protocol (`scp -O`).
    Scp,
    /// `rsync --server`.
    Rsync,
}

impl Protocol {
    /// Its name, as in the notes and the audit records.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sftp => "sftp",
            Self::Scp => "scp",
            Self::Rsync => "rsync",
        }
    }
}

/// What a command is, for the transfer function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// An ordinary command.
    Ordinary,
    /// A transfer: the remote end of a transfer tool, written plainly.
    Transfer(Protocol),
    /// Names a transfer tool otherwise: needs the transfer function, then
    /// runs and is recorded as an ordinary command.
    Mentions(&'static str),
}

/// A character a command word may hold outside quotes without the shell of
/// the target reading anything into it.
fn plain(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"_./:@%+,=-".contains(&b)
}

/// The words of `command` if it is a plain list of words: separated by
/// spaces, each made of [`plain`] characters or single-quoted parts
/// without a quote inside. `None` for anything the shell would interpret.
fn words(command: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut words = Vec::new();
    let mut word: Option<Vec<u8>> = None;
    let mut quoted = false;
    for &b in command {
        if quoted {
            if b == b'\'' {
                quoted = false;
            } else if b.is_ascii_control() {
                return None;
            } else {
                word.get_or_insert_with(Vec::new).push(b);
            }
        } else if b == b'\'' {
            quoted = true;
            word.get_or_insert_with(Vec::new);
        } else if b == b' ' {
            words.extend(word.take());
        } else if plain(b) {
            word.get_or_insert_with(Vec::new).push(b);
        } else {
            return None;
        }
    }
    if quoted {
        return None;
    }
    words.extend(word);
    Some(words)
}

fn basename(word: &[u8]) -> &[u8] {
    word.rsplit(|b| *b == b'/').next().unwrap_or(word)
}

/// The transfer tool a word names, if any.
fn tool(word: &[u8]) -> Option<&'static str> {
    match basename(word) {
        b"scp" => Some("scp"),
        b"rsync" => Some("rsync"),
        b"sftp" => Some("sftp"),
        b"sftp-server" => Some("sftp-server"),
        _ => None,
    }
}

/// What `command` is (see the module documentation).
pub fn classify(command: &[u8]) -> Command {
    if let Some(words) = words(command)
        && let Some(first) = words.first()
    {
        let options = || {
            words[1..]
                .iter()
                .take_while(|w| w.as_slice() != b"--")
                .filter(|w| w.len() > 1 && w[0] == b'-' && w[1] != b'-')
        };
        match tool(first) {
            Some("scp") if options().any(|w| w.contains(&b't') || w.contains(&b'f')) => {
                return Command::Transfer(Protocol::Scp);
            }
            Some("rsync") if words[1..].iter().any(|w| w.as_slice() == b"--server") => {
                return Command::Transfer(Protocol::Rsync);
            }
            Some("sftp-server") => return Command::Transfer(Protocol::Sftp),
            _ => {}
        }
    }
    // Any word naming a tool, whatever separates it.
    command
        .split(|b| !(b.is_ascii_alphanumeric() || b"_.+-/".contains(b)))
        .find_map(tool)
        .map_or(Command::Ordinary, Command::Mentions)
}

/// A file operation seen in an SFTP stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    /// What.
    pub kind: NoteKind,
    /// The path, or both paths separated by a NUL, as sent, each cut at
    /// [`MAX_PATH`] bytes; never empty.
    pub text: Vec<u8>,
}

/// The SFTP stream cannot be followed: the session must be cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("flux SFTP illisible : {0}")]
pub struct SftpError(pub &'static str);

#[derive(Debug)]
enum State {
    /// Reading the length and the type of a message.
    Header {
        bytes: [u8; 5],
        have: usize,
    },
    /// In the body of a message of type `kind`: `remaining` bytes to pass,
    /// the first ones kept for parsing up to `want`.
    Body {
        kind: u8,
        remaining: u32,
        want: usize,
        kept: Vec<u8>,
    },
    Failed,
}

/// Follows the requests of an SFTP client and reports the file operations
/// (see the module documentation).
#[derive(Debug)]
pub struct SftpObserver {
    state: State,
}

impl Default for SftpObserver {
    fn default() -> Self {
        Self::new()
    }
}

/// A string of SFTP (u32 length, bytes): what is present of it, cut at
/// [`MAX_PATH`], and the rest of `data`.
fn string(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = usize::try_from(u32::from_be_bytes(data.get(..4)?.try_into().ok()?)).ok()?;
    let body = &data[4..];
    let present = &body[..len.min(body.len())];
    let rest = body.get(len..).unwrap_or_default();
    Some((&present[..present.len().min(MAX_PATH)], rest))
}

fn interesting(kind: u8) -> bool {
    matches!(
        kind,
        OPEN | SETSTAT | REMOVE | MKDIR | RMDIR | RENAME | SYMLINK | EXTENDED
    )
}

/// A path for a note: never empty (a NUL is replaced, so that it cannot
/// pass for a separator).
fn path(p: &[u8]) -> Vec<u8> {
    if p.is_empty() {
        return b"?".to_vec();
    }
    p.iter().map(|&b| if b == 0 { b'?' } else { b }).collect()
}

fn two(a: &[u8], b: &[u8]) -> Vec<u8> {
    [path(a), vec![0], path(b)].concat()
}

/// The operation of a request of `kind` whose body (after the type) begins
/// with `body`, if it is one that is noted.
fn parse(kind: u8, body: &[u8]) -> Option<Observed> {
    // The request identifier.
    let body = body.get(4..)?;
    let (first, rest) = string(body)?;
    let observed = |kind, text| Some(Observed { kind, text });
    match kind {
        OPEN => {
            let flags = rest
                .get(..4)
                .and_then(|f| f.try_into().ok())
                .map_or(0, u32::from_be_bytes);
            let note = if flags & WRITE_FLAGS != 0 {
                NoteKind::Write
            } else {
                NoteKind::Read
            };
            observed(note, path(first))
        }
        SETSTAT => observed(NoteKind::Setstat, path(first)),
        REMOVE => observed(NoteKind::Remove, path(first)),
        MKDIR => observed(NoteKind::Mkdir, path(first)),
        RMDIR => observed(NoteKind::Rmdir, path(first)),
        RENAME | SYMLINK => {
            let second = string(rest).map_or(&b""[..], |(s, _)| s);
            let note = if kind == RENAME {
                NoteKind::Rename
            } else {
                NoteKind::Link
            };
            observed(note, two(first, second))
        }
        EXTENDED => {
            let (a, rest) = string(rest)?;
            match first {
                b"posix-rename@openssh.com" | b"hardlink@openssh.com" => {
                    let b = string(rest).map_or(&b""[..], |(s, _)| s);
                    let note = if first == b"hardlink@openssh.com" {
                        NoteKind::Link
                    } else {
                        NoteKind::Rename
                    };
                    observed(note, two(a, b))
                }
                b"lsetstat@openssh.com" => observed(NoteKind::Setstat, path(a)),
                _ => None,
            }
        }
        _ => None,
    }
}

impl SftpObserver {
    /// An observer at the start of a stream.
    pub fn new() -> Self {
        Self {
            state: State::Header {
                bytes: [0; 5],
                have: 0,
            },
        }
    }

    /// Follows `data`, the next bytes from the client, and appends the
    /// operations of the requests it completes to `out`.
    ///
    /// # Errors
    ///
    /// [`SftpError`] for a message out of bounds; every later call fails.
    pub fn feed(&mut self, mut data: &[u8], out: &mut Vec<Observed>) -> Result<(), SftpError> {
        while !data.is_empty() {
            match &mut self.state {
                State::Failed => return Err(SftpError("flux déjà refusé")),
                State::Header { bytes, have } => {
                    let n = (5 - *have).min(data.len());
                    bytes[*have..*have + n].copy_from_slice(&data[..n]);
                    *have += n;
                    data = &data[n..];
                    if *have < 5 {
                        continue;
                    }
                    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                    let kind = bytes[4];
                    if len == 0 || len > MAX_MESSAGE {
                        self.state = State::Failed;
                        return Err(SftpError("longueur de message hors bornes"));
                    }
                    let remaining = len - 1;
                    let want = if interesting(kind) {
                        usize::try_from(remaining).unwrap_or(PREFIX).min(PREFIX)
                    } else {
                        0
                    };
                    self.state = State::Body {
                        kind,
                        remaining,
                        want,
                        kept: Vec::with_capacity(want),
                    };
                    self.complete(out);
                }
                State::Body {
                    remaining,
                    want,
                    kept,
                    ..
                } => {
                    let n = usize::try_from(*remaining)
                        .unwrap_or(usize::MAX)
                        .min(data.len());
                    let keep = want.saturating_sub(kept.len()).min(n);
                    kept.extend_from_slice(&data[..keep]);
                    // n <= remaining, which is a u32.
                    *remaining -= u32::try_from(n).unwrap_or(*remaining);
                    data = &data[n..];
                    self.complete(out);
                }
            }
        }
        Ok(())
    }

    /// Ends the message in progress if its body is passed.
    fn complete(&mut self, out: &mut Vec<Observed>) {
        if let State::Body {
            kind,
            remaining: 0,
            kept,
            ..
        } = &self.state
        {
            out.extend(parse(*kind, kept));
            self.state = State::Header {
                bytes: [0; 5],
                have: 0,
            };
        }
    }
}

#[cfg(test)]
mod tests;
