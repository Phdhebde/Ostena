//! Reading a password from the terminal without echo (`ostena login`,
//! `ostena core user set-password`).
//!
//! - Unix: the controlling terminal (`/dev/tty`) is switched to a raw mode
//!   (no echo, no line discipline, **no signals**), and the line is edited
//!   here. Ctrl-C arrives as a byte and cancels the input
//!   ([`io::ErrorKind::Interrupted`]) instead of killing the process with
//!   the echo off. The previous mode is restored by a guard, on every path.
//! - Windows: the console input (`CONIN$`) loses echo, line and processed
//!   input; Ctrl-C arrives as a character too.
//! - Without a terminal (a pipe, a test), one line is read from the
//!   standard input, as is.
//!
//! The typed bytes live in a buffer wiped on drop, and end in a
//! [`SecretString`].

use std::io::{self, BufRead, Write};

use ostena_common::secret::SecretString;
use zeroize::Zeroize;

/// Longest line accepted, in bytes; further bytes are ignored.
pub const MAX_LINE: usize = 4096;

/// What a byte does to the line being typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    /// Keep reading.
    Continue,
    /// Enter: the line is complete.
    Done,
    /// Ctrl-C: cancelled.
    Cancelled,
    /// Ctrl-D on an empty line, or end of input.
    Eof,
}

/// The line editor: printable bytes, backspace, Ctrl-U, Enter, Ctrl-C and
/// Ctrl-D; other control bytes are ignored. Wiped on drop.
#[derive(Default)]
pub(crate) struct Editor {
    line: Vec<u8>,
}

impl Drop for Editor {
    fn drop(&mut self) {
        self.line.zeroize();
    }
}

impl Editor {
    pub(crate) fn feed(&mut self, byte: u8) -> Step {
        match byte {
            b'\r' | b'\n' => Step::Done,
            0x03 => Step::Cancelled,
            0x04 if self.line.is_empty() => Step::Eof,
            // Backspace and DEL: remove one UTF-8 character.
            0x08 | 0x7f => {
                while let Some(b) = self.line.pop() {
                    if b & 0xc0 != 0x80 {
                        break;
                    }
                }
                Step::Continue
            }
            // Ctrl-U: erase the line.
            0x15 => {
                self.line.zeroize();
                self.line.clear();
                Step::Continue
            }
            b if b < 0x20 => Step::Continue,
            b => {
                if self.line.len() < MAX_LINE {
                    self.line.push(b);
                }
                Step::Continue
            }
        }
    }

    /// The line typed, as a secret.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidData`] if it is not UTF-8.
    pub(crate) fn finish(mut self) -> io::Result<SecretString> {
        let line = std::mem::take(&mut self.line);
        match String::from_utf8(line) {
            Ok(text) => Ok(SecretString::from(text)),
            Err(e) => {
                e.into_bytes().zeroize();
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "saisie invalide : UTF-8 attendu",
                ))
            }
        }
    }
}

/// Feeds `input` to an editor until a line ends.
pub(crate) fn edit(mut next: impl FnMut() -> io::Result<Option<u8>>) -> io::Result<SecretString> {
    let mut editor = Editor::default();
    loop {
        let step = match next()? {
            Some(byte) => editor.feed(byte),
            None => Step::Eof,
        };
        match step {
            Step::Continue => {}
            Step::Done => return editor.finish(),
            Step::Cancelled => {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "saisie interrompue",
                ));
            }
            Step::Eof => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "fin de la saisie",
                ));
            }
        }
    }
}

/// Reads one line from a non-terminal input, without its line ending.
pub(crate) fn read_plain_line(input: &mut impl BufRead) -> io::Result<SecretString> {
    let mut bytes = Vec::new();
    let read = input.read_until(b'\n', &mut bytes);
    let mut editor = Editor::default();
    let result = read.and_then(|n| {
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "fin de la saisie",
            ));
        }
        let end = bytes
            .iter()
            .rposition(|b| *b != b'\n' && *b != b'\r')
            .map_or(0, |i| i + 1);
        editor.line.extend_from_slice(&bytes[..end.min(MAX_LINE)]);
        Ok(())
    });
    bytes.zeroize();
    result?;
    editor.finish()
}

/// Shows `prompt` and reads a line without echo.
///
/// # Errors
///
/// [`io::ErrorKind::Interrupted`] on Ctrl-C, [`io::ErrorKind::UnexpectedEof`]
/// on Ctrl-D or the end of input, [`io::ErrorKind::InvalidData`] for
/// non-UTF-8 input, or an I/O error of the terminal.
pub fn read_hidden(prompt: &str) -> io::Result<SecretString> {
    imp::read_hidden(prompt)
}

/// Shows `prompt` and reads a line with echo (a TOTP code).
///
/// # Errors
///
/// As [`read_hidden`], without the terminal modes.
pub fn read_visible(prompt: &str) -> io::Result<SecretString> {
    let mut err = io::stderr().lock();
    err.write_all(prompt.as_bytes())?;
    err.flush()?;
    read_plain_line(&mut io::stdin().lock())
}

#[cfg(unix)]
#[allow(
    unsafe_code,
    reason = "tcgetattr and tcsetattr on the controlling terminal; documented and tested"
)]
pub(crate) mod imp {
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, RawFd};

    use ostena_common::secret::SecretString;

    /// The terminal in raw mode; the saved mode is restored on drop.
    pub(crate) struct RawMode {
        fd: RawFd,
        saved: libc::termios,
    }

    impl RawMode {
        /// Switches `fd` to raw mode: no echo, no canonical mode, no
        /// signal characters, no extended processing, no flow control; one
        /// byte per read.
        pub(crate) fn enter(fd: RawFd) -> io::Result<Self> {
            let mut saved = MaybeUninit::<libc::termios>::uninit();
            // SAFETY: `fd` is an open descriptor owned by the caller for the
            // life of the guard; `saved` points to writable memory of the
            // size of a termios, initialised by tcgetattr on success.
            if unsafe { libc::tcgetattr(fd, saved.as_mut_ptr()) } != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: tcgetattr returned 0, so it filled the structure.
            let saved = unsafe { saved.assume_init() };
            let mut raw = saved;
            raw.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN);
            raw.c_iflag &= !(libc::IXON | libc::ICRNL);
            raw.c_cc[libc::VMIN] = 1;
            raw.c_cc[libc::VTIME] = 0;
            // SAFETY: `fd` is open, and `raw` is a valid termios copied from
            // the one the system returned.
            if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &raw const raw) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { fd, saved })
        }
    }

    impl Drop for RawMode {
        fn drop(&mut self) {
            // SAFETY: `fd` is still open (the guard does not outlive the
            // file), and `saved` is the termios tcgetattr returned.
            unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &raw const self.saved) };
        }
    }

    /// Reads a hidden line on an already open terminal.
    pub(crate) fn read_on(tty: &mut File, prompt: &str) -> io::Result<SecretString> {
        tty.write_all(prompt.as_bytes())?;
        tty.flush()?;
        let result = {
            let _raw = RawMode::enter(tty.as_raw_fd())?;
            let mut reader: &File = tty;
            super::edit(|| {
                let mut byte = [0u8; 1];
                loop {
                    match reader.read(&mut byte) {
                        Ok(0) => return Ok(None),
                        Ok(_) => return Ok(Some(byte[0])),
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) => return Err(e),
                    }
                }
            })
        };
        // The guard is gone: the mode is restored before anything else.
        let _ = tty.write_all(b"\n");
        result
    }

    pub(crate) fn read_hidden(prompt: &str) -> io::Result<SecretString> {
        if let Ok(mut tty) = OpenOptions::new().read(true).write(true).open("/dev/tty") {
            read_on(&mut tty, prompt)
        } else {
            // No controlling terminal: a pipe or a service.
            let mut err = io::stderr().lock();
            err.write_all(prompt.as_bytes())?;
            err.flush()?;
            super::read_plain_line(&mut io::stdin().lock())
        }
    }
}

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "GetConsoleMode, SetConsoleMode and ReadConsoleW; documented and tested"
)]
pub(crate) mod imp {
    use std::fs::{File, OpenOptions};
    use std::io::{self, Write};
    use std::os::windows::io::AsRawHandle;
    use std::ptr::null;

    use ostena_common::secret::SecretString;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::Console::{
        CONSOLE_MODE, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, GetConsoleMode,
        ReadConsoleW, SetConsoleMode,
    };

    /// The console input without echo, line or processed input; the saved
    /// mode is restored on drop.
    pub(crate) struct RawMode {
        handle: HANDLE,
        saved: CONSOLE_MODE,
    }

    impl RawMode {
        pub(crate) fn enter(handle: HANDLE) -> io::Result<Self> {
            let mut saved: CONSOLE_MODE = 0;
            // SAFETY: `handle` is an open console input handle owned by the
            // caller for the life of the guard; `saved` is writable.
            if unsafe { GetConsoleMode(handle, &raw mut saved) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let raw = saved & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);
            // SAFETY: `handle` is an open console input handle.
            if unsafe { SetConsoleMode(handle, raw) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { handle, saved })
        }
    }

    impl Drop for RawMode {
        fn drop(&mut self) {
            // SAFETY: the handle outlives the guard; `saved` is the mode the
            // console returned.
            unsafe { SetConsoleMode(self.handle, self.saved) };
        }
    }

    /// Reads one UTF-16 unit from the console.
    fn read_unit(handle: HANDLE) -> io::Result<Option<u16>> {
        let mut unit = 0u16;
        let mut read = 0u32;
        // SAFETY: the buffer holds one UTF-16 unit, as requested; `read`
        // is writable; no input control structure.
        let ok = unsafe { ReadConsoleW(handle, (&raw mut unit).cast(), 1, &raw mut read, null()) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((read == 1).then_some(unit))
    }

    pub(crate) fn read_on(
        input: &File,
        output: &mut File,
        prompt: &str,
    ) -> io::Result<SecretString> {
        output.write_all(prompt.as_bytes())?;
        output.flush()?;
        let handle: HANDLE = input.as_raw_handle();
        let result = {
            let _raw = RawMode::enter(handle)?;
            let mut pending: Vec<u8> = Vec::new();
            let mut high: Option<u16> = None;
            let line = super::edit(|| {
                loop {
                    if !pending.is_empty() {
                        return Ok(Some(pending.remove(0)));
                    }
                    let Some(unit) = read_unit(handle)? else {
                        return Ok(None);
                    };
                    let units = match (high.take(), unit) {
                        (None, 0xd800..=0xdbff) => {
                            high = Some(unit);
                            continue;
                        }
                        (Some(h), 0xdc00..=0xdfff) => vec![h, unit],
                        (_, u) => vec![u],
                    };
                    let mut buf = [0u8; 4];
                    for c in char::decode_utf16(units) {
                        let c = c.unwrap_or(char::REPLACEMENT_CHARACTER);
                        pending.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                    }
                    zeroize::Zeroize::zeroize(&mut buf);
                }
            });
            zeroize::Zeroize::zeroize(&mut pending);
            line
        };
        let _ = output.write_all(b"\r\n");
        result
    }

    pub(crate) fn read_hidden(prompt: &str) -> io::Result<SecretString> {
        let input = OpenOptions::new().read(true).write(true).open("CONIN$");
        let output = OpenOptions::new().write(true).open("CONOUT$");
        if let (Ok(input), Ok(mut output)) = (input, output) {
            read_on(&input, &mut output, prompt)
        } else {
            // No console: a pipe or a service.
            let mut err = io::stderr().lock();
            err.write_all(prompt.as_bytes())?;
            err.flush()?;
            super::read_plain_line(&mut io::stdin().lock())
        }
    }
}

#[cfg(test)]
mod tests;
