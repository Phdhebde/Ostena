use proptest::prelude::*;

use super::*;

fn shown(s: &SecretString) -> String {
    // SECRET-EXPOSURE: test assertion on a throwaway value.
    #[expect(clippy::disallowed_methods)]
    let v = s.expose_secret().to_owned();
    v
}

fn run(bytes: &[u8]) -> io::Result<SecretString> {
    let mut it = bytes.iter().copied();
    edit(|| Ok(it.next()))
}

#[test]
fn line_editing() {
    assert_eq!(shown(&run(b"secret\r").unwrap()), "secret");
    assert_eq!(shown(&run(b"secret\n").unwrap()), "secret");
    assert_eq!(shown(&run(b"secrex\x7ft\r").unwrap()), "secret");
    assert_eq!(shown(&run(b"abc\x08\x08\x08xyz\r").unwrap()), "xyz");
    assert_eq!(shown(&run(b"\x7f\x7fa\r").unwrap()), "a");
    assert_eq!(shown(&run(b"wrong\x15right\r").unwrap()), "right");
    // Other control bytes (escape sequences of arrow keys) are dropped.
    assert_eq!(shown(&run(b"a\x1b[Db\r").unwrap()), "a[Db");
    assert_eq!(shown(&run(b"a\x04b\r").unwrap()), "ab");
    // Backspace removes a whole UTF-8 character.
    assert_eq!(shown(&run("mot é\x7fe\r".as_bytes()).unwrap()), "mot e");
    assert_eq!(shown(&run("pass€\r".as_bytes()).unwrap()), "pass€");
}

#[test]
fn cancel_and_end_of_input() {
    assert_eq!(
        run(b"sec\x03ret\r").err().map(|e| e.kind()),
        Some(io::ErrorKind::Interrupted)
    );
    assert_eq!(
        run(b"\x04").err().map(|e| e.kind()),
        Some(io::ErrorKind::UnexpectedEof)
    );
    assert_eq!(
        run(b"no end").err().map(|e| e.kind()),
        Some(io::ErrorKind::UnexpectedEof)
    );
    assert_eq!(
        run(b"\xff\xfe\r").err().map(|e| e.kind()),
        Some(io::ErrorKind::InvalidData)
    );
}

#[test]
fn line_is_bounded() {
    let mut long = vec![b'a'; MAX_LINE + 100];
    long.push(b'\r');
    assert_eq!(shown(&run(&long).unwrap()).len(), MAX_LINE);
}

#[test]
fn plain_lines() {
    let mut input: &[u8] = b"secret\r\nnext\n";
    assert_eq!(shown(&read_plain_line(&mut input).unwrap()), "secret");
    assert_eq!(shown(&read_plain_line(&mut input).unwrap()), "next");
    assert_eq!(
        read_plain_line(&mut input).err().map(|e| e.kind()),
        Some(io::ErrorKind::UnexpectedEof)
    );
    let mut input: &[u8] = b"last line without end";
    assert_eq!(
        shown(&read_plain_line(&mut input).unwrap()),
        "last line without end"
    );
    let mut input: &[u8] = b"\n";
    assert_eq!(shown(&read_plain_line(&mut input).unwrap()), "");
}

proptest! {
    /// Printable input followed by Enter comes back unchanged.
    #[test]
    fn printable_lines_come_back(line in "[ -~]{0,200}") {
        let mut bytes = line.clone().into_bytes();
        bytes.push(b'\r');
        prop_assert_eq!(shown(&run(&bytes).unwrap()), line);
    }

    /// Whatever is typed, the editor never panics.
    #[test]
    fn any_input(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
        let _ = run(&bytes);
    }
}

#[cfg(unix)]
#[allow(unsafe_code, reason = "openpty to test the terminal modes")]
mod unix {
    use std::fs::File;
    use std::io::{Read, Write};
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::ptr::null_mut;

    use super::super::imp::{RawMode, read_on};
    use super::shown;

    /// A pseudo-terminal pair: (controller, terminal).
    fn pty() -> (File, File) {
        let (mut controller, mut terminal) = (0, 0);
        // SAFETY: both out-pointers are writable; no name, mode or size.
        let rc = unsafe {
            libc::openpty(
                &raw mut controller,
                &raw mut terminal,
                null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(rc, 0, "openpty: {}", std::io::Error::last_os_error());
        // SAFETY: openpty returned two new descriptors we now own.
        unsafe { (File::from_raw_fd(controller), File::from_raw_fd(terminal)) }
    }

    fn lflag(file: &File) -> libc::tcflag_t {
        let mut t = MaybeUninit::<libc::termios>::uninit();
        // SAFETY: the descriptor is open and the buffer is a termios.
        let rc = unsafe { libc::tcgetattr(file.as_raw_fd(), t.as_mut_ptr()) };
        assert_eq!(rc, 0);
        // SAFETY: tcgetattr succeeded.
        unsafe { t.assume_init() }.c_lflag
    }

    #[test]
    fn raw_mode_is_restored_on_drop() {
        let (_controller, terminal) = pty();
        let before = lflag(&terminal);
        assert_ne!(before & libc::ECHO, 0);
        {
            let _raw = RawMode::enter(terminal.as_raw_fd()).unwrap();
            let during = lflag(&terminal);
            assert_eq!(during & (libc::ECHO | libc::ICANON | libc::ISIG), 0);
        }
        assert_eq!(lflag(&terminal), before);
    }

    #[test]
    fn raw_mode_refuses_a_non_terminal() {
        let file = File::open("/dev/null").unwrap();
        assert!(RawMode::enter(file.as_raw_fd()).is_err());
    }

    fn typed(
        input: &[u8],
    ) -> (
        std::io::Result<String>,
        Vec<u8>,
        libc::tcflag_t,
        libc::tcflag_t,
    ) {
        let (mut controller, mut terminal) = pty();
        let before = lflag(&terminal);
        // Entering raw mode flushes type-ahead input: type once the echo is
        // off (the controller sees the terminal's modes on Linux and BSD).
        let mut typist = controller.try_clone().unwrap();
        let input = input.to_vec();
        let writer = std::thread::spawn(move || {
            for _ in 0..500 {
                if lflag(&typist) & libc::ECHO == 0 {
                    typist.write_all(&input).unwrap();
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            panic!("the terminal never left echo mode");
        });
        let result = read_on(&mut terminal, "Mot de passe : ").map(|s| shown(&s));
        writer.join().unwrap();
        let after = lflag(&terminal);
        drop(terminal);
        let mut echoed = Vec::new();
        // The controller reads until the terminal side is closed.
        let mut buf = [0u8; 256];
        while let Ok(n) = controller.read(&mut buf) {
            if n == 0 {
                break;
            }
            echoed.extend_from_slice(&buf[..n]);
        }
        (result, echoed, before, after)
    }

    #[test]
    fn hidden_input_is_not_echoed() {
        let (result, echoed, before, after) = typed(b"s3cret\r");
        assert_eq!(result.unwrap(), "s3cret");
        let echoed = String::from_utf8_lossy(&echoed);
        assert!(echoed.starts_with("Mot de passe : "), "{echoed:?}");
        assert!(!echoed.contains("s3cret"), "{echoed:?}");
        assert_eq!(before, after);
    }

    #[test]
    fn ctrl_c_cancels_and_restores_the_terminal() {
        let (result, _, before, after) = typed(b"s3c\x03");
        assert_eq!(
            result.err().map(|e| e.kind()),
            Some(std::io::ErrorKind::Interrupted)
        );
        assert_eq!(before, after);
    }
}

#[cfg(windows)]
mod windows {
    use std::fs::{File, OpenOptions};
    use std::os::windows::io::AsRawHandle;

    use super::super::imp::RawMode;

    #[test]
    fn raw_mode_refuses_a_non_console() {
        let path = std::env::temp_dir().join(format!("ostena-tty-{}", std::process::id()));
        let file = File::create(&path).unwrap();
        assert!(RawMode::enter(file.as_raw_handle()).is_err());
        drop(file);
        let _ = std::fs::remove_file(&path);
    }

    /// Only where the test process has a console (not on every CI runner).
    #[test]
    fn raw_mode_is_restored_on_drop_when_a_console_exists() {
        let Ok(input) = OpenOptions::new().read(true).write(true).open("CONIN$") else {
            return;
        };
        let Ok(raw) = RawMode::enter(input.as_raw_handle()) else {
            return;
        };
        drop(raw);
        assert!(RawMode::enter(input.as_raw_handle()).is_ok());
    }
}
