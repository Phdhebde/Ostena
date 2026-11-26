use proptest::prelude::*;

use super::*;

fn s(text: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(text.len()).unwrap().to_be_bytes().to_vec();
    out.extend_from_slice(text);
    out
}

fn message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(body.len() + 1)
        .unwrap()
        .to_be_bytes()
        .to_vec();
    out.push(kind);
    out.extend_from_slice(body);
    out
}

fn request(kind: u8, id: u32, fields: &[Vec<u8>]) -> Vec<u8> {
    let mut body = id.to_be_bytes().to_vec();
    for f in fields {
        body.extend_from_slice(f);
    }
    message(kind, &body)
}

fn open(path: &[u8], flags: u32) -> Vec<u8> {
    request(
        OPEN,
        1,
        &[s(path), flags.to_be_bytes().to_vec(), vec![0; 4]],
    )
}

/// A session as `sftp` sends it: init, a download, an upload with its
/// data, a rename and removals, extensions, and requests that are not
/// noted.
fn session() -> (Vec<u8>, Vec<Observed>) {
    let note = |kind, text: &[u8]| Observed {
        kind,
        text: text.to_vec(),
    };
    let mut stream = message(1, &3u32.to_be_bytes());
    stream.extend(request(16, 2, &[s(b".")]));
    stream.extend(open(b"/etc/hosts", 0x01));
    stream.extend(request(
        5,
        4,
        &[
            s(b"h1"),
            0u64.to_be_bytes().to_vec(),
            32768u32.to_be_bytes().to_vec(),
        ],
    ));
    stream.extend(open(b"/tmp/up", 0x02 | 0x08 | 0x10));
    stream.extend(request(
        6,
        5,
        &[
            s(b"h2"),
            0u64.to_be_bytes().to_vec(),
            s(&vec![0xab; 40_000]),
        ],
    ));
    stream.extend(request(4, 6, &[s(b"h2")]));
    stream.extend(request(SETSTAT, 7, &[s(b"/tmp/up"), vec![0; 4]]));
    stream.extend(request(RENAME, 8, &[s(b"/tmp/up"), s(b"/tmp/final")]));
    stream.extend(request(SYMLINK, 9, &[s(b"/tmp/l"), s(b"/tmp/final")]));
    stream.extend(request(REMOVE, 10, &[s(b"/tmp/old")]));
    stream.extend(request(MKDIR, 11, &[s(b"/tmp/d"), vec![0; 4]]));
    stream.extend(request(RMDIR, 12, &[s(b"/tmp/d")]));
    stream.extend(request(
        EXTENDED,
        13,
        &[s(b"posix-rename@openssh.com"), s(b"/a"), s(b"/b")],
    ));
    stream.extend(request(
        EXTENDED,
        14,
        &[s(b"hardlink@openssh.com"), s(b"/c"), s(b"/d")],
    ));
    stream.extend(request(
        EXTENDED,
        15,
        &[s(b"lsetstat@openssh.com"), s(b"/e"), vec![0; 4]],
    ));
    stream.extend(request(EXTENDED, 16, &[s(b"limits@openssh.com")]));
    stream.extend(request(EXTENDED, 17, &[s(b"statvfs@openssh.com"), s(b"/")]));
    let expected = vec![
        note(NoteKind::Read, b"/etc/hosts"),
        note(NoteKind::Write, b"/tmp/up"),
        note(NoteKind::Setstat, b"/tmp/up"),
        note(NoteKind::Rename, b"/tmp/up\0/tmp/final"),
        note(NoteKind::Link, b"/tmp/l\0/tmp/final"),
        note(NoteKind::Remove, b"/tmp/old"),
        note(NoteKind::Mkdir, b"/tmp/d"),
        note(NoteKind::Rmdir, b"/tmp/d"),
        note(NoteKind::Rename, b"/a\0/b"),
        note(NoteKind::Link, b"/c\0/d"),
        note(NoteKind::Setstat, b"/e"),
    ];
    (stream, expected)
}

fn observe(stream: &[u8], chunk: usize) -> Result<Vec<Observed>, SftpError> {
    let mut observer = SftpObserver::new();
    let mut out = Vec::new();
    for part in stream.chunks(chunk.max(1)) {
        observer.feed(part, &mut out)?;
    }
    Ok(out)
}

#[test]
fn a_session_shows_its_file_operations() {
    let (stream, expected) = session();
    assert_eq!(observe(&stream, stream.len()).unwrap(), expected);
    assert_eq!(observe(&stream, 1).unwrap(), expected);
    // Each note is a valid transcript note.
    for o in expected {
        ostena_recorder::Event::Note {
            kind: o.kind,
            text: o.text,
        }
        .check()
        .unwrap();
    }
}

#[test]
fn a_request_is_noted_once_complete() {
    let stream = open(b"/etc/shadow", 0x01);
    let mut observer = SftpObserver::new();
    let mut out = Vec::new();
    observer
        .feed(&stream[..stream.len() - 1], &mut out)
        .unwrap();
    assert_eq!(out, Vec::<Observed>::new());
    observer
        .feed(&stream[stream.len() - 1..], &mut out)
        .unwrap();
    assert_eq!(out.len(), 1);
}

#[test]
fn messages_out_of_bounds_end_the_observation() {
    let mut observer = SftpObserver::new();
    let mut out = Vec::new();
    let too_long = (MAX_MESSAGE + 1).to_be_bytes();
    assert!(
        observer
            .feed(&[too_long.as_slice(), &[OPEN]].concat(), &mut out)
            .is_err()
    );
    assert!(
        observer.feed(&open(b"/x", 1), &mut out).is_err(),
        "stays failed"
    );
    let mut observer = SftpObserver::new();
    assert!(observer.feed(&[0, 0, 0, 0, 1], &mut out).is_err());
    // The longest message passes.
    let mut observer = SftpObserver::new();
    let mut longest = MAX_MESSAGE.to_be_bytes().to_vec();
    longest.push(6);
    longest.resize(4 + MAX_MESSAGE as usize, 0);
    observer.feed(&longest, &mut out).unwrap();
    assert_eq!(out, Vec::<Observed>::new());
}

#[test]
fn names_are_bounded_and_never_empty() {
    let long = vec![b'a'; MAX_PATH + 100];
    let out = observe(&open(&long, 0x02), 7).unwrap();
    assert_eq!(out[0].text.len(), MAX_PATH);
    let out = observe(&open(b"", 0x01), 3).unwrap();
    assert_eq!(out[0].text, b"?");
    let out = observe(&open(b"a\0b", 0x01), 3).unwrap();
    assert_eq!(out[0].text, b"a?b");
    // A truncated request (string longer than its message) still notes
    // what is present.
    let mut body = 1u32.to_be_bytes().to_vec();
    body.extend_from_slice(&100u32.to_be_bytes());
    body.extend_from_slice(b"/short");
    let out = observe(&message(REMOVE, &body), 2).unwrap();
    assert_eq!(out[0].text, b"/short");
    // A rename whose first path fills the kept prefix: the second is `?`.
    let out = observe(&request(RENAME, 1, &[s(&long), s(b"/b")]), 4096).unwrap();
    assert_eq!(out[0].kind, NoteKind::Rename);
    let note = ostena_recorder::Event::Note {
        kind: out[0].kind,
        text: out[0].text.clone(),
    };
    note.check().unwrap();
}

#[test]
fn commands_are_classified() {
    use Command::{Mentions, Ordinary, Transfer};
    for (command, expected) in [
        (&b"scp -t /tmp"[..], Transfer(Protocol::Scp)),
        (b"scp -v -r -p -t -- '/tmp/a dir'", Transfer(Protocol::Scp)),
        (b"/usr/bin/scp -f /etc/hosts", Transfer(Protocol::Scp)),
        (b"scp -pf -- /etc/hosts", Transfer(Protocol::Scp)),
        (
            b"rsync --server -vlogDtpre.iLsfxC . /tmp/x",
            Transfer(Protocol::Rsync),
        ),
        (
            b"rsync --server --sender -vlogDtpre.iLsfxC . /etc",
            Transfer(Protocol::Rsync),
        ),
        (b"/usr/lib/openssh/sftp-server", Transfer(Protocol::Sftp)),
        (b"uname -a", Ordinary),
        (b"ls -la /tmp | wc -l", Ordinary),
        (b"echo scpx rsyncd", Ordinary),
        (b"scp host:/a /b", Mentions("scp")),
        (b"scp -t /tmp; cat /etc/shadow", Mentions("scp")),
        (b"rsync --server . /x && id", Mentions("rsync")),
        (b"sh -c 'scp -f /etc/shadow'", Mentions("scp")),
        (b"cd /;rsync -a x y", Mentions("rsync")),
        (b"sftp host", Mentions("sftp")),
        (b"scp -t '/tmp/a", Mentions("scp")),
        (b"scp -t /tmp/$(id)", Mentions("scp")),
        (b"scp -t \n/tmp", Mentions("scp")),
    ] {
        assert_eq!(
            classify(command),
            expected,
            "{}",
            String::from_utf8_lossy(command)
        );
    }
}

proptest! {
    #[test]
    fn prop_observation_does_not_depend_on_chunking(chunk in 1usize..5000) {
        let (stream, expected) = session();
        prop_assert_eq!(observe(&stream, chunk).unwrap(), expected);
    }

    #[test]
    fn prop_never_panics_and_notes_are_valid(data in proptest::collection::vec(any::<u8>(), 0..2048), chunk in 1usize..64) {
        if let Ok(out) = observe(&data, chunk) {
            for o in out {
                let note = ostena_recorder::Event::Note { kind: o.kind, text: o.text };
                prop_assert!(note.check().is_ok());
            }
        }
    }

    #[test]
    fn prop_classify_never_panics(command in proptest::collection::vec(any::<u8>(), 0..256)) {
        let _ = classify(&command);
    }
}
