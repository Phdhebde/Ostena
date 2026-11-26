//! Entry points for `cargo fuzz` (the `fuzz/` workspace) and for the stable
//! tests that replay their corpora.

use crate::cert;
use crate::login::parse_login;
use crate::precheck::{Role, inspect};

/// The pre-check on arbitrary peer bytes, in both roles: never panics.
pub fn precheck(data: &[u8]) {
    let _ = inspect(data, Role::Server);
    let _ = inspect(data, Role::Client);
}

/// The certificate codec on arbitrary bytes: never panics, and whatever
/// parses is canonical (written back byte for byte) and goes through the
/// policies without panicking.
///
/// # Panics
///
/// If a parsed certificate does not encode back to its input: a bug.
pub fn certificate(data: &[u8]) {
    let Ok(parsed) = cert::parse(data) else {
        return;
    };
    assert_eq!(parsed.encode(), data, "non-canonical certificate accepted");
    let authority = parsed.authority;
    let _ = parsed.verify(&[authority]);
    let _ = parsed.verify(&[]);
    for now in [0, parsed.valid_after, parsed.valid_before, u64::MAX] {
        let _ = cert::check_user(&parsed, now);
        let _ = cert::check_host(&parsed, &parsed.public, now);
    }
}

/// The `account@resource` parser on arbitrary bytes: never panics, and what
/// it accepts rebuilds the input.
///
/// # Panics
///
/// If an accepted name does not rebuild the input: a bug.
pub fn login(data: &[u8]) {
    let Ok(user) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(login) = parse_login(user) {
        assert_eq!(format!("{}@{}", login.account, login.resource), user);
    }
}

/// The SFTP observer and the command classifier on arbitrary bytes, the
/// stream cut where its first byte says: never panics, the operations do
/// not depend on the cut, and each is a valid transcript note.
///
/// # Panics
///
/// If the cut changes what is observed, or a note is invalid: a bug.
pub fn sftp(data: &[u8]) {
    use crate::transfer::{SftpObserver, classify};
    let _ = classify(data);
    let Some((&cut, stream)) = data.split_first() else {
        return;
    };
    let observe = |chunk: usize| {
        let mut observer = SftpObserver::new();
        let mut out = Vec::new();
        let result = stream
            .chunks(chunk.max(1))
            .try_for_each(|part| observer.feed(part, &mut out));
        (result.is_ok(), out)
    };
    let whole = observe(stream.len());
    assert_eq!(
        whole,
        observe(usize::from(cut)),
        "observation depends on the cut"
    );
    for o in whole.1 {
        let note = ostena_recorder::Event::Note {
            kind: o.kind,
            text: o.text,
        };
        assert!(note.check().is_ok(), "invalid note");
    }
}
