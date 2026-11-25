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
