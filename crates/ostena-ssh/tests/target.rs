//! Our client, behind the pre-check, against a real OpenSSH 9.x server
//! (Debian 12). Run by `tests/ssh/debian12-target.sh`, which starts the
//! server and sets:
//! - `OSTENA_SSH_TARGET`: `host:port`;
//! - `OSTENA_SSH_TARGET_USER`: the account;
//! - `OSTENA_SSH_TARGET_KEY`: the client private key (its public key is in
//!   `authorized_keys` with `restrict,from=…`);
//! - `OSTENA_SSH_TARGET_HOST_KEY`: the expected ECDSA P-256 host key line.
//!
//! Without them the test is skipped, unless `OSTENA_REQUIRE_TARGET=1` (CI).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stderr,
    reason = "test helpers outside #[test] functions; notices go to stderr"
)]

mod common;

use common::{dir, events, keygen, load, openssh, public, refusals, run_command, runtime};

struct Target {
    addr: String,
    user: String,
    key: std::path::PathBuf,
    host_key: String,
}

fn target() -> Option<Target> {
    let var = |name: &str| std::env::var(name).ok();
    let found = (|| {
        Some(Target {
            addr: var("OSTENA_SSH_TARGET")?,
            user: var("OSTENA_SSH_TARGET_USER")?,
            key: var("OSTENA_SSH_TARGET_KEY")?.into(),
            host_key: var("OSTENA_SSH_TARGET_HOST_KEY")?,
        })
    })();
    if found.is_none() {
        assert!(
            var("OSTENA_REQUIRE_TARGET").as_deref() != Some("1"),
            "cible OpenSSH non configurée alors que OSTENA_REQUIRE_TARGET=1"
        );
        eprintln!("cible OpenSSH non configurée : test sauté (tests/ssh/debian12-target.sh)");
    }
    found
}

#[test]
fn session_with_openssh_server_succeeds_through_the_precheck() {
    let Some(t) = target() else { return };
    events();
    let runtime = runtime();
    let printed = runtime
        .block_on(run_command(
            &t.addr,
            "target-ok",
            public(&t.host_key),
            &t.user,
            load(&t.key),
            "echo ok",
        ))
        .unwrap();
    assert_eq!(printed, "ok\n");
    assert_eq!(refusals("target-ok"), Vec::<String>::new());
}

#[test]
fn unexpected_host_key_is_refused() {
    let Some(t) = target() else { return };
    let Some(keygen_bin) = openssh("ssh-keygen") else {
        return;
    };
    let dir = dir("target-other");
    // Another ECDSA P-256 key: the target is not trusted.
    let (_, other) = keygen(&keygen_bin, &dir.0, "other");
    let runtime = runtime();
    let refused = runtime.block_on(run_command(
        &t.addr,
        "target-wrong-key",
        public(&other),
        &t.user,
        load(&t.key),
        "echo ok",
    ));
    assert!(refused.is_err(), "{refused:?}");
}
