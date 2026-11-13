//! Replays the cargo-fuzz corpus (`fuzz/corpus/ssh_precheck`) on the stable
//! toolchain. The seeds are real offers captured from OpenSSH: each one must
//! be accepted in its role, so that the fuzzer starts past the framing.

#![allow(clippy::expect_used, reason = "test helpers")]

use std::path::PathBuf;

use ostena_ssh::precheck::{Progress, Role, inspect};

fn corpus() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/ssh_precheck")
}

#[test]
fn replay_ssh_precheck_corpus() {
    let mut count = 0;
    for entry in std::fs::read_dir(corpus()).expect("corpus directory must exist") {
        let data = std::fs::read(entry.expect("entry").path()).expect("corpus file");
        ostena_ssh::fuzz::precheck(&data);
        count += 1;
    }
    assert!(count > 0, "empty corpus");
}

#[test]
fn captured_openssh_offers_are_accepted_in_their_role() {
    for (name, role) in [
        ("seed-openssh-9.5-client.bin", Role::Server),
        ("seed-openssh-9.2-debian12-server.bin", Role::Client),
    ] {
        let data = std::fs::read(corpus().join(name)).expect("seed");
        assert_eq!(
            inspect(&data, role),
            Ok(Progress::Accepted {
                consumed: data.len()
            }),
            "{name}"
        );
    }
}
