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

fn replay(target: &str, run: fn(&[u8])) -> usize {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/corpus")
        .join(target);
    let mut count = 0;
    for entry in std::fs::read_dir(dir).expect("corpus directory must exist") {
        run(&std::fs::read(entry.expect("entry").path()).expect("corpus file"));
        count += 1;
    }
    count
}

#[test]
fn replay_ssh_certificate_corpus() {
    assert!(replay("ssh_certificate", ostena_ssh::fuzz::certificate) > 0);
}

#[test]
fn replay_ssh_login_corpus() {
    assert!(replay("ssh_login", ostena_ssh::fuzz::login) > 0);
}

#[test]
fn certificate_seeds_from_ssh_keygen_parse() {
    for entry in std::fs::read_dir(corpus().join("../ssh_certificate")).expect("corpus") {
        let path = entry.expect("entry").path();
        let data = std::fs::read(&path).expect("seed");
        if path
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with("seed-"))
        {
            let parsed = ostena_ssh::cert::parse(&data).expect("seed parses");
            assert_eq!(parsed.encode(), data, "{}", path.display());
        }
    }
}
