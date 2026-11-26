//! Replays the cargo-fuzz corpus (`fuzz/corpus/tunnel_control_decode`) on the
//! stable toolchain, so that every input the fuzzer kept is a regression test.

#![allow(clippy::expect_used, reason = "test helpers")]

use std::path::PathBuf;

#[test]
fn replay_tunnel_control_decode_corpus() {
    let dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/tunnel_control_decode");
    let mut count = 0;
    for entry in std::fs::read_dir(&dir).expect("corpus directory must exist") {
        let data = std::fs::read(entry.expect("entry").path()).expect("corpus file");
        ostena_tunnel::fuzz::decode(&data);
        count += 1;
    }
    assert!(count > 0, "empty corpus {}", dir.display());
}

/// The seeds are valid messages, so that the fuzzer starts past the JSON layer.
#[test]
fn json_seeds_decode() {
    use ostena_tunnel::control::{AgentMessage, CoreMessage, decode};
    let dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/tunnel_control_decode");
    for name in [
        "seed-hello-ack",
        "seed-policy",
        "seed-session-params",
        "seed-refused",
        "seed-ping",
        "seed-ssh-trust",
        "seed-ssh-grant",
        "seed-login-revoked",
        "seed-session-params-ssh",
    ] {
        let data = std::fs::read(dir.join(format!("{name}.json"))).expect("seed");
        assert!(decode::<CoreMessage>(&data).is_ok(), "{name}");
    }
    for name in ["seed-hello", "seed-ssh-host-key", "seed-ssh-grant-request"] {
        let data = std::fs::read(dir.join(format!("{name}.json"))).expect("seed");
        assert!(decode::<AgentMessage>(&data).is_ok(), "{name}");
    }
}

/// The enrolment seeds are valid messages too.
#[test]
fn enrolment_seeds_decode() {
    use ostena_tunnel::enroll::{decode_client, decode_server};
    let dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/tunnel_control_decode");
    for name in ["seed-enroll-challenge", "seed-enroll-refused"] {
        let data = std::fs::read(dir.join(format!("{name}.json"))).expect("seed");
        assert!(decode_server(&data).is_ok(), "{name}");
    }
    let request = std::fs::read(dir.join("seed-enroll-request.json")).expect("seed");
    assert!(decode_client(&request).is_ok());
}

/// Replays the corpus of the TCP multiplexer (`fuzz/corpus/tunnel_mux_decode`).
#[test]
fn replay_tunnel_mux_decode_corpus() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/tunnel_mux_decode");
    let mut count = 0;
    for entry in std::fs::read_dir(&dir).expect("corpus directory must exist") {
        let data = std::fs::read(entry.expect("entry").path()).expect("corpus file");
        ostena_tunnel::fuzz::mux(&data);
        count += 1;
    }
    assert!(count > 0, "empty corpus {}", dir.display());
}
