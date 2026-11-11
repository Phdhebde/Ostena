//! Replays the cargo-fuzz corpora (`fuzz/corpus/scope_*`) on the stable
//! toolchain, so that every input the fuzzer kept is a regression test.

#![allow(clippy::expect_used, reason = "test helper outside #[test] functions")]

use std::path::PathBuf;

fn replay(target: &str, run: fn(&[u8])) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/corpus")
        .join(target);
    let mut count = 0;
    for entry in std::fs::read_dir(&dir).expect("corpus directory must exist") {
        let data = std::fs::read(entry.expect("entry").path()).expect("corpus file");
        run(&data);
        count += 1;
    }
    assert!(count > 0, "empty corpus {}", dir.display());
}

#[test]
fn replay_scope_target_corpus() {
    replay("scope_target", ostena_scope::fuzz::target);
}

#[test]
fn replay_scope_policy_corpus() {
    replay("scope_policy", ostena_scope::fuzz::policy);
}
