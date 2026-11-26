//! Replays the cargo-fuzz corpora (`fuzz/corpus/ldap_message`,
//! `fuzz/corpus/ldap_filter`) on the stable toolchain: every seed goes
//! through the fuzzing entry point, and the seeds of real messages and
//! filters must be accepted.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside #[test] functions"
)]

use std::path::PathBuf;

fn corpus(name: &str) -> Vec<(String, Vec<u8>)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/corpus")
        .join(name);
    std::fs::read_dir(dir)
        .expect("corpus directory must exist")
        .map(|e| {
            let path = e.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            (name, std::fs::read(&path).unwrap())
        })
        .collect()
}

#[test]
fn replay_ldap_message_corpus() {
    let seeds = corpus("ldap_message");
    assert!(seeds.len() >= 10);
    for (name, data) in seeds {
        ostena_ldap::fuzz::messages(&data);
        if name.starts_with("seed-") {
            let ok = if name.ends_with("-request") || name == "seed-unbind" {
                ostena_ldap::decode_request(&data).is_ok()
            } else {
                ostena_ldap::decode_response(&data).is_ok()
            };
            assert!(ok, "{name} must decode");
        }
    }
}

#[test]
fn replay_ldap_filter_corpus() {
    let seeds = corpus("ldap_filter");
    assert!(seeds.len() >= 7);
    for (name, data) in seeds {
        ostena_ldap::fuzz::filter(&data);
        if name.starts_with("seed-") {
            let text = std::str::from_utf8(&data).unwrap();
            assert!(
                ostena_ldap::Filter::parse(text).is_ok(),
                "{name} must parse"
            );
        }
    }
}
