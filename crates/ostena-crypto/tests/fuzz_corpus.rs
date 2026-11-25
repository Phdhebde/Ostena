//! Replays the cargo-fuzz corpus `fuzz/corpus/release_manifest` on the
//! stable toolchain, so that every input the fuzzer kept is a regression
//! test; checks that the signed seed is valid for the harness key.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside #[test] functions"
)]

use std::path::PathBuf;

use ostena_common::secret::SecretBytes;
use ostena_crypto::p256::{SigningKey, VerifyingKey};
use ostena_crypto::release::{self, Entry, Manifest, fuzz};

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/release_manifest")
}

/// The RFC 6979 appendix A.2.5 P-256 test key (public test vector), whose
/// public key the fuzz harness trusts.
fn harness_key() -> SigningKey {
    let scalar = vec![
        0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6,
        0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f,
        0x67, 0x21,
    ];
    SigningKey::from_scalar(&SecretBytes::from(scalar)).expect("RFC 6979 key")
}

fn seed_manifest() -> Manifest {
    Manifest::new(vec![
        Entry::new("ostena", [0x11; 32]).unwrap(),
        Entry::new("ostena-cli.cdx.json", [0x22; 32]).unwrap(),
        Entry::new("ostena.exe", [0x33; 32]).unwrap(),
    ])
    .unwrap()
}

#[test]
fn harness_key_matches_the_fuzz_key() {
    assert_eq!(harness_key().verifying_key().to_bytes(), fuzz::FUZZ_KEY);
}

#[test]
fn replay_corpus() {
    let mut count = 0;
    for entry in std::fs::read_dir(corpus_dir()).expect("corpus directory must exist") {
        let data = std::fs::read(entry.unwrap().path()).unwrap();
        fuzz::decode(&data);
        count += 1;
    }
    assert!(count > 0, "empty corpus");
}

#[test]
fn signed_seed_verifies() {
    let data = std::fs::read(corpus_dir().join("seed-signed.bin")).unwrap();
    let split = data.iter().position(|b| *b == 0).unwrap();
    let key = VerifyingKey::from_bytes(&fuzz::FUZZ_KEY).unwrap();
    let manifest = release::verify(
        &data[split + 1..],
        std::str::from_utf8(&data[..split]).unwrap(),
        &[key],
    )
    .unwrap();
    assert_eq!(manifest, seed_manifest());
}

/// Writes the seeds again: `OSTENA_WRITE_SEEDS=1 cargo test -p
/// ostena-crypto --test fuzz_corpus write_seeds`.
#[test]
fn write_seeds() {
    if std::env::var_os("OSTENA_WRITE_SEEDS").is_none() {
        return;
    }
    let dir = corpus_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let manifest = seed_manifest();
    let signature = release::sign(&manifest, &harness_key()).unwrap().to_text();
    std::fs::write(dir.join("seed-manifest.txt"), manifest.encode()).unwrap();
    std::fs::write(dir.join("seed-signature.txt"), &signature).unwrap();
    let mut signed = signature.into_bytes();
    signed.push(0);
    signed.extend_from_slice(manifest.encode().as_bytes());
    std::fs::write(dir.join("seed-signed.bin"), signed).unwrap();
    std::fs::write(dir.join("seed-empty.bin"), b"").unwrap();
}
