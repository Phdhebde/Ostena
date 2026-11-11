//! Replays the cargo-fuzz corpus (`fuzz/corpus/grant_decode`) on the stable
//! toolchain, so that every input the fuzzer kept is a regression test.

use std::path::PathBuf;

use ostena_common::secret::SecretBytes;
use ostena_crypto::ed25519::SigningKey;
use ostena_grant::{Claims, GatewayGroupId, Issuer, Protocol, ResourceId, Rights, SubjectId};

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/grant_decode")
}

#[test]
fn replay_fuzz_corpus() {
    let mut count = 0;
    for entry in std::fs::read_dir(corpus_dir()).expect("corpus directory must exist") {
        let path = entry.expect("readable entry").path();
        let data = std::fs::read(&path).expect("readable corpus file");
        ostena_grant::fuzz::decode(&data);
        count += 1;
    }
    assert!(count > 0, "empty corpus");
}

/// Regenerates the seed inputs: `cargo test -p ostena-grant --test fuzz_corpus -- --ignored`.
/// The valid seed is signed with the RFC 8032 test 1 key, which the fuzz
/// harness trusts, so the fuzzer starts from grants that pass the signature.
#[test]
#[ignore = "writes files; run on demand"]
fn write_seed_corpus() {
    // PKCS#8 v1 wrapping of the RFC 8032 section 7.1 TEST 1 secret key (public test vector).
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(&[
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ]);
    let key = SigningKey::from_pkcs8(&SecretBytes::from(der)).expect("RFC 8032 key");
    let issuer = Issuer::new(key);
    let claims = Claims {
        subject: SubjectId::from_bytes([1; 16]),
        resource: ResourceId::from_bytes([2; 16]),
        audience: GatewayGroupId::from_bytes([0; 16]),
        protocol: Protocol::Ssh,
        rights: Rights::CLIPBOARD_TO_TARGET,
        max_session_secs: 3600,
    };
    let signed = issuer.issue(&claims, 1_800_000_000 - 10).expect("issued");
    let dir = corpus_dir();
    std::fs::create_dir_all(&dir).expect("corpus directory");
    std::fs::write(dir.join("seed-valid.bin"), signed.as_bytes()).expect("write");
    std::fs::write(dir.join("seed-valid.txt"), signed.to_text()).expect("write");
    std::fs::write(dir.join("seed-short.bin"), &signed.as_bytes()[..100]).expect("write");
    std::fs::write(dir.join("seed-empty.bin"), b"").expect("write");
}

/// The valid seed must pass every check of the harness, otherwise the fuzzer
/// never reaches the code behind the signature.
#[test]
fn valid_seed_passes_the_harness_verifier() {
    let pk = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    let mut keys = ostena_grant::KeySet::new();
    keys.insert(ostena_crypto::ed25519::VerifyingKey::from_bytes(&pk).expect("valid key"));
    let verifier = ostena_grant::Verifier::new(
        keys,
        GatewayGroupId::from_bytes([0; 16]),
        ostena_grant::Policy::default(),
    );
    let seed = std::fs::read(corpus_dir().join("seed-valid.bin")).expect("seed");
    assert!(verifier.check(&seed, 1_800_000_000).is_ok());
}
