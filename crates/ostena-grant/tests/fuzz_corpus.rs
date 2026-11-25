//! Replays the cargo-fuzz corpus (`fuzz/corpus/grant_decode`) on the stable
//! toolchain, so that every input the fuzzer kept is a regression test.

use std::path::PathBuf;

use ostena_common::secret::SecretBytes;
use ostena_crypto::p256::SigningKey;
use ostena_grant::{
    Binding, Claims, GatewayGroupId, Issuer, Protocol, ResourceId, Rights, SubjectId,
};

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

/// The RFC 6979 appendix A.2.5 P-256 test key (public test vector), whose
/// public key the fuzz harness trusts.
#[expect(clippy::expect_used, reason = "test helper on a fixed test vector")]
fn harness_key() -> SigningKey {
    // PKCS#8 wrapping of the scalar, without the optional public key.
    let mut der = vec![
        0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
        0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27, 0x30, 0x25,
        0x02, 0x01, 0x01, 0x04, 0x20,
    ];
    der.extend_from_slice(&[
        0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6,
        0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f,
        0x67, 0x21,
    ]);
    SigningKey::from_pkcs8(&SecretBytes::from(der)).expect("RFC 6979 key")
}

#[test]
fn harness_key_matches_the_fuzz_key() {
    assert_eq!(
        harness_key().verifying_key().to_bytes(),
        ostena_grant::fuzz::FUZZ_KEY
    );
}

/// Regenerates the seed inputs: `cargo test -p ostena-grant --test fuzz_corpus -- --ignored`.
/// The valid seed is signed with the key the fuzz harness trusts, so the
/// fuzzer starts from grants that pass the signature.
#[test]
#[ignore = "writes files; run on demand"]
fn write_seed_corpus() {
    let issuer = Issuer::new(harness_key());
    let claims = Claims {
        subject: SubjectId::from_bytes([1; 16]),
        resource: ResourceId::from_bytes([2; 16]),
        audience: GatewayGroupId::from_bytes([0; 16]),
        protocol: Protocol::Ssh,
        rights: Rights::CLIPBOARD_TO_TARGET,
        max_session_secs: 3600,
        binding: Binding::of([3; 16], "root"),
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
    let mut keys = ostena_grant::KeySet::new();
    keys.insert(
        ostena_crypto::p256::VerifyingKey::from_bytes(&ostena_grant::fuzz::FUZZ_KEY)
            .expect("valid key"),
    );
    let verifier = ostena_grant::Verifier::new(
        keys,
        GatewayGroupId::from_bytes([0; 16]),
        ostena_grant::Policy::default(),
    );
    let seed = std::fs::read(corpus_dir().join("seed-valid.bin")).expect("seed");
    assert!(verifier.check(&seed, 1_800_000_000).is_ok());
}
