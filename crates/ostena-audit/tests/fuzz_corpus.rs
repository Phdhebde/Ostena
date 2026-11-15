//! Replays the cargo-fuzz corpora (`fuzz/corpus/audit_decode` and
//! `fuzz/corpus/audit_verify`) on the stable toolchain, so that every input
//! the fuzzer kept is a regression test.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside #[test] functions"
)]

use std::path::PathBuf;

use ostena_audit::{
    ActorKind, ChainId, ChainTip, Event, EventKind, ExportWriter, Head, Options, Outcome,
    UnsignedHead, field, verify_export,
};
use ostena_common::secret::SecretBytes;
use ostena_crypto::p256::SigningKey;

fn corpus_dir(target: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../fuzz/corpus/{target}"))
}

fn replay(target: &str, run: fn(&[u8])) {
    let mut count = 0;
    for entry in std::fs::read_dir(corpus_dir(target)).expect("corpus directory must exist") {
        let path = entry.expect("readable entry").path();
        let data = std::fs::read(&path).expect("readable corpus file");
        run(&data);
        count += 1;
    }
    assert!(count > 0, "empty corpus {target}");
}

#[test]
fn replay_decode_corpus() {
    replay("audit_decode", ostena_audit::fuzz::decode);
}

#[test]
fn replay_verify_corpus() {
    replay("audit_verify", ostena_audit::fuzz::verify);
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

#[test]
fn harness_key_matches_the_fuzz_key() {
    assert_eq!(
        harness_key().verifying_key().to_bytes(),
        ostena_audit::fuzz::FUZZ_KEY
    );
}

/// A chain of five records with heads after records 2 and 5, as export
/// items; returns the export bytes and the parts used by the seeds.
struct Seeds {
    records: Vec<Vec<u8>>,
    heads: Vec<Head>,
    full: Vec<u8>,
    partial: Vec<u8>,
}

fn seeds() -> Seeds {
    let key = harness_key();
    let chain_id = ChainId::from_bytes([0x0a; 16]);
    let mut tip = ChainTip::empty(chain_id);
    let mut records = Vec::new();
    let mut heads: Vec<Head> = Vec::new();
    let mut after = Vec::new();
    let t0 = 1_800_000_000_000;
    for seq in 1..=5u64 {
        let event = match seq {
            1 => Event::new(
                EventKind::AuditChainStarted,
                Outcome::Success,
                ActorKind::Core,
                "core",
            ),
            2 => Event::new(
                EventKind::AgentEnrolled,
                Outcome::Success,
                ActorKind::Agent,
                "agent",
            )
            .uuid(field::AGENT_ID, [1; 16])
            .bytes(field::KID, [2; 8])
            .bool("renewal", false),
            _ => Event::new(
                EventKind::TunnelRefused,
                Outcome::Refused,
                ActorKind::Peer,
                "192.0.2.7",
            )
            .text(field::CODE, "TUN-E012")
            .u64(field::FIRST_SEQ, seq),
        };
        let appended = tip.append(event, t0 + seq * 1000).unwrap();
        records.push(appended.body);
        if seq == 2 || seq == 5 {
            let head = UnsignedHead::after(
                heads.last(),
                chain_id,
                tip.seq,
                tip.hash,
                t0 + seq * 1000 + 1,
                60,
            )
            .sign(&key)
            .unwrap();
            heads.push(head);
            after.push(seq);
        }
    }
    let export = |first_seq: u64| {
        let mut writer = ExportWriter::new(Vec::new(), chain_id, t0 + 6000, first_seq).unwrap();
        if first_seq > 1 {
            writer.head(&heads[0]).unwrap();
        }
        for seq in first_seq..=5 {
            writer
                .record(&records[usize::try_from(seq - 1).unwrap()])
                .unwrap();
            for (head, &at) in heads.iter().zip(&after) {
                if at == seq {
                    writer.head(head).unwrap();
                }
            }
        }
        writer.finish().unwrap()
    };
    Seeds {
        full: export(1),
        partial: export(3),
        records,
        heads,
    }
}

/// Regenerates the seed inputs:
/// `cargo test -p ostena-audit --test fuzz_corpus -- --ignored`. The heads
/// are signed with the key the harness trusts, so the fuzzer starts from
/// exports that pass verification.
#[test]
#[ignore = "writes files; run on demand"]
fn write_seed_corpus() {
    let s = seeds();
    let decode = corpus_dir("audit_decode");
    std::fs::create_dir_all(&decode).unwrap();
    std::fs::write(decode.join("seed-record-1.bin"), &s.records[0]).unwrap();
    std::fs::write(decode.join("seed-record-2.bin"), &s.records[1]).unwrap();
    std::fs::write(decode.join("seed-record-3.bin"), &s.records[2]).unwrap();
    std::fs::write(decode.join("seed-record-short.bin"), &s.records[1][..40]).unwrap();
    std::fs::write(decode.join("seed-head.bin"), s.heads[0].encode()).unwrap();
    std::fs::write(decode.join("seed-head.txt"), s.heads[1].to_text()).unwrap();
    std::fs::write(decode.join("seed-export.bin"), &s.full).unwrap();
    std::fs::write(decode.join("seed-empty.bin"), b"").unwrap();
    let verify = corpus_dir("audit_verify");
    std::fs::create_dir_all(&verify).unwrap();
    std::fs::write(verify.join("seed-full.bin"), &s.full).unwrap();
    std::fs::write(verify.join("seed-partial.bin"), &s.partial).unwrap();
    std::fs::write(
        verify.join("seed-truncated.bin"),
        &s.full[..s.full.len() - 20],
    )
    .unwrap();
    std::fs::write(verify.join("seed-empty.bin"), b"").unwrap();
}

/// The valid seeds must pass the harness verifier, otherwise the fuzzer
/// never reaches the code behind the signatures.
#[test]
fn valid_seeds_pass_the_harness_verifier() {
    for name in ["seed-full.bin", "seed-partial.bin"] {
        let seed = std::fs::read(corpus_dir("audit_verify").join(name)).expect("seed");
        let report = verify_export(
            seed.as_slice(),
            ostena_audit::fuzz::keys(),
            Options::default(),
        )
        .unwrap();
        assert_eq!(report.exit_code(), 0, "{name}: {:?}", report.findings);
    }
    // Freshly generated seeds pass too (the files may be older).
    let s = seeds();
    for export in [&s.full, &s.partial] {
        let report = verify_export(
            export.as_slice(),
            ostena_audit::fuzz::keys(),
            Options::default(),
        )
        .unwrap();
        assert_eq!(report.exit_code(), 0, "{:?}", report.findings);
    }
}
