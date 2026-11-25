use std::future::Future;

use proptest::prelude::*;

use super::*;
use crate::format::{Claims, Protocol, Rights, SIGNED_LEN, TEXT_LEN};
use crate::ids::{Binding, Jti, Kid, ResourceId, SubjectId};
use crate::keys::Issuer;
use crate::replay::tests::block_on;
use crate::replay::{MemoryReplayStore, ReplayStoreError};
use ostena_crypto::p256::SigningKey;

const NOW: u64 = 1_800_000_000;
const GROUP: GatewayGroupId = GatewayGroupId::from_bytes([0x42; 16]);

struct Fixture {
    key: SigningKey,
    issuer: Issuer,
    verifier: Verifier,
}

fn fixture() -> Fixture {
    let (key, pkcs8) = SigningKey::generate().unwrap();
    let issuer = Issuer::new(SigningKey::from_pkcs8(&pkcs8).unwrap());
    let mut keys = KeySet::new();
    keys.insert(issuer.verifying_key());
    Fixture {
        key,
        issuer,
        verifier: Verifier::new(keys, GROUP, Policy::default()),
    }
}

impl Issuer {
    fn sign_ok(&self, grant: &Grant) -> SignedGrant {
        self.sign(grant).unwrap()
    }
}

fn claims() -> Claims {
    Claims {
        subject: SubjectId::from_bytes([1; 16]),
        resource: ResourceId::from_bytes([2; 16]),
        audience: GROUP,
        protocol: Protocol::Rdp,
        rights: Rights::CLIPBOARD_TO_TARGET.with(Rights::FILE_DOWNLOAD),
        max_session_secs: 3600,
        binding: Binding::of([3; 16], "administrateur"),
    }
}

fn grant(f: &Fixture) -> Grant {
    Grant {
        kid: f.issuer.kid(),
        jti: Jti::from_bytes([3; 16]),
        claims: claims(),
        issued_at: NOW,
        expires_at: NOW + 60,
    }
}

/// Signs arbitrary bytes as if they were a grant, to test checks that run
/// after a valid signature.
fn sign_raw(key: &SigningKey, mut unsigned: [u8; SIGNED_LEN]) -> SignedGrant {
    unsigned[8..16].copy_from_slice(&Kid::of(&key.verifying_key()).to_bytes());
    let sig = key.sign(&format::signed_message(&unsigned)).unwrap();
    format::assemble(&unsigned, &sig.to_bytes())
}

fn tampered(f: &Fixture, edit: impl FnOnce(&mut [u8; SIGNED_LEN])) -> SignedGrant {
    let mut unsigned = format::encode_unsigned(&grant(f));
    edit(&mut unsigned);
    sign_raw(&f.key, unsigned)
}

fn code(f: &Fixture, signed: &SignedGrant, now: u64) -> &'static str {
    f.verifier.check(signed.as_bytes(), now).unwrap_err().code()
}

#[test]
fn issued_grant_is_accepted_once() {
    let f = fixture();
    let signed = f.issuer.issue(&claims(), NOW).unwrap();
    let store = MemoryReplayStore::new();
    let g = block_on(f.verifier.verify(signed.as_bytes(), NOW, &store)).unwrap();
    assert_eq!(g.claims, claims());
    assert_eq!(g.expires_at - g.issued_at, 60);
    let again = block_on(f.verifier.verify(signed.as_bytes(), NOW + 1, &store));
    assert_eq!(again.unwrap_err().code(), "GRT-E010");
}

#[test]
fn text_form_round_trip() {
    let f = fixture();
    let signed = f.issuer.issue(&claims(), NOW).unwrap();
    let text = signed.to_text();
    assert_eq!(text.len(), 246);
    let parsed = SignedGrant::from_text(&text).unwrap();
    assert!(f.verifier.check(parsed.as_bytes(), NOW).is_ok());
}

#[test]
fn e001_malformed() {
    let f = fixture();
    let signed = f.issuer.sign_ok(&grant(&f));
    assert_eq!(
        f.verifier
            .check(&signed.as_bytes()[..167], NOW)
            .unwrap_err()
            .code(),
        "GRT-E001"
    );
    let mut long = signed.as_bytes().to_vec();
    long.push(0);
    assert_eq!(f.verifier.check(&long, NOW).unwrap_err().code(), "GRT-E001");
    assert_eq!(code(&f, &tampered(&f, |b| b[0] = b'X'), NOW), "GRT-E001");
    assert_eq!(code(&f, &tampered(&f, |b| b[7] = 1), NOW), "GRT-E001");
}

#[test]
fn e002_e003_version_and_algorithm() {
    let f = fixture();
    // Version 1 (168 bytes, no binding) is refused, whatever its length:
    // by its length first, by its version at the length of version 2.
    for version in [0u8, 1, 3, 0xff] {
        assert_eq!(code(&f, &tampered(&f, |b| b[3] = version), NOW), "GRT-E002");
    }
    let signed = f.issuer.sign_ok(&grant(&f));
    let mut v1 = signed.as_bytes()[..168].to_vec();
    v1[3] = 1;
    assert_eq!(f.verifier.check(&v1, NOW).unwrap_err().code(), "GRT-E001");
    // Validly signed, but announcing another algorithm: refused anyway.
    // 1 was Ed25519 in the first draft: refused like any other value.
    for alg in [0u8, 1, 3, 0xff] {
        assert_eq!(code(&f, &tampered(&f, |b| b[4] = alg), NOW), "GRT-E003");
    }
}

#[test]
fn binding_is_signed() {
    let f = fixture();
    let signed = f.issuer.issue(&claims(), NOW).unwrap();
    let g = f.verifier.check(signed.as_bytes(), NOW).unwrap();
    assert_eq!(g.claims.binding, Binding::of([3; 16], "administrateur"));
    assert_ne!(g.claims.binding, Binding::of([3; 16], "root"));
    // Any change of the binding breaks the signature.
    let mut bytes = *signed.as_bytes();
    bytes[110] ^= 1;
    assert_eq!(
        f.verifier.check(&bytes, NOW).unwrap_err().code(),
        "GRT-E006"
    );
}

#[test]
fn e004_invalid_fields() {
    let f = fixture();
    for protocol in [0u8, 5, 0xff] {
        assert_eq!(
            code(&f, &tampered(&f, |b| b[5] = protocol), NOW),
            "GRT-E004"
        );
    }
    assert_eq!(code(&f, &tampered(&f, |b| b[80] = 0x80), NOW), "GRT-E004");
    assert_eq!(
        code(
            &f,
            &tampered(&f, |b| b[84..88].copy_from_slice(&[0; 4])),
            NOW
        ),
        "GRT-E004"
    );
    let same_time = tampered(&f, |b| b[96..104].copy_from_slice(&NOW.to_be_bytes()));
    assert_eq!(code(&f, &same_time, NOW), "GRT-E004");
}

#[test]
fn e005_unknown_kid() {
    let f = fixture();
    let stranger = Issuer::new(SigningKey::generate().unwrap().0);
    let signed = stranger.issue(&claims(), NOW).unwrap();
    assert_eq!(code(&f, &signed, NOW), "GRT-E005");
}

#[test]
fn e006_bad_signature() {
    let f = fixture();
    let mut bytes = *f.issuer.sign_ok(&grant(&f)).as_bytes();
    bytes[33] ^= 1; // subject changed, not re-signed
    assert_eq!(
        f.verifier.check(&bytes, NOW).unwrap_err().code(),
        "GRT-E006"
    );
}

#[test]
fn e006_high_s_form_of_a_valid_grant() {
    // The P-256 group order, big-endian.
    const N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    let f = fixture();
    let mut bytes = *f.issuer.sign_ok(&grant(&f)).as_bytes();
    assert!(f.verifier.check(&bytes, NOW).is_ok());
    // s ← n − s: the same signature, mathematically valid, in its high form.
    let s = &mut bytes[SIGNED_LEN + 32..];
    let mut borrow = 0u16;
    for i in (0..32).rev() {
        let d = u16::from(N[i]) + 256 - u16::from(s[i]) - borrow;
        s[i] = d.to_le_bytes()[0];
        borrow = u16::from(d < 256);
    }
    assert_eq!(
        f.verifier.check(&bytes, NOW).unwrap_err().code(),
        "GRT-E006"
    );
}

#[test]
fn e007_e008_validity_window() {
    let f = fixture();
    let signed = f.issuer.sign_ok(&grant(&f));
    // Issued up to 5 s "in the future" is tolerated.
    assert!(f.verifier.check(signed.as_bytes(), NOW - 5).is_ok());
    assert_eq!(code(&f, &signed, NOW - 6), "GRT-E007");
    assert!(f.verifier.check(signed.as_bytes(), NOW + 59).is_ok());
    assert_eq!(code(&f, &signed, NOW + 60), "GRT-E008");
}

#[test]
fn e009_out_of_bounds() {
    let f = fixture();
    let long_ttl = Grant {
        expires_at: NOW + 301,
        ..grant(&f)
    };
    assert_eq!(code(&f, &f.issuer.sign_ok(&long_ttl), NOW), "GRT-E009");
    let max_ttl = Grant {
        expires_at: NOW + 300,
        ..grant(&f)
    };
    assert!(
        f.verifier
            .check(f.issuer.sign_ok(&max_ttl).as_bytes(), NOW)
            .is_ok()
    );
    let long_session = Grant {
        claims: Claims {
            max_session_secs: 12 * 3600 + 1,
            ..claims()
        },
        ..grant(&f)
    };
    assert_eq!(code(&f, &f.issuer.sign_ok(&long_session), NOW), "GRT-E009");
}

#[test]
fn e011_wrong_audience() {
    let f = fixture();
    let other = Grant {
        claims: Claims {
            audience: GatewayGroupId::from_bytes([0x43; 16]),
            ..claims()
        },
        ..grant(&f)
    };
    assert_eq!(code(&f, &f.issuer.sign_ok(&other), NOW), "GRT-E011");
}

#[test]
fn e012_e013_revoked_and_retired_keys() {
    let mut f = fixture();
    let signed = f.issuer.sign_ok(&grant(&f));
    let kid = f.issuer.kid();
    f.verifier.keys_mut().retire_at(kid, NOW + 10).unwrap();
    assert!(f.verifier.check(signed.as_bytes(), NOW).is_ok());
    assert_eq!(code(&f, &signed, NOW + 10), "GRT-E013");
    // Revocation applies before the retirement date.
    f.verifier.keys_mut().revoke(kid).unwrap();
    assert_eq!(code(&f, &signed, NOW), "GRT-E012");
}

#[test]
fn rotation_accepts_old_and_new_keys() {
    let mut f = fixture();
    let old = f.issuer.sign_ok(&grant(&f));
    let next = Issuer::new(SigningKey::generate().unwrap().0);
    f.verifier.keys_mut().insert(next.verifying_key());
    assert!(f.verifier.check(old.as_bytes(), NOW).is_ok());
    assert!(
        f.verifier
            .check(next.issue(&claims(), NOW).unwrap().as_bytes(), NOW)
            .is_ok()
    );
}

struct BrokenStore;

impl ReplayStore for BrokenStore {
    fn consume(
        &self,
        _: Jti,
        _: u64,
    ) -> impl Future<Output = Result<Freshness, ReplayStoreError>> + Send {
        std::future::ready(Err(ReplayStoreError("disque plein".into())))
    }
}

struct FencedStore;

impl ReplayStore for FencedStore {
    fn consume(
        &self,
        _: Jti,
        _: u64,
    ) -> impl Future<Output = Result<Freshness, ReplayStoreError>> + Send {
        std::future::ready(Ok(Freshness::Fenced))
    }
}

#[test]
fn e014_store_failure_refuses_and_fence_counts_as_replay() {
    let f = fixture();
    let signed = f.issuer.sign_ok(&grant(&f));
    let broken = block_on(f.verifier.verify(signed.as_bytes(), NOW, &BrokenStore));
    assert_eq!(broken.unwrap_err().code(), "GRT-E014");
    let fenced = block_on(f.verifier.verify(signed.as_bytes(), NOW, &FencedStore));
    assert_eq!(fenced.unwrap_err().code(), "GRT-E010");
}

#[test]
fn rejected_grant_does_not_consume_the_jti() {
    let f = fixture();
    let signed = f.issuer.sign_ok(&grant(&f));
    let store = MemoryReplayStore::new();
    let early = block_on(f.verifier.verify(signed.as_bytes(), NOW - 10, &store));
    assert_eq!(early.unwrap_err().code(), "GRT-E007");
    assert!(block_on(f.verifier.verify(signed.as_bytes(), NOW, &store)).is_ok());
}

// ---------------------------------------------------------------- properties

fn arb_claims() -> impl Strategy<Value = Claims> {
    (
        any::<[u8; 16]>(),
        any::<[u8; 16]>(),
        proptest::sample::select(Protocol::ALL.to_vec()),
        0u32..(1 << 9),
        1u32..=12 * 3600,
    )
        .prop_map(|(s, r, protocol, rights, max_session_secs)| Claims {
            binding: Binding::from_bytes(r),
            subject: SubjectId::from_bytes(s),
            resource: ResourceId::from_bytes(r),
            audience: GROUP,
            protocol,
            rights: Rights::from_bits(rights).unwrap_or_default(),
            max_session_secs,
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn prop_issued_grants_verify_with_their_claims(c in arb_claims(), ttl in 1u32..=300) {
        let f = fixture();
        let issuer = Issuer::new(f.key).with_ttl(ttl);
        let mut keys = KeySet::new();
        keys.insert(issuer.verifying_key());
        let verifier = Verifier::new(keys, GROUP, Policy::default());
        let signed = issuer.issue(&c, NOW).unwrap();
        let g = verifier.check(signed.as_bytes(), NOW).unwrap();
        prop_assert_eq!(g.claims, c);
        prop_assert_eq!(g.expires_at, NOW + u64::from(ttl));
    }

    /// The core property: a grant with any single bit flipped is refused.
    #[test]
    fn prop_any_single_bit_flip_is_refused(c in arb_claims(), bit in 0usize..(GRANT_LEN * 8)) {
        let f = fixture();
        let mut bytes = *f.issuer.issue(&c, NOW).unwrap().as_bytes();
        prop_assert!(f.verifier.check(&bytes, NOW).is_ok());
        bytes[bit / 8] ^= 1 << (bit % 8);
        prop_assert!(f.verifier.check(&bytes, NOW).is_err());
    }

    #[test]
    fn prop_any_text_character_change_is_refused(c in arb_claims(), pos in 0usize..TEXT_LEN, ch in "[A-Za-z0-9_-]") {
        let f = fixture();
        let text = f.issuer.issue(&c, NOW).unwrap().to_text();
        prop_assume!(text.as_bytes()[pos] != ch.as_bytes()[0]);
        let mut changed = text.into_bytes();
        changed[pos] = ch.as_bytes()[0];
        let changed = String::from_utf8(changed).unwrap();
        let refused = SignedGrant::from_text(&changed)
            .and_then(|s| f.verifier.check(s.as_bytes(), NOW))
            .is_err();
        prop_assert!(refused);
    }

    #[test]
    fn prop_check_never_panics(data in proptest::collection::vec(any::<u8>(), 0..400)) {
        let f = fixture();
        let _ = f.verifier.check(&data, NOW);
    }
}
