use proptest::prelude::*;

use super::testing::{TestTsa, TokenOptions, generalized_time, granted, refusal};
use super::*;

/// Now, with a fraction of a second: inside the validity of the test
/// authority.
static T: std::sync::LazyLock<u64> = std::sync::LazyLock::new(|| {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    u64::try_from(now).unwrap() / 1000 * 1000 + 123
});

fn digest(n: u8) -> [u8; 32] {
    [n; 32]
}

#[test]
fn a_granted_response_verifies_with_its_nonce() {
    let tsa = TestTsa::new();
    let request = Request::with_nonce(digest(7), &[0x81, 2, 3]);
    let response = tsa.respond(request.der(), *T);
    let (token, stamp) = request.check(&response, &tsa.trust()).unwrap();
    assert_eq!(stamp.gen_time_ms, *T);
    assert_eq!(stamp.policy, "1.3.6.1.4.1.99999.3161");
    assert_eq!(
        stamp.signer_sha256,
        crate::sha256::digest(tsa.certificate())
    );
    assert_eq!(verify(&token, &digest(7), &tsa.trust()).unwrap(), stamp);
    // Another request (another nonce) does not accept this response.
    let other = Request::with_nonce(digest(7), &[9]);
    assert_eq!(
        other.check(&response, &tsa.trust()).unwrap_err(),
        TspError::Mismatch("nonce")
    );
    // Random nonces differ.
    assert_ne!(
        Request::new(digest(1)).unwrap(),
        Request::new(digest(1)).unwrap()
    );
}

#[test]
fn the_request_is_der() {
    let request = Request::with_nonce(digest(1), &[0, 0x80]);
    // version 1, imprint, nonce 0x0080 (minimal positive), certReq TRUE.
    let mut r = Reader::new(request.der());
    let mut seq = r.nested(tag::SEQUENCE, "req").unwrap();
    assert_eq!(seq.small("v").unwrap(), 1);
    seq.expect(tag::SEQUENCE, "imprint").unwrap();
    assert_eq!(seq.integer("nonce").unwrap(), &[0x00, 0x80]);
    assert!(seq.boolean("certReq").unwrap());
    seq.finish("end").unwrap();
}

#[test]
fn refusals_and_profile_violations_have_their_codes() {
    let tsa = TestTsa::new();
    let trust = tsa.trust();
    let token = |o: TokenOptions| tsa.token(&digest(3), None, *T, &o);
    let code = |token: &[u8]| verify(token, &digest(3), &trust).unwrap_err().code();

    assert_eq!(
        token_of_response(&refusal(2)).unwrap_err().code(),
        "TSP-E002"
    );
    assert!(
        token_of_response(&refusal(2))
            .unwrap_err()
            .to_string()
            .contains("refus de test")
    );
    assert_eq!(
        verify(&token(TokenOptions::default()), &digest(4), &trust)
            .unwrap_err()
            .code(),
        "TSP-E006"
    );
    assert_eq!(
        code(&token(TokenOptions {
            sign_other_content: true,
            ..TokenOptions::default()
        })),
        "TSP-E004"
    );
    assert_eq!(
        code(&token(TokenOptions {
            digest_algorithm: Some(vec![0x2b, 0x0e, 0x03, 0x02, 0x1a]), // SHA-1
            ..TokenOptions::default()
        })),
        "TSP-E003"
    );
    assert_eq!(
        code(&token(TokenOptions {
            sha1_signing_certificate: true,
            ..TokenOptions::default()
        })),
        "TSP-E003"
    );
    assert_eq!(
        code(&token(TokenOptions {
            omit_signing_certificate: true,
            ..TokenOptions::default()
        })),
        "TSP-E001"
    );
    // Without its certificate, the token needs it among the trusted ones.
    let bare = token(TokenOptions {
        omit_certificates: true,
        ..TokenOptions::default()
    });
    assert_eq!(code(&bare), "TSP-E005");
    // Another authority is not trusted.
    let other = TestTsa::new();
    assert_eq!(
        verify(&token(TokenOptions::default()), &digest(3), &other.trust())
            .unwrap_err()
            .code(),
        "TSP-E005"
    );
    // A non-critical extended key usage is refused (RFC 3161 section 2.3).
    let lax = TestTsa::with_eku(false);
    let t = lax.token(&digest(3), None, *T, &TokenOptions::default());
    assert_eq!(
        verify(&t, &digest(3), &lax.trust()).unwrap_err().code(),
        "TSP-E005"
    );
    // Stamped outside the validity of the certificate.
    let t = tsa.token(&digest(3), None, 1_000_000, &TokenOptions::default());
    assert_eq!(code(&t), "TSP-E005");
}

#[test]
fn accuracy_is_read() {
    let tsa = TestTsa::new();
    let t = tsa.token(
        &digest(3),
        None,
        *T,
        &TokenOptions {
            accuracy_secs: Some(2),
            ..TokenOptions::default()
        },
    );
    assert_eq!(
        verify(&t, &digest(3), &tsa.trust()).unwrap().accuracy_ms,
        Some(2000)
    );
}

#[test]
fn trust_is_bounded_and_read_from_pem() {
    let tsa = TestTsa::new();
    let trust = TsaTrust::from_pem(tsa.root_pem().as_bytes()).unwrap();
    assert_eq!(trust.anchors().len(), 1);
    assert!(TsaTrust::from_pem(b"").is_err());
    assert!(TsaTrust::new(vec![tsa.certificate().clone(); MAX_ANCHORS + 1]).is_err());
    let mut many = TsaTrust::new(vec![tsa.certificate().clone(); MAX_ANCHORS]).unwrap();
    assert!(many.extend(tsa.trust()).is_err());
}

#[test]
fn generalized_time_is_strict() {
    for (text, ms) in [
        ("19700101000000Z", 0),
        ("20261127123456.5Z", 1_795_782_896_500),
        ("20000229235959.123Z", 951_868_799_123),
    ] {
        assert_eq!(
            der::generalized_time(text.as_bytes()).unwrap(),
            ms,
            "{text}"
        );
        assert_eq!(generalized_time(ms), text);
    }
    for bad in [
        "20261127123456",
        "20261127123456.50Z",
        "20261127123456.Z",
        "2026112712345Z",
        "20260230000000Z",
        "20261127243456Z",
        "19691231235959Z",
        "20261127123456+0100",
    ] {
        assert!(der::generalized_time(bad.as_bytes()).is_err(), "{bad}");
    }
}

#[test]
fn der_lengths_and_integers_are_minimal() {
    for bad in [
        &[0x02, 0x81, 0x01, 0x00][..], // long form for a short length
        &[0x02, 0x80],                 // indefinite
        &[0x02, 0x82, 0x00, 0x80],     // leading zero in the length
        &[0x1f, 0x01, 0x00],           // multi-byte tag
        &[0x02, 0x02, 0x00],           // truncated
    ] {
        assert!(Reader::new(bad).any().is_err(), "{bad:?}");
    }
    assert!(der::check_integer(&[0x00, 0x01], "i").is_err());
    assert!(der::check_integer(&[0xff, 0x80], "i").is_err());
    assert!(der::check_integer(&[], "i").is_err());
    assert!(der::check_integer(&[0x00, 0x80], "i").is_ok());
    assert_eq!(oid_text(oid::SHA256).unwrap(), "2.16.840.1.101.3.4.2.1");
    assert!(oid_text(&[0x80, 0x01]).is_err());
    assert!(oid_text(&[0x2a, 0x86]).is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Every byte flipped, every truncation and every extension of a valid
    /// token is refused, never accepted as another stamp.
    #[test]
    fn prop_altered_tokens_are_refused(flip in any::<prop::sample::Index>(), bit in 0u8..8, cut in any::<prop::sample::Index>(), d in any::<[u8; 32]>()) {
        let tsa = shared_tsa();
        let token = tsa.token(&d, Some(&[1, 2]), *T, &TokenOptions::default());
        let trust = tsa.trust();
        prop_assert!(verify(&token, &d, &trust).is_ok());
        let mut flipped = token.clone();
        let i = flip.index(flipped.len());
        flipped[i] ^= 1 << bit;
        if let Ok(stamp) = verify(&flipped, &d, &trust) {
            // Only bytes outside what is signed can change: the
            // certificate copy, or unsigned framing. Never the stamp.
            prop_assert_eq!(stamp.gen_time_ms, *T);
        }
        let n = cut.index(token.len());
        prop_assert!(verify(&token[..n], &d, &trust).is_err());
        let mut longer = token.clone();
        longer.push(0);
        prop_assert!(verify(&longer, &d, &trust).is_err());
        prop_assert!(token_of_response(&granted(&token[..n])).is_err() || n == token.len());
    }

    /// The parser never panics, and anything accepted re-reads the same.
    #[test]
    fn prop_parsers_do_not_panic(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = token_of_response(&bytes);
        let _ = parse(&bytes);
        let _ = der::generalized_time(&bytes);
        let mut r = Reader::new(&bytes);
        while let Ok((t, content, whole)) = r.any() {
            prop_assert_eq!(write::element(t, content), whole.to_vec());
        }
    }

    /// GeneralizedTime round trip.
    #[test]
    fn prop_generalized_time_round_trip(ms in 0u64..253_402_300_799_999) {
        prop_assert_eq!(der::generalized_time(generalized_time(ms).as_bytes()).unwrap(), ms);
    }
}

fn shared_tsa() -> &'static TestTsa {
    static TSA: std::sync::OnceLock<TestTsa> = std::sync::OnceLock::new();
    TSA.get_or_init(TestTsa::new)
}

fn corpus_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/tsp_response")
}

/// Replays the cargo-fuzz corpus `fuzz/corpus/tsp_response` on the stable
/// toolchain: every input the fuzzer kept is a regression test.
#[test]
fn replay_corpus() {
    let mut count = 0;
    for entry in std::fs::read_dir(corpus_dir()).unwrap() {
        fuzz::response(&std::fs::read(entry.unwrap().path()).unwrap());
        count += 1;
    }
    assert!(count > 0, "empty corpus");
}

/// Writes the seeds again: `OSTENA_WRITE_SEEDS=1 cargo test -p
/// ostena-crypto --lib tsp::tests::write_seeds`.
#[test]
fn write_seeds() {
    if std::env::var_os("OSTENA_WRITE_SEEDS").is_none() {
        return;
    }
    let dir = corpus_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let tsa = TestTsa::new();
    let request = Request::with_nonce(digest(5), &[1, 2, 3, 4]);
    std::fs::write(dir.join("seed-granted.der"), tsa.respond(request.der(), *T)).unwrap();
    std::fs::write(dir.join("seed-refused.der"), refusal(2)).unwrap();
    let token = tsa.token(
        &digest(6),
        None,
        *T,
        &TokenOptions {
            accuracy_secs: Some(1),
            ..TokenOptions::default()
        },
    );
    std::fs::write(dir.join("seed-token.der"), &token).unwrap();
    std::fs::write(dir.join("seed-request.der"), request.der()).unwrap();
    std::fs::write(dir.join("seed-time.txt"), b"20261127123456.5Z").unwrap();
}
