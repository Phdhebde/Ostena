use proptest::prelude::*;

use super::*;

const SEED_SHA1: &[u8] = b"12345678901234567890";
const SEED_SHA256: &[u8] = b"12345678901234567890123456789012";

fn secret(algorithm: TotpAlgorithm, seed: &[u8]) -> TotpSecret {
    TotpSecret::from_bytes(algorithm, SecretBytes::from(seed.to_vec())).unwrap()
}

fn code(text: &str) -> SecretString {
    SecretString::from(text.to_owned())
}

fn shown(s: &SecretString) -> String {
    // SECRET-EXPOSURE: test assertion on a throwaway value.
    #[expect(clippy::disallowed_methods)]
    let v = s.expose_secret().to_owned();
    v
}

/// RFC 6238 appendix B, eight digits.
#[test]
fn rfc6238_vectors() {
    let sha1 = secret(TotpAlgorithm::Sha1, SEED_SHA1);
    let sha256 = secret(TotpAlgorithm::Sha256, SEED_SHA256);
    for (time, expected_sha1, expected_sha256) in [
        (59, 94_287_082, 46_119_246),
        (1_111_111_109, 7_081_804, 68_084_774),
        (1_111_111_111, 14_050_471, 67_062_674),
        (1_234_567_890, 89_005_924, 91_819_424),
        (2_000_000_000, 69_279_037, 90_698_825),
        (20_000_000_000, 65_353_130, 77_737_706),
    ] {
        let step = step_at(time);
        assert_eq!(sha1.hotp(step, 8), expected_sha1, "SHA-1 at {time}");
        assert_eq!(sha256.hotp(step, 8), expected_sha256, "SHA-256 at {time}");
        // Six digits are the last six of the eight.
        assert_eq!(
            shown(&sha1.code(step)),
            format!("{:06}", expected_sha1 % 1_000_000)
        );
        let six = format!("{:06}", expected_sha256 % 1_000_000);
        assert_eq!(sha256.verify(&code(&six), time, 0), Ok(step));
    }
}

/// RFC 4226 appendix D, six digits.
#[test]
fn rfc4226_vectors() {
    let s = secret(TotpAlgorithm::Sha1, SEED_SHA1);
    let expected = [
        "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871",
        "520489",
    ];
    for (counter, want) in expected.iter().enumerate() {
        assert_eq!(shown(&s.code(counter as u64)), *want);
    }
}

#[test]
fn window_is_one_step_each_side() {
    let s = TotpSecret::generate(TotpAlgorithm::Sha1).unwrap();
    let now = 1_800_000_015;
    let step = step_at(now);
    for (offset, accepted) in [(-2i64, false), (-1, true), (0, true), (1, true), (2, false)] {
        let candidate = step.checked_add_signed(offset).unwrap();
        let typed = s.code(candidate);
        let result = s.verify(&typed, now, 0);
        if accepted {
            assert_eq!(result, Ok(candidate), "offset {offset}");
        } else {
            // A code two steps away may collide by chance (1 in 10^6):
            // it never verifies as that step.
            assert_ne!(result, Ok(candidate), "offset {offset}");
        }
    }
}

#[test]
fn replay_is_refused() {
    let s = TotpSecret::generate(TotpAlgorithm::Sha256).unwrap();
    let now = 1_800_000_000;
    let typed = s.code(step_at(now));
    let step = s.verify(&typed, now, 0).unwrap();
    assert_eq!(s.verify(&typed, now, step), Err(TotpError::Replayed));
    // Still refused a step later, while the code is in the window.
    assert_eq!(s.verify(&typed, now + 30, step), Err(TotpError::Replayed));
    // An older code than the last one accepted is refused too.
    let older = s.code(step_at(now) - 1);
    assert_eq!(s.verify(&older, now, step), Err(TotpError::Replayed));
    // The next step is accepted.
    let next = s.code(step_at(now) + 1);
    assert_eq!(s.verify(&next, now + 30, step), Ok(step + 1));
}

#[test]
fn malformed_codes_are_refused() {
    let s = secret(TotpAlgorithm::Sha1, SEED_SHA1);
    for bad in [
        "",
        "12345",
        "1234567",
        "12345a",
        " 12345",
        "١٢٣٤٥٦",
        "+12345",
    ] {
        assert_eq!(
            s.verify(&code(bad), 59, 0),
            Err(TotpError::Format),
            "{bad:?}"
        );
    }
}

#[test]
fn epoch_start_has_no_previous_step() {
    let s = secret(TotpAlgorithm::Sha1, SEED_SHA1);
    assert_eq!(s.verify(&code("755224"), 0, 0), Err(TotpError::Replayed));
    assert_eq!(s.verify(&code("287082"), 0, 0), Ok(1));
}

#[test]
fn secret_length_matches_the_algorithm() {
    for algorithm in [TotpAlgorithm::Sha1, TotpAlgorithm::Sha256] {
        let s = TotpSecret::generate(algorithm).unwrap();
        // SECRET-EXPOSURE: test assertion on the length only.
        #[expect(clippy::disallowed_methods)]
        let len = s.bytes().expose_secret().len();
        assert_eq!(len, algorithm.secret_len());
        assert_eq!(TotpAlgorithm::parse(algorithm.as_str()), Some(algorithm));
    }
    assert_eq!(
        TotpSecret::from_bytes(TotpAlgorithm::Sha256, SecretBytes::from(SEED_SHA1.to_vec())).err(),
        Some(TotpError::SecretLength)
    );
    assert_eq!(TotpAlgorithm::parse("SHA1"), None);
}

#[test]
fn rfc4648_base32() {
    for (input, want) in [
        ("", ""),
        ("f", "MY"),
        ("fo", "MZXQ"),
        ("foo", "MZXW6"),
        ("foob", "MZXW6YQ"),
        ("fooba", "MZXW6YTB"),
        ("foobar", "MZXW6YTBOI"),
    ] {
        assert_eq!(base32(input.as_bytes()), want);
    }
    let s = secret(TotpAlgorithm::Sha1, SEED_SHA1);
    assert_eq!(shown(&s.base32()), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
}

#[test]
fn provisioning_uri() {
    let s = secret(TotpAlgorithm::Sha1, SEED_SHA1);
    assert_eq!(
        shown(&s.provisioning_uri("Ostena lab", "jdupont").unwrap()),
        "otpauth://totp/Ostena%20lab:jdupont?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\
         &issuer=Ostena%20lab&algorithm=SHA1&digits=6&period=30"
    );
    let s = secret(TotpAlgorithm::Sha256, SEED_SHA256);
    assert!(
        shown(&s.provisioning_uri("Ostena", "a.b-c_d@x").unwrap())
            .starts_with("otpauth://totp/Ostena:a.b-c_d%40x?secret=")
    );
    assert!(shown(&s.provisioning_uri("Ostena", "x").unwrap()).contains("&algorithm=SHA256&"));
    for (issuer, account) in [
        ("", "a"),
        ("a", ""),
        ("a:b", "c"),
        ("a", "b:c"),
        ("a\n", "b"),
    ] {
        assert!(matches!(
            s.provisioning_uri(issuer, account),
            Err(TotpError::Label(_))
        ));
    }
    assert!(s.provisioning_uri(&"a".repeat(65), "b").is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// The current code always verifies, once.
    #[test]
    fn current_code_verifies_once(
        seed in proptest::collection::vec(any::<u8>(), 20),
        now in 60u64..40_000_000_000,
    ) {
        let s = secret(TotpAlgorithm::Sha1, &seed);
        let typed = s.code(step_at(now));
        let step = s.verify(&typed, now, 0).unwrap();
        prop_assert_eq!(step, step_at(now));
        prop_assert_eq!(s.verify(&typed, now, step), Err(TotpError::Replayed));
    }

    /// A code computed with another secret never verifies as the current step.
    #[test]
    fn another_secret_does_not_verify(
        a in proptest::collection::vec(any::<u8>(), 32),
        b in proptest::collection::vec(any::<u8>(), 32),
        now in 60u64..40_000_000_000,
    ) {
        prop_assume!(a != b);
        let sa = secret(TotpAlgorithm::Sha256, &a);
        let sb = secret(TotpAlgorithm::Sha256, &b);
        let typed = sb.code(step_at(now));
        // Only a chance collision (about 3 in 10^6) is accepted, and then
        // for a step whose code really is the typed one.
        if let Ok(step) = sa.verify(&typed, now, 0) {
            prop_assert_eq!(shown(&sa.code(step)), shown(&typed));
        }
    }

    /// Codes are always six ASCII digits.
    #[test]
    fn codes_are_six_digits(seed in proptest::collection::vec(any::<u8>(), 20), step in any::<u64>()) {
        let c = shown(&secret(TotpAlgorithm::Sha1, &seed).code(step));
        prop_assert_eq!(c.len(), 6);
        prop_assert!(c.bytes().all(|b| b.is_ascii_digit()));
    }
}
