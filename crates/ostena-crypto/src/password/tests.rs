use proptest::prelude::*;

use super::*;

fn pw(text: &str) -> SecretString {
    SecretString::from(text.to_owned())
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// RFC 7914 § 11 (PBKDF2-HMAC-SHA256): RFC 6070 only covers SHA-1.
#[test]
fn rfc7914_vectors() {
    for (password, salt, count, expected) in [
        (
            "passwd",
            "salt",
            1,
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc\
             49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
        ),
        (
            "Password",
            "NaCl",
            80_000,
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56\
             a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d",
        ),
    ] {
        let mut out = [0u8; 64];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(count).unwrap(),
            salt.as_bytes(),
            password.as_bytes(),
            &mut out,
        );
        assert_eq!(out.as_slice(), hex(expected).as_slice());
        // Our 32-byte derivation is the prefix of the same output.
        let ours = derive(
            &pw(password),
            salt.as_bytes(),
            NonZeroU32::new(count).unwrap(),
        );
        assert_eq!(ours.as_slice(), &out[..32]);
    }
}

/// Digests computed independently, at the production parameters and above.
#[test]
fn stored_vectors_verify() {
    let at_600k = "$ostena-pbkdf2-sha256$v=1$i=600000$AAECAwQFBgcICQoLDA0ODw$\
                   7xdxRO7JQgy8EJPSqLNEqSvFBtDU7JwCjdGfgyTYweY";
    let stored = PasswordHash::parse(at_600k).unwrap();
    assert!(!stored.needs_rehash());
    verify(&pw("correct horse battery staple"), &stored).unwrap();
    assert_eq!(
        verify(&pw("correct horse battery stapl"), &stored),
        Err(PasswordError::Mismatch)
    );
    assert_eq!(stored.encode(), at_600k);

    let at_700k = "$ostena-pbkdf2-sha256$v=1$i=700000$AAECAwQFBgcICQoLDA0ODw$\
                   GtnGYnuo9MblzuYCTxPD6LBvHX72XidrTr27BN0yjT0";
    let stored = PasswordHash::parse(at_700k).unwrap();
    assert!(stored.needs_rehash());
    assert_eq!(stored.iterations(), 700_000);
    verify(&pw("mot de passe é"), &stored).unwrap();
}

#[test]
fn hash_then_verify() {
    let stored = hash(&pw("s3cret-Passw0rd")).unwrap();
    assert_eq!(stored.iterations(), ITERATIONS);
    assert!(!stored.needs_rehash());
    verify(&pw("s3cret-Passw0rd"), &stored).unwrap();
    assert_eq!(
        verify(&pw("s3cret-passw0rd"), &stored),
        Err(PasswordError::Mismatch)
    );
    let reparsed = PasswordHash::parse(&stored.encode()).unwrap();
    assert_eq!(reparsed, stored);
    // A fresh salt every time.
    assert_ne!(hash(&pw("s3cret-Passw0rd")).unwrap(), stored);
}

#[test]
fn length_bounds() {
    assert_eq!(hash(&pw("")).err(), Some(PasswordError::Length));
    assert_eq!(
        hash(&pw(&"a".repeat(MAX_PASSWORD_LEN + 1))).err(),
        Some(PasswordError::Length)
    );
    let stored = hash(&pw(&"a".repeat(MAX_PASSWORD_LEN))).unwrap();
    assert_eq!(verify(&pw(""), &stored), Err(PasswordError::Length));
}

#[test]
fn debug_hides_salt_and_digest() {
    let stored = hash(&pw("x")).unwrap();
    let shown = format!("{stored:?}");
    assert_eq!(shown, "PasswordHash { iterations: 600000, .. }");
}

#[test]
fn non_canonical_encodings_are_refused() {
    let good = "$ostena-pbkdf2-sha256$v=1$i=600000$AAECAwQFBgcICQoLDA0ODw$\
                7xdxRO7JQgy8EJPSqLNEqSvFBtDU7JwCjdGfgyTYweY";
    assert!(PasswordHash::parse(good).is_ok());
    for bad in [
        "",
        "$ostena-pbkdf2-sha256$v=2$i=600000$AAECAwQFBgcICQoLDA0ODw$7xdxRO7JQgy8EJPSqLNEqSvFBtDU7JwCjdGfgyTYweY",
        "$ostena-pbkdf2-sha256$v=1$i=0600000$AAECAwQFBgcICQoLDA0ODw$7xdxRO7JQgy8EJPSqLNEqSvFBtDU7JwCjdGfgyTYweY",
        "$ostena-pbkdf2-sha256$v=1$i=+600000$AAECAwQFBgcICQoLDA0ODw$7xdxRO7JQgy8EJPSqLNEqSvFBtDU7JwCjdGfgyTYweY",
        "$ostena-pbkdf2-sha256$v=1$i=599999$AAECAwQFBgcICQoLDA0ODw$7xdxRO7JQgy8EJPSqLNEqSvFBtDU7JwCjdGfgyTYweY",
        "$ostena-pbkdf2-sha256$v=1$i=10000001$AAECAwQFBgcICQoLDA0ODw$7xdxRO7JQgy8EJPSqLNEqSvFBtDU7JwCjdGfgyTYweY",
        "$ostena-pbkdf2-sha256$v=1$i=600000$AAECAwQFBgcICQoLDA0ODw==$7xdxRO7JQgy8EJPSqLNEqSvFBtDU7JwCjdGfgyTYweY",
        // Trailing bits set in the last salt character.
        "$ostena-pbkdf2-sha256$v=1$i=600000$AAECAwQFBgcICQoLDA0ODx$7xdxRO7JQgy8EJPSqLNEqSvFBtDU7JwCjdGfgyTYweY",
        "$ostena-pbkdf2-sha256$v=1$i=600000$AAECAwQFBgcICQoLDA0O$7xdxRO7JQgy8EJPSqLNEqSvFBtDU7JwCjdGfgyTYweY",
        "$ostena-pbkdf2-sha256$v=1$i=600000$AAECAwQFBgcICQoLDA0ODw$7xdxRO7JQgy8EJPSqLNEqSvFBtDU7JwCjdGfgyTYweY$",
        "$ostena-pbkdf2-sha256$v=1$i=600000$AAECAwQFBgcICQoLDA0ODw",
        " $ostena-pbkdf2-sha256$v=1$i=600000$AAECAwQFBgcICQoLDA0ODw$7xdxRO7JQgy8EJPSqLNEqSvFBtDU7JwCjdGfgyTYweY",
    ] {
        assert_eq!(
            PasswordHash::parse(bad),
            Err(PasswordError::Format),
            "{bad}"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Whatever the text, parsing either fails or gives back the same text.
    #[test]
    fn parse_is_canonical(text in "\\$ostena-pbkdf2-sha256\\$v=1\\$i=[0-9]{6,8}\\$[A-Za-z0-9+/]{20,24}\\$[A-Za-z0-9+/]{42,44}") {
        if let Ok(parsed) = PasswordHash::parse(&text) {
            prop_assert_eq!(parsed.encode(), text);
        }
    }

    /// Encoding then parsing any parameters gives them back.
    #[test]
    fn encode_round_trips(
        iterations in ACCEPTED_ITERATIONS,
        salt in any::<[u8; SALT_LEN]>(),
        digest in any::<[u8; DIGEST_LEN]>(),
    ) {
        let stored = PasswordHash { iterations, salt, digest };
        prop_assert_eq!(PasswordHash::parse(&stored.encode()).unwrap(), stored);
    }
}

proptest! {
    // Each case runs PBKDF2 at 600 000 iterations three times.
    #![proptest_config(ProptestConfig::with_cases(6))]

    #[test]
    fn any_password_verifies_and_another_does_not(
        password in "\\PC{1,64}",
        other in "\\PC{1,64}",
    ) {
        let stored = hash(&pw(&password)).unwrap();
        prop_assert!(verify(&pw(&password), &stored).is_ok());
        if other != password {
            prop_assert_eq!(verify(&pw(&other), &stored), Err(PasswordError::Mismatch));
        }
    }
}
