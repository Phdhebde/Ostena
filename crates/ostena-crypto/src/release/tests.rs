use std::fmt::Write as _;

use proptest::prelude::*;

use super::*;

fn entry(name: &str, byte: u8) -> Entry {
    Entry::new(name, [byte; 32]).unwrap()
}

fn sample() -> Manifest {
    Manifest::new(vec![
        entry("ostena.exe", 2),
        entry("ostena", 1),
        entry("ostena-cli.cdx.json", 3),
    ])
    .unwrap()
}

fn new_key() -> SigningKey {
    SigningKey::generate().unwrap().0
}

#[test]
fn manifest_is_sorted_and_round_trips() {
    let manifest = sample();
    let names: Vec<&str> = manifest.entries().iter().map(Entry::name).collect();
    assert_eq!(names, ["ostena", "ostena-cli.cdx.json", "ostena.exe"]);
    let text = manifest.encode();
    assert!(text.starts_with("ostena-release-manifest-v1\n0101"));
    assert!(text.ends_with("  ostena.exe\n"));
    assert_eq!(Manifest::decode(text.as_bytes()), Ok(manifest));
}

#[test]
fn manifest_lines_are_those_of_sha256sum() {
    let digest = crate::sha256::digest(b"abc");
    let manifest = Manifest::new(vec![Entry::new("abc.txt", digest).unwrap()]).unwrap();
    assert_eq!(
        manifest.encode(),
        "ostena-release-manifest-v1\n\
         ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  abc.txt\n"
    );
}

#[test]
fn names_are_restricted() {
    for good in [
        "a",
        "ostena",
        "ostena.exe",
        "x_1+2-3.cdx.json",
        &"a".repeat(128),
    ] {
        assert!(check_name(good).is_ok(), "{good}");
    }
    for bad in [
        "",
        ".hidden",
        "-flag",
        "_x",
        "dir/file",
        "dir\\file",
        "..",
        "a b",
        "é",
        "a\nb",
        "a*",
        &"a".repeat(129),
    ] {
        assert!(
            matches!(check_name(bad), Err(ReleaseError::MalformedManifest(_))),
            "{bad:?}"
        );
    }
}

#[test]
fn manifest_needs_one_to_256_unique_entries() {
    assert!(Manifest::new(Vec::new()).is_err());
    assert!(Manifest::new(vec![entry("a", 1), entry("a", 2)]).is_err());
    let many: Vec<Entry> = (0..=MAX_ENTRIES)
        .map(|i| entry(&format!("f{i}"), 0))
        .collect();
    assert!(Manifest::new(many[..MAX_ENTRIES].to_vec()).is_ok());
    assert!(Manifest::new(many).is_err());
}

#[test]
fn decoder_refuses_every_non_canonical_form() {
    let good = sample().encode();
    let line = format!("{}  b\n", "00".repeat(32));
    let cases: Vec<(String, &str)> = vec![
        (good.trim_end().to_owned(), "no final newline"),
        (good.replace("v1\n", "v2\n"), "other version"),
        (good.replace('\n', "\r\n"), "CR LF"),
        (format!("{good}\n"), "empty line at the end"),
        (good.replacen("  ", " ", 1), "one space"),
        (good.replacen("  ", " *", 1), "binary marker"),
        (good.replacen("0101", "0A01", 1), "uppercase hex"),
        (good.replacen("0101", "0g01", 1), "not hex"),
        (
            good.replacen("  ostena\n", "  ostena \n", 1),
            "trailing space",
        ),
        ("ostena-release-manifest-v1\n".to_owned(), "no entry"),
        (
            format!("ostena-release-manifest-v1\n{line}{line}"),
            "duplicate",
        ),
        (
            format!(
                "ostena-release-manifest-v1\n{}  b\n{}  a\n",
                "00".repeat(32),
                "00".repeat(32)
            ),
            "unsorted",
        ),
        (format!("\u{feff}{good}"), "byte order mark"),
        (format!("{}  a\n", "00".repeat(32)), "no header"),
    ];
    for (text, why) in cases {
        assert!(
            matches!(
                Manifest::decode(text.as_bytes()),
                Err(ReleaseError::MalformedManifest(_))
            ),
            "{why}"
        );
    }
    assert!(Manifest::decode(&[0xff, b'\n']).is_err());
}

#[test]
fn decoder_bounds_the_entries_and_the_size() {
    let mut text = format!("{MANIFEST_HEADER}\n");
    for i in 0..=MAX_ENTRIES {
        let _ = writeln!(text, "{}  f{i:04}", "00".repeat(32));
    }
    assert!(Manifest::decode(text.as_bytes()).is_err());
    assert!(Manifest::decode(&vec![b'a'; MAX_MANIFEST_LEN + 1]).is_err());
    // The largest manifest fits the bound.
    let largest: Vec<Entry> = (0..MAX_ENTRIES)
        .map(|i| entry(&format!("{i:03}{}", "a".repeat(MAX_NAME_LEN - 3)), 0xff))
        .collect();
    let text = Manifest::new(largest).unwrap().encode();
    assert_eq!(text.len(), MAX_MANIFEST_LEN);
    assert!(Manifest::decode(text.as_bytes()).is_ok());
}

#[test]
fn signature_verifies_and_names_its_key() {
    let key = new_key();
    let manifest = sample();
    let signature = sign(&manifest, &key).unwrap();
    let text = signature.to_text();
    assert!(text.starts_with(SIGNATURE_PREFIX));
    assert!(text.len() <= MAX_SIGNATURE_LEN);
    assert_eq!(text.len(), MAX_SIGNATURE_LEN);
    assert_eq!(signature.kid(), kid(&key.verifying_key()));
    let other = new_key().verifying_key();
    let verified = verify(
        manifest.encode().as_bytes(),
        &text,
        &[other, key.verifying_key()],
    )
    .unwrap();
    assert_eq!(verified, manifest);
}

#[test]
fn kid_matches_the_grant_and_audit_definition() {
    let key = new_key().verifying_key();
    let digest = crate::sha256::digest(&key.to_bytes());
    assert_eq!(kid(&key), digest[..8]);
    assert_eq!(hex(&kid(&key)).len(), 16);
}

#[test]
fn a_modified_manifest_or_signature_is_refused() {
    let key = new_key();
    let manifest = sample().encode();
    let signature = sign(&sample(), &key).unwrap().to_text();
    let trusted = [key.verifying_key()];

    // One digest changed: still canonical, the signature fails.
    let changed = manifest.replacen("0101", "0102", 1);
    assert_eq!(
        verify(changed.as_bytes(), &signature, &trusted),
        Err(ReleaseError::BadSignature)
    );
    // One entry removed.
    let mut lines: Vec<&str> = manifest.lines().collect();
    lines.remove(1);
    let shorter = format!("{}\n", lines.join("\n"));
    assert_eq!(
        verify(shorter.as_bytes(), &signature, &trusted),
        Err(ReleaseError::BadSignature)
    );
    // The signature bytes changed.
    let mut raw = signature.clone().into_bytes();
    let at = SIGNATURE_PREFIX.len() + 17 + 10;
    raw[at] = if raw[at] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(raw).unwrap();
    assert_eq!(
        verify(manifest.as_bytes(), &tampered, &trusted),
        Err(ReleaseError::BadSignature)
    );
    // Another key.
    let stranger = new_key().verifying_key();
    assert!(matches!(
        verify(manifest.as_bytes(), &signature, &[stranger]),
        Err(ReleaseError::UnknownKey(_))
    ));
    // The kid of the trusted key, the signature of another.
    let impostor = new_key();
    let forged = sign(&sample(), &impostor).unwrap().to_text().replacen(
        &hex(&kid(&impostor.verifying_key())),
        &hex(&kid(&key.verifying_key())),
        1,
    );
    assert_eq!(
        verify(manifest.as_bytes(), &forged, &trusted),
        Err(ReleaseError::BadSignature)
    );
}

#[test]
fn the_domain_is_part_of_the_signed_message() {
    let key = new_key();
    let manifest = sample().encode();
    // A plain signature of the manifest, without the domain, is refused.
    let plain = key.sign(manifest.as_bytes()).unwrap();
    let text = format!(
        "{SIGNATURE_PREFIX}{}:{}\n",
        hex(&kid(&key.verifying_key())),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(plain.to_bytes())
    );
    assert_eq!(
        verify(manifest.as_bytes(), &text, &[key.verifying_key()]),
        Err(ReleaseError::BadSignature)
    );
}

#[test]
fn signature_text_is_strict() {
    let good = sign(&sample(), &new_key()).unwrap().to_text();
    let body = good.strip_suffix('\n').unwrap();
    let cases = [
        body.to_owned(),
        format!("{good}\n"),
        format!("{body}\r\n"),
        good.replacen("v1:", "v2:", 1),
        good.replacen(':', "::", 1),
        format!("{body}=\n"),
        good.to_uppercase(),
        format!(" {good}"),
        String::new(),
    ];
    for text in cases {
        assert!(
            matches!(
                ReleaseSignature::from_text(&text),
                Err(ReleaseError::MalformedSignature(_))
            ),
            "{text:?}"
        );
    }
    // Non-zero trailing bits in the last base64url character.
    let mut raw = good.clone().into_bytes();
    let last = raw.len() - 2;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&body[SIGNATURE_PREFIX.len() + 17..])
        .unwrap();
    assert_eq!(decoded.len(), 64);
    // 64 bytes give 86 characters: the last one carries 2 bits only, its
    // 4 low bits must be zero.
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let index = alphabet.iter().position(|c| *c == raw[last]).unwrap();
    raw[last] = alphabet[index | 1];
    let text = String::from_utf8(raw).unwrap();
    assert!(ReleaseSignature::from_text(&text).is_err());
}

#[test]
fn verify_needs_one_to_16_trusted_keys() {
    let key = new_key();
    let manifest = sample().encode();
    let signature = sign(&sample(), &key).unwrap().to_text();
    assert_eq!(
        verify(manifest.as_bytes(), &signature, &[]),
        Err(ReleaseError::TrustedKeys)
    );
    let many = vec![key.verifying_key(); MAX_TRUSTED_KEYS + 1];
    assert_eq!(
        verify(manifest.as_bytes(), &signature, &many),
        Err(ReleaseError::TrustedKeys)
    );
}

#[test]
fn error_codes_are_stable() {
    assert_eq!(ReleaseError::MalformedManifest("x").code(), "REL-E001");
    assert_eq!(ReleaseError::MalformedSignature("x").code(), "REL-E002");
    assert_eq!(ReleaseError::UnknownKey(String::new()).code(), "REL-E003");
    assert_eq!(ReleaseError::BadSignature.code(), "REL-E004");
    assert_eq!(
        ReleaseError::Signing(CryptoError::Signing).code(),
        "REL-E007"
    );
    assert_eq!(ReleaseError::TrustedKeys.code(), "REL-E009");
    for e in [ReleaseError::BadSignature, ReleaseError::TrustedKeys] {
        assert!(e.to_string().starts_with(&format!("[{}]", e.code())));
    }
}

#[test]
fn digest_reader_matches_the_one_shot_digest() {
    let data: Vec<u8> = (0..200_000u32)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    assert_eq!(
        digest_reader(data.as_slice()).unwrap(),
        crate::sha256::digest(&data)
    );
    assert_eq!(digest_reader(&b""[..]).unwrap(), crate::sha256::digest(b""));
}

#[test]
fn fuzz_entry_accepts_seeds() {
    fuzz::decode(sample().encode().as_bytes());
    fuzz::decode(b"");
    fuzz::decode(b"\0");
}

fn name_strategy() -> impl Strategy<Value = String> {
    "[A-Za-z0-9][A-Za-z0-9._+-]{0,40}"
}

proptest! {
    #[test]
    fn any_manifest_round_trips(
        names in proptest::collection::btree_set(name_strategy(), 1..20),
        seed in any::<u8>(),
    ) {
        let entries: Vec<Entry> = names
            .iter()
            .enumerate()
            .map(|(i, n)| Entry::new(n, [seed.wrapping_add(u8::try_from(i).unwrap()); 32]).unwrap())
            .collect();
        let manifest = Manifest::new(entries).unwrap();
        let text = manifest.encode();
        prop_assert_eq!(Manifest::decode(text.as_bytes()), Ok(manifest));
    }

    #[test]
    fn decoder_never_panics_and_is_canonical(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        if let Ok(manifest) = Manifest::decode(&data) {
            prop_assert_eq!(manifest.encode().into_bytes(), data);
        }
    }

    #[test]
    fn one_changed_byte_breaks_the_signature(at in any::<prop::sample::Index>(), bit in 0u8..8) {
        // One key for all cases: generation dominates the run time.
        static KEY: std::sync::OnceLock<SigningKey> = std::sync::OnceLock::new();
        let key = KEY.get_or_init(new_key);
        let manifest = sample().encode().into_bytes();
        let signature = sign(&sample(), key).unwrap().to_text();
        let mut changed = manifest.clone();
        let i = at.index(changed.len());
        changed[i] ^= 1 << bit;
        prop_assert!(verify(&changed, &signature, &[key.verifying_key()]).is_err());
    }
}
