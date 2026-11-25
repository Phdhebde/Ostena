#![allow(clippy::unwrap_used, reason = "tests")]

use proptest::prelude::*;

use super::*;

/// A key whose scalar starts with a zero byte, written as OpenSSH writes it
/// (minimal mpint, 31 bytes: the second byte below 0x80 too): what
/// `ssh-keygen` produces about once in 512.
pub(crate) fn short_scalar_key() -> GeneratedKey {
    let mut scalar = ostena_crypto::rand::array::<32>().unwrap();
    scalar[0] = 0;
    scalar[1] = (scalar[1] & 0x7f) | 0x01;
    let key = SigningKey::from_scalar(&SecretBytes::from(scalar.to_vec())).unwrap();
    encode(&key, "short").unwrap()
}

#[test]
fn generated_scalars_take_32_bytes() {
    for _ in 0..300 {
        let key = generate("test").unwrap();
        // SECRET-EXPOSURE: test only.
        #[expect(clippy::disallowed_methods)]
        let len = scalar_len(key.private.expose_secret()).unwrap();
        assert!(len == 32 || len == 33, "{len}");
    }
}

#[test]
fn public_line_format() {
    let key = generate("ostena-agent").unwrap();
    assert!(
        key.public
            .starts_with("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY")
    );
    assert!(key.public.ends_with(" ostena-agent"));
}

#[test]
fn public_line_of_a_verifying_key_matches_the_generated_line() {
    let (signing, _) = SigningKey::generate().unwrap();
    let generated = encode(&signing, "ca").unwrap();
    let public = signing.verifying_key();
    assert_eq!(public_line(&public, "ca"), generated.public);
    assert_eq!(
        public_line(&public, ""),
        generated.public.trim_end_matches(" ca")
    );
    assert_eq!(parse_public_line(&generated.public), Some(public));
    assert_eq!(parse_public_line(&public_line(&public, "")), Some(public));
}

#[test]
fn foreign_public_lines_are_refused() {
    let (signing, _) = SigningKey::generate().unwrap();
    let line = public_line(&signing.verifying_key(), "x");
    let blob = line.split(' ').nth(1).unwrap();
    for bad in [
        String::new(),
        "ecdsa-sha2-nistp256".to_owned(),
        line.replacen("ecdsa-sha2-nistp256", "ssh-ed25519", 1),
        format!("ecdsa-sha2-nistp256 {}A", &blob[..blob.len() - 1]),
        format!("ecdsa-sha2-nistp256 {blob}AAAA"),
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
            .to_owned(),
    ] {
        assert_eq!(parse_public_line(&bad), None, "{bad}");
    }
}

#[test]
fn short_scalar_is_detected() {
    let key = short_scalar_key();
    // SECRET-EXPOSURE: test only.
    #[expect(clippy::disallowed_methods)]
    let len = scalar_len(key.private.expose_secret());
    assert_eq!(len, Some(31));
}

/// UPSTREAM DEFECT (ssh-key 0.7.0-rc.11, ADR-0010): a valid P-256 key whose
/// scalar is encoded on 31 bytes is refused. When this test fails, ssh-key
/// accepts such keys: remove this test, the redraw in `generate` and the
/// `SSH-E007` diagnosis, and the key regeneration in the test helpers.
#[cfg(feature = "russh")]
#[test]
fn upstream_defect_short_scalar_is_refused_by_ssh_key() {
    let key = short_scalar_key();
    // SECRET-EXPOSURE: test only.
    #[expect(clippy::disallowed_methods)]
    let parsed = russh::keys::PrivateKey::from_openssh(key.private.expose_secret());
    assert!(
        parsed.is_err(),
        "ssh-key now accepts 31-byte scalars: see the comment"
    );
    assert_eq!(load(&key.private).unwrap_err(), KeyError::ShortScalar(31));
    assert!(
        load(&key.private)
            .unwrap_err()
            .to_string()
            .contains("31 octets")
    );
}

#[cfg(feature = "russh")]
#[test]
fn other_algorithms_and_garbage_are_refused() {
    let garbage = SecretBytes::from(b"not a key".to_vec());
    assert_eq!(load(&garbage).unwrap_err().code(), "SSH-E008");
}

#[test]
fn scalar_len_rejects_what_is_not_an_unencrypted_p256_key() {
    assert_eq!(scalar_len(b""), None);
    assert_eq!(
        scalar_len(b"-----BEGIN OPENSSH PRIVATE KEY-----\n!!\n-----END OPENSSH PRIVATE KEY-----"),
        None
    );
    assert_eq!(scalar_len(&vec![b'a'; MAX_KEY_FILE + 1]), None);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Every key we generate is read back by ssh-key, as ECDSA P-256, with
    /// the same public key.
    #[cfg(feature = "russh")]
    #[test]
    fn prop_generated_keys_are_read_by_ssh_key(_case in 0u8..=255) {
        let key = generate("prop").unwrap();
        let loaded = load(&key.private).unwrap();
        let public = loaded.public_key().to_openssh().unwrap();
        prop_assert_eq!(public.split(' ').nth(1), key.public.split(' ').nth(1));
    }

    /// The diagnosis parser never panics.
    #[test]
    fn prop_scalar_len_never_panics(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = scalar_len(&data);
        let mut file = BEGIN.as_bytes().to_vec();
        file.push(b'\n');
        file.extend(STANDARD.encode(&data).into_bytes());
        file.push(b'\n');
        file.extend_from_slice(END.as_bytes());
        let _ = scalar_len(&file);
        let _ = decode(&SecretBytes::from(file));
    }
}

#[test]
fn decode_gives_back_the_generated_key_and_its_comment() {
    let key = generate("ostena-agent-gw01").unwrap();
    let (signing, comment) = decode(&key.private).unwrap();
    assert_eq!(comment, "ostena-agent-gw01");
    assert_eq!(encode(&signing, &comment).unwrap().public, key.public);
    // A 31-byte scalar, refused by ssh-key, is still read here.
    let short = short_scalar_key();
    let (signing, _) = decode(&short.private).unwrap();
    assert_eq!(encode(&signing, "short").unwrap().public, short.public);
}

/// `file` with the public point of its private section replaced by `to`.
fn with_public(file: &SecretBytes, from: &[u8; 65], to: &[u8; 65]) -> SecretBytes {
    // SECRET-EXPOSURE: test only.
    #[expect(clippy::disallowed_methods)]
    let text = std::str::from_utf8(file.expose_secret())
        .unwrap()
        .to_owned();
    let inner: String = text
        .trim()
        .strip_prefix(BEGIN)
        .unwrap()
        .strip_suffix(END)
        .unwrap()
        .split_whitespace()
        .collect();
    let mut body = STANDARD.decode(inner).unwrap();
    let at = body.windows(65).rposition(|w| w == from).unwrap();
    body[at..at + 65].copy_from_slice(to);
    SecretBytes::from(format!("{BEGIN}\n{}\n{END}\n", STANDARD.encode(body)).into_bytes())
}

#[test]
fn decode_refuses_garbage_and_an_inconsistent_file() {
    for bad in [&b""[..], b"not a key", &vec![b'a'; MAX_KEY_FILE + 1]] {
        assert_eq!(
            decode(&SecretBytes::from(bad.to_vec()))
                .err()
                .unwrap()
                .code(),
            "SSH-E008"
        );
    }
    let (a, _) = decode(&generate("a").unwrap().private).unwrap();
    let (b, _) = decode(&generate("b").unwrap().private).unwrap();
    let file = encode(&a, "a").unwrap().private;
    let forged = with_public(
        &file,
        &a.verifying_key().to_bytes(),
        &b.verifying_key().to_bytes(),
    );
    assert!(
        decode(&forged)
            .err()
            .unwrap()
            .to_string()
            .contains("ne correspond pas")
    );
}
