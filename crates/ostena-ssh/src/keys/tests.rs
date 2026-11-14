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
    }
}
