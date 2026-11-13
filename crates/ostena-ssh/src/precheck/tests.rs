#![allow(clippy::unwrap_used, reason = "tests")]

use proptest::prelude::*;

use super::*;

/// What OpenSSH 9.x sends as a client (abridged lists, real names).
const OPENSSH_CLIENT_KEX: &str = "sntrup761x25519-sha512,mlkem768x25519-sha256,curve25519-sha256,\
ecdh-sha2-nistp256,ecdh-sha2-nistp384,diffie-hellman-group14-sha256,ext-info-c,\
kex-strict-c-v00@openssh.com";

fn name_list(out: &mut Vec<u8>, names: &str) {
    out.extend_from_slice(&u32::try_from(names.len()).unwrap().to_be_bytes());
    out.extend_from_slice(names.as_bytes());
}

/// A KEXINIT payload with these lists (languages empty).
fn kexinit(kex: &str, host_key: &str, cipher: &str, compression: &str) -> Vec<u8> {
    let mut p = vec![MSG_KEXINIT];
    p.extend_from_slice(&[0x5a; 16]);
    for list in [
        kex,
        host_key,
        cipher,
        cipher,
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-256-etm@openssh.com",
        compression,
        compression,
        "",
        "",
    ] {
        name_list(&mut p, list);
    }
    p.push(0);
    p.extend_from_slice(&[0; 4]);
    p
}

/// An unencrypted packet around `payload`, padded to a multiple of 8.
fn packet_of(payload: &[u8]) -> Vec<u8> {
    let mut padding = 8 - (payload.len() + 5) % 8;
    if padding < 4 {
        padding += 8;
    }
    let length = payload.len() + padding + 1;
    let mut out = u32::try_from(length).unwrap().to_be_bytes().to_vec();
    out.push(u8::try_from(padding).unwrap());
    out.extend_from_slice(payload);
    out.extend(std::iter::repeat_n(0u8, padding));
    out
}

fn good_payload() -> Vec<u8> {
    kexinit(
        OPENSSH_CLIENT_KEX,
        "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512",
        "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-ctr",
        "none,zlib@openssh.com",
    )
}

fn client_bytes(payload: &[u8]) -> Vec<u8> {
    let mut out = b"SSH-2.0-OpenSSH_9.6\r\n".to_vec();
    out.extend(packet_of(payload));
    out
}

#[test]
fn openssh_client_offer_is_accepted() {
    let bytes = client_bytes(&good_payload());
    assert_eq!(
        inspect(&bytes, Role::Server),
        Ok(Progress::Accepted {
            consumed: bytes.len()
        })
    );
}

#[test]
fn every_prefix_needs_more() {
    let bytes = client_bytes(&good_payload());
    for end in 0..bytes.len() {
        assert_eq!(
            inspect(&bytes[..end], Role::Server),
            Ok(Progress::NeedMore),
            "{end}"
        );
    }
}

#[test]
fn bytes_after_the_packet_are_not_consumed() {
    let mut bytes = client_bytes(&good_payload());
    let expected = bytes.len();
    bytes.extend_from_slice(b"guessed kex packet");
    assert_eq!(
        inspect(&bytes, Role::Server),
        Ok(Progress::Accepted { consumed: expected })
    );
}

#[test]
fn without_strict_kex_is_refused() {
    let payload = kexinit(
        "curve25519-sha256,ecdh-sha2-nistp256,ext-info-c",
        "ecdsa-sha2-nistp256",
        "aes256-gcm@openssh.com",
        "none",
    );
    assert_eq!(
        inspect(&client_bytes(&payload), Role::Server),
        Err(PrecheckError::NoStrictKex("kex-strict-c-v00@openssh.com"))
    );
}

#[test]
fn the_marker_of_the_other_role_does_not_count() {
    // A client offering the server marker only.
    let payload = kexinit(
        "ecdh-sha2-nistp256,kex-strict-s-v00@openssh.com",
        "ecdsa-sha2-nistp256",
        "aes256-gcm@openssh.com",
        "none",
    );
    assert_eq!(
        inspect(&client_bytes(&payload), Role::Server)
            .unwrap_err()
            .code(),
        "SSH-E004"
    );
}

#[test]
fn only_unlisted_algorithms_are_refused_by_kind() {
    let strict = "kex-strict-c-v00@openssh.com";
    let cases = [
        (
            format!("curve25519-sha256,mlkem768x25519-sha256,{strict}"),
            "ecdsa-sha2-nistp256",
            "aes256-gcm@openssh.com",
            "l'échange de clés",
        ),
        (
            format!("ecdh-sha2-nistp256,{strict}"),
            "ssh-ed25519,rsa-sha2-512",
            "aes256-gcm@openssh.com",
            "la clé hôte",
        ),
        (
            format!("ecdh-sha2-nistp256,{strict}"),
            "ecdsa-sha2-nistp256",
            "chacha20-poly1305@openssh.com,aes256-ctr",
            "le chiffrement client vers serveur",
        ),
    ];
    for (kex, host, cipher, kind) in cases {
        let payload = kexinit(&kex, host, cipher, "none");
        match inspect(&client_bytes(&payload), Role::Server) {
            Err(PrecheckError::NoCommonAlgorithm { kind: k, .. }) => assert_eq!(k, kind),
            other => panic!("{kind}: {other:?}"),
        }
    }
    let payload = kexinit(
        &format!("ecdh-sha2-nistp256,{strict}"),
        "ecdsa-sha2-nistp256",
        "aes256-gcm@openssh.com",
        "zlib",
    );
    assert_eq!(
        inspect(&client_bytes(&payload), Role::Server)
            .unwrap_err()
            .code(),
        "SSH-E005"
    );
}

#[test]
fn a_target_server_may_send_preface_lines_a_client_may_not() {
    let payload = kexinit(
        "ecdh-sha2-nistp256,kex-strict-s-v00@openssh.com",
        "ecdsa-sha2-nistp256",
        "aes256-gcm@openssh.com",
        "none",
    );
    let mut bytes = b"Bienvenue\r\nSSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n".to_vec();
    bytes.extend(packet_of(&payload));
    assert!(matches!(
        inspect(&bytes, Role::Client),
        Ok(Progress::Accepted { .. })
    ));
    assert_eq!(
        inspect(&bytes, Role::Server).unwrap_err().code(),
        "SSH-E001"
    );
}

#[test]
fn identification_rules() {
    let refused = |bytes: &[u8]| inspect(bytes, Role::Server).unwrap_err().code();
    assert_eq!(refused(b"SSH-1.99-old\r\n"), "SSH-E001");
    assert_eq!(refused(b"SSH-2.0-\r\n"), "SSH-E001");
    assert_eq!(refused(b"SSH-2.0-x\n"), "SSH-E001", "LF alone");
    assert_eq!(refused(b"SSH-2.0-a\x01b\r\n"), "SSH-E001");
    let long = [b"SSH-2.0-".as_slice(), &[b'a'; 300]].concat();
    assert_eq!(refused(&long), "SSH-E001", "no CR LF within 255 bytes");
    let mut exact = b"SSH-2.0-".to_vec();
    exact.extend(std::iter::repeat_n(b'a', MAX_LINE - 10));
    exact.extend_from_slice(b"\r\n");
    assert_eq!(exact.len(), MAX_LINE);
    assert_eq!(inspect(&exact, Role::Server), Ok(Progress::NeedMore));
    let preface: Vec<u8> = std::iter::repeat_n(b"line\r\n".as_slice(), MAX_PREFACE_LINES)
        .flatten()
        .copied()
        .collect();
    assert_eq!(
        inspect(&preface, Role::Client).unwrap_err().code(),
        "SSH-E001"
    );
}

#[test]
fn packet_rules() {
    let refused = |packet: &[u8]| {
        let mut bytes = b"SSH-2.0-x\r\n".to_vec();
        bytes.extend_from_slice(packet);
        inspect(&bytes, Role::Server).unwrap_err().code()
    };
    let too_big = u32::try_from(MAX_PACKET + 4).unwrap().to_be_bytes();
    assert_eq!(refused(&[too_big.as_slice(), &[4]].concat()), "SSH-E002");
    assert_eq!(
        refused(&[0, 0, 0, 13, 4]),
        "SSH-E002",
        "not a multiple of 8"
    );
    assert_eq!(refused(&[0, 0, 0, 12, 3]), "SSH-E002", "padding below 4");
    assert_eq!(refused(&[0, 0, 0, 12, 11]), "SSH-E002", "no payload");
    // A packet that is not a KEXINIT.
    assert_eq!(refused(&packet_of(&[21, 0, 0, 0])), "SSH-E002");
    // Trailing bytes inside the KEXINIT payload.
    let mut payload = good_payload();
    payload.push(0);
    assert_eq!(refused(&packet_of(&payload)), "SSH-E002");
    // Name lists: empty name, comma at the end, space.
    for bad in ["a,,b", "a,", "a b"] {
        let payload = kexinit(bad, "ecdsa-sha2-nistp256", "aes256-gcm@openssh.com", "none");
        assert_eq!(refused(&packet_of(&payload)), "SSH-E002", "{bad}");
    }
}

#[test]
fn kexinit_lists_are_read_in_order() {
    let payload = good_payload();
    let k = parse_kexinit(&payload).unwrap();
    assert!(k.kex.contains(&"kex-strict-c-v00@openssh.com"));
    assert_eq!(
        k.host_key,
        vec!["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512"]
    );
    assert_eq!(k.compression_s2c, vec!["none", "zlib@openssh.com"]);
    assert!(!k.first_kex_follows);
}

proptest! {
    /// Never panics, whatever the bytes and the role.
    #[test]
    fn prop_never_panics(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let _ = inspect(&data, Role::Server);
        let _ = inspect(&data, Role::Client);
    }

    /// A valid offer cut anywhere is incomplete, never refused or accepted.
    #[test]
    fn prop_prefix_needs_more(cut in 0usize..400) {
        let bytes = client_bytes(&good_payload());
        let cut = cut.min(bytes.len() - 1);
        prop_assert_eq!(inspect(&bytes[..cut], Role::Server), Ok(Progress::NeedMore));
    }

    /// Accepted offers consume exactly the identification and the packet.
    #[test]
    fn prop_accepted_consumes_exactly(extra in proptest::collection::vec(any::<u8>(), 0..64)) {
        let base = client_bytes(&good_payload());
        let mut bytes = base.clone();
        bytes.extend_from_slice(&extra);
        prop_assert_eq!(
            inspect(&bytes, Role::Server),
            Ok(Progress::Accepted { consumed: base.len() })
        );
    }
}
