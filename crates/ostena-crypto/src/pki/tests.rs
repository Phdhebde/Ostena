use super::testing::TestPki;
use super::*;

fn validity() -> Validity {
    Validity {
        not_before: 1_800_000_000,
        not_after: 1_800_000_000 + 30 * 86_400,
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn key() -> p256::VerifyingKey {
    p256::SigningKey::generate().unwrap().0.verifying_key()
}

const GROUP: &str = "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6";

#[test]
fn agent_certificate_carries_the_group_and_the_agent() {
    let pki = TestPki::new("t").unwrap();
    let agent_key = key();
    let cert = pki
        .issuing
        .issue_agent(&agent_key, GROUP, "agent-7", validity())
        .unwrap();
    assert!(contains(
        &cert,
        format!("urn:ostena:gateway-group:{GROUP}").as_bytes()
    ));
    assert!(contains(&cert, b"urn:ostena:agent:agent-7"));
    // Issued for the agent's own public key.
    assert!(contains(&cert, &agent_key.to_bytes()));
}

#[test]
fn agent_identifiers_are_restricted() {
    let pki = TestPki::new("t").unwrap();
    for (group, agent) in [
        ("", "a"),
        ("G", "a"),
        ("g", "a b"),
        ("g", "a/../b"),
        (&*"g".repeat(65), "a"),
    ] {
        assert!(matches!(
            pki.issuing.issue_agent(&key(), group, agent, validity()),
            Err(PkiError::Name(_))
        ));
    }
}

#[test]
fn issuing_ca_is_restricted_to_agent_certificates() {
    let pki = TestPki::new("t").unwrap();
    let cert = &pki.issuing_certificate;
    // id-kp-clientAuth (1.3.6.1.5.5.7.3.2), and not id-kp-serverAuth (.3.1).
    let client_auth = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
    let server_auth = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
    assert!(contains(cert, &client_auth));
    assert!(!contains(cert, &server_auth));
    // Name constraints extension (2.5.29.30) present.
    assert!(contains(cert, &[0x06, 0x03, 0x55, 0x1d, 0x1e]));
    // Basic constraints with pathLen 0: CA true, INTEGER 0.
    assert!(contains(cert, &[0x01, 0x01, 0xff, 0x02, 0x01, 0x00]));
}

#[test]
fn server_certificate_is_server_auth_only() {
    let pki = TestPki::new("t").unwrap();
    let id = pki.server(&["core.example.test"]).unwrap();
    let cert = id.certificate();
    assert!(contains(cert, b"core.example.test"));
    assert!(contains(
        cert,
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01]
    ));
    assert!(!contains(
        cert,
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02]
    ));
}

#[test]
fn serial_numbers_and_fingerprints_differ() {
    let pki = TestPki::new("t").unwrap();
    let k = key();
    let a = pki.issuing.issue_agent(&k, "g", "a", validity()).unwrap();
    let b = pki.issuing.issue_agent(&k, "g", "a", validity()).unwrap();
    assert_ne!(crate::tls::fingerprint(&a), crate::tls::fingerprint(&b));
}

#[test]
fn inverted_or_out_of_range_validity_is_refused() {
    let inverted = Validity {
        not_before: 2,
        not_after: 1,
    };
    assert!(matches!(
        RootAuthority::generate("CA", inverted),
        Err(PkiError::Validity)
    ));
    let huge = Validity {
        not_before: 0,
        not_after: u64::MAX,
    };
    assert!(matches!(
        RootAuthority::generate("CA", huge),
        Err(PkiError::Validity)
    ));
}

#[test]
fn invalid_server_names_are_refused() {
    let pki = TestPki::new("t").unwrap();
    for names in [&["not a name"][..], &[][..]] {
        assert!(matches!(
            pki.root.sign_server(&key(), names, validity()),
            Err(PkiError::Name(_))
        ));
    }
}

#[test]
fn reloaded_root_keeps_its_identity_and_refuses_other_keys() {
    let pki = TestPki::new("t").unwrap();
    let reloaded = RootAuthority::from_parts(
        "t root",
        &pki.root.key_pkcs8(),
        pki.root_anchor().certificate().clone(),
    )
    .unwrap();
    assert_eq!(
        reloaded.trust_anchor().certificate(),
        pki.root_anchor().certificate()
    );
    let p384 = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    assert!(
        RootAuthority::from_parts(
            "t root",
            &SecretBytes::from(p384.serialize_der()),
            pki.root_anchor().certificate().clone()
        )
        .is_err()
    );
}

#[test]
fn pem_wraps_at_64_columns() {
    let pki = TestPki::new("t").unwrap();
    let pem = pki.root.certificate_pem();
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
    assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
    assert!(pem.lines().all(|l| l.len() <= 64));
}

#[test]
fn public_key_file_round_trip_and_refusals() {
    use base64::Engine;
    let k = key();
    let text = encode_public_key(&k);
    assert!(text.starts_with("ostena-p256-public-key-v1\n"));
    assert_eq!(decode_public_key(&text).unwrap(), k);
    assert!(decode_public_key("hello\nAAAA\n").is_err());
    assert!(decode_public_key("ostena-p256-public-key-v1\nAAAA\n").is_err());
    let mut bytes = k.to_bytes();
    bytes[64] ^= 1;
    let off_curve = format!(
        "ostena-p256-public-key-v1\n{}\n",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    );
    assert_eq!(decode_public_key(&off_curve), Err(PkiError::Issuance));
}

#[test]
fn private_key_pem_is_read_back_by_identity() {
    let pki = TestPki::new("t").unwrap();
    let (key, pkcs8) = p256::SigningKey::generate().unwrap();
    let cert = pki
        .issuing
        .issue_agent(&key.verifying_key(), "g", "a", validity())
        .unwrap();
    let id =
        crate::tls::Identity::from_pem(pem_certificate(&cert).as_bytes(), &pem_private_key(&pkcs8))
            .unwrap();
    assert_eq!(id.certificate(), &cert);
}
