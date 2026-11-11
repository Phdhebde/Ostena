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

#[test]
fn agent_certificate_carries_the_group_and_the_agent() {
    let ca = CertificateAuthority::generate("CA", validity()).unwrap();
    let key = p256::SigningKey::generate().unwrap().0;
    let group = "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6";
    let cert = ca
        .issue_agent(&key.verifying_key(), group, "agent-7", validity())
        .unwrap();
    assert!(contains(
        &cert,
        format!("urn:ostena:gateway-group:{group}").as_bytes()
    ));
    assert!(contains(&cert, b"urn:ostena:agent:agent-7"));
    // The certificate is issued for the agent's own public key.
    assert!(contains(&cert, &key.verifying_key().to_bytes()));
}

#[test]
fn serial_numbers_and_fingerprints_differ() {
    let ca = CertificateAuthority::generate("CA", validity()).unwrap();
    let key = p256::SigningKey::generate().unwrap().0.verifying_key();
    let a = ca.issue_agent(&key, "g", "a", validity()).unwrap();
    let b = ca.issue_agent(&key, "g", "a", validity()).unwrap();
    assert_ne!(crate::tls::fingerprint(&a), crate::tls::fingerprint(&b));
}

#[test]
fn inverted_or_out_of_range_validity_is_refused() {
    let inverted = Validity {
        not_before: 2,
        not_after: 1,
    };
    assert!(matches!(
        CertificateAuthority::generate("CA", inverted),
        Err(PkiError::Validity)
    ));
    let huge = Validity {
        not_before: 0,
        not_after: u64::MAX,
    };
    assert!(matches!(
        CertificateAuthority::generate("CA", huge),
        Err(PkiError::Validity)
    ));
}

#[test]
fn invalid_server_name_is_refused() {
    let ca = CertificateAuthority::generate("CA", validity()).unwrap();
    assert!(matches!(
        ca.issue_server(&["not a name"], validity()),
        Err(PkiError::Name(_))
    ));
}

#[test]
fn reloaded_ca_issues_certificates_under_the_same_identity() {
    let ca = CertificateAuthority::generate("Ostena core CA", validity()).unwrap();
    let reloaded = CertificateAuthority::from_parts(
        "Ostena core CA",
        &ca.key_pkcs8(),
        ca.trust_anchor().certificate().clone(),
    )
    .unwrap();
    assert_eq!(
        reloaded.trust_anchor().certificate(),
        ca.trust_anchor().certificate()
    );
    // A non-P-256 key is refused.
    let p384 = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    assert!(
        CertificateAuthority::from_parts(
            "CA",
            &SecretBytes::from(p384.serialize_der()),
            ca.trust_anchor().certificate().clone()
        )
        .is_err()
    );
}

#[test]
fn pem_wraps_at_64_columns() {
    let ca = CertificateAuthority::generate("CA", validity()).unwrap();
    let pem = ca.certificate_pem();
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
    assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
    assert!(pem.lines().all(|l| l.len() <= 64));
}
