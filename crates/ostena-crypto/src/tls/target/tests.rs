use std::sync::Arc;

use proptest::prelude::*;
use rustls::{ClientConnection, ProtocolVersion, ServerConfig, ServerConnection};

use super::testing::{
    KeyKind, TargetCa, TargetIdentity, Usage, Versions, self_signed, server_config,
    weak_server_config,
};
use super::*;

/// Runs a handshake in memory; the negotiated version, or the client error.
fn handshake(
    client: Arc<ClientConfig>,
    server: Arc<ServerConfig>,
    name: &str,
) -> Result<ProtocolVersion, rustls::Error> {
    let name = ServerName::try_from(name.to_owned()).unwrap();
    let mut c = ClientConnection::new(client, name).unwrap();
    let mut s = ServerConnection::new(server).unwrap();
    for _ in 0..16 {
        let mut buf = Vec::new();
        while c.wants_write() {
            c.write_tls(&mut buf).unwrap();
        }
        if !buf.is_empty() {
            let mut slice = buf.as_slice();
            while !slice.is_empty() {
                s.read_tls(&mut slice).unwrap();
            }
            // The server's own errors reach the client as alerts.
            let _ = s.process_new_packets();
        }
        let mut buf = Vec::new();
        while s.wants_write() {
            s.write_tls(&mut buf).unwrap();
        }
        if !buf.is_empty() {
            let mut slice = buf.as_slice();
            while !slice.is_empty() {
                c.read_tls(&mut slice).unwrap();
            }
            c.process_new_packets()?;
        }
        if !c.is_handshaking() && !s.is_handshaking() {
            return Ok(c.protocol_version().unwrap());
        }
    }
    panic!("handshake did not finish");
}

fn pinned(identity: &TargetIdentity) -> (Arc<ClientConfig>, TargetCheck) {
    target_client_config(&TargetTrust::Pinned(identity.fingerprint())).unwrap()
}

#[test]
fn pinned_rsa_target_over_tls12_and_tls13() {
    let target = self_signed(KeyKind::Rsa2048, "srv01.example.test").unwrap();
    for (versions, expected) in [
        (Versions::Tls12, ProtocolVersion::TLSv1_2),
        (Versions::Tls13, ProtocolVersion::TLSv1_3),
        (Versions::Both, ProtocolVersion::TLSv1_3),
    ] {
        let (client, check) = pinned(&target);
        let server = server_config(&target, versions).unwrap();
        assert_eq!(handshake(client, server, "192.0.2.10"), Ok(expected));
        let seen = check.presented().unwrap();
        assert!(seen.verified);
        assert_eq!(seen.fingerprint, target.fingerprint());
        assert_eq!(
            check.verified_public_key().unwrap(),
            subject_public_key(target.certificate.as_ref()).unwrap()
        );
    }
}

#[test]
fn pinned_ecdsa_target() {
    let target = self_signed(KeyKind::EcdsaP256, "srv02").unwrap();
    let (client, check) = pinned(&target);
    let server = server_config(&target, Versions::Tls12).unwrap();
    assert_eq!(
        handshake(client, server, "srv02"),
        Ok(ProtocolVersion::TLSv1_2)
    );
    // An uncompressed P-256 point.
    assert_eq!(check.verified_public_key().unwrap().len(), 65);
}

/// REG-SEC-01: another certificate than the pinned one is refused, and the
/// presented fingerprint is reported for a re-pin after verification.
#[test]
fn another_certificate_than_the_pin_is_refused() {
    let pinned_one = self_signed(KeyKind::Rsa2048, "srv01").unwrap();
    let other = self_signed(KeyKind::Rsa2048, "srv01").unwrap();
    let (client, check) = pinned(&pinned_one);
    let server = server_config(&other, Versions::Both).unwrap();
    let error = handshake(client, server, "srv01").unwrap_err();
    assert!(is_pin_mismatch(&error), "{error:?}");
    let seen = check.presented().unwrap();
    assert!(!seen.verified);
    assert_eq!(seen.fingerprint, other.fingerprint());
    assert_eq!(check.verified_public_key(), None);
}

#[test]
fn pki_target_with_its_name_is_accepted() {
    let ca = TargetCa::new("customer ca").unwrap();
    let target = ca
        .issue(
            KeyKind::Rsa2048,
            &["srv03.example.test"],
            Some(Usage::ServerAuth),
        )
        .unwrap();
    let (client, check) = target_client_config(&TargetTrust::Pki(vec![ca.anchor()])).unwrap();
    let server = server_config(&target, Versions::Tls12).unwrap();
    assert_eq!(
        handshake(client, server, "srv03.example.test"),
        Ok(ProtocolVersion::TLSv1_2)
    );
    assert!(check.verified_public_key().is_some());
}

/// REG-SEC-01, PKI mode: another name, another CA or a certificate without
/// the server usage are refused before any credential.
#[test]
fn pki_refusals() {
    let ca = TargetCa::new("customer ca").unwrap();
    let rogue = TargetCa::new("rogue ca").unwrap();
    let pki = TargetTrust::Pki(vec![ca.anchor()]);
    let cases = [
        (
            ca.issue(
                KeyKind::EcdsaP256,
                &["other.example.test"],
                Some(Usage::ServerAuth),
            ),
            "srv03.example.test",
        ),
        (
            rogue.issue(
                KeyKind::EcdsaP256,
                &["srv03.example.test"],
                Some(Usage::ServerAuth),
            ),
            "srv03.example.test",
        ),
        (
            ca.issue(
                KeyKind::EcdsaP256,
                &["srv03.example.test"],
                Some(Usage::ClientAuth),
            ),
            "srv03.example.test",
        ),
        (
            self_signed(KeyKind::Rsa2048, "srv03.example.test"),
            "srv03.example.test",
        ),
    ];
    for (target, name) in cases {
        let target = target.unwrap();
        let (client, check) = target_client_config(&pki).unwrap();
        let server = server_config(&target, Versions::Both).unwrap();
        assert!(matches!(
            handshake(client, server, name),
            Err(rustls::Error::InvalidCertificate(_))
        ));
        assert_eq!(check.verified_public_key(), None);
    }
}

#[test]
fn keys_and_suites_outside_the_profile_are_refused() {
    // A P-384 certificate: its handshake signature is outside the profile.
    let target = self_signed(KeyKind::EcdsaP384, "srv04").unwrap();
    let (client, _) = pinned(&target);
    let server = server_config(&target, Versions::Both).unwrap();
    assert!(handshake(client, server, "srv04").is_err());

    // AES-128 and ChaCha20 only.
    let target = self_signed(KeyKind::Rsa2048, "srv05").unwrap();
    let (client, _) = pinned(&target);
    let server = weak_server_config(&target).unwrap();
    assert!(handshake(client, server, "srv05").is_err());
}

#[test]
fn the_tunnel_profile_still_refuses_tls12() {
    // The tls12 feature serves the target profile only: a tunnel client
    // never speaks TLS 1.2.
    let pki = crate::pki::testing::TestPki::new("tls12").unwrap();
    let target = self_signed(KeyKind::EcdsaP256, "core").unwrap();
    let client = crate::tls::client_config(&pki.root_anchor(), None, &[]).unwrap();
    let server = server_config(&target, Versions::Tls12).unwrap();
    assert!(handshake(client, server, "core").is_err());
}

#[test]
fn empty_ca_bundle_is_refused() {
    assert!(target_client_config(&TargetTrust::Pki(Vec::new())).is_err());
    assert!(anchors_from_pem(b"").is_err());
    let ca = TargetCa::new("bundle").unwrap();
    let pem = crate::pki::pem_certificate(&ca.certificate);
    assert_eq!(anchors_from_pem(pem.as_bytes()).unwrap().len(), 1);
}

proptest! {
    #[test]
    fn subject_public_key_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = subject_public_key(&bytes);
    }
}
