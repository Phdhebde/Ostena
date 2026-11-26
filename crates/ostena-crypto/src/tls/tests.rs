use std::collections::HashMap;
use std::sync::Mutex;

use rustls::{CipherSuite, NamedGroup, ProtocolVersion};

use super::*;
use crate::pki::testing::TestPki;
use crate::pki::{IssuingAuthority, Validity};

const ALPN: &[u8] = b"ostena-tunnel/1";
const DAY: u64 = 86_400;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn valid() -> Validity {
    Validity {
        not_before: now() - DAY,
        not_after: now() + 30 * DAY,
    }
}

#[derive(Debug, Default)]
struct Registry(Mutex<HashMap<[u8; 32], ClientRefusal>>);

impl Registry {
    fn set(&self, cert: &CertificateDer<'_>, refusal: ClientRefusal) {
        self.0.lock().unwrap().insert(fingerprint(cert), refusal);
    }
}

/// Accepts every certificate except those explicitly refused; the unknown
/// case is tested with [`Strict`].
impl ClientAuthorizer for Registry {
    fn authorize(&self, fingerprint: &[u8; 32]) -> Result<(), ClientRefusal> {
        self.0
            .lock()
            .unwrap()
            .get(fingerprint)
            .map_or(Ok(()), |r| Err(*r))
    }
}

/// Knows no certificate at all.
#[derive(Debug)]
struct Strict;

impl ClientAuthorizer for Strict {
    fn authorize(&self, _: &[u8; 32]) -> Result<(), ClientRefusal> {
        Err(ClientRefusal::Unknown)
    }
}

struct Fixture {
    pki: TestPki,
    server: Identity,
    registry: Arc<Registry>,
}

fn fixture() -> Fixture {
    let pki = TestPki::new("Ostena test").unwrap();
    let server = pki.server(&["core.test", "127.0.0.1"]).unwrap();
    Fixture {
        pki,
        server,
        registry: Arc::new(Registry::default()),
    }
}

fn agent(pki: &TestPki, validity: Validity) -> Identity {
    pki.agent("group-1", validity).unwrap()
}

fn server_config_for(f: &Fixture, authorizer: Arc<dyn ClientAuthorizer>) -> Arc<ServerConfig> {
    server_config(
        &f.server,
        ClientAuth::Required {
            issuing_cas: vec![f.pki.issuing_anchor()],
            authorizer,
        },
        &[ALPN],
    )
    .unwrap()
}

struct Outcome {
    client: Result<(), rustls::Error>,
    server: Result<(), rustls::Error>,
    client_conn: ClientConnection,
    server_conn: ServerConnection,
}

/// Runs a handshake in memory, passing each side's alert to the other.
fn handshake(client: Arc<ClientConfig>, server: Arc<ServerConfig>, name: &str) -> Outcome {
    let name = ServerName::try_from(name.to_owned()).unwrap();
    let mut c = ClientConnection::new(client, name).unwrap();
    let mut s = ServerConnection::new(server).unwrap();
    let (mut client_result, mut server_result) = (Ok(()), Ok(()));
    for _ in 0..16 {
        let mut buf = Vec::new();
        while c.wants_write() {
            c.write_tls(&mut buf).unwrap();
        }
        if !buf.is_empty() && server_result.is_ok() {
            s.read_tls(&mut buf.as_slice()).unwrap();
            if let Err(e) = s.process_new_packets() {
                server_result = Err(e);
            }
        }
        let mut buf = Vec::new();
        while s.wants_write() {
            s.write_tls(&mut buf).unwrap();
        }
        if !buf.is_empty() && client_result.is_ok() {
            c.read_tls(&mut buf.as_slice()).unwrap();
            if let Err(e) = c.process_new_packets() {
                client_result = Err(e);
            }
        }
        if !c.is_handshaking() && !s.is_handshaking() {
            break;
        }
        if client_result.is_err() && server_result.is_err() {
            break;
        }
    }
    if client_result.is_ok() && c.is_handshaking() {
        client_result = Err(rustls::Error::General("handshake did not complete".into()));
    }
    if server_result.is_ok() && s.is_handshaking() {
        server_result = Err(rustls::Error::General("handshake did not complete".into()));
    }
    Outcome {
        client: client_result,
        server: server_result,
        client_conn: c,
        server_conn: s,
    }
}

fn failure(result: &Result<(), rustls::Error>) -> HandshakeFailure {
    classify(result.as_ref().unwrap_err())
}

#[test]
fn provider_offers_exactly_one_suite_and_one_group() {
    let p = provider();
    assert_eq!(p.cipher_suites.len(), 1);
    assert_eq!(
        p.cipher_suites[0].suite(),
        CipherSuite::TLS13_AES_256_GCM_SHA384
    );
    assert_eq!(p.kx_groups.len(), 1);
    assert_eq!(p.kx_groups[0].name(), NamedGroup::secp256r1MLKEM768);
    assert_eq!(p.signature_verification_algorithms.all.len(), 1);
}

#[test]
fn quic_initial_suite_is_aes_128_gcm_and_not_negotiable() {
    let initial = quic_initial_suite();
    assert_eq!(
        initial.suite.common.suite,
        CipherSuite::TLS13_AES_128_GCM_SHA256
    );
    assert!(
        provider()
            .cipher_suites
            .iter()
            .all(|s| s.suite() != CipherSuite::TLS13_AES_128_GCM_SHA256)
    );
}

#[test]
fn mutual_handshake_negotiates_the_fixed_parameters() {
    let f = fixture();
    let agent = agent(&f.pki, valid());
    let client = client_config(&f.pki.root_anchor(), Some(&agent), &[ALPN]).unwrap();
    let o = handshake(
        client,
        server_config_for(&f, f.registry.clone()),
        "core.test",
    );
    assert!(o.client.is_ok(), "{:?}", o.client);
    assert!(o.server.is_ok(), "{:?}", o.server);
    for (suite, group, version, alpn) in [
        (
            o.client_conn.negotiated_cipher_suite(),
            o.client_conn.negotiated_key_exchange_group(),
            o.client_conn.protocol_version(),
            o.client_conn.alpn_protocol(),
        ),
        (
            o.server_conn.negotiated_cipher_suite(),
            o.server_conn.negotiated_key_exchange_group(),
            o.server_conn.protocol_version(),
            o.server_conn.alpn_protocol(),
        ),
    ] {
        assert_eq!(
            suite.unwrap().suite(),
            CipherSuite::TLS13_AES_256_GCM_SHA384
        );
        assert_eq!(group.unwrap().name(), NamedGroup::secp256r1MLKEM768);
        assert_eq!(version, Some(ProtocolVersion::TLSv1_3));
        assert_eq!(alpn, Some(ALPN));
    }
    // The server sees the agent certificate, whose fingerprint is its identity.
    let peer = o.server_conn.peer_certificates().unwrap();
    assert_eq!(fingerprint(&peer[0]), fingerprint(agent.certificate()));
}

#[test]
fn server_certificate_from_the_issuing_ca_is_refused() {
    let f = fixture();
    // An attacker with the issuing CA key makes a server certificate for
    // the right name and presents the full chain to the root.
    let rogue = f.pki.rogue_server(&["core.test"]).unwrap();
    let server = server_config(&rogue, ClientAuth::None, &[ALPN]).unwrap();
    let client = client_config(&f.pki.root_anchor(), None, &[ALPN]).unwrap();
    let o = handshake(client, server, "core.test");
    assert_eq!(failure(&o.client), HandshakeFailure::NotRootIssued);
    assert!(
        o.client
            .as_ref()
            .unwrap_err()
            .to_string()
            .contains(NOT_ROOT_ISSUED)
    );

    // Without the intermediate, it does not chain to the root at all.
    // SECRET-EXPOSURE: a throwaway test key, reused for a second identity.
    #[expect(clippy::disallowed_methods)]
    let key = SecretBytes::from(rogue.key.expose_secret().to_vec());
    let alone = Identity::new(vec![rogue.certificate().clone()], key).unwrap();
    let server = server_config(&alone, ClientAuth::None, &[ALPN]).unwrap();
    let client = client_config(&f.pki.root_anchor(), None, &[ALPN]).unwrap();
    let o = handshake(client, server, "core.test");
    assert_eq!(failure(&o.client), HandshakeFailure::UnknownIssuer);
}

#[test]
fn issuing_ca_name_constraints_forbid_server_names() {
    // Even a relying party that accepts intermediates refuses a server
    // certificate under the issuing CA: DNS names and IP addresses are
    // excluded by its name constraints.
    let f = fixture();
    let rogue = f.pki.rogue_server(&["core.test"]).unwrap();
    let verifier = WebPkiServerVerifier::builder_with_provider(
        f.pki.root_anchor().roots().unwrap(),
        provider(),
    )
    .build()
    .unwrap();
    let chain = &rogue.chain;
    let result = verifier.verify_server_cert(
        &chain[0],
        &chain[1..],
        &ServerName::try_from("core.test").unwrap(),
        &[],
        UnixTime::now(),
    );
    assert!(result.is_err(), "{result:?}");
}

#[test]
fn server_certificate_from_another_ca_is_refused() {
    let f = fixture();
    let other = TestPki::new("Other").unwrap();
    let agent = agent(&f.pki, valid());
    let client = client_config(&other.root_anchor(), Some(&agent), &[ALPN]).unwrap();
    let o = handshake(
        client,
        server_config_for(&f, f.registry.clone()),
        "core.test",
    );
    assert_eq!(failure(&o.client), HandshakeFailure::UnknownIssuer);
    assert!(o.server.is_err());
}

#[test]
fn agent_certificate_from_another_ca_is_refused() {
    let f = fixture();
    let other = TestPki::new("Other").unwrap();
    let client =
        client_config(&f.pki.root_anchor(), Some(&agent(&other, valid())), &[ALPN]).unwrap();
    let o = handshake(
        client,
        server_config_for(&f, f.registry.clone()),
        "core.test",
    );
    assert_eq!(failure(&o.server), HandshakeFailure::UnknownIssuer);
    assert_eq!(failure(&o.client), HandshakeFailure::UnknownIssuer);
}

#[test]
fn client_certificate_is_mandatory() {
    let f = fixture();
    let client = client_config(&f.pki.root_anchor(), None, &[ALPN]).unwrap();
    let o = handshake(
        client,
        server_config_for(&f, f.registry.clone()),
        "core.test",
    );
    assert_eq!(failure(&o.server), HandshakeFailure::NoClientCertificate);
    assert!(o.client.is_err());
}

#[test]
fn expired_agent_certificate_is_refused() {
    let f = fixture();
    let expired = Validity {
        not_before: now() - 40 * DAY,
        not_after: now() - DAY,
    };
    let client =
        client_config(&f.pki.root_anchor(), Some(&agent(&f.pki, expired)), &[ALPN]).unwrap();
    let o = handshake(
        client,
        server_config_for(&f, f.registry.clone()),
        "core.test",
    );
    assert_eq!(failure(&o.server), HandshakeFailure::Expired);
    assert_eq!(failure(&o.client), HandshakeFailure::Expired);
}

#[test]
fn agent_certificate_not_valid_yet_is_refused() {
    let f = fixture();
    let future = Validity {
        not_before: now() + DAY,
        not_after: now() + 30 * DAY,
    };
    let client =
        client_config(&f.pki.root_anchor(), Some(&agent(&f.pki, future)), &[ALPN]).unwrap();
    let o = handshake(
        client,
        server_config_for(&f, f.registry.clone()),
        "core.test",
    );
    assert_eq!(failure(&o.server), HandshakeFailure::NotYetValid);
}

#[test]
fn revoked_agent_certificate_is_refused() {
    let f = fixture();
    let agent = agent(&f.pki, valid());
    f.registry.set(agent.certificate(), ClientRefusal::Revoked);
    let client = client_config(&f.pki.root_anchor(), Some(&agent), &[ALPN]).unwrap();
    let o = handshake(
        client,
        server_config_for(&f, f.registry.clone()),
        "core.test",
    );
    assert_eq!(failure(&o.server), HandshakeFailure::Revoked);
    assert_eq!(failure(&o.client), HandshakeFailure::Revoked);
}

#[test]
fn unreadable_registry_refuses_the_agent() {
    let f = fixture();
    let agent = agent(&f.pki, valid());
    f.registry
        .set(agent.certificate(), ClientRefusal::Unavailable);
    let client = client_config(&f.pki.root_anchor(), Some(&agent), &[ALPN]).unwrap();
    let o = handshake(
        client,
        server_config_for(&f, f.registry.clone()),
        "core.test",
    );
    assert_eq!(failure(&o.server), HandshakeFailure::RegistryUnavailable);
    // Plain TLS carries only the alert; over QUIC the close reason names it.
    assert_eq!(failure(&o.client), HandshakeFailure::Other);
}

#[test]
fn agent_unknown_to_the_registry_is_refused() {
    let f = fixture();
    let client =
        client_config(&f.pki.root_anchor(), Some(&agent(&f.pki, valid())), &[ALPN]).unwrap();
    let o = handshake(client, server_config_for(&f, Arc::new(Strict)), "core.test");
    assert_eq!(failure(&o.server), HandshakeFailure::UnknownClient);
    assert!(o.client.is_err());
}

#[test]
fn certificate_from_a_reloaded_ca_is_accepted() {
    let f = fixture();
    let reloaded = IssuingAuthority::from_parts(
        "Ostena test issuing",
        &f.pki.issuing_key,
        f.pki.issuing_certificate.clone(),
    )
    .unwrap();
    let (key, pkcs8) = p256::SigningKey::generate().unwrap();
    let cert = reloaded
        .issue_agent(&key.verifying_key(), "group-1", "agent-1", valid())
        .unwrap();
    let client = client_config(
        &f.pki.root_anchor(),
        Some(&Identity::new(vec![cert], pkcs8).unwrap()),
        &[ALPN],
    )
    .unwrap();
    let o = handshake(
        client,
        server_config_for(&f, f.registry.clone()),
        "core.test",
    );
    assert!(
        o.client.is_ok() && o.server.is_ok(),
        "{:?} {:?}",
        o.client,
        o.server
    );
}

#[test]
fn server_name_mismatch_is_refused() {
    let f = fixture();
    let client =
        client_config(&f.pki.root_anchor(), Some(&agent(&f.pki, valid())), &[ALPN]).unwrap();
    let o = handshake(
        client,
        server_config_for(&f, f.registry.clone()),
        "other.test",
    );
    assert_eq!(failure(&o.client), HandshakeFailure::NameMismatch);
}

#[test]
fn ip_address_name_is_accepted() {
    let f = fixture();
    let client =
        client_config(&f.pki.root_anchor(), Some(&agent(&f.pki, valid())), &[ALPN]).unwrap();
    let o = handshake(
        client,
        server_config_for(&f, f.registry.clone()),
        "127.0.0.1",
    );
    assert!(
        o.client.is_ok() && o.server.is_ok(),
        "{:?} {:?}",
        o.client,
        o.server
    );
}

#[test]
fn agent_certificate_cannot_serve_as_server_certificate() {
    let f = fixture();
    // An agent certificate (client authentication only) presented by a server.
    let rogue = server_config(&agent(&f.pki, valid()), ClientAuth::None, &[ALPN]).unwrap();
    let client = client_config(&f.pki.root_anchor(), None, &[ALPN]).unwrap();
    let o = handshake(client, rogue, "core.test");
    assert!(o.client.is_err());
}

/// A client built on the stock aws-lc-rs provider, restricted as asked.
fn foreign_client(f: &Fixture, adjust: impl FnOnce(&mut CryptoProvider)) -> Arc<ClientConfig> {
    let mut p = aws_lc_rs::default_provider();
    adjust(&mut p);
    let p = Arc::new(p);
    let verifier = WebPkiServerVerifier::builder_with_provider(
        f.pki.root_anchor().roots().unwrap(),
        p.clone(),
    )
    .build()
    .unwrap();
    let agent = agent(&f.pki, valid());
    let mut config = ClientConfig::builder_with_provider(p)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(agent.chain.clone(), agent.rustls_key())
        .unwrap();
    config.alpn_protocols = vec![ALPN.to_vec()];
    Arc::new(config)
}

#[test]
fn peer_without_the_hybrid_group_fails() {
    let f = fixture();
    for group in [
        aws_lc_rs::kx_group::X25519,
        aws_lc_rs::kx_group::SECP256R1,
        aws_lc_rs::kx_group::X25519MLKEM768,
    ] {
        let client = foreign_client(&f, |p| p.kx_groups = vec![group]);
        let o = handshake(
            client,
            server_config_for(&f, f.registry.clone()),
            "core.test",
        );
        assert_eq!(failure(&o.server), HandshakeFailure::NoCommonGroup);
        assert!(o.client.is_err());
    }
}

#[test]
fn peer_without_the_aes_256_suite_fails() {
    let f = fixture();
    let client = foreign_client(&f, |p| {
        p.kx_groups = vec![aws_lc_rs::kx_group::SECP256R1MLKEM768];
        p.cipher_suites = vec![
            aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
            aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        ];
    });
    let o = handshake(
        client,
        server_config_for(&f, f.registry.clone()),
        "core.test",
    );
    assert_eq!(failure(&o.server), HandshakeFailure::NoCommonCipherSuite);
    assert!(o.client.is_err());
}

#[test]
fn stock_peer_offering_the_hybrid_group_succeeds() {
    // Sanity check of the foreign client: with the right group and suite, it works.
    let f = fixture();
    let client = foreign_client(&f, |p| {
        p.kx_groups = vec![aws_lc_rs::kx_group::SECP256R1MLKEM768];
    });
    let o = handshake(
        client,
        server_config_for(&f, f.registry.clone()),
        "core.test",
    );
    assert!(
        o.client.is_ok() && o.server.is_ok(),
        "{:?} {:?}",
        o.client,
        o.server
    );
}

#[test]
fn application_protocol_mismatch_fails() {
    let f = fixture();
    let client = client_config(
        &f.pki.root_anchor(),
        Some(&agent(&f.pki, valid())),
        &[b"other/1"],
    )
    .unwrap();
    let o = handshake(
        client,
        server_config_for(&f, f.registry.clone()),
        "core.test",
    );
    assert_eq!(failure(&o.server), HandshakeFailure::NoApplicationProtocol);
    assert_eq!(failure(&o.client), HandshakeFailure::NoApplicationProtocol);
}

#[test]
fn enrolment_listener_needs_no_client_certificate() {
    let f = fixture();
    let server = server_config(&f.server, ClientAuth::None, &[b"ostena-enroll/1"]).unwrap();
    let client = client_config(&f.pki.root_anchor(), None, &[b"ostena-enroll/1"]).unwrap();
    let o = handshake(client, server, "core.test");
    assert!(
        o.client.is_ok() && o.server.is_ok(),
        "{:?} {:?}",
        o.client,
        o.server
    );
}

#[test]
fn no_resumption_and_no_early_data() {
    let f = fixture();
    let client = client_config(&f.pki.root_anchor(), None, &[ALPN]).unwrap();
    assert!(!client.enable_early_data);
    let server = server_config_for(&f, f.registry.clone());
    assert_eq!(server.send_tls13_tickets, 0);
    assert_eq!(server.max_early_data_size, 0);
}

#[test]
fn identity_requires_a_p256_key() {
    let f = fixture();
    let agent = agent(&f.pki, valid());
    let p384 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    assert_eq!(
        Identity::new(
            vec![agent.certificate().clone()],
            SecretBytes::from(p384.serialize_der())
        )
        .err(),
        Some(TlsError::KeyAlgorithm)
    );
    assert_eq!(
        Identity::new(Vec::new(), SecretBytes::from(Vec::new())).err(),
        Some(TlsError::Pem("chaîne de certificats vide"))
    );
}

#[test]
fn identity_and_anchor_from_pem() {
    let f = fixture();
    let (key, pkcs8) = p256::SigningKey::generate().unwrap();
    let cert = f
        .pki
        .issuing
        .issue_agent(&key.verifying_key(), "g", "a", valid())
        .unwrap();
    let cert_pem = crate::pki::pem_certificate(&cert);
    // SECRET-EXPOSURE: a throwaway test key, converted to PEM.
    #[expect(clippy::disallowed_methods)]
    let der = pkcs8.expose_secret().to_vec();
    let key_pem = rcgen::KeyPair::try_from(der.as_slice())
        .unwrap()
        .serialize_pem();
    let id = Identity::from_pem(
        cert_pem.as_bytes(),
        &SecretBytes::from(key_pem.into_bytes()),
    )
    .unwrap();
    assert_eq!(id.certificate(), &cert);
    let anchor = TrustAnchor::from_pem(f.pki.root.certificate_pem().as_bytes()).unwrap();
    assert_eq!(anchor.certificate(), f.pki.root_anchor().certificate());
    assert!(TrustAnchor::from_pem(b"not pem").is_err());
}

#[test]
fn classify_io_finds_the_tls_error() {
    let tls = std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer),
    );
    assert_eq!(classify_io(&tls), Some(HandshakeFailure::UnknownIssuer));
    let plain = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
    assert_eq!(classify_io(&plain), None);
}

#[test]
fn web_provider_offers_the_hybrid_groups_and_the_fixed_suite() {
    let names = |p: &CryptoProvider| p.kx_groups.iter().map(|g| g.name()).collect::<Vec<_>>();
    let hybrid = web_provider(WebGroups::Hybrid);
    assert_eq!(
        names(&hybrid),
        [NamedGroup::secp256r1MLKEM768, NamedGroup::X25519MLKEM768]
    );
    assert_eq!(hybrid.cipher_suites.len(), 1);
    assert_eq!(
        hybrid.cipher_suites[0].suite(),
        CipherSuite::TLS13_AES_256_GCM_SHA384
    );
    assert_eq!(hybrid.signature_verification_algorithms.all.len(), 1);
    assert_eq!(
        names(&web_provider(WebGroups::HybridThenClassic)),
        [
            NamedGroup::secp256r1MLKEM768,
            NamedGroup::X25519MLKEM768,
            NamedGroup::secp256r1
        ]
    );
    assert_eq!(WebGroups::Hybrid.names().len(), 2);
    assert_eq!(WebGroups::HybridThenClassic.names().len(), 3);
}

#[test]
fn web_listener_accepts_browsers_with_a_hybrid_group_only() {
    use testing::{Offer, browser_client_config};
    let f = fixture();
    let root = f.pki.root_anchor();
    let hybrid = web_server_config(&f.server, WebGroups::Hybrid).unwrap();
    let classic = web_server_config(&f.server, WebGroups::HybridThenClassic).unwrap();

    // A browser offering X25519MLKEM768: accepted, hybrid, http/1.1.
    let o = handshake(
        browser_client_config(Offer::X25519MlKem768, &root).unwrap(),
        hybrid.clone(),
        "core.test",
    );
    assert!(o.client.is_ok() && o.server.is_ok(), "{:?}", o.server);
    assert_eq!(
        o.server_conn
            .negotiated_key_exchange_group()
            .unwrap()
            .name(),
        NamedGroup::X25519MLKEM768
    );
    assert_eq!(o.server_conn.alpn_protocol(), Some(&b"http/1.1"[..]));
    assert_eq!(
        o.server_conn.negotiated_cipher_suite().unwrap().suite(),
        CipherSuite::TLS13_AES_256_GCM_SHA384
    );
    // The fixed hybrid of the tunnel is accepted too.
    let o = handshake(
        client_config(&root, None, &[b"http/1.1"]).unwrap(),
        hybrid.clone(),
        "core.test",
    );
    assert!(o.server.is_ok(), "{:?}", o.server);
    assert_eq!(
        o.server_conn
            .negotiated_key_exchange_group()
            .unwrap()
            .name(),
        NamedGroup::secp256r1MLKEM768
    );

    // Classical only: refused, unless the fallback is on (development).
    let o = handshake(
        browser_client_config(Offer::Secp256r1, &root).unwrap(),
        hybrid.clone(),
        "core.test",
    );
    assert_eq!(failure(&o.server), HandshakeFailure::NoCommonGroup);
    let o = handshake(
        browser_client_config(Offer::Secp256r1, &root).unwrap(),
        classic.clone(),
        "core.test",
    );
    assert!(o.server.is_ok(), "{:?}", o.server);
    // X25519 alone is never accepted.
    for server in [hybrid.clone(), classic] {
        let o = handshake(
            browser_client_config(Offer::X25519, &root).unwrap(),
            server,
            "core.test",
        );
        assert_eq!(failure(&o.server), HandshakeFailure::NoCommonGroup);
    }
    // AES-128 suites only: refused.
    let o = handshake(
        browser_client_config(Offer::Aes128Suite, &root).unwrap(),
        hybrid,
        "core.test",
    );
    assert_eq!(failure(&o.server), HandshakeFailure::NoCommonCipherSuite);
}
