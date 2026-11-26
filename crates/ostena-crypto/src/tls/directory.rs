//! TLS towards the LDAPS directories of the identity sources (ADR-0021,
//! ADR-0009 « Annuaires LDAPS »).
//!
//! Active Directory, OpenLDAP and FreeIPA offer no ML-KEM and certify their
//! LDAPS service with RSA keys from the customer PKI: the frozen tunnel
//! profile cannot apply. This profile is confined to the identity sources
//! of the core and fixed here, never negotiable by a directory or the
//! configuration:
//!
//! - protocol: **TLS 1.3 only**; no resumption, no 0-RTT. TLS 1.2 is not
//!   offered: a directory that only speaks TLS 1.2 (domain controllers
//!   before Windows Server 2022) fails the handshake;
//! - cipher suite: `TLS13_AES_256_GCM_SHA384` only;
//! - groups, in order of preference: `SecP256r1MLKEM768` (hybrid, taken
//!   when the directory offers it), then P-256 and P-384;
//! - certificate keys and handshake signatures: RSA of 2048 to 8192 bits
//!   (PSS in the handshake, PKCS#1 v1.5 or PSS with SHA-256/384/512 in the
//!   chain), ECDSA P-256 / SHA-256.
//!
//! Trust is the CA bundle of the source only (never the public or system
//! roots): chain to it, the server name in the SAN, `serverAuth` usage,
//! dates. No revocation check (known limit, ADR-0021). There is no pinning
//! mode and no way to skip the verification.

use std::sync::Arc;

use rustls::ClientConfig;
use rustls::client::{Resumption, WebPkiServerVerifier};
use rustls::crypto::{CryptoProvider, aws_lc_rs};

use super::target::TARGET_ALGORITHMS;
use super::{TlsError, TrustAnchor, roots};

pub use super::target::anchors_from_pem;

/// The fixed provider of the directory profile.
pub fn directory_provider() -> Arc<CryptoProvider> {
    let base = aws_lc_rs::default_provider();
    Arc::new(CryptoProvider {
        cipher_suites: vec![aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384],
        kx_groups: vec![
            aws_lc_rs::kx_group::SECP256R1MLKEM768,
            aws_lc_rs::kx_group::SECP256R1,
            aws_lc_rs::kx_group::SECP384R1,
        ],
        signature_verification_algorithms: TARGET_ALGORITHMS,
        secure_random: base.secure_random,
        key_provider: base.key_provider,
    })
}

/// The client configuration towards the directories of one source, trusting
/// `anchors` only.
///
/// # Errors
///
/// [`TlsError::Config`] if the bundle is empty or rustls refuses it.
pub fn directory_client_config(anchors: &[TrustAnchor]) -> Result<Arc<ClientConfig>, TlsError> {
    if anchors.is_empty() {
        return Err(TlsError::Config(
            "aucune autorité pour les annuaires de la source".into(),
        ));
    }
    let provider = directory_provider();
    let verifier = WebPkiServerVerifier::builder_with_provider(roots(anchors)?, provider.clone())
        .build()
        .map_err(|e| TlsError::Config(e.to_string()))?;
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError::Config(e.to_string()))?
        .with_webpki_verifier(verifier)
        .with_no_client_auth();
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    config.enable_sni = true;
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rustls::pki_types::ServerName;
    use rustls::{ClientConnection, ProtocolVersion, ServerConfig, ServerConnection};

    use super::super::target::testing::{
        KeyKind, TargetCa, Usage, Versions, self_signed, server_config, weak_server_config,
    };
    use super::*;

    fn handshake(
        client: Arc<ClientConfig>,
        server: Arc<ServerConfig>,
        name: &str,
    ) -> Result<(ProtocolVersion, Option<rustls::NamedGroup>), rustls::Error> {
        let name = ServerName::try_from(name.to_owned()).unwrap();
        let mut c = ClientConnection::new(client, name).unwrap();
        let mut s = ServerConnection::new(server).unwrap();
        for _ in 0..16 {
            let mut buf = Vec::new();
            while c.wants_write() {
                c.write_tls(&mut buf).unwrap();
            }
            let mut slice = buf.as_slice();
            while !slice.is_empty() {
                s.read_tls(&mut slice).unwrap();
            }
            let _ = s.process_new_packets();
            let mut buf = Vec::new();
            while s.wants_write() {
                s.write_tls(&mut buf).unwrap();
            }
            let mut slice = buf.as_slice();
            while !slice.is_empty() {
                c.read_tls(&mut slice).unwrap();
            }
            c.process_new_packets()?;
            if !c.is_handshaking() && !s.is_handshaking() {
                let group = c
                    .negotiated_key_exchange_group()
                    .map(rustls::crypto::SupportedKxGroup::name);
                return Ok((c.protocol_version().unwrap(), group));
            }
        }
        panic!("handshake did not finish");
    }

    #[test]
    fn rsa_directory_of_the_customer_pki() {
        let ca = TargetCa::new("customer ca").unwrap();
        let dc = ca
            .issue(
                KeyKind::Rsa2048,
                &["dc01.corp.test"],
                Some(Usage::ServerAuth),
            )
            .unwrap();
        let client = directory_client_config(&[ca.anchor()]).unwrap();
        let server = server_config(&dc, Versions::Both).unwrap();
        let (version, _) = handshake(client, server, "dc01.corp.test").unwrap();
        assert_eq!(version, ProtocolVersion::TLSv1_3);
        let ecdsa = ca
            .issue(KeyKind::EcdsaP256, &["10.0.0.5"], Some(Usage::ServerAuth))
            .unwrap();
        let client = directory_client_config(&[ca.anchor()]).unwrap();
        let server = server_config(&ecdsa, Versions::Tls13).unwrap();
        assert!(handshake(client, server, "10.0.0.5").is_ok());
    }

    #[test]
    fn hybrid_group_preferred() {
        let ca = TargetCa::new("customer ca").unwrap();
        let dc = ca
            .issue(
                KeyKind::Rsa2048,
                &["dc01.corp.test"],
                Some(Usage::ServerAuth),
            )
            .unwrap();
        // A directory of today (the stock provider, like Windows): P-256.
        let client = directory_client_config(&[ca.anchor()]).unwrap();
        let server = server_config(&dc, Versions::Tls13).unwrap();
        let (_, group) = handshake(client.clone(), server, "dc01.corp.test").unwrap();
        assert_eq!(group, Some(rustls::NamedGroup::secp256r1));
        // A directory that offers the hybrid group gets it.
        // SECRET-EXPOSURE: rustls keeps its own copy of the test key.
        #[expect(clippy::disallowed_methods)]
        let der = dc.key.expose_secret().to_vec();
        let server = ServerConfig::builder_with_provider(directory_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![dc.certificate.clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(der.into()),
            )
            .unwrap();
        let (_, group) = handshake(client, Arc::new(server), "dc01.corp.test").unwrap();
        assert_eq!(group, Some(rustls::NamedGroup::secp256r1MLKEM768));
    }

    /// A directory that only speaks TLS 1.2 is refused: the profile offers
    /// TLS 1.3 alone.
    #[test]
    fn tls12_directory_is_refused() {
        let ca = TargetCa::new("customer ca").unwrap();
        let dc = ca
            .issue(
                KeyKind::Rsa2048,
                &["dc01.corp.test"],
                Some(Usage::ServerAuth),
            )
            .unwrap();
        let client = directory_client_config(&[ca.anchor()]).unwrap();
        let server = server_config(&dc, Versions::Tls12).unwrap();
        assert!(handshake(client, server, "dc01.corp.test").is_err());
    }

    /// An invalid directory certificate is refused: another name, another
    /// CA, no server usage, self-signed, key outside the profile.
    #[test]
    fn invalid_certificates_are_refused() {
        let ca = TargetCa::new("customer ca").unwrap();
        let rogue = TargetCa::new("rogue ca").unwrap();
        let name = "dc01.corp.test";
        let cases = [
            ca.issue(
                KeyKind::Rsa2048,
                &["dc02.corp.test"],
                Some(Usage::ServerAuth),
            ),
            rogue.issue(KeyKind::Rsa2048, &[name], Some(Usage::ServerAuth)),
            ca.issue(KeyKind::Rsa2048, &[name], Some(Usage::ClientAuth)),
            self_signed(KeyKind::Rsa2048, name),
            ca.issue(KeyKind::EcdsaP384, &[name], Some(Usage::ServerAuth)),
        ];
        for (i, dc) in cases.into_iter().enumerate() {
            let client = directory_client_config(&[ca.anchor()]).unwrap();
            let server = server_config(&dc.unwrap(), Versions::Both).unwrap();
            assert!(handshake(client, server, name).is_err(), "case {i}");
        }
    }

    #[test]
    fn suites_outside_the_profile_are_refused() {
        let ca = TargetCa::new("customer ca").unwrap();
        let dc = ca
            .issue(
                KeyKind::Rsa2048,
                &["dc01.corp.test"],
                Some(Usage::ServerAuth),
            )
            .unwrap();
        let client = directory_client_config(&[ca.anchor()]).unwrap();
        let server = weak_server_config(&dc).unwrap();
        assert!(handshake(client, server, "dc01.corp.test").is_err());
    }

    #[test]
    fn empty_bundle_is_refused() {
        assert!(directory_client_config(&[]).is_err());
    }
}
