//! TLS towards the syslog collectors of the audit export (RFC 5425,
//! ADR-0012 « Export syslog TLS en OCSF »).
//!
//! The frozen profile of the tunnel, never negotiable by a collector or the
//! configuration: TLS 1.3 only, `TLS_AES_256_GCM_SHA384`, group
//! `SecP256r1MLKEM768`, ECDSA P-256 / SHA-256 certificates and handshake
//! signatures; no resumption, no 0-RTT. The collector is authenticated by
//! the CA bundle of the destination only (chain, name in the SAN,
//! `serverAuth`, dates; RFC 5425 section 5.2, no fingerprint mode), and the
//! core presents its own certificate when one is configured (mutual
//! authentication, section 5.1). No revocation check.

use std::sync::Arc;

use rustls::ClientConfig;
use rustls::client::{Resumption, WebPkiServerVerifier};

use super::{Identity, TlsError, TrustAnchor, provider, roots};

/// The client configuration towards one collector, trusting `anchors`
/// only, presenting `identity` if given.
///
/// # Errors
///
/// [`TlsError::Config`] if the bundle is empty or rustls refuses it.
pub fn syslog_client_config(
    anchors: &[TrustAnchor],
    identity: Option<&Identity>,
) -> Result<Arc<ClientConfig>, TlsError> {
    if anchors.is_empty() {
        return Err(TlsError::Config(
            "aucune autorité pour le collecteur syslog".into(),
        ));
    }
    let provider = provider();
    let verifier = WebPkiServerVerifier::builder_with_provider(roots(anchors)?, provider.clone())
        .build()
        .map_err(|e| TlsError::Config(e.to_string()))?;
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError::Config(e.to_string()))?
        .with_webpki_verifier(verifier);
    let mut config = match identity {
        Some(id) => builder
            .with_client_auth_cert(id.chain.clone(), id.rustls_key())
            .map_err(|e| TlsError::Config(e.to_string()))?,
        None => builder.with_no_client_auth(),
    };
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    config.enable_sni = true;
    Ok(Arc::new(config))
}

/// Test collectors.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use std::sync::Arc;

    use rustls::server::WebPkiClientVerifier;
    use rustls::{ServerConfig, crypto::aws_lc_rs};

    use crate::tls::target::testing::TargetIdentity;
    use crate::tls::{TlsError, TrustAnchor, provider, roots};

    fn err(e: impl std::fmt::Display) -> TlsError {
        TlsError::Config(e.to_string())
    }

    /// A collector on the profile presenting `identity`; with `clients`,
    /// it requires a client certificate from these authorities. `stock`
    /// takes the stock aws-lc-rs provider instead (no `SecP256r1MLKEM768`),
    /// to prove the refusal.
    ///
    /// # Errors
    ///
    /// [`TlsError::Config`] if rustls refuses the configuration.
    pub fn collector_config(
        identity: &TargetIdentity,
        clients: Option<&[TrustAnchor]>,
        stock: bool,
    ) -> Result<Arc<ServerConfig>, TlsError> {
        let provider = if stock {
            Arc::new(aws_lc_rs::default_provider())
        } else {
            provider()
        };
        let builder = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(err)?;
        let builder = match clients {
            Some(anchors) => builder.with_client_cert_verifier(
                WebPkiClientVerifier::builder_with_provider(roots(anchors)?, provider)
                    .build()
                    .map_err(err)?,
            ),
            None => builder.with_no_client_auth(),
        };
        // SECRET-EXPOSURE: rustls keeps its own copy of the test key.
        #[expect(clippy::disallowed_methods)]
        let der = identity.key.expose_secret().to_vec();
        builder
            .with_single_cert(
                vec![identity.certificate.clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(der.into()),
            )
            .map(Arc::new)
            .map_err(err)
    }
}

#[cfg(test)]
mod tests {
    use rustls::pki_types::ServerName;
    use rustls::{ClientConnection, ServerConnection};

    use super::testing::collector_config;
    use super::*;
    use crate::tls::target::testing::{KeyKind, TargetCa, Usage};

    fn handshake(
        client: Arc<ClientConfig>,
        server: Arc<rustls::ServerConfig>,
        name: &str,
    ) -> Result<(), String> {
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
            s.process_new_packets()
                .map_err(|e| format!("serveur : {e}"))?;
            let mut buf = Vec::new();
            while s.wants_write() {
                s.write_tls(&mut buf).unwrap();
            }
            let mut slice = buf.as_slice();
            while !slice.is_empty() {
                c.read_tls(&mut slice).unwrap();
            }
            c.process_new_packets()
                .map_err(|e| format!("client : {e}"))?;
            if !c.is_handshaking() && !s.is_handshaking() {
                return Ok(());
            }
        }
        Err("poignée de main inachevée".into())
    }

    #[test]
    fn the_collector_is_authenticated_by_its_bundle() {
        let ca = TargetCa::new("siem ca").unwrap();
        let collector = ca
            .issue(KeyKind::EcdsaP256, &["siem.test"], Some(Usage::ServerAuth))
            .unwrap();
        let client = syslog_client_config(&[ca.anchor()], None).unwrap();
        let server = collector_config(&collector, None, false).unwrap();
        handshake(client.clone(), server.clone(), "siem.test").unwrap();
        // Another name, another authority, another group, an RSA key: refused.
        assert!(handshake(client.clone(), server.clone(), "other.test").is_err());
        let other = TargetCa::new("other ca").unwrap();
        let foreign = syslog_client_config(&[other.anchor()], None).unwrap();
        assert!(handshake(foreign, server, "siem.test").is_err());
        let stock = collector_config(&collector, None, true).unwrap();
        assert!(handshake(client.clone(), stock, "siem.test").is_err());
        let rsa = ca
            .issue(KeyKind::Rsa2048, &["siem.test"], Some(Usage::ServerAuth))
            .unwrap();
        let rsa = collector_config(&rsa, None, false).unwrap();
        assert!(handshake(client, rsa, "siem.test").is_err());
        assert!(syslog_client_config(&[], None).is_err());
    }

    #[test]
    fn the_core_presents_its_certificate_when_configured() {
        let ca = TargetCa::new("siem ca").unwrap();
        let collector = ca
            .issue(KeyKind::EcdsaP256, &["siem.test"], Some(Usage::ServerAuth))
            .unwrap();
        let clients = TargetCa::new("core clients").unwrap();
        let core = clients
            .issue(KeyKind::EcdsaP256, &["core.test"], Some(Usage::ClientAuth))
            .unwrap();
        // SECRET-EXPOSURE: a test key, copied into the identity.
        #[expect(clippy::disallowed_methods)]
        let key = ostena_common::secret::SecretBytes::from(core.key.expose_secret().to_vec());
        let identity = Identity::new(vec![core.certificate.clone()], key).unwrap();
        let server = collector_config(&collector, Some(&[clients.anchor()]), false).unwrap();
        let with = syslog_client_config(&[ca.anchor()], Some(&identity)).unwrap();
        handshake(with, server.clone(), "siem.test").unwrap();
        let without = syslog_client_config(&[ca.anchor()], None).unwrap();
        assert!(handshake(without, server, "siem.test").is_err());
    }
}
