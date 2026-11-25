//! TLS 1.3 for the agent-core tunnel (ADR-0009), on rustls with a provider
//! built here from `aws-lc-rs`. Nothing is negotiable:
//!
//! - protocol: TLS 1.3 only, no resumption, no 0-RTT;
//! - cipher suite: `TLS_AES_256_GCM_SHA384` only;
//! - key exchange: `SecP256r1MLKEM768` only (hybrid P-256 + ML-KEM-768); a
//!   peer that does not offer it fails the handshake;
//! - signatures (certificates and handshake): ECDSA P-256 / SHA-256 only;
//! - trust: the agent pins the offline root and accepts only a core
//!   certificate the root signed directly, with no intermediate; the core
//!   trusts its issuing CAs for agent certificates; never the system roots;
//! - client certificate: mandatory, checked against the issuing CAs, then
//!   against a [`ClientAuthorizer`] (the core registry: unknown or revoked
//!   agents).
//!
//! The transports receive the [`ClientConfig`] and [`ServerConfig`] built
//! here; no other crate depends on rustls directly (`deny.toml`).

use std::fmt;
use std::sync::Arc;

use ::aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use ostena_common::secret::SecretBytes;
use rustls::client::Resumption;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms, aws_lc_rs};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{
    AlgorithmIdentifier, InvalidSignature, PrivateKeyDer, PrivatePkcs8KeyDer,
    SignatureVerificationAlgorithm, UnixTime, alg_id,
};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{NoServerSessionStorage, WebPkiClientVerifier};
use rustls::{
    AlertDescription, CertificateError, DigitallySignedStruct, DistinguishedName, PeerIncompatible,
    RootCertStore, SignatureScheme,
};

pub use rustls::pki_types::{CertificateDer, ServerName};
pub use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};

use crate::p256;

/// TLS setup and handshake errors, coarse on purpose.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TlsError {
    /// A certificate or key in PEM could not be read.
    #[error("certificat ou clé illisible : {0}")]
    Pem(&'static str),
    /// The private key is not an ECDSA P-256 key.
    #[error("la clé privée n'est pas une clé ECDSA P-256")]
    KeyAlgorithm,
    /// rustls refused the configuration.
    #[error("configuration TLS refusée : {0}")]
    Config(String),
}

/// Why a handshake failed, for the stable `TUN-` codes of the tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeFailure {
    /// The peer does not offer `SecP256r1MLKEM768`.
    NoCommonGroup,
    /// The peer does not offer `TLS_AES_256_GCM_SHA384`.
    NoCommonCipherSuite,
    /// The peer does not speak TLS 1.3.
    ProtocolVersion,
    /// Certificate not issued by the pinned CA.
    UnknownIssuer,
    /// Certificate expired.
    Expired,
    /// Certificate not valid yet.
    NotYetValid,
    /// Certificate valid for another name.
    NameMismatch,
    /// Client certificate revoked in the core registry.
    Revoked,
    /// Client certificate unknown to the core registry.
    UnknownClient,
    /// No client certificate presented.
    NoClientCertificate,
    /// No common application protocol (ALPN).
    NoApplicationProtocol,
    /// The core presented a chain: its certificate is not signed directly
    /// by the pinned root (for example, issued by the online issuing CA).
    NotRootIssued,
    /// The core cannot read its registry of agents: it refuses rather than
    /// trust a stale copy.
    RegistryUnavailable,
    /// Anything else (signature, encoding, peer misbehaviour, I/O).
    Other,
}

/// Text of the refusal of a core certificate not signed directly by the
/// root; it travels in the QUIC close reason, so both ends can classify it.
pub const NOT_ROOT_ISSUED: &str = "core certificate not issued directly by the pinned root";

/// Its `Debug` form is the refusal text: rustls shows the details of an
/// `Other` certificate error with `Debug`, and that text reaches the peer.
struct NotRootIssued;

impl fmt::Debug for NotRootIssued {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(NOT_ROOT_ISSUED)
    }
}

impl fmt::Display for NotRootIssued {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(NOT_ROOT_ISSUED)
    }
}

impl std::error::Error for NotRootIssued {}

/// Text of the refusal while the core registry cannot be read; it travels in
/// the QUIC close reason, like [`NOT_ROOT_ISSUED`].
pub const REGISTRY_UNAVAILABLE: &str = "agent registry of the core unavailable";

/// Its `Debug` form is the refusal text (see [`NotRootIssued`]).
struct RegistryUnavailable;

impl fmt::Debug for RegistryUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REGISTRY_UNAVAILABLE)
    }
}

impl fmt::Display for RegistryUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REGISTRY_UNAVAILABLE)
    }
}

impl std::error::Error for RegistryUnavailable {}

/// Classifies a handshake error carried by an I/O error (as returned by
/// the TLS streams of tokio-rustls); `None` if it is not a TLS error.
pub fn classify_io(error: &std::io::Error) -> Option<HandshakeFailure> {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        .map(classify)
}

/// Classifies a handshake error, seen from either side.
pub fn classify(error: &rustls::Error) -> HandshakeFailure {
    use rustls::Error as E;
    match error {
        E::PeerIncompatible(PeerIncompatible::NoKxGroupsInCommon) => {
            HandshakeFailure::NoCommonGroup
        }
        E::PeerIncompatible(PeerIncompatible::NoCipherSuitesInCommon) => {
            HandshakeFailure::NoCommonCipherSuite
        }
        E::PeerIncompatible(
            PeerIncompatible::Tls13RequiredForQuic
            | PeerIncompatible::SupportedVersionsExtensionRequired
            | PeerIncompatible::ServerDoesNotSupportTls12Or13
            | PeerIncompatible::ServerTlsVersionIsDisabledByOurConfig,
        )
        | E::AlertReceived(AlertDescription::ProtocolVersion) => HandshakeFailure::ProtocolVersion,
        E::InvalidCertificate(e) => match e {
            CertificateError::UnknownIssuer => HandshakeFailure::UnknownIssuer,
            CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
                HandshakeFailure::Expired
            }
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                HandshakeFailure::NotYetValid
            }
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                HandshakeFailure::NameMismatch
            }
            CertificateError::Revoked => HandshakeFailure::Revoked,
            CertificateError::ApplicationVerificationFailure => HandshakeFailure::UnknownClient,
            CertificateError::Other(other) if other.0.downcast_ref::<NotRootIssued>().is_some() => {
                HandshakeFailure::NotRootIssued
            }
            CertificateError::Other(other)
                if other.0.downcast_ref::<RegistryUnavailable>().is_some() =>
            {
                HandshakeFailure::RegistryUnavailable
            }
            _ => HandshakeFailure::Other,
        },
        E::NoCertificatesPresented | E::AlertReceived(AlertDescription::CertificateRequired) => {
            HandshakeFailure::NoClientCertificate
        }
        E::NoApplicationProtocol | E::AlertReceived(AlertDescription::NoApplicationProtocol) => {
            HandshakeFailure::NoApplicationProtocol
        }
        E::AlertReceived(AlertDescription::UnknownCA) => HandshakeFailure::UnknownIssuer,
        E::AlertReceived(AlertDescription::CertificateExpired) => HandshakeFailure::Expired,
        E::AlertReceived(AlertDescription::CertificateRevoked) => HandshakeFailure::Revoked,
        _ => HandshakeFailure::Other,
    }
}

/// ECDSA P-256 / SHA-256 verification (ASN.1 signatures, as in X.509 and the
/// TLS handshake), the only algorithm accepted.
#[derive(Debug)]
struct EcdsaP256Sha256;

impl SignatureVerificationAlgorithm for EcdsaP256Sha256 {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
            .verify(message, signature)
            .map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P256
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_SHA256
    }
}

static ECDSA_P256_SHA256: EcdsaP256Sha256 = EcdsaP256Sha256;

static SIGNATURE_ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[&ECDSA_P256_SHA256],
    mapping: &[(
        SignatureScheme::ECDSA_NISTP256_SHA256,
        &[&ECDSA_P256_SHA256],
    )],
};

/// The fixed provider: one suite, one group, one signature algorithm.
pub fn provider() -> Arc<CryptoProvider> {
    let base = aws_lc_rs::default_provider();
    Arc::new(CryptoProvider {
        cipher_suites: vec![aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384],
        kx_groups: vec![aws_lc_rs::kx_group::SECP256R1MLKEM768],
        signature_verification_algorithms: SIGNATURE_ALGORITHMS,
        secure_random: base.secure_random,
        key_provider: base.key_provider,
    })
}

pub use rustls::quic::Suite as QuicInitialSuite;

/// The suite QUIC uses for its Initial packets (RFC 9001 section 5.2):
/// AES-128-GCM with keys derived from a public salt and the connection ID.
/// It hides nothing from an observer and carries only the start of the
/// handshake; the handshake and all data use the negotiated
/// `TLS_AES_256_GCM_SHA384`. It is not offered for negotiation.
///
/// # Panics
///
/// Never: the rustls aws-lc-rs provider always has this suite and its QUIC
/// variant.
pub fn quic_initial_suite() -> QuicInitialSuite {
    // The aws-lc-rs TLS 1.3 suite always has a QUIC variant.
    #[expect(
        clippy::expect_used,
        reason = "invariant of the rustls aws-lc-rs provider"
    )]
    aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .and_then(rustls::Tls13CipherSuite::quic_suite)
        .expect("TLS13_AES_128_GCM_SHA256 has a QUIC suite")
}

/// SHA-256 of a certificate (DER): the identity of an agent in the registry.
pub fn fingerprint(certificate: &CertificateDer<'_>) -> [u8; 32] {
    crate::sha256::digest(certificate.as_ref())
}

/// A CA certificate pinned as the only trust anchor.
#[derive(Debug, Clone)]
pub struct TrustAnchor(CertificateDer<'static>);

impl TrustAnchor {
    /// Wraps a DER certificate.
    pub fn from_der(der: CertificateDer<'static>) -> Self {
        Self(der)
    }

    /// Reads the first certificate of a PEM document.
    ///
    /// # Errors
    ///
    /// [`TlsError::Pem`] if there is no readable certificate.
    pub fn from_pem(pem: &[u8]) -> Result<Self, TlsError> {
        CertificateDer::from_pem_slice(pem)
            .map(Self)
            .map_err(|_| TlsError::Pem("aucun certificat PEM lisible"))
    }

    /// The DER certificate.
    pub fn certificate(&self) -> &CertificateDer<'static> {
        &self.0
    }

    fn roots(&self) -> Result<Arc<RootCertStore>, TlsError> {
        roots(std::slice::from_ref(self))
    }
}

fn roots(anchors: &[TrustAnchor]) -> Result<Arc<RootCertStore>, TlsError> {
    let mut roots = RootCertStore::empty();
    for anchor in anchors {
        roots
            .add(anchor.0.clone())
            .map_err(|e| TlsError::Config(e.to_string()))?;
    }
    Ok(Arc::new(roots))
}

/// A certificate chain and its ECDSA P-256 private key. No `Debug`.
pub struct Identity {
    chain: Vec<CertificateDer<'static>>,
    key: SecretBytes,
}

impl Identity {
    /// Builds an identity from a DER chain (end entity first) and a PKCS#8
    /// key.
    ///
    /// # Errors
    ///
    /// [`TlsError::KeyAlgorithm`] if the key is not ECDSA P-256,
    /// [`TlsError::Pem`] for an empty chain.
    pub fn new(chain: Vec<CertificateDer<'static>>, pkcs8: SecretBytes) -> Result<Self, TlsError> {
        if chain.is_empty() {
            return Err(TlsError::Pem("chaîne de certificats vide"));
        }
        p256::SigningKey::from_pkcs8(&pkcs8).map_err(|_| TlsError::KeyAlgorithm)?;
        Ok(Self { chain, key: pkcs8 })
    }

    /// Reads a PEM chain and a PEM PKCS#8 key (`PRIVATE KEY`).
    ///
    /// # Errors
    ///
    /// [`TlsError::Pem`] or [`TlsError::KeyAlgorithm`].
    pub fn from_pem(chain_pem: &[u8], key_pem: &SecretBytes) -> Result<Self, TlsError> {
        let chain = CertificateDer::pem_slice_iter(chain_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| TlsError::Pem("chaîne de certificats PEM illisible"))?;
        // SECRET-EXPOSURE: the PEM document is decoded into a PKCS#8 secret.
        #[expect(clippy::disallowed_methods)]
        let key = PrivatePkcs8KeyDer::from_pem_slice(key_pem.expose_secret())
            .map_err(|_| TlsError::Pem("clé privée PKCS#8 PEM illisible"))?;
        Self::new(chain, SecretBytes::from(key.secret_pkcs8_der().to_vec()))
    }

    /// The end-entity certificate.
    pub fn certificate(&self) -> &CertificateDer<'static> {
        &self.chain[0]
    }

    fn rustls_key(&self) -> PrivateKeyDer<'static> {
        // SECRET-EXPOSURE: rustls keeps its own copy of the key to sign the handshake.
        #[expect(clippy::disallowed_methods)]
        let der = self.key.expose_secret().to_vec();
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der))
    }
}

/// Why the core refuses an agent certificate that chains to its CA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientRefusal {
    /// Not in the registry.
    Unknown,
    /// Revoked.
    Revoked,
    /// The registry cannot be read: refused, never accepted from a stale
    /// copy.
    Unavailable,
}

/// The core registry of agent certificates, consulted at every handshake.
pub trait ClientAuthorizer: Send + Sync + fmt::Debug {
    /// Accepts or refuses the certificate whose SHA-256 is `fingerprint`.
    ///
    /// # Errors
    ///
    /// The reason of the refusal.
    fn authorize(&self, fingerprint: &[u8; 32]) -> Result<(), ClientRefusal>;
}

/// How a server authenticates its clients.
#[derive(Debug, Clone)]
pub enum ClientAuth {
    /// Mandatory certificate from one of `issuing_cas`, then the registry
    /// (tunnel listener).
    Required {
        /// The issuing CAs of agent certificates: the current one, plus the
        /// previous one during a rotation.
        issuing_cas: Vec<TrustAnchor>,
        /// The registry.
        authorizer: Arc<dyn ClientAuthorizer>,
    },
    /// No client certificate (enrolment listener only, ADR-0008).
    None,
}

#[derive(Debug)]
struct RegistryClientVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    authorizer: Arc<dyn ClientAuthorizer>,
}

impl ClientCertVerifier for RegistryClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let verified = self
            .inner
            .verify_client_cert(end_entity, intermediates, now)?;
        match self.authorizer.authorize(&fingerprint(end_entity)) {
            Ok(()) => Ok(verified),
            Err(ClientRefusal::Revoked) => Err(CertificateError::Revoked.into()),
            Err(ClientRefusal::Unknown) => {
                Err(CertificateError::ApplicationVerificationFailure.into())
            }
            Err(ClientRefusal::Unavailable) => Err(CertificateError::Other(rustls::OtherError(
                Arc::new(RegistryUnavailable),
            ))
            .into()),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Accepts only a core certificate signed directly by the pinned root:
/// a chain with an intermediate (such as the online issuing CA) is refused
/// before any other check.
#[derive(Debug)]
struct RootIssuedServerVerifier {
    inner: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for RootIssuedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if !intermediates.is_empty() {
            return Err(
                CertificateError::Other(rustls::OtherError(Arc::new(NotRootIssued))).into(),
            );
        }
        // No intermediate: the only possible chain is end entity -> root.
        self.inner
            .verify_server_cert(end_entity, &[], server_name, ocsp, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// The agent side: trusts only a core certificate signed directly by
/// `root`, presents `identity` if given (absent only for enrolment), offers
/// `alpn`.
///
/// # Errors
///
/// [`TlsError::Config`] if rustls refuses the configuration.
pub fn client_config(
    root: &TrustAnchor,
    identity: Option<&Identity>,
    alpn: &[&[u8]],
) -> Result<Arc<ClientConfig>, TlsError> {
    let provider = provider();
    let inner = WebPkiServerVerifier::builder_with_provider(root.roots()?, provider.clone())
        .build()
        .map_err(|e| TlsError::Config(e.to_string()))?;
    let verifier: Arc<dyn ServerCertVerifier> = Arc::new(RootIssuedServerVerifier { inner });
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError::Config(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut config = match identity {
        Some(id) => builder
            .with_client_auth_cert(id.chain.clone(), id.rustls_key())
            .map_err(|e| TlsError::Config(e.to_string()))?,
        None => builder.with_no_client_auth(),
    };
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(config))
}

/// The core side: presents `identity`, authenticates clients per
/// `client_auth`, accepts only `alpn`.
///
/// # Errors
///
/// [`TlsError::Config`] if rustls refuses the configuration.
pub fn server_config(
    identity: &Identity,
    client_auth: ClientAuth,
    alpn: &[&[u8]],
) -> Result<Arc<ServerConfig>, TlsError> {
    let provider = provider();
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError::Config(e.to_string()))?;
    let builder = match client_auth {
        ClientAuth::Required {
            issuing_cas,
            authorizer,
        } => {
            let inner = WebPkiClientVerifier::builder_with_provider(roots(&issuing_cas)?, provider)
                .build()
                .map_err(|e| TlsError::Config(e.to_string()))?;
            builder
                .with_client_cert_verifier(Arc::new(RegistryClientVerifier { inner, authorizer }))
        }
        ClientAuth::None => builder.with_no_client_auth(),
    };
    let mut config = builder
        .with_single_cert(identity.chain.clone(), identity.rustls_key())
        .map_err(|e| TlsError::Config(e.to_string()))?;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests;

/// Deliberately non-compliant peers, to prove they are refused.
#[cfg(feature = "testing")]
pub mod testing {
    use super::{
        Arc, ClientConfig, Identity, TlsError, TrustAnchor, WebPkiServerVerifier, aws_lc_rs,
    };

    /// What a foreign client offers instead of the fixed parameters.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Offer {
        /// Only X25519 (classical).
        X25519,
        /// Only P-256 (classical).
        Secp256r1,
        /// Only X25519MLKEM768 (hybrid, but not the one we fixed).
        X25519MlKem768,
        /// The right group, but only AES-128-GCM and ChaCha20-Poly1305.
        Aes128Suite,
    }

    /// A client on the stock aws-lc-rs provider, restricted to `offer`, that
    /// trusts `core_ca` and presents `identity`.
    ///
    /// # Errors
    ///
    /// [`TlsError::Config`] if rustls refuses the configuration.
    pub fn foreign_client_config(
        offer: Offer,
        core_ca: &TrustAnchor,
        identity: &Identity,
        alpn: &[&[u8]],
    ) -> Result<Arc<ClientConfig>, TlsError> {
        let mut p = aws_lc_rs::default_provider();
        match offer {
            Offer::X25519 => p.kx_groups = vec![aws_lc_rs::kx_group::X25519],
            Offer::Secp256r1 => p.kx_groups = vec![aws_lc_rs::kx_group::SECP256R1],
            Offer::X25519MlKem768 => p.kx_groups = vec![aws_lc_rs::kx_group::X25519MLKEM768],
            Offer::Aes128Suite => {
                p.kx_groups = vec![aws_lc_rs::kx_group::SECP256R1MLKEM768];
                p.cipher_suites = vec![
                    aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
                    aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                ];
            }
        }
        let p = Arc::new(p);
        let verifier = WebPkiServerVerifier::builder_with_provider(core_ca.roots()?, p.clone())
            .build()
            .map_err(|e| TlsError::Config(e.to_string()))?;
        let mut config = ClientConfig::builder_with_provider(p)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| TlsError::Config(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(identity.chain.clone(), identity.rustls_key())
            .map_err(|e| TlsError::Config(e.to_string()))?;
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Ok(Arc::new(config))
    }
}
