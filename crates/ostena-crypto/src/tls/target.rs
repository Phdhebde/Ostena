//! TLS towards the RDP targets (ADR-0019 section 3, ADR-0009 « écart RDP »).
//!
//! Windows targets offer neither ML-KEM nor, for 2016 and 2019, TLS 1.3 for
//! RDP: the frozen tunnel profile cannot apply. This profile is confined to
//! the RDP driver and fixed here, never negotiable by a target or a grant:
//!
//! - protocol: TLS 1.3 when the target offers it, else TLS 1.2 with the
//!   *extended master secret* required; no resumption, no 0-RTT;
//! - cipher suites: `TLS13_AES_256_GCM_SHA384`,
//!   `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`,
//!   `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`;
//! - groups: P-256 and P-384;
//! - certificate keys and handshake signatures: RSA of 2048 to 8192 bits
//!   (PKCS#1 v1.5 with SHA-256/384/512 in TLS 1.2, PSS), ECDSA P-256 /
//!   SHA-256.
//!
//! The target certificate is validated before anything else, in one of two
//! ways ([`TargetTrust`]):
//!
//! - **pinned**: the SHA-256 of the DER certificate must equal the pin, in
//!   constant time; the chain is not looked at, the handshake signature
//!   still is (proof of possession of the key);
//! - **PKI**: chain to the configured CA bundle only (never the public or
//!   system roots), the target DNS name in the SAN, `serverAuth` usage,
//!   dates. No revocation check (known limit, ADR-0019).
//!
//! [`TargetCheck`] tells the caller what was presented (to report a pin
//! mismatch with the presented fingerprint) and, once verified, the
//! `subjectPublicKey` that CredSSP binds to the session ([MS-CSSP]): the
//! RDP driver never reads the certificate itself.

use std::sync::{Arc, Mutex, PoisonError};

use ::aws_lc_rs::signature::{
    self as sig, ECDSA_P256_SHA256_ASN1, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA512, RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA384,
    RSA_PSS_2048_8192_SHA512, UnparsedPublicKey,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{Resumption, WebPkiServerVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms, aws_lc_rs};
use rustls::pki_types::{
    AlgorithmIdentifier, CertificateDer, InvalidSignature, ServerName,
    SignatureVerificationAlgorithm, UnixTime, alg_id,
};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, SignatureScheme};

use super::{TlsError, TrustAnchor, roots};

/// A signature algorithm accepted from an RDP target.
#[derive(Debug)]
struct TargetAlgorithm {
    verify: &'static dyn sig::VerificationAlgorithm,
    public_key: AlgorithmIdentifier,
    signature: AlgorithmIdentifier,
}

impl SignatureVerificationAlgorithm for TargetAlgorithm {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        UnparsedPublicKey::new(self.verify, public_key)
            .verify(message, signature)
            .map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.public_key
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature
    }
}

static RSA_PKCS1_SHA256: TargetAlgorithm = TargetAlgorithm {
    verify: &RSA_PKCS1_2048_8192_SHA256,
    public_key: alg_id::RSA_ENCRYPTION,
    signature: alg_id::RSA_PKCS1_SHA256,
};
static RSA_PKCS1_SHA384: TargetAlgorithm = TargetAlgorithm {
    verify: &RSA_PKCS1_2048_8192_SHA384,
    public_key: alg_id::RSA_ENCRYPTION,
    signature: alg_id::RSA_PKCS1_SHA384,
};
static RSA_PKCS1_SHA512: TargetAlgorithm = TargetAlgorithm {
    verify: &RSA_PKCS1_2048_8192_SHA512,
    public_key: alg_id::RSA_ENCRYPTION,
    signature: alg_id::RSA_PKCS1_SHA512,
};
static RSA_PSS_SHA256: TargetAlgorithm = TargetAlgorithm {
    verify: &RSA_PSS_2048_8192_SHA256,
    public_key: alg_id::RSA_ENCRYPTION,
    signature: alg_id::RSA_PSS_SHA256,
};
static RSA_PSS_SHA384: TargetAlgorithm = TargetAlgorithm {
    verify: &RSA_PSS_2048_8192_SHA384,
    public_key: alg_id::RSA_ENCRYPTION,
    signature: alg_id::RSA_PSS_SHA384,
};
static RSA_PSS_SHA512: TargetAlgorithm = TargetAlgorithm {
    verify: &RSA_PSS_2048_8192_SHA512,
    public_key: alg_id::RSA_ENCRYPTION,
    signature: alg_id::RSA_PSS_SHA512,
};
static ECDSA_P256_SHA256: TargetAlgorithm = TargetAlgorithm {
    verify: &ECDSA_P256_SHA256_ASN1,
    public_key: alg_id::ECDSA_P256,
    signature: alg_id::ECDSA_SHA256,
};

pub(super) static TARGET_ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        &ECDSA_P256_SHA256,
        &RSA_PSS_SHA256,
        &RSA_PSS_SHA384,
        &RSA_PSS_SHA512,
        &RSA_PKCS1_SHA256,
        &RSA_PKCS1_SHA384,
        &RSA_PKCS1_SHA512,
    ],
    mapping: &[
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[&ECDSA_P256_SHA256],
        ),
        (SignatureScheme::RSA_PSS_SHA256, &[&RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PSS_SHA384, &[&RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA512, &[&RSA_PSS_SHA512]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[&RSA_PKCS1_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[&RSA_PKCS1_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA512, &[&RSA_PKCS1_SHA512]),
    ],
};

/// The fixed provider of the RDP target profile.
pub fn target_provider() -> Arc<CryptoProvider> {
    let base = aws_lc_rs::default_provider();
    Arc::new(CryptoProvider {
        cipher_suites: vec![
            aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
            aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ],
        kx_groups: vec![
            aws_lc_rs::kx_group::SECP256R1,
            aws_lc_rs::kx_group::SECP384R1,
        ],
        signature_verification_algorithms: TARGET_ALGORITHMS,
        secure_random: base.secure_random,
        key_provider: base.key_provider,
    })
}

/// How the certificate of a target is trusted.
#[derive(Debug, Clone)]
pub enum TargetTrust {
    /// SHA-256 of the DER certificate, from the inventory.
    Pinned([u8; 32]),
    /// The CA bundle of the customer (`rdp.pki_ca_bundle`).
    Pki(Vec<TrustAnchor>),
}

/// What the verifier saw: the presented certificate and, once verified,
/// its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentedCertificate {
    /// SHA-256 of the DER certificate presented by the target.
    pub fingerprint: [u8; 32],
    /// Whether it passed the verification (pin or PKI).
    pub verified: bool,
    /// `subjectPublicKey` (the content of the BIT STRING, without the
    /// unused-bits octet), for CredSSP; empty if unreadable.
    pub subject_public_key: Vec<u8>,
}

/// Shared with the verifier of one connection: what the target presented.
#[derive(Debug, Clone, Default)]
pub struct TargetCheck(Arc<Mutex<Option<PresentedCertificate>>>);

impl TargetCheck {
    /// The certificate presented, if the handshake got that far.
    pub fn presented(&self) -> Option<PresentedCertificate> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The `subjectPublicKey` of the verified certificate; `None` if the
    /// certificate was not verified.
    pub fn verified_public_key(&self) -> Option<Vec<u8>> {
        self.presented()
            .filter(|p| p.verified && !p.subject_public_key.is_empty())
            .map(|p| p.subject_public_key)
    }

    fn record(&self, presented: PresentedCertificate) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(presented);
    }
}

/// Refusal text of a certificate that is not the pinned one.
pub const PIN_MISMATCH: &str = "target certificate does not match the pinned fingerprint";

struct PinMismatch;

impl std::fmt::Debug for PinMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(PIN_MISMATCH)
    }
}

impl std::fmt::Display for PinMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(PIN_MISMATCH)
    }
}

impl std::error::Error for PinMismatch {}

/// Whether a handshake error is the refusal of a non-pinned certificate.
pub fn is_pin_mismatch(error: &rustls::Error) -> bool {
    matches!(
        error,
        rustls::Error::InvalidCertificate(CertificateError::Other(other))
            if other.0.downcast_ref::<PinMismatch>().is_some()
    )
}

#[derive(Debug)]
enum Trust {
    Pinned([u8; 32]),
    Pki(Arc<WebPkiServerVerifier>),
}

#[derive(Debug)]
struct TargetVerifier {
    trust: Trust,
    check: TargetCheck,
}

impl ServerCertVerifier for TargetVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fingerprint = super::fingerprint(end_entity);
        let subject_public_key = subject_public_key(end_entity.as_ref())
            .map(<[u8]>::to_vec)
            .unwrap_or_default();
        let verdict = match &self.trust {
            Trust::Pinned(pin) => {
                if crate::constant_time_eq(pin, &fingerprint) {
                    Ok(ServerCertVerified::assertion())
                } else {
                    Err(CertificateError::Other(rustls::OtherError(Arc::new(PinMismatch))).into())
                }
            }
            Trust::Pki(inner) => {
                inner.verify_server_cert(end_entity, intermediates, server_name, ocsp, now)
            }
        };
        // A key CredSSP cannot bind is refused like a bad certificate.
        let verdict = verdict.and_then(|ok| {
            if subject_public_key.is_empty() {
                Err(CertificateError::BadEncoding.into())
            } else {
                Ok(ok)
            }
        });
        self.check.record(PresentedCertificate {
            fingerprint,
            verified: verdict.is_ok(),
            subject_public_key,
        });
        verdict
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &TARGET_ALGORITHMS)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &TARGET_ALGORITHMS)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        TARGET_ALGORITHMS.supported_schemes()
    }
}

/// The client configuration towards one RDP target, and what its verifier
/// will see.
///
/// # Errors
///
/// [`TlsError::Config`] if rustls refuses the configuration or the CA
/// bundle (empty, or a certificate it cannot read).
pub fn target_client_config(
    trust: &TargetTrust,
) -> Result<(Arc<ClientConfig>, TargetCheck), TlsError> {
    let provider = target_provider();
    let trust = match trust {
        TargetTrust::Pinned(pin) => Trust::Pinned(*pin),
        TargetTrust::Pki(anchors) => {
            if anchors.is_empty() {
                return Err(TlsError::Config(
                    "aucune autorité de la PKI des cibles".into(),
                ));
            }
            Trust::Pki(
                WebPkiServerVerifier::builder_with_provider(roots(anchors)?, provider.clone())
                    .build()
                    .map_err(|e| TlsError::Config(e.to_string()))?,
            )
        }
    };
    let check = TargetCheck::default();
    let verifier = Arc::new(TargetVerifier {
        trust,
        check: check.clone(),
    });
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| TlsError::Config(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    config.require_ems = true;
    config.enable_sni = true;
    Ok((Arc::new(config), check))
}

/// Reads every certificate of a PEM bundle (the customer CA of the
/// targets).
///
/// # Errors
///
/// [`TlsError::Pem`] if the bundle holds no readable certificate.
pub fn anchors_from_pem(pem: &[u8]) -> Result<Vec<TrustAnchor>, TlsError> {
    use rustls::pki_types::pem::PemObject;
    let anchors = CertificateDer::pem_slice_iter(pem)
        .map(|c| c.map(TrustAnchor::from_der))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TlsError::Pem("lot d'autorités PEM illisible"))?;
    if anchors.is_empty() {
        return Err(TlsError::Pem("aucun certificat dans le lot d'autorités"));
    }
    Ok(anchors)
}

/// The content of `subjectPublicKeyInfo.subjectPublicKey` (after the
/// unused-bits octet, which must be zero), with a strict DER walk.
pub fn subject_public_key(der: &[u8]) -> Option<&[u8]> {
    use crate::pki::der_element;
    let (certificate, _) = der_element(der, 0x30)?;
    let (tbs, _) = der_element(certificate, 0x30)?;
    let mut rest = tbs;
    if rest.first() == Some(&0xa0) {
        rest = der_element(rest, 0xa0)?.1;
    }
    let (_, rest) = der_element(rest, 0x02)?; // serialNumber
    let (_, rest) = der_element(rest, 0x30)?; // signature
    let (_, rest) = der_element(rest, 0x30)?; // issuer
    let (_, rest) = der_element(rest, 0x30)?; // validity
    let (_, rest) = der_element(rest, 0x30)?; // subject
    let (spki, _) = der_element(rest, 0x30)?;
    let (_, spki) = der_element(spki, 0x30)?; // algorithm
    let (bits, _) = der_element(spki, 0x03)?;
    match bits.split_first()? {
        (&0, key) if !key.is_empty() => Some(key),
        _ => None,
    }
}

/// Test targets (tests and feature `testing` only): a TLS server shaped
/// like a Windows RDP listener.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use std::sync::Arc;

    use ostena_common::secret::SecretBytes;
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose, SanType,
    };
    use rustls::crypto::aws_lc_rs;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ServerConfig, SupportedProtocolVersion};

    use crate::tls::{TlsError, TrustAnchor};

    /// The key of a test target certificate.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum KeyKind {
        /// RSA 2048, signed with SHA-256 (the self-signed Windows default).
        Rsa2048,
        /// ECDSA P-256.
        EcdsaP256,
        /// ECDSA P-384, outside the profile.
        EcdsaP384,
    }

    /// A target certificate and its key.
    pub struct TargetIdentity {
        /// DER certificate.
        pub certificate: CertificateDer<'static>,
        /// PKCS#8 key.
        pub key: SecretBytes,
    }

    impl TargetIdentity {
        /// SHA-256 of the certificate, as pinned in the inventory.
        pub fn fingerprint(&self) -> [u8; 32] {
            crate::tls::fingerprint(&self.certificate)
        }
    }

    /// A test CA of the customer.
    pub struct TargetCa {
        params: CertificateParams,
        key: KeyPair,
        /// Its certificate.
        pub certificate: CertificateDer<'static>,
    }

    fn err(e: impl std::fmt::Display) -> TlsError {
        TlsError::Config(e.to_string())
    }

    fn key_pair(kind: KeyKind) -> Result<KeyPair, TlsError> {
        match kind {
            KeyKind::Rsa2048 => KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256),
            KeyKind::EcdsaP256 => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256),
            KeyKind::EcdsaP384 => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384),
        }
        .map_err(err)
    }

    fn params(name: &str, names: &[&str]) -> Result<CertificateParams, TlsError> {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, name);
        params.distinguished_name = dn;
        params.subject_alt_names = names
            .iter()
            .map(|n| {
                n.parse::<std::net::IpAddr>().map_or_else(
                    |_| n.to_string().try_into().map(SanType::DnsName).map_err(err),
                    |ip| Ok(SanType::IpAddress(ip)),
                )
            })
            .collect::<Result<_, _>>()?;
        Ok(params)
    }

    impl TargetCa {
        /// A fresh CA.
        ///
        /// # Errors
        ///
        /// If the key or the certificate cannot be produced.
        pub fn new(name: &str) -> Result<Self, TlsError> {
            let key = key_pair(KeyKind::EcdsaP256)?;
            let mut params = params(name, &[])?;
            params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
            let certificate = params.self_signed(&key).map_err(err)?.der().clone();
            Ok(Self {
                params,
                key,
                certificate,
            })
        }

        /// The anchor of the PKI mode.
        pub fn anchor(&self) -> TrustAnchor {
            TrustAnchor::from_der(self.certificate.clone())
        }

        /// A target certificate for `names`, with `usage` (`None`: no
        /// extended key usage).
        ///
        /// # Errors
        ///
        /// If the key or the certificate cannot be produced.
        pub fn issue(
            &self,
            kind: KeyKind,
            names: &[&str],
            usage: Option<ExtendedKeyUsagePurpose>,
        ) -> Result<TargetIdentity, TlsError> {
            let key = key_pair(kind)?;
            let mut params = params(names.first().copied().unwrap_or("target"), names)?;
            params.extended_key_usages = usage.into_iter().collect();
            let issuer = rcgen::Issuer::from_params(&self.params, &self.key);
            let certificate = params.signed_by(&key, &issuer).map_err(err)?.der().clone();
            Ok(TargetIdentity {
                certificate,
                key: SecretBytes::from(key.serialize_der()),
            })
        }
    }

    /// A self-signed target certificate, as Windows makes for RDP.
    ///
    /// # Errors
    ///
    /// If the key or the certificate cannot be produced.
    pub fn self_signed(kind: KeyKind, name: &str) -> Result<TargetIdentity, TlsError> {
        let key = key_pair(kind)?;
        let mut params = params(name, &[name])?;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let certificate = params.self_signed(&key).map_err(err)?.der().clone();
        Ok(TargetIdentity {
            certificate,
            key: SecretBytes::from(key.serialize_der()),
        })
    }

    /// Re-exported for [`TargetCa::issue`].
    pub use rcgen::ExtendedKeyUsagePurpose as Usage;

    /// The protocol versions of a test target.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Versions {
        /// TLS 1.2 only (Windows Server 2016 and 2019).
        Tls12,
        /// TLS 1.3 only.
        Tls13,
        /// Both.
        Both,
    }

    /// A target server on the stock aws-lc-rs provider (what Windows
    /// offers is wider than the profile), presenting `identity`.
    ///
    /// # Errors
    ///
    /// [`TlsError::Config`] if rustls refuses the configuration.
    pub fn server_config(
        identity: &TargetIdentity,
        versions: Versions,
    ) -> Result<Arc<ServerConfig>, TlsError> {
        let v: &[&'static SupportedProtocolVersion] = match versions {
            Versions::Tls12 => &[&rustls::version::TLS12],
            Versions::Tls13 => &[&rustls::version::TLS13],
            Versions::Both => &[&rustls::version::TLS13, &rustls::version::TLS12],
        };
        // SECRET-EXPOSURE: rustls keeps its own copy of the test key.
        #[expect(clippy::disallowed_methods)]
        let der = identity.key.expose_secret().to_vec();
        ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
            .with_protocol_versions(v)
            .map_err(err)?
            .with_no_client_auth()
            .with_single_cert(
                vec![identity.certificate.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)),
            )
            .map(Arc::new)
            .map_err(err)
    }

    /// A server restricted to suites outside the profile (AES-128 and
    /// ChaCha20 only), to prove the refusal.
    ///
    /// # Errors
    ///
    /// [`TlsError::Config`] if rustls refuses the configuration.
    pub fn weak_server_config(identity: &TargetIdentity) -> Result<Arc<ServerConfig>, TlsError> {
        let mut provider = aws_lc_rs::default_provider();
        provider.cipher_suites = vec![
            aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
            aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        ];
        // SECRET-EXPOSURE: rustls keeps its own copy of the test key.
        #[expect(clippy::disallowed_methods)]
        let der = identity.key.expose_secret().to_vec();
        ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(err)?
            .with_no_client_auth()
            .with_single_cert(
                vec![identity.certificate.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)),
            )
            .map(Arc::new)
            .map_err(err)
    }
}

#[cfg(test)]
mod tests;
