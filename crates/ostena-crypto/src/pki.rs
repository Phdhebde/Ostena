//! X.509 issuance for the tunnel (ADR-0008, ADR-0009): the core CA, the core
//! server certificate and the agent certificates, all ECDSA P-256 / SHA-256.
//!
//! An agent certificate is issued for a public key the agent generated
//! itself: its private key never leaves the agent. The core identifies an
//! agent by the SHA-256 of its certificate ([`crate::tls::fingerprint`]); the
//! names in the certificate are informative.

use ostena_common::secret::SecretBytes;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PublicKeyData, SanType, SerialNumber,
    SignatureAlgorithm,
};
use time::OffsetDateTime;

use crate::p256;
use crate::tls::{CertificateDer, Identity, TrustAnchor};

/// PKI errors, coarse on purpose.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PkiError {
    /// Validity bounds out of range or inverted.
    #[error("période de validité invalide")]
    Validity,
    /// A name is not a valid DNS name or IP address.
    #[error("nom de certificat invalide : {0}")]
    Name(String),
    /// Key generation, loading or signature failed.
    #[error("échec de l'émission du certificat")]
    Issuance,
}

/// Validity period, in Unix seconds (`not_after` included).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    /// Start.
    pub not_before: u64,
    /// End.
    pub not_after: u64,
}

impl Validity {
    fn apply(self, params: &mut CertificateParams) -> Result<(), PkiError> {
        let at = |t: u64| {
            i64::try_from(t)
                .ok()
                .and_then(|t| OffsetDateTime::from_unix_timestamp(t).ok())
                .ok_or(PkiError::Validity)
        };
        if self.not_after <= self.not_before {
            return Err(PkiError::Validity);
        }
        params.not_before = at(self.not_before)?;
        params.not_after = at(self.not_after)?;
        Ok(())
    }
}

/// An agent public key, as rcgen expects it.
struct AgentPublicKey([u8; p256::PUBLIC_KEY_LEN]);

impl PublicKeyData for AgentPublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

fn random_serial() -> Result<SerialNumber, PkiError> {
    let mut bytes = crate::rand::array::<16>().map_err(|_| PkiError::Issuance)?;
    // Positive and non-zero, as RFC 5280 requires.
    bytes[0] = (bytes[0] & 0x7f) | 0x01;
    Ok(SerialNumber::from_slice(&bytes))
}

fn ca_params(common_name: &str) -> CertificateParams {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
}

/// The core CA. No `Debug`, no `Clone`.
pub struct CertificateAuthority {
    params: CertificateParams,
    key: KeyPair,
    certificate: CertificateDer<'static>,
}

impl CertificateAuthority {
    /// Generates a CA key and its self-signed certificate.
    ///
    /// # Errors
    ///
    /// [`PkiError::Validity`] or [`PkiError::Issuance`].
    pub fn generate(common_name: &str, validity: Validity) -> Result<Self, PkiError> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|_| PkiError::Issuance)?;
        let mut params = ca_params(common_name);
        validity.apply(&mut params)?;
        params.serial_number = Some(random_serial()?);
        let certificate = params
            .self_signed(&key)
            .map_err(|_| PkiError::Issuance)?
            .der()
            .clone();
        Ok(Self {
            params,
            key,
            certificate,
        })
    }

    /// Reloads a CA from its common name, PKCS#8 key and certificate.
    ///
    /// # Errors
    ///
    /// [`PkiError::Issuance`] if the key is not ECDSA P-256.
    pub fn from_parts(
        common_name: &str,
        pkcs8: &SecretBytes,
        certificate: CertificateDer<'static>,
    ) -> Result<Self, PkiError> {
        // SECRET-EXPOSURE: the CA key is loaded by rcgen to sign certificates.
        #[expect(clippy::disallowed_methods)]
        let key = KeyPair::try_from(pkcs8.expose_secret()).map_err(|_| PkiError::Issuance)?;
        if key.algorithm() != &PKCS_ECDSA_P256_SHA256 {
            return Err(PkiError::Issuance);
        }
        Ok(Self {
            params: ca_params(common_name),
            key,
            certificate,
        })
    }

    /// The PKCS#8 encoding of the CA key, to be stored as a secret.
    pub fn key_pkcs8(&self) -> SecretBytes {
        SecretBytes::from(self.key.serialize_der())
    }

    /// The CA certificate, to pin on the other side.
    pub fn trust_anchor(&self) -> TrustAnchor {
        TrustAnchor::from_der(self.certificate.clone())
    }

    /// The CA certificate in PEM.
    pub fn certificate_pem(&self) -> String {
        pem_certificate(&self.certificate)
    }

    fn issuer(&self) -> Issuer<'_, &KeyPair> {
        Issuer::from_params(&self.params, &self.key)
    }

    /// Issues the core server certificate for `names` (DNS names or IP
    /// addresses), with a fresh key.
    ///
    /// # Errors
    ///
    /// [`PkiError::Name`], [`PkiError::Validity`] or [`PkiError::Issuance`].
    pub fn issue_server(&self, names: &[&str], validity: Validity) -> Result<Identity, PkiError> {
        let (key, pkcs8) = p256::SigningKey::generate().map_err(|_| PkiError::Issuance)?;
        let mut params = CertificateParams::default();
        params.subject_alt_names = names.iter().map(|n| san(n)).collect::<Result<_, _>>()?;
        let mut dn = DistinguishedName::new();
        dn.push(
            DnType::CommonName,
            names.first().copied().unwrap_or("ostena-core"),
        );
        params.distinguished_name = dn;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        validity.apply(&mut params)?;
        params.serial_number = Some(random_serial()?);
        let public = AgentPublicKey(key.verifying_key().to_bytes());
        let cert = params
            .signed_by(&public, &self.issuer())
            .map_err(|_| PkiError::Issuance)?;
        Identity::new(vec![cert.der().clone()], pkcs8).map_err(|_| PkiError::Issuance)
    }

    /// Issues an agent certificate for `public_key`, bound to its gateway
    /// group: SAN URIs `urn:ostena:gateway-group:<group>` and
    /// `urn:ostena:agent:<agent>`, client authentication only.
    ///
    /// # Errors
    ///
    /// [`PkiError::Validity`] or [`PkiError::Issuance`].
    pub fn issue_agent(
        &self,
        public_key: &p256::VerifyingKey,
        gateway_group: &str,
        agent: &str,
        validity: Validity,
    ) -> Result<CertificateDer<'static>, PkiError> {
        let mut params = CertificateParams::default();
        let uri = |s: String| {
            s.try_into()
                .map(SanType::URI)
                .map_err(|_| PkiError::Name(String::new()))
        };
        params.subject_alt_names = vec![
            uri(format!("urn:ostena:gateway-group:{gateway_group}"))?,
            uri(format!("urn:ostena:agent:{agent}"))?,
        ];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, format!("ostena-agent {agent}"));
        params.distinguished_name = dn;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        validity.apply(&mut params)?;
        params.serial_number = Some(random_serial()?);
        let cert = params
            .signed_by(&AgentPublicKey(public_key.to_bytes()), &self.issuer())
            .map_err(|_| PkiError::Issuance)?;
        Ok(cert.der().clone())
    }
}

fn san(name: &str) -> Result<SanType, PkiError> {
    if let Ok(ip) = name.parse() {
        return Ok(SanType::IpAddress(ip));
    }
    // The same DNS name rules as the verifier, stricter than an IA5String.
    match crate::tls::ServerName::try_from(name) {
        Ok(crate::tls::ServerName::DnsName(_)) => name
            .to_owned()
            .try_into()
            .map(SanType::DnsName)
            .map_err(|_| PkiError::Name(name.to_owned())),
        _ => Err(PkiError::Name(name.to_owned())),
    }
}

/// A certificate in PEM.
pub fn pem_certificate(certificate: &CertificateDer<'_>) -> String {
    use base64::Engine;
    let body = base64::engine::general_purpose::STANDARD.encode(certificate.as_ref());
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    // base64 output is ASCII, so every 64-byte chunk is valid UTF-8.
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

#[cfg(test)]
mod tests;
