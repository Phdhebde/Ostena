//! X.509 issuance for the tunnel (ADR-0008, ADR-0009), ECDSA P-256 / SHA-256,
//! with separate roles:
//!
//! - the **root**, kept offline, signs the issuing CA and the core server
//!   certificate during a ceremony; the agents pin it;
//! - the **issuing CA**, online on the core, signs agent certificates only:
//!   client authentication only, no sub-CA (`pathLen 0`), and name
//!   constraints that exclude every DNS name and IP address, so that it cannot
//!   produce a valid server certificate. RFC 5280 URI name constraints only
//!   apply to URIs with a host, which `urn:` names do not have: the
//!   restriction to `urn:ostena:` names is enforced here and by the core
//!   registry.
//!
//! An agent or server certificate is issued for a public key generated where
//! it is used: private keys never travel. The core identifies an agent by the
//! SHA-256 of its certificate ([`crate::tls::fingerprint`]).

use ostena_common::secret::SecretBytes;
use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    NameConstraints, PKCS_ECDSA_P256_SHA256, PublicKeyData, SanType, SerialNumber,
    SignatureAlgorithm,
};
use time::OffsetDateTime;

use crate::p256;
use crate::tls::{CertificateDer, TrustAnchor};

/// PKI errors, coarse on purpose.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PkiError {
    /// Validity bounds out of range or inverted.
    #[error("période de validité invalide")]
    Validity,
    /// A name is not a valid DNS name, IP address or Ostena URN part.
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

/// A P-256 public key, as rcgen expects it.
struct P256PublicKey([u8; p256::PUBLIC_KEY_LEN]);

impl PublicKeyData for P256PublicKey {
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

fn named(common_name: &str) -> CertificateParams {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    params
}

fn root_params(common_name: &str) -> CertificateParams {
    let mut params = named(common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
}

pub(crate) fn issuing_params(common_name: &str) -> CertificateParams {
    let mut params = named(common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: Vec::new(),
        excluded_subtrees: vec![
            // The empty DNS constraint matches every DNS name.
            GeneralSubtree::DnsName(String::new()),
            GeneralSubtree::IpAddress(CidrSubnet::V4([0; 4], [0; 4])),
            GeneralSubtree::IpAddress(CidrSubnet::V6([0; 16], [0; 16])),
        ],
    });
    params
}

fn load_key(pkcs8: &SecretBytes) -> Result<KeyPair, PkiError> {
    // SECRET-EXPOSURE: the CA key is loaded by rcgen to sign certificates.
    #[expect(clippy::disallowed_methods)]
    let key = KeyPair::try_from(pkcs8.expose_secret()).map_err(|_| PkiError::Issuance)?;
    if key.algorithm() != &PKCS_ECDSA_P256_SHA256 {
        return Err(PkiError::Issuance);
    }
    Ok(key)
}

fn sign(
    mut params: CertificateParams,
    validity: Validity,
    public_key: &p256::VerifyingKey,
    issuer: &Issuer<'_, &KeyPair>,
) -> Result<CertificateDer<'static>, PkiError> {
    validity.apply(&mut params)?;
    params.serial_number = Some(random_serial()?);
    let cert = params
        .signed_by(&P256PublicKey(public_key.to_bytes()), issuer)
        .map_err(|_| PkiError::Issuance)?;
    Ok(cert.der().clone())
}

/// The offline root. No `Debug`, no `Clone`.
pub struct RootAuthority {
    params: CertificateParams,
    key: KeyPair,
    certificate: CertificateDer<'static>,
}

impl RootAuthority {
    /// Generates the root key and its self-signed certificate.
    ///
    /// # Errors
    ///
    /// [`PkiError::Validity`] or [`PkiError::Issuance`].
    pub fn generate(common_name: &str, validity: Validity) -> Result<Self, PkiError> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|_| PkiError::Issuance)?;
        let mut params = root_params(common_name);
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

    /// Reloads the root from its common name, PKCS#8 key and certificate.
    ///
    /// # Errors
    ///
    /// [`PkiError::Issuance`] if the key is not ECDSA P-256.
    pub fn from_parts(
        common_name: &str,
        pkcs8: &SecretBytes,
        certificate: CertificateDer<'static>,
    ) -> Result<Self, PkiError> {
        Ok(Self {
            params: root_params(common_name),
            key: load_key(pkcs8)?,
            certificate,
        })
    }

    /// The PKCS#8 encoding of the root key, to be sealed.
    pub fn key_pkcs8(&self) -> SecretBytes {
        SecretBytes::from(self.key.serialize_der())
    }

    /// The root certificate, pinned by the agents.
    pub fn trust_anchor(&self) -> TrustAnchor {
        TrustAnchor::from_der(self.certificate.clone())
    }

    /// The root certificate in PEM.
    pub fn certificate_pem(&self) -> String {
        pem_certificate(&self.certificate)
    }

    fn issuer(&self) -> Issuer<'_, &KeyPair> {
        Issuer::from_params(&self.params, &self.key)
    }

    /// Signs the issuing CA certificate for `public_key` (generated on the
    /// core): agent certificates only, see the module documentation.
    ///
    /// # Errors
    ///
    /// [`PkiError::Validity`] or [`PkiError::Issuance`].
    pub fn sign_issuing(
        &self,
        public_key: &p256::VerifyingKey,
        common_name: &str,
        validity: Validity,
    ) -> Result<CertificateDer<'static>, PkiError> {
        sign(
            issuing_params(common_name),
            validity,
            public_key,
            &self.issuer(),
        )
    }

    /// Signs the core server certificate for `public_key` (generated on the
    /// core) and `names` (DNS names or IP addresses): server authentication
    /// only.
    ///
    /// # Errors
    ///
    /// [`PkiError::Name`], [`PkiError::Validity`] or [`PkiError::Issuance`].
    pub fn sign_server(
        &self,
        public_key: &p256::VerifyingKey,
        names: &[&str],
        validity: Validity,
    ) -> Result<CertificateDer<'static>, PkiError> {
        let first = names
            .first()
            .ok_or_else(|| PkiError::Name("aucun nom".into()))?;
        let mut params = named(first);
        params.subject_alt_names = names.iter().map(|n| san(n)).collect::<Result<_, _>>()?;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        sign(params, validity, public_key, &self.issuer())
    }
}

/// The online issuing CA: agent certificates only. No `Debug`, no `Clone`.
pub struct IssuingAuthority {
    common_name: String,
    params: CertificateParams,
    key: KeyPair,
    certificate: CertificateDer<'static>,
}

impl IssuingAuthority {
    /// Loads the issuing CA from its common name, PKCS#8 key and the
    /// certificate the root signed.
    ///
    /// # Errors
    ///
    /// [`PkiError::Issuance`] if the key is not ECDSA P-256.
    pub fn from_parts(
        common_name: &str,
        pkcs8: &SecretBytes,
        certificate: CertificateDer<'static>,
    ) -> Result<Self, PkiError> {
        Ok(Self {
            common_name: common_name.to_owned(),
            params: issuing_params(common_name),
            key: load_key(pkcs8)?,
            certificate,
        })
    }

    /// Its common name.
    pub fn common_name(&self) -> &str {
        &self.common_name
    }

    /// The issuing CA certificate: the core trusts agent certificates that
    /// chain to it.
    pub fn trust_anchor(&self) -> TrustAnchor {
        TrustAnchor::from_der(self.certificate.clone())
    }

    /// Issues an agent certificate for `public_key`, bound to its gateway
    /// group: SAN URIs `urn:ostena:gateway-group:<group>` and
    /// `urn:ostena:agent:<agent>`, client authentication only.
    ///
    /// # Errors
    ///
    /// [`PkiError::Name`] unless both identifiers are made of lowercase
    /// letters, digits and dashes (UUIDs), [`PkiError::Validity`] or
    /// [`PkiError::Issuance`].
    pub fn issue_agent(
        &self,
        public_key: &p256::VerifyingKey,
        gateway_group: &str,
        agent: &str,
        validity: Validity,
    ) -> Result<CertificateDer<'static>, PkiError> {
        let urn_part = |s: &str| {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        };
        if !urn_part(gateway_group) || !urn_part(agent) {
            return Err(PkiError::Name(format!("{gateway_group} / {agent}")));
        }
        let uri = |s: String| {
            s.try_into()
                .map(SanType::URI)
                .map_err(|_| PkiError::Name(String::new()))
        };
        let mut params = named(&format!("ostena-agent {agent}"));
        params.subject_alt_names = vec![
            uri(format!("urn:ostena:gateway-group:{gateway_group}"))?,
            uri(format!("urn:ostena:agent:{agent}"))?,
        ];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        sign(
            params,
            validity,
            public_key,
            &Issuer::from_params(&self.params, &self.key),
        )
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

fn pem(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    // base64 output is ASCII, so every 64-byte chunk is valid UTF-8.
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

/// A certificate in PEM.
pub fn pem_certificate(certificate: &CertificateDer<'_>) -> String {
    pem("CERTIFICATE", certificate)
}

/// A PKCS#8 private key in PEM (`PRIVATE KEY`), still a secret.
pub fn pem_private_key(pkcs8: &SecretBytes) -> SecretBytes {
    // SECRET-EXPOSURE: encoded into a new secret, written to a 0600 file.
    #[expect(clippy::disallowed_methods)]
    let text = pem("PRIVATE KEY", pkcs8.expose_secret());
    SecretBytes::from(text.into_bytes())
}

/// First line of a public key file.
const PUBLIC_KEY_HEADER: &str = "ostena-p256-public-key-v1";

/// A P-256 public key file: a header line, then the uncompressed SEC1 key in
/// base64url. Moved from the core to the ceremony workstation and back.
pub fn encode_public_key(key: &p256::VerifyingKey) -> String {
    use base64::Engine;
    let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.to_bytes());
    format!("{PUBLIC_KEY_HEADER}\n{body}\n")
}

/// Reads a public key file written by [`encode_public_key`].
///
/// # Errors
///
/// [`PkiError::Name`] for another format, [`PkiError::Issuance`] for a key
/// that is not on the curve.
pub fn decode_public_key(text: &str) -> Result<p256::VerifyingKey, PkiError> {
    use base64::Engine;
    let mut lines = text.lines();
    if lines.next() != Some(PUBLIC_KEY_HEADER) {
        return Err(PkiError::Name(
            "fichier de clé publique Ostena attendu".into(),
        ));
    }
    let raw = lines
        .next()
        .and_then(|b| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(b.trim())
                .ok()
        })
        .ok_or_else(|| PkiError::Name("clé publique illisible".into()))?;
    let bytes: [u8; p256::PUBLIC_KEY_LEN] = raw
        .try_into()
        .map_err(|_| PkiError::Name("clé publique de taille inattendue".into()))?;
    p256::VerifyingKey::from_bytes(&bytes).map_err(|_| PkiError::Issuance)
}

#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "testing"))]
pub mod testing;
