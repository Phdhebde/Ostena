//! A complete test PKI (tests and feature `testing` only): root, issuing CA,
//! core server certificate, agent certificates.

use ostena_common::secret::SecretBytes;

use super::{IssuingAuthority, PkiError, RootAuthority, Validity};
use crate::p256;
use crate::tls::{CertificateDer, Identity, TrustAnchor};

const DAY: u64 = 86_400;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Valid from yesterday for 30 days.
pub fn valid() -> Validity {
    Validity {
        not_before: now().saturating_sub(DAY),
        not_after: now() + 30 * DAY,
    }
}

/// Root, issuing CA and their material, as after a ceremony.
pub struct TestPki {
    /// The offline root.
    pub root: RootAuthority,
    /// The online issuing CA.
    pub issuing: IssuingAuthority,
    /// The issuing CA certificate.
    pub issuing_certificate: CertificateDer<'static>,
    /// The issuing CA key (PKCS#8).
    pub issuing_key: SecretBytes,
}

impl TestPki {
    /// A fresh PKI whose names start with `name`.
    ///
    /// # Errors
    ///
    /// If a key or a certificate cannot be produced.
    pub fn new(name: &str) -> Result<Self, PkiError> {
        let root = RootAuthority::generate(&format!("{name} root"), valid())?;
        let (key, issuing_key) = p256::SigningKey::generate().map_err(|_| PkiError::Issuance)?;
        let issuing_name = format!("{name} issuing");
        let issuing_certificate =
            root.sign_issuing(&key.verifying_key(), &issuing_name, valid())?;
        let issuing =
            IssuingAuthority::from_parts(&issuing_name, &issuing_key, issuing_certificate.clone())?;
        Ok(Self {
            root,
            issuing,
            issuing_certificate,
            issuing_key,
        })
    }

    /// The anchor the agents pin.
    pub fn root_anchor(&self) -> TrustAnchor {
        self.root.trust_anchor()
    }

    /// The anchor the core trusts for agent certificates.
    pub fn issuing_anchor(&self) -> TrustAnchor {
        self.issuing.trust_anchor()
    }

    /// A core server identity for `names`, signed by the root.
    ///
    /// # Errors
    ///
    /// If a key or a certificate cannot be produced.
    pub fn server(&self, names: &[&str]) -> Result<Identity, PkiError> {
        let (key, pkcs8) = p256::SigningKey::generate().map_err(|_| PkiError::Issuance)?;
        let cert = self
            .root
            .sign_server(&key.verifying_key(), names, valid())?;
        Identity::new(vec![cert], pkcs8).map_err(|_| PkiError::Issuance)
    }

    /// An agent identity of `group`, issued by the issuing CA.
    ///
    /// # Errors
    ///
    /// If a key or a certificate cannot be produced.
    pub fn agent(&self, group: &str, validity: Validity) -> Result<Identity, PkiError> {
        let (key, pkcs8) = p256::SigningKey::generate().map_err(|_| PkiError::Issuance)?;
        let cert = self
            .issuing
            .issue_agent(&key.verifying_key(), group, "test-agent", validity)?;
        Identity::new(vec![cert], pkcs8).map_err(|_| PkiError::Issuance)
    }

    /// A server certificate for `names` signed by the **issuing CA**, as an
    /// attacker holding its key would make it, with its chain
    /// `[server, issuing CA]`. Must be refused by the agents.
    ///
    /// # Errors
    ///
    /// If a key or a certificate cannot be produced.
    pub fn rogue_server(&self, names: &[&str]) -> Result<Identity, PkiError> {
        use rcgen::{ExtendedKeyUsagePurpose, Issuer, KeyPair, KeyUsagePurpose};
        // SECRET-EXPOSURE: test only, plays an attacker who stole the issuing key.
        #[expect(clippy::disallowed_methods)]
        let issuing_key =
            KeyPair::try_from(self.issuing_key.expose_secret()).map_err(|_| PkiError::Issuance)?;
        let issuing_params = super::issuing_params(self.issuing.common_name());
        let issuer = Issuer::from_params(&issuing_params, &issuing_key);
        let (key, pkcs8) = p256::SigningKey::generate().map_err(|_| PkiError::Issuance)?;
        let mut params = super::named(names.first().copied().unwrap_or("core"));
        params.subject_alt_names = names
            .iter()
            .map(|n| super::san(n))
            .collect::<Result<_, _>>()?;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let cert = super::sign(params, valid(), &key.verifying_key(), &issuer)?;
        Identity::new(vec![cert, self.issuing_certificate.clone()], pkcs8)
            .map_err(|_| PkiError::Issuance)
    }
}
