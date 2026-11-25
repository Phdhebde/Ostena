//! The SSH certificate authorities of the core (ADR-0014): user
//! certificates for `ostena login`, host certificates for the SSH servers
//! of the agents. Two distinct P-256 keys, never the grant or audit key.
//!
//! Certificates are made by `ostena_ssh::cert` (without the SSH library)
//! and signed by `ostena-crypto`. Serial numbers are random: a certificate
//! is revoked through its login session or its agent, not by serial.

use ostena_crypto::p256::{SigningKey, VerifyingKey};
use ostena_ssh::cert::{self, Kind, PERMIT_PTY, Template};

use crate::error::CoreError;

/// Tolerated clock difference at the start of a certificate.
const SKEW: u64 = 60;
const DAY: u64 = 86_400;

/// A user certificate issued for a login session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedUserCertificate {
    /// OpenSSH certificate blob.
    pub blob: Vec<u8>,
    /// Its SHA-256, the key of the login session.
    pub sha256: [u8; 32],
}

/// A host certificate issued for an agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedHostCertificate {
    /// OpenSSH certificate blob.
    pub blob: Vec<u8>,
    /// Start of validity, Unix seconds.
    pub valid_after: u64,
    /// End of validity, Unix seconds (exclusive).
    pub valid_before: u64,
}

/// The two SSH authorities and the validity of host certificates.
pub struct SshAuthorities {
    user: SigningKey,
    host: SigningKey,
    host_certificate_secs: u64,
}

impl std::fmt::Debug for SshAuthorities {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshAuthorities")
            .field("host_certificate_secs", &self.host_certificate_secs)
            .finish_non_exhaustive()
    }
}

fn serial() -> Result<u64, CoreError> {
    ostena_crypto::rand::array::<8>()
        .map(u64::from_be_bytes)
        .map_err(|e| CoreError::Keys(format!("aléa : {e}")))
}

fn issue(template: &Template, authority: &SigningKey) -> Result<Vec<u8>, CoreError> {
    cert::issue(template, authority).map_err(|e| CoreError::Keys(e.to_string()))
}

impl SshAuthorities {
    /// The authorities; host certificates last `host_certificate_days`.
    ///
    /// # Errors
    ///
    /// [`CoreError::Keys`] if both keys are the same.
    pub fn new(
        user: SigningKey,
        host: SigningKey,
        host_certificate_days: u32,
    ) -> Result<Self, CoreError> {
        if user.verifying_key() == host.verifying_key() {
            return Err(CoreError::Keys(
                "core.ssh.user_ca_key et core.ssh.host_ca_key : même clé".into(),
            ));
        }
        Ok(Self {
            user,
            host,
            host_certificate_secs: u64::from(host_certificate_days.max(1)) * DAY,
        })
    }

    /// The public key of the user authority.
    pub fn user_ca_public(&self) -> VerifyingKey {
        self.user.verifying_key()
    }

    /// The public key of the host authority.
    pub fn host_ca_public(&self) -> VerifyingKey {
        self.host.verifying_key()
    }

    /// The line users add to their `known_hosts`:
    /// `@cert-authority * ecdsa-sha2-nistp256 AAAA… ostena-host-ca`. The
    /// host names are checked by the client against the principals of the
    /// certificate (the SSH host names of the group).
    pub fn host_ca_openssh_line(&self) -> String {
        format!(
            "@cert-authority * {}",
            ostena_ssh::keys::public_line(&self.host_ca_public(), "ostena-host-ca")
        )
    }

    /// A user certificate for `public`: principal the user, key identifier
    /// the login session, no critical option, `permit-pty` if asked (the
    /// rules of `ostena_ssh::cert::check_user`).
    ///
    /// # Errors
    ///
    /// [`CoreError::Keys`] if the validity is empty or longer than
    /// `ostena_ssh::cert::MAX_USER_VALIDITY_SECS`, or the signature fails.
    pub fn issue_user(
        &self,
        public: &VerifyingKey,
        user: [u8; 16],
        login_session: [u8; 16],
        valid_after: u64,
        valid_before: u64,
        permit_pty: bool,
    ) -> Result<IssuedUserCertificate, CoreError> {
        if valid_before <= valid_after || valid_before - valid_after > cert::MAX_USER_VALIDITY_SECS
        {
            return Err(CoreError::Keys(
                "validité du certificat utilisateur vide ou de plus de 8 heures".into(),
            ));
        }
        let template = Template {
            kind: Kind::User,
            public: *public,
            serial: serial()?,
            key_id: cert::format_uuid(&login_session),
            principals: vec![cert::format_uuid(&user)],
            valid_after,
            valid_before,
            critical_options: Vec::new(),
            extensions: if permit_pty {
                vec![(PERMIT_PTY.to_owned(), Vec::new())]
            } else {
                Vec::new()
            },
        };
        let blob = issue(&template, &self.user)?;
        let sha256 = ostena_crypto::sha256::digest(&blob);
        Ok(IssuedUserCertificate { blob, sha256 })
    }

    /// A host certificate for the SSH server key `public` of `agent`,
    /// valid from `now` (less the clock skew) for the configured days, for
    /// `host_names` (1 to 16).
    ///
    /// # Errors
    ///
    /// [`CoreError::Keys`] for no or too many names, or if the signature
    /// fails.
    pub fn issue_host(
        &self,
        public: &VerifyingKey,
        agent: [u8; 16],
        host_names: &[String],
        now: u64,
    ) -> Result<IssuedHostCertificate, CoreError> {
        if host_names.is_empty() || host_names.len() > cert::MAX_PRINCIPALS {
            return Err(CoreError::Keys(
                "certificat d'hôte : 1 à 16 noms d'hôte attendus".into(),
            ));
        }
        let valid_after = now.saturating_sub(SKEW);
        let valid_before = now.saturating_add(self.host_certificate_secs);
        let template = Template {
            kind: Kind::Host,
            public: *public,
            serial: serial()?,
            key_id: cert::format_uuid(&agent),
            principals: host_names.to_vec(),
            valid_after,
            valid_before,
            critical_options: Vec::new(),
            extensions: Vec::new(),
        };
        Ok(IssuedHostCertificate {
            blob: issue(&template, &self.host)?,
            valid_after,
            valid_before,
        })
    }

    /// Whether a host certificate issued at `issued_at` and valid until
    /// `valid_before` is due for renewal at `now` (two thirds of its life).
    pub fn host_renewal_due(issued_at: u64, valid_before: u64, now: u64) -> bool {
        let life = valid_before.saturating_sub(issued_at);
        now >= issued_at.saturating_add(life / 3 * 2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn authorities() -> SshAuthorities {
        SshAuthorities::new(
            SigningKey::generate().unwrap().0,
            SigningKey::generate().unwrap().0,
            30,
        )
        .unwrap()
    }

    #[test]
    fn user_certificate_passes_the_agent_checks() {
        let ca = authorities();
        let (key, _) = SigningKey::generate().unwrap();
        let issued = ca
            .issue_user(
                &key.verifying_key(),
                [1; 16],
                [2; 16],
                NOW,
                NOW + 3600,
                true,
            )
            .unwrap();
        let parsed = cert::parse(&issued.blob).unwrap();
        parsed.verify(&[ca.user_ca_public()]).unwrap();
        assert!(parsed.verify(&[ca.host_ca_public()]).is_err());
        let identity = cert::check_user(&parsed, NOW).unwrap();
        assert_eq!(identity.subject, [1; 16]);
        assert_eq!(identity.login_session, [2; 16]);
        assert!(identity.allow_pty);
        assert_eq!(identity.certificate_sha256, issued.sha256);
        let no_pty = ca
            .issue_user(&key.verifying_key(), [1; 16], [2; 16], NOW, NOW + 60, false)
            .unwrap();
        assert!(
            !cert::check_user(&cert::parse(&no_pty.blob).unwrap(), NOW)
                .unwrap()
                .allow_pty
        );
    }

    #[test]
    fn user_certificate_validity_is_bounded() {
        let ca = authorities();
        let key = SigningKey::generate().unwrap().0.verifying_key();
        for (after, before) in [(NOW, NOW), (NOW, NOW - 1), (NOW, NOW + 9 * 3600)] {
            assert_eq!(
                ca.issue_user(&key, [1; 16], [2; 16], after, before, false)
                    .unwrap_err()
                    .code(),
                "CORE-E006"
            );
        }
    }

    #[test]
    fn host_certificate_passes_the_agent_checks() {
        let ca = authorities();
        let (key, _) = SigningKey::generate().unwrap();
        let names = vec!["bastion.example".to_owned(), "bastion".to_owned()];
        let issued = ca
            .issue_host(&key.verifying_key(), [3; 16], &names, NOW)
            .unwrap();
        assert_eq!(issued.valid_before, NOW + 30 * DAY);
        let parsed = cert::parse(&issued.blob).unwrap();
        parsed.verify(&[ca.host_ca_public()]).unwrap();
        cert::check_host(&parsed, &key.verifying_key(), NOW).unwrap();
        assert_eq!(parsed.principals, ["bastion.example", "bastion"]);
        assert!(
            ca.issue_host(&key.verifying_key(), [3; 16], &[], NOW)
                .is_err()
        );
    }

    #[test]
    fn renewal_is_due_after_two_thirds() {
        let day = DAY;
        assert!(!SshAuthorities::host_renewal_due(0, 30 * day, 19 * day));
        assert!(SshAuthorities::host_renewal_due(0, 30 * day, 20 * day));
        assert!(SshAuthorities::host_renewal_due(0, 30 * day, 40 * day));
    }

    #[test]
    fn same_key_twice_is_refused_and_lines_are_openssh() {
        let (key, pkcs8) = SigningKey::generate().unwrap();
        let again = SigningKey::from_pkcs8(&pkcs8).unwrap();
        assert!(SshAuthorities::new(key, again, 30).is_err());
        let line = authorities().host_ca_openssh_line();
        assert!(line.starts_with("@cert-authority * ecdsa-sha2-nistp256 AAAA"));
        assert!(line.ends_with(" ostena-host-ca"));
    }
}
