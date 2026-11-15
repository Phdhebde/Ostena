//! What the tunnel carries for native SSH access (ADR-0010).
//!
//! - **Host key**: the agent sends the public host key of its SSH server
//!   with a proof of possession, a signature by that key over a domain
//!   prefix, the SHA-256 of the current tunnel certificate and the key
//!   itself (the model of `renew`). The core certifies it and sends the host
//!   certificate back in [`CoreMessage::SshTrust`](crate::control::CoreMessage).
//! - **Trust**: the user certificate authorities and the host certificate,
//!   pushed by the core, kept by [`GatewayState`](crate::gateway::GatewayState).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ostena_crypto::p256::{self, Signature, SigningKey, VerifyingKey};

use crate::control::{AgentMessage, host_certificate, p256_point};
use crate::error::TunnelError;

const DOMAIN: &[u8] = b"ostena-ssh-host-key-v1\0";

fn message(tunnel_certificate: &[u8; 32], public: &[u8; p256::PUBLIC_KEY_LEN]) -> Vec<u8> {
    let mut m = Vec::with_capacity(DOMAIN.len() + 32 + p256::PUBLIC_KEY_LEN);
    m.extend_from_slice(DOMAIN);
    m.extend_from_slice(tunnel_certificate);
    m.extend_from_slice(public);
    m
}

/// The `ssh_host_key` message for `host_key`, bound to the SHA-256 of the
/// certificate of the tunnel it travels on.
///
/// # Errors
///
/// If the signature fails.
pub fn host_key_message(
    host_key: &SigningKey,
    tunnel_certificate: &[u8; 32],
) -> Result<AgentMessage, TunnelError> {
    let public = host_key.verifying_key().to_bytes();
    let proof = host_key
        .sign(&message(tunnel_certificate, &public))
        .map_err(|e| TunnelError::Io(e.to_string()))?;
    Ok(AgentMessage::SshHostKey {
        p256_public: URL_SAFE_NO_PAD.encode(public),
        proof: URL_SAFE_NO_PAD.encode(proof.to_bytes()),
    })
}

/// Core side: the host key of an `ssh_host_key` message received on the
/// tunnel of the certificate `tunnel_certificate`, after checking the proof
/// of possession.
///
/// # Errors
///
/// [`TunnelError::ProofOfPossession`].
pub fn verify_host_key(
    p256_public: &str,
    proof: &str,
    tunnel_certificate: &[u8; 32],
) -> Result<VerifyingKey, TunnelError> {
    let key = p256_point("p256_public", p256_public).map_err(|_| TunnelError::ProofOfPossession)?;
    let signature: [u8; p256::SIGNATURE_LEN] = URL_SAFE_NO_PAD
        .decode(proof)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(TunnelError::ProofOfPossession)?;
    key.verify(
        &message(tunnel_certificate, &key.to_bytes()),
        &Signature::from_bytes(&signature),
    )
    .map_err(|_| TunnelError::ProofOfPossession)?;
    Ok(key)
}

/// What the core pushed for the SSH server of the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshTrust {
    /// Version applied.
    pub version: u64,
    /// Authorities of the user certificates.
    pub user_cas: Vec<VerifyingKey>,
    /// Host certificate of the agent (OpenSSH blob), if issued.
    pub host_certificate: Option<Vec<u8>>,
}

impl SshTrust {
    /// Decodes a push (already validated as a control message).
    ///
    /// # Errors
    ///
    /// [`TunnelError::Protocol`] for an invalid value.
    pub fn decode(
        version: u64,
        user_cas: &[String],
        certificate: Option<&str>,
    ) -> Result<Self, TunnelError> {
        Ok(Self {
            version,
            user_cas: user_cas
                .iter()
                .map(|ca| p256_point("user_ca_p256_public", ca))
                .collect::<Result<_, _>>()?,
            host_certificate: certificate.map(host_certificate).transpose()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_key_round_trip_and_refusals() {
        let key = SigningKey::generate().unwrap().0;
        let tunnel = [7u8; 32];
        let message = host_key_message(&key, &tunnel).unwrap();
        assert!(message.validate().is_ok());
        let AgentMessage::SshHostKey { p256_public, proof } = message else {
            unreachable!()
        };
        assert_eq!(
            verify_host_key(&p256_public, &proof, &tunnel).unwrap(),
            key.verifying_key()
        );
        // Bound to the tunnel certificate.
        assert_eq!(
            verify_host_key(&p256_public, &proof, &[8u8; 32]),
            Err(TunnelError::ProofOfPossession)
        );
        // Another key claimed.
        let other =
            URL_SAFE_NO_PAD.encode(SigningKey::generate().unwrap().0.verifying_key().to_bytes());
        assert_eq!(
            verify_host_key(&other, &proof, &tunnel),
            Err(TunnelError::ProofOfPossession)
        );
        assert_eq!(
            verify_host_key("AA", "AA", &tunnel),
            Err(TunnelError::ProofOfPossession)
        );
    }
}
