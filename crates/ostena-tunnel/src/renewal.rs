//! Certificate renewal over the tunnel (ADR-0008): at two thirds of its
//! validity, the agent generates a **new key** and sends `renew` with the new
//! public key, signed by that key and bound to the certificate of the current
//! tunnel. The core issues a certificate for the same agent and group and
//! answers `certificate`; the old certificate stays valid until it expires,
//! unless revoked.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ostena_crypto::p256::{self, Signature, SigningKey, VerifyingKey};

use crate::control::AgentMessage;
use crate::error::TunnelError;

const DOMAIN: &[u8] = b"ostena-renew-v1\0";
const REQUEST_LEN: usize = p256::PUBLIC_KEY_LEN + p256::SIGNATURE_LEN;

/// When to renew a certificate valid from `not_before` to `not_after`:
/// at two thirds of its validity.
pub fn due_at(not_before: u64, not_after: u64) -> u64 {
    not_before + not_after.saturating_sub(not_before) / 3 * 2
}

fn message(current_certificate: &[u8; 32], public_key: &[u8; p256::PUBLIC_KEY_LEN]) -> Vec<u8> {
    let mut m = Vec::with_capacity(DOMAIN.len() + 32 + p256::PUBLIC_KEY_LEN);
    m.extend_from_slice(DOMAIN);
    m.extend_from_slice(current_certificate);
    m.extend_from_slice(public_key);
    m
}

/// The `renew` message for `new_key`, bound to the SHA-256 of the current
/// certificate.
///
/// # Errors
///
/// If the signature fails.
pub fn request(
    new_key: &SigningKey,
    current_certificate: &[u8; 32],
) -> Result<AgentMessage, TunnelError> {
    let public_key = new_key.verifying_key().to_bytes();
    let signature = new_key
        .sign(&message(current_certificate, &public_key))
        .map_err(|e| TunnelError::Io(e.to_string()))?;
    let mut raw = public_key.to_vec();
    raw.extend_from_slice(&signature.to_bytes());
    Ok(AgentMessage::Renew {
        request: URL_SAFE_NO_PAD.encode(raw),
    })
}

/// Core side: the new public key of a `renew` request received on the tunnel
/// of the certificate `current_certificate`, after checking the proof of
/// possession.
///
/// # Errors
///
/// [`TunnelError::ProofOfPossession`].
pub fn verify(request: &str, current_certificate: &[u8; 32]) -> Result<VerifyingKey, TunnelError> {
    let raw: [u8; REQUEST_LEN] = URL_SAFE_NO_PAD
        .decode(request)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(TunnelError::ProofOfPossession)?;
    let mut public_key = [0u8; p256::PUBLIC_KEY_LEN];
    public_key.copy_from_slice(&raw[..p256::PUBLIC_KEY_LEN]);
    let mut signature = [0u8; p256::SIGNATURE_LEN];
    signature.copy_from_slice(&raw[p256::PUBLIC_KEY_LEN..]);
    let key = VerifyingKey::from_bytes(&public_key).map_err(|_| TunnelError::ProofOfPossession)?;
    key.verify(
        &message(current_certificate, &public_key),
        &Signature::from_bytes(&signature),
    )
    .map_err(|_| TunnelError::ProofOfPossession)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn due_at_two_thirds() {
        assert_eq!(due_at(0, 30 * 86_400), 20 * 86_400);
        assert_eq!(due_at(100, 100), 100);
        assert_eq!(due_at(100, 50), 100);
    }

    #[test]
    fn request_round_trip_and_refusals() {
        let key = SigningKey::generate().unwrap().0;
        let current = [7u8; 32];
        let AgentMessage::Renew { request: text } = request(&key, &current).unwrap() else {
            unreachable!()
        };
        assert!(
            AgentMessage::Renew {
                request: text.clone()
            }
            .validate()
            .is_ok()
        );
        assert_eq!(verify(&text, &current).unwrap(), key.verifying_key());
        // Bound to the certificate of the tunnel it travels on.
        assert_eq!(
            verify(&text, &[8u8; 32]),
            Err(TunnelError::ProofOfPossession)
        );
        // Signed by another key.
        let mut raw = URL_SAFE_NO_PAD.decode(&text).unwrap();
        let other = SigningKey::generate().unwrap().0;
        raw[..p256::PUBLIC_KEY_LEN].copy_from_slice(&other.verifying_key().to_bytes());
        assert_eq!(
            verify(&URL_SAFE_NO_PAD.encode(&raw), &current),
            Err(TunnelError::ProofOfPossession)
        );
        assert_eq!(verify("AA", &current), Err(TunnelError::ProofOfPossession));
    }
}
