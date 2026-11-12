//! Control messages v1 (ADR-0008): strict JSON, length-prefixed.
//!
//! Every message from the peer is untrusted. Decoding refuses unknown fields
//! and types, frames above the size limits, and then checks every value
//! ([`AgentMessage::validate`], [`CoreMessage::validate`]) before the message
//! is handed to the application.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ostena_common::config::Mode;
use ostena_common::config::scope::PolicySpec;
use ostena_crypto::p256::{self, VerifyingKey};
use ostena_grant::{Kid, SignedGrant};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::error::TunnelError;
use crate::ids::Uuid;

/// Version of the control protocol.
pub const PROTOCOL_VERSION: u16 = 1;
/// Largest control message, policy excepted.
pub const MAX_MESSAGE: usize = 64 * 1024;
/// Largest policy message.
pub const MAX_POLICY_MESSAGE: usize = 1024 * 1024;
/// Largest grant key set.
pub const MAX_KEYS: usize = 16;

/// Bounds of the heartbeat interval announced by the core, in seconds.
pub const HEARTBEAT_SECS: std::ops::RangeInclusive<u16> = 1..=60;

/// Messages from the agent to the core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentMessage {
    /// First message of a tunnel.
    Hello {
        /// [`PROTOCOL_VERSION`].
        protocol: u16,
        /// Agent version.
        agent_version: String,
        /// Gateway group (UUID).
        gateway_group: String,
        /// `sha256:<hex>` of the configuration file.
        config_fingerprint: String,
    },
    /// Heartbeat.
    Ping {
        /// Sequence number.
        seq: u64,
    },
    /// Heartbeat answer.
    Pong {
        /// Sequence number of the ping.
        seq: u64,
    },
    /// Parameters of a session, for a grant the agent verified (the core
    /// consumes its jti too, ADR-0004).
    SessionRequest {
        /// Correlates the answer.
        request_id: u64,
        /// The grant, text form.
        grant: String,
    },
    /// A session ended.
    SessionClosed {
        /// Session (UUID).
        session_id: String,
        /// Why.
        reason: String,
        /// Bytes sent to the target.
        bytes_to_target: u64,
        /// Bytes received from the target.
        bytes_from_target: u64,
    },
    /// Certificate renewal request (signed request, base64url).
    Renew {
        /// The request.
        request: String,
    },
}

/// A grant verification key pushed by the core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantKey {
    /// Key identifier, 16 hexadecimal characters.
    pub kid: String,
    /// Uncompressed SEC1 public key, base64url without padding.
    pub public_key: String,
    /// Retirement date (Unix seconds), if any.
    pub retire_at: Option<u64>,
}

/// Protocol of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[expect(missing_docs, reason = "protocol names")]
pub enum SessionProtocol {
    Ssh,
    Rdp,
    Vnc,
    Web,
}

/// Messages from the core to the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum CoreMessage {
    /// Answer to [`AgentMessage::Hello`].
    HelloAck {
        /// [`PROTOCOL_VERSION`].
        protocol: u16,
        /// Core version.
        core_version: String,
        /// Heartbeat interval the agent uses, in seconds.
        heartbeat_secs: u16,
    },
    /// Heartbeat.
    Ping {
        /// Sequence number.
        seq: u64,
    },
    /// Heartbeat answer.
    Pong {
        /// Sequence number of the ping.
        seq: u64,
    },
    /// Scope policy for this gateway group (intersected with the local one).
    Policy {
        /// Increases with every change.
        version: u64,
        /// The policy.
        policy: PolicySpec,
    },
    /// Grant verification keys.
    KeySet {
        /// Increases with every change; a lower version is refused.
        version: u64,
        /// The keys.
        keys: Vec<GrantKey>,
    },
    /// Parameters of a session.
    SessionParams {
        /// The request answered.
        request_id: u64,
        /// Session (UUID).
        session_id: String,
        /// Protocol.
        protocol: SessionProtocol,
        /// Target host (checked again by the scope control).
        host: String,
        /// Target port.
        port: u16,
        /// Maximum session length, in seconds.
        max_session_secs: u32,
    },
    /// The session is refused.
    SessionRefused {
        /// The request answered.
        request_id: u64,
        /// Stable code, e.g. `GRT-E010`.
        code: String,
        /// Explanation.
        message: String,
    },
    /// A renewed agent certificate (PEM), with its validity, so that the
    /// agent schedules the next renewal without parsing X.509.
    Certificate {
        /// The certificate.
        certificate: String,
        /// Start of validity (Unix seconds).
        not_before: u64,
        /// End of validity (Unix seconds).
        not_after: u64,
    },
    /// The core closes the tunnel.
    Shutdown {
        /// Why.
        reason: String,
    },
}

fn invalid(what: impl Into<String>) -> TunnelError {
    TunnelError::Protocol(what.into())
}

/// Printable text of at most `max` bytes, without control characters (they
/// would end up in logs).
fn text(field: &str, value: &str, max: usize) -> Result<(), TunnelError> {
    if value.len() > max || value.chars().any(char::is_control) {
        return Err(invalid(format!(
            "{field} trop long ou avec des caractères de contrôle"
        )));
    }
    Ok(())
}

fn uuid(field: &str, value: &str) -> Result<(), TunnelError> {
    Uuid::parse(value)
        .map(|_| ())
        .ok_or_else(|| invalid(format!("{field} n'est pas un UUID canonique")))
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl AgentMessage {
    /// Checks every value.
    ///
    /// # Errors
    ///
    /// [`TunnelError::Protocol`] for the first invalid value,
    /// [`TunnelError::Version`] for another protocol version.
    pub fn validate(&self) -> Result<(), TunnelError> {
        match self {
            Self::Hello {
                protocol,
                agent_version,
                gateway_group,
                config_fingerprint,
            } => {
                if *protocol != PROTOCOL_VERSION {
                    return Err(TunnelError::Version(*protocol));
                }
                text("agent_version", agent_version, 32)?;
                uuid("gateway_group", gateway_group)?;
                let hex = config_fingerprint
                    .strip_prefix("sha256:")
                    .unwrap_or_default();
                if hex.len() != 64 || !is_lower_hex(hex) {
                    return Err(invalid("config_fingerprint n'est pas sha256:<64 hex>"));
                }
                Ok(())
            }
            Self::Ping { .. } | Self::Pong { .. } => Ok(()),
            Self::SessionRequest { grant, .. } => SignedGrant::from_text(grant)
                .map(|_| ())
                .map_err(|e| invalid(format!("grant : {e}"))),
            Self::SessionClosed {
                session_id, reason, ..
            } => {
                uuid("session_id", session_id)?;
                text("reason", reason, 128)
            }
            Self::Renew { request } => {
                if request.len() > 1024 || URL_SAFE_NO_PAD.decode(request).is_err() {
                    return Err(invalid(
                        "request n'est pas du base64url d'au plus 1024 caractères",
                    ));
                }
                Ok(())
            }
        }
    }
}

impl GrantKey {
    /// The key, after checking that it is on the curve and that `kid`
    /// matches it.
    ///
    /// # Errors
    ///
    /// [`TunnelError::Protocol`].
    pub fn verifying_key(&self) -> Result<VerifyingKey, TunnelError> {
        let raw = URL_SAFE_NO_PAD
            .decode(&self.public_key)
            .map_err(|_| invalid("public_key n'est pas du base64url"))?;
        let bytes: [u8; p256::PUBLIC_KEY_LEN] = raw
            .try_into()
            .map_err(|_| invalid("public_key n'a pas 65 octets"))?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| invalid("public_key invalide"))?;
        if Kid::of(&key).to_string() != self.kid {
            return Err(invalid("kid ne correspond pas à la clé"));
        }
        Ok(key)
    }
}

impl CoreMessage {
    /// Checks every value. A policy is compiled as for production: the core
    /// cannot push floor exceptions or unjustified weakenings.
    ///
    /// # Errors
    ///
    /// [`TunnelError::Protocol`] for the first invalid value,
    /// [`TunnelError::Version`] for another protocol version.
    pub fn validate(&self) -> Result<(), TunnelError> {
        match self {
            Self::HelloAck {
                protocol,
                core_version,
                heartbeat_secs,
            } => {
                if *protocol != PROTOCOL_VERSION {
                    return Err(TunnelError::Version(*protocol));
                }
                text("core_version", core_version, 32)?;
                if !HEARTBEAT_SECS.contains(heartbeat_secs) {
                    return Err(invalid("heartbeat_secs hors de 1..=60"));
                }
                Ok(())
            }
            Self::Ping { .. } | Self::Pong { .. } => Ok(()),
            Self::Policy { policy, .. } => {
                if !policy.floor_exceptions.is_empty() {
                    return Err(invalid(
                        "une politique poussée ne peut pas lever le plancher",
                    ));
                }
                ostena_scope::CompiledPolicy::compile(policy, Mode::Production)
                    .map(|_| ())
                    .map_err(|e| invalid(format!("politique : {e}")))
            }
            Self::KeySet { version, keys } => {
                if *version == 0 || keys.is_empty() || keys.len() > MAX_KEYS {
                    return Err(invalid("jeu de clés vide, trop grand ou de version 0"));
                }
                let mut kids = std::collections::HashSet::new();
                for key in keys {
                    key.verifying_key()?;
                    if !kids.insert(&key.kid) {
                        return Err(invalid("kid en double"));
                    }
                }
                Ok(())
            }
            Self::SessionParams {
                session_id,
                host,
                port,
                max_session_secs,
                ..
            } => {
                uuid("session_id", session_id)?;
                ostena_scope::parse_host(host).map_err(|e| invalid(format!("host : {e}")))?;
                if *port == 0 || *max_session_secs == 0 {
                    return Err(invalid("port ou durée de session nuls"));
                }
                Ok(())
            }
            Self::SessionRefused { code, message, .. } => {
                let b = code.as_bytes();
                let well_formed = b.len() == 8
                    && b[..3].iter().all(u8::is_ascii_uppercase)
                    && b[3] == b'-'
                    && b[4].is_ascii_uppercase()
                    && b[5..].iter().all(u8::is_ascii_digit);
                if !well_formed {
                    return Err(invalid("code de refus mal formé"));
                }
                text("message", message, 256)
            }
            Self::Certificate {
                certificate,
                not_before,
                not_after,
            } => {
                if not_after <= not_before {
                    return Err(invalid("validité du certificat incohérente"));
                }
                let pem_chars = certificate
                    .bytes()
                    .all(|b| b.is_ascii_graphic() || matches!(b, b' ' | b'\n' | b'\r'));
                if certificate.len() > 8 * 1024
                    || !pem_chars
                    || !certificate.starts_with("-----BEGIN CERTIFICATE-----")
                    || !certificate
                        .trim_end()
                        .ends_with("-----END CERTIFICATE-----")
                {
                    return Err(invalid("certificate n'est pas un certificat PEM"));
                }
                Ok(())
            }
            Self::Shutdown { reason } => text("reason", reason, 128),
        }
    }
}

/// A control message type, decoded and checked the same way on both sides.
pub trait Message: Serialize + DeserializeOwned + Send + Sync + 'static {
    /// Checks every value.
    ///
    /// # Errors
    ///
    /// See the implementations.
    fn validate(&self) -> Result<(), TunnelError>;
    /// Largest frame accepted for this message (policy pushes are larger).
    fn max_len(&self) -> usize;
    /// A ping.
    fn ping(seq: u64) -> Self;
    /// A pong.
    fn pong(seq: u64) -> Self;
    /// The sequence number if this is a ping.
    fn as_ping(&self) -> Option<u64>;
    /// The sequence number if this is a pong.
    fn as_pong(&self) -> Option<u64>;
}

impl Message for AgentMessage {
    fn validate(&self) -> Result<(), TunnelError> {
        Self::validate(self)
    }
    fn max_len(&self) -> usize {
        MAX_MESSAGE
    }
    fn ping(seq: u64) -> Self {
        Self::Ping { seq }
    }
    fn pong(seq: u64) -> Self {
        Self::Pong { seq }
    }
    fn as_ping(&self) -> Option<u64> {
        match self {
            Self::Ping { seq } => Some(*seq),
            _ => None,
        }
    }
    fn as_pong(&self) -> Option<u64> {
        match self {
            Self::Pong { seq } => Some(*seq),
            _ => None,
        }
    }
}

impl Message for CoreMessage {
    fn validate(&self) -> Result<(), TunnelError> {
        Self::validate(self)
    }
    fn max_len(&self) -> usize {
        match self {
            Self::Policy { .. } => MAX_POLICY_MESSAGE,
            _ => MAX_MESSAGE,
        }
    }
    fn ping(seq: u64) -> Self {
        Self::Ping { seq }
    }
    fn pong(seq: u64) -> Self {
        Self::Pong { seq }
    }
    fn as_ping(&self) -> Option<u64> {
        match self {
            Self::Ping { seq } => Some(*seq),
            _ => None,
        }
    }
    fn as_pong(&self) -> Option<u64> {
        match self {
            Self::Pong { seq } => Some(*seq),
            _ => None,
        }
    }
}

/// Largest frame read from the network, whatever the type.
pub const MAX_FRAME: usize = MAX_POLICY_MESSAGE;

/// Decodes and checks one frame payload (without the length prefix).
///
/// # Errors
///
/// [`TunnelError::Protocol`] or [`TunnelError::Version`].
pub fn decode<M: Message>(payload: &[u8]) -> Result<M, TunnelError> {
    if payload.len() > MAX_FRAME {
        return Err(invalid("message trop long"));
    }
    let message: M =
        serde_json::from_slice(payload).map_err(|e| invalid(format!("JSON refusé : {e}")))?;
    if payload.len() > message.max_len() {
        return Err(invalid("message trop long pour son type"));
    }
    message.validate()?;
    Ok(message)
}

/// Encodes one frame: 4-byte big-endian length, then the JSON payload.
///
/// # Errors
///
/// [`TunnelError::Protocol`] if the message is too long for its type.
pub fn encode<M: Message>(message: &M) -> Result<Vec<u8>, TunnelError> {
    let payload = serde_json::to_vec(message).map_err(|e| invalid(e.to_string()))?;
    if payload.len() > message.max_len() {
        return Err(invalid("message trop long pour son type"));
    }
    let len = u32::try_from(payload.len()).map_err(|_| invalid("message trop long"))?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

#[cfg(test)]
mod tests;
