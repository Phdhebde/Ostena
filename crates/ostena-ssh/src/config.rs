//! The SSH library configured with the frozen list only (defence in depth:
//! the pre-check has already refused a peer without a common algorithm).
//!
//! Both ends identify as `SSH-2.0-Ostena`, without a version: the library
//! default would announce its name and version to every peer.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use russh::keys::{Algorithm, Certificate, EcdsaCurve, PrivateKey};
use russh::{MethodKind, MethodSet, Preferred, SshId, cipher, compression, kex};

use crate::precheck::Role;

/// Identification line of both ends, without a version.
pub const IDENTIFICATION: &str = "SSH-2.0-Ostena";
/// Initial window of a channel: 256 KiB, as a tunnel stream (ADR-0008).
pub const WINDOW: u32 = 256 * 1024;
/// Largest packet.
pub const MAX_PACKET: u32 = 32 * 1024;
/// Unprocessed messages held per channel before back-pressure.
pub const CHANNEL_BUFFER: usize = 8;

/// The frozen algorithms for `role`: the key exchange with our strict KEX
/// marker, AES-256-GCM (no MAC), ECDSA P-256, no compression.
pub fn preferred(role: Role) -> Preferred {
    let strict = match role {
        Role::Server => kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
        Role::Client => kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
    };
    Preferred {
        kex: Cow::Owned(vec![kex::ECDH_SHA2_NISTP256, strict]),
        key: Cow::Borrowed(&[Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        }]),
        host_key_certificates: Cow::Borrowed(&[]),
        cipher: Cow::Borrowed(&[cipher::AES_256_GCM]),
        mac: Cow::Borrowed(&[]),
        compression: Cow::Borrowed(&[compression::NONE]),
    }
}

fn identification() -> SshId {
    SshId::Standard(Cow::Borrowed(IDENTIFICATION))
}

/// Server configuration: `host_keys` (ECDSA P-256), public key
/// authentication only.
pub fn server(host_keys: Vec<PrivateKey>) -> Arc<russh::server::Config> {
    session_server(host_keys, Vec::new(), 3)
}

/// The agent server configuration: its host key and host certificates,
/// public key authentication only, at most `max_auth_attempts`, bounded
/// windows and buffers.
pub fn session_server(
    host_keys: Vec<PrivateKey>,
    certificates: Vec<Certificate>,
    max_auth_attempts: usize,
) -> Arc<russh::server::Config> {
    Arc::new(russh::server::Config {
        server_id: identification(),
        preferred: preferred(Role::Server),
        keys: host_keys,
        certificates,
        methods: MethodSet::from(&[MethodKind::PublicKey][..]),
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: Some(Duration::ZERO),
        max_auth_attempts,
        window_size: WINDOW,
        maximum_packet_size: MAX_PACKET,
        channel_buffer_size: CHANNEL_BUFFER,
        inactivity_timeout: Some(Duration::from_secs(3600)),
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 3,
        nodelay: true,
        ..russh::server::Config::default()
    })
}

/// Client configuration (driver to the targets).
pub fn client() -> Arc<russh::client::Config> {
    Arc::new(russh::client::Config {
        client_id: identification(),
        preferred: preferred(Role::Client),
        window_size: WINDOW,
        maximum_packet_size: MAX_PACKET,
        channel_buffer_size: CHANNEL_BUFFER,
        inactivity_timeout: Some(Duration::from_secs(3600)),
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 3,
        nodelay: true,
        ..russh::client::Config::default()
    })
}
