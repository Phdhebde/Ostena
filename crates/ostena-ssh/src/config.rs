//! The SSH library configured with the frozen list only (defence in depth:
//! the pre-check has already refused a peer without a common algorithm).

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use russh::keys::{Algorithm, EcdsaCurve, PrivateKey};
use russh::{MethodKind, MethodSet, Preferred, cipher, compression, kex};

use crate::precheck::Role;

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

/// Server configuration: `host_keys` (ECDSA P-256), public key
/// authentication only.
pub fn server(host_keys: Vec<PrivateKey>) -> Arc<russh::server::Config> {
    Arc::new(russh::server::Config {
        preferred: preferred(Role::Server),
        keys: host_keys,
        methods: MethodSet::from(&[MethodKind::PublicKey][..]),
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: Some(Duration::ZERO),
        max_auth_attempts: 3,
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
        preferred: preferred(Role::Client),
        inactivity_timeout: Some(Duration::from_secs(3600)),
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 3,
        nodelay: true,
        ..russh::client::Config::default()
    })
}
