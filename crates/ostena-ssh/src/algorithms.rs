//! The frozen SSH algorithm list (ADR-0009, ADR-0010): one choice per kind,
//! never negotiable by the peer. Plain names, shared by the pre-check (which
//! does not depend on the SSH library) and the library configuration.
//!
//! - Key exchange: ECDH on P-256. X25519 (`curve25519-sha256`,
//!   `mlkem768x25519-sha256`) is off: outside the ANSSI list. A hybrid
//!   P-256 + ML-KEM exchange is an open question (ADR-0009).
//! - Cipher: AES-256-GCM, an AEAD, so no separate MAC.
//! - Host and user keys, and certificates: ECDSA P-256.
//! - Strict KEX mandatory (CVE-2023-48795), checked by the pre-check.

/// Key exchange.
pub const KEX: &str = "ecdh-sha2-nistp256";
/// Cipher, both directions.
pub const CIPHER: &str = "aes256-gcm@openssh.com";
/// Host and user key.
pub const HOST_KEY: &str = "ecdsa-sha2-nistp256";
/// Host and user certificate.
pub const HOST_KEY_CERTIFICATE: &str = "ecdsa-sha2-nistp256-cert-v01@openssh.com";
/// Strict KEX marker of a client.
pub const STRICT_KEX_CLIENT: &str = "kex-strict-c-v00@openssh.com";
/// Strict KEX marker of a server.
pub const STRICT_KEX_SERVER: &str = "kex-strict-s-v00@openssh.com";
