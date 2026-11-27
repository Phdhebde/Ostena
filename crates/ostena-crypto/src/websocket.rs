//! The `Sec-WebSocket-Accept` value of the WebSocket handshake (RFC 6455,
//! § 4.2.2): `base64(SHA-1(key ‖ GUID))`.
//!
//! SHA-1 is not a compliant hash ([PG-083] § 2.1.4). It is admitted here
//! only, as an accepted deviation (ADR-0009, amendment of 2026-11-26): the
//! key, the GUID and the value are public, and the value only proves that
//! the server understood a WebSocket request. Neither the authentication
//! (cookie, grant) nor the integrity (TLS) depend on it. The module gives
//! that value and nothing else: no generic SHA-1 is exposed.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

/// The GUID of RFC 6455, § 1.3.
pub const GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Length of a `Sec-WebSocket-Accept` value: 20 bytes in padded base64.
pub const ACCEPT_LEN: usize = 28;

/// The `Sec-WebSocket-Accept` value for the `Sec-WebSocket-Key` the client
/// sent (its text, as received; the caller checked its form).
pub fn accept_key(client_key: &[u8]) -> String {
    let mut context = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY);
    context.update(client_key);
    context.update(GUID);
    STANDARD.encode(context.finish().as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_of_rfc_6455() {
        // RFC 6455, § 1.3.
        let accept = accept_key(b"dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        assert_eq!(accept.len(), ACCEPT_LEN);
    }

    #[test]
    fn other_keys_give_other_values() {
        assert_ne!(
            accept_key(b"dGhlIHNhbXBsZSBub25jZQ=="),
            accept_key(b"AQIDBAUGBwgJCgsMDQ4PEA==")
        );
        assert_eq!(accept_key(b"").len(), ACCEPT_LEN);
    }
}
