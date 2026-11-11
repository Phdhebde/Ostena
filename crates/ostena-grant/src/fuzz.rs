//! Entry point shared by the cargo-fuzz target (`fuzz/`) and the stable test
//! that replays its corpus. Not part of the API.

use crate::format::{self, GRANT_LEN, SignedGrant};
use crate::ids::GatewayGroupId;
use crate::keys::KeySet;
use crate::verify::{Policy, Verifier};
use ostena_crypto::ed25519::VerifyingKey;

/// RFC 8032 test 1 public key: a valid key whose kid the fuzzer can reach.
const FUZZ_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

/// Runs every decoder on untrusted input. Must never panic.
pub fn decode(data: &[u8]) {
    if let Ok(signed) = SignedGrant::from_bytes(data) {
        let raw: &[u8; GRANT_LEN] = signed.as_bytes();
        let _ = format::parse_header(raw);
        // The body parser normally runs after the signature: exercise it alone.
        let _ = format::parse_body(raw);
        let _ = SignedGrant::from_text(&signed.to_text());
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = SignedGrant::from_text(text);
    }
    if let Ok(key) = VerifyingKey::from_bytes(&FUZZ_KEY) {
        let mut keys = KeySet::new();
        keys.insert(key);
        let verifier = Verifier::new(keys, GatewayGroupId::from_bytes([0; 16]), Policy::default());
        let _ = verifier.check(data, 1_800_000_000);
    }
}
