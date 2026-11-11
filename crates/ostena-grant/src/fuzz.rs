//! Entry point shared by the cargo-fuzz target (`fuzz/`) and the stable test
//! that replays its corpus. Not part of the API.

use crate::format::{self, GRANT_LEN, SignedGrant};
use crate::ids::GatewayGroupId;
use crate::keys::KeySet;
use crate::verify::{Policy, Verifier};
use ostena_crypto::p256::VerifyingKey;

/// RFC 6979 appendix A.2.5 P-256 public key (uncompressed SEC1): a valid key
/// whose kid the fuzzer can reach.
pub const FUZZ_KEY: [u8; 65] = [
    0x04, 0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d,
    0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f,
    0xb6, 0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc,
    0x64, 0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22,
    0x99,
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
