//! Entry points shared by the cargo-fuzz targets (`fuzz/`) and the stable
//! tests that replay their corpora. Not part of the API.

use ostena_crypto::p256::VerifyingKey;

use crate::export::ExportReader;
use crate::head::{Head, TrustedKeys};
use crate::record::Record;
use crate::verify::{Options, verify_export};

/// RFC 6979 appendix A.2.5 P-256 public key (uncompressed SEC1): a valid key
/// whose kid the fuzzer can reach (same test key as the grant harness).
pub const FUZZ_KEY: [u8; 65] = [
    0x04, 0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d,
    0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f,
    0xb6, 0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc,
    0x64, 0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22,
    0x99,
];

/// Runs every decoder on untrusted input. Must never panic; checks that the
/// decoders only accept canonical encodings.
pub fn decode(data: &[u8]) {
    if let Ok(record) = Record::decode(data) {
        let encoded = record.encode();
        assert_eq!(
            encoded.as_deref(),
            Ok(data),
            "a decoded record re-encodes to the same bytes"
        );
    }
    if let Ok(head) = Head::decode(data) {
        assert_eq!(head.encode().as_slice(), data, "canonical head");
        assert_eq!(Head::from_text(&head.to_text()), Ok(head));
        let _ = head.hash();
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = Head::from_text(text);
    }
    if let Ok(reader) = ExportReader::new(data) {
        for frame in reader {
            if frame.is_err() {
                break;
            }
        }
    }
}

/// The trusted keys of the harness: [`FUZZ_KEY`].
pub fn keys() -> TrustedKeys {
    let mut keys = TrustedKeys::new();
    if let Ok(key) = VerifyingKey::from_bytes(&FUZZ_KEY) {
        let _ = keys.insert(key);
    }
    keys
}

/// Verifies untrusted input as an export, with [`FUZZ_KEY`] trusted. Must
/// never panic.
pub fn verify(data: &[u8]) {
    if let Ok(report) = verify_export(data, keys(), Options::default()) {
        let _ = report.exit_code();
        for finding in &report.findings {
            let _ = finding.to_string();
        }
    }
}
