//! `ostena core portal-manifest` (ADR-0020): with the portal embedded, the
//! digest it prints is the SHA-256 of the `SHA256SUMS` it embeds; without,
//! it fails with a clear message.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, reason = "test")]

use std::process::Command;

#[test]
fn portal_manifest_prints_the_embedded_digest_or_fails() {
    let out = Command::new(env!("CARGO_BIN_EXE_ostena"))
        .args(["core", "portal-manifest"])
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    if ostena_core::web::portal::EMBEDDED.is_present() {
        assert!(out.status.success(), "{stderr}");
        let (head, sums) = stdout.split_once("\n\n").unwrap();
        let digest = ostena_crypto::sha256::digest(sums.as_bytes()).iter().fold(
            String::new(),
            |mut s, b| {
                use std::fmt::Write as _;
                let _ = write!(s, "{b:02x}");
                s
            },
        );
        assert!(head.ends_with(&format!(": {digest}")), "{head}");
        assert!(sums.contains("  index.html\n"));
    } else {
        assert_eq!(out.status.code(), Some(1));
        assert!(stderr.contains("aucun portail embarqué"), "{stderr}");
    }
}
