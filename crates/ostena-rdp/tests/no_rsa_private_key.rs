//! Guard of the RUSTSEC-2023-0071 exception (ADR-0019 section 9): the
//! Marvin attack targets RSA private-key decryption and signature; the agent
//! must never perform one. `ostena-rdp` does not depend on `rsa` (the
//! `deny.toml` wrappers admit it only under `picky`, `sspi` and
//! `winscard`), and this test fails if its code names a type or a path that
//! builds or uses a private key: smart card identities, PKINIT, PKU2U,
//! private keys of `picky` or `rsa`.

#![allow(clippy::unwrap_used, reason = "test helpers outside #[test] functions")]

use std::path::Path;

/// Names that would build or use an RSA private key through the
/// dependencies.
const FORBIDDEN: &[&str] = &[
    "RsaPrivateKey",
    "PrivateKey",
    "rsa::",
    "SmartCard",
    "smart_card",
    "scard",
    "Pkinit",
    "pkinit",
    "Pku2u",
    "pku2u",
    "DecodeRsaPrivateKey",
    "DecodePrivateKey",
];

fn sources(dir: &Path, out: &mut Vec<(String, String)>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push((
                path.display().to_string(),
                std::fs::read_to_string(&path).unwrap(),
            ));
        }
    }
}

#[test]
fn no_rsa_private_key_in_ostena_rdp() {
    let mut files = Vec::new();
    sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    assert_ne!(files.len(), 0);
    let mut found = Vec::new();
    for (path, text) in &files {
        for (n, line) in text.lines().enumerate() {
            // Documentation may explain what is never done.
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            for name in FORBIDDEN {
                if code.contains(name) {
                    found.push(format!("{path}:{}: {name}", n + 1));
                }
            }
        }
    }
    assert_eq!(
        found,
        Vec::<String>::new(),
        "RSA private key path in ostena-rdp (RUSTSEC-2023-0071 exception, ADR-0019 \
         section 9):\n{}",
        found.join("\n")
    );
}
