//! Loading the keys of the core: each key has one use, whatever its file.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test helpers and scenarios"
)]

use std::path::{Path, PathBuf};

use ostena_common::config::CoreConfig;
use ostena_common::secret::SecretBytes;
use ostena_core::server::Keys;
use ostena_crypto::p256::SigningKey;
use ostena_crypto::pki::testing::{TestPki, valid};
use ostena_crypto::pki::{pem_certificate, pem_private_key};

struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn write_key(path: &Path, pkcs8: &SecretBytes) {
    // SECRET-EXPOSURE: test only, a key file as an operator writes it.
    #[expect(clippy::disallowed_methods)]
    std::fs::write(path, pem_private_key(pkcs8).expose_secret()).unwrap();
}

/// The key files of a core in `dir`: the TLS and issuing keys of a test
/// PKI, and new audit and grant keys. Returns the TLS and issuing keys.
fn files(dir: &Path) -> (SecretBytes, SecretBytes) {
    let pki = TestPki::new("Ostena keys").unwrap();
    let (server_key, server_pkcs8) = SigningKey::generate().unwrap();
    let server = pki
        .root
        .sign_server(&server_key.verifying_key(), &["127.0.0.1"], valid())
        .unwrap();
    std::fs::write(dir.join("root.pem"), pki.root.certificate_pem()).unwrap();
    std::fs::write(dir.join("server.pem"), pem_certificate(&server)).unwrap();
    std::fs::write(
        dir.join("issuing.pem"),
        pem_certificate(&pki.issuing_certificate),
    )
    .unwrap();
    write_key(&dir.join("server.key"), &server_pkcs8);
    write_key(&dir.join("issuing.key"), &pki.issuing_key);
    write_key(&dir.join("audit.key"), &SigningKey::generate().unwrap().1);
    write_key(&dir.join("grant.key"), &SigningKey::generate().unwrap().1);
    (server_pkcs8, pki.issuing_key)
}

fn config(dir: &Path) -> CoreConfig {
    // Literal TOML strings: a Windows path holds backslashes.
    let d = dir.display();
    toml::from_str(&format!(
        "tunnel_listen = \"127.0.0.1:0\"\n\
         tls_root_ca = '{d}/root.pem'\n\
         tls_certificate = '{d}/server.pem'\n\
         tls_private_key = {{ file = '{d}/server.key' }}\n\
         issuing_certificate = '{d}/issuing.pem'\n\
         issuing_private_key = {{ file = '{d}/issuing.key' }}\n\
         grant_signing_key = {{ file = '{d}/grant.key' }}\n\
         [audit]\nsigning_key = {{ file = '{d}/audit.key' }}\n"
    ))
    .unwrap()
}

#[test]
fn every_key_of_the_core_has_one_use() {
    let dir = Dir(std::env::temp_dir().join(format!("ostena-core-keys-{}", std::process::id())));
    let _ = std::fs::remove_dir_all(&dir.0);
    std::fs::create_dir_all(&dir.0).unwrap();
    let (server_pkcs8, issuing_pkcs8) = files(&dir.0);
    let config = config(&dir.0);
    Keys::load(&config, None).unwrap();

    // The issuing key copied as the grant key: another file, the same key.
    write_key(&dir.0.join("grant.key"), &issuing_pkcs8);
    let error = Keys::load(&config, None).unwrap_err().to_string();
    assert!(
        error.contains("core.grant_signing_key") && error.contains("core.issuing_private_key"),
        "{error}"
    );
    write_key(&dir.0.join("grant.key"), &SigningKey::generate().unwrap().1);
    Keys::load(&config, None).unwrap();

    // The TLS key copied as the audit key.
    write_key(&dir.0.join("audit.key"), &server_pkcs8);
    let error = Keys::load(&config, None).unwrap_err().to_string();
    assert!(
        error.contains("core.audit.signing_key") && error.contains("core.tls_private_key"),
        "{error}"
    );
}
