//! The keys we generate, seen by OpenSSH: every one is accepted, and so is a
//! key whose scalar takes 31 bytes, which only ssh-key refuses (ADR-0010).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stderr,
    reason = "test helpers outside #[test] functions; notices go to stderr"
)]

mod common;

use std::path::Path;
use std::process::Command;

use common::{dir, openssh};
use ostena_common::secret::SecretBytes;
use ostena_crypto::p256::SigningKey;
use ostena_ssh::keys::{GeneratedKey, encode, generate};
use proptest::prelude::*;

/// Writes the private key with owner-only rights, as OpenSSH requires.
fn write_private(path: &Path, key: &GeneratedKey) {
    // SECRET-EXPOSURE: test only.
    #[expect(clippy::disallowed_methods)]
    std::fs::write(path, key.private.expose_secret()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

/// The public key OpenSSH derives from the private key file.
fn openssh_public(keygen: &Path, path: &Path) -> String {
    let out = Command::new(keygen)
        .arg("-y")
        .arg("-f")
        .arg(path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn blob(line: &str) -> &str {
    line.split(' ').nth(1).unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Every key we generate is accepted by OpenSSH, with the same public key.
    #[test]
    fn prop_generated_keys_are_accepted_by_openssh(case in 0u32..1_000_000) {
        let Some(keygen) = openssh("ssh-keygen") else { return Ok(()) };
        let dir = dir(&format!("keys-{case}"));
        let key = generate("prop").unwrap();
        let path = dir.0.join("key");
        write_private(&path, &key);
        let public = openssh_public(&keygen, &path);
        prop_assert_eq!(blob(&public), blob(&key.public));
    }
}

/// UPSTREAM DEFECT (ssh-key 0.7.0-rc.11): OpenSSH accepts a key whose scalar
/// takes 31 bytes; only ssh-key refuses it. Remove with the defect.
#[test]
fn upstream_defect_short_scalar_is_accepted_by_openssh() {
    let Some(keygen) = openssh("ssh-keygen") else {
        return;
    };
    let mut scalar = ostena_crypto::rand::array::<32>().unwrap();
    scalar[0] = 0;
    scalar[1] = (scalar[1] & 0x7f) | 0x01;
    let key = SigningKey::from_scalar(&SecretBytes::from(scalar.to_vec())).unwrap();
    let key = encode(&key, "short").unwrap();
    let dir = dir("keys-short");
    let path = dir.0.join("key");
    write_private(&path, &key);
    assert_eq!(blob(&openssh_public(&keygen, &path)), blob(&key.public));
    assert_eq!(
        ostena_ssh::keys::load(&key.private).unwrap_err().code(),
        "SSH-E007"
    );
}
