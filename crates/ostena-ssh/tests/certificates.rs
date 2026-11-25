//! Our certificate codec against OpenSSH: certificates signed by
//! `ssh-keygen -s` parse and encode back byte for byte, and the ones we
//! issue are read by `ssh-keygen -L`.
//!
//! `ssh-keygen` may produce high-S ECDSA signatures, which the strict
//! verifier of `ostena-crypto` refuses: its certificates are used for
//! parsing only.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stderr,
    reason = "test helpers outside #[test] functions; notices go to stderr"
)]

mod common;

use std::path::Path;
use std::process::Command;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::{dir, openssh};
use ostena_crypto::p256::SigningKey;
use ostena_ssh::cert::{self, CertError, Kind, PERMIT_PTY, Template};

const SUBJECT: &str = "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6";
const LOGIN: &str = "7a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";

fn keygen_run(keygen: &Path, args: &[&str]) -> String {
    let out = Command::new(keygen).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn new_key(keygen: &Path, path: &Path) {
    let _ = std::fs::remove_file(path);
    let status = Command::new(keygen)
        .args(["-q", "-t", "ecdsa", "-b", "256", "-N", "", "-C", "t", "-f"])
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success());
}

fn blob_of(line: &str) -> Vec<u8> {
    STANDARD.decode(line.split(' ').nth(1).unwrap()).unwrap()
}

#[test]
fn certificates_signed_by_ssh_keygen_parse_canonically() {
    let Some(keygen) = openssh("ssh-keygen") else {
        return;
    };
    let dir = dir("cert-keygen");
    let ca = dir.0.join("ca");
    let user = dir.0.join("user");
    new_key(&keygen, &ca);
    new_key(&keygen, &user);
    let ca_public = std::fs::read_to_string(dir.0.join("ca.pub")).unwrap();
    let ca_key = ostena_crypto::p256::VerifyingKey::from_bytes(
        &blob_of(&ca_public)[39..].try_into().unwrap(),
    )
    .unwrap();
    // Several certificates: ssh-keygen draws its signatures, about half of
    // them in the high-S form.
    for (i, extra) in [
        &["-O", "clear", "-O", "permit-pty"][..],
        &[][..],
        &["-O", "clear"][..],
        &["-O", "clear", "-O", "force-command=/bin/true"][..],
        &["-h"][..],
    ]
    .iter()
    .enumerate()
    {
        let ca_path = ca.to_str().unwrap();
        let user_pub = dir.0.join("user.pub");
        let mut args = vec!["-q", "-s", ca_path, "-I", LOGIN, "-n", SUBJECT, "-V", "+1h"];
        args.extend_from_slice(extra);
        let serial = i.to_string();
        args.extend_from_slice(&["-z", &serial]);
        let user_pub = user_pub.to_str().unwrap().to_owned();
        args.push(&user_pub);
        keygen_run(&keygen, &args);
        let line = std::fs::read_to_string(dir.0.join("user-cert.pub")).unwrap();
        let blob = blob_of(&line);
        let parsed = cert::parse(&blob).unwrap();
        assert_eq!(parsed.encode(), blob, "{extra:?}");
        assert_eq!(parsed.authority, ca_key);
        assert_eq!(parsed.key_id, LOGIN);
        assert_eq!(parsed.principals, [SUBJECT]);
        assert_eq!(parsed.serial, i as u64);
        // Signed by ssh-keygen: valid, but perhaps in the high-S form.
        match parsed.verify(&[ca_key]) {
            Ok(_) | Err(CertError::BadSignature) => {}
            Err(e) => panic!("{e}"),
        }
        if extra.contains(&"-h") {
            assert_eq!(parsed.kind, Kind::Host);
        }
        if extra.is_empty() {
            // The default extensions of ssh-keygen allow forwarding.
            assert!(parsed.extensions.len() > 1);
        }
    }
}

#[test]
fn our_certificates_are_read_by_ssh_keygen() {
    let Some(keygen) = openssh("ssh-keygen") else {
        return;
    };
    let dir = dir("cert-ours");
    let ca = SigningKey::generate().unwrap().0;
    let user = SigningKey::generate().unwrap().0;
    let now = ostena_grant::unix_now();
    let blob = cert::issue(
        &Template {
            kind: Kind::User,
            public: user.verifying_key(),
            serial: 42,
            key_id: LOGIN.into(),
            principals: vec![SUBJECT.into()],
            valid_after: now - 60,
            valid_before: now + 3600,
            critical_options: vec![],
            extensions: vec![(PERMIT_PTY.into(), vec![])],
        },
        &ca,
    )
    .unwrap();
    let path = dir.0.join("user-cert.pub");
    std::fs::write(
        &path,
        format!("{} {} test\n", cert::CERT_TYPE, STANDARD.encode(&blob)),
    )
    .unwrap();
    let listing = keygen_run(&keygen, &["-L", "-f", path.to_str().unwrap()]);
    eprintln!("{listing}");
    assert!(listing.contains("ecdsa-sha2-nistp256-cert-v01@openssh.com user certificate"));
    assert!(listing.contains(&format!("Key ID: \"{LOGIN}\"")));
    assert!(listing.contains("Serial: 42"));
    assert!(listing.contains(SUBJECT));
    assert!(listing.contains("permit-pty"));
    assert!(!listing.contains("permit-port-forwarding"));
    assert!(listing.contains("Critical Options: (none)"));
}

/// The agent checks the signature of its own host certificate against the
/// host authorities pushed by the core (`SSH-E018`).
#[test]
fn host_certificate_must_be_signed_by_a_pushed_host_authority() {
    use ostena_crypto::p256::VerifyingKey;
    use ostena_ssh::server::SshIdentity;

    let host_ca = SigningKey::generate().unwrap().0;
    let rogue = SigningKey::generate().unwrap().0;
    let user_ca = SigningKey::generate().unwrap().0;
    let generated = ostena_ssh::keys::generate("host").unwrap();
    let now = ostena_grant::unix_now();
    let public = VerifyingKey::from_bytes(
        &ostena_ssh::driver::sec1_point(
            ostena_ssh::keys::load(&generated.private)
                .unwrap()
                .public_key(),
        )
        .unwrap()
        .try_into()
        .unwrap(),
    )
    .unwrap();
    let issue = |ca: &SigningKey| {
        cert::issue(
            &Template {
                kind: Kind::Host,
                public,
                serial: 1,
                key_id: "gw".into(),
                principals: vec!["gw.example.test".into()],
                valid_after: now - 60,
                valid_before: now + 3600,
                critical_options: vec![],
                extensions: vec![],
            },
            ca,
        )
        .unwrap()
    };
    let identity = |certificate: &[u8], host_cas: &[VerifyingKey]| {
        SshIdentity::new(
            ostena_ssh::keys::load(&generated.private).unwrap(),
            certificate,
            host_cas,
            vec![user_ca.verifying_key()],
            now,
        )
    };
    let good = issue(&host_ca);
    assert!(identity(&good, &[host_ca.verifying_key()]).is_ok());
    // Signed by another authority, or no host authority pushed.
    let refused = identity(&issue(&rogue), &[host_ca.verifying_key()]).unwrap_err();
    assert_eq!(refused.code(), "SSH-E018");
    assert!(refused.to_string().contains("autorité"), "{refused}");
    assert_eq!(identity(&good, &[]).unwrap_err().code(), "SSH-E018");
    // Rotation: either authority of the list.
    assert!(identity(&good, &[rogue.verifying_key(), host_ca.verifying_key()]).is_ok());
    // A tampered signature.
    let mut tampered = good.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(
        identity(&tampered, &[host_ca.verifying_key()])
            .unwrap_err()
            .code(),
        "SSH-E018"
    );
}
