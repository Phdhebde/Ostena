//! `ostena release sign` and `ostena release verify` with the real binary
//! (ADR-0017): a key from `ostena ca key new`, files signed then verified,
//! and every kind of tampering refused.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside #[test] functions"
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn ostena(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ostena"))
        .args(args)
        .output()
        .unwrap()
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

struct Lab {
    dir: PathBuf,
    key: PathBuf,
    public: PathBuf,
    dist: PathBuf,
    manifest: PathBuf,
}

impl Lab {
    /// A key, two files in `dist/`, signed.
    fn signed(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("ostena-release-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let dist = dir.join("dist");
        std::fs::create_dir_all(&dist).unwrap();
        let (key, public) = (dir.join("release.key"), dir.join("release.pub"));
        let out = ostena(&[
            "ca",
            "key",
            "new",
            "--key-out",
            s(&key),
            "--public-out",
            s(&public),
        ]);
        assert!(out.status.success(), "{}", stderr(&out));
        std::fs::write(dist.join("ostena"), b"binary").unwrap();
        std::fs::write(dist.join("ostena-cli.cdx.json"), b"{\"bom\":1}").unwrap();
        let manifest = dist.join("ostena-release.manifest");
        let out = ostena(&[
            "release",
            "sign",
            "--key",
            s(&key),
            "--out",
            s(&manifest),
            s(&dist.join("ostena")),
            s(&dist.join("ostena-cli.cdx.json")),
        ]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert!(stdout(&out).contains("2 fichier(s)"), "{}", stdout(&out));
        Self {
            dir,
            key,
            public,
            dist,
            manifest,
        }
    }

    fn verify(&self, extra: &[&str]) -> Output {
        let mut args = vec![
            "release",
            "verify",
            s(&self.manifest),
            "--key",
            s(&self.public),
        ];
        args.extend_from_slice(extra);
        ostena(&args)
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn signed_files_verify() {
    let lab = Lab::signed("ok");
    let text = std::fs::read_to_string(&lab.manifest).unwrap();
    assert!(text.starts_with("ostena-release-manifest-v1\n"));
    // sha256sum("binary")
    assert!(
        text.contains("9a3a45d01531a20e89ac6ae10b0b0beb0492acd7216a368aa062d1a5fecaf9cd  ostena\n")
    );
    let sig = std::fs::read_to_string(lab.dist.join("ostena-release.manifest.sig")).unwrap();
    assert!(sig.starts_with("ostena-release-signature-v1:"));

    let out = lab.verify(&[]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}{}",
        stdout(&out),
        stderr(&out)
    );
    let report = stdout(&out);
    assert!(report.contains("ok          ostena\n"), "{report}");
    assert!(report.contains("2 fichier(s), 0 erreur(s)"), "{report}");
    assert!(report.contains("Signé par la clé "), "{report}");
}

#[test]
fn a_modified_or_missing_file_fails() {
    let lab = Lab::signed("file");
    std::fs::write(lab.dist.join("ostena"), b"binarY").unwrap();
    let out = lab.verify(&[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stdout(&out).contains("[REL-E006] ostena : empreinte différente"),
        "{}",
        stdout(&out)
    );

    std::fs::remove_file(lab.dist.join("ostena-cli.cdx.json")).unwrap();
    let out = lab.verify(&[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains("[REL-E005]"), "{}", stdout(&out));
    assert!(stdout(&out).contains("2 erreur(s)"), "{}", stdout(&out));
}

#[test]
fn a_modified_manifest_or_signature_fails() {
    let lab = Lab::signed("manifest");
    let original = std::fs::read_to_string(&lab.manifest).unwrap();
    // A digest replaced by that of other content: still well formed.
    let forged = original.replacen("9a3a", "9a3b", 1);
    std::fs::write(&lab.manifest, &forged).unwrap();
    let out = lab.verify(&[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains("[REL-E004]"), "{}", stdout(&out));
    assert!(
        stdout(&out).contains("Aucun fichier vérifié"),
        "{}",
        stdout(&out)
    );

    std::fs::write(&lab.manifest, &original).unwrap();
    let sig_path = lab.dist.join("ostena-release.manifest.sig");
    std::fs::write(&sig_path, b"ostena-release-signature-v1:zz\n").unwrap();
    let out = lab.verify(&[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains("[REL-E002]"), "{}", stdout(&out));
}

#[test]
fn another_key_is_refused() {
    let lab = Lab::signed("stranger");
    let (other, other_pub) = (lab.dir.join("other.key"), lab.dir.join("other.pub"));
    let out = ostena(&[
        "ca",
        "key",
        "new",
        "--key-out",
        s(&other),
        "--public-out",
        s(&other_pub),
    ]);
    assert!(out.status.success());
    let out = ostena(&[
        "release",
        "verify",
        s(&lab.manifest),
        "--key",
        s(&other_pub),
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains("[REL-E003]"), "{}", stdout(&out));
    // Both keys trusted: accepted, signed by the first one.
    let out = lab.verify(&["--key", s(&other_pub)]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
}

#[test]
fn files_are_never_overwritten_and_names_are_checked() {
    let lab = Lab::signed("again");
    let out = ostena(&[
        "release",
        "sign",
        "--key",
        s(&lab.key),
        "--out",
        s(&lab.manifest),
        s(&lab.dist.join("ostena")),
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("[REL-E008]"), "{}", stderr(&out));

    let odd = lab.dist.join("-flag");
    std::fs::write(&odd, b"x").unwrap();
    let out = ostena(&[
        "release",
        "sign",
        "--key",
        s(&lab.key),
        "--out",
        s(&lab.dir.join("other.manifest")),
        s(&odd),
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("[REL-E001]"), "{}", stderr(&out));
    assert!(!lab.dir.join("other.manifest").exists());

    // A public key is not a signing key.
    let out = ostena(&[
        "release",
        "sign",
        "--key",
        s(&lab.public),
        "--out",
        s(&lab.dir.join("third.manifest")),
        s(&lab.dist.join("ostena")),
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("[REL-E007]"), "{}", stderr(&out));
}

#[test]
fn usage_and_input_errors_exit_with_3() {
    let lab = Lab::signed("usage");
    let out = ostena(&["release", "verify", s(&lab.manifest)]);
    assert_eq!(out.status.code(), Some(3), "missing --key");
    let out = ostena(&[
        "release",
        "verify",
        s(&lab.dir.join("absent.manifest")),
        "--key",
        s(&lab.public),
    ]);
    assert_eq!(out.status.code(), Some(3));
    let out = ostena(&["release", "verify", s(&lab.manifest), "--key", s(&lab.key)]);
    assert_eq!(
        out.status.code(),
        Some(3),
        "a private key is not a public key file"
    );
    // An explicit signature file and directory.
    let moved = lab.dir.join("elsewhere.sig");
    std::fs::rename(lab.dist.join("ostena-release.manifest.sig"), &moved).unwrap();
    let out = lab.verify(&[]);
    assert_eq!(out.status.code(), Some(3));
    let out = lab.verify(&["--signature", s(&moved), "--dir", s(&lab.dist)]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
}
