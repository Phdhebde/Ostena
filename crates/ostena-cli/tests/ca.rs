//! The root ceremony with the real binary: `ostena ca root init`, `key new`,
//! `issuing sign`, `server sign`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside #[test] functions"
)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn ostena(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ostena"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ostena-ca-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// Runs `root init` into two media and returns the passphrase printed.
fn init(dir: &Path) -> (PathBuf, String) {
    let (a, b) = (dir.join("media-a"), dir.join("media-b"));
    let out = ostena(
        &[
            "ca",
            "root",
            "init",
            "--name",
            "Ostena test root",
            "--out",
            s(&a),
            "--out",
            s(&b),
        ],
        "",
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("Empreinte SHA-256 du certificat racine : "));
    let mut passphrase = String::new();
    for line in stdout.lines().filter(|l| l.contains("Dépositaire")) {
        passphrase.push_str(line.split(':').nth(1).unwrap().trim());
        passphrase.push(' ');
    }
    assert_eq!(passphrase.split_whitespace().count(), 6, "{stdout}");
    for media in [&a, &b] {
        for file in ["root.pem", "root.name", "root.key.sealed"] {
            assert!(media.join(file).exists(), "{file}");
        }
    }
    (a, passphrase)
}

#[test]
fn full_ceremony() {
    let dir = temp("full");
    let (media, passphrase) = init(&dir);

    // On the core: two keys, their public halves carried to the ceremony.
    for name in ["issuing", "server"] {
        let out = ostena(
            &[
                "ca",
                "key",
                "new",
                "--key-out",
                s(&dir.join(format!("{name}.key"))),
                "--public-out",
                s(&dir.join(format!("{name}.pub"))),
            ],
            "",
        );
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let key = std::fs::read_to_string(dir.join(format!("{name}.key"))).unwrap();
        assert!(key.starts_with("-----BEGIN PRIVATE KEY-----"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join(format!("{name}.key")))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    let issuing = ostena(
        &[
            "ca",
            "issuing",
            "sign",
            "--root",
            s(&media),
            "--public-key",
            s(&dir.join("issuing.pub")),
            "--name",
            "Ostena issuing 2026",
            "--out",
            s(&dir.join("issuing.pem")),
        ],
        &format!("{passphrase}\n"),
    );
    assert!(
        issuing.status.success(),
        "{}",
        String::from_utf8_lossy(&issuing.stderr)
    );

    let server = ostena(
        &[
            "ca",
            "server",
            "sign",
            "--root",
            s(&media),
            "--public-key",
            s(&dir.join("server.pub")),
            "--name",
            "core.example.test",
            "--out",
            s(&dir.join("server.pem")),
        ],
        // Typed back in lower case, with dashes: accepted.
        &format!("{}\n", passphrase.to_lowercase().replace(' ', "-")),
    );
    assert!(
        server.status.success(),
        "{}",
        String::from_utf8_lossy(&server.stderr)
    );
    for cert in ["issuing.pem", "server.pem"] {
        let pem = std::fs::read_to_string(dir.join(cert)).unwrap();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"), "{cert}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wrong_passphrase_signs_nothing() {
    let dir = temp("wrong");
    let (media, _) = init(&dir);
    let out = ostena(
        &[
            "ca",
            "key",
            "new",
            "--key-out",
            s(&dir.join("k.key")),
            "--public-out",
            s(&dir.join("k.pub")),
        ],
        "",
    );
    assert!(out.status.success());
    let out = ostena(
        &[
            "ca",
            "issuing",
            "sign",
            "--root",
            s(&media),
            "--public-key",
            s(&dir.join("k.pub")),
            "--name",
            "x",
            "--out",
            s(&dir.join("x.pem")),
        ],
        &format!("{}\n", "A".repeat(30)),
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("phrase secrète fausse"));
    assert!(!dir.join("x.pem").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn root_init_needs_two_media_and_never_overwrites() {
    let dir = temp("guard");
    let one = ostena(
        &[
            "ca",
            "root",
            "init",
            "--name",
            "r",
            "--out",
            s(&dir.join("only")),
        ],
        "",
    );
    assert!(!one.status.success());
    assert!(String::from_utf8_lossy(&one.stderr).contains("au moins deux --out"));

    let (media, _) = init(&dir);
    let before = std::fs::read(media.join("root.key.sealed")).unwrap();
    let again = ostena(
        &[
            "ca",
            "root",
            "init",
            "--name",
            "r",
            "--out",
            s(&media),
            "--out",
            s(&dir.join("other")),
        ],
        "",
    );
    assert!(!again.status.success());
    assert_eq!(
        std::fs::read(media.join("root.key.sealed")).unwrap(),
        before
    );
    let _ = std::fs::remove_dir_all(&dir);
}
