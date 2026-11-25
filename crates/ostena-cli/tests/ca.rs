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

/// Runs `root init` into two media and returns the three shares printed.
fn init(dir: &Path) -> (PathBuf, Vec<String>) {
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
    let shares: Vec<String> = stdout
        .lines()
        .filter(|l| l.trim_start().starts_with("Dépositaire"))
        .map(|l| l.split(':').nth(1).unwrap().trim().to_owned())
        .collect();
    assert_eq!(shares.len(), 3, "{stdout}");
    for media in [&a, &b] {
        for file in ["root.pem", "root.name", "root.key.sealed"] {
            assert!(media.join(file).exists(), "{file}");
        }
    }
    (a, shares)
}

#[test]
fn full_ceremony() {
    let dir = temp("full");
    let (media, shares) = init(&dir);

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
        // Custodians 1 and 2.
        &format!("{}\n{}\n\n", shares[0], shares[1]),
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
        // Custodians 3 and 1, typed back in lower case with spaces: accepted.
        &format!(
            "{}\n{}\n\n",
            shares[2].to_lowercase().replace('-', " "),
            shares[0]
        ),
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
fn one_share_or_shares_of_another_root_sign_nothing() {
    let dir = temp("wrong");
    let (media, shares) = init(&dir);
    let (_, others) = init(&dir.join("other-root"));
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
    let sign = |stdin: String| {
        ostena(
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
            &stdin,
        )
    };
    for (stdin, expected) in [
        // A single share, whichever it is.
        (format!("{}\n\n", shares[0]), "deux parts"),
        (format!("{}\n\n", shares[2]), "deux parts"),
        // Twice the same share.
        (format!("{}\n{}\n\n", shares[1], shares[1]), "deux parts"),
        // A share of this root and one of another root.
        (
            format!("{}\n{}\n\n", shares[0], others[1]),
            "parts d'une autre racine",
        ),
        // A mistyped share.
        (
            format!("{}X\n{}\n\n", shares[0], shares[1]),
            "part mal recopiée",
        ),
    ] {
        let out = sign(stdin);
        assert!(!out.status.success());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(expected), "{stderr}");
        assert!(!dir.join("x.pem").exists());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The command key (ADR-0016): 32 random bytes, private, never overwritten.
#[test]
fn key_new_mac_writes_32_private_bytes_once() {
    let dir = temp("mac");
    let out = dir.join("mac.key");
    let first = ostena(&["ca", "key", "new-mac", "--out", s(&out)], "");
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let key = std::fs::read(&out).unwrap();
    assert_eq!(key.len(), 32);
    assert!(key.iter().any(|b| *b != key[0]));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&out).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let again = ostena(&["ca", "key", "new-mac", "--out", s(&out)], "");
    assert!(!again.status.success());
    assert_eq!(std::fs::read(&out).unwrap(), key);
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

#[test]
fn reseal_gives_new_shares_and_retires_the_old_ones() {
    let dir = temp("reseal");
    let (media, old) = init(&dir);
    let (a, b) = (dir.join("new-a"), dir.join("new-b"));
    let out = ostena(
        &[
            "ca",
            "root",
            "reseal",
            "--root",
            s(&media),
            "--out",
            s(&a),
            "--out",
            s(&b),
        ],
        // The custodian of share 1 lost the envelope: shares 2 and 3.
        &format!("{}\n{}\n\n", old[1], old[2]),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let new: Vec<String> = stdout
        .lines()
        .filter(|l| l.trim_start().starts_with("Dépositaire"))
        .map(|l| l.split(':').nth(1).unwrap().trim().to_owned())
        .collect();
    assert_eq!(new.len(), 3);
    // Same root certificate, new seal.
    assert_eq!(
        std::fs::read(media.join("root.pem")).unwrap(),
        std::fs::read(a.join("root.pem")).unwrap()
    );
    assert_ne!(
        std::fs::read(media.join("root.key.sealed")).unwrap(),
        std::fs::read(a.join("root.key.sealed")).unwrap()
    );
    let key = |name: &str| {
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
        assert!(out.status.success());
    };
    key("k");
    let sign = |root: &Path, shares: [&str; 2], out: &str| {
        ostena(
            &[
                "ca",
                "issuing",
                "sign",
                "--root",
                s(root),
                "--public-key",
                s(&dir.join("k.pub")),
                "--name",
                "x",
                "--out",
                s(&dir.join(out)),
            ],
            &format!("{}\n{}\n\n", shares[0], shares[1]),
        )
    };
    // The new seal opens with the new shares, not with the old ones.
    assert!(sign(&a, [&new[0], &new[2]], "new.pem").status.success());
    assert!(!sign(&a, [&old[0], &old[1]], "old.pem").status.success());
    let _ = std::fs::remove_dir_all(&dir);
}
