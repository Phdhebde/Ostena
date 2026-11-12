#![allow(clippy::unwrap_used, reason = "tests")]

use super::{Reader, create};

fn dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ostena-private-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn created_once_never_overwritten() {
    let dir = dir("once");
    let key = dir.join("agent.key");
    create(&key, b"first", Reader::CurrentProcess).unwrap();
    let again = create(&key, b"second", Reader::CurrentProcess).unwrap_err();
    assert_eq!(again.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&key).unwrap(), b"first");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn mode_0600_from_creation() {
    use std::os::unix::fs::PermissionsExt;
    let dir = dir("mode");
    let key = dir.join("agent.key");
    create(&key, b"key", Reader::CurrentProcess).unwrap();
    let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The new key has exactly SYSTEM, the Administrators and the current
/// account, nothing inherited, and passes the `CFG-P008` check.
#[cfg(windows)]
#[test]
fn protected_dacl_from_creation() {
    use crate::acl::{ADMINISTRATORS, SYSTEM, evaluate, read_security};

    let dir = dir("acl");
    let key = dir.join("agent.key");
    create(&key, b"key", Reader::CurrentProcess).unwrap();
    let me = super::current_user_sid().unwrap();
    let security = read_security(&key).unwrap();
    let mut sids: Vec<String> = security
        .dacl
        .clone()
        .unwrap()
        .into_iter()
        .filter(|a| a.allow)
        .map(|a| a.sid)
        .collect();
    sids.sort();
    let mut expected = vec![SYSTEM.to_owned(), ADMINISTRATORS.to_owned(), me.clone()];
    expected.sort();
    expected.dedup();
    assert_eq!(sids, expected);
    let trusted = [SYSTEM, ADMINISTRATORS, me.as_str(), security.owner.as_str()];
    assert_eq!(evaluate("clé", &security, &trusted, true), None);
    // Nothing inherited from the directory: icacls marks inherited entries
    // with "(I)".
    let icacls = std::process::Command::new("icacls")
        .arg(&key)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&icacls.stdout);
    assert!(!text.contains("(I)"), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(windows)]
#[test]
fn reader_ace_reads_and_deletes_only() {
    let sddl = super::imp::sddl(Reader::CurrentProcess).unwrap();
    assert!(sddl.starts_with("D:P(A;;FA;;;SY)(A;;FA;;;BA)"), "{sddl}");
    assert!(
        sddl.ends_with(";;;S-1-5-18)") || sddl.contains("(A;;FRSD;;;"),
        "{sddl}"
    );
}
