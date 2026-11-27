use std::io::Write;
use std::path::PathBuf;

use super::*;

fn dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ostena-worm-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Whether this host lets the tests set the attributes (root with
/// `CAP_LINUX_IMMUTABLE` on a supporting file system); CI runners do not.
fn supported(dir: &Path) -> bool {
    match probe(dir) {
        Ok(()) => true,
        Err(e) => {
            assert!(
                matches!(
                    e.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported
                ),
                "{e:?}"
            );
            false
        }
    }
}

#[test]
fn the_probe_leaves_nothing_behind() {
    let dir = dir("probe");
    let _ = probe(&dir);
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_leftover_probe_file_is_removed() {
    let dir = dir("leftover");
    std::fs::write(dir.join(PROBE), b"x").unwrap();
    let _ = probe(&dir);
    if supported(&dir) {
        assert!(!dir.join(PROBE).exists());
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn an_unprotected_file_reads_as_none_or_unsupported() {
    let dir = dir("none");
    let path = dir.join("f");
    let file = File::create(&path).unwrap();
    match protection(&file) {
        Ok(p) => assert_eq!(p, Protection::None),
        Err(e) => assert_eq!(e.kind(), io::ErrorKind::Unsupported),
    }
    drop(file);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn append_only_then_immutable_forbid_rewriting_and_removal() {
    let dir = dir("cycle");
    if !supported(&dir) {
        std::fs::remove_dir_all(&dir).unwrap();
        return;
    }
    let path = dir.join("t.cast");
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    protect(&file, Protection::AppendOnly).unwrap();
    assert_eq!(protection(&file).unwrap(), Protection::AppendOnly);
    file.write_all(b"one\n").unwrap();
    // Appending goes on through the open descriptor; nothing else works.
    assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err());
    assert!(File::create(&path).is_err());
    assert!(std::fs::remove_file(&path).is_err());
    assert!(std::fs::rename(&path, dir.join("other")).is_err());
    file.write_all(b"two\n").unwrap();

    protect(&file, Protection::Immutable).unwrap();
    assert_eq!(protection(&file).unwrap(), Protection::Immutable);
    assert!(
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .is_err()
    );
    assert!(std::fs::remove_file(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"one\ntwo\n");

    // A read-only descriptor is enough to read and change the attributes.
    let reader = File::open(&path).unwrap();
    assert_eq!(protection(&reader).unwrap(), Protection::Immutable);
    protect(&reader, Protection::None).unwrap();
    drop((file, reader));
    std::fs::remove_dir_all(&dir).unwrap();
}
