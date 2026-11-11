//! End-to-end checks on the built `ostena` binary.

use std::process::Command;

#[test]
fn binary_reports_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_ostena"))
        .arg("--version")
        .output()
        .expect("binary must run");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    assert!(stdout.starts_with("ostena "));
}

#[test]
fn binary_rejects_unknown_argument() {
    let output = Command::new(env!("CARGO_BIN_EXE_ostena"))
        .arg("--nope")
        .output()
        .expect("binary must run");
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn replay_store_repair_keeps_original_and_logs() {
    let dir = std::env::temp_dir().join(format!("ostena-cli-repair-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let journal = dir.join("replay.journal");
    // A damaged journal: valid header, one record with a bad checksum.
    let mut bytes = b"OSTRPL01".to_vec();
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(&[0xab; 28]);
    std::fs::write(&journal, &bytes).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_ostena"))
        .args(["agent", "replay-store", "repair", "--path"])
        .arg(&journal)
        .output()
        .expect("binary must run");
    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    assert!(output.status.success(), "{stdout}");
    assert!(
        stdout.contains("\"event\":\"replay_store.repaired\""),
        "{stdout}"
    );
    assert!(stdout.contains("\"dropped\":1"), "{stdout}");

    let backups: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().contains(".corrupt-"))
        .collect();
    assert_eq!(backups.len(), 1);
    assert_eq!(std::fs::read(backups[0].path()).unwrap(), bytes);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn replay_store_repair_of_missing_file_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_ostena"))
        .args([
            "agent",
            "replay-store",
            "repair",
            "--path",
            "/nonexistent/replay.journal",
        ])
        .output()
        .expect("binary must run");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    assert!(stdout.contains("replay_store.repair_failed"), "{stdout}");
}
