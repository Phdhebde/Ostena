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
