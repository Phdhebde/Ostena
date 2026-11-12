//! `ostena agent keyset-state repair` with the real binary.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside #[test] functions"
)]

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A development configuration with its own control endpoint; the state
/// file is `state/keyset.version`.
fn setup(name: &str) -> (Dir, PathBuf) {
    let dir = std::env::temp_dir().join(format!("ostena-keyset-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("state")).unwrap();
    let path = |p: &str| dir.join(p).display().to_string().replace('\\', "\\\\");
    let endpoint = if cfg!(windows) {
        format!(r"\\\\.\\pipe\\ostena-keyset-{name}-{}", std::process::id())
    } else {
        path("run/agent.sock")
    };
    let config = format!(
        "mode = \"development\"\n\n[agent]\ngateway_group = \"2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6\"\n\
         core_address = \"core.invalid:8443\"\ntls_certificate = \"{}\"\ntls_private_key = \"{}\"\n\
         replay_journal = \"{}\"\nshutdown_grace_secs = 2\ncontrol_endpoint = \"{endpoint}\"\n",
        path("agent.crt"),
        path("agent.key"),
        path("state/replay.journal"),
    );
    let file = dir.join("ostena.toml");
    std::fs::write(&file, config).unwrap();
    std::fs::write(dir.join("agent.key"), b"key").unwrap();
    (Dir(dir), file)
}

fn state(dir: &Dir) -> PathBuf {
    dir.0.join("state").join("keyset.version")
}

fn backups(dir: &Dir) -> Vec<PathBuf> {
    std::fs::read_dir(dir.0.join("state"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("keyset.version.corrupt-"))
        })
        .collect()
}

fn repair(config: &Path, args: &[&str], input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ostena"))
        .args(["agent", "keyset-state", "repair", "--config"])
        .arg(config)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
    child.wait_with_output().unwrap()
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn corrupt_state_is_reset_after_confirmation_and_kept() {
    let (dir, config) = setup("confirm");
    std::fs::write(state(&dir), "garbage").unwrap();
    let out = repair(&config, &[], "réinitialiser\n");
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("keyset_state.repaired"),
        "{}",
        text(&out)
    );
    assert!(!state(&dir).exists(), "reset");
    let kept = backups(&dir);
    assert_eq!(kept.len(), 1);
    assert_eq!(std::fs::read_to_string(&kept[0]).unwrap(), "garbage");
}

#[test]
fn nothing_happens_without_confirmation() {
    let (dir, config) = setup("refuse");
    std::fs::write(state(&dir), "garbage").unwrap();
    let out = repair(&config, &[], "non\n");
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        text(&out).contains("keyset_state.repair_failed"),
        "{}",
        text(&out)
    );
    assert_eq!(std::fs::read_to_string(state(&dir)).unwrap(), "garbage");
    assert_eq!(backups(&dir), Vec::<PathBuf>::new());
}

#[test]
fn readable_state_is_never_reset() {
    let (dir, config) = setup("readable");
    std::fs::write(state(&dir), "5\n").unwrap();
    let out = repair(&config, &["--yes"], "");
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(text(&out).contains("version 5"), "{}", text(&out));
    assert_eq!(std::fs::read_to_string(state(&dir)).unwrap(), "5\n");
    assert_eq!(backups(&dir), Vec::<PathBuf>::new());
}

#[test]
fn missing_state_needs_nothing() {
    let (dir, config) = setup("missing");
    let out = repair(&config, &["--yes"], "");
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(backups(&dir), Vec::<PathBuf>::new());
}

struct Agent(Child);

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn running_agent_is_not_repaired_under() {
    let (dir, config) = setup("running");
    let mut agent = Agent(
        Command::new(env!("CARGO_BIN_EXE_ostena"))
            .args(["agent", "run", "--config"])
            .arg(&config)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stdout = agent.0.stdout.as_mut().unwrap();
    let started = std::io::BufReader::new(stdout)
        .lines()
        .map_while(Result::ok)
        .any(|l| l.contains("agent.started"));
    assert!(started);
    std::fs::write(state(&dir), "garbage").unwrap();
    let out = repair(&config, &["--yes"], "");
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(text(&out).contains("arrêtez-le"), "{}", text(&out));
    assert_eq!(std::fs::read_to_string(state(&dir)).unwrap(), "garbage");
}
