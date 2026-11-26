//! End-to-end checks on the built `ostena` binary.

#![allow(clippy::unwrap_used, reason = "test helpers outside #[test] functions")]

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

/// A development agent configuration in a fresh directory.
fn agent_config(name: &str, mode: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("ostena-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("state")).unwrap();
    let path = |p: &str| dir.join(p).display().to_string().replace('\\', "\\\\");
    // A control endpoint of its own, so that tests do not collide.
    let endpoint = if cfg!(windows) {
        format!(r"\\\\.\\pipe\\ostena-cli-{name}-{}", std::process::id())
    } else {
        path("run/agent.sock")
    };
    let config = format!(
        "mode = \"{mode}\"\n\n[agent]\ngateway_group = \"2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6\"\n\
         core_address = \"core.invalid:8443\"\ntls_certificate = \"{}\"\ntls_private_key = \"{}\"\n\
         replay_journal = \"{}\"\nshutdown_grace_secs = 2\ncontrol_endpoint = \"{endpoint}\"\n",
        path("agent.crt"),
        path("agent.key"),
        path("state/replay.journal"),
    );
    let file = dir.join("ostena.toml");
    std::fs::write(&file, config).unwrap();
    std::fs::write(dir.join("agent.key"), b"key").unwrap();
    (dir, file)
}

#[test]
fn agent_run_refuses_an_invalid_production_configuration() {
    let (dir, file) = agent_config("prod", "production");
    let output = Command::new(env!("CARGO_BIN_EXE_ostena"))
        .args(["agent", "run", "--config"])
        .arg(&file)
        .output()
        .expect("binary must run");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("agent.config_refused"), "{stdout}");
    assert!(stdout.contains("CFG-P007"), "{stdout}"); // no core CA
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn agent_status_reports_a_state() {
    let output = Command::new(env!("CARGO_BIN_EXE_ostena"))
        .args(["agent", "status"])
        .output()
        .expect("binary must run");
    // 4 when not installed (development machines and test runners).
    assert!(
        matches!(output.status.code(), Some(0 | 3 | 4)),
        "{output:?}"
    );
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("Agent : "));
}

/// Kills the agent when the test ends, even on panic, so that an orphan
/// does not keep the test harness waiting on its output.
struct Agent(std::process::Child);

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl std::ops::Deref for Agent {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Agent {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Waits for `needle` on the child's stdout, returning what was read.
fn read_until(child: &mut std::process::Child, needle: &str) -> String {
    use std::io::BufRead;
    let stdout = child.stdout.as_mut().unwrap();
    let mut seen = String::new();
    for line in std::io::BufReader::new(stdout).lines() {
        let line = line.unwrap();
        seen.push_str(&line);
        seen.push('\n');
        if line.contains(needle) {
            return seen;
        }
    }
    seen
}

#[cfg(unix)]
#[test]
fn agent_run_stops_cleanly_on_sigterm() {
    use std::process::Stdio;
    let (dir, file) = agent_config("run", "development");
    let mut child = Agent(
        Command::new(env!("CARGO_BIN_EXE_ostena"))
            .args(["agent", "run", "--config"])
            .arg(&file)
            .stdout(Stdio::piped())
            .spawn()
            .expect("binary must run"),
    );
    let started = read_until(&mut child, "agent.started");
    assert!(started.contains("agent.started"), "{started}");
    let pid = child.id().to_string();
    assert!(
        Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .unwrap()
            .success()
    );
    let rest = read_until(&mut child, "agent.stopped");
    let status = child.wait().unwrap();
    assert!(status.success(), "{rest}");
    assert!(
        rest.contains("agent.stopping") && rest.contains("agent.stopped"),
        "{rest}"
    );
    assert!(dir.join("state/replay.journal").exists());
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(windows)]
#[test]
fn agent_run_starts_in_the_foreground() {
    use std::process::Stdio;
    let (dir, file) = agent_config("run", "development");
    let mut child = Agent(
        Command::new(env!("CARGO_BIN_EXE_ostena"))
            .args(["agent", "run", "--config"])
            .arg(&file)
            .stdout(Stdio::piped())
            .spawn()
            .expect("binary must run"),
    );
    let started = read_until(&mut child, "agent.started");
    // Development mode: the Windows ACL check is reported as a weakening.
    assert!(started.contains("agent.started"), "{started}");
    child.kill().unwrap();
    let _ = child.wait();
    assert!(dir.join("state/replay.journal").exists());
    let _ = std::fs::remove_dir_all(dir);
}

/// A foreground agent answers `status` on its control plane, and a second
/// agent on the same endpoint refuses to start (AGT-E006).
#[test]
fn agent_status_queries_the_control_plane() {
    use std::process::Stdio;
    let (dir, file) = agent_config("status", "development");
    let mut child = Agent(
        Command::new(env!("CARGO_BIN_EXE_ostena"))
            .args(["agent", "run", "--config"])
            .arg(&file)
            .stdout(Stdio::piped())
            .spawn()
            .expect("binary must run"),
    );
    let started = read_until(&mut child, "agent.started");
    assert!(started.contains("agent.started"), "{started}");

    let status = Command::new(env!("CARGO_BIN_EXE_ostena"))
        .args(["agent", "status", "--config"])
        .arg(&file)
        .args(["--pid", &child.id().to_string()])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&status.stdout);
    assert!(
        status.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&status.stderr)
    );
    assert!(
        text.contains("Groupe : 2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6"),
        "{text}"
    );
    assert!(
        text.contains("Empreinte de la configuration : sha256:"),
        "{text}"
    );
    assert!(text.contains("Sessions : 0"), "{text}");

    // Wrong expected process: the server is not trusted (AGT-E007), on
    // Windows where the server process is checked.
    if cfg!(windows) {
        let wrong = Command::new(env!("CARGO_BIN_EXE_ostena"))
            .args(["agent", "status", "--config"])
            .arg(&file)
            .args(["--pid", &(child.id() + 1).to_string()])
            .output()
            .unwrap();
        assert!(
            String::from_utf8_lossy(&wrong.stderr).contains("AGT-E007"),
            "{wrong:?}"
        );
    }

    // Same endpoint, second agent (with its own journal, whose lock would
    // refuse it first otherwise): refused on the control plane name.
    std::fs::create_dir_all(dir.join("state2")).unwrap();
    let text = std::fs::read_to_string(&file)
        .unwrap()
        .replace("state", "state2");
    let second_file = dir.join("second.toml");
    std::fs::write(&second_file, text).unwrap();
    let second = Command::new(env!("CARGO_BIN_EXE_ostena"))
        .args(["agent", "run", "--config"])
        .arg(&second_file)
        .output()
        .unwrap();
    assert_eq!(second.status.code(), Some(1));
    let out = String::from_utf8_lossy(&second.stdout);
    assert!(
        out.contains("agent.control_unavailable") && out.contains("AGT-E006"),
        "{out}"
    );

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(dir);
}

/// The MSI passes every property of `agent setup`, set or not: empty values
/// are accepted by the parser (exit code 2 would be a usage error) and count
/// as absent, so a missing configuration is reported (AGT-E012).
#[test]
fn agent_setup_accepts_empty_values() {
    let dir = std::env::temp_dir().join(format!("ostena-setup-empty-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let out = Command::new(env!("CARGO_BIN_EXE_ostena"))
        .args(["agent", "setup", "--quiet", "--config"])
        .arg(dir.join("ostena.toml"))
        .args([
            "--executable",
            "",
            "--log",
            "",
            "--core-address",
            "",
            "--gateway-group",
            "",
            "--enrollment-address",
            "",
            "--root-ca",
            "",
            "--root-fingerprint",
            "",
            "--token-file",
            "",
        ])
        .output()
        .expect("binary must run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("AGT-E012"), "{stderr}");
    assert!(!dir.exists(), "nothing written");
}
