//! `ostena agent run` connects to the core at startup and `agent status`
//! shows it, with the real binary against the in-process test core.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside #[test] functions"
)]

use std::io::BufRead;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use ostena_crypto::pki::{Validity, pem_certificate};
use ostena_tunnel::testing::{Behaviour, TestCore, valid};
use ostena_tunnel::{Limits, Uuid};

const GROUP: &str = "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6";

struct Agent(Child, PathBuf);

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

/// Starts `agent run` with an identity enrolled on `core`, valid `validity`;
/// the agent dials `address` (the core by default).
fn start_agent(
    core: &TestCore,
    name: &str,
    validity: Validity,
    address: Option<&str>,
) -> (Agent, PathBuf) {
    let dir = std::env::temp_dir().join(format!("ostena-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("state")).unwrap();
    let (cert, key) = core
        .agent_files(Uuid::parse(GROUP).unwrap(), validity)
        .unwrap();
    std::fs::write(dir.join("agent.crt"), cert).unwrap();
    // SECRET-EXPOSURE: test only, the key file `agent enroll` would write.
    #[expect(clippy::disallowed_methods)]
    std::fs::write(dir.join("agent.key"), key.expose_secret()).unwrap();
    std::fs::write(
        dir.join("root.pem"),
        pem_certificate(core.trust_anchor().certificate()),
    )
    .unwrap();
    let path = |p: &str| dir.join(p).display().to_string().replace('\\', "\\\\");
    let endpoint = if cfg!(windows) {
        format!(r"\\\\.\\pipe\\ostena-cli-{name}-{}", std::process::id())
    } else {
        path("run/agent.sock")
    };
    let config = format!(
        "mode = \"development\"\n\n[agent]\ngateway_group = \"{GROUP}\"\ncore_address = \"{}\"\n\
         tls_certificate = \"{}\"\ntls_private_key = \"{}\"\ntls_core_ca = \"{}\"\n\
         replay_journal = \"{}\"\nshutdown_grace_secs = 2\ncontrol_endpoint = \"{endpoint}\"\n",
        address.map_or_else(|| core.addr().to_string(), str::to_owned),
        path("agent.crt"),
        path("agent.key"),
        path("root.pem"),
        path("state/replay.journal"),
    );
    let file = dir.join("ostena.toml");
    std::fs::write(&file, config).unwrap();
    (Agent(run_agent(&file), dir), file)
}

fn run_agent(config: &PathBuf) -> Child {
    Command::new(env!("CARGO_BIN_EXE_ostena"))
        .args(["agent", "run", "--config"])
        .arg(config)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap()
}

impl Agent {
    /// Stops the agent process and starts it again with the same files.
    fn restart(&mut self, config: &PathBuf) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        self.0 = run_agent(config);
    }
}

/// Reads the agent log until a line contains `needle`.
fn read_until(agent: &mut Agent, needle: &str) -> String {
    let stdout = agent.0.stdout.as_mut().unwrap();
    let mut seen = String::new();
    for line in std::io::BufReader::new(stdout).lines() {
        let line = line.unwrap();
        seen.push_str(&line);
        seen.push('\n');
        if line.contains(needle) {
            break;
        }
    }
    seen
}

fn status(agent: &Agent, config: &PathBuf) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_ostena"))
        .args(["agent", "status", "--config"])
        .arg(config)
        .args(["--pid", &agent.0.id().to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn agent_connects_at_startup_and_reports_it() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let core = runtime
        .block_on(async { TestCore::start(Limits::default(), Behaviour::default()) })
        .unwrap();
    let (mut agent, config) = start_agent(&core, "link", valid(), None);
    let log = read_until(&mut agent, "agent.core_connected");
    assert!(log.contains("agent.core_connected"), "{log}");

    let text = status(&agent, &config);
    assert!(text.contains("Core : connecté (QUIC) depuis"), "{text}");
    // 30 days of validity, rounded down to 29 or 30 depending on the second.
    assert!(
        text.contains("Certificat : expire dans 29 j")
            || text.contains("Certificat : expire dans 30 j"),
        "{text}"
    );
    assert!(text.contains("renouvellement automatique dans"), "{text}");

    // The core goes away: the agent reports it and retries.
    core.stop();
    let mut lost = String::new();
    for _ in 0..80 {
        lost = status(&agent, &config);
        if lost.contains("Core : non connecté") {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    assert!(
        lost.contains("Core : non connecté, nouvelle tentative dans"),
        "{lost}"
    );
    drop(core);
    drop(runtime);
}

#[test]
fn overdue_renewal_is_reported_by_status_and_event() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let core = runtime
        .block_on(async { TestCore::start(Limits::default(), Behaviour::default()) })
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // 95 % of a 100-day validity are past; the core cannot be reached, so
    // the renewal cannot happen.
    let late = Validity {
        not_before: now - 95 * 86_400,
        not_after: now + 5 * 86_400,
    };
    let (mut agent, config) = start_agent(&core, "overdue", late, Some("127.0.0.1:9"));
    let log = read_until(&mut agent, "tunnel.renewal_overdue");
    assert!(log.contains("tunnel.renewal_overdue"), "{log}");
    let text = status(&agent, &config);
    assert!(
        text.contains("AVERTISSEMENT : certificat non renouvelé à 90 % de sa validité"),
        "{text}"
    );
}

/// The key set version survives a restart of the agent: after it, a lower
/// version pushed by the core is refused.
#[test]
fn keyset_version_is_kept_across_a_restart() {
    use ostena_tunnel::control::CoreMessage;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let core = runtime
        .block_on(async { TestCore::start(Limits::default(), Behaviour::default()) })
        .unwrap();
    let (mut agent, config) = start_agent(&core, "keyset", valid(), None);
    let log = read_until(&mut agent, "agent.core_connected");
    assert!(log.contains("agent.core_connected"), "{log}");
    let text = status(&agent, &config);
    assert!(text.contains("Politique du core : non reçue"), "{text}");
    assert!(
        text.contains("Clés de grant : non reçues (aucune session possible)"),
        "{text}"
    );

    let push = |version| {
        runtime.block_on(core.push(&CoreMessage::KeySet {
            version,
            keys: vec![core.grant_key()],
        }))
    };
    assert_eq!(push(5), 1);
    let log = read_until(&mut agent, "agent.keyset_applied");
    assert!(log.contains("agent.keyset_applied"), "{log}");
    assert!(status(&agent, &config).contains("Clés de grant : version 5"));

    agent.restart(&config);
    let log = read_until(&mut agent, "agent.core_connected");
    assert!(log.contains("agent.core_connected"), "{log}");
    let text = status(&agent, &config);
    assert!(
        text.contains("Clés de grant : non reçues (dernière version acceptée : 5"),
        "{text}"
    );
    // The connection of the restarted agent is the last one: push to it.
    assert!(push(3) >= 1);
    let log = read_until(&mut agent, "agent.keyset_refused");
    assert!(log.contains("TUN-E024"), "{log}");
    assert!(
        status(&agent, &config).contains("dernière version acceptée : 5"),
        "lower version not applied"
    );
}
