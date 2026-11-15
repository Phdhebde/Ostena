//! The M1 demonstration of the core base (ADR-0011), with the real binary
//! on both ends: the agent enrols with the core, which restarts without
//! losing it; once revoked, the agent is cut off and stays refused after
//! another restart. Needs a PostgreSQL server (see `ostena_core::testing`).

#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test helpers outside #[test] functions"
)]

use std::io::BufRead;
use std::net::{Ipv4Addr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use ostena_common::config::Mode;
use ostena_core::testing::{TestDb, block_on};
use ostena_crypto::p256::SigningKey;
use ostena_crypto::pki::testing::{TestPki, valid};
use ostena_crypto::pki::{pem_certificate, pem_private_key};

const GROUP: &str = "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6";
const WAIT: Duration = Duration::from_secs(20);

/// A free UDP port on 127.0.0.1 (QUIC listeners).
fn free_port() -> u16 {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn write_private(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

/// A process whose standard output is read line by line in a thread.
struct Process {
    child: Child,
    lines: mpsc::Receiver<String>,
    seen: String,
}

impl Process {
    fn spawn(args: &[&str], config: &Path) -> Self {
        let credentials = config.parent().unwrap().join("credentials");
        let mut child = Command::new(env!("CARGO_BIN_EXE_ostena"))
            .args(args)
            .arg("--config")
            .arg(config)
            .env("CREDENTIALS_DIRECTORY", credentials)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            lines,
            seen: String::new(),
        }
    }

    /// Waits for a line containing `needle`; returns it.
    fn wait_for(&mut self, needle: &str) -> String {
        let deadline = Instant::now() + WAIT;
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    self.seen.push_str(&line);
                    self.seen.push('\n');
                    if line.contains(needle) {
                        return line;
                    }
                }
                Err(_) => break,
            }
        }
        panic!("« {needle} » attendu ; journal :\n{}", self.seen);
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Runs a one-shot command; returns its standard output, or panics with
/// its standard error.
fn command(args: &[&str], config: &Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_ostena"))
        .args(args)
        .arg("--config")
        .arg(config)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{args:?} : {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

struct Lab {
    dir: PathBuf,
    core_config: PathBuf,
    agent_config: PathBuf,
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The PKI after a ceremony, the core configuration on `db`, and an agent
/// configuration pointing at it.
fn lab(db: &TestDb) -> Lab {
    let dir = std::env::temp_dir().join(format!("ostena-core-demo-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("agent")).unwrap();
    let pki = TestPki::new("Ostena demo").unwrap();
    let (server_key, server_pkcs8) = SigningKey::generate().unwrap();
    let server = pki
        .root
        .sign_server(&server_key.verifying_key(), &["127.0.0.1"], valid())
        .unwrap();
    let root_pem = pem_certificate(pki.root_anchor().certificate());
    std::fs::write(dir.join("root.pem"), &root_pem).unwrap();
    std::fs::write(dir.join("agent/root.pem"), &root_pem).unwrap();
    std::fs::write(dir.join("server.pem"), pem_certificate(&server)).unwrap();
    std::fs::write(
        dir.join("issuing.pem"),
        pem_certificate(&pki.issuing_certificate),
    )
    .unwrap();
    // The keys as systemd hands them over (LoadCredentialEncrypted=): files
    // in $CREDENTIALS_DIRECTORY, which the core is started with.
    std::fs::create_dir_all(dir.join("credentials")).unwrap();
    // SECRET-EXPOSURE: test only, the key files `ostena ca key new` writes.
    #[expect(clippy::disallowed_methods)]
    write_private(
        &dir.join("credentials/server.key"),
        pem_private_key(&server_pkcs8).expose_secret(),
    );
    // SECRET-EXPOSURE: test only, the key files `ostena ca key new` writes.
    #[expect(clippy::disallowed_methods)]
    write_private(
        &dir.join("credentials/issuing.key"),
        pem_private_key(&pki.issuing_key).expose_secret(),
    );

    let (tunnel, enrollment) = (free_port(), free_port());
    let p = |name: &str| dir.join(name).display().to_string();
    let database = &db.config;
    let connection = match &database.tcp {
        None => format!("socket_dir = \"{}\"\n", database.socket_dir.display()),
        Some(tcp) => format!(
            "[core.database.tcp]\nhost = \"{}\"\n{}",
            tcp.host,
            tcp.password_file
                .as_ref()
                .map(|f| format!("password_file = \"{}\"\n", f.display()))
                .unwrap_or_default()
        ),
    };
    let mode = match db.mode {
        Mode::Production => "production",
        Mode::Development => "development",
    };
    let core_config = dir.join("core.toml");
    std::fs::write(
        &core_config,
        format!(
            "mode = \"{mode}\"\n\n[core]\ntunnel_listen = \"127.0.0.1:{tunnel}\"\n\
             enrollment_listen = \"127.0.0.1:{enrollment}\"\ntls_root_ca = \"{}\"\n\
             tls_certificate = \"{}\"\ntls_private_key = {{ credential = \"server.key\" }}\n\
             issuing_certificate = \"{}\"\nissuing_private_key = {{ credential = \"issuing.key\" }}\n\n\
             [core.database]\nport = {}\nname = \"{}\"\nuser = \"{}\"\n{connection}",
            p("root.pem"),
            p("server.pem"),
            p("issuing.pem"),
            database.port,
            database.name,
            database.user,
        ),
    )
    .unwrap();
    let agent_config = dir.join("agent/ostena.toml");
    std::fs::write(
        &agent_config,
        format!(
            "mode = \"development\"\n\n[agent]\ngateway_group = \"{GROUP}\"\n\
             core_address = \"127.0.0.1:{tunnel}\"\nenrollment_address = \"127.0.0.1:{enrollment}\"\n\
             tls_certificate = \"{}\"\ntls_private_key = \"{}\"\ntls_core_ca = \"{}\"\n\
             replay_journal = \"{}\"\nshutdown_grace_secs = 2\ncontrol_endpoint = \"{}\"\n",
            p("agent/agent.crt"),
            p("agent/agent.key"),
            p("agent/root.pem"),
            p("agent/replay.journal"),
            p("agent/run/agent.sock"),
        ),
    )
    .unwrap();
    Lab {
        dir,
        core_config,
        agent_config,
    }
}

#[test]
fn the_agent_enrols_survives_core_restarts_and_is_cut_off_once_revoked() {
    let Some(db) = block_on(TestDb::create(
        "the_agent_enrols_survives_core_restarts_and_is_cut_off_once_revoked",
    )) else {
        return;
    };
    let lab = lab(&db);
    let mut core = Process::spawn(&["core", "run"], &lab.core_config);
    core.wait_for("core.started");

    // Enrolment with a token issued by the administration command.
    let token = lab.dir.join("token");
    command(
        &[
            "core",
            "agent",
            "token",
            "--group",
            GROUP,
            "--out",
            token.to_str().unwrap(),
        ],
        &lab.core_config,
    );
    core.wait_for("enroll.listener_opened");
    let out = Command::new(env!("CARGO_BIN_EXE_ostena"))
        .args(["agent", "enroll", "--timeout", "5", "--config"])
        .arg(&lab.agent_config)
        .arg("--token-file")
        .arg(&token)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    core.wait_for("enroll.accepted");

    let mut agent = Process::spawn(&["agent", "run"], &lab.agent_config);
    agent.wait_for("agent.core_connected");
    core.wait_for("tunnel.agent_connected");
    let list = command(&["core", "agent", "list"], &lab.core_config);
    let row = list.lines().nth(1).expect("une ligne par agent");
    let fields: Vec<&str> = row.split('\t').collect();
    assert_eq!(fields[1], GROUP, "{list}");
    assert_eq!((fields[3], fields[4]), ("1", "-"), "{list}");
    let agent_id = fields[0].to_owned();

    // The core restarts: the agent comes back without enrolling again.
    core.stop();
    agent.wait_for("agent.core_disconnected");
    let mut core = Process::spawn(&["core", "run"], &lab.core_config);
    core.wait_for("core.started");
    agent.wait_for("agent.core_connected");
    core.wait_for("tunnel.agent_connected");

    // Revocation: the running core closes the tunnel at once.
    command(&["core", "agent", "revoke", &agent_id], &lab.core_config);
    core.wait_for("agent.revocation_applied");
    let cut = agent.wait_for("agent.core_disconnected");
    assert!(cut.contains("TUN-E005"), "{cut}");

    // And after another restart, the agent stays refused.
    core.stop();
    let mut core = Process::spawn(&["core", "run"], &lab.core_config);
    core.wait_for("core.started");
    let refused = agent.wait_for("TUN-E005");
    assert!(!refused.contains("agent.core_connected"), "{refused}");
    let list = command(&["core", "agent", "list"], &lab.core_config);
    assert!(!list.lines().nth(1).unwrap().ends_with("\t-"), "{list}");

    agent.stop();
    core.stop();
    drop(lab);
    block_on(db.drop_database());
}
