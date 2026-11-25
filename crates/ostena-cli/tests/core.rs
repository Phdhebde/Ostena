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

use std::io::{BufRead, Write as _};
use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use ostena_audit::{ExportReader, Frame, Record};
use ostena_common::config::Mode;
use ostena_core::testing::{TestDb, block_on};
use ostena_crypto::p256::SigningKey;
use ostena_crypto::pki::testing::{TestPki, valid};
use ostena_crypto::pki::{encode_public_key, pem_certificate, pem_private_key};
use ostena_crypto::totp::{TotpAlgorithm, TotpSecret, step_at};

const GROUP: &str = "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6";
const WAIT: Duration = Duration::from_secs(20);

/// A free TCP port on 127.0.0.1 (the login listener).
fn free_tcp_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

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

    /// Sends SIGTERM (what systemd does) and waits for a clean exit.
    fn terminate(&mut self) {
        let status = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "{status} ; journal :\n{}", self.seen);
                return;
            }
            assert!(Instant::now() < deadline, "pas d'arrêt après SIGTERM");
            std::thread::sleep(Duration::from_millis(50));
        }
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
    login_port: u16,
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The keys of the core besides TLS, as credentials in `dir/credentials`:
/// the head signing key of the audit chain (its public key in
/// `dir/audit.pub`, for the auditor), the grant signing key and the two SSH
/// authorities (what `ostena ca key new` writes).
fn write_service_keys(dir: &Path) {
    for name in ["audit.key", "grant.key", "user_ca.key", "host_ca.key"] {
        let (key, pkcs8) = SigningKey::generate().unwrap();
        if name == "audit.key" {
            std::fs::write(
                dir.join("audit.pub"),
                encode_public_key(&key.verifying_key()),
            )
            .unwrap();
        }
        // SECRET-EXPOSURE: test only, the key files `ostena ca key new` writes.
        #[expect(clippy::disallowed_methods)]
        write_private(
            &dir.join("credentials").join(name),
            pem_private_key(&pkcs8).expose_secret(),
        );
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
    write_service_keys(&dir);
    // The key of the TOTP secrets: 32 random bytes.
    let totp_key: [u8; 32] = ostena_crypto::rand::array().unwrap();
    write_private(&dir.join("credentials/totp.key"), &totp_key);

    let (tunnel, enrollment, login_port) = (free_port(), free_port(), free_tcp_port());
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
             issuing_certificate = \"{}\"\nissuing_private_key = {{ credential = \"issuing.key\" }}\n\
             grant_signing_key = {{ credential = \"grant.key\" }}\n\n\
             [core.ssh]\nuser_ca_key = {{ credential = \"user_ca.key\" }}\n\
             host_ca_key = {{ credential = \"host_ca.key\" }}\n\n\
             [core.login]\nlisten = \"127.0.0.1:{login_port}\"\n\
             totp_key = {{ credential = \"totp.key\" }}\nssh_hosts = [\"bastion.lab\"]\n\n\
             [core.audit]\nsigning_key = {{ credential = \"audit.key\" }}\nhead_interval_secs = 1\n\
             heartbeat_secs = 60\n\n\
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
        login_port,
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

    inventory_is_administered(&lab, &mut agent);
    login_and_logout(&lab, &mut core);

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

    audit_chain_is_exported_and_verified(&lab, &db, &mut core);

    core.stop();
    drop(lab);
    block_on(db.drop_database());
}

/// The minimal inventory with the administration commands (ADR-0014): the
/// policy of the group reaches the connected agent at once; the dry run
/// says whether an access would be granted.
#[expect(clippy::too_many_lines, reason = "one scenario of commands")]
fn inventory_is_administered(lab: &Lab, agent: &mut Process) {
    let config = &lab.core_config;
    let group = command(
        &[
            "core",
            "group",
            "add",
            "lab",
            "--id",
            GROUP,
            "--host-name",
            "bastion.lab",
        ],
        config,
    );
    assert_eq!(group.trim(), GROUP);
    let policy = lab.dir.join("lab-policy.toml");
    std::fs::write(
        &policy,
        "[[allow]]\nnetworks = [\"10.20.0.0/16\"]\nports = [\"22\"]\n",
    )
    .unwrap();
    let version = command(
        &["core", "group", "policy", "lab", policy.to_str().unwrap()],
        config,
    );
    assert!(version.contains("version"), "{version}");
    agent.wait_for("agent.policy_applied");
    command(
        &[
            "core",
            "user",
            "add",
            "alice",
            "--display-name",
            "Alice Martin",
        ],
        config,
    );
    let host_key = lab.dir.join("ssh_host_ecdsa_key.pub");
    let (target, _) = SigningKey::generate().unwrap();
    std::fs::write(
        &host_key,
        ostena_ssh::keys::public_line(&target.verifying_key(), "root@srv-lab01"),
    )
    .unwrap();
    command(
        &[
            "core",
            "resource",
            "add",
            "srv-lab01",
            "--host",
            "10.20.0.5",
            "--group",
            "lab",
            "--host-key",
            host_key.to_str().unwrap(),
        ],
        config,
    );
    command(
        &["core", "account", "add", "--resource", "srv-lab01", "root"],
        config,
    );
    let right = command(
        &[
            "core",
            "right",
            "grant",
            "--user",
            "alice",
            "--resource",
            "srv-lab01",
            "--account",
            "root",
            "--days",
            "30",
            "--max-session-mins",
            "30",
        ],
        config,
    );
    let check = command(
        &[
            "core",
            "access",
            "check",
            "--user",
            "alice",
            "--resource",
            "srv-lab01",
            "--account",
            "root",
        ],
        config,
    );
    assert!(check.starts_with("autorisé"), "{check}");
    assert!(check.contains(right.trim()), "{check}");
    assert!(check.contains("1800 s"), "{check}");
    command(&["core", "right", "revoke", right.trim()], config);
    let refused = Command::new(env!("CARGO_BIN_EXE_ostena"))
        .args([
            "core",
            "access",
            "check",
            "--user",
            "alice",
            "--resource",
            "srv-lab01",
        ])
        .args(["--account", "root", "--config"])
        .arg(config)
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("ACC-E006"));
    let resources = command(&["core", "resource", "list"], config);
    assert!(
        resources.contains("srv-lab01\t10.20.0.5:22\tlab\toui\troot"),
        "{resources}"
    );
    command(&["core", "user", "disable", "alice"], config);
    let users = command(&["core", "user", "list"], config);
    assert!(users.contains("alice\tAlice Martin\tdisabled"), "{users}");
}

/// Runs `args` with `CREDENTIALS_DIRECTORY` and `input` on its standard
/// input; returns (success, stdout, stderr).
fn run_with_input(args: &[&str], config: Option<&Path>, input: &str) -> (bool, String, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ostena"));
    command.args(args);
    if let Some(config) = config {
        command.arg("--config").arg(config).env(
            "CREDENTIALS_DIRECTORY",
            config.parent().unwrap().join("credentials"),
        );
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// RFC 4648 base32 without padding, as shown by `totp-enroll`.
fn base32_decode(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0);
    for c in text.bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => panic!("base32 : {c}"),
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).unwrap());
        }
    }
    out
}

/// `ostena login` against the running core (ADR-0010, step 1): the
/// administrator sets the password and enrols the TOTP of bob, who logs in
/// with the real client and logs out.
fn login_and_logout(lab: &Lab, core: &mut Process) {
    // The login listener is bound before `core.started`.
    let config = &lab.core_config;
    command(
        &["core", "user", "add", "bob", "--display-name", "Bob Durand"],
        config,
    );
    let password = "un mot de passe assez long";
    let (ok, _, err) = run_with_input(
        &["core", "user", "set-password", "bob", "--stdin"],
        Some(config),
        &format!("{password}\n"),
    );
    assert!(ok, "{err}");
    let (ok, shown, err) =
        run_with_input(&["core", "user", "totp-enroll", "bob"], Some(config), "");
    assert!(ok, "{err}");
    assert!(shown.contains("otpauth://totp/"), "{shown}");
    let base32 = shown
        .lines()
        .find_map(|l| l.trim().strip_prefix("clé : "))
        .expect("clé affichée");
    let secret = TotpSecret::from_bytes(
        TotpAlgorithm::Sha1,
        ostena_common::secret::SecretBytes::from(base32_decode(base32)),
    )
    .unwrap();
    let code = |step: u64| {
        // SECRET-EXPOSURE: test only, the code an authenticator shows.
        #[expect(clippy::disallowed_methods)]
        let shown = secret.code(step).expose_secret().to_owned();
        shown
    };
    let step = step_at(ostena_grant::unix_now());
    let (ok, _, err) = run_with_input(
        &["core", "user", "totp-enroll", "bob", "--confirm", "--stdin"],
        Some(config),
        &format!("{}\n", code(step)),
    );
    assert!(ok, "{err}");
    let users = command(&["core", "user", "list"], config);
    assert!(
        users.contains("bob\tBob Durand\tactive\toui\toui\t-"),
        "{users}"
    );

    // The client: password and code on standard input.
    let dir = lab.dir.join("bob");
    let core_address = format!("127.0.0.1:{}", lab.login_port);
    let root = lab.dir.join("root.pem");
    let login = |code: String| {
        run_with_input(
            &[
                "login",
                "--core",
                &core_address,
                "--root",
                root.to_str().unwrap(),
                "--user",
                "bob",
                "--dir",
                dir.to_str().unwrap(),
                "--stdin",
            ],
            None,
            &format!("{password}\n{code}\n"),
        )
    };
    // The confirmed code is spent.
    let (ok, _, err) = login(code(step));
    assert!(!ok && err.contains("AUTH-E001"), "{err}");
    let (ok, out, err) = login(code(step + 1));
    assert!(ok, "{err}");
    assert!(out.contains("Connecté : session"), "{out}");
    for name in [
        "id_ecdsa",
        "id_ecdsa-cert.pub",
        "known_hosts",
        "ssh_config",
        "root.pem",
    ] {
        assert!(dir.join(name).exists(), "{name}");
    }
    core.wait_for("login.succeeded");

    let (ok, out, err) = run_with_input(&["logout", "--dir", dir.to_str().unwrap()], None, "");
    assert!(ok, "{err}");
    assert!(out.contains("fermée"), "{out}");
    assert!(!dir.join("id_ecdsa").exists());
    core.wait_for("login_session.revoked");
}

/// `ostena audit verify <export> --key audit.pub`: exit code and report.
fn verify(lab: &Lab, export: &Path) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_ostena"))
        .args(["audit", "verify"])
        .arg(export)
        .arg("--key")
        .arg(lab.dir.join("audit.pub"))
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// The audit chain of the demonstration: exported, then verified offline
/// with the public key only; a graceful stop ends it with `core.stopped`
/// and a last head; an edit by the database owner is found.
fn audit_chain_is_exported_and_verified(lab: &Lab, db: &TestDb, core: &mut Process) {
    let mut attempt = 0;
    let deadline = Instant::now() + WAIT;
    let report = loop {
        attempt += 1;
        let export = lab.dir.join(format!("audit-{attempt}.ostaud"));
        let out = command(
            &["core", "audit", "export", "--out", export.to_str().unwrap()],
            &lab.core_config,
        );
        assert!(out.contains("enregistrements"), "{out}");
        let (exit, report) = verify(lab, &export);
        if exit == 0 || Instant::now() > deadline {
            assert_eq!(exit, 0, "{report}");
            break report;
        }
        std::thread::sleep(Duration::from_millis(300));
    };
    assert!(report.contains("Résultat : chaîne intacte"), "{report}");
    let again = lab.dir.join("audit-1.ostaud");
    let refused = Command::new(env!("CARGO_BIN_EXE_ostena"))
        .args(["core", "audit", "export", "--out", again.to_str().unwrap()])
        .arg("--config")
        .arg(&lab.core_config)
        .output()
        .unwrap();
    assert!(!refused.status.success(), "an export was overwritten");
    let head = command(&["core", "audit", "head"], &lab.core_config);
    assert!(head.starts_with("ostena-audit-head-v1:"), "{head}");
    let online = Command::new(env!("CARGO_BIN_EXE_ostena"))
        .args(["core", "audit", "verify", "--key"])
        .arg(lab.dir.join("audit.pub"))
        .arg("--config")
        .arg(&lab.core_config)
        .output()
        .unwrap();
    assert!(
        matches!(online.status.code(), Some(0 | 2)),
        "{}",
        String::from_utf8_lossy(&online.stdout)
    );

    // SIGTERM: the core writes core.stopped, then signs a last head over it.
    core.terminate();
    let stopped = lab.dir.join("audit-stopped.ostaud");
    command(
        &[
            "core",
            "audit",
            "export",
            "--out",
            stopped.to_str().unwrap(),
        ],
        &lab.core_config,
    );
    let (exit, report) = verify(lab, &stopped);
    assert_eq!(exit, 0, "{report}");
    let frames: Vec<Frame> = ExportReader::new(std::fs::File::open(&stopped).unwrap())
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let last = frames
        .iter()
        .rposition(|f| matches!(f, Frame::Record(_)))
        .unwrap();
    let Frame::Record(body) = &frames[last] else {
        unreachable!()
    };
    let record = Record::decode(body).unwrap();
    assert_eq!(record.event, "core.stopped");
    assert!(
        matches!(&frames[last + 1], Frame::Head(h) if h.record_seq() == record.seq),
        "{:?}",
        &frames[last + 1..]
    );

    // The owner of the database edits a record behind the triggers: the
    // next export does not verify.
    block_on(db.execute(
        "ALTER TABLE audit_record DISABLE TRIGGER USER;
         UPDATE audit_record SET body = overlay(body placing '\\xffff'::bytea from 60 for 2)
             WHERE seq = 2;
         ALTER TABLE audit_record ENABLE TRIGGER USER;",
    ));
    let tampered = lab.dir.join("audit-tampered.ostaud");
    command(
        &[
            "core",
            "audit",
            "export",
            "--out",
            tampered.to_str().unwrap(),
        ],
        &lab.core_config,
    );
    let (exit, report) = verify(lab, &tampered);
    assert_eq!(exit, 1, "{report}");
    assert!(report.contains("AUD-E007"), "{report}");
}
