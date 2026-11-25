//! Native SSH access through the real agent (ADR-0010): `ostena agent run`
//! with `[agent.ssh]`, against the in-process test core, reached by the
//! OpenSSH client with a certificate as `ostena login` issues it.
//!
//! - Always (an OpenSSH client is enough): keys created private at the
//!   first start, host key sent to the core with its proof, identity built
//!   from the pushed trust (a host certificate signed by another authority
//!   than the pushed host authority is refused), `ostena agent ssh-key`,
//!   status; refusals: expired
//!   certificate, no right (resource unknown to the core), target refused by
//!   the scope control (loopback); clean stop.
//! - With a target, the full path to it: `OSTENA_E2E_TARGET` (ip:port, not
//!   an address of this host: the scope control refuses those),
//!   `OSTENA_E2E_TARGET_USER`, `OSTENA_E2E_TARGET_HOST_KEY` (file holding its
//!   ECDSA P-256 host key line) and `OSTENA_E2E_AGENT_KEY` (private key whose
//!   public key the target account holds as `restrict,from=`), as
//!   `tests/ssh/native-e2e.sh` sets them. The agent key is imported as its
//!   key on the targets. Then: a session, a revocation that cuts a session,
//!   a target whose host key differs from the pinned one.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stderr,
    clippy::panic,
    reason = "test helpers outside #[test] functions"
)]

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ostena_common::config::scope::{AllowRuleSpec, PolicySpec};
use ostena_common::secret::SecretBytes;
use ostena_crypto::p256::{SigningKey, VerifyingKey};
use ostena_crypto::pki::pem_certificate;
use ostena_platform::private_file::{self, Reader};
use ostena_ssh::cert::{self, Kind, Template};
use ostena_tunnel::control::CoreMessage;
use ostena_tunnel::testing::{Behaviour, SshResource, TestCore, valid};
use ostena_tunnel::{Limits, Uuid};

const GROUP: &str = "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6";
const SUBJECT: &str = "5d1c2b3a-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
const LOGIN: &str = "7a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";

/// The OpenSSH client, or `None` (test skipped) unless
/// `OSTENA_REQUIRE_OPENSSH=1`.
fn ssh_client() -> Option<PathBuf> {
    let candidates = if cfg!(windows) {
        vec![
            PathBuf::from(r"C:\Windows\System32\OpenSSH\ssh.exe"),
            PathBuf::from("ssh.exe"),
        ]
    } else {
        vec![PathBuf::from("ssh")]
    };
    let found = candidates
        .into_iter()
        .find(|c| Command::new(c).arg("-V").output().is_ok());
    if found.is_none() {
        assert!(
            std::env::var("OSTENA_REQUIRE_OPENSSH").as_deref() != Ok("1"),
            "ssh introuvable alors que OSTENA_REQUIRE_OPENSSH=1"
        );
        eprintln!("ssh introuvable : test sauté");
    }
    found
}

/// The target of the full path, from the environment.
struct Target {
    address: std::net::SocketAddr,
    user: String,
    host_key: VerifyingKey,
    agent_key: PathBuf,
}

fn target() -> Option<Target> {
    let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let address = var("OSTENA_E2E_TARGET")?;
    Some(Target {
        address: address.parse().expect("OSTENA_E2E_TARGET ip:port"),
        user: var("OSTENA_E2E_TARGET_USER").expect("OSTENA_E2E_TARGET_USER"),
        host_key: point_of_line(
            &std::fs::read_to_string(
                var("OSTENA_E2E_TARGET_HOST_KEY").expect("OSTENA_E2E_TARGET_HOST_KEY"),
            )
            .unwrap(),
        ),
        agent_key: var("OSTENA_E2E_AGENT_KEY")
            .expect("OSTENA_E2E_AGENT_KEY")
            .into(),
    })
}

/// The P-256 point of an OpenSSH public key line.
fn point_of_line(line: &str) -> VerifyingKey {
    let blob = STANDARD
        .decode(line.split_whitespace().nth(1).unwrap())
        .unwrap();
    let point: [u8; 65] = blob[blob.len() - 65..].try_into().unwrap();
    VerifyingKey::from_bytes(&point).unwrap()
}

fn public_line(key: &VerifyingKey) -> String {
    let mut blob = Vec::new();
    for part in [&b"ecdsa-sha2-nistp256"[..], b"nistp256", &key.to_bytes()] {
        blob.extend_from_slice(&u32::try_from(part.len()).unwrap().to_be_bytes());
        blob.extend_from_slice(part);
    }
    format!("ecdsa-sha2-nistp256 {}", STANDARD.encode(blob))
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The agent process and its log, read in the background.
struct Agent {
    child: Child,
    log: Arc<Mutex<Vec<String>>>,
    dir: PathBuf,
    config: PathBuf,
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Agent {
    fn start(core: &TestCore, name: &str, port: u16, target: Option<&Target>) -> Self {
        let dir = std::env::temp_dir().join(format!("ostena-cli-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("state")).unwrap();
        let (cert, key) = core
            .agent_files(Uuid::parse(GROUP).unwrap(), valid())
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
        if let Some(target) = target {
            // An imported key on the targets, private as the agent wants it.
            let bytes = std::fs::read(&target.agent_key).unwrap();
            private_file::create(
                &dir.join("state/ssh_target_key"),
                &bytes,
                Reader::CurrentProcess,
            )
            .unwrap();
        }
        let path = |p: &str| dir.join(p).display().to_string().replace('\\', "\\\\");
        let endpoint = if cfg!(windows) {
            format!(r"\\\\.\\pipe\\ostena-cli-{name}-{}", std::process::id())
        } else {
            path("run/agent.sock")
        };
        let config = format!(
            "mode = \"development\"\n\n[agent]\ngateway_group = \"{GROUP}\"\n\
             core_address = \"{}\"\ntls_certificate = \"{}\"\ntls_private_key = \"{}\"\n\
             tls_core_ca = \"{}\"\nreplay_journal = \"{}\"\nshutdown_grace_secs = 3\n\
             control_endpoint = \"{endpoint}\"\n\n[[agent.scope.allow]]\n\
             networks = [\"0.0.0.0/0\"]\nports = [\"1-65535\"]\n\n[agent.ssh]\n\
             listen = [\"127.0.0.1:{port}\"]\n",
            core.addr(),
            path("agent.crt"),
            path("agent.key"),
            path("root.pem"),
            path("state/replay.journal"),
        );
        let config_path = dir.join("ostena.toml");
        std::fs::write(&config_path, config).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_ostena"))
            .args(["agent", "run", "--config"])
            .arg(&config_path)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let log: Arc<Mutex<Vec<String>>> = Arc::default();
        std::thread::spawn({
            let log = log.clone();
            move || {
                for line in std::io::BufReader::new(stdout).lines() {
                    let Ok(line) = line else { break };
                    log.lock().unwrap().push(line);
                }
            }
        });
        Self {
            child,
            log,
            dir,
            config: config_path,
        }
    }

    /// The log lines of `event`, waiting up to 20 s for one.
    fn wait_event(&self, event: &str) -> Vec<String> {
        let needle = format!("\"event\":\"{event}\"");
        for _ in 0..400 {
            let found: Vec<String> = self
                .log
                .lock()
                .unwrap()
                .iter()
                .filter(|l| l.contains(&needle))
                .cloned()
                .collect();
            if !found.is_empty() {
                return found;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!(
            "événement {event} absent ; journal :\n{}",
            self.log.lock().unwrap().join("\n")
        );
    }

    fn has_event(&self, event: &str) -> bool {
        let needle = format!("\"event\":\"{event}\"");
        self.log.lock().unwrap().iter().any(|l| l.contains(&needle))
    }

    fn cli(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_ostena"))
            .args(["agent"])
            .args(args)
            .arg("--config")
            .arg(&self.config)
            .output()
            .unwrap()
    }
}

/// What `ostena login` gives the user: a key and its certificate.
struct User {
    key: PathBuf,
    dir: PathBuf,
}

impl User {
    fn new(dir: &Path) -> Self {
        let generated = ostena_ssh::keys::generate("user").unwrap();
        let key = dir.join("user");
        // SECRET-EXPOSURE: test only, the key `ostena login` would write.
        #[expect(clippy::disallowed_methods)]
        private_file::create(
            &key,
            generated.private.expose_secret(),
            Reader::CurrentProcess,
        )
        .unwrap();
        std::fs::write(dir.join("user.pub"), &generated.public).unwrap();
        Self {
            key,
            dir: dir.to_path_buf(),
        }
    }

    /// A certificate of the user key signed by `ca`, valid from `after` to
    /// `before` (Unix seconds); returns its path.
    fn certify(&self, name: &str, ca: &SigningKey, after: u64, before: u64) -> PathBuf {
        let public = point_of_line(&std::fs::read_to_string(self.dir.join("user.pub")).unwrap());
        let blob = cert::issue(
            &Template {
                kind: Kind::User,
                public,
                serial: 1,
                key_id: LOGIN.into(),
                principals: vec![SUBJECT.into()],
                valid_after: after,
                valid_before: before,
                critical_options: vec![],
                extensions: vec![],
            },
            ca,
        )
        .unwrap();
        let path = self.dir.join(format!("{name}-cert.pub"));
        std::fs::write(
            &path,
            format!("{} {} user\n", cert::CERT_TYPE, STANDARD.encode(blob)),
        )
        .unwrap();
        path
    }
}

/// Runs `ssh login@127.0.0.1 command` through the agent.
fn ssh(
    client: &Path,
    user: &User,
    certificate: &Path,
    port: u16,
    login: &str,
    command: &str,
) -> Output {
    let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
    Command::new(client)
        .args([
            "-F",
            "none",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
        ])
        .arg("-o")
        .arg(format!(
            "UserKnownHostsFile={}",
            user.dir.join("known_hosts").display()
        ))
        .args(["-o", &format!("GlobalKnownHostsFile={null}")])
        .args(["-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none"])
        .args(["-o", "ConnectTimeout=10"])
        .arg("-o")
        .arg(format!("CertificateFile={}", certificate.display()))
        .arg("-i")
        .arg(&user.key)
        .args(["-p", &port.to_string(), "-l", login, "127.0.0.1", command])
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

/// Waits until `check` holds, up to 20 s.
fn until(mut check: impl FnMut() -> bool) -> bool {
    for _ in 0..400 {
        if check() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// The agent connected to the core, its SSH identity built: keys, policy,
/// trust with a host certificate issued for the host key the agent sent.
fn ready_agent(
    runtime: &tokio::runtime::Runtime,
    core: &TestCore,
    name: &str,
    target: Option<&Target>,
) -> (Agent, u16) {
    let port = free_port();
    let agent = Agent::start(core, name, port, target);
    agent.wait_event("agent.ssh_started");
    agent.wait_event("agent.core_connected");
    assert!(
        until(|| !core.ssh_host_keys().is_empty()),
        "clé d'hôte non reçue"
    );
    let host_key = core.ssh_host_keys()[0];
    let host_ca = core.ssh_host_ca();
    let host_certificate = host_certificate_by(host_key, host_ca);
    let networks = target.map_or_else(
        || vec!["10.0.0.0/8".to_owned(), "127.0.0.0/8".to_owned()],
        |t| vec![format!("{}/32", t.address.ip()), "127.0.0.0/8".to_owned()],
    );
    runtime.block_on(async {
        core.push(&CoreMessage::KeySet {
            version: 1,
            keys: vec![core.grant_key()],
        })
        .await;
        core.push(&CoreMessage::Policy {
            version: 1,
            policy: PolicySpec {
                gateway_group: GROUP.into(),
                allow: vec![AllowRuleSpec {
                    label: Some("tests".into()),
                    networks,
                    ports: vec!["1-65535".into()],
                }],
                ..PolicySpec::default()
            },
        })
        .await;
        // Signed by another authority than the pushed one: refused, and
        // the server stays without identity.
        let stranger = SigningKey::generate().unwrap().0;
        core.push_ssh_trust(1, Some(&host_certificate_by(host_key, &stranger)))
            .await;
    });
    assert!(
        agent.wait_event("agent.ssh_identity_refused")[0].contains("SSH-E018"),
        "refus sans SSH-E018"
    );
    runtime.block_on(core.push_ssh_trust(2, Some(&host_certificate)));
    agent.wait_event("agent.ssh_identity_ready");
    std::fs::write(
        agent.dir.join("known_hosts"),
        format!(
            "@cert-authority [127.0.0.1]:{port} {}\n",
            public_line(&host_ca.verifying_key())
        ),
    )
    .unwrap();
    (agent, port)
}

/// A host certificate of `host_key` for 127.0.0.1, signed by `ca`.
fn host_certificate_by(host_key: VerifyingKey, ca: &SigningKey) -> Vec<u8> {
    let now = ostena_grant::unix_now();
    cert::issue(
        &Template {
            kind: Kind::Host,
            public: host_key,
            serial: 1,
            key_id: "agent".into(),
            principals: vec!["127.0.0.1".into()],
            valid_after: now - 60,
            valid_before: now + 86_400,
            critical_options: vec![],
            extensions: vec![],
        },
        ca,
    )
    .unwrap()
}

#[test]
fn native_ssh_through_the_real_agent() {
    let Some(client) = ssh_client() else { return };
    let runtime = runtime();
    let core = runtime
        .block_on(async { TestCore::start(Limits::default(), Behaviour::default()) })
        .unwrap();
    let target = target();
    let (agent, port) = ready_agent(&runtime, &core, "agent-ssh", target.as_ref());

    // Keys created by the agent, private, and the host key sent is its own.
    let state = agent.dir.join("state");
    for name in ["ssh_host_key", "ssh_target_key"] {
        assert!(state.join(name).exists(), "{name}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(state.join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{name}");
        }
    }
    let host = SecretBytes::from(std::fs::read(state.join("ssh_host_key")).unwrap());
    let (host, _) = ostena_ssh::keys::decode(&host).unwrap();
    assert_eq!(core.ssh_host_keys()[0], host.verifying_key());
    assert!(
        std::fs::read_to_string(state.join("ssh_host_certificate"))
            .unwrap()
            .starts_with(cert::CERT_TYPE)
    );

    // ostena agent ssh-key: the line to deposit on the targets.
    let out = agent.cli(&["ssh-key", "--line", "--from", "10.20.0.11,10.20.0.12"]);
    assert!(out.status.success(), "{out:?}");
    let line = String::from_utf8(out.stdout).unwrap();
    assert!(
        line.starts_with("restrict,from=\"10.20.0.11,10.20.0.12\" ecdsa-sha2-nistp256 "),
        "{line}"
    );
    let out = agent.cli(&["ssh-key"]);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("ADRESSES_DES_AGENTS"), "{text}");
    assert!(text.contains("Certificat d'hôte : valide encore"), "{text}");
    assert!(!agent.cli(&["ssh-key", "--from", "x\"y"]).status.success());

    let user = User::new(&agent.dir);
    let now = ostena_grant::unix_now();
    let fresh = user.certify("fresh", core.ssh_user_ca(), now - 60, now + 3600);

    // Refused: an expired certificate, a resource unknown to the core, a
    // target on the loopback (scope control).
    let expired = user.certify("expired", core.ssh_user_ca(), now - 7200, now - 3600);
    let out = ssh(&client, &user, &expired, port, "root@srv", "true");
    assert!(!out.status.success());
    agent.wait_event("ssh.auth_refused");
    let out = ssh(&client, &user, &fresh, port, "root@unknown", "true");
    assert!(!out.status.success());
    let refused = agent.wait_event("ssh.access_refused");
    assert!(
        refused.iter().any(|l| l.contains("SSH-E013")),
        "{refused:?}"
    );
    core.add_ssh_resource(
        "loop",
        SshResource::new(
            "127.0.0.1",
            22,
            SigningKey::generate().unwrap().0.verifying_key(),
        ),
    );
    let out = ssh(&client, &user, &fresh, port, "root@loop", "true");
    assert!(!out.status.success());
    assert!(until(|| agent.log.lock().unwrap().iter().any(|l| l
        .contains("ssh.access_refused")
        && l.contains("SCP-E"))));

    if let Some(target) = &target {
        full_path(
            &runtime, &core, &agent, &client, &user, &fresh, port, target,
        );
    } else {
        eprintln!("OSTENA_E2E_TARGET absent : parcours jusqu'à une cible non testé");
    }

    // Status, then a clean stop.
    let out = agent.cli(&["status", "--pid", &agent.child.id().to_string()]);
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains(&format!("SSH : à l'écoute sur 127.0.0.1:{port}")),
        "{text}"
    );
    assert!(text.contains("Identité SSH : prête"), "{text}");

    // A trust the agent cannot apply (no host certificate) withdraws the
    // identity: no connection before the banner, not even with a valid
    // certificate of the old user authority.
    runtime.block_on(core.push_ssh_trust(3, None));
    assert!(until(|| agent.log.lock().unwrap().iter().any(|l| l
        .contains("\"event\":\"agent.ssh_identity_refused\"")
        && l.contains("\"withdrawn\":true"))));
    let out = ssh(&client, &user, &fresh, port, "root@unknown", "true");
    assert!(!out.status.success());
    agent.wait_event("ssh.connection_refused");
    let out = agent.cli(&["status", "--pid", &agent.child.id().to_string()]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("Identité SSH : aucune"), "{text}");
    assert!(text.contains("version 3 reçue, non applicable"), "{text}");
    stop_cleanly(agent);
}

#[allow(clippy::too_many_arguments, reason = "one linear scenario")]
fn full_path(
    runtime: &tokio::runtime::Runtime,
    core: &TestCore,
    agent: &Agent,
    client: &Path,
    user: &User,
    certificate: &Path,
    port: u16,
    target: &Target,
) {
    core.add_ssh_resource(
        "debian12",
        SshResource::new(
            &target.address.ip().to_string(),
            target.address.port(),
            target.host_key,
        ),
    );
    let login = format!("{}@debian12", target.user);
    let out = ssh(client, user, certificate, port, &login, "echo ok; id -un");
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("ok\n{}\n", target.user)
    );
    agent.wait_event("ssh.session_opened");
    agent.wait_event("ssh.session_closed");
    assert!(!agent.has_event("agent.session_report_lost"));

    // A revocation of the login session cuts the session in progress.
    let child = std::thread::spawn({
        let (client, user_key, dir, certificate) = (
            client.to_path_buf(),
            user.key.clone(),
            user.dir.clone(),
            certificate.to_path_buf(),
        );
        let login = login.clone();
        move || {
            let user = User { key: user_key, dir };
            ssh(&client, &user, &certificate, port, &login, "sleep 30")
        }
    });
    assert!(until(|| {
        agent
            .log
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.contains("\"event\":\"ssh.session_opened\""))
            .count()
            >= 2
    }));
    let started = std::time::Instant::now();
    runtime.block_on(core.revoke_login(Uuid::parse(LOGIN).unwrap()));
    let out = child.join().unwrap();
    assert!(!out.status.success());
    assert!(started.elapsed() < Duration::from_secs(20));
    agent.wait_event("ssh.session_revoked");
    agent.wait_event("agent.login_revocation_applied");

    // A target whose host key is not the pinned one.
    core.add_ssh_resource(
        "wrong-key",
        SshResource::new(
            &target.address.ip().to_string(),
            target.address.port(),
            SigningKey::generate().unwrap().0.verifying_key(),
        ),
    );
    let out = ssh(
        client,
        user,
        certificate,
        port,
        &format!("{}@wrong-key", target.user),
        "true",
    );
    assert!(!out.status.success());
    let mismatch = agent.wait_event("ssh.target_host_key_mismatch");
    assert!(
        mismatch.iter().any(|l| l.contains("SSH-E014")),
        "{mismatch:?}"
    );
}

/// Stops the agent as the service manager does and checks the SSH server
/// stopped with it.
fn stop_cleanly(mut agent: Agent) {
    #[cfg(unix)]
    {
        let status = Command::new("kill")
            .args(["-TERM", &agent.child.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
        let exit = agent.child.wait().unwrap();
        assert!(exit.success(), "{exit:?}");
        agent.wait_event("agent.ssh_stopped");
        agent.wait_event("agent.stopped");
    }
    #[cfg(not(unix))]
    {
        let _ = agent.child.kill();
    }
}

#[test]
fn an_unusable_listen_address_refuses_the_start() {
    let runtime = runtime();
    let core = runtime
        .block_on(async { TestCore::start(Limits::default(), Behaviour::default()) })
        .unwrap();
    // Taken by someone else.
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port();
    let mut agent = Agent::start(&core, "agent-ssh-taken", port, None);
    let exit = agent.child.wait().unwrap();
    assert!(!exit.success());
    let refused = agent.wait_event("agent.ssh_unavailable");
    assert!(refused[0].contains("AGT-E010"), "{refused:?}");
}

#[test]
fn ssh_key_says_when_the_agent_has_not_created_its_keys_yet() {
    let dir = std::env::temp_dir().join(format!("ostena-cli-ssh-key-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("ostena.toml");
    std::fs::write(
        &config,
        format!(
            "[agent]\ngateway_group = \"{GROUP}\"\ncore_address = \"core.invalid:8443\"\n\
             tls_certificate = \"/a.crt\"\ntls_private_key = \"/a.key\"\n\
             replay_journal = \"{}\"\n\n[agent.ssh]\nlisten = [\"0.0.0.0:2222\"]\n",
            dir.join("replay.journal")
                .display()
                .to_string()
                .replace('\\', "\\\\")
        ),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ostena"))
        .args(["agent", "ssh-key", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(text.contains("premier démarrage"), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}
