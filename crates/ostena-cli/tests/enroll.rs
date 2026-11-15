//! `ostena agent enroll` with the real binary against the in-process test
//! core.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside #[test] functions"
)]

use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use ostena_crypto::pki::pem_certificate;
use ostena_tunnel::enroll::EnrollmentToken;
use ostena_tunnel::testing::{Behaviour, TestCore};
use ostena_tunnel::{Limits, Uuid};

const GROUP: &str = "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6";
const HOUR: Duration = Duration::from_secs(3600);

fn group() -> Uuid {
    Uuid::parse(GROUP).unwrap()
}

fn run<F: Future<Output = ()>>(test: F) {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(test);
}

struct Agent {
    dir: PathBuf,
}

impl Agent {
    /// A configuration for `group` pointing to `core`.
    fn new(name: &str, core: &TestCore, group: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("ostena-enroll-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("root.pem"),
            pem_certificate(core.trust_anchor().certificate()),
        )
        .unwrap();
        let path = |f: &str| dir.join(f).display().to_string().replace('\\', "\\\\");
        let config = format!(
            "[agent]\ngateway_group = \"{group}\"\ncore_address = \"{}\"\nenrollment_address = \"{}\"\n\
             tls_certificate = \"{}\"\ntls_private_key = \"{}\"\ntls_core_ca = \"{}\"\n\
             replay_journal = \"{}\"\n",
            core.addr(),
            core.enrollment_addr(),
            path("agent.crt"),
            path("agent.key"),
            path("root.pem"),
            path("replay.journal"),
        );
        std::fs::write(dir.join("ostena.toml"), config).unwrap();
        Self { dir }
    }

    fn token_file(&self, token: &EnrollmentToken) -> PathBuf {
        let file = self.dir.join("token");
        // SECRET-EXPOSURE: test only, the token file the operator would copy.
        #[expect(clippy::disallowed_methods)]
        std::fs::write(&file, token.to_text().expose_secret()).unwrap();
        file
    }

    fn files(&self) -> (bool, bool) {
        (
            self.dir.join("agent.key").exists(),
            self.dir.join("agent.crt").exists(),
        )
    }

    /// Runs `agent enroll` off the runtime threads.
    async fn enroll(&self, token: &Path, stdin: &str) -> Output {
        let config = self.dir.join("ostena.toml");
        let token = token.to_path_buf();
        let stdin = stdin.to_owned();
        tokio::task::spawn_blocking(move || {
            let mut child = Command::new(env!("CARGO_BIN_EXE_ostena"))
                .args(["agent", "enroll", "--timeout", "3", "--config"])
                .arg(&config)
                .arg("--token-file")
                .arg(&token)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(stdin.as_bytes())
                .unwrap();
            child.wait_with_output().unwrap()
        })
        .await
        .unwrap()
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn core() -> TestCore {
    TestCore::start(Limits::default(), Behaviour::default()).unwrap()
}

#[test]
fn enrolment_writes_the_key_and_the_certificate_then_the_listener_closes() {
    run(async {
        let core = core();
        let agent = Agent::new("ok", &core, GROUP);
        let token = core.issue_token(group(), HOUR).await.unwrap();
        let out = agent.enroll(&agent.token_file(&token), "").await;
        assert!(out.status.success(), "{}", stderr(&out));
        assert!(String::from_utf8_lossy(&out.stdout).contains("Agent enrôlé"));
        assert_eq!(agent.files(), (true, true));
        let key = std::fs::read_to_string(agent.dir.join("agent.key")).unwrap();
        assert!(key.starts_with("-----BEGIN PRIVATE KEY-----"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(agent.dir.join("agent.key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // The only token is spent: the enrolment listener closes.
        let mut closed = false;
        for _ in 0..60 {
            if !core.enrollment_open() {
                closed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(closed);

        // Another agent with the same token finds nobody listening.
        let late = Agent::new("late", &core, GROUP);
        let out = late.enroll(&late.token_file(&token), "").await;
        assert!(!out.status.success());
        assert!(stderr(&out).contains("TUN-E013"), "{}", stderr(&out));
        assert_eq!(
            late.files(),
            (true, false),
            "the key stays for a new attempt"
        );
    });
}

#[test]
fn replayed_token_is_refused() {
    run(async {
        let core = core();
        let token = core.issue_token(group(), HOUR).await.unwrap();
        let _keep_open = core.issue_token(group(), HOUR).await.unwrap();
        let first = Agent::new("first", &core, GROUP);
        assert!(
            first
                .enroll(&first.token_file(&token), "")
                .await
                .status
                .success()
        );
        let second = Agent::new("second", &core, GROUP);
        let out = second.enroll(&second.token_file(&token), "").await;
        assert!(!out.status.success());
        assert!(stderr(&out).contains("TUN-E020"), "{}", stderr(&out));
        assert_eq!(second.files(), (true, false));
    });
}

#[test]
fn expired_token_is_refused() {
    run(async {
        let core = core();
        let token = core
            .issue_token(group(), Duration::from_secs(1))
            .await
            .unwrap();
        let _keep_open = core.issue_token(group(), HOUR).await.unwrap();
        tokio::time::sleep(Duration::from_millis(2100)).await;
        let agent = Agent::new("expired", &core, GROUP);
        let out = agent.enroll(&agent.token_file(&token), "").await;
        assert!(!out.status.success());
        assert!(stderr(&out).contains("TUN-E019"), "{}", stderr(&out));
        assert_eq!(agent.files(), (true, false));
    });
}

#[test]
fn token_of_another_group_is_refused() {
    run(async {
        let core = core();
        let token = core.issue_token(group(), HOUR).await.unwrap();
        let agent = Agent::new("other-group", &core, "11111111-2222-4333-8444-555555555555");
        let out = agent.enroll(&agent.token_file(&token), "").await;
        assert!(!out.status.success());
        assert!(stderr(&out).contains("TUN-E021"), "{}", stderr(&out));
        assert_eq!(agent.files(), (true, false));
    });
}

#[test]
fn token_on_standard_input_and_no_overwrite() {
    run(async {
        let core = core();
        let token = core.issue_token(group(), HOUR).await.unwrap();
        let _keep_open = core.issue_token(group(), HOUR).await.unwrap();
        let agent = Agent::new("stdin", &core, GROUP);
        // SECRET-EXPOSURE: test only, the token typed on standard input.
        #[expect(clippy::disallowed_methods)]
        let text = String::from_utf8(token.to_text().expose_secret().to_vec()).unwrap();
        let out = agent.enroll(Path::new("-"), &format!("{text}\n")).await;
        assert!(out.status.success(), "{}", stderr(&out));
        // Already enrolled: refused before any network exchange.
        let before = std::fs::read(agent.dir.join("agent.key")).unwrap();
        let again = agent.enroll(Path::new("-"), &format!("{text}\n")).await;
        assert!(!again.status.success());
        assert!(stderr(&again).contains("déjà enrôlé"), "{}", stderr(&again));
        assert_eq!(std::fs::read(agent.dir.join("agent.key")).unwrap(), before);
    });
}

#[test]
fn failed_attempt_leaves_a_key_that_the_next_attempt_reuses() {
    run(async {
        let core = core();
        let agent = Agent::new("retry", &core, GROUP);
        // No token issued yet: the enrolment listener is closed, the attempt
        // fails on the network after the key is written.
        let not_yet = EnrollmentToken::generate().unwrap();
        let out = agent.enroll(&agent.token_file(&not_yet), "").await;
        assert!(!out.status.success());
        assert!(stderr(&out).contains("TUN-E013"), "{}", stderr(&out));
        assert_eq!(agent.files(), (true, false));
        let key = std::fs::read(agent.dir.join("agent.key")).unwrap();

        // The operator gets a token and tries again: same key, certificate.
        let token = core.issue_token(group(), HOUR).await.unwrap();
        let out = agent.enroll(&agent.token_file(&token), "").await;
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(agent.files(), (true, true));
        assert_eq!(std::fs::read(agent.dir.join("agent.key")).unwrap(), key);
    });
}

#[test]
fn unreadable_key_without_certificate_is_recreated() {
    run(async {
        let core = core();
        let agent = Agent::new("garbage-key", &core, GROUP);
        std::fs::write(agent.dir.join("agent.key"), b"not a key").unwrap();
        let token = core.issue_token(group(), HOUR).await.unwrap();
        let out = agent.enroll(&agent.token_file(&token), "").await;
        assert!(out.status.success(), "{}", stderr(&out));
        let key = std::fs::read_to_string(agent.dir.join("agent.key")).unwrap();
        assert!(key.starts_with("-----BEGIN PRIVATE KEY-----"));
    });
}
