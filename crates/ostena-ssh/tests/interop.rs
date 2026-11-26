//! The pre-check and the frozen list with real peers: the OpenSSH 9.x client
//! against our server, our client against our server, and refusals, each
//! audited (`ssh.precheck_refused`); then the native access end to end: the
//! OpenSSH client with an `ostena login` certificate through the agent server
//! to a target, its refusals, and the driver alone.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stderr,
    reason = "test helpers outside #[test] functions; notices go to stderr"
)]

mod common;

use std::process::{Command, Output};
use std::sync::Arc;

use common::{
    EchoTarget, TestServer, certificate_line, dir, events, events_on, events_with, keygen, load,
    loopback, openssh, point, public, public_line, raw_offer, refusals, run_command, runtime,
    serve, serve_handler, user_template, wait_event, wait_refusals,
};
use ostena_ssh::driver;
use ostena_ssh::server::ServerSettings;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Runs the OpenSSH client against `port` with strict host key checking,
/// plus `extra` options.
fn ssh(
    ssh: &std::path::Path,
    dir: &std::path::Path,
    port: u16,
    key: &std::path::Path,
    extra: &[&str],
) -> Output {
    let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
    Command::new(ssh)
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
            dir.join("known_hosts").display()
        ))
        .args(["-o", &format!("GlobalKnownHostsFile={null}")])
        .args([
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "-o",
            "ConnectTimeout=10",
        ])
        .args(extra)
        .arg("-i")
        .arg(key)
        .args(["-p", &port.to_string(), "tester@127.0.0.1", "hello"])
        .output()
        .unwrap()
}

/// An OpenSSH client, a host key and a client key, and our server.
struct Setup {
    ssh: std::path::PathBuf,
    dir: common::Dir,
    port: u16,
    client_key: std::path::PathBuf,
}

fn setup(runtime: &tokio::runtime::Runtime, name: &str) -> Option<Setup> {
    events();
    let ssh_bin = openssh("ssh")?;
    let keygen_bin = openssh("ssh-keygen")?;
    let dir = dir(name);
    let (host_path, host_public) = keygen(&keygen_bin, &dir.0, "host");
    let (client_key, client_public) = keygen(&keygen_bin, &dir.0, "client");
    let addr = runtime.block_on(serve(
        load(&host_path),
        TestServer {
            allowed: public(&client_public),
        },
        name,
    ));
    std::fs::write(
        dir.0.join("known_hosts"),
        format!("[127.0.0.1]:{} {host_public}\n", addr.port()),
    )
    .unwrap();
    Some(Setup {
        ssh: ssh_bin,
        dir,
        port: addr.port(),
        client_key,
    })
}

#[test]
fn openssh_client_session_succeeds_through_the_precheck() {
    let runtime = runtime();
    let Some(s) = setup(&runtime, "openssh-ok") else {
        return;
    };
    let version = Command::new(&s.ssh).arg("-V").output().unwrap();
    eprintln!("{}", String::from_utf8_lossy(&version.stderr).trim());
    let out = ssh(&s.ssh, &s.dir.0, s.port, &s.client_key, &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "ok\n");
    assert_eq!(refusals("openssh-ok"), Vec::<String>::new());
}

#[test]
fn openssh_client_with_only_unlisted_algorithms_is_refused() {
    let runtime = runtime();
    let Some(s) = setup(&runtime, "openssh-unlisted") else {
        return;
    };
    for (option, value) in [
        (
            "KexAlgorithms",
            "curve25519-sha256,diffie-hellman-group14-sha256",
        ),
        ("Ciphers", "chacha20-poly1305@openssh.com,aes256-ctr"),
        ("HostKeyAlgorithms", "ssh-ed25519,rsa-sha2-512"),
    ] {
        let out = ssh(
            &s.ssh,
            &s.dir.0,
            s.port,
            &s.client_key,
            &["-o", &format!("{option}={value}")],
        );
        assert!(!out.status.success(), "{option} accepted");
    }
    assert_eq!(
        wait_refusals("openssh-unlisted", 3),
        vec!["SSH-E005", "SSH-E005", "SSH-E005"],
        "every refusal audited"
    );
}

#[test]
fn client_without_strict_kex_is_refused() {
    let runtime = runtime();
    events();
    let Some(keygen_bin) = openssh("ssh-keygen") else {
        return;
    };
    let dir = dir("raw");
    let (host_path, _) = keygen(&keygen_bin, &dir.0, "host");
    let (_, client_public) = keygen(&keygen_bin, &dir.0, "client");
    runtime.block_on(async {
        let addr = serve(
            load(&host_path),
            TestServer {
                allowed: public(&client_public),
            },
            "raw-no-strict",
        )
        .await;
        let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        tcp.write_all(&raw_offer("ecdh-sha2-nistp256,ext-info-c"))
            .await
            .unwrap();
        // The server sends its identification, then closes.
        let mut seen = Vec::new();
        let _ = tcp.read_to_end(&mut seen).await;
        assert!(seen.starts_with(b"SSH-2.0-"));
    });
    assert_eq!(refusals("raw-no-strict"), vec!["SSH-E004"]);
}

#[test]
fn our_client_reaches_our_server_and_refuses_a_server_without_strict_kex() {
    let runtime = runtime();
    events();
    let Some(keygen_bin) = openssh("ssh-keygen") else {
        return;
    };
    let dir = dir("client");
    let (host_path, host_public) = keygen(&keygen_bin, &dir.0, "host");
    let (client_path, client_public) = keygen(&keygen_bin, &dir.0, "client");
    runtime.block_on(async {
        let addr = serve(
            load(&host_path),
            TestServer {
                allowed: public(&client_public),
            },
            "client-server",
        )
        .await;
        let printed = run_command(
            &addr.to_string(),
            "client-ok",
            public(&host_public),
            "tester",
            load(&client_path),
            "hello",
        )
        .await
        .unwrap();
        assert_eq!(printed, "ok\n");

        // A server offering everything but strict KEX.
        let fake = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fake_addr = fake.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut tcp, _)) = fake.accept().await {
                let _ = tcp.write_all(&raw_offer("ecdh-sha2-nistp256")).await;
                let mut sink = Vec::new();
                let _ = tcp.read_to_end(&mut sink).await;
            }
        });
        let refused = run_command(
            &fake_addr.to_string(),
            "client-no-strict",
            public(&host_public),
            "tester",
            load(&client_path),
            "hello",
        )
        .await;
        assert!(refused.is_err());
    });
    assert_eq!(refusals("client-ok"), Vec::<String>::new());
    assert_eq!(refusals("client-no-strict"), vec!["SSH-E004"]);
}

// ------------------------------------------ native access, end to end

/// The OpenSSH client, a user key and certificate, the agent server and a
/// russh echo target behind it.
struct Native {
    ssh: std::path::PathBuf,
    dir: common::Dir,
    agent: common::Agent,
    user_key: std::path::PathBuf,
    user_public: ostena_crypto::p256::VerifyingKey,
    target_label: String,
}

fn native(
    runtime: &tokio::runtime::Runtime,
    name: &str,
    settings: ServerSettings,
) -> Option<Native> {
    events();
    let ssh_bin = openssh("ssh")?;
    let keygen_bin = openssh("ssh-keygen")?;
    let dir = dir(name);
    let (host_path, _) = keygen(&keygen_bin, &dir.0, "agent_host");
    let (agent_path, agent_public) = keygen(&keygen_bin, &dir.0, "agent_target");
    let (target_host_path, target_host_public) = keygen(&keygen_bin, &dir.0, "target_host");
    let (user_key, user_public) = keygen(&keygen_bin, &dir.0, "user");
    let target_label = format!("target-{name}");
    let agent = runtime.block_on(async {
        let target = serve_handler(
            load(&target_host_path),
            EchoTarget {
                allowed: public(&agent_public),
            },
            &target_label,
        )
        .await;
        let agent = common::agent(load(&host_path), load(&agent_path), settings).await;
        let pinned = loopback(target.port()).await;
        agent.authorizer.targets.lock().unwrap().insert(
            "srv-lab01".into(),
            (pinned, point(&public(&target_host_public))),
        );
        agent
    });
    let host_ca_line = public_line(&agent.host_ca.verifying_key());
    std::fs::write(
        dir.0.join("known_hosts"),
        format!(
            "@cert-authority [127.0.0.1]:{} {host_ca_line}\n",
            agent.addr.port()
        ),
    )
    .unwrap();
    Some(Native {
        ssh: ssh_bin,
        user_public: point(&public(&user_public)),
        dir,
        agent,
        user_key,
        target_label,
    })
}

impl Native {
    /// Issues the user certificate from `template` with `ca` (the user
    /// authority of the agent by default) next to the user key.
    fn certify(&self, change: impl FnOnce(&mut ostena_ssh::cert::Template)) -> std::path::PathBuf {
        let mut template = user_template(self.user_public);
        change(&mut template);
        self.certify_with(&template, &self.agent.user_ca)
    }

    fn certify_with(
        &self,
        template: &ostena_ssh::cert::Template,
        ca: &ostena_crypto::p256::SigningKey,
    ) -> std::path::PathBuf {
        let blob = ostena_ssh::cert::issue(template, ca).unwrap();
        let path = self.dir.0.join("user-cert.pub");
        std::fs::write(&path, certificate_line(&blob)).unwrap();
        path
    }

    /// Runs the OpenSSH client as `user` with `certificate` (none: the
    /// bare key), `extra` options and `command`.
    fn run(
        &self,
        user: &str,
        certificate: Option<&std::path::Path>,
        extra: &[&str],
        command: &[&str],
    ) -> Output {
        let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
        let mut cmd = Command::new(&self.ssh);
        cmd.args([
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
            self.dir.0.join("known_hosts").display()
        ))
        .args(["-o", &format!("GlobalKnownHostsFile={null}")])
        .args(["-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none"])
        .args(["-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR"])
        .arg("-i")
        .arg(&self.user_key);
        match certificate {
            Some(path) => cmd
                .arg("-o")
                .arg(format!("CertificateFile={}", path.display())),
            None => cmd.args(["-o", "CertificateFile=none"]),
        };
        cmd.args(extra)
            .args(["-p", &self.agent.addr.port().to_string()])
            .arg(format!("{user}@127.0.0.1"))
            .args(command)
            .output()
            .unwrap()
    }

    fn codes(&self, name: &str) -> Vec<String> {
        events_on(self.agent.addr, name)
            .into_iter()
            .map(|e| e.code)
            .collect()
    }
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn native_session_with_a_certificate_reaches_the_target() {
    let runtime = runtime();
    let Some(n) = native(&runtime, "native-ok", ServerSettings::default()) else {
        return;
    };
    let certificate = n.certify(|_| {});
    let out = n.run(
        "root@srv-lab01",
        Some(&certificate),
        &[],
        &["hello", "world"],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "ran:hello world\n");
    // The account and the resource reached the authoriser; the certificate
    // was checked a second time.
    let requests = n.agent.authorizer.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].account, "root");
    assert_eq!(requests[0].resource, "srv-lab01");
    assert_eq!(
        ostena_ssh::cert::format_uuid(&requests[0].identity.subject),
        common::SUBJECT
    );
    assert!(!wait_event(n.agent.addr, "ssh.session_closed").is_empty());
    let opened = events_on(n.agent.addr, "ssh.session_opened");
    assert_eq!(opened.len(), 1);
    assert_eq!(opened[0].field("account"), "root");
    // The command is logged by its length only, never its text nor a
    // plain digest (ADR-0016): the text is in the transcript.
    let exec = events_on(n.agent.addr, "ssh.exec");
    assert_eq!(exec.len(), 1);
    assert_eq!(exec[0].field("length"), "11");
    assert!(!exec[0].fields.contains_key("sha256"));
    assert!(exec[0].fields.values().all(|v| !v.contains("hello")));
    let mut closed = Vec::new();
    for _ in 0..100 {
        closed = n.agent.authorizer.closed.lock().unwrap().clone();
        if !closed.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].bytes_from_target, 16);
    // The transcript: the command, the output relayed, the end.
    let frames = n.agent.authorizer.transcript(&closed[0].session_id);
    assert!(matches!(
        &frames[0].event,
        ostena_recorder::Event::Start { command: Some(c), .. } if c == b"hello world"
    ));
    let output: Vec<u8> = frames
        .iter()
        .filter_map(|f| match &f.event {
            ostena_recorder::Event::Output(d) => Some(d.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(output, b"ran:hello world\n");
    // The exit status of the target, before the end.
    assert_eq!(
        frames[frames.len() - 2].event,
        ostena_recorder::Event::Exit(ostena_recorder::Exit::Status(0))
    );
    assert_eq!(
        frames.last().unwrap().event,
        ostena_recorder::Event::End {
            reason: ostena_recorder::EndReason::Closed,
            output_bytes: 16
        }
    );
    for _ in 0..100 {
        if n.agent.server.sessions() == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert_eq!(n.agent.server.sessions(), 0);
    assert_eq!(n.codes("ssh.auth_refused"), Vec::<String>::new());
    assert_eq!(refusals(&n.target_label), Vec::<String>::new());
}

#[test]
fn native_session_rejects_an_untrusted_host_authority() {
    let runtime = runtime();
    let Some(n) = native(&runtime, "native-host-ca", ServerSettings::default()) else {
        return;
    };
    let other = ostena_crypto::p256::SigningKey::generate().unwrap().0;
    std::fs::write(
        n.dir.0.join("known_hosts"),
        format!(
            "@cert-authority [127.0.0.1]:{} {}\n",
            n.agent.addr.port(),
            public_line(&other.verifying_key())
        ),
    )
    .unwrap();
    let certificate = n.certify(|_| {});
    let out = n.run("root@srv-lab01", Some(&certificate), &[], &["hello"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("verification failed")
            || stderr(&out).contains("Host key verification"),
        "{}",
        stderr(&out)
    );
    assert!(n.agent.authorizer.requests.lock().unwrap().is_empty());
}

#[test]
fn native_session_refusals_are_audited() {
    let runtime = runtime();
    let Some(n) = native(&runtime, "native-refusals", ServerSettings::default()) else {
        return;
    };
    // A bare key.
    let out = n.run("root@srv-lab01", None, &[], &["hello"]);
    assert!(!out.status.success());
    assert!(wait_codes(&n, "SSH-E012"));
    // Another authority.
    let other = ostena_crypto::p256::SigningKey::generate().unwrap().0;
    let certificate = n.certify_with(&user_template(n.user_public), &other);
    assert!(
        !n.run("root@srv-lab01", Some(&certificate), &[], &["hello"])
            .status
            .success()
    );
    // A forwarding extension.
    let certificate = n.certify(|t| {
        t.extensions.push(("permit-port-forwarding".into(), vec![]));
    });
    assert!(
        !n.run("root@srv-lab01", Some(&certificate), &[], &["hello"])
            .status
            .success()
    );
    // The bare key above is audited twice: SSH-E012, and no certificate.
    assert!(
        wait_count(&n, "SSH-E011", 3),
        "{:?}",
        n.codes("ssh.auth_refused")
    );
    // Expired: refused by the library itself, audited at the end of the
    // connection.
    let now = ostena_grant::unix_now();
    let certificate = n.certify(|t| {
        t.valid_after = now - 7200;
        t.valid_before = now - 3600;
    });
    assert!(
        !n.run("root@srv-lab01", Some(&certificate), &[], &["hello"])
            .status
            .success()
    );
    assert!(wait_count(&n, "SSH-E011", 4));
    // No resource.
    let certificate = n.certify(|_| {});
    assert!(
        !n.run("root", Some(&certificate), &[], &["hello"])
            .status
            .success()
    );
    assert!(wait_codes(&n, "SSH-E010"));
    // Nothing reached the authoriser.
    assert!(n.agent.authorizer.requests.lock().unwrap().is_empty());
    // The authoriser refuses: the underlying code is kept.
    *n.agent.authorizer.refuse.lock().unwrap() = Some(ostena_ssh::server::Refusal {
        code: "GRT-E010".into(),
        message: "grant déjà utilisé".into(),
    });
    assert!(
        !n.run("root@srv-lab01", Some(&certificate), &[], &["hello"])
            .status
            .success()
    );
    let refused = wait_event(n.agent.addr, "ssh.access_refused");
    assert_eq!(refused[0].code, "SSH-E013");
    assert_eq!(refused[0].field("cause"), "GRT-E010");
}

fn wait_codes(n: &Native, code: &str) -> bool {
    wait_count(n, code, 1)
}

fn wait_count(n: &Native, code: &str, count: usize) -> bool {
    for _ in 0..200 {
        if n.codes("ssh.auth_refused")
            .iter()
            .filter(|c| *c == code)
            .count()
            >= count
        {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    false
}

#[test]
fn native_session_refuses_forwarding_agent_and_subsystems() {
    let runtime = runtime();
    let Some(n) = native(&runtime, "native-channels", ServerSettings::default()) else {
        return;
    };
    let certificate = n.certify(|_| {});
    // Stdio forwarding: a direct-tcpip channel, as -L opens.
    let out = n.run(
        "root@srv-lab01",
        Some(&certificate),
        &["-W", "127.0.0.1:22"],
        &[],
    );
    assert!(!out.status.success());
    // Remote forwarding, -R.
    let out = n.run(
        "root@srv-lab01",
        Some(&certificate),
        &["-o", "ExitOnForwardFailure=yes", "-R", "0:127.0.0.1:22"],
        &["hello"],
    );
    assert!(!out.status.success());
    // sftp.
    let out = n.run("root@srv-lab01", Some(&certificate), &["-s"], &["sftp"]);
    assert!(!out.status.success());
    // Agent forwarding is refused, the session goes on.
    let out = n.run(
        "root@srv-lab01",
        Some(&certificate),
        &["-o", "ForwardAgent=yes"],
        &["hello"],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    for _ in 0..100 {
        if events_on(n.agent.addr, "ssh.channel_refused").len() >= 3 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let kinds: Vec<String> = events_on(n.agent.addr, "ssh.channel_refused")
        .iter()
        .map(|e| e.field("kind").to_owned())
        .collect();
    for expected in ["direct-tcpip", "tcpip-forward", "sous-système sftp"] {
        assert!(
            kinds.iter().any(|k| k == expected),
            "{expected} in {kinds:?}"
        );
    }
    assert!(
        events_on(n.agent.addr, "ssh.channel_refused")
            .iter()
            .all(|e| e.code == "SSH-E017")
    );
}

#[test]
fn native_session_ends_at_its_maximum_length_or_on_revocation() {
    let runtime = runtime();
    let Some(n) = native(&runtime, "native-expiry", ServerSettings::default()) else {
        return;
    };
    let certificate = n.certify(|_| {});
    *n.agent.authorizer.max_session.lock().unwrap() = Some(std::time::Duration::from_secs(2));
    let started = std::time::Instant::now();
    let out = n.run("root@srv-lab01", Some(&certificate), &[], &["hold"]);
    assert!(!out.status.success());
    assert!(started.elapsed() < std::time::Duration::from_secs(15));
    assert!(!wait_event(n.agent.addr, "ssh.session_expired").is_empty());
    let closed = wait_event(n.agent.addr, "ssh.session_closed");
    assert_eq!(closed[0].field("reason"), "expirée");

    // Revocation of the login session.
    *n.agent.authorizer.max_session.lock().unwrap() = None;
    let child = std::thread::spawn({
        let ssh = n.ssh.clone();
        let args = n.args_for(&certificate);
        move || Command::new(ssh).args(args).output().unwrap()
    });
    let login = ostena_ssh::cert::parse_uuid(common::LOGIN).unwrap();
    let mut revoked = 0;
    for _ in 0..200 {
        revoked = n.agent.server.revoke_login(login);
        if revoked > 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert_eq!(revoked, 1);
    assert!(!child.join().unwrap().status.success());
    assert!(!wait_event(n.agent.addr, "ssh.session_revoked").is_empty());
}

#[test]
fn native_session_ends_at_its_idle_delay_and_user_quota_holds() {
    let runtime = runtime();
    let settings = ServerSettings {
        idle_timeout: Some(std::time::Duration::from_secs(1)),
        max_sessions_per_user: Some(1),
        ..ServerSettings::default()
    };
    let Some(n) = native(&runtime, "native-idle", settings) else {
        return;
    };
    let certificate = n.certify(|_| {});
    let child = std::thread::spawn({
        let ssh = n.ssh.clone();
        let args = n.args_for(&certificate);
        move || Command::new(ssh).args(args).output().unwrap()
    });
    // While the first session holds the only slot of the user, a second
    // one is refused by the session manager.
    for _ in 0..200 {
        if n.agent.server.sessions() == 1 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let started = std::time::Instant::now();
    let second = n.run("root@srv-lab01", Some(&certificate), &[], &["hold"]);
    assert!(!second.status.success());
    let limited = wait_event(n.agent.addr, "ssh.connection_limited");
    assert_eq!(limited[0].code, "SSH-E019");
    assert_eq!(limited[0].field("cause"), "SES-E002");
    // The first one, silent, is cut at its idle delay.
    assert!(!child.join().unwrap().status.success());
    assert!(started.elapsed() < std::time::Duration::from_secs(15));
    assert!(!wait_event(n.agent.addr, "ssh.session_idle").is_empty());
    let closed = wait_event(n.agent.addr, "ssh.session_closed");
    assert_eq!(closed[0].field("reason"), "inactive");
    for _ in 0..200 {
        if n.agent.server.in_progress() == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(n.agent.server.in_progress(), 0);
}

impl Native {
    /// The arguments of a `hold` session as `root@srv-lab01`.
    fn args_for(&self, certificate: &std::path::Path) -> Vec<String> {
        let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
        [
            "-F",
            "none",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            &format!(
                "UserKnownHostsFile={}",
                self.dir.0.join("known_hosts").display()
            ),
            "-o",
            &format!("GlobalKnownHostsFile={null}"),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "-o",
            &format!("CertificateFile={}", certificate.display()),
            "-i",
            &self.user_key.display().to_string(),
            "-p",
            &self.agent.addr.port().to_string(),
            "root@srv-lab01@127.0.0.1",
            "hold",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
    }
}

#[test]
fn driver_pins_the_target_host_key_and_authenticates_with_the_agent_key() {
    let runtime = runtime();
    events();
    let Some(keygen_bin) = openssh("ssh-keygen") else {
        return;
    };
    let dir = dir("driver");
    let (agent_path, agent_public) = keygen(&keygen_bin, &dir.0, "agent");
    let (other_path, _) = keygen(&keygen_bin, &dir.0, "other");
    let (target_host_path, target_host_public) = keygen(&keygen_bin, &dir.0, "target_host");
    runtime.block_on(async {
        let addr = serve_handler(
            load(&target_host_path),
            EchoTarget {
                allowed: public(&agent_public),
            },
            "driver-target",
        )
        .await;
        let pinned = loopback(addr.port()).await;
        let host_key = point(&public(&target_host_public));
        let timeout = std::time::Duration::from_secs(5);
        let agent = Arc::new(load(&agent_path));
        let session = driver::connect(
            &pinned,
            &host_key,
            "ostena",
            agent.clone(),
            timeout,
            "driver-ok",
        )
        .await
        .unwrap();
        let mut channel = session.open_session().await.unwrap();
        channel.exec(true, "x").await.unwrap();
        let mut output = Vec::new();
        while let Some(message) = channel.wait().await {
            match message {
                russh::ChannelMsg::Data { data } => output.extend_from_slice(&data),
                russh::ChannelMsg::Close => break,
                _ => {}
            }
        }
        assert_eq!(output, b"ran:x\n");
        session.close().await;

        // Another host key: refused before authentication.
        let other_host = ostena_crypto::p256::SigningKey::generate()
            .unwrap()
            .0
            .verifying_key();
        let e = driver::connect(
            &pinned,
            &other_host,
            "ostena",
            agent.clone(),
            timeout,
            "driver-mismatch",
        )
        .await
        .unwrap_err();
        assert_eq!(e.code(), "SSH-E014");
        // Another agent key: refused by the target.
        let e = driver::connect(
            &pinned,
            &host_key,
            "ostena",
            Arc::new(load(&other_path)),
            timeout,
            "driver-auth",
        )
        .await
        .unwrap_err();
        assert_eq!(e.code(), "SSH-E015");
        // Nobody listening.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let e = driver::connect(
            &loopback(port).await,
            &host_key,
            "ostena",
            agent,
            timeout,
            "driver-down",
        )
        .await
        .unwrap_err();
        assert_eq!(e.code(), "SSH-E016");
    });
    for (label, event) in [
        ("driver-mismatch", "ssh.target_host_key_mismatch"),
        ("driver-auth", "ssh.target_auth_failed"),
        ("driver-down", "ssh.target_unreachable"),
    ] {
        assert_eq!(events_with(event, "target", label).len(), 1, "{event}");
    }
}

#[test]
fn agent_identifies_without_a_version() {
    let runtime = runtime();
    let Some(n) = native(&runtime, "native-banner", ServerSettings::default()) else {
        return;
    };
    let mut tcp = std::net::TcpStream::connect(n.agent.addr).unwrap();
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let mut line = [0u8; 16];
    std::io::Read::read_exact(&mut tcp, &mut line).unwrap();
    assert_eq!(&line, b"SSH-2.0-Ostena\r\n");
}

#[test]
fn driver_refuses_channels_opened_by_the_target() {
    let runtime = runtime();
    events();
    let Some(keygen_bin) = openssh("ssh-keygen") else {
        return;
    };
    let dir = dir("driver-channels");
    let (agent_path, agent_public) = keygen(&keygen_bin, &dir.0, "agent");
    let (target_host_path, target_host_public) = keygen(&keygen_bin, &dir.0, "target_host");
    runtime.block_on(async {
        let addr = serve_handler(
            load(&target_host_path),
            EchoTarget {
                allowed: public(&agent_public),
            },
            "driver-channels-target",
        )
        .await;
        let session = driver::connect(
            &loopback(addr.port()).await,
            &point(&public(&target_host_public)),
            "ostena",
            Arc::new(load(&agent_path)),
            std::time::Duration::from_secs(5),
            "driver-channels",
        )
        .await
        .unwrap();
        let mut channel = session.open_session().await.unwrap();
        channel.exec(true, "open-channels").await.unwrap();
        while let Some(message) = channel.wait().await {
            if matches!(message, russh::ChannelMsg::Close) {
                break;
            }
        }
        let mut kinds = Vec::new();
        for _ in 0..100 {
            kinds = events_with("ssh.target_channel_refused", "target", "driver-channels")
                .iter()
                .map(|e| e.field("kind").to_owned())
                .collect();
            if kinds.len() >= 4 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        kinds.sort();
        assert_eq!(kinds, ["agent", "forwarded-tcpip", "session", "x11"]);
        session.close().await;
    });
}

/// Waits until the authoriser has seen `count` requests.
fn wait_requests(n: &Native, count: usize) -> bool {
    for _ in 0..200 {
        if n.agent.authorizer.requests.lock().unwrap().len() >= count {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    false
}

fn wait_closed(n: &Native, count: usize) -> Vec<ostena_ssh::server::SessionSummary> {
    for _ in 0..300 {
        let closed = n.agent.authorizer.closed.lock().unwrap().clone();
        if closed.len() >= count {
            return closed;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    n.agent.authorizer.closed.lock().unwrap().clone()
}

#[test]
fn a_revocation_during_the_authorisation_cuts_the_session() {
    let runtime = runtime();
    let Some(n) = native(&runtime, "native-revoke-race", ServerSettings::default()) else {
        return;
    };
    let certificate = n.certify(|_| {});
    *n.agent.authorizer.delay.lock().unwrap() = Some(std::time::Duration::from_secs(2));
    let child = std::thread::spawn({
        let ssh = n.ssh.clone();
        let args = n.args_for(&certificate);
        move || Command::new(ssh).args(args).output().unwrap()
    });
    assert!(wait_requests(&n, 1));
    // The core revokes while it is still deciding.
    let login = ostena_ssh::cert::parse_uuid(common::LOGIN).unwrap();
    assert_eq!(n.agent.server.revoke_login(login), 1);
    assert!(!child.join().unwrap().status.success());
    let closed = wait_closed(&n, 1);
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].reason, "révoquée");
    assert!(!wait_event(n.agent.addr, "ssh.session_revoked").is_empty());
}

/// Fail closed (ADR-0016): a session whose transcript can no longer reach
/// the core is cut, and its end says why.
#[test]
fn a_session_whose_transcript_is_lost_is_cut() {
    let runtime = runtime();
    let Some(n) = native(
        &runtime,
        "native-transcript-lost",
        ServerSettings::default(),
    ) else {
        return;
    };
    let certificate = n.certify(|_| {});
    *n.agent.authorizer.lose_transcript_after.lock().unwrap() =
        Some(std::time::Duration::from_secs(1));
    let started = std::time::Instant::now();
    let out = n.run("root@srv-lab01", Some(&certificate), &[], &["hold"]);
    assert!(!out.status.success());
    assert!(started.elapsed() < std::time::Duration::from_secs(15));
    let lost = wait_event(n.agent.addr, "ssh.transcript_lost");
    assert_eq!(lost[0].code, "SSH-E021");
    let closed = wait_closed(&n, 1);
    assert_eq!(closed[0].reason, "transcript perdu");
}

/// A transcript lost before the shell starts: the session is cut, and the
/// journal says the transcript was lost, not that a channel was refused.
#[test]
fn a_transcript_lost_before_the_start_is_logged_as_lost() {
    let runtime = runtime();
    let Some(n) = native(
        &runtime,
        "native-transcript-lost-early",
        ServerSettings::default(),
    ) else {
        return;
    };
    let certificate = n.certify(|_| {});
    *n.agent.authorizer.lose_transcript_after.lock().unwrap() = Some(std::time::Duration::ZERO);
    let out = n.run("root@srv-lab01", Some(&certificate), &[], &["hold"]);
    assert!(!out.status.success());
    let lost = wait_event(n.agent.addr, "ssh.transcript_lost");
    assert_eq!(lost[0].code, "SSH-E021");
    assert_eq!(wait_closed(&n, 1)[0].reason, "transcript perdu");
    assert!(events_on(n.agent.addr, "ssh.channel_refused").is_empty());
}

/// The exit signal of the target is relayed and recorded.
#[test]
fn the_exit_signal_is_recorded() {
    let runtime = runtime();
    let Some(n) = native(&runtime, "native-exit-signal", ServerSettings::default()) else {
        return;
    };
    let certificate = n.certify(|_| {});
    let out = n.run("root@srv-lab01", Some(&certificate), &[], &["signal"]);
    assert!(!out.status.success());
    let closed = wait_closed(&n, 1);
    let frames = n.agent.authorizer.transcript(&closed[0].session_id);
    assert!(
        frames.iter().any(|f| f.event
            == ostena_recorder::Event::Exit(ostena_recorder::Exit::Signal {
                name: "KILL".into(),
                core_dumped: false
            })),
        "{frames:?}"
    );
}

/// A core that no longer reads the transcript (ADR-0016): the output
/// waits, then the session is cut in the delay, and its permit and report
/// are given back.
#[test]
fn a_session_whose_transcript_is_not_read_is_cut_in_the_delay() {
    let runtime = runtime();
    let Some(n) = native(
        &runtime,
        "native-transcript-stalled",
        ServerSettings::default(),
    ) else {
        return;
    };
    let certificate = n.certify(|_| {});
    *n.agent.authorizer.stall_transcript.lock().unwrap() = Some(std::time::Duration::from_secs(1));
    let started = std::time::Instant::now();
    let out = n.run("root@srv-lab01", Some(&certificate), &[], &["flood"]);
    assert!(!out.status.success());
    assert!(started.elapsed() < std::time::Duration::from_secs(15));
    // Not one byte reached the user unrecorded.
    assert!(out.stdout.is_empty(), "{} octets", out.stdout.len());
    let lost = wait_event(n.agent.addr, "ssh.transcript_lost");
    assert_eq!(lost[0].code, "SSH-E021");
    let closed = wait_closed(&n, 1);
    assert_eq!(closed[0].reason, "transcript perdu");
    assert_eq!(n.agent.server.sessions(), 0);
    assert_eq!(n.agent.server.in_progress(), 0);
}

#[test]
fn a_session_being_authorised_is_in_progress_until_its_close() {
    let runtime = runtime();
    let Some(n) = native(&runtime, "native-in-progress", ServerSettings::default()) else {
        return;
    };
    let certificate = n.certify(|_| {});
    *n.agent.authorizer.delay.lock().unwrap() = Some(std::time::Duration::from_secs(2));
    *n.agent.authorizer.max_session.lock().unwrap() = Some(std::time::Duration::from_secs(1));
    assert_eq!(n.agent.server.in_progress(), 0);
    let child = std::thread::spawn({
        let ssh = n.ssh.clone();
        let args = n.args_for(&certificate);
        move || Command::new(ssh).args(args).output().unwrap()
    });
    assert!(wait_requests(&n, 1));
    // Not a session yet, but a stop must wait for it.
    assert_eq!(n.agent.server.sessions(), 0);
    assert_eq!(n.agent.server.in_progress(), 1);
    let _ = child.join().unwrap();
    let closed = wait_closed(&n, 1);
    assert_eq!(closed.len(), 1);
    assert_eq!(n.agent.server.in_progress(), 0);
}

#[test]
fn revoke_all_cuts_every_session_whatever_its_login_session() {
    let runtime = runtime();
    let Some(n) = native(&runtime, "native-revoke-all", ServerSettings::default()) else {
        return;
    };
    let certificate = n.certify(|_| {});
    assert_eq!(n.agent.server.revoke_all(), 0);
    let child = std::thread::spawn({
        let ssh = n.ssh.clone();
        let args = n.args_for(&certificate);
        move || Command::new(ssh).args(args).output().unwrap()
    });
    let mut revoked = 0;
    for _ in 0..200 {
        if n.agent.server.sessions() > 0 {
            revoked = n.agent.server.revoke_all();
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert_eq!(revoked, 1);
    assert!(!child.join().unwrap().status.success());
    let closed = wait_closed(&n, 1);
    assert_eq!(closed[0].reason, "révoquée");
}

#[test]
fn a_client_gone_right_after_the_authorisation_still_closes_the_session() {
    let runtime = runtime();
    let Some(n) = native(&runtime, "native-gone", ServerSettings::default()) else {
        return;
    };
    let certificate = n.certify(|_| {});
    *n.agent.authorizer.delay.lock().unwrap() = Some(std::time::Duration::from_secs(2));
    let mut child = Command::new(&n.ssh)
        .args(n.args_for(&certificate))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    assert!(wait_requests(&n, 1));
    child.kill().unwrap();
    let _ = child.wait();
    // The grant was consumed: the session is closed once, audited.
    let closed = wait_closed(&n, 1);
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].reason, "fermée");
    let events = wait_event(n.agent.addr, "ssh.session_closed");
    assert_eq!(events.len(), 1);
    std::thread::sleep(std::time::Duration::from_millis(500));
    assert_eq!(n.agent.authorizer.closed.lock().unwrap().len(), 1);
    assert_eq!(n.agent.server.sessions(), 0);
}

#[test]
fn unauthenticated_connections_are_bounded_per_source_address() {
    let runtime = runtime();
    let settings = ServerSettings {
        max_unauthenticated_per_source: 2,
        ..ServerSettings::default()
    };
    let Some(n) = native(&runtime, "native-per-source", settings) else {
        return;
    };
    // Two silent connections hold their slots (the pre-check waits).
    let held: Vec<_> = (0..2)
        .map(|_| std::net::TcpStream::connect(n.agent.addr).unwrap())
        .collect();
    std::thread::sleep(std::time::Duration::from_millis(300));
    let third = std::net::TcpStream::connect(n.agent.addr).unwrap();
    let limited = wait_event(n.agent.addr, "ssh.connection_limited");
    assert_eq!(limited.len(), 1, "{limited:?}");
    assert_eq!(limited[0].code, "SSH-E019");
    assert!(limited[0].field("message").contains("cette adresse"));
    drop(third);
    // Once released, a new connection gets through to a session.
    drop(held);
    std::thread::sleep(std::time::Duration::from_millis(300));
    let certificate = n.certify(|_| {});
    let out = n.run("root@srv-lab01", Some(&certificate), &[], &["hello"]);
    assert!(out.status.success(), "{}", stderr(&out));
}
