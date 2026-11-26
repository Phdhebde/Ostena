//! File transfers and port forwarding through the agent with the real
//! OpenSSH tools (ADR-0010): `scp` (legacy protocol and SFTP mode), `sftp`
//! and `rsync` reach a target running the real `sftp-server`, `scp` and
//! `rsync`, only under the transfer function of the right; the file names
//! are noted in the transcript, never the contents. `ssh -W` (as `-L` and
//! `ProxyJump` do) is relayed only under the port forwarding function.
//! Unix only: the test target runs processes.

#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stderr,
    clippy::panic,
    reason = "test helpers outside #[test] functions; notices go to stderr"
)]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use common::{
    ExecTarget, certificate_line, dir, events, events_on, keygen, load, loopback, openssh, point,
    public, public_line, runtime, serve_handler, user_template, wait_event,
};
use ostena_grant::Rights;
use ostena_recorder::{Event, NoteKind};
use ostena_ssh::server::{ServerSettings, SessionSummary};

const TRANSFER: Rights = Rights::FILE_UPLOAD.with(Rights::FILE_DOWNLOAD);

/// The agent, a target running processes in `remote`, and the user's key
/// and certificate in `local`.
struct Bench {
    _dir: common::Dir,
    agent: common::Agent,
    local: PathBuf,
    remote: PathBuf,
    options: Vec<String>,
}

/// The tool `name` (`scp`, `sftp`, `rsync`) and the target's
/// `sftp-server`, if present; required with `OSTENA_REQUIRE_OPENSSH=1`.
fn tool(name: &str) -> Option<PathBuf> {
    let found = Command::new(name)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
        && common::sftp_server().is_some();
    if !found {
        assert!(
            std::env::var("OSTENA_REQUIRE_OPENSSH").as_deref() != Ok("1"),
            "{name} ou sftp-server introuvable alors que OSTENA_REQUIRE_OPENSSH=1"
        );
        eprintln!("{name} ou sftp-server introuvable : test sauté");
        return None;
    }
    Some(PathBuf::from(name))
}

fn bench(name: &str, rights: Rights) -> Option<(tokio::runtime::Runtime, Bench)> {
    events();
    let keygen_bin = openssh("ssh-keygen")?;
    openssh("ssh")?;
    let runtime = runtime();
    let dir = dir(name);
    let local = dir.0.join("local");
    let remote = dir.0.join("remote");
    std::fs::create_dir_all(&local).unwrap();
    std::fs::create_dir_all(&remote).unwrap();
    let (host_path, _) = keygen(&keygen_bin, &dir.0, "agent_host");
    let (agent_path, agent_public) = keygen(&keygen_bin, &dir.0, "agent_target");
    let (target_host_path, target_host_public) = keygen(&keygen_bin, &dir.0, "target_host");
    let (user_key, user_public) = keygen(&keygen_bin, &dir.0, "user");
    let agent = runtime.block_on(async {
        let target = serve_handler(
            load(&target_host_path),
            ExecTarget::new(public(&agent_public), remote.clone()),
            &format!("target-{name}"),
        )
        .await;
        let agent = common::agent(
            load(&host_path),
            load(&agent_path),
            ServerSettings::default(),
        )
        .await;
        let pinned = loopback(target.port()).await;
        agent.authorizer.targets.lock().unwrap().insert(
            "srv-lab01".into(),
            (pinned, point(&public(&target_host_public))),
        );
        agent
    });
    *agent.authorizer.rights.lock().unwrap() = rights;
    let blob =
        ostena_ssh::cert::issue(&user_template(point(&public(&user_public))), &agent.user_ca)
            .unwrap();
    let certificate = dir.0.join("user-cert.pub");
    std::fs::write(&certificate, certificate_line(&blob)).unwrap();
    let known_hosts = dir.0.join("known_hosts");
    std::fs::write(
        &known_hosts,
        format!(
            "@cert-authority [127.0.0.1]:{} {}\n",
            agent.addr.port(),
            public_line(&agent.host_ca.verifying_key())
        ),
    )
    .unwrap();
    let options = [
        "BatchMode=yes".to_owned(),
        "StrictHostKeyChecking=yes".to_owned(),
        format!("UserKnownHostsFile={}", known_hosts.display()),
        "GlobalKnownHostsFile=/dev/null".to_owned(),
        "IdentitiesOnly=yes".to_owned(),
        "IdentityAgent=none".to_owned(),
        "ConnectTimeout=10".to_owned(),
        "LogLevel=ERROR".to_owned(),
        format!("IdentityFile={}", user_key.display()),
        format!("CertificateFile={}", certificate.display()),
        "User=root@srv-lab01".to_owned(),
    ]
    .into_iter()
    .flat_map(|o| ["-o".to_owned(), o])
    .collect();
    Some((
        runtime,
        Bench {
            _dir: dir,
            agent,
            local,
            remote,
            options,
        },
    ))
}

impl Bench {
    /// Runs `program` with `-F none`, the options, `port_flag` and the
    /// port of the agent, then `args`, in the local directory.
    fn run(&self, program: &Path, port_flag: &str, args: &[&str]) -> Output {
        Command::new(program)
            .args(["-F", "none"])
            .args(&self.options)
            .args([port_flag, &self.agent.addr.port().to_string()])
            .args(args)
            .current_dir(&self.local)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    /// The `ssh` command line for `rsync -e`.
    fn rsync_shell(&self) -> String {
        let mut line = vec!["ssh".to_owned(), "-F".to_owned(), "none".to_owned()];
        line.extend(self.options.iter().cloned());
        line.extend(["-p".to_owned(), self.agent.addr.port().to_string()]);
        line.join(" ")
    }

    /// Waits for `count` closed sessions.
    fn closed(&self, count: usize) -> Vec<SessionSummary> {
        for _ in 0..200 {
            let closed = self.agent.authorizer.closed.lock().unwrap().clone();
            if closed.len() >= count {
                return closed;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("{count} sessions not closed");
    }

    /// The notes of the transcript of `session`, as `(kind, text)`.
    fn notes(&self, session: &SessionSummary) -> Vec<(NoteKind, String)> {
        self.agent
            .authorizer
            .transcript(&session.session_id)
            .into_iter()
            .filter_map(|f| match f.event {
                Event::Note { kind, text } => {
                    Some((kind, String::from_utf8_lossy(&text).into_owned()))
                }
                _ => None,
            })
            .collect()
    }

    /// Everything the transcript of `session` recorded of the outputs.
    fn output(&self, session: &SessionSummary) -> Vec<u8> {
        self.agent
            .authorizer
            .transcript(&session.session_id)
            .into_iter()
            .filter_map(|f| match f.event {
                Event::Output(d) => Some(d),
                _ => None,
            })
            .flatten()
            .collect()
    }

    /// The `function` of each `ssh.request_refused` event, after waiting
    /// for `count` of them.
    fn refused(&self, count: usize) -> Vec<String> {
        for _ in 0..200 {
            let events = events_on(self.agent.addr, "ssh.request_refused");
            if events.len() >= count {
                assert!(events.iter().all(|e| e.code == "SSH-E022"));
                return events
                    .iter()
                    .map(|e| format!("{} {}", e.field("function"), e.field("detail")))
                    .collect();
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("fewer than {count} requests refused");
    }
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// A content that no note may carry.
const CONTENT: &[u8] = b"contenu-secret-du-fichier\n";

#[test]
fn transfers_without_the_transfer_function_are_refused() {
    let (Some(scp), Some(sftp)) = (tool("scp"), tool("sftp")) else {
        return;
    };
    let Some((_runtime, b)) = bench("transfer-refused", Rights::NONE) else {
        return;
    };
    std::fs::write(b.local.join("a.txt"), CONTENT).unwrap();
    // scp, legacy protocol (exec "scp -t") and SFTP mode (subsystem).
    let out = b.run(&scp, "-P", &["-O", "a.txt", "127.0.0.1:a.txt"]);
    assert!(!out.status.success());
    let out = b.run(&scp, "-P", &["a.txt", "127.0.0.1:b.txt"]);
    assert!(!out.status.success());
    let batch = b.local.join("batch");
    std::fs::write(&batch, "put a.txt c.txt\n").unwrap();
    let out = b.run(&sftp, "-P", &["-b", batch.to_str().unwrap(), "127.0.0.1"]);
    assert!(!out.status.success());
    let mut expected = vec!["transfer scp", "transfer sftp", "transfer sftp"];
    if let Some(rsync) = tool("rsync") {
        let out = Command::new(rsync)
            .args(["-e", &b.rsync_shell(), "a.txt", "127.0.0.1:d.txt"])
            .current_dir(&b.local)
            .output()
            .unwrap();
        assert!(!out.status.success());
        expected.push("transfer rsync");
    }
    let mut refused = b.refused(expected.len());
    refused.sort();
    expected.sort_unstable();
    assert_eq!(refused, expected);
    // Nothing reached the target.
    assert_eq!(std::fs::read_dir(&b.remote).unwrap().count(), 0);
    // An ordinary command naming a transfer tool is refused too: it could
    // be a transfer the agent cannot read.
    let ssh = openssh("ssh").unwrap();
    let out = b.run(&ssh, "-p", &["127.0.0.1", "echo x | rsync --version"]);
    assert!(!out.status.success());
    let out = b.run(&ssh, "-p", &["127.0.0.1", "echo bonjour"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(out.stdout, b"bonjour\n");
}

#[test]
fn scp_both_protocols_and_directions_are_relayed_and_noted() {
    let Some(scp) = tool("scp") else {
        return;
    };
    let Some((_runtime, b)) = bench("transfer-scp", TRANSFER) else {
        return;
    };
    std::fs::write(b.local.join("a.txt"), CONTENT).unwrap();
    std::fs::write(b.remote.join("r.txt"), CONTENT).unwrap();
    // Legacy protocol, both ways.
    let out = b.run(&scp, "-P", &["-O", "a.txt", "127.0.0.1:up-legacy.txt"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = b.run(&scp, "-P", &["-O", "127.0.0.1:r.txt", "down-legacy.txt"]);
    assert!(out.status.success(), "{}", stderr(&out));
    // SFTP mode (the default since OpenSSH 9.0), both ways.
    let out = b.run(&scp, "-P", &["a.txt", "127.0.0.1:up-sftp.txt"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = b.run(&scp, "-P", &["127.0.0.1:r.txt", "down-sftp.txt"]);
    assert!(out.status.success(), "{}", stderr(&out));
    for path in [
        b.remote.join("up-legacy.txt"),
        b.remote.join("up-sftp.txt"),
        b.local.join("down-legacy.txt"),
        b.local.join("down-sftp.txt"),
    ] {
        assert_eq!(std::fs::read(&path).unwrap(), CONTENT, "{}", path.display());
    }
    let closed = b.closed(4);
    let mut all = Vec::new();
    for session in &closed {
        let notes = b.notes(session);
        assert!(
            notes.iter().any(|(k, _)| *k == NoteKind::Transfer),
            "{notes:?}"
        );
        // The contents never reach the transcript.
        let output = b.output(session);
        assert!(!output.windows(CONTENT.len()).any(|w| w == CONTENT));
        all.extend(notes);
    }
    for (kind, path) in [
        (NoteKind::Transfer, "scp"),
        (NoteKind::Transfer, "sftp"),
        (NoteKind::Write, "up-sftp.txt"),
        (NoteKind::Read, "r.txt"),
    ] {
        assert!(
            all.iter().any(|(k, t)| *k == kind && t.ends_with(path)),
            "{kind:?} {path} in {all:?}"
        );
    }
    // The legacy command (with its path) starts the transcript.
    assert!(closed.iter().any(|s| {
        b.agent
            .authorizer
            .transcript(&s.session_id)
            .first()
            .is_some_and(|f| {
                matches!(&f.event, Event::Start { command: Some(c), .. }
                    if String::from_utf8_lossy(c).contains("up-legacy.txt"))
            })
    }));
    assert_eq!(wait_event(b.agent.addr, "ssh.transfer_started").len(), 4);
}

#[test]
fn sftp_operations_are_noted_with_their_file_names() {
    let Some(sftp) = tool("sftp") else {
        return;
    };
    let Some((_runtime, b)) = bench("transfer-sftp", TRANSFER) else {
        return;
    };
    std::fs::write(b.local.join("a.txt"), CONTENT).unwrap();
    std::fs::write(b.remote.join("r.txt"), CONTENT).unwrap();
    let batch = b.local.join("batch");
    std::fs::write(
        &batch,
        "mkdir d\nput a.txt d/a.txt\nrename d/a.txt d/b.txt\nget r.txt r.txt\n\
         rm d/b.txt\nrmdir d\n",
    )
    .unwrap();
    let out = b.run(&sftp, "-P", &["-b", batch.to_str().unwrap(), "127.0.0.1"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(std::fs::read(b.local.join("r.txt")).unwrap(), CONTENT);
    assert!(!b.remote.join("d").exists());
    let closed = b.closed(1);
    let notes = b.notes(&closed[0]);
    let at = |kind: NoteKind, path: &str| {
        notes
            .iter()
            .position(|(k, t)| *k == kind && t.ends_with(path))
            .unwrap_or_else(|| panic!("{kind:?} {path} in {notes:?}"))
    };
    // In the order of the operations; the paths as the client sends them
    // (absolute for sftp), a rename with both.
    let order = [
        at(NoteKind::Transfer, "sftp"),
        at(NoteKind::Mkdir, "/d"),
        at(NoteKind::Write, "/d/a.txt"),
        at(NoteKind::Rename, "/d/b.txt"),
        at(NoteKind::Read, "/r.txt"),
        at(NoteKind::Remove, "/d/b.txt"),
        at(NoteKind::Rmdir, "/d"),
    ];
    assert!(order.windows(2).all(|w| w[0] < w[1]), "{notes:?}");
    assert!(
        !b.output(&closed[0])
            .windows(CONTENT.len())
            .any(|w| w == CONTENT)
    );
}

#[test]
fn rsync_is_relayed_with_its_command_recorded() {
    let Some(rsync) = tool("rsync") else {
        return;
    };
    let Some((_runtime, b)) = bench("transfer-rsync", TRANSFER) else {
        return;
    };
    std::fs::write(b.local.join("a.txt"), CONTENT).unwrap();
    let out = Command::new(&rsync)
        .args(["-e", &b.rsync_shell(), "a.txt", "127.0.0.1:up.txt"])
        .current_dir(&b.local)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let out = Command::new(&rsync)
        .args(["-e", &b.rsync_shell(), "127.0.0.1:up.txt", "down.txt"])
        .current_dir(&b.local)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(std::fs::read(b.remote.join("up.txt")).unwrap(), CONTENT);
    assert_eq!(std::fs::read(b.local.join("down.txt")).unwrap(), CONTENT);
    for session in b.closed(2) {
        let frames = b.agent.authorizer.transcript(&session.session_id);
        assert!(
            matches!(&frames[0].event, Event::Start { command: Some(c), .. }
            if c.starts_with(b"rsync --server"))
        );
        assert_eq!(
            b.notes(&session),
            vec![(NoteKind::Transfer, "rsync".to_owned())]
        );
        assert!(
            !b.output(&session)
                .windows(CONTENT.len())
                .any(|w| w == CONTENT)
        );
    }
}

/// A TCP server that answers each connection with what it receives, in
/// upper case, until the end.
async fn upper_server() -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = tcp.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let upper = buf[..n].to_ascii_uppercase();
                    if tcp.write_all(&upper).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

/// `ssh -W` through the agent, sending `input`.
fn stdio_forward(b: &Bench, port: u16, input: &[u8]) -> Output {
    use std::io::Write;
    let mut child = Command::new(openssh("ssh").unwrap())
        .args(["-F", "none"])
        .args(&b.options)
        .args(["-p", &b.agent.addr.port().to_string()])
        .args(["-W", &format!("127.0.0.1:{port}"), "127.0.0.1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(input).unwrap();
    // The answer comes back before the end of the input.
    std::thread::sleep(std::time::Duration::from_millis(500));
    drop(stdin);
    child.wait_with_output().unwrap()
}

#[test]
fn stdio_forwarding_is_relayed_under_the_port_forwarding_function() {
    let Some((runtime, b)) = bench("forward-allowed", Rights::SSH_PORT_FORWARDING) else {
        return;
    };
    let port = runtime.block_on(upper_server());
    let out = stdio_forward(&b, port, b"bonjour\n");
    assert_eq!(out.stdout, b"BONJOUR\n", "{}", stderr(&out));
    let opened = wait_event(b.agent.addr, "ssh.forward_opened");
    assert_eq!(opened[0].field("destination"), format!("127.0.0.1:{port}"));
    // The transfer function is not implied.
    let ssh = openssh("ssh").unwrap();
    let out = b.run(&ssh, "-p", &["-s", "127.0.0.1", "sftp"]);
    assert!(!out.status.success());
    assert_eq!(b.refused(1), vec!["transfer sftp"]);
}

#[test]
fn stdio_forwarding_without_the_function_is_refused() {
    let Some((runtime, b)) = bench("forward-refused", TRANSFER) else {
        return;
    };
    let port = runtime.block_on(upper_server());
    let out = stdio_forward(&b, port, b"bonjour\n");
    assert_eq!(out.stdout, b"");
    assert_eq!(
        b.refused(1),
        vec![format!("port-forwarding 127.0.0.1:{port}")]
    );
    assert!(events_on(b.agent.addr, "ssh.forward_opened").is_empty());
}
