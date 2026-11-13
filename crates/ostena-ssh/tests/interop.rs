//! The pre-check and the frozen list with real peers: the OpenSSH 9.x client
//! against our server, our client against our server, and refusals, each
//! audited (`ssh.precheck_refused`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stderr,
    reason = "test helpers outside #[test] functions; notices go to stderr"
)]

mod common;

use std::process::{Command, Output};

use common::{
    TestServer, dir, events, keygen, load, openssh, public, raw_offer, refusals, run_command,
    runtime, serve,
};
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
        refusals("openssh-unlisted"),
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
