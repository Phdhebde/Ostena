//! Memory per RDP session on the agent side, measured on demand:
//!
//! ```text
//! cargo test --release -p ostena-rdp --test footprint -- --ignored --nocapture memory_per_session
//! ```
//!
//! The test targets run in a child process (this same test binary,
//! `serve_targets`), so that the resident memory of the measuring process
//! holds only the client side: connection, CredSSP, TLS, session loop.
//! Linux only (`/proc/self/statm`).

#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    reason = "measure on demand; the result is printed"
)]

mod support;

use std::io::{BufRead as _, BufReader};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use ostena_common::secret::SecretString;
use ostena_crypto::hmac::HmacKey;
use ostena_rdp::RdpError;
use ostena_rdp::driver::{
    RdpDriver, RdpMode, RdpPolicy, RdpSessionParams, SecretSource, TargetParams, Validation,
};
use ostena_rdp::profile::to_hex;
use ostena_session::{Driver, DriverConnection};
use support::{Options, PASSWORD, Script, Target, USER, loopback};

/// Sessions held at the same time.
const SESSIONS: usize = 20;
const SERVE: &str = "OSTENA_RDP_FOOTPRINT_SERVE";

/// Child side: starts `SESSIONS + 1` targets, prints their ports and
/// fingerprints, and waits until each session is closed.
#[test]
#[ignore = "child process of memory_per_session"]
fn serve_targets() {
    if std::env::var_os(SERVE).is_none() {
        return;
    }
    let targets: Vec<Target> = (0..=SESSIONS)
        .map(|_| {
            Target::start(Options {
                restricted_admin: true,
                script: Script::WaitClient,
                ..Options::default()
            })
        })
        .collect();
    for t in &targets {
        println!("TARGET {} {}", t.addr.port(), to_hex(&t.fingerprint()));
    }
    println!("READY");
    for t in targets {
        drop(t.join());
    }
}

struct Secrets;

impl SecretSource for Secrets {
    fn password(&self, _: &str) -> Result<SecretString, RdpError> {
        Ok(SecretString::from(PASSWORD.to_owned()))
    }
}

fn resident_bytes() -> u64 {
    let statm = std::fs::read_to_string("/proc/self/statm").unwrap();
    let pages: u64 = statm.split_whitespace().nth(1).unwrap().parse().unwrap();
    pages * 4096
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "measure on demand, in release"]
async fn memory_per_session() {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "serve_targets", "--nocapture"])
        .env(SERVE, "1")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut targets = Vec::new();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    for line in lines.by_ref() {
        let line = line.unwrap();
        if line == "READY" {
            break;
        }
        if let Some(rest) = line.strip_prefix("TARGET ") {
            let (port, fp) = rest.split_once(' ').unwrap();
            targets.push((port.parse::<u16>().unwrap(), fp.to_owned()));
        }
    }
    assert_eq!(targets.len(), SESSIONS + 1);
    // The rest of the output of the child, read until its end.
    let drain = std::thread::spawn(move || lines.count());
    let driver = RdpDriver::new(
        Arc::new(RdpPolicy {
            production: true,
            validation: Validation::Pinned,
            password_delegation: false,
            ntlm_fallback: true,
            realms: Vec::new(),
            identity_key: HmacKey::new(&HmacKey::generate().unwrap()).unwrap(),
            workstation: "OST-AGENT".into(),
        }),
        Arc::new(Secrets),
    );
    let connect = |port: u16, fp: String| {
        let driver = driver.clone();
        async move {
            let pinned = loopback(port).await;
            let params = TargetParams {
                session: RdpSessionParams {
                    account: USER.into(),
                    target_name: Some("target.example.test".into()),
                    certificate_sha256: Some(fp),
                    mode: RdpMode::RestrictedAdmin,
                    width: 1920,
                    height: 1080,
                    profile: None,
                    license: None,
                },
                label: "footprint".into(),
            };
            driver
                .connect(&pinned, params, Duration::from_secs(20))
                .await
                .unwrap()
        }
    };
    // One session first: the one-time costs (TLS configuration, runtime,
    // lazy tables) stay out of the measure.
    let mut targets = targets.into_iter();
    let (port, fp) = targets.next().unwrap();
    let warm = connect(port, fp).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let before = resident_bytes();
    let mut held = Vec::new();
    for (port, fp) in targets {
        held.push(connect(port, fp).await);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let after = resident_bytes();
    let per_session = after.saturating_sub(before) / SESSIONS as u64;
    println!(
        "RSS avant : {} Kio, après {SESSIONS} sessions : {} Kio, par session : {} Kio",
        before / 1024,
        after / 1024,
        per_session / 1024
    );
    for c in held {
        c.close().await;
    }
    warm.close().await;
    assert!(child.wait().unwrap().success());
    drop(drain.join());
}
