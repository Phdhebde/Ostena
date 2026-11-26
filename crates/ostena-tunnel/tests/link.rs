//! The agent link against the in-process test core: connection, reconnection
//! with backoff, automatic renewal, stop.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside #[test] functions"
)]

use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;

use ostena_crypto::pki::{Validity, certificate_validity};
use ostena_crypto::tls::TrustAnchor;
use ostena_platform::private_file::{self, Reader};
use ostena_tunnel::link::{AgentLink, Backoff, LinkParams, LinkState, SystemClock};
use ostena_tunnel::testing::{Behaviour, TestCore, valid};
use ostena_tunnel::{Hello, Limits, Uuid};

fn group() -> Uuid {
    Uuid::parse("2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6").unwrap()
}

fn fast() -> Limits {
    Limits {
        keep_alive: Duration::from_millis(100),
        idle_timeout: Duration::from_secs(1),
        heartbeat_interval: Duration::from_millis(100),
        heartbeat_timeout: Duration::from_millis(400),
        handshake_timeout: Duration::from_secs(2),
        ..Limits::default()
    }
}

fn run<F: Future<Output = ()>>(test: F) {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(test);
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

struct Files(PathBuf);

impl Drop for Files {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn params(core: &TestCore, name: &str, validity: Validity) -> (LinkParams, Files) {
    let dir = std::env::temp_dir().join(format!("ostena-link-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (cert, key) = core.agent_files(group(), validity).unwrap();
    std::fs::write(dir.join("agent.crt"), cert).unwrap();
    // SECRET-EXPOSURE: test only, the key file `agent enroll` would write.
    #[expect(clippy::disallowed_methods)]
    std::fs::write(dir.join("agent.key"), key.expose_secret()).unwrap();
    let root = TrustAnchor::from_der(core.trust_anchor().certificate().clone());
    let params = LinkParams {
        core_address: core.addr().to_string(),
        certificate: dir.join("agent.crt"),
        private_key: dir.join("agent.key"),
        root,
        hello: Hello {
            agent_version: "test".into(),
            gateway_group: group(),
            config_fingerprint: format!("sha256:{}", "0".repeat(64)),
        },
        transport: ostena_tunnel::TransportMode::Auto,
        limits: fast(),
        backoff: Backoff {
            base: Duration::from_millis(100),
            max: Duration::from_millis(400),
            stable_after: Duration::from_secs(60),
        },
        clock: std::sync::Arc::new(SystemClock),
        write_key: |path, bytes| private_file::create(path, bytes, Reader::CurrentProcess),
    };
    (params, Files(dir))
}

async fn until(link: &AgentLink, mut check: impl FnMut(&LinkState) -> bool) -> bool {
    for _ in 0..100 {
        if check(&link.status().state) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

fn connected(state: &LinkState) -> bool {
    matches!(state, LinkState::Connected { .. })
}

#[test]
fn connects_and_reports_its_state() {
    run(async {
        let core = TestCore::start(fast(), Behaviour::default()).unwrap();
        let (params, _files) = params(&core, "connect", valid());
        let link = AgentLink::spawn(params);
        assert!(until(&link, connected).await);
        let status = link.status();
        assert_eq!(status.connections, 1);
        assert!(status.renewal_due.is_some());
        assert!(status.summary(now()).starts_with("connecté (QUIC)"));
        link.stop().await;
        assert_eq!(link.status().state, LinkState::Stopped);
    });
}

#[test]
fn reconnects_after_the_core_comes_back() {
    run(async {
        let core = TestCore::start(fast(), Behaviour::default()).unwrap();
        let (params, _files) = params(&core, "reconnect", valid());
        let link = AgentLink::spawn(params);
        assert!(until(&link, connected).await);
        core.stop();
        // Read the code in the same look as the state: the next attempt may
        // start right after.
        let mut last_code = "";
        assert!(
            until(&link, |s| match s {
                LinkState::Reconnecting { code: c, .. } => {
                    last_code = c;
                    true
                }
                _ => false,
            })
            .await,
            "the loss is detected"
        );
        assert_eq!(last_code, "TUN-E013");
        core.restart().await.unwrap();
        assert!(until(&link, connected).await, "{:?}", link.status());
        assert_eq!(link.status().connections, 2);
        link.stop().await;
    });
}

#[test]
fn tells_each_connection_with_its_certificate() {
    run(async {
        let core = TestCore::start(fast(), Behaviour::default()).unwrap();
        let (params, _files) = params(&core, "connected", valid());
        let pem = std::fs::read(&params.certificate).unwrap();
        let der = TrustAnchor::from_pem(&pem).unwrap();
        let expected = ostena_crypto::tls::fingerprint(der.certificate());
        let link = AgentLink::spawn(params);
        let mut connected = link.subscribe_connected();
        assert_eq!(*connected.borrow(), None);
        let first =
            tokio::time::timeout(Duration::from_secs(10), connected.wait_for(Option::is_some))
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        assert_eq!(first.count, 1);
        assert_eq!(first.certificate_sha256, expected);
        // Usable at once: the message goes on the connection just told.
        link.send(&ostena_tunnel::control::AgentMessage::SessionClosed {
            session_id: "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6".into(),
            reason: "test".into(),
            bytes_to_target: 0,
            bytes_from_target: 0,
        })
        .await
        .unwrap();
        core.stop();
        core.restart().await.unwrap();
        let second = tokio::time::timeout(
            Duration::from_secs(20),
            connected.wait_for(|c| c.is_some_and(|c| c.count == 2)),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!(second.certificate_sha256, expected);
        link.stop().await;
    });
}

#[test]
fn renews_its_certificate_at_two_thirds_with_a_new_key() {
    run(async {
        let core = TestCore::start(fast(), Behaviour::default()).unwrap();
        // Two thirds of this validity are already past: renewal is due now.
        let short = Validity {
            not_before: now() - 40,
            not_after: now() + 20,
        };
        let (params, files) = params(&core, "renew", short);
        let old_key = std::fs::read(&params.private_key).unwrap();
        let link = AgentLink::spawn(params.clone());
        let mut renewed = false;
        for _ in 0..100 {
            let cert = std::fs::read(&params.certificate).unwrap();
            let der = TrustAnchor::from_pem(&cert).unwrap();
            if let Some((_, not_after)) = certificate_validity(der.certificate())
                && not_after > now() + 86_400
            {
                renewed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(renewed, "certificate renewed");
        assert_ne!(
            std::fs::read(&params.private_key).unwrap(),
            old_key,
            "new key"
        );
        assert!(!files.0.join("agent.key.new").exists());
        assert!(!files.0.join("agent.crt.new").exists());
        assert!(link.status().certificate_not_after.unwrap() > now() + 86_400);
        assert!(!link.status().renewal_overdue);
        // No session open: the agent reconnects at once with the renewed
        // identity, and the old key leaves memory.
        assert!(
            until(&link, |_| link.status().connections == 2).await,
            "{:?}",
            link.status()
        );
        assert!(until(&link, connected).await);
        renewed_key_is_private(&params.private_key);
        let names: Vec<_> = std::fs::read_dir(&files.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(
            names.len(),
            2,
            "only the current key and certificate: {names:?}"
        );
        link.stop().await;
    });
}

#[test]
fn interrupted_renewal_is_completed_at_the_next_connection() {
    run(async {
        let core = TestCore::start(fast(), Behaviour::default()).unwrap();
        let (params, files) = params(&core, "interrupted", valid());
        // As if the agent stopped between the two renames: the new key is in
        // place, the new certificate still next to the old one.
        let (cert, key) = core.agent_files(group(), valid()).unwrap();
        // SECRET-EXPOSURE: test only.
        #[expect(clippy::disallowed_methods)]
        std::fs::write(&params.private_key, key.expose_secret()).unwrap();
        std::fs::write(files.0.join("agent.crt.new"), &cert).unwrap();
        let link = AgentLink::spawn(params.clone());
        assert!(until(&link, connected).await, "{:?}", link.status());
        assert_eq!(std::fs::read_to_string(&params.certificate).unwrap(), cert);
        link.stop().await;
    });
}

/// The renewed key was created with its final rights: 0600, or on Windows a
/// protected DACL (SYSTEM, Administrators, the agent account), nothing
/// inherited.
fn renewed_key_is_private(key: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    #[cfg(windows)]
    {
        use ostena_platform::acl::{ADMINISTRATORS, SYSTEM, read_security};
        let me = private_file::current_user_sid().unwrap();
        let security = read_security(key).unwrap();
        let mut sids: Vec<String> = security
            .dacl
            .unwrap()
            .into_iter()
            .filter(|a| a.allow)
            .map(|a| a.sid)
            .collect();
        sids.sort();
        let mut expected = vec![SYSTEM.to_owned(), ADMINISTRATORS.to_owned(), me];
        expected.sort();
        expected.dedup();
        assert_eq!(sids, expected);
        let icacls = std::process::Command::new("icacls")
            .arg(key)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&icacls.stdout);
        assert!(!text.contains("(I)"), "nothing inherited: {text}");
    }
}

#[test]
fn renewal_interrupted_before_the_renames_is_discarded() {
    run(async {
        let core = TestCore::start(fast(), Behaviour::default()).unwrap();
        let (params, files) = params(&core, "discarded", valid());
        let cert = std::fs::read(&params.certificate).unwrap();
        // As if the agent stopped after writing the new files, before any
        // rename: the current pair is consistent, the new files are left.
        std::fs::write(files.0.join("agent.key.new"), b"partial").unwrap();
        std::fs::write(files.0.join("agent.crt.new"), b"partial").unwrap();
        let link = AgentLink::spawn(params.clone());
        assert!(until(&link, connected).await, "{:?}", link.status());
        assert!(!files.0.join("agent.key.new").exists());
        assert!(!files.0.join("agent.crt.new").exists());
        assert_eq!(std::fs::read(&params.certificate).unwrap(), cert);
        link.stop().await;
    });
}
