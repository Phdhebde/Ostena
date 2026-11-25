//! The SSH access through the gateway against the in-process test core
//! (ADR-0008, ADR-0010): grant asked by the agent, verified and consumed on
//! both sides, then the answer checked against the access and pinned by the
//! scope control.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside #[test] functions"
)]

mod common;

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ostena_common::config::Mode;
use ostena_crypto::p256::{SigningKey, VerifyingKey};
use ostena_grant::{MemoryReplayStore, Protocol};
use ostena_scope::{AllowRuleSpec, LocalAddresses, PolicySpec, SharedLocalAddresses};
use ostena_tunnel::control::{AgentMessage, CoreMessage};
use ostena_tunnel::gateway::{Gateway, GatewayParams, GatewayState, SshAccess};
use ostena_tunnel::link::{AgentLink, Backoff, LinkParams, LinkState, SystemClock};
use ostena_tunnel::testing::{Behaviour, SshResource, TestCore, valid};
use ostena_tunnel::{Hello, Limits, Uuid};

fn group() -> Uuid {
    Uuid::parse("2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6").unwrap()
}

fn subject() -> Uuid {
    Uuid::parse("5d1c2b3a-4e5f-4a6b-8c7d-9e0f1a2b3c4d").unwrap()
}

fn login() -> Uuid {
    Uuid::parse("7a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d").unwrap()
}

fn run<F: Future<Output = ()>>(test: F) {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(test);
}

fn allow(networks: &[&str]) -> PolicySpec {
    PolicySpec {
        gateway_group: group().to_string(),
        allow: vec![AllowRuleSpec {
            label: None,
            networks: networks.iter().map(|n| (*n).to_owned()).collect(),
            ports: vec!["22".into()],
        }],
        ..PolicySpec::default()
    }
}

struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn dir(name: &str) -> Dir {
    let dir = std::env::temp_dir().join(format!("ostena-ssh-gw-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Dir(dir)
}

fn write(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

/// An agent connected to `core`, its local policy allowing `local`.
async fn agent(core: &TestCore, dir: &Dir, local: PolicySpec) -> Gateway {
    let (cert, key) = core.agent_files(group(), valid()).unwrap();
    let certificate = dir.0.join("agent.crt");
    let private_key = dir.0.join("agent.key");
    std::fs::write(&certificate, cert).unwrap();
    // SECRET-EXPOSURE: test only, the key file `agent enroll` would write.
    #[expect(clippy::disallowed_methods)]
    std::fs::write(&private_key, key.expose_secret()).unwrap();
    let link = Arc::new(AgentLink::spawn(LinkParams {
        core_address: core.addr().to_string(),
        certificate,
        private_key,
        root: ostena_crypto::tls::TrustAnchor::from_der(core.trust_anchor().certificate().clone()),
        hello: Hello {
            agent_version: "test".into(),
            gateway_group: group(),
            config_fingerprint: format!("sha256:{}", "0".repeat(64)),
        },
        limits: Limits::default(),
        backoff: Backoff::default(),
        clock: Arc::new(SystemClock),
        write_key: write,
    }));
    for _ in 0..100 {
        if matches!(link.status().state, LinkState::Connected { .. }) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let state = GatewayState::open(GatewayParams {
        gateway_group: group(),
        mode: Mode::Production,
        local_policy: local,
        infrastructure: Arc::new(Mutex::new(Vec::new())),
        local_addresses: SharedLocalAddresses::new(LocalAddresses::from_addrs([])),
        keyset_state: dir.0.join("keyset.version"),
        write_private: write,
        grant_policy: ostena_grant::Policy::default(),
    })
    .unwrap();
    Gateway::start(Arc::new(state), link).unwrap()
}

async fn until(gateway: &Gateway, check: impl Fn(&Gateway) -> bool) -> bool {
    for _ in 0..100 {
        if check(gateway) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// Keys, policy and, if `trust`, the SSH trust (version 1).
async fn push(core: &TestCore, gateway: &Gateway, policy: PolicySpec, trust: bool) {
    core.push(&CoreMessage::KeySet {
        version: 1,
        keys: vec![core.grant_key()],
    })
    .await;
    core.push(&CoreMessage::Policy { version: 1, policy }).await;
    if trust {
        core.push_ssh_trust(1, None).await;
    }
    assert!(
        until(gateway, |g| {
            let v = g.state().versions();
            v.policy == Some(1) && v.keyset == Some(1) && (!trust || v.ssh_trust == Some(1))
        })
        .await
    );
}

fn access(account: &str, resource: &str) -> SshAccess {
    SshAccess {
        subject: subject(),
        login_session: login(),
        certificate_sha256: [0xab; 32],
        account: account.into(),
        resource: resource.into(),
        client_address: "10.1.2.3:51000".parse().unwrap(),
    }
}

fn target_key() -> VerifyingKey {
    SigningKey::generate().unwrap().0.verifying_key()
}

fn now() -> u64 {
    ostena_grant::unix_now()
}

#[test]
fn ssh_session_consumes_the_jti_on_both_sides() {
    run(async {
        let core = TestCore::start(Limits::default(), Behaviour::default()).unwrap();
        let dir = dir("jti");
        let gateway = agent(&core, &dir, allow(&["10.0.0.0/8"])).await;
        push(&core, &gateway, allow(&["10.20.0.0/16"]), true).await;
        let key = target_key();
        core.add_ssh_resource("srv-lab01", SshResource::new("10.20.0.5", 22, key));
        let store = MemoryReplayStore::new();
        let session = gateway
            .open_ssh_session(&access("admin@corp.local", "srv-lab01"), now(), &store)
            .await
            .unwrap();
        assert_eq!(session.account, "admin@corp.local");
        assert_eq!(session.target_host_key, key);
        assert_eq!(
            session.session.target.addrs(),
            &["10.20.0.5:22".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(session.session.grant.claims.protocol, Protocol::Ssh);
        assert_eq!(
            session.session.grant.claims.subject.to_bytes(),
            subject().to_bytes()
        );
        // What the core was asked.
        let requests = core.ssh_grant_requests();
        let [
            AgentMessage::SshGrantRequest {
                subject: asked,
                login_session,
                certificate_sha256,
                account,
                resource,
                client_address,
                ..
            },
        ] = requests.as_slice()
        else {
            panic!("{requests:?}")
        };
        assert_eq!(asked, &subject().to_string());
        assert_eq!(login_session, &login().to_string());
        assert_eq!(certificate_sha256, &"ab".repeat(32));
        assert_eq!(account, "admin@corp.local");
        assert_eq!(resource, "srv-lab01");
        assert_eq!(client_address, "10.1.2.3:51000");

        // Replayed on this agent: refused by its own store.
        let grant = core.ssh_grants().pop().unwrap();
        let replay = gateway
            .open_session(&grant, now(), &store)
            .await
            .unwrap_err();
        assert_eq!(replay.code(), "GRT-E010");
        // Replayed with a fresh store (another agent of the group): the core
        // consumed it too.
        let replay = gateway
            .open_session(&grant, now(), &MemoryReplayStore::new())
            .await
            .unwrap_err();
        assert_eq!(replay.code(), "GRT-E010");
        assert!(
            replay.to_string().contains("refusé par le core"),
            "{replay}"
        );
    });
}

/// The transcript stream of an SSH session reaches the core, finished;
/// once the connection is lost, the transcript of a live session sees it
/// at once (fail closed, ADR-0016).
#[test]
fn the_transcript_reaches_the_core_and_its_loss_is_seen() {
    use ostena_recorder::{Decoder, EndReason, Limits as RecLimits};
    use ostena_ssh::transcript::Transcript;
    use ostena_tunnel::recording::{QUEUE, pump};
    run(async {
        let core = TestCore::start(Limits::default(), Behaviour::default()).unwrap();
        let dir = dir("transcript");
        let gateway = agent(&core, &dir, allow(&["10.0.0.0/8"])).await;
        push(&core, &gateway, allow(&["10.20.0.0/16"]), true).await;
        core.add_ssh_resource("srv-lab01", SshResource::new("10.20.0.5", 22, target_key()));
        let store = MemoryReplayStore::new();

        let session = gateway
            .open_ssh_session(&access("root", "srv-lab01"), now(), &store)
            .await
            .unwrap();
        let id = session.session.session_id;
        let (transcript, rx) = Transcript::channel(QUEUE);
        let pumped = tokio::spawn(pump(rx, session.recording));
        transcript.start(None, Some(b"uname -a")).await.unwrap();
        transcript.output(b"Linux srv-lab01\n").await.unwrap();
        transcript.end(EndReason::Closed).await.unwrap();
        drop(transcript);
        pumped.await.unwrap().unwrap();
        let (bytes, finished) = core.recording(id).unwrap();
        assert!(finished);
        let mut decoder = Decoder::new(RecLimits::default());
        decoder.feed(&bytes);
        let mut frames = 0;
        while decoder.next_frame().unwrap().is_some() {
            frames += 1;
        }
        decoder.finish().unwrap();
        assert_eq!(frames, 3);

        // A live session, then the core goes away.
        let session = gateway
            .open_ssh_session(&access("root", "srv-lab01"), now(), &store)
            .await
            .unwrap();
        let (transcript, rx) = Transcript::channel(QUEUE);
        let pumped = tokio::spawn(pump(rx, session.recording));
        transcript.start(None, None).await.unwrap();
        core.stop();
        tokio::time::timeout(Duration::from_secs(20), transcript.closed())
            .await
            .expect("loss of the tunnel seen by the transcript");
        assert!(pumped.await.unwrap().is_err());
        assert_eq!(
            transcript.output(b"x").await.unwrap_err().code(),
            "SSH-E021"
        );
    });
}

/// A core that accepts the transcript stream but no longer reads it: the
/// pump gives up after its write delay, resets the stream, and the
/// transcript is lost (the session is cut).
#[test]
fn a_transcript_the_core_does_not_read_is_lost_in_the_delay() {
    use ostena_ssh::transcript::Transcript;
    use ostena_tunnel::recording::pump_with;
    run(async {
        let core = TestCore::start(
            Limits::default(),
            Behaviour {
                stall_recordings: true,
                ..Behaviour::default()
            },
        )
        .unwrap();
        let dir = dir("transcript-stalled");
        let gateway = agent(&core, &dir, allow(&["10.0.0.0/8"])).await;
        push(&core, &gateway, allow(&["10.20.0.0/16"]), true).await;
        core.add_ssh_resource("srv-lab01", SshResource::new("10.20.0.5", 22, target_key()));
        let store = MemoryReplayStore::new();
        let session = gateway
            .open_ssh_session(&access("root", "srv-lab01"), now(), &store)
            .await
            .unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel(2);
        let transcript = Transcript::with_timeout(tx, Duration::from_secs(30));
        let pumped = tokio::spawn(pump_with(rx, session.recording, Duration::from_millis(500)));
        transcript.start(None, None).await.unwrap();
        let started = std::time::Instant::now();
        let writer = tokio::spawn({
            let transcript = transcript.clone();
            async move {
                // Far beyond the window of the stream.
                for _ in 0..64 {
                    transcript.output(&[b'x'; 16 * 1024]).await?;
                }
                Ok::<_, ostena_ssh::SshError>(())
            }
        });
        tokio::time::timeout(Duration::from_secs(10), transcript.closed())
            .await
            .expect("transcript lost in the delay");
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(pumped.await.unwrap().is_err());
        assert_eq!(writer.await.unwrap().unwrap_err().code(), "SSH-E021");
    });
}

#[test]
fn a_grant_or_an_answer_that_does_not_match_the_access_is_refused() {
    run(async {
        let core = TestCore::start(Limits::default(), Behaviour::default()).unwrap();
        let dir = dir("mismatch");
        let gateway = agent(&core, &dir, allow(&["10.0.0.0/8"])).await;
        push(&core, &gateway, allow(&["10.0.0.0/8"]), true).await;
        let store = MemoryReplayStore::new();

        let mut other_subject = SshResource::new("10.20.0.5", 22, target_key());
        other_subject.grant_subject = Some(Uuid::random().unwrap());
        core.add_ssh_resource("other-subject", other_subject);
        let refused = gateway
            .open_ssh_session(&access("root", "other-subject"), now(), &store)
            .await
            .unwrap_err();
        assert_eq!(refused.code(), "TUN-E010");
        assert!(refused.to_string().contains("sujet"), "{refused}");

        let mut rdp = SshResource::new("10.20.0.5", 22, target_key());
        rdp.grant_protocol = Protocol::Rdp;
        core.add_ssh_resource("rdp", rdp);
        let refused = gateway
            .open_ssh_session(&access("root", "rdp"), now(), &store)
            .await
            .unwrap_err();
        assert_eq!(refused.code(), "TUN-E010");

        let mut other_account = SshResource::new("10.20.0.5", 22, target_key());
        other_account.answer_account = Some("admin".into());
        core.add_ssh_resource("other-account", other_account);
        let refused = gateway
            .open_ssh_session(&access("root", "other-account"), now(), &store)
            .await
            .unwrap_err();
        assert_eq!(refused.code(), "TUN-E010");
        assert!(refused.to_string().contains("compte"), "{refused}");

        // A grant bound to another account (or login session): burned.
        let mut other_binding = SshResource::new("10.20.0.5", 22, target_key());
        other_binding.bind_account = Some("admin".into());
        core.add_ssh_resource("other-binding", other_binding);
        let refused = gateway
            .open_ssh_session(&access("root", "other-binding"), now(), &store)
            .await
            .unwrap_err();
        assert_eq!(refused.code(), "TUN-E010");
        assert!(refused.to_string().contains("liaison"), "{refused}");
        let burned = core.ssh_grants().last().unwrap().clone();
        let again = gateway.open_session(&burned, now(), &store).await;
        assert_eq!(again.unwrap_err().code(), "GRT-E010");

        // Unknown resource: the core refuses with its code.
        let refused = gateway
            .open_ssh_session(&access("root", "unknown"), now(), &store)
            .await
            .unwrap_err();
        assert_eq!(refused.code(), "INV-E001");
    });
}

#[test]
fn session_parameters_without_the_target_host_key_are_refused() {
    common::events();
    run(async {
        let core = TestCore::start(Limits::default(), Behaviour::default()).unwrap();
        let dir = dir("no-host-key");
        let gateway = agent(&core, &dir, allow(&["10.0.0.0/8"])).await;
        push(&core, &gateway, allow(&["10.0.0.0/8"]), true).await;
        let mut resource = SshResource::new("10.20.0.5", 22, target_key());
        resource.omit_target_key = true;
        core.add_ssh_resource("no-key", resource);
        let refused = gateway
            .open_ssh_session(&access("root", "no-key"), now(), &MemoryReplayStore::new())
            .await
            .unwrap_err();
        // The agent refuses the message and closes the tunnel: the request
        // gets no answer.
        assert!(
            ["TUN-E027", "TUN-E013", "TUN-E010"].contains(&refused.code().as_str()),
            "{refused}"
        );
    });
    let refusals: Vec<_> = common::events()
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.name == "tunnel.message_refused")
        .map(|e| e.code.clone())
        .collect();
    assert!(refusals.iter().any(|c| c == "TUN-E010"), "{refusals:?}");
}

#[test]
fn metadata_and_loopback_targets_are_refused_by_the_scope_control() {
    run(async {
        let core = TestCore::start(Limits::default(), Behaviour::default()).unwrap();
        let dir = dir("scope");
        let wide = allow(&["10.0.0.0/8"]);
        let gateway = agent(&core, &dir, wide.clone()).await;
        push(&core, &gateway, wide, true).await;
        for (name, host) in [
            ("metadata", "169.254.169.254"),
            ("loopback", "127.0.0.1"),
            ("outside", "192.168.1.5"),
        ] {
            core.add_ssh_resource(name, SshResource::new(host, 22, target_key()));
            let refused = gateway
                .open_ssh_session(&access("root", name), now(), &MemoryReplayStore::new())
                .await
                .unwrap_err();
            assert!(refused.code().starts_with("SCP-E"), "{host}: {refused}");
        }
    });
}

#[test]
fn nothing_passes_before_the_ssh_trust_and_a_lower_trust_is_refused() {
    common::events();
    run(async {
        let core = TestCore::start(Limits::default(), Behaviour::default()).unwrap();
        let dir = dir("trust");
        let gateway = agent(&core, &dir, allow(&["10.0.0.0/8"])).await;
        core.add_ssh_resource("srv", SshResource::new("10.20.0.5", 22, target_key()));
        let store = MemoryReplayStore::new();
        let refused = gateway
            .open_ssh_session(&access("root", "srv"), now(), &store)
            .await
            .unwrap_err();
        assert_eq!(refused.code(), "TUN-E026");
        push(&core, &gateway, allow(&["10.0.0.0/8"]), false).await;
        let refused = gateway
            .open_ssh_session(&access("root", "srv"), now(), &store)
            .await
            .unwrap_err();
        assert_eq!(refused.code(), "TUN-E026");
        assert!(refused.to_string().contains("confiance SSH"), "{refused}");
        assert!(core.ssh_grant_requests().is_empty(), "nothing asked");

        core.push_ssh_trust(2, None).await;
        assert!(until(&gateway, |g| g.state().versions().ssh_trust == Some(2)).await);
        let trust = gateway.state().ssh_trust().unwrap();
        assert_eq!(trust.user_cas, [core.ssh_user_ca().verifying_key()]);
        assert_eq!(trust.host_cas, [core.ssh_host_ca().verifying_key()]);
        // A lower version is refused, the trust stays.
        core.push_ssh_trust(1, None).await;
        // The same version again is ignored; with another content, refused.
        core.push_ssh_trust(2, None).await;
        let host = SigningKey::generate().unwrap().0;
        let issued = now();
        let certificate = ostena_ssh::cert::issue(
            &ostena_ssh::cert::Template {
                kind: ostena_ssh::cert::Kind::Host,
                public: host.verifying_key(),
                serial: 1,
                key_id: "gw".into(),
                principals: vec!["gw.example.test".into()],
                valid_after: issued,
                valid_before: issued + 3600,
                critical_options: vec![],
                extensions: vec![],
            },
            &host,
        )
        .unwrap();
        core.push_ssh_trust(2, Some(&certificate)).await;
        core.push(&CoreMessage::Policy {
            version: 2,
            policy: allow(&["10.0.0.0/8"]),
        })
        .await;
        assert!(until(&gateway, |g| g.state().versions().policy == Some(2)).await);
        assert_eq!(gateway.state().versions().ssh_trust, Some(2));
        assert!(
            gateway
                .open_ssh_session(&access("root", "srv"), now(), &store)
                .await
                .is_ok()
        );
    });
    let refused: Vec<_> = common::events()
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.name == "agent.ssh_trust_refused")
        .map(|e| e.code.clone())
        .collect();
    assert_eq!(
        refused.iter().filter(|c| *c == "TUN-E030").count(),
        2,
        "lower version and same version with another content: {refused:?}"
    );
}

#[test]
fn login_revocations_reach_the_ssh_server() {
    run(async {
        let core = TestCore::start(Limits::default(), Behaviour::default()).unwrap();
        let dir = dir("revoke");
        let gateway = agent(&core, &dir, allow(&["10.0.0.0/8"])).await;
        let mut revocations = gateway.subscribe_login_revocations();
        assert_eq!(core.revoke_login(login()).await, 1);
        let revoked = tokio::time::timeout(Duration::from_secs(5), revocations.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(revoked, login());
    });
}
