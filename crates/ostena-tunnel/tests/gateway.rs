//! What the core pushes and the session requests, against the in-process
//! test core: policy intersection, key set versions kept across a restart,
//! jti consumed by the agent then by the core.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside #[test] functions"
)]

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ostena_common::config::Mode;
use ostena_grant::{MemoryReplayStore, Protocol};
use ostena_platform::private_file::{self, Reader};
use ostena_scope::{AllowRuleSpec, LocalAddresses, PolicySpec, SharedLocalAddresses};
use ostena_tunnel::control::CoreMessage;
use ostena_tunnel::gateway::{Gateway, GatewayParams, GatewayState};
use ostena_tunnel::link::{AgentLink, Backoff, LinkParams, LinkState, SystemClock};
use ostena_tunnel::testing::{Behaviour, TestCore, valid};
use ostena_tunnel::{Hello, Limits, TunnelError, Uuid};

fn group() -> Uuid {
    Uuid::parse("2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6").unwrap()
}

fn run<F: Future<Output = ()>>(test: F) {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(test);
}

/// A policy allowing `networks` on port 22, for the agent group (the core
/// always names the group of the policy it pushes).
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
    let dir = std::env::temp_dir().join(format!("ostena-gateway-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Dir(dir)
}

fn state(dir: &Dir, file: &str, local: PolicySpec) -> Arc<GatewayState> {
    Arc::new(
        GatewayState::open(GatewayParams {
            gateway_group: group(),
            mode: Mode::Production,
            local_policy: local,
            infrastructure: Arc::new(Mutex::new(Vec::new())),
            local_addresses: SharedLocalAddresses::new(LocalAddresses::from_addrs([])),
            keyset_state: dir.0.join(file),
            write_private: |path, bytes| private_file::create(path, bytes, Reader::CurrentProcess),
            grant_policy: ostena_grant::Policy::default(),
        })
        .unwrap(),
    )
}

/// An agent connected to `core`, with its own files in `dir` and the key
/// set state `state_file`.
async fn agent(
    core: &TestCore,
    dir: &Dir,
    name: &str,
    state_file: &str,
    local: PolicySpec,
) -> Gateway {
    let (cert, key) = core.agent_files(group(), valid()).unwrap();
    let certificate = dir.0.join(format!("{name}.crt"));
    let private_key = dir.0.join(format!("{name}.key"));
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
        transport: ostena_tunnel::TransportMode::Auto,
        limits: Limits::default(),
        backoff: Backoff::default(),
        clock: Arc::new(SystemClock),
        write_key: |path, bytes| private_file::create(path, bytes, Reader::CurrentProcess),
    }));
    for _ in 0..100 {
        if matches!(link.status().state, LinkState::Connected { .. }) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Gateway::start(state(dir, state_file, local), link).unwrap()
}

/// Waits until `check` holds on the gateway versions.
async fn until(gateway: &Gateway, check: impl Fn(&Gateway) -> bool) -> bool {
    for _ in 0..100 {
        if check(gateway) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

async fn push_all(core: &TestCore, gateway: &Gateway, policy: PolicySpec) {
    core.push(&CoreMessage::KeySet {
        version: 1,
        keys: vec![core.grant_key()],
    })
    .await;
    core.push(&CoreMessage::Policy { version: 1, policy }).await;
    assert!(
        until(gateway, |g| {
            let v = g.state().versions();
            v.policy == Some(1) && v.keyset == Some(1)
        })
        .await
    );
}

/// Pushes a policy of `version` and waits for it: the pushes are applied in
/// order, so everything pushed before has been processed. No fixed delay.
async fn processed(core: &TestCore, gateway: &Gateway, version: u64) {
    core.push(&CoreMessage::Policy {
        version,
        policy: allow(&["10.0.0.0/8"]),
    })
    .await;
    assert!(until(gateway, |g| g.state().versions().policy == Some(version)).await);
}

fn now() -> u64 {
    ostena_grant::unix_now()
}

#[test]
fn nothing_passes_before_the_core_pushes() {
    run(async {
        let core = TestCore::start(Limits::default(), Behaviour::default()).unwrap();
        let dir = dir("before");
        let gateway = agent(&core, &dir, "a", "a.version", allow(&["10.0.0.0/8"])).await;
        let grant = core
            .issue_grant(group(), Protocol::Ssh, "10.20.0.5", 22)
            .unwrap();
        let store = MemoryReplayStore::new();
        let refused = gateway
            .open_session(&grant, now(), &store)
            .await
            .unwrap_err();
        assert_eq!(refused.code(), "TUN-E026");
    });
}

#[test]
fn session_opens_through_the_intersection() {
    run(async {
        let core = TestCore::start(Limits::default(), Behaviour::default()).unwrap();
        let dir = dir("open");
        let gateway = agent(&core, &dir, "a", "a.version", allow(&["10.0.0.0/8"])).await;
        push_all(&core, &gateway, allow(&["10.20.0.0/16", "192.168.0.0/16"])).await;
        let store = MemoryReplayStore::new();

        // Allowed by both.
        let grant = core
            .issue_grant(group(), Protocol::Ssh, "10.20.0.5", 22)
            .unwrap();
        let session = gateway.open_session(&grant, now(), &store).await.unwrap();
        assert_eq!(
            session.target.addrs(),
            &["10.20.0.5:22".parse::<SocketAddr>().unwrap()]
        );
        // The same grant again: refused by the agent's own store.
        let again = gateway
            .open_session(&grant, now(), &store)
            .await
            .unwrap_err();
        assert_eq!(again.code(), "GRT-E010");

        // Allowed locally, not by the core.
        let grant = core
            .issue_grant(group(), Protocol::Ssh, "10.30.0.5", 22)
            .unwrap();
        let refused = gateway
            .open_session(&grant, now(), &store)
            .await
            .unwrap_err();
        assert!(refused.code().starts_with("SCP-E"), "{refused}");
        assert!(
            refused.to_string().contains("politique du core"),
            "{refused}"
        );

        // Allowed by the core, not locally: the core cannot widen.
        let grant = core
            .issue_grant(group(), Protocol::Ssh, "192.168.1.5", 22)
            .unwrap();
        let refused = gateway
            .open_session(&grant, now(), &store)
            .await
            .unwrap_err();
        assert!(refused.code().starts_with("SCP-E"), "{refused}");
    });
}

#[test]
fn empty_local_policy_lets_nothing_pass() {
    run(async {
        let core = TestCore::start(Limits::default(), Behaviour::default()).unwrap();
        let dir = dir("empty");
        let gateway = agent(&core, &dir, "a", "a.version", PolicySpec::default()).await;
        push_all(&core, &gateway, allow(&["10.0.0.0/8"])).await;
        let grant = core
            .issue_grant(group(), Protocol::Ssh, "10.20.0.5", 22)
            .unwrap();
        let store = MemoryReplayStore::new();
        let refused = gateway
            .open_session(&grant, now(), &store)
            .await
            .unwrap_err();
        assert!(refused.code().starts_with("SCP-E"), "{refused}");
    });
}

/// Two agents of the same group, each with its own store: the second use of
/// a grant passes the second agent's store, the core refuses it.
#[test]
fn the_core_consumes_the_jti() {
    run(async {
        let core = TestCore::start(Limits::default(), Behaviour::default()).unwrap();
        let dir = dir("jti");
        let a = agent(&core, &dir, "a", "a.version", allow(&["10.0.0.0/8"])).await;
        let b = agent(&core, &dir, "b", "b.version", allow(&["10.0.0.0/8"])).await;
        push_all(&core, &a, allow(&["10.0.0.0/8"])).await;
        assert!(
            until(&b, |g| g.state().versions().keyset == Some(1)).await,
            "pushed to every agent"
        );
        let grant = core
            .issue_grant(group(), Protocol::Ssh, "10.20.0.5", 22)
            .unwrap();
        a.open_session(&grant, now(), &MemoryReplayStore::new())
            .await
            .unwrap();
        let refused = b
            .open_session(&grant, now(), &MemoryReplayStore::new())
            .await
            .unwrap_err();
        assert_eq!(refused.code(), "GRT-E010");
        assert!(
            refused.to_string().contains("refusé par le core"),
            "{refused}"
        );
    });
}

#[test]
fn lower_policy_version_is_refused() {
    let dir = dir("policy");
    let state = state(&dir, "keyset.version", allow(&["10.0.0.0/8"]));
    state.apply_policy(2, &allow(&["10.20.0.0/16"])).unwrap();
    let refused = state.apply_policy(1, &allow(&["10.0.0.0/8"])).unwrap_err();
    assert_eq!(refused, TunnelError::PolicyRollback { got: 1, current: 2 });
    assert_eq!(state.versions().policy, Some(2));
}

/// The key set version never goes back, even across a restart of the agent:
/// first through the state API, then with pushes from the core to a new
/// agent reading the same state file.
#[test]
fn keyset_version_never_goes_back_across_a_restart() {
    run(async {
        let core = TestCore::start(Limits::default(), Behaviour::default()).unwrap();
        let dir = dir("keyset");
        let keys = vec![core.grant_key()];
        {
            let gateway = agent(&core, &dir, "a", "keyset.version", allow(&["10.0.0.0/8"])).await;
            core.push(&CoreMessage::KeySet {
                version: 5,
                keys: keys.clone(),
            })
            .await;
            assert!(until(&gateway, |g| g.state().versions().keyset == Some(5)).await);
            core.push(&CoreMessage::KeySet {
                version: 3,
                keys: keys.clone(),
            })
            .await;
            processed(&core, &gateway, 1).await;
            assert_eq!(gateway.state().versions().keyset, Some(5));
        }
        assert_eq!(
            std::fs::read_to_string(dir.0.join("keyset.version")).unwrap(),
            "5\n"
        );

        // Restart: a new agent reads the state file.
        let restarted = agent(&core, &dir, "b", "keyset.version", allow(&["10.0.0.0/8"])).await;
        let versions = restarted.state().versions();
        assert_eq!(versions.keyset, None, "no keys before the core pushes");
        assert_eq!(versions.keyset_floor, Some(5));
        core.push(&CoreMessage::KeySet {
            version: 3,
            keys: keys.clone(),
        })
        .await;
        processed(&core, &restarted, 1).await;
        assert_eq!(
            restarted.state().versions().keyset,
            None,
            "version 3 refused"
        );
        assert_eq!(
            restarted.state().apply_keyset(4, &keys).unwrap_err(),
            TunnelError::KeySetRollback { got: 4, current: 5 }
        );
        // The same version as before the restart is accepted again.
        core.push(&CoreMessage::KeySet { version: 5, keys }).await;
        assert!(until(&restarted, |g| g.state().versions().keyset == Some(5)).await);
    });
}

#[test]
fn unreadable_keyset_state_refuses_to_open() {
    let dir = dir("unreadable");
    std::fs::write(dir.0.join("keyset.version"), "not a version").unwrap();
    let opened = GatewayState::open(GatewayParams {
        gateway_group: group(),
        mode: Mode::Production,
        local_policy: PolicySpec::default(),
        infrastructure: Arc::new(Mutex::new(Vec::new())),
        local_addresses: SharedLocalAddresses::new(LocalAddresses::from_addrs([])),
        keyset_state: dir.0.join("keyset.version"),
        write_private: |path, bytes| private_file::create(path, bytes, Reader::CurrentProcess),
        grant_policy: ostena_grant::Policy::default(),
    });
    assert_eq!(opened.unwrap_err().code(), "TUN-E015");
}

#[test]
fn policy_of_another_group_is_refused() {
    let dir = dir("other");
    let state = state(&dir, "keyset.version", allow(&["10.0.0.0/8"]));
    let mut other = allow(&["10.0.0.0/8"]);
    other.gateway_group = "00000000-0000-0000-0000-000000000001".into();
    assert_eq!(
        state.apply_policy(1, &other).unwrap_err().code(),
        "TUN-E028"
    );
    assert_eq!(state.versions().policy, None);
}
