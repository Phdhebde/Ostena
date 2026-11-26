//! The agent end against the in-process test core, over TLS 1.3 on TCP
//! with the multiplexer (the QUIC fallback, ADR-0008), on 127.0.0.1: the
//! same behaviour as `tests/tunnel.rs` over QUIC, and the same codes, except
//! where only a TLS alert can reach the agent (noted).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside #[test] functions"
)]

use std::future::Future;
use std::time::Duration;

use ostena_crypto::pki::Validity;
use ostena_crypto::tls::{self, testing::Offer, testing::foreign_client_config};
use ostena_tunnel::control::{CoreMessage, GrantKey};
use ostena_tunnel::testing::{Behaviour, TestCore, valid};
use ostena_tunnel::{
    ALPN, AgentConfig, FALLBACK_AFTER, Limits, StreamClass, Transport, TransportMode, TunnelError,
    Uuid, connect, connect_with,
};

const DAY: u64 = 86_400;

fn group() -> Uuid {
    Uuid::parse("2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6").unwrap()
}

fn fast() -> Limits {
    Limits {
        max_sessions: 2,
        keep_alive: Duration::from_millis(100),
        idle_timeout: Duration::from_secs(1),
        heartbeat_interval: Duration::from_millis(100),
        heartbeat_timeout: Duration::from_millis(400),
        handshake_timeout: Duration::from_secs(5),
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

/// The agent configuration of `core`, over TCP.
fn tcp_config(
    core: &TestCore,
    id: &tls::Identity,
    group: Uuid,
    limits: Limits,
) -> Result<AgentConfig, TunnelError> {
    let mut config = core.agent_config(id, group, limits)?;
    config.transport = Transport::Tcp;
    Ok(config)
}

fn core() -> TestCore {
    TestCore::start(fast(), Behaviour::default()).unwrap()
}

/// Connects with `config` and returns the agent error and the core error.
async fn refused(core: &TestCore, config: AgentConfig) -> (TunnelError, Option<TunnelError>) {
    let agent = connect(&config).await.expect_err("connection must fail");
    (agent, core.wait_error(Duration::from_secs(3)).await)
}

#[test]
fn connects_over_tcp_and_keeps_the_heartbeat() {
    run(async {
        let core = core();
        let id = core.agent_identity(group(), valid(), true).unwrap();
        let (tunnel, ack) = connect(&tcp_config(&core, &id, group(), fast()).unwrap())
            .await
            .unwrap();
        assert!(ack.heartbeat <= fast().heartbeat_interval);
        // Several heartbeat timeouts later, the tunnel is still up.
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(!tunnel.is_closed());
        assert_eq!(core.tunnels(), 1);
        assert_eq!(tunnel.transport(), Transport::Tcp);
        assert!(tunnel.rtt() > Duration::ZERO);
    });
}

#[test]
fn channels_echo_with_their_class_priority() {
    run(async {
        let core = core();
        let id = core.agent_identity(group(), valid(), true).unwrap();
        let (tunnel, _) = connect(&tcp_config(&core, &id, group(), fast()).unwrap())
            .await
            .unwrap();
        let session = Uuid::random().unwrap();
        // A transcript stream is kept, not echoed.
        for class in StreamClass::ALL
            .into_iter()
            .filter(|c| *c != StreamClass::Recording)
        {
            let mut ch = tunnel.open_channel(session, class).await.unwrap();
            assert_eq!(ch.send.priority().unwrap(), class.priority());
            ch.send.write_all(b"ping").await.unwrap();
            let mut buf = [0u8; 4];
            ch.recv.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
        }
    });
}

#[test]
fn stream_limit_is_enforced_by_the_peer() {
    run(async {
        let limits = Limits {
            max_sessions: 1,
            ..fast()
        };
        let core = TestCore::start(limits, Behaviour::default()).unwrap();
        let id = core.agent_identity(group(), valid(), true).unwrap();
        let (tunnel, _) = connect(&tcp_config(&core, &id, group(), limits).unwrap())
            .await
            .unwrap();
        // One session: control stream + four channels.
        let session = Uuid::random().unwrap();
        let mut open = Vec::new();
        for class in StreamClass::ALL {
            open.push(tunnel.open_channel(session, class).await.unwrap());
        }
        let extra = tokio::time::timeout(
            Duration::from_millis(500),
            tunnel.open_channel(Uuid::random().unwrap(), StreamClass::Interactive),
        )
        .await;
        assert!(extra.is_err(), "a fifth stream must wait for credit");
    });
}

#[test]
fn loss_of_the_core_is_detected() {
    run(async {
        let core = core();
        let id = core.agent_identity(group(), valid(), true).unwrap();
        let (tunnel, _) = connect(&tcp_config(&core, &id, group(), fast()).unwrap())
            .await
            .unwrap();
        core.stop();
        let why = tokio::time::timeout(Duration::from_secs(5), tunnel.closed())
            .await
            .unwrap();
        assert_eq!(why.code(), "TUN-E013", "{why}");
    });
}

#[test]
fn silent_core_trips_the_heartbeat() {
    run(async {
        let core = TestCore::start(
            fast(),
            Behaviour {
                mute: true,
                ..Behaviour::default()
            },
        )
        .unwrap();
        let id = core.agent_identity(group(), valid(), true).unwrap();
        let (tunnel, _) = connect(&tcp_config(&core, &id, group(), fast()).unwrap())
            .await
            .unwrap();
        let why = tokio::time::timeout(Duration::from_secs(5), tunnel.closed())
            .await
            .unwrap();
        assert_eq!(why, TunnelError::HeartbeatTimeout);
    });
}

#[test]
fn core_certificate_from_an_unknown_ca_is_refused() {
    run(async {
        let core = core();
        let other = TestCore::start(fast(), Behaviour::default()).unwrap();
        let id = core.agent_identity(group(), valid(), true).unwrap();
        let mut config = tcp_config(&core, &id, group(), fast()).unwrap();
        config.tls = tls::client_config(&other.trust_anchor(), Some(&id), &[ALPN]).unwrap();
        let (agent, _) = refused(&core, config).await;
        assert_eq!(agent, TunnelError::UnknownIssuer);
    });
}

#[test]
fn core_certificate_from_the_issuing_ca_is_refused() {
    run(async {
        // The core presents a certificate signed by the online issuing CA,
        // with its chain to the root: what an attacker holding that key
        // could do. Only a certificate signed directly by the root passes.
        let core = TestCore::start(
            fast(),
            Behaviour {
                rogue_server: true,
                ..Behaviour::default()
            },
        )
        .unwrap();
        let id = core.agent_identity(group(), valid(), true).unwrap();
        let (agent, at_core) =
            refused(&core, tcp_config(&core, &id, group(), fast()).unwrap()).await;
        assert_eq!(agent, TunnelError::NotRootIssued);
        // Over TCP the core only receives the alert of the agent: it logs
        // a handshake failure, without the reason QUIC carries.
        assert!(at_core.is_some());
    });
}

#[test]
fn agent_certificate_from_an_unknown_ca_is_refused() {
    run(async {
        let core = core();
        let other = TestCore::start(fast(), Behaviour::default()).unwrap();
        let foreign = other.agent_identity(group(), valid(), true).unwrap();
        let (agent, at_core) =
            refused(&core, tcp_config(&core, &foreign, group(), fast()).unwrap()).await;
        assert_eq!(at_core, Some(TunnelError::UnknownIssuer));
        assert_eq!(agent, TunnelError::UnknownIssuer);
    });
}

#[test]
fn expired_agent_certificate_is_refused() {
    run(async {
        let core = core();
        let expired = Validity {
            not_before: now() - 40 * DAY,
            not_after: now() - DAY,
        };
        let id = core.agent_identity(group(), expired, true).unwrap();
        let (agent, at_core) =
            refused(&core, tcp_config(&core, &id, group(), fast()).unwrap()).await;
        assert_eq!(at_core, Some(TunnelError::CertificateValidity));
        assert_eq!(agent, TunnelError::CertificateValidity);
    });
}

#[test]
fn revoked_agent_certificate_is_refused() {
    run(async {
        let core = core();
        let id = core.agent_identity(group(), valid(), true).unwrap();
        core.revoke(&id);
        let (agent, at_core) =
            refused(&core, tcp_config(&core, &id, group(), fast()).unwrap()).await;
        assert_eq!(at_core, Some(TunnelError::Revoked));
        assert_eq!(agent, TunnelError::Revoked);
    });
}

#[test]
fn agent_unknown_to_the_registry_is_refused() {
    run(async {
        let core = core();
        let id = core.agent_identity(group(), valid(), false).unwrap();
        let (agent, at_core) =
            refused(&core, tcp_config(&core, &id, group(), fast()).unwrap()).await;
        assert_eq!(at_core, Some(TunnelError::UnknownAgent));
        assert_eq!(agent, TunnelError::UnknownAgent);
    });
}

#[test]
fn missing_client_certificate_is_refused() {
    run(async {
        let core = core();
        let id = core.agent_identity(group(), valid(), true).unwrap();
        let mut config = tcp_config(&core, &id, group(), fast()).unwrap();
        config.tls = tls::client_config(&core.trust_anchor(), None, &[ALPN]).unwrap();
        let (agent, at_core) = refused(&core, config).await;
        assert_eq!(at_core, Some(TunnelError::NoClientCertificate));
        assert_eq!(agent, TunnelError::NoClientCertificate);
    });
}

#[test]
fn hello_for_another_group_is_refused() {
    run(async {
        let core = core();
        let id = core.agent_identity(group(), valid(), true).unwrap();
        let other_group = Uuid::from_bytes([9; 16]);
        let (agent, at_core) =
            refused(&core, tcp_config(&core, &id, other_group, fast()).unwrap()).await;
        assert_eq!(at_core.map(|e| e.code()), Some("TUN-E010"));
        assert!(agent.to_string().contains("TUN-E010"), "{agent}");
    });
}

#[test]
fn peer_without_the_hybrid_group_is_refused() {
    run(async {
        for offer in [Offer::X25519, Offer::Secp256r1, Offer::X25519MlKem768] {
            let core = core();
            let id = core.agent_identity(group(), valid(), true).unwrap();
            let mut config = tcp_config(&core, &id, group(), fast()).unwrap();
            config.tls = foreign_client_config(offer, &core.trust_anchor(), &id, &[ALPN]).unwrap();
            let (agent, at_core) = refused(&core, config).await;
            assert_eq!(at_core, Some(TunnelError::NoCommonGroup), "{offer:?}");
            // Over TCP the agent only receives the handshake_failure alert:
            // a negotiation failure (TUN-E002), where QUIC carries the reason.
            assert!(
                matches!(agent, TunnelError::Negotiation(_)),
                "{offer:?} {agent}"
            );
        }
    });
}

#[test]
fn peer_without_the_aes_256_suite_is_refused() {
    run(async {
        let core = core();
        let id = core.agent_identity(group(), valid(), true).unwrap();
        let mut config = tcp_config(&core, &id, group(), fast()).unwrap();
        config.tls =
            foreign_client_config(Offer::Aes128Suite, &core.trust_anchor(), &id, &[ALPN]).unwrap();
        let (agent, at_core) = refused(&core, config).await;
        assert!(
            matches!(at_core, Some(TunnelError::Negotiation(_))),
            "{at_core:?}"
        );
        assert!(matches!(agent, TunnelError::Negotiation(_)), "{agent}");
    });
}

#[test]
fn application_protocol_mismatch_is_refused() {
    run(async {
        let core = core();
        let id = core.agent_identity(group(), valid(), true).unwrap();
        let mut config = tcp_config(&core, &id, group(), fast()).unwrap();
        config.tls =
            tls::client_config(&core.trust_anchor(), Some(&id), &[b"ostena-tunnel/9"]).unwrap();
        let (agent, at_core) = refused(&core, config).await;
        assert_eq!(at_core, Some(TunnelError::ApplicationProtocol));
        assert_eq!(agent, TunnelError::ApplicationProtocol);
    });
}

#[test]
fn core_name_mismatch_is_refused() {
    run(async {
        let core = core();
        let id = core.agent_identity(group(), valid(), true).unwrap();
        let mut config = tcp_config(&core, &id, group(), fast()).unwrap();
        config.server_name = "other.test".into();
        let agent = connect(&config).await.expect_err("connection must fail");
        assert_eq!(agent, TunnelError::NameMismatch);
    });
}

#[test]
fn pushes_reach_the_agent_and_invalid_ones_close_the_tunnel() {
    run(async {
        let core = core();
        let id = core.agent_identity(group(), valid(), true).unwrap();
        let (tunnel, _) = connect(&tcp_config(&core, &id, group(), fast()).unwrap())
            .await
            .unwrap();
        let shutdown = CoreMessage::Shutdown {
            reason: "maintenance".into(),
        };
        core.broadcast(&shutdown).await;
        let got = tokio::time::timeout(Duration::from_secs(2), tunnel.recv())
            .await
            .unwrap();
        assert_eq!(got, Some(shutdown));

        // A key whose kid does not match: untrusted input, refused.
        let bad = CoreMessage::KeySet {
            version: 1,
            keys: vec![GrantKey {
                kid: "0000000000000000".into(),
                public_key: "AA".into(),
                retire_at: None,
            }],
        };
        core.broadcast(&bad).await;
        let why = tokio::time::timeout(Duration::from_secs(2), tunnel.closed())
            .await
            .unwrap();
        assert_eq!(why.code(), "TUN-E010", "{why}");
    });
}

#[test]
fn auto_mode_prefers_quic() {
    run(async {
        let core = core();
        let id = core.agent_identity(group(), valid(), true).unwrap();
        let config = core.agent_config(&id, group(), fast()).unwrap();
        let (tunnel, _) = connect_with(&config, TransportMode::Auto).await.unwrap();
        assert_eq!(tunnel.transport(), Transport::Quic);
    });
}

#[test]
fn auto_mode_falls_back_to_tcp_when_udp_is_blocked() {
    run(async {
        let core = TestCore::start(
            fast(),
            Behaviour {
                udp_blocked: true,
                ..Behaviour::default()
            },
        )
        .unwrap();
        let id = core.agent_identity(group(), valid(), true).unwrap();
        let config = core.agent_config(&id, group(), fast()).unwrap();
        let started = std::time::Instant::now();
        let (tunnel, _) = connect_with(&config, TransportMode::Auto).await.unwrap();
        assert_eq!(tunnel.transport(), Transport::Tcp);
        // TCP is dialled after one second without an answer from QUIC.
        let took = started.elapsed();
        assert!(
            took >= FALLBACK_AFTER && took < FALLBACK_AFTER * 3,
            "{took:?}"
        );
        // Forced QUIC does not get through.
        let quic = connect_with(&config, TransportMode::Quic).await;
        assert!(quic.is_err());
    });
}

#[test]
fn auto_mode_does_not_retry_a_refusal_over_tcp() {
    run(async {
        let core = core();
        let id = core.agent_identity(group(), valid(), true).unwrap();
        core.revoke(&id);
        let config = core.agent_config(&id, group(), fast()).unwrap();
        let e = connect_with(&config, TransportMode::Auto)
            .await
            .expect_err("revoked");
        assert_eq!(e, TunnelError::Revoked);
        assert_eq!(
            core.wait_error(Duration::from_secs(1)).await,
            Some(TunnelError::Revoked)
        );
        // Only the QUIC attempt reached the core.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(core.errors().len(), 1, "{:?}", core.errors());
    });
}
