//! Enrolment, renewal and revocation against the in-process test core.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside #[test] functions"
)]

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ostena_common::secret::SecretBytes;
use ostena_crypto::p256::SigningKey;
use ostena_crypto::pki::pem_private_key;
use ostena_crypto::tls::{self, Identity};
use ostena_tunnel::control::CoreMessage;
use ostena_tunnel::enroll::{
    ENROLL_ALPN, EnrollParams, EnrollServer, Enrolled, EnrollmentToken, enroll,
    testing::raw_request,
};
use ostena_tunnel::link::Clock;
use ostena_tunnel::testing::{Behaviour, TestCore};
use ostena_tunnel::{ALPN, Limits, TunnelError, Uuid, connect, renewal};

fn group() -> Uuid {
    Uuid::parse("2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6").unwrap()
}

fn fast() -> Limits {
    Limits {
        keep_alive: Duration::from_millis(100),
        idle_timeout: Duration::from_secs(1),
        heartbeat_interval: Duration::from_millis(100),
        heartbeat_timeout: Duration::from_millis(400),
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

const HOUR: Duration = Duration::from_secs(3600);

async fn enrol_with(
    core: &TestCore,
    token: &EnrollmentToken,
    group: Uuid,
    timeout: Duration,
) -> Result<(Enrolled, Identity), TunnelError> {
    let (key, pkcs8) = SigningKey::generate().unwrap();
    let root = core.trust_anchor();
    let enrolled = enroll(&EnrollParams {
        address: core.enrollment_addr(),
        server_name: "localhost".into(),
        root: &root,
        token,
        gateway_group: group,
        key: &key,
        timeout,
    })
    .await?;
    let identity =
        Identity::from_pem(enrolled.certificate.as_bytes(), &pem_private_key(&pkcs8)).unwrap();
    Ok((enrolled, identity))
}

async fn enrol(
    core: &TestCore,
    token: &EnrollmentToken,
) -> Result<(Enrolled, Identity), TunnelError> {
    enrol_with(core, token, group(), Duration::from_secs(5)).await
}

async fn eventually(mut check: impl FnMut() -> bool) -> bool {
    for _ in 0..50 {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[test]
fn enrolled_agent_opens_a_tunnel_and_the_listener_closes() {
    run(async {
        let core = TestCore::start(fast(), Behaviour::default()).unwrap();
        assert!(!core.enrollment_open(), "closed by default");
        let token = core.issue_token(group(), HOUR).await.unwrap();
        assert!(core.enrollment_open());
        let (enrolled, identity) = enrol(&core, &token).await.unwrap();
        assert!(enrolled.not_after > enrolled.not_before);
        // The only token is spent: the listener closes.
        assert!(eventually(|| !core.enrollment_open()).await);
        let (tunnel, _) = connect(&core.agent_config(&identity, group(), fast()).unwrap())
            .await
            .unwrap();
        assert!(!tunnel.is_closed());
        // A new attempt finds nobody listening.
        let other = EnrollmentToken::generate().unwrap();
        let closed = enrol_with(&core, &other, group(), Duration::from_secs(1)).await;
        assert!(
            matches!(closed, Err(TunnelError::ConnectionLost(_))),
            "{:?}",
            closed.err()
        );
    });
}

#[test]
fn replayed_token_is_refused() {
    run(async {
        let core = TestCore::start(fast(), Behaviour::default()).unwrap();
        let token = core.issue_token(group(), HOUR).await.unwrap();
        let _keep_open = core.issue_token(group(), HOUR).await.unwrap();
        enrol(&core, &token).await.unwrap();
        assert_eq!(
            enrol(&core, &token).await.err(),
            Some(TunnelError::TokenUsed)
        );
    });
}

#[test]
fn expired_token_is_refused() {
    run(async {
        let core = TestCore::start(fast(), Behaviour::default()).unwrap();
        let token = core
            .issue_token(group(), Duration::from_secs(1))
            .await
            .unwrap();
        let _keep_open = core.issue_token(group(), HOUR).await.unwrap();
        tokio::time::sleep(Duration::from_millis(2100)).await;
        assert_eq!(
            enrol(&core, &token).await.err(),
            Some(TunnelError::TokenExpired)
        );
    });
}

#[test]
fn token_of_another_group_is_refused_and_not_spent() {
    run(async {
        let core = TestCore::start(fast(), Behaviour::default()).unwrap();
        let token = core.issue_token(group(), HOUR).await.unwrap();
        let other = Uuid::from_bytes([9; 16]);
        assert_eq!(
            enrol_with(&core, &token, other, Duration::from_secs(5))
                .await
                .err(),
            Some(TunnelError::TokenGroup)
        );
        // A configuration mistake does not burn the token.
        assert!(enrol(&core, &token).await.is_ok());
    });
}

#[test]
fn wrong_token_secret_is_refused() {
    run(async {
        let core = TestCore::start(fast(), Behaviour::default()).unwrap();
        let token = core.issue_token(group(), HOUR).await.unwrap();
        // SECRET-EXPOSURE: test only, forges a token with the same id.
        #[expect(clippy::disallowed_methods)]
        let text = String::from_utf8(token.to_text().expose_secret().to_vec()).unwrap();
        let (head, _) = text.rsplit_once('.').unwrap();
        let forged = format!("{head}.{}", "A".repeat(43));
        let forged = EnrollmentToken::parse(&SecretBytes::from(forged.into_bytes())).unwrap();
        assert_eq!(
            enrol(&core, &forged).await.err(),
            Some(TunnelError::TokenUnknown)
        );
        // The real token still works.
        assert!(enrol(&core, &token).await.is_ok());
    });
}

/// A wall clock the test sets by hand.
#[derive(Debug)]
struct ManualClock(AtomicU64);

impl Clock for ManualClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// One thread, Tokio time paused: tasks run only when the test waits, and
/// sleeps end as soon as everything is idle. No real delay, no margin.
fn run_paused<F: Future<Output = ()>>(test: F) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .unwrap()
        .block_on(test);
}

#[test]
fn listener_closes_when_its_last_token_expires() {
    run_paused(async {
        let clock = Arc::new(ManualClock(AtomicU64::new(1_000)));
        let core = TestCore::start_with_clock(fast(), Behaviour::default(), clock.clone()).unwrap();
        core.issue_token(group(), Duration::from_secs(1))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(core.enrollment_open(), "token still valid");
        clock.0.store(1_001, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(!core.enrollment_open());
    });
}

/// A token can expire within the second it was issued, before the expiry
/// watch first looks: the listener must close anyway.
#[test]
fn listener_closes_when_the_token_expired_before_the_first_look() {
    run_paused(async {
        let clock = Arc::new(ManualClock(AtomicU64::new(1_000)));
        let core = TestCore::start_with_clock(fast(), Behaviour::default(), clock.clone()).unwrap();
        core.issue_token(group(), Duration::from_secs(1))
            .await
            .unwrap();
        // Nothing spawned has run yet (one thread, no await so far).
        clock.0.store(1_001, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(!core.enrollment_open());
    });
}

#[test]
fn listener_serves_the_enrolment_protocol_only() {
    run(async {
        let core = TestCore::start(fast(), Behaviour::default()).unwrap();
        let _token = core.issue_token(group(), HOUR).await.unwrap();
        let root = core.trust_anchor();
        // Another protocol: refused by TLS.
        let tunnel_alpn = raw_request(core.enrollment_addr(), &root, ALPN, b"{}").await;
        assert_eq!(tunnel_alpn.err(), Some(TunnelError::ApplicationProtocol));
        // Anything but a well-formed request: refused.
        for payload in [
            &br#"{"type":"hello","protocol":1}"#[..],
            br#"{"type":"request"}"#,
            b"not json",
            b"",
        ] {
            let answer = raw_request(core.enrollment_addr(), &root, ENROLL_ALPN, payload)
                .await
                .unwrap();
            let EnrollServer::Refused { code, .. } = answer else {
                panic!("refusal expected for {payload:?}, got {answer:?}");
            };
            assert_eq!(code, "TUN-E010", "{payload:?}");
        }
    });
}

#[test]
fn renewal_issues_a_certificate_for_a_new_key() {
    run(async {
        let core = TestCore::start(fast(), Behaviour::default()).unwrap();
        let token = core.issue_token(group(), HOUR).await.unwrap();
        let (_, identity) = enrol(&core, &token).await.unwrap();
        let (tunnel, _) = connect(&core.agent_config(&identity, group(), fast()).unwrap())
            .await
            .unwrap();
        let (new_key, new_pkcs8) = SigningKey::generate().unwrap();
        let current = tls::fingerprint(identity.certificate());
        tunnel
            .send(&renewal::request(&new_key, &current).unwrap())
            .await
            .unwrap();
        let answer = tokio::time::timeout(Duration::from_secs(5), tunnel.recv())
            .await
            .unwrap()
            .unwrap();
        let CoreMessage::Certificate { certificate, .. } = answer else {
            panic!("certificate expected, got {answer:?}");
        };
        let renewed =
            Identity::from_pem(certificate.as_bytes(), &pem_private_key(&new_pkcs8)).unwrap();
        let new_public = new_key.verifying_key().to_bytes();
        assert!(renewed.certificate().windows(65).any(|w| w == new_public));
        // The renewed certificate opens a tunnel; the old one is still valid.
        assert!(
            connect(&core.agent_config(&renewed, group(), fast()).unwrap())
                .await
                .is_ok()
        );
        assert!(
            connect(&core.agent_config(&identity, group(), fast()).unwrap())
                .await
                .is_ok()
        );
    });
}

#[test]
fn revocation_closes_open_tunnels_at_once() {
    run(async {
        let core = TestCore::start(fast(), Behaviour::default()).unwrap();
        let token = core.issue_token(group(), HOUR).await.unwrap();
        let (_, identity) = enrol(&core, &token).await.unwrap();
        let (tunnel, _) = connect(&core.agent_config(&identity, group(), fast()).unwrap())
            .await
            .unwrap();
        core.revoke(&identity);
        let why = tokio::time::timeout(Duration::from_secs(2), tunnel.closed())
            .await
            .unwrap();
        assert_eq!(why, TunnelError::Revoked);
        let again = connect(&core.agent_config(&identity, group(), fast()).unwrap()).await;
        assert_eq!(again.err(), Some(TunnelError::Revoked));
    });
}

#[test]
fn token_is_burned_after_three_failures() {
    run(async {
        let core = TestCore::start(fast(), Behaviour::default()).unwrap();
        let token = core.issue_token(group(), HOUR).await.unwrap();
        let keep_open = core.issue_token(group(), HOUR).await.unwrap();
        let other = Uuid::from_bytes([9; 16]);
        let attempt = |g| enrol_with(&core, &token, g, Duration::from_secs(5));
        assert_eq!(attempt(other).await.err(), Some(TunnelError::TokenGroup));
        assert_eq!(attempt(other).await.err(), Some(TunnelError::TokenGroup));
        assert_eq!(attempt(other).await.err(), Some(TunnelError::TokenBurned));
        // Burned for good, even with the right group.
        assert_eq!(attempt(group()).await.err(), Some(TunnelError::TokenBurned));
        // The other token is untouched.
        assert!(enrol(&core, &keep_open).await.is_ok());
    });
}
