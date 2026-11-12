//! Security events of the enrolment service. Alone in its test binary: a
//! thread-scoped tracing subscriber misses events when other tests log on
//! other threads at the same time (shared interest cache).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside #[test] functions"
)]

use std::time::Duration;

use ostena_crypto::p256::SigningKey;
use ostena_tunnel::enroll::{EnrollParams, enroll};
use ostena_tunnel::testing::{Behaviour, TestCore};
use ostena_tunnel::{Limits, TunnelError, Uuid};

/// Collects the `event` field of every log event.
#[derive(Clone, Default)]
struct Events(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Events {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        struct Visitor(Vec<String>);
        impl tracing::field::Visit for Visitor {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "event" {
                    self.0.push(value.to_owned());
                }
            }
            fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
        }
        let mut visitor = Visitor(Vec::new());
        event.record(&mut visitor);
        self.0.lock().unwrap().extend(visitor.0);
    }
}

#[test]
fn suspicious_attempts_raise_a_security_event() {
    use tracing_subscriber::layer::SubscriberExt;
    let events = Events::default();
    let subscriber = tracing_subscriber::registry().with(events.clone());
    let _guard = tracing::subscriber::set_default(subscriber);
    // One thread: the core tasks log under the subscriber above.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let core = TestCore::start(Limits::default(), Behaviour::default()).unwrap();
            let token = core
                .issue_token(Uuid::from_bytes([1; 16]), Duration::from_secs(3600))
                .unwrap();
            let (key, _) = SigningKey::generate().unwrap();
            let root = core.trust_anchor();
            let refused = enroll(&EnrollParams {
                address: core.enrollment_addr(),
                server_name: "localhost".into(),
                root: &root,
                token: &token,
                gateway_group: Uuid::from_bytes([9; 16]),
                key: &key,
                timeout: Duration::from_secs(5),
            })
            .await;
            assert_eq!(refused.err(), Some(TunnelError::TokenGroup));
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
    let seen = events.0.lock().unwrap().clone();
    assert!(
        seen.iter().any(|e| e == "tunnel.enrollment_suspicious"),
        "{seen:?}"
    );
}
