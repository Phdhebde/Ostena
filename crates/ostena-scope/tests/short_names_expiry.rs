//! The short names waiver expires at midnight UTC on its last day, without a
//! restart. Alone in its process: it inspects the emitted events, and the
//! `tracing` callsite cache is shared between test threads.

#![allow(clippy::unwrap_used, reason = "test helpers outside #[test] functions")]

use std::future::Future;
use std::io::Write;
use std::net::IpAddr;
use std::pin::pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use ostena_common::config::Mode;
use ostena_scope::{
    AllowRuleSpec, Clock, Code, CompiledPolicy, Hostname, LocalAddresses, PolicySpec, ResolveError,
    Resolver, Scope, SharedLocalAddresses,
};
use tracing_subscriber::layer::SubscriberExt;

/// 2026-11-11T12:00:00Z, and the following midnight UTC.
const NOW: u64 = 1_794_398_400;
const MIDNIGHT: u64 = 1_794_441_600;

struct OneAddress;

impl Resolver for OneAddress {
    fn resolve(
        &self,
        _: &Hostname,
    ) -> impl Future<Output = Result<Vec<IpAddr>, ResolveError>> + Send {
        std::future::ready(Ok(vec!["10.1.2.3".parse().unwrap()]))
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = future.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Write for Buffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn waiver_expires_at_midnight_without_restart() {
    let spec = PolicySpec {
        gateway_group: "dc-paris".into(),
        allow: vec![AllowRuleSpec {
            label: None,
            networks: vec!["10.0.0.0/8".into()],
            ports: vec!["22".into()],
        }],
        allow_short_names: true,
        short_names_justification: Some("parc NetBIOS historique, ticket SEC-42".into()),
        short_names_expires: Some("2026-11-11".into()),
        ..PolicySpec::default()
    };
    let policy = Arc::new(CompiledPolicy::compile_at(&spec, Mode::Production, NOW).unwrap());
    let now = Arc::new(AtomicU64::new(MIDNIGHT - 1));
    let clock = {
        let now = Arc::clone(&now);
        Clock::from_fn(move || now.load(Ordering::SeqCst))
    };
    let scope = Scope::new(
        policy,
        SharedLocalAddresses::new(LocalAddresses::default()),
        OneAddress,
    )
    .with_clock(clock);

    let buffer = Buffer::default();
    let subscriber = tracing_subscriber::registry::Registry::default().with(
        ostena_common::logging::JsonLayer::new(vec![Box::new(buffer.clone())]),
    );
    tracing::subscriber::with_default(subscriber, || {
        // 23:59:59 UTC on the last day: still allowed.
        assert!(block_on(scope.pin("srv01", 22)).is_ok());
        // Midnight UTC: the same running scope now refuses.
        now.store(MIDNIGHT, Ordering::SeqCst);
        for _ in 0..2 {
            let err = block_on(scope.pin("srv01", 22)).unwrap_err();
            assert_eq!(err.code(), Code::ShortNamesExpired);
            assert!(err.to_string().contains("2026-11-11"), "{err}");
        }
        // Full names and addresses are not affected.
        assert!(block_on(scope.pin("10.1.2.3", 22)).is_ok());
    });
    let logs = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        logs.matches("\"scope.weakening_expired\"").count(),
        1,
        "{logs}"
    );
    assert_eq!(logs.matches("\"SCP-E018\"").count(), 2, "{logs}");
    assert_eq!(
        logs.matches("\"scope.short_name_used\"").count(),
        1,
        "{logs}"
    );
}
