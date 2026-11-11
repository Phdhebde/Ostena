use std::collections::HashMap;
use std::pin::pin;
use std::sync::atomic::AtomicUsize;
use std::task::{Context, Poll, Waker};

use ostena_common::config::Mode;

use super::*;
use crate::error::Code;
use crate::floor::FloorCause;
use crate::local::LocalAddresses;
use crate::policy::{AllowRuleSpec, PolicySpec};

/// Polls until ready, parking briefly: enough for the resolver threads.
fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = future.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Answers from a table and counts calls.
#[derive(Default)]
struct FakeResolver {
    answers: HashMap<String, Result<Vec<IpAddr>, ResolveError>>,
    calls: AtomicUsize,
}

impl FakeResolver {
    fn with(mut self, name: &str, ips: &[&str]) -> Self {
        self.answers.insert(
            name.into(),
            Ok(ips.iter().map(|s| s.parse().unwrap()).collect()),
        );
        self
    }
}

impl Resolver for FakeResolver {
    fn resolve(
        &self,
        name: &Hostname,
    ) -> impl Future<Output = Result<Vec<IpAddr>, ResolveError>> + Send {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let answer = self
            .answers
            .get(name.as_str())
            .cloned()
            .unwrap_or_else(|| Err(ResolveError("NXDOMAIN".into())));
        std::future::ready(answer)
    }
}

fn scope(resolver: FakeResolver, short: bool, mode: Mode) -> Scope<FakeResolver> {
    let spec = PolicySpec {
        gateway_group: "dc-paris".into(),
        allow: vec![AllowRuleSpec {
            label: None,
            networks: vec!["10.0.0.0/8".into(), "2001:db8::/32".into()],
            ports: vec!["22".into(), "3389".into()],
        }],
        allow_short_names: short,
        short_names_justification: Some("test".into()),
        ..PolicySpec::default()
    };
    let policy = Arc::new(CompiledPolicy::compile(&spec, mode).unwrap());
    let local =
        SharedLocalAddresses::new(LocalAddresses::from_addrs(["10.0.0.2".parse().unwrap()]));
    Scope::new(policy, local, resolver)
}

#[test]
fn name_pins_every_verified_address_in_order() {
    let r = FakeResolver::default().with(
        "srv.corp.example",
        &["2001:db8::10", "10.1.2.3", "10.1.2.3"],
    );
    let s = scope(r, false, Mode::Production);
    let pinned = block_on(s.pin("SRV.corp.example.", 3389)).unwrap();
    let addrs: Vec<String> = pinned.addrs().iter().map(ToString::to_string).collect();
    assert_eq!(addrs, ["[2001:db8::10]:3389", "10.1.2.3:3389"]);
    assert_eq!(
        pinned.name().map(Hostname::as_str),
        Some("srv.corp.example")
    );
    assert_eq!(s.resolver.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn ip_literal_is_not_resolved() {
    let s = scope(FakeResolver::default(), false, Mode::Production);
    let pinned = block_on(s.pin("10.9.9.9", 22)).unwrap();
    assert_eq!(pinned.addrs(), [SocketAddr::from(([10, 9, 9, 9], 22))]);
    assert_eq!(pinned.name(), None);
    assert_eq!(s.resolver.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn one_bad_address_refuses_the_whole_name() {
    // DNS rebinding style answer: one internal-looking, one metadata address.
    let r = FakeResolver::default().with("evil.example", &["10.1.2.3", "169.254.169.254"]);
    let s = scope(r, false, Mode::Production);
    let err = block_on(s.pin("evil.example", 22)).unwrap_err();
    assert_eq!(err.code(), Code::ResolvedAddressRefused);
    let ScopeError::Refused { refusal, rule, .. } = &err else {
        panic!("expected a refusal: {err}");
    };
    assert_eq!(
        refusal.rule,
        crate::error::Rule::Floor(FloorCause::CloudMetadata)
    );
    assert_eq!(refusal.code, Code::Floor);
    assert!(rule.contains("métadonnées"));
}

#[test]
fn gateway_own_address_is_refused() {
    let s = scope(FakeResolver::default(), false, Mode::Production);
    let err = block_on(s.pin("10.0.0.2", 22)).unwrap_err();
    assert_eq!(err.code(), Code::Floor);
}

#[test]
fn e014_short_names() {
    let r = FakeResolver::default().with("srv01", &["10.1.2.3"]);
    let s = scope(r, false, Mode::Production);
    assert_eq!(
        block_on(s.pin("srv01", 22)).unwrap_err().code(),
        Code::ShortName
    );
    assert_eq!(
        s.resolver.calls.load(Ordering::SeqCst),
        0,
        "refused before resolution"
    );

    let r = FakeResolver::default().with("srv01", &["10.1.2.3"]);
    let allowed = scope(r, true, Mode::Production);
    assert!(block_on(allowed.pin("srv01", 22)).is_ok());
}

#[test]
fn e010_resolution_failures() {
    let mut r = FakeResolver::default().with("empty.example", &[]);
    let many: Vec<String> = (0..=MAX_ADDRESSES).map(|i| format!("10.0.1.{i}")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    r = r.with("many.example", &many);
    let s = scope(r, false, Mode::Production);
    for host in ["nx.example", "empty.example", "many.example"] {
        assert_eq!(
            block_on(s.pin(host, 22)).unwrap_err().code(),
            Code::Resolution,
            "{host}"
        );
    }
}

#[test]
fn parse_errors_keep_their_code() {
    let s = scope(FakeResolver::default(), false, Mode::Production);
    for (host, code) in [
        ("0x7f.1", Code::AmbiguousNumeric),
        ("bücher.example", Code::NonAscii),
        ("localhost", Code::ReservedName),
        ("fe80::1%eth0", Code::ZoneId),
        ("a_b.example", Code::InvalidTarget),
    ] {
        assert_eq!(
            block_on(s.pin(host, 22)).unwrap_err().code(),
            code,
            "{host}"
        );
    }
}

#[test]
fn system_resolver_bounds_concurrency() {
    let r = SystemResolver::new(Duration::from_secs(5), 1);
    r.in_flight.store(1, Ordering::SeqCst);
    let name = match crate::target::parse_host("example.invalid").unwrap() {
        Host::Name(n) => n,
        Host::Ip(_) => unreachable!(),
    };
    let err = block_on(r.resolve(&name)).unwrap_err();
    assert!(err.0.contains("simultanées"));
}

#[test]
fn system_resolver_reports_unknown_names() {
    let r = SystemResolver::new(Duration::from_secs(10), 4);
    // RFC 6761: `.invalid` never resolves.
    let Host::Name(name) = crate::target::parse_host("ostena-test.invalid").unwrap() else {
        unreachable!()
    };
    assert!(block_on(r.resolve(&name)).is_err());
}
