//! Micro-benchmark of the scope decision. Prints nanoseconds per decision;
//! not a gate yet (ADR-0005: the 10 % rule needs a stable reference machine).
//!
//! `cargo bench -p ostena-scope`

#![allow(
    clippy::expect_used,
    clippy::print_stdout,
    reason = "benchmark binary: prints its results, fixed inputs"
)]

use std::hint::black_box;
use std::net::SocketAddr;
use std::time::Instant;

use ostena_common::config::Mode;
use ostena_scope::{AllowRuleSpec, CompiledPolicy, DenyRuleSpec, LocalAddresses, PolicySpec};

const ITERATIONS: u32 = 2_000_000;

fn main() {
    // 1 000 allow rules (500 IPv4, 500 IPv6) and 100 deny rules.
    let mut allow = Vec::new();
    for i in 0..500u32 {
        allow.push(AllowRuleSpec {
            label: None,
            networks: vec![format!("10.{}.{}.0/24", i / 256, i % 256)],
            ports: vec![
                "22".into(),
                "3389".into(),
                format!("{}-{}", 5000 + i, 5010 + i),
            ],
        });
        allow.push(AllowRuleSpec {
            label: None,
            networks: vec![format!("2001:db8:{i:x}::/48")],
            ports: vec!["22".into(), "443".into()],
        });
    }
    let deny = (0..100u32)
        .map(|i| DenyRuleSpec {
            label: None,
            networks: vec![format!("10.{}.{}.128/25", i / 256, i % 256)],
        })
        .collect();
    let spec = PolicySpec {
        gateway_group: "bench".into(),
        allow,
        deny,
        ..PolicySpec::default()
    };
    let start = Instant::now();
    let policy = CompiledPolicy::compile(&spec, Mode::Production).expect("valid policy");
    let compile = start.elapsed();
    let local = LocalAddresses::from_addrs(["10.255.0.1".parse().expect("ip")]);

    println!("compilation (1 000 allow + 100 deny): {compile:?}");
    for (label, addr) in [
        ("allowed IPv4", "10.1.20.5:3389"),
        ("allowed IPv6", "[2001:db8:1f3::9]:443"),
        ("denied", "10.0.50.200:22"),
        ("port refused", "10.1.20.5:80"),
        ("default deny", "192.168.1.1:22"),
        ("floor (metadata)", "169.254.169.254:80"),
        ("hidden IPv4", "[::ffff:10.1.20.5]:3389"),
    ] {
        let addr: SocketAddr = addr.parse().expect("socket address");
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let _ = black_box(policy.check(black_box(addr), &local));
        }
        let ns = start.elapsed().as_secs_f64() * 1e9 / f64::from(ITERATIONS);
        println!("{label:<18} {ns:>7.1} ns/decision");
    }
}
