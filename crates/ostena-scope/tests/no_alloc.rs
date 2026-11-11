//! Proves that a decision on a compiled policy does not allocate (dhat).
//! Alone in its file: dhat counts every allocation of the process.

use std::hint::black_box;
use std::net::SocketAddr;

use ostena_common::config::Mode;
use ostena_scope::{
    AllowRuleSpec, CompiledPolicy, DenyRuleSpec, InfrastructureRole, InfrastructureSpec,
    LocalAddresses, PolicySpec,
};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[test]
fn decision_does_not_allocate() {
    let spec = PolicySpec {
        gateway_group: "bench".into(),
        allow: (0..200)
            .map(|i| AllowRuleSpec {
                label: None,
                networks: vec![format!("10.{i}.0.0/16"), format!("2001:db8:{i:x}::/48")],
                ports: vec!["22".into(), "3389".into(), "5900-5910".into()],
            })
            .collect(),
        deny: vec![DenyRuleSpec {
            label: Some("x".into()),
            networks: vec!["10.5.5.0/24".into()],
        }],
        infrastructure: vec![InfrastructureSpec {
            role: InfrastructureRole::Core,
            networks: vec!["10.7.0.1".into()],
        }],
        ..PolicySpec::default()
    };
    let policy = CompiledPolicy::compile(&spec, Mode::Production).expect("valid policy");
    let local = LocalAddresses::from_addrs(["10.9.0.1".parse().expect("ip")]);
    let addrs: Vec<SocketAddr> = [
        "10.3.4.5:22",           // allowed
        "10.3.4.5:80",           // port refused
        "10.5.5.5:22",           // denied
        "10.7.0.1:22",           // infrastructure
        "10.9.0.1:22",           // gateway address
        "172.16.0.1:22",         // default deny
        "169.254.169.254:80",    // floor
        "[::ffff:10.3.4.5]:22",  // normalised
        "[2001:db8:10::1]:3389", // IPv6 allowed
        "[2002:7f00:1::1]:22",   // 6to4 floor
    ]
    .iter()
    .map(|s| s.parse().expect("socket address"))
    .collect();

    let _profiler = dhat::Profiler::builder().testing().build();
    let before = dhat::HeapStats::get();
    for _ in 0..1000 {
        for addr in &addrs {
            let _ = black_box(policy.check(black_box(*addr), &local));
        }
    }
    let after = dhat::HeapStats::get();
    dhat::assert_eq!(after.total_blocks, before.total_blocks);
}
