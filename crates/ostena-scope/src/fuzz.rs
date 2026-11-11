//! Entry points shared by the cargo-fuzz targets (`fuzz/`) and the stable
//! tests that replay their corpus. Not part of the API.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::OnceLock;

use ostena_common::config::Mode;

use crate::local::LocalAddresses;
use crate::policy::{
    AllowRuleSpec, CompiledPolicy, DenyRuleSpec, FloorExceptionSpec, InfrastructureRole,
    InfrastructureSpec, PolicySpec,
};
use crate::target::{Host, Target, parse_host};

/// Allows everything, so that only the floor and deny rules refuse.
fn wide_policy() -> Option<&'static CompiledPolicy> {
    static POLICY: OnceLock<Option<CompiledPolicy>> = OnceLock::new();
    POLICY
        .get_or_init(|| {
            let spec = PolicySpec {
                gateway_group: "fuzz".into(),
                allow: vec![AllowRuleSpec {
                    label: None,
                    networks: vec!["0.0.0.0/0".into(), "::/0".into()],
                    ports: vec!["1-65535".into()],
                }],
                deny: vec![DenyRuleSpec {
                    label: None,
                    networks: vec!["10.66.0.0/16".into()],
                }],
                ..PolicySpec::default()
            };
            CompiledPolicy::compile(&spec, Mode::Production).ok()
        })
        .as_ref()
}

/// Target parsing and decision on arbitrary input. Must never panic.
pub fn target(data: &[u8]) {
    let local = LocalAddresses::default();
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = parse_host(text);
        if let Ok(t) = Target::parse(text)
            && let Host::Ip(ip) = t.host()
            && let Some(p) = wide_policy()
        {
            let _ = p.check(SocketAddr::new(*ip, t.port()), &local);
        }
    }
    // Raw bytes as an IPv6 address and port: exercises normalisation.
    if data.len() >= 18 {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&data[..16]);
        let port = u16::from_be_bytes([data[16], data[17]]);
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port);
        if let Some(p) = wide_policy() {
            let _ = p.check(addr, &local);
        }
    }
}

/// Policy parsing and compilation from a line format. Must never panic.
///
/// Lines: `allow <net,...> <port,...>`, `deny <net,...>`, `infra <net,...>`,
/// `except <net> <reason>`, `short [justification]`, `check <ip> <port>`.
pub fn policy(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut spec = PolicySpec {
        gateway_group: "fuzz".into(),
        ..PolicySpec::default()
    };
    let mut checks = Vec::new();
    for line in text.lines().take(256) {
        let mut words = line.split_whitespace();
        let list = |w: Option<&str>| -> Vec<String> {
            w.map(|s| s.split(',').map(str::to_owned).collect())
                .unwrap_or_default()
        };
        match words.next() {
            Some("allow") => spec.allow.push(AllowRuleSpec {
                label: None,
                networks: list(words.next()),
                ports: list(words.next()),
            }),
            Some("deny") => spec.deny.push(DenyRuleSpec {
                label: None,
                networks: list(words.next()),
            }),
            Some("infra") => spec.infrastructure.push(InfrastructureSpec {
                role: InfrastructureRole::Core,
                networks: list(words.next()),
            }),
            Some("except") => spec.floor_exceptions.push(FloorExceptionSpec {
                network: words.next().unwrap_or_default().to_owned(),
                reason: words.collect::<Vec<_>>().join(" "),
            }),
            Some("short") => {
                spec.allow_short_names = true;
                spec.short_names_justification = words.next().map(str::to_owned);
            }
            Some("check") => {
                if let (Some(ip), Some(port)) = (words.next(), words.next())
                    && let (Ok(ip), Ok(port)) = (ip.parse::<IpAddr>(), port.parse::<u16>())
                {
                    checks.push(SocketAddr::new(ip, port));
                }
            }
            _ => {}
        }
    }
    let local = LocalAddresses::default();
    for mode in [Mode::Production, Mode::Development] {
        if let Ok(policy) = CompiledPolicy::compile(&spec, mode) {
            for addr in &checks {
                let _ = policy.check(*addr, &local);
            }
        }
    }
}
