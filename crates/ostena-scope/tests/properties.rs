//! Properties of the scope decision (ADR-0005).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    reason = "test generators and oracle: truncation to IPv4 is intended"
)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use ostena_common::config::Mode;
use ostena_scope::{
    AllowRuleSpec, Code, CompiledPolicy, DenyRuleSpec, InfrastructureRole, InfrastructureSpec,
    LocalAddresses, PolicySpec, Rule, normalize,
};
use proptest::prelude::*;

/// A generated network with its own containment test (independent oracle).
#[derive(Debug, Clone, Copy)]
enum Net {
    V4(u32, u8),
    V6(u128, u8),
}

impl Net {
    fn mask4(len: u8) -> u32 {
        if len == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(len))
        }
    }

    fn mask6(len: u8) -> u128 {
        if len == 0 {
            0
        } else {
            u128::MAX << (128 - u32::from(len))
        }
    }

    fn text(self) -> String {
        match self {
            Self::V4(a, l) => format!("{}/{l}", Ipv4Addr::from(a & Self::mask4(l))),
            Self::V6(a, l) => format!("{}/{l}", Ipv6Addr::from(a & Self::mask6(l))),
        }
    }

    fn contains(self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::V4(a, l), IpAddr::V4(x)) => (u32::from(x) ^ a) & Self::mask4(l) == 0,
            (Self::V6(a, l), IpAddr::V6(x)) => (u128::from(x) ^ a) & Self::mask6(l) == 0,
            _ => false,
        }
    }
}

fn net() -> impl Strategy<Value = Net> {
    prop_oneof![
        3 => (any::<u32>(), 0u8..=32).prop_map(|(a, l)| Net::V4(a, l)),
        // IPv6 under 2001:db8::/32 so as not to fall in normalised ranges.
        1 => (any::<u128>(), 32u8..=128).prop_map(|(a, l)| {
            Net::V6((a & (u128::MAX >> 32)) | (0x2001_0db8u128 << 96), l)
        }),
    ]
}

fn ports() -> impl Strategy<Value = Vec<(u16, u16)>> {
    proptest::collection::vec(
        (1u16..=65535, 0u16..200).prop_map(|(s, w)| (s, s.saturating_add(w))),
        1..3,
    )
}

type GenAllow = (Vec<Net>, Vec<(u16, u16)>);

#[derive(Debug, Clone)]
struct GenPolicy {
    allow: Vec<GenAllow>,
    deny: Vec<Vec<Net>>,
}

fn gen_policy() -> impl Strategy<Value = GenPolicy> {
    (
        proptest::collection::vec((proptest::collection::vec(net(), 1..3), ports()), 0..6),
        proptest::collection::vec(proptest::collection::vec(net(), 1..3), 0..4),
    )
        .prop_map(|(allow, deny)| GenPolicy { allow, deny })
}

impl GenPolicy {
    fn spec(&self) -> PolicySpec {
        PolicySpec {
            gateway_group: "prop".into(),
            allow: self
                .allow
                .iter()
                .map(|(nets, ports)| AllowRuleSpec {
                    label: None,
                    networks: nets.iter().map(|n| n.text()).collect(),
                    ports: ports.iter().map(|(s, e)| format!("{s}-{e}")).collect(),
                })
                .collect(),
            deny: self
                .deny
                .iter()
                .map(|nets| DenyRuleSpec {
                    label: None,
                    networks: nets.iter().map(|n| n.text()).collect(),
                })
                .collect(),
            ..PolicySpec::default()
        }
    }

    fn compile(&self) -> CompiledPolicy {
        CompiledPolicy::compile(&self.spec(), Mode::Production).expect("generated policy is valid")
    }

    /// Naive oracle, ignoring the floor: deny, allow, port.
    fn oracle(&self, ip: IpAddr, port: u16) -> Result<(), (Code, Rule)> {
        if let Some(i) = self
            .deny
            .iter()
            .position(|nets| nets.iter().any(|n| n.contains(ip)))
        {
            return Err((Code::Denied, Rule::Denied(u32::try_from(i).unwrap())));
        }
        let covering: Vec<_> = self
            .allow
            .iter()
            .filter(|(nets, _)| nets.iter().any(|n| n.contains(ip)))
            .collect();
        if covering.is_empty() {
            return Err((Code::NotAllowed, Rule::NoAllowedNetwork));
        }
        if port == 0 {
            return Err((Code::PortNotAllowed, Rule::PortZero));
        }
        if covering
            .iter()
            .any(|(_, ports)| ports.iter().any(|(s, e)| (*s..=*e).contains(&port)))
        {
            Ok(())
        } else {
            Err((Code::PortNotAllowed, Rule::PortNotAllowed))
        }
    }
}

fn floor_cause(ip: IpAddr) -> bool {
    let (ip, _) = normalize(ip);
    let (v4, k) = match ip {
        IpAddr::V4(a) => (true, u128::from(u32::from(a))),
        IpAddr::V6(a) => (false, u128::from(a)),
    };
    ostena_scope::floor::static_ranges().any(|(f4, s, e, _)| f4 == v4 && (s..=e).contains(&k))
}

/// IPv6 forms that hide an IPv4 and are normalised.
fn hidden_forms(v4: Ipv4Addr) -> Vec<Ipv6Addr> {
    let x = u128::from(u32::from(v4));
    vec![
        Ipv6Addr::from(0xffff_0000_0000u128 | x),    // mapped
        Ipv6Addr::from((0xffff_0000u128 << 32) | x), // SIIT
        Ipv6Addr::from((0x0064_ff9b_0000_0000_0000_0000u128 << 32) | x), // NAT64
        Ipv6Addr::from(x),                           // compatible
    ]
}

fn decision(p: &CompiledPolicy, addr: SocketAddr) -> Result<(), (Code, Rule)> {
    p.check(addr, &LocalAddresses::default())
        .map(|_| ())
        .map_err(|r| (r.code, r.rule))
}

/// An address inside a static floor range.
fn floor_address() -> impl Strategy<Value = IpAddr> {
    let ranges: Vec<_> = ostena_scope::floor::static_ranges().collect();
    (proptest::sample::select(ranges), any::<u128>()).prop_map(|((v4, s, e, _), r)| {
        let k = s + if e - s == u128::MAX {
            r
        } else {
            r % (e - s + 1)
        };
        ostena_scope::policy::sample_ip(v4, k)
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// No floor address is ever accepted, whatever the policy, even one that
    /// allows everything; hidden IPv4 forms included.
    #[test]
    fn prop_floor_is_never_accepted(g in gen_policy(), ip in floor_address(), port in 0u16..=65535) {
        let mut spec = g.spec();
        spec.allow.push(AllowRuleSpec {
            label: None,
            networks: vec!["0.0.0.0/0".into(), "::/0".into()],
            ports: vec!["1-65535".into()],
        });
        let p = CompiledPolicy::compile(&spec, Mode::Production).unwrap();
        let r = decision(&p, SocketAddr::new(ip, port));
        prop_assert!(matches!(r, Err((Code::Floor, _))), "{ip} accepted: {r:?}");
        if let IpAddr::V4(v4) = ip {
            for form in hidden_forms(v4) {
                let r = decision(&p, SocketAddr::new(IpAddr::V6(form), port));
                prop_assert!(matches!(r, Err((Code::Floor, _))), "{form} accepted");
            }
        }
    }

    /// Gateway and infrastructure addresses are never accepted either.
    #[test]
    fn prop_gateway_and_infrastructure_are_never_accepted(a in any::<u32>(), b in any::<u32>(), port in 1u16..=65535) {
        let (a, b) = (Ipv4Addr::from(a), Ipv4Addr::from(b));
        prop_assume!(a != b);
        let spec = PolicySpec {
            gateway_group: "prop".into(),
            allow: vec![AllowRuleSpec { label: None, networks: vec!["0.0.0.0/0".into(), "::/0".into()], ports: vec!["1-65535".into()] }],
            infrastructure: vec![InfrastructureSpec { role: InfrastructureRole::Postgresql, networks: vec![b.to_string()] }],
            ..PolicySpec::default()
        };
        let p = CompiledPolicy::compile(&spec, Mode::Production).unwrap();
        let local = LocalAddresses::from_addrs([IpAddr::V4(a)]);
        for form in std::iter::once(IpAddr::V4(a)).chain(hidden_forms(a).into_iter().map(IpAddr::V6)) {
            prop_assert!(p.check(SocketAddr::new(form, port), &local).is_err());
        }
        for form in std::iter::once(IpAddr::V4(b)).chain(hidden_forms(b).into_iter().map(IpAddr::V6)) {
            prop_assert!(p.check(SocketAddr::new(form, port), &local).is_err());
        }
    }

    /// An IPv4 and its hidden IPv6 forms always get the same decision.
    #[test]
    fn prop_ipv4_and_its_ipv6_forms_agree(g in gen_policy(), a in any::<u32>(), port in 0u16..=65535) {
        let p = g.compile();
        let v4 = Ipv4Addr::from(a);
        let expected = decision(&p, SocketAddr::new(IpAddr::V4(v4), port));
        for form in hidden_forms(v4) {
            prop_assert_eq!(decision(&p, SocketAddr::new(IpAddr::V6(form), port)), expected, "{}", form);
        }
    }

    /// The compiled policy decides like the naive oracle, outside the floor;
    /// in particular a denied address is never accepted.
    #[test]
    fn prop_compiled_matches_oracle(g in gen_policy(), pick in any::<prop::sample::Index>(), r in any::<u128>(), port in 0u16..=65535) {
        let p = g.compile();
        // Bias towards addresses inside generated networks.
        let nets: Vec<Net> = g.allow.iter().flat_map(|(n, _)| n.clone()).chain(g.deny.iter().flatten().copied()).collect();
        let ip = if nets.is_empty() {
            IpAddr::V4(Ipv4Addr::from(r as u32))
        } else {
            match *pick.get(&nets) {
                Net::V4(a, l) => IpAddr::V4(Ipv4Addr::from((a & Net::mask4(l)) | (r as u32 & !Net::mask4(l)))),
                Net::V6(a, l) => IpAddr::V6(Ipv6Addr::from((a & Net::mask6(l)) | (r & !Net::mask6(l)))),
            }
        };
        prop_assume!(!floor_cause(ip));
        prop_assert_eq!(decision(&p, SocketAddr::new(ip, port)), g.oracle(ip, port));
    }
}
