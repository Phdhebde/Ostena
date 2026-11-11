use std::net::SocketAddr;

use super::*;

fn allow(networks: &[&str], ports: &[&str]) -> AllowRuleSpec {
    AllowRuleSpec {
        label: None,
        networks: networks.iter().map(|s| (*s).to_owned()).collect(),
        ports: ports.iter().map(|s| (*s).to_owned()).collect(),
    }
}

fn deny(label: &str, networks: &[&str]) -> DenyRuleSpec {
    DenyRuleSpec {
        label: Some(label.to_owned()),
        networks: networks.iter().map(|s| (*s).to_owned()).collect(),
    }
}

fn spec() -> PolicySpec {
    PolicySpec {
        gateway_group: "dc-paris".into(),
        allow: vec![
            allow(&["10.1.0.0/16"], &["22"]),
            allow(&["10.2.0.0/16", "2001:db8:2::/48"], &["3389", "5900-5910"]),
        ],
        deny: vec![deny("sauvegardes", &["10.1.99.0/24"])],
        infrastructure: vec![InfrastructureSpec {
            role: InfrastructureRole::Core,
            networks: vec!["10.2.0.10".into()],
        }],
        ..PolicySpec::default()
    }
}

fn compiled() -> CompiledPolicy {
    CompiledPolicy::compile(&spec(), Mode::Production).unwrap()
}

fn sa(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn none() -> LocalAddresses {
    LocalAddresses::default()
}

fn refusal(p: &CompiledPolicy, addr: &str) -> (Code, Rule) {
    let r = p.check(sa(addr), &none()).unwrap_err();
    (r.code, r.rule)
}

#[test]
fn allowed_per_rule_ports() {
    let p = compiled();
    assert!(p.check(sa("10.1.2.3:22"), &none()).is_ok());
    assert!(p.check(sa("10.2.2.3:3389"), &none()).is_ok());
    assert!(p.check(sa("10.2.2.3:5905"), &none()).is_ok());
    assert!(p.check(sa("[2001:db8:2::5]:3389"), &none()).is_ok());
    // Ports are per rule: 3389 is not open on 10.1/16.
    assert_eq!(
        refusal(&p, "10.1.2.3:3389"),
        (Code::PortNotAllowed, Rule::PortNotAllowed)
    );
    assert_eq!(
        refusal(&p, "10.2.2.3:22"),
        (Code::PortNotAllowed, Rule::PortNotAllowed)
    );
    assert_eq!(
        refusal(&p, "10.2.2.3:5911"),
        (Code::PortNotAllowed, Rule::PortNotAllowed)
    );
}

#[test]
fn overlapping_rules_union_their_ports() {
    let mut s = spec();
    s.allow.push(allow(&["10.1.5.0/24"], &["443"]));
    let p = CompiledPolicy::compile(&s, Mode::Production).unwrap();
    assert!(p.check(sa("10.1.5.1:22"), &none()).is_ok());
    assert!(p.check(sa("10.1.5.1:443"), &none()).is_ok());
    assert_eq!(refusal(&p, "10.1.6.1:443").0, Code::PortNotAllowed);
}

#[test]
fn e006_port_zero() {
    assert_eq!(
        refusal(&compiled(), "10.1.2.3:0"),
        (Code::PortNotAllowed, Rule::PortZero)
    );
}

#[test]
fn e007_floor_wins_over_allow() {
    let mut s = spec();
    s.allow.push(allow(&["0.0.0.0/0", "::/0"], &["1-65535"]));
    let p = CompiledPolicy::compile(&s, Mode::Production).unwrap();
    for (addr, cause) in [
        ("127.0.0.1:22", FloorCause::Loopback),
        ("169.254.169.254:80", FloorCause::CloudMetadata),
        ("[::ffff:169.254.169.254]:80", FloorCause::CloudMetadata),
        ("[fd00:ec2::254]:80", FloorCause::CloudMetadata),
        ("[2002:7f00:1::1]:22", FloorCause::SixToFour),
        ("[2001::1]:22", FloorCause::Teredo),
        ("255.255.255.255:22", FloorCause::Broadcast),
    ] {
        assert_eq!(
            refusal(&p, addr),
            (Code::Floor, Rule::Floor(cause)),
            "{addr}"
        );
    }
}

#[test]
fn e007_gateway_addresses() {
    let p = compiled();
    let local = LocalAddresses::from_addrs(["10.1.0.5".parse().unwrap()]);
    let r = p.check(sa("10.1.0.5:22"), &local).unwrap_err();
    assert_eq!(
        (r.code, r.rule),
        (Code::Floor, Rule::Floor(FloorCause::AgentAddress))
    );
    let r = p.check(sa("[::ffff:10.1.0.5]:22"), &local).unwrap_err();
    assert_eq!(r.rule, Rule::Floor(FloorCause::AgentAddress));
    assert_eq!(r.original, Some("::ffff:10.1.0.5".parse().unwrap()));
}

#[test]
fn e008_deny_wins_over_allow() {
    let p = compiled();
    assert_eq!(refusal(&p, "10.1.99.7:22"), (Code::Denied, Rule::Denied(0)));
    assert_eq!(
        p.describe(Rule::Denied(0)),
        "réseau interdit « sauvegardes »"
    );
    assert_eq!(p.rule_id(Rule::Denied(0)), "deny[0]");
}

#[test]
fn e009_default_deny() {
    let p = compiled();
    assert_eq!(
        refusal(&p, "10.3.0.1:22"),
        (Code::NotAllowed, Rule::NoAllowedNetwork)
    );
    assert_eq!(
        refusal(&p, "[2001:db8:3::1]:22"),
        (Code::NotAllowed, Rule::NoAllowedNetwork)
    );
    let empty = CompiledPolicy::compile(
        &PolicySpec {
            gateway_group: "g".into(),
            ..PolicySpec::default()
        },
        Mode::Production,
    )
    .unwrap();
    assert_eq!(refusal(&empty, "10.1.2.3:22").0, Code::NotAllowed);
}

#[test]
fn e016_infrastructure() {
    let p = compiled();
    assert_eq!(
        refusal(&p, "10.2.0.10:3389"),
        (Code::Infrastructure, Rule::Infrastructure(0))
    );
    assert_eq!(
        p.describe(Rule::Infrastructure(0)),
        "infrastructure Ostena : core"
    );
}

#[test]
fn e012_invalid_policies_report_everything() {
    let s = PolicySpec {
        gateway_group: " ".into(),
        allow: vec![
            allow(&["10.0.0.1/8", "nope"], &["0", "22"]),
            allow(&[], &[]),
            allow(&["::ffff:10.0.0.0/104"], &["22"]),
        ],
        deny: vec![deny("x", &[])],
        ..PolicySpec::default()
    };
    let err = CompiledPolicy::compile(&s, Mode::Development).unwrap_err();
    assert!(err.codes().iter().all(|c| *c == Code::InvalidPolicy));
    assert_eq!(err.0.len(), 8, "{err}");
    let text = err.to_string();
    assert!(text.contains("allow[0].networks[0] = « 10.0.0.1/8 » : bits d'hôte"));
    assert!(text.contains("allow[2].networks[0]"));
}

#[test]
fn e013_floor_exception_only_in_development() {
    let mut s = spec();
    s.floor_exceptions.push(FloorExceptionSpec {
        network: "127.0.0.0/8".into(),
        reason: "cible de test locale".into(),
    });
    s.allow.push(allow(&["127.0.0.0/8"], &["2222"]));
    let err = CompiledPolicy::compile(&s, Mode::Production).unwrap_err();
    assert_eq!(err.codes(), vec![Code::FloorExceptionInProduction]);

    let p = CompiledPolicy::compile(&s, Mode::Development).unwrap();
    assert_eq!(
        p.check(sa("127.0.0.1:2222"), &none()),
        Ok(Allowed {
            floor_exception: Some(0)
        })
    );
    // The exception lifts the floor, not the policy.
    assert_eq!(refusal(&p, "127.0.0.1:22").0, Code::PortNotAllowed);
    assert_eq!(p.weakenings().len(), 1);
    assert_eq!(p.exception_reason(0), "cible de test locale");
}

/// 2026-11-11T12:00:00Z.
const NOW: u64 = 1_794_398_400;

fn waiver(justification: Option<&str>, expires: Option<&str>) -> PolicySpec {
    PolicySpec {
        allow_short_names: true,
        short_names_justification: justification.map(str::to_owned),
        short_names_expires: expires.map(str::to_owned),
        ..spec()
    }
}

fn codes(s: &PolicySpec, mode: Mode, now: u64) -> Vec<Code> {
    CompiledPolicy::compile_at(s, mode, now)
        .err()
        .map(|e| e.codes())
        .unwrap_or_default()
}

#[test]
fn e015_short_names_need_justification_in_production() {
    let s = waiver(None, Some("2027-01-31"));
    assert_eq!(
        codes(&s, Mode::Production, NOW),
        vec![Code::ShortNamesInProduction]
    );

    let dev = CompiledPolicy::compile_at(&waiver(None, None), Mode::Development, NOW).unwrap();
    assert_eq!(dev.short_names_at(NOW), ShortNames::Allowed);
    assert_eq!(dev.weakenings()[0].kind, "allow_short_names");

    let ok = waiver(
        Some("parc NetBIOS historique, ticket SEC-42"),
        Some("2027-01-31"),
    );
    let prod = CompiledPolicy::compile_at(&ok, Mode::Production, NOW).unwrap();
    assert!(prod.weakenings()[0].message.contains("SEC-42"));
    assert!(prod.weakenings()[0].message.contains("2027-01-31"));
    assert_eq!(prod.short_names_expires().as_deref(), Some("2027-01-31"));
}

#[test]
fn e017_waiver_rules() {
    let long = Some("parc NetBIOS historique, ticket SEC-42");
    // At least 20 characters, counted as characters (not bytes) after trimming.
    let j19 = "é".repeat(19);
    let j20 = "é".repeat(20);
    let padded = format!("   {j19}   ");
    for (j, expected) in [
        (&j19, vec![Code::ShortNamesWaiver]),
        (&padded, vec![Code::ShortNamesWaiver]),
        (&j20, vec![]),
    ] {
        assert_eq!(
            codes(&waiver(Some(j), Some("2027-01-31")), Mode::Production, NOW),
            expected,
            "{j}"
        );
    }
    // Missing, malformed or too distant expiry.
    assert_eq!(
        codes(&waiver(long, None), Mode::Production, NOW),
        vec![Code::ShortNamesWaiver]
    );
    for bad in ["2027-02-30", "31/01/2027", "2027-01-31T00:00:00Z", ""] {
        assert_eq!(
            codes(&waiver(long, Some(bad)), Mode::Production, NOW),
            vec![Code::ShortNamesWaiver],
            "{bad}"
        );
        // Malformed dates are refused in development too.
        assert_eq!(
            codes(&waiver(long, Some(bad)), Mode::Development, NOW),
            vec![Code::ShortNamesWaiver],
            "{bad}"
        );
    }
    // At most 366 days ahead: 2027-11-11 ends 365.5 days after NOW.
    assert_eq!(
        codes(&waiver(long, Some("2027-11-11")), Mode::Production, NOW),
        vec![]
    );
    assert_eq!(
        codes(&waiver(long, Some("2027-11-12")), Mode::Production, NOW),
        vec![Code::ShortNamesWaiver]
    );
}

#[test]
fn e018_expired_waiver_at_startup() {
    let s = waiver(
        Some("parc NetBIOS historique, ticket SEC-42"),
        Some("2026-11-10"),
    );
    assert_eq!(
        codes(&s, Mode::Production, NOW),
        vec![Code::ShortNamesExpired]
    );
    // Last day included, refused from midnight UTC.
    let today = waiver(
        Some("parc NetBIOS historique, ticket SEC-42"),
        Some("2026-11-11"),
    );
    let p = CompiledPolicy::compile_at(&today, Mode::Production, NOW).unwrap();
    let midnight = 1_794_441_600; // 2026-11-12T00:00:00Z
    assert_eq!(p.short_names_at(midnight - 1), ShortNames::Allowed);
    assert_eq!(p.short_names_at(midnight), ShortNames::Expired);
    // Development: compiles, but the expiry still applies at decision time.
    let dev = CompiledPolicy::compile_at(&s, Mode::Development, NOW).unwrap();
    assert_eq!(dev.short_names_at(NOW), ShortNames::Expired);
    assert_eq!(compiled().short_names_at(NOW), ShortNames::Refused);
}

#[test]
fn interval_map_merges_and_splits() {
    let m = IntervalMap::build(&[(10, 20, 1), (15, 30, 2), (31, 40, 2)], first);
    assert_eq!(m.get(9), None);
    assert_eq!(m.get(10), Some(1));
    assert_eq!(m.get(20), Some(1));
    assert_eq!(m.get(21), Some(2));
    assert_eq!(m.get(40), Some(2));
    assert_eq!(m.get(41), None);
    // 21..=30 and 31..=40 carry the same value and are merged.
    assert_eq!(m.starts.len(), 2);
    let full = IntervalMap::build(&[(0, u128::MAX, 7)], first);
    assert_eq!(full.get(u128::MAX), Some(7));
    // Nested networks of the same rule (regression found by proptest).
    let nested = IntervalMap::build(&[(0, u128::MAX, 0), (0, 99, 0), (50, 200, 1)], first);
    assert_eq!(nested.get(150), Some(0));
    assert_eq!(nested.get(1000), Some(0));
}
