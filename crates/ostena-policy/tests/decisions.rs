//! Decisions of the PDP on small policies (ADR-0022).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers outside #[test] functions"
)]

use std::sync::Arc;

use ostena_policy::{
    AccountGroupId, AccountId, Code, CompiledPolicy, Decision, Effect, Function, Functions, Pdp,
    PolicyError, Protocol, Protocols, Request, Rule, RuleId, Snapshot, Subject, Target,
    UserGroupId, UserId,
};

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;

const ALICE: UserId = UserId(1);
const BOB: UserId = UserId(2);
const ADMINS: UserGroupId = UserGroupId(10);
const OPS: UserGroupId = UserGroupId(11);
const ROOT_WEB1: AccountId = AccountId(100);
const ROOT_WEB2: AccountId = AccountId(101);
const ADMIN_DC1: AccountId = AccountId(102);
const LINUX: AccountGroupId = AccountGroupId(200);

fn ssh() -> Protocols {
    Protocols::NONE.with(Protocol::Ssh)
}

fn allow(id: u128, subject: Subject, target: Target, functions: Functions) -> Rule {
    Rule {
        id: RuleId(id),
        subject,
        target,
        protocols: ssh(),
        effect: Effect::Allow {
            functions,
            max_session_secs: 3_600,
        },
        valid_from: NOW - DAY,
        valid_until: NOW + 30 * DAY,
    }
}

fn deny(id: u128, subject: Subject, target: Target, effect: Effect) -> Rule {
    Rule {
        id: RuleId(id),
        subject,
        target,
        protocols: ssh(),
        effect,
        valid_from: 0,
        valid_until: u64::MAX,
    }
}

fn snapshot(rules: Vec<Rule>) -> Snapshot {
    Snapshot {
        version: 7,
        user_groups: vec![(ADMINS, ALICE), (OPS, ALICE), (OPS, BOB)],
        account_groups: vec![(LINUX, ROOT_WEB1), (LINUX, ROOT_WEB2)],
        rules,
    }
}

fn request(user: UserId, account: AccountId) -> Request {
    Request {
        user,
        account,
        protocol: Protocol::Ssh,
        wanted: Functions::NONE,
        now: NOW,
    }
}

fn decide(rules: Vec<Rule>, request: &Request) -> Decision {
    CompiledPolicy::compile(&snapshot(rules))
        .unwrap()
        .decide(request)
}

fn code(decision: Decision) -> Code {
    match decision {
        Decision::Deny(d) => d.code,
        Decision::Allow(a) => panic!("allowed: {a:?}"),
    }
}

#[test]
fn refused_by_default() {
    assert_eq!(
        code(decide(vec![], &request(ALICE, ROOT_WEB1))),
        Code::NoRule
    );
    // Unknown user, unknown account.
    let rules = vec![allow(
        1,
        Subject::Group(OPS),
        Target::AccountGroup(LINUX),
        Functions::NONE,
    )];
    assert_eq!(
        code(decide(rules.clone(), &request(UserId(9), ROOT_WEB1))),
        Code::NoRule
    );
    assert_eq!(
        code(decide(rules.clone(), &request(ALICE, AccountId(9)))),
        Code::NoRule
    );
    // Account outside the group.
    assert_eq!(
        code(decide(rules, &request(ALICE, ADMIN_DC1))),
        Code::NoRule
    );
}

#[test]
fn group_on_group_of_accounts() {
    let rules = vec![allow(
        1,
        Subject::Group(OPS),
        Target::AccountGroup(LINUX),
        Functions::TRANSFER,
    )];
    let Decision::Allow(a) = decide(rules.clone(), &request(BOB, ROOT_WEB2)) else {
        panic!("refused")
    };
    assert_eq!(a.version, 7);
    assert_eq!(a.rule, RuleId(1));
    assert_eq!(a.functions, Functions::TRANSFER);
    assert_eq!(a.max_session_secs, 3_600);
    assert_eq!(a.valid_until, NOW + 30 * DAY);
    // Another protocol.
    let mut rdp = request(BOB, ROOT_WEB2);
    rdp.protocol = Protocol::Rdp;
    assert_eq!(code(decide(rules, &rdp)), Code::NoRule);
}

#[test]
fn window_is_half_open_and_bounds_the_session() {
    let mut rule = allow(
        1,
        Subject::User(ALICE),
        Target::Account(ADMIN_DC1),
        Functions::NONE,
    );
    rule.valid_until = NOW + 600;
    let Decision::Allow(a) = decide(vec![rule], &request(ALICE, ADMIN_DC1)) else {
        panic!("refused")
    };
    assert_eq!(a.max_session_secs, 600);
    let mut at_end = request(ALICE, ADMIN_DC1);
    at_end.now = NOW + 600;
    assert_eq!(code(decide(vec![rule], &at_end)), Code::NoRule);
    rule.valid_from = NOW + 1;
    assert_eq!(
        code(decide(vec![rule], &request(ALICE, ADMIN_DC1))),
        Code::NoRule
    );
}

#[test]
fn deny_wins_and_names_the_smallest_rule() {
    let rules = vec![
        allow(
            1,
            Subject::User(ALICE),
            Target::Account(ROOT_WEB1),
            Functions::NONE,
        ),
        allow(
            2,
            Subject::Group(OPS),
            Target::AccountGroup(LINUX),
            Functions::NONE,
        ),
        deny(
            9,
            Subject::Group(ADMINS),
            Target::AccountGroup(LINUX),
            Effect::Deny,
        ),
        deny(
            5,
            Subject::User(ALICE),
            Target::Account(ROOT_WEB1),
            Effect::Deny,
        ),
    ];
    let Decision::Deny(d) = decide(rules.clone(), &request(ALICE, ROOT_WEB1)) else {
        panic!("allowed")
    };
    assert_eq!(
        (d.code, d.rule, d.version),
        (Code::DeniedByRule, Some(RuleId(5)), Some(7))
    );
    // Bob is in OPS only: allowed.
    assert!(decide(rules, &request(BOB, ROOT_WEB1)).is_allowed());
}

#[test]
fn refused_functions_are_taken_away() {
    let all = Functions::TRANSFER
        .with(Function::PortForwarding)
        .with(Function::AgentForwarding);
    let rules = vec![
        allow(1, Subject::Group(OPS), Target::AccountGroup(LINUX), all),
        deny(
            3,
            Subject::Group(ADMINS),
            Target::Account(ROOT_WEB1),
            Effect::DenyFunctions(Functions::NONE.with(Function::PortForwarding)),
        ),
        // Takes one direction of a transfer: SSH then loses both.
        deny(
            4,
            Subject::User(ALICE),
            Target::AccountGroup(LINUX),
            Effect::DenyFunctions(Functions::NONE.with(Function::Upload)),
        ),
    ];
    let mut req = request(ALICE, ROOT_WEB1);
    req.wanted = Functions::TRANSFER;
    let Decision::Allow(a) = decide(rules.clone(), &req) else {
        panic!("refused")
    };
    assert_eq!(a.functions, Functions::NONE.with(Function::AgentForwarding));
    assert_eq!(a.missing, Functions::TRANSFER);
    assert_eq!(a.restricted_by, Some(RuleId(3)));
    let Decision::Allow(b) = decide(rules, &request(BOB, ROOT_WEB1)) else {
        panic!("refused")
    };
    assert_eq!(b.functions, all);
    assert_eq!(b.restricted_by, None);
}

#[test]
fn functions_do_not_add_up_the_wanted_ones_come_first() {
    let long = allow(
        1,
        Subject::Group(OPS),
        Target::AccountGroup(LINUX),
        Functions::NONE,
    );
    let mut short = allow(
        2,
        Subject::User(BOB),
        Target::Account(ROOT_WEB1),
        Functions::TRANSFER,
    );
    short.valid_until = NOW + DAY;
    let rules = vec![long, short];
    // Nothing wanted: the longest rule, without its functions.
    let Decision::Allow(a) = decide(rules.clone(), &request(BOB, ROOT_WEB1)) else {
        panic!("refused")
    };
    assert_eq!((a.rule, a.functions), (RuleId(1), Functions::NONE));
    // Transfer wanted: the rule that has it, though shorter.
    let mut req = request(BOB, ROOT_WEB1);
    req.wanted = Functions::TRANSFER;
    let Decision::Allow(b) = decide(rules, &req) else {
        panic!("refused")
    };
    assert_eq!(
        (b.rule, b.functions, b.missing),
        (RuleId(2), Functions::TRANSFER, Functions::NONE)
    );
}

#[test]
fn functions_are_limited_to_the_protocol() {
    let mut rule = allow(
        1,
        Subject::User(ALICE),
        Target::Account(ADMIN_DC1),
        Functions::CLIPBOARD
            .union(Functions::TRANSFER)
            .with(Function::DriveRedirection)
            .with(Function::PortForwarding),
    );
    rule.protocols = Protocols::ALL;
    let decided = |protocol| {
        let mut req = request(ALICE, ADMIN_DC1);
        req.protocol = protocol;
        match decide(vec![rule], &req) {
            Decision::Allow(a) => a.functions,
            Decision::Deny(d) => panic!("{d:?}"),
        }
    };
    assert_eq!(
        decided(Protocol::Ssh),
        Functions::TRANSFER.with(Function::PortForwarding)
    );
    assert_eq!(
        decided(Protocol::Rdp),
        Functions::CLIPBOARD
            .union(Functions::TRANSFER)
            .with(Function::DriveRedirection)
    );
    assert_eq!(decided(Protocol::Vnc), Functions::CLIPBOARD);
    assert_eq!(
        decided(Protocol::Web),
        Functions::CLIPBOARD.union(Functions::TRANSFER)
    );
    // A one-way transfer is never granted over SSH.
    let one_way = Functions::NONE.with(Function::Download);
    assert_eq!(one_way.for_protocol(Protocol::Ssh), Functions::NONE);
    assert_eq!(one_way.for_protocol(Protocol::Rdp), one_way);
}

#[test]
fn invalid_policies_are_refused_whole() {
    let ok = allow(
        1,
        Subject::User(ALICE),
        Target::Account(ADMIN_DC1),
        Functions::NONE,
    );
    let compile = |rule: Rule| CompiledPolicy::compile(&snapshot(vec![ok, rule])).unwrap_err();
    let mut dup = ok;
    dup.subject = Subject::User(BOB);
    assert_eq!(compile(dup), PolicyError::DuplicateRule(RuleId(1)));
    let mut r = allow(
        2,
        Subject::User(ALICE),
        Target::Account(ADMIN_DC1),
        Functions::NONE,
    );
    r.protocols = Protocols::NONE;
    assert_eq!(compile(r), PolicyError::NoProtocol(RuleId(2)));
    let mut r = allow(
        2,
        Subject::User(ALICE),
        Target::Account(ADMIN_DC1),
        Functions::NONE,
    );
    r.valid_until = r.valid_from;
    assert_eq!(compile(r), PolicyError::Window(RuleId(2)));
    let mut r = allow(
        2,
        Subject::User(ALICE),
        Target::Account(ADMIN_DC1),
        Functions::NONE,
    );
    r.valid_until = r.valid_from + 366 * DAY + 1;
    assert_eq!(compile(r), PolicyError::AllowTooLong(RuleId(2)));
    for secs in [59, 12 * 3_600 + 1] {
        let mut r = allow(
            2,
            Subject::User(ALICE),
            Target::Account(ADMIN_DC1),
            Functions::NONE,
        );
        r.effect = Effect::Allow {
            functions: Functions::NONE,
            max_session_secs: secs,
        };
        assert_eq!(compile(r), PolicyError::SessionLength(RuleId(2)));
    }
    let r = deny(
        2,
        Subject::User(ALICE),
        Target::Account(ADMIN_DC1),
        Effect::DenyFunctions(Functions::NONE),
    );
    let err = compile(r);
    assert_eq!(err, PolicyError::NoFunction(RuleId(2)));
    assert_eq!(err.code().as_str(), "POL-E004");
    assert!(err.to_string().starts_with("POL-E004"));
    // A refusal may last forever; an allowance of exactly 366 days is fine.
    let mut r = allow(
        2,
        Subject::User(ALICE),
        Target::Account(ADMIN_DC1),
        Functions::NONE,
    );
    r.valid_until = r.valid_from + 366 * DAY;
    assert!(CompiledPolicy::compile(&snapshot(vec![ok, r])).is_ok());
}

#[test]
fn pdp_installs_forward_and_refuses_when_invalidated() {
    let pdp = Pdp::new();
    let req = request(ALICE, ADMIN_DC1);
    let Decision::Deny(d) = pdp.decide(&req) else {
        panic!("allowed")
    };
    assert_eq!((d.code, d.version), (Code::Unavailable, None));

    let rule = allow(
        1,
        Subject::User(ALICE),
        Target::Account(ADMIN_DC1),
        Functions::NONE,
    );
    let v7 = Arc::new(CompiledPolicy::compile(&snapshot(vec![rule])).unwrap());
    let installed = pdp.install(v7.clone()).unwrap();
    assert_eq!((installed.version, installed.previous), (7, None));
    assert_eq!(pdp.decide(&req).version(), Some(7));
    assert!(pdp.decide(&req).is_allowed());

    // Version 8 removes the rule.
    let mut empty = snapshot(vec![]);
    empty.version = 8;
    let v8 = Arc::new(CompiledPolicy::compile(&empty).unwrap());
    assert_eq!(pdp.install(v8.clone()).unwrap().previous, Some(7));
    assert_eq!(code(pdp.decide(&req)), Code::NoRule);

    // Version 7 again: refused, version 8 stays.
    let err = pdp.install(v7).unwrap_err();
    assert_eq!(
        err,
        PolicyError::Stale {
            installed: 8,
            offered: 7
        }
    );
    assert_eq!(err.code().as_str(), "POL-E005");
    assert_eq!(pdp.current().unwrap().version(), 8);

    // Invalidated: everything refused, and an older version is still refused.
    assert_eq!(pdp.invalidate(), Some(8));
    assert_eq!(pdp.invalidate(), None);
    assert_eq!(code(pdp.decide(&req)), Code::Unavailable);
    // The same version reloaded is accepted.
    assert_eq!(pdp.install(v8).unwrap().previous, None);
    assert_eq!(code(pdp.decide(&req)), Code::NoRule);
}

#[test]
fn names_and_bits() {
    assert_eq!(
        Functions::parse(&["transfer", "x11-forwarding", "clipboard", "transfer"]).unwrap(),
        Functions::TRANSFER
            .union(Functions::CLIPBOARD)
            .with(Function::X11Forwarding)
    );
    assert_eq!(Functions::parse(&["Transfer"]).unwrap_err(), "Transfer");
    for f in Function::ALL {
        let one = Functions::NONE.with(f);
        assert_eq!(Functions::parse(&[f.name()]).unwrap(), one);
        assert_eq!(one.bits(), 1 << (f as u32));
        assert_eq!(Functions::from_bits(one.bits()), Some(one));
    }
    assert_eq!(Functions::from_bits(1 << 10), None);
    assert_eq!(Functions::TRANSFER.to_string(), "upload,download");
    assert_eq!(Functions::NONE.to_string(), "-");
    for p in Protocol::ALL {
        assert_eq!(Protocol::parse(p.name()), Some(p));
        assert!(Protocols::ALL.contains(p));
        assert!(!Protocols::NONE.contains(p));
    }
    assert_eq!(
        Protocol::ALL.into_iter().collect::<Protocols>(),
        Protocols::ALL
    );
    assert_eq!(UserId(0xab).to_string(), "000000000000000000000000000000ab");
}
