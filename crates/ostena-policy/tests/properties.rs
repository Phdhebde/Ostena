//! Properties of the PDP (ADR-0022): the compiled decision equals a naive
//! reading of the rules, refusals win, and the result does not depend on
//! the order of the snapshot.

#![allow(
    clippy::unwrap_used,
    reason = "test generators and oracle outside #[test] functions"
)]

use std::cmp::Reverse;

use ostena_policy::{
    AccountGroupId, AccountId, Code, CompiledPolicy, Decision, Effect, Functions, Protocol,
    Protocols, Request, Rule, RuleId, Snapshot, Subject, Target, UserGroupId, UserId,
};
use proptest::prelude::*;

const NOW: u64 = 10_000;

fn functions() -> impl Strategy<Value = Functions> {
    (0u32..1024).prop_map(|b| Functions::from_bits(b).unwrap())
}

fn protocol() -> impl Strategy<Value = Protocol> {
    prop::sample::select(Protocol::ALL.to_vec())
}

fn rule() -> impl Strategy<Value = Rule> {
    let subject = prop_oneof![
        (0u128..6).prop_map(|u| Subject::User(UserId(u))),
        (0u128..4).prop_map(|g| Subject::Group(UserGroupId(g))),
    ];
    let target = prop_oneof![
        (0u128..8).prop_map(|a| Target::Account(AccountId(a))),
        (0u128..4).prop_map(|g| Target::AccountGroup(AccountGroupId(g))),
    ];
    let effect = prop_oneof![
        6 => (functions(), 60u32..=43_200).prop_map(|(functions, max_session_secs)| {
            Effect::Allow { functions, max_session_secs }
        }),
        1 => Just(Effect::Deny),
        1 => functions()
            .prop_filter("some function", |f| !f.is_empty())
            .prop_map(Effect::DenyFunctions),
    ];
    let protocols =
        prop::collection::vec(protocol(), 1..4).prop_map(|v| v.into_iter().collect::<Protocols>());
    (
        0u128..40,
        subject,
        target,
        protocols,
        effect,
        NOW - 3_000..NOW + 3_000,
        1u64..6_000,
    )
        .prop_map(
            |(id, subject, target, protocols, effect, valid_from, length)| Rule {
                id: RuleId(id),
                subject,
                target,
                protocols,
                effect,
                valid_from,
                valid_until: valid_from + length,
            },
        )
}

fn snapshot() -> impl Strategy<Value = Snapshot> {
    (
        prop::collection::vec((0u128..4, 0u128..6), 0..16),
        prop::collection::vec((0u128..4, 0u128..8), 0..16),
        prop::collection::vec(rule(), 0..24),
    )
        .prop_map(|(ug, ag, mut rules)| {
            rules.sort_by_key(|r| r.id);
            rules.dedup_by_key(|r| r.id);
            Snapshot {
                version: 1,
                user_groups: ug
                    .into_iter()
                    .map(|(g, u)| (UserGroupId(g), UserId(u)))
                    .collect(),
                account_groups: ag
                    .into_iter()
                    .map(|(g, a)| (AccountGroupId(g), AccountId(a)))
                    .collect(),
                rules,
            }
        })
}

fn request() -> impl Strategy<Value = Request> {
    (
        0u128..7,
        0u128..9,
        protocol(),
        functions(),
        NOW - 3_500..NOW + 6_500,
    )
        .prop_map(|(u, a, protocol, wanted, now)| Request {
            user: UserId(u),
            account: AccountId(a),
            protocol,
            wanted,
            now,
        })
}

/// The rules read one by one, without index.
fn naive(s: &Snapshot, r: &Request) -> Decision {
    let applies = |rule: &&Rule| {
        rule.protocols.contains(r.protocol)
            && rule.valid_from <= r.now
            && r.now < rule.valid_until
            && match rule.subject {
                Subject::User(u) => u == r.user,
                Subject::Group(g) => s.user_groups.contains(&(g, r.user)),
            }
            && match rule.target {
                Target::Account(a) => a == r.account,
                Target::AccountGroup(g) => s.account_groups.contains(&(g, r.account)),
            }
    };
    let rules: Vec<&Rule> = s.rules.iter().filter(applies).collect();
    if let Some(d) = rules
        .iter()
        .filter(|r| r.effect == Effect::Deny)
        .map(|r| r.id)
        .min()
    {
        return Decision::Deny(ostena_policy::Denied {
            version: Some(1),
            code: Code::DeniedByRule,
            rule: Some(d),
        });
    }
    let taken = rules.iter().fold(Functions::NONE, |t, r| match r.effect {
        Effect::DenyFunctions(f) => t.union(f),
        _ => t,
    });
    let restricted_by = rules
        .iter()
        .filter(|r| matches!(r.effect, Effect::DenyFunctions(_)))
        .map(|r| r.id)
        .min();
    let wanted = r.wanted.for_protocol(r.protocol);
    let best = rules
        .iter()
        .filter_map(|rule| match rule.effect {
            Effect::Allow {
                functions,
                max_session_secs,
            } => Some((rule, functions.for_protocol(r.protocol), max_session_secs)),
            _ => None,
        })
        .max_by_key(|(rule, f, m)| (f.contains(wanted), rule.valid_until, *m, Reverse(rule.id)));
    let Some((rule, functions, max)) = best else {
        return Decision::Deny(ostena_policy::Denied {
            version: Some(1),
            code: Code::NoRule,
            rule: None,
        });
    };
    let granted = functions.difference(taken).for_protocol(r.protocol);
    Decision::Allow(ostena_policy::Allowed {
        version: 1,
        rule: rule.id,
        functions: granted,
        missing: wanted.difference(granted),
        restricted_by: (granted != functions).then_some(restricted_by).flatten(),
        max_session_secs: max.min(u32::try_from(rule.valid_until - r.now).unwrap()),
        valid_until: rule.valid_until,
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn compiled_equals_naive(s in snapshot(), requests in prop::collection::vec(request(), 1..16)) {
        let policy = CompiledPolicy::compile(&s).unwrap();
        for r in &requests {
            prop_assert_eq!(policy.decide(r), naive(&s, r), "{:?}", r);
        }
    }

    #[test]
    fn order_of_the_snapshot_does_not_matter(s in snapshot(), r in request()) {
        let mut reversed = s.clone();
        reversed.rules.reverse();
        reversed.user_groups.reverse();
        reversed.account_groups.reverse();
        let a = CompiledPolicy::compile(&s).unwrap().decide(&r);
        let b = CompiledPolicy::compile(&reversed).unwrap().decide(&r);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn a_refusal_always_wins(s in snapshot(), r in request()) {
        let mut with_deny = s.clone();
        with_deny.rules.push(Rule {
            id: RuleId(1_000),
            subject: Subject::User(r.user),
            target: Target::Account(r.account),
            protocols: Protocols::ALL,
            effect: Effect::Deny,
            valid_from: 0,
            valid_until: u64::MAX,
        });
        let decision = CompiledPolicy::compile(&with_deny).unwrap().decide(&r);
        let Decision::Deny(d) = decision else {
            return Err(TestCaseError::fail("allowed despite a refusal"));
        };
        prop_assert_eq!(d.code, Code::DeniedByRule);
    }

    #[test]
    fn granted_functions_never_exceed_the_rule_or_the_protocol(s in snapshot(), r in request()) {
        if let Decision::Allow(a) = CompiledPolicy::compile(&s).unwrap().decide(&r) {
            let rule = s.rules.iter().find(|x| x.id == a.rule).unwrap();
            let Effect::Allow { functions, max_session_secs } = rule.effect else {
                return Err(TestCaseError::fail("retained a refusal"));
            };
            prop_assert!(functions.contains(a.functions));
            prop_assert!(r.protocol.functions().contains(a.functions));
            prop_assert!(a.max_session_secs <= max_session_secs);
            prop_assert!(r.now + u64::from(a.max_session_secs) <= rule.valid_until);
        }
    }
}
