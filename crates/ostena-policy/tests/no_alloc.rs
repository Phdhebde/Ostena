//! Proves that a decision does not allocate (dhat), through the PDP and on
//! the compiled policy. Alone in its file: dhat counts every allocation of
//! the process.

use std::hint::black_box;
use std::sync::Arc;

use ostena_policy::{
    AccountGroupId, AccountId, CompiledPolicy, Effect, Function, Functions, Pdp, Protocol,
    Protocols, Request, Rule, RuleId, Snapshot, Subject, Target, UserGroupId, UserId,
};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[test]
fn decision_does_not_allocate() {
    let rules = (0..200u128)
        .map(|i| Rule {
            id: RuleId(i),
            subject: if i % 3 == 0 {
                Subject::User(UserId(i % 7))
            } else {
                Subject::Group(UserGroupId(i % 5))
            },
            target: if i % 2 == 0 {
                Target::Account(AccountId(i % 11))
            } else {
                Target::AccountGroup(AccountGroupId(i % 4))
            },
            protocols: Protocols::ALL,
            effect: match i % 10 {
                0 => Effect::Deny,
                1 => Effect::DenyFunctions(Functions::NONE.with(Function::PortForwarding)),
                _ => Effect::Allow {
                    functions: Functions::TRANSFER.with(Function::PortForwarding),
                    max_session_secs: 3_600,
                },
            },
            valid_from: 0,
            valid_until: 1_000_000,
        })
        .collect();
    let snapshot = Snapshot {
        version: 1,
        user_groups: (0..20u128)
            .map(|u| (UserGroupId(u % 5), UserId(u % 7)))
            .collect(),
        account_groups: (0..30u128)
            .map(|a| (AccountGroupId(a % 4), AccountId(a % 11)))
            .collect(),
        rules,
    };
    let policy = Arc::new(CompiledPolicy::compile(&snapshot).unwrap());
    let pdp = Pdp::new();
    pdp.install(policy.clone()).unwrap();
    let requests: Vec<Request> = (0..64u128)
        .map(|i| Request {
            user: UserId(i % 8),
            account: AccountId(i % 12),
            protocol: Protocol::ALL[(i % 4) as usize],
            wanted: Functions::TRANSFER,
            now: 500_000,
        })
        .collect();
    let mut allowed = 0;
    let _profiler = dhat::Profiler::builder().testing().build();
    for r in &requests {
        allowed += usize::from(pdp.decide(black_box(r)).is_allowed());
        allowed += usize::from(policy.decide(black_box(r)).is_allowed());
    }
    let stats = dhat::HeapStats::get();
    dhat::assert_eq!(stats.total_blocks, 0);
    assert!(allowed > 0);
}
