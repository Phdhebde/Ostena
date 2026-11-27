//! Cost of one PDP decision (ADR-0022): 10 000 rules and 50 000 resources
//! (two accounts each), 5 000 users in 500 groups, 1 000 groups of
//! accounts. Times each decision through [`Pdp::decide`] (lock and policy
//! clone included) and prints p50, p99 and the maximum, the compilation
//! time, and the heap held by the compiled policy (dhat). The criterion is
//! p99 < 1 ms; not a gate in CI (ADR-0005).
//!
//! `cargo bench -p ostena-policy --bench decision`.

#![allow(
    clippy::expect_used,
    clippy::print_stdout,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    reason = "benchmark binary: prints its results, fixed inputs"
)]

use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ostena_policy::{
    AccountGroupId, AccountId, CompiledPolicy, Effect, Function, Functions, Pdp, Protocol,
    Protocols, Request, Rule, RuleId, Snapshot, Subject, Target, UserGroupId, UserId,
};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

const RESOURCES: u64 = 50_000;
const ACCOUNTS_PER_RESOURCE: u64 = 2;
const ACCOUNTS: u64 = RESOURCES * ACCOUNTS_PER_RESOURCE;
const USERS: u64 = 5_000;
const USER_GROUPS: u64 = 500;
const GROUPS_PER_USER: u64 = 10;
const ACCOUNT_GROUPS: u64 = 1_000;
const RULES: u64 = 10_000;
const DECISIONS: usize = 200_000;
const NOW: u64 = 1_800_000_000;

/// `SplitMix64`: deterministic inputs without a dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn snapshot(rng: &mut Rng) -> Snapshot {
    let mut user_groups = Vec::new();
    for u in 0..USERS {
        for _ in 0..GROUPS_PER_USER {
            user_groups.push((UserGroupId(rng.below(USER_GROUPS).into()), UserId(u.into())));
        }
    }
    // Each account in one group, one in four in a second one.
    let mut account_groups = Vec::new();
    for a in 0..ACCOUNTS {
        account_groups.push((
            AccountGroupId((a % ACCOUNT_GROUPS).into()),
            AccountId(a.into()),
        ));
        if a % 4 == 0 {
            account_groups.push((
                AccountGroupId(rng.below(ACCOUNT_GROUPS).into()),
                AccountId(a.into()),
            ));
        }
    }
    let allow = |functions: Functions| Effect::Allow {
        functions,
        max_session_secs: 3_600,
    };
    let mut rules = Vec::new();
    for i in 0..RULES {
        let (subject, target, effect) = match i % 20 {
            // 80 %: group of users on a group of accounts.
            0..=15 => (
                Subject::Group(UserGroupId(rng.below(USER_GROUPS).into())),
                Target::AccountGroup(AccountGroupId(rng.below(ACCOUNT_GROUPS).into())),
                allow(Functions::TRANSFER.with(Function::PortForwarding)),
            ),
            // 10 %: one user on one account (the rights of ADR-0014).
            16 | 17 => (
                Subject::User(UserId(rng.below(USERS).into())),
                Target::Account(AccountId(rng.below(ACCOUNTS).into())),
                allow(Functions::NONE),
            ),
            // 5 %: refusals, 5 %: refusals of functions.
            18 => (
                Subject::Group(UserGroupId(rng.below(USER_GROUPS).into())),
                Target::Account(AccountId(rng.below(ACCOUNTS).into())),
                Effect::Deny,
            ),
            _ => (
                Subject::Group(UserGroupId(rng.below(USER_GROUPS).into())),
                Target::AccountGroup(AccountGroupId(rng.below(ACCOUNT_GROUPS).into())),
                Effect::DenyFunctions(Functions::NONE.with(Function::PortForwarding)),
            ),
        };
        rules.push(Rule {
            id: RuleId(i.into()),
            subject,
            target,
            protocols: Protocols::NONE.with(Protocol::Ssh).with(Protocol::Rdp),
            effect,
            valid_from: NOW - 86_400,
            valid_until: if matches!(effect, Effect::Allow { .. }) {
                NOW + 86_400 * 30
            } else {
                u64::MAX
            },
        });
    }
    Snapshot {
        version: 1,
        user_groups,
        account_groups,
        rules,
    }
}

fn percentile(sorted: &[Duration], per_mille: usize) -> Duration {
    sorted[(sorted.len() - 1) * per_mille / 1000]
}

fn micros(d: Duration) -> f64 {
    d.as_secs_f64() * 1e6
}

fn main() {
    let _profiler = dhat::Profiler::builder().testing().build();
    let mut rng = Rng(0x0057_e4a0_0022);
    let snapshot = snapshot(&mut rng);
    let rules = snapshot.rules.len();
    let before = dhat::HeapStats::get();
    let start = Instant::now();
    let policy = CompiledPolicy::compile(&snapshot).expect("valid policy");
    let compile = start.elapsed();
    let after = dhat::HeapStats::get();
    let held = after.curr_bytes - before.curr_bytes;
    let peak = after.max_bytes.saturating_sub(before.curr_bytes);
    let stats = policy.stats();
    drop(snapshot);

    let pdp = Pdp::new();
    pdp.install(Arc::new(policy)).expect("first version");

    let requests: Vec<Request> = (0..DECISIONS)
        .map(|_| Request {
            user: UserId(rng.below(USERS).into()),
            account: AccountId(rng.below(ACCOUNTS).into()),
            protocol: if rng.below(2) == 0 {
                Protocol::Ssh
            } else {
                Protocol::Rdp
            },
            wanted: Functions::NONE,
            now: NOW,
        })
        .collect();
    for r in requests.iter().take(10_000) {
        black_box(pdp.decide(black_box(r)));
    }
    let mut samples = Vec::with_capacity(DECISIONS);
    let mut allowed = 0usize;
    let allocations = dhat::HeapStats::get().total_blocks;
    for r in &requests {
        let start = Instant::now();
        let decision = pdp.decide(black_box(r));
        samples.push(start.elapsed());
        allowed += usize::from(black_box(decision).is_allowed());
    }
    let allocated = dhat::HeapStats::get().total_blocks - allocations;
    samples.sort_unstable();

    println!(
        "policy: {rules} rules, {} users in {} groups, {} accounts on {RESOURCES} resources in {} groups",
        stats.users, stats.user_groups, stats.accounts, stats.account_groups
    );
    println!("compilation: {compile:?}");
    println!(
        "heap held by the compiled policy: {:.1} MiB (peak during compilation: {:.1} MiB)",
        held as f64 / 1_048_576.0,
        peak as f64 / 1_048_576.0
    );
    println!(
        "decisions: {DECISIONS}, allowed {:.1} %, allocations {allocated}",
        allowed as f64 * 100.0 / DECISIONS as f64
    );
    println!(
        "pdp decision: p50 {:.2} µs, p99 {:.2} µs, max {:.2} µs",
        micros(percentile(&samples, 500)),
        micros(percentile(&samples, 990)),
        micros(samples[samples.len() - 1])
    );
}
