//! `REG-SEC-06`: 1 000 openings at once, beyond the quotas, never give one
//! session too many: exactly the bound succeeds, the others are refused
//! with the code of the quota reached, and every slot is given back.

#![allow(clippy::unwrap_used, reason = "test helper outside #[test] functions")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use ostena_session::{Claim, Limits, Protocol, SessionError, SessionManager};

const OPENINGS: usize = 1_000;
const HOUR: Duration = Duration::from_secs(3600);

fn claim(user: usize, target: &str) -> Claim {
    let mut subject = [0; 16];
    subject[..8].copy_from_slice(&(user as u64).to_be_bytes());
    Claim {
        protocol: Protocol::Ssh,
        subject,
        login_session: subject,
        target: Arc::from(target),
    }
}

fn session_id(n: usize) -> [u8; 16] {
    let mut id = [0xab; 16];
    id[..8].copy_from_slice(&(n as u64).to_be_bytes());
    id
}

/// Opens `OPENINGS` sessions from as many threads released together; each
/// success is held until every thread has tried. Returns the successes and
/// the refusals.
fn storm(
    manager: &SessionManager,
    claim_of: impl Fn(usize) -> Claim + Sync,
) -> (usize, Vec<SessionError>) {
    let start = Barrier::new(OPENINGS);
    let tried = Barrier::new(OPENINGS);
    let held = AtomicUsize::new(0);
    let peak = AtomicUsize::new(0);
    let outcomes = thread::scope(|scope| {
        let handles: Vec<_> = (0..OPENINGS)
            .map(|n| {
                let (start, tried, held, peak, claim_of) =
                    (&start, &tried, &held, &peak, &claim_of);
                thread::Builder::new()
                    .stack_size(64 * 1024)
                    .spawn_scoped(scope, move || {
                        start.wait();
                        let outcome = manager.open(claim_of(n), session_id(n), HOUR);
                        if outcome.is_ok() {
                            let now = held.fetch_add(1, Ordering::SeqCst) + 1;
                            peak.fetch_max(now, Ordering::SeqCst);
                        }
                        tried.wait();
                        outcome.map(drop)
                    })
                    .unwrap()
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    let successes = outcomes.iter().filter(|o| o.is_ok()).count();
    assert_eq!(peak.load(Ordering::SeqCst), successes);
    let refusals = outcomes.into_iter().filter_map(Result::err).collect();
    // Every slot is given back.
    assert!(manager.is_empty());
    (successes, refusals)
}

#[test]
fn reg_sec_06_agent_quota_under_1000_concurrent_openings() {
    let manager = SessionManager::new(Limits::new(64), Vec::new());
    let (successes, refusals) = storm(&manager, |n| claim(n, &format!("t{n}")));
    assert_eq!(successes, 64);
    assert_eq!(refusals.len(), OPENINGS - 64);
    assert!(refusals.iter().all(|e| *e == SessionError::AgentLimit(64)));
}

#[test]
fn reg_sec_06_user_quota_under_1000_concurrent_openings() {
    let limits = Limits {
        max_per_user: Some(5),
        ..Limits::new(256)
    };
    let manager = SessionManager::new(limits, Vec::new());
    // Ten users, a hundred openings each.
    let (successes, refusals) = storm(&manager, |n| claim(n % 10, &format!("t{n}")));
    assert_eq!(successes, 50);
    assert!(refusals.iter().all(|e| *e == SessionError::UserLimit(5)));
}

#[test]
fn reg_sec_06_target_quota_under_1000_concurrent_openings() {
    let limits = Limits {
        max_per_target: Some(3),
        ..Limits::new(256)
    };
    let manager = SessionManager::new(limits, Vec::new());
    // Seven targets.
    let (successes, refusals) = storm(&manager, |n| claim(n, &format!("t{}", n % 7)));
    assert_eq!(successes, 21);
    assert!(refusals.iter().all(|e| *e == SessionError::TargetLimit(3)));
}

#[test]
fn reg_sec_06_duplicate_identifier_under_concurrent_openings() {
    let manager = SessionManager::new(Limits::new(OPENINGS), Vec::new());
    let start = Barrier::new(64);
    let tried = Barrier::new(64);
    let outcomes: Vec<_> = thread::scope(|scope| {
        let handles: Vec<_> = (0..64)
            .map(|n| {
                let (start, tried, manager) = (&start, &tried, &manager);
                scope.spawn(move || {
                    start.wait();
                    let outcome = manager.open(claim(n, "t"), session_id(7), HOUR);
                    tried.wait();
                    outcome.map(drop)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(outcomes.iter().filter(|o| o.is_ok()).count(), 1);
    assert!(
        outcomes
            .iter()
            .filter_map(|o| o.err())
            .all(|e| e == SessionError::DuplicateId)
    );
    assert!(manager.is_empty());
}

#[test]
fn reg_sec_06_bound_holds_while_sessions_come_and_go() {
    const BOUND: usize = 16;
    let manager = SessionManager::new(Limits::new(BOUND), Vec::new());
    let held = AtomicUsize::new(0);
    let peak = AtomicUsize::new(0);
    let opened = AtomicUsize::new(0);
    thread::scope(|scope| {
        for t in 0..32 {
            let (manager, held, peak, opened) = (&manager, &held, &peak, &opened);
            scope.spawn(move || {
                for i in 0..200 {
                    let n = t * 1_000 + i;
                    if let Ok(session) = manager.open(claim(n, "t"), session_id(n), HOUR) {
                        let now = held.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        assert!(manager.len() <= BOUND);
                        opened.fetch_add(1, Ordering::Relaxed);
                        thread::yield_now();
                        held.fetch_sub(1, Ordering::SeqCst);
                        drop(session);
                    }
                }
            });
        }
    });
    assert!(peak.load(Ordering::SeqCst) <= BOUND);
    assert!(opened.load(Ordering::Relaxed) >= BOUND);
    assert!(manager.is_empty());
}
