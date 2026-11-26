//! Properties of the quotas, against a model: whatever the sequence of
//! reservations, openings, releases and cuts, a slot is granted exactly when
//! the model has room for it, no count ever exceeds its bound, an
//! identifier is never open twice, and everything is given back.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use ostena_session::{
    Claim, EndReason, Limits, Protocol, Reservation, Session, SessionError, SessionManager,
};
use proptest::prelude::*;

const HOUR: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone)]
enum Op {
    Reserve { user: u8, target: u8 },
    Activate { slot: usize, id: u8 },
    Release { slot: usize },
    CutUser { user: u8 },
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (0..4u8, 0..4u8).prop_map(|(user, target)| Op::Reserve { user, target }),
        3 => (any::<usize>(), 0..12u8).prop_map(|(slot, id)| Op::Activate { slot, id }),
        2 => any::<usize>().prop_map(|slot| Op::Release { slot }),
        1 => (0..4u8).prop_map(|user| Op::CutUser { user }),
    ]
}

fn limits() -> impl Strategy<Value = Limits> {
    (
        0..8usize,
        proptest::option::of(0..4usize),
        proptest::option::of(0..4usize),
    )
        .prop_map(|(max, user, target)| Limits {
            max_per_user: user,
            max_per_target: target,
            ..Limits::new(max)
        })
}

enum Held {
    Reserved(Reservation),
    Open(Session),
}

struct Entry {
    user: u8,
    target: u8,
    id: Option<u8>,
    held: Held,
}

fn claim(user: u8, target: u8) -> Claim {
    Claim {
        protocol: Protocol::Ssh,
        subject: [user; 16],
        login_session: [user; 16],
        target: Arc::from(format!("t{target}")),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn quotas_match_the_model(limits in limits(), ops in proptest::collection::vec(op(), 1..64)) {
        let manager = SessionManager::new(limits, Vec::new());
        let mut held: Vec<Entry> = Vec::new();
        for op in ops {
            match op {
                Op::Reserve { user, target } => {
                    let users = held.iter().filter(|e| e.user == user).count();
                    let targets = held.iter().filter(|e| e.target == target).count();
                    let expected = if held.len() >= limits.max_sessions {
                        Err(SessionError::AgentLimit(limits.max_sessions))
                    } else if limits.max_per_user.is_some_and(|m| users >= m) {
                        Err(SessionError::UserLimit(limits.max_per_user.unwrap_or(0)))
                    } else if limits.max_per_target.is_some_and(|m| targets >= m) {
                        Err(SessionError::TargetLimit(limits.max_per_target.unwrap_or(0)))
                    } else {
                        Ok(())
                    };
                    match manager.reserve(claim(user, target)) {
                        Ok(r) => {
                            prop_assert_eq!(expected, Ok(()));
                            held.push(Entry { user, target, id: None, held: Held::Reserved(r) });
                        }
                        Err(e) => prop_assert_eq!(expected, Err(e)),
                    }
                }
                Op::Activate { slot, id } => {
                    let reserved: Vec<usize> = (0..held.len())
                        .filter(|i| matches!(held[*i].held, Held::Reserved(_)))
                        .collect();
                    if reserved.is_empty() {
                        continue;
                    }
                    let index = reserved[slot % reserved.len()];
                    let duplicate = held.iter().any(|e| e.id == Some(id));
                    let entry = held.remove(index);
                    let Held::Reserved(r) = entry.held else { unreachable!() };
                    match r.activate([id; 16], HOUR) {
                        Ok(session) => {
                            prop_assert!(!duplicate);
                            held.push(Entry { id: Some(id), held: Held::Open(session), ..entry });
                        }
                        Err(e) => {
                            prop_assert!(duplicate);
                            prop_assert_eq!(e, SessionError::DuplicateId);
                        }
                    }
                }
                Op::Release { slot } => {
                    if !held.is_empty() {
                        let entry = held.remove(slot % held.len());
                        if let Held::Open(session) = entry.held {
                            session.finish(EndReason::Closed);
                        }
                    }
                }
                Op::CutUser { user } => {
                    let cut = manager.cut_where(|s| s.claim.subject == [user; 16], EndReason::Revoked);
                    prop_assert_eq!(cut, held.iter().filter(|e| e.user == user).count());
                    for entry in held.iter().filter(|e| e.user == user) {
                        if let Held::Reserved(r) = &entry.held {
                            prop_assert!(r.is_cut());
                        }
                    }
                }
            }
            // Invariants after every step.
            prop_assert_eq!(manager.len(), held.len());
            prop_assert!(manager.len() <= limits.max_sessions);
            let mut users: HashMap<u8, usize> = HashMap::new();
            let mut targets: HashMap<u8, usize> = HashMap::new();
            let mut ids = HashSet::new();
            for e in &held {
                *users.entry(e.user).or_default() += 1;
                *targets.entry(e.target).or_default() += 1;
                if let Some(id) = e.id {
                    prop_assert!(ids.insert(id), "identifier open twice");
                }
            }
            for (user, n) in users {
                prop_assert!(limits.max_per_user.is_none_or(|m| n <= m));
                prop_assert_eq!(manager.count(|s| s.claim.subject == [user; 16]), n);
            }
            for n in targets.values() {
                prop_assert!(limits.max_per_target.is_none_or(|m| *n <= m));
            }
            prop_assert_eq!(manager.count(|s| s.session_id.is_some()), ids.len());
        }
        drop(held);
        prop_assert!(manager.is_empty());
        // Once all is given back, the full bound is available again.
        let all: Vec<_> = (0..limits.max_sessions)
            .map(|i| manager.reserve(claim(u8::try_from(i).unwrap_or(0) % 255, 200)))
            .collect();
        if limits.max_per_user.is_none() && limits.max_per_target.is_none() {
            prop_assert!(all.iter().all(Result::is_ok));
        }
    }
}
