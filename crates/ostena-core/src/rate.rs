//! Per-agent limits on the SSH requests an agent sends to the core
//! (ADR-0014): one token bucket per agent, held in memory and bounded. A
//! request over the limit is refused without reaching the database; the
//! refusals are logged in aggregate, at most once per [`LOG_WINDOW`] for
//! each agent.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ostena_tunnel::Uuid;

/// Interval between two log lines about the refusals of one agent.
pub const LOG_WINDOW: Duration = Duration::from_secs(60);
/// Most agents followed at once (the agents are enrolled, so this is far
/// above any real count); beyond it, a new agent is refused.
pub const MAX_AGENTS: usize = 65_536;

/// A limit: `burst` requests at once, then one every `refill`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate {
    /// Requests allowed at once.
    pub burst: u32,
    /// Time to earn one more request.
    pub refill: Duration,
}

/// `ssh_grant_request`: 50 at once, then 10 a second, per agent (a gateway
/// relays every SSH connection of its group).
pub const GRANT_REQUESTS: Rate = Rate {
    burst: 50,
    refill: Duration::from_millis(100),
};

/// `ssh_host_key`: 4 at once, then one a minute, per agent (sent when the
/// agent connects and when its key changes).
pub const HOST_KEYS: Rate = Rate {
    burst: 4,
    refill: Duration::from_secs(60),
};

/// Session streams the core refuses (ADR-0016): 8 at once, then one every
/// 15 s, per agent. A refusal is rare (a race with the close of a
/// session); beyond the limit, the tunnel of the agent is closed.
pub const STREAM_REFUSALS: Rate = Rate {
    burst: 8,
    refill: Duration::from_secs(15),
};

/// What [`Limiter::check`] decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Within the limit.
    Allowed,
    /// Over the limit. `log` is the number of refusals to log now (since the
    /// last line for this agent), or `None` until [`LOG_WINDOW`] has passed.
    Refused {
        /// Refusals to log now, if it is time.
        log: Option<u64>,
    },
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: u32,
    /// When the last token was earned (or the bucket filled).
    earned: Instant,
    /// Refusals not logged yet, and when the last line was written.
    refused: u64,
    logged: Option<Instant>,
}

/// The buckets of the agents for one kind of request.
#[derive(Debug)]
pub struct Limiter {
    rate: Rate,
    buckets: Mutex<HashMap<Uuid, Bucket>>,
}

impl Limiter {
    /// A limiter with `rate` per agent.
    pub fn new(rate: Rate) -> Self {
        Self {
            rate,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    fn refill(&self, bucket: &mut Bucket, now: Instant) {
        let refill = self.rate.refill.max(Duration::from_millis(1));
        let elapsed = now.saturating_duration_since(bucket.earned);
        let earned = u32::try_from(elapsed.as_millis() / refill.as_millis()).unwrap_or(u32::MAX);
        if earned == 0 {
            return;
        }
        bucket.tokens = bucket.tokens.saturating_add(earned).min(self.rate.burst);
        bucket.earned = if bucket.tokens == self.rate.burst {
            now
        } else {
            bucket.earned + refill * earned
        };
    }

    /// Takes one request of `agent` at `now`.
    pub fn check(&self, agent: Uuid, now: Instant) -> Decision {
        let Ok(mut buckets) = self.buckets.lock() else {
            return Decision::Refused { log: None };
        };
        if buckets.len() >= MAX_AGENTS && !buckets.contains_key(&agent) {
            // Full buckets are idle agents: forgetting them changes nothing.
            let burst = self.rate.burst;
            let mut idle = Vec::new();
            for (id, bucket) in buckets.iter_mut() {
                self.refill(bucket, now);
                if bucket.tokens == burst && bucket.refused == 0 {
                    idle.push(*id);
                }
            }
            for id in idle {
                buckets.remove(&id);
            }
            if buckets.len() >= MAX_AGENTS {
                return Decision::Refused { log: None };
            }
        }
        let bucket = buckets.entry(agent).or_insert(Bucket {
            tokens: self.rate.burst,
            earned: now,
            refused: 0,
            logged: None,
        });
        self.refill(bucket, now);
        if bucket.tokens > 0 {
            bucket.tokens -= 1;
            return Decision::Allowed;
        }
        bucket.refused += 1;
        let due = bucket
            .logged
            .is_none_or(|t| now.saturating_duration_since(t) >= LOG_WINDOW);
        if !due {
            return Decision::Refused { log: None };
        }
        let count = bucket.refused;
        bucket.refused = 0;
        bucket.logged = Some(now);
        Decision::Refused { log: Some(count) }
    }

    /// Agents followed (for the tests).
    pub fn followed(&self) -> usize {
        self.buckets.lock().map_or(0, |b| b.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RATE: Rate = Rate {
        burst: 3,
        refill: Duration::from_secs(1),
    };

    fn agent(n: u8) -> Uuid {
        Uuid::from_bytes([n; 16])
    }

    #[test]
    fn a_burst_then_one_per_refill() {
        let limiter = Limiter::new(RATE);
        let t0 = Instant::now();
        for _ in 0..3 {
            assert_eq!(limiter.check(agent(1), t0), Decision::Allowed);
        }
        // The first refusal is logged at once.
        assert_eq!(
            limiter.check(agent(1), t0),
            Decision::Refused { log: Some(1) }
        );
        assert_eq!(limiter.check(agent(1), t0), Decision::Refused { log: None });
        // Another agent has its own bucket.
        assert_eq!(limiter.check(agent(2), t0), Decision::Allowed);
        // One more after one refill, not two.
        let t1 = t0 + Duration::from_millis(1500);
        assert_eq!(limiter.check(agent(1), t1), Decision::Allowed);
        assert_eq!(limiter.check(agent(1), t1), Decision::Refused { log: None });
        // The half refill already elapsed counts.
        assert_eq!(
            limiter.check(agent(1), t0 + Duration::from_secs(2)),
            Decision::Allowed
        );
        // Never more than the burst after a long pause.
        let later = t0 + Duration::from_secs(3600);
        for _ in 0..3 {
            assert_eq!(limiter.check(agent(1), later), Decision::Allowed);
        }
        // The refusals since the last line (one at t0, one at t1, this
        // one), once the window has passed.
        assert_eq!(
            limiter.check(agent(1), later),
            Decision::Refused { log: Some(3) }
        );
    }

    #[test]
    fn memory_is_bounded() {
        let limiter = Limiter::new(RATE);
        let t0 = Instant::now();
        for i in 0..MAX_AGENTS {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&(i as u64).to_be_bytes());
            assert_eq!(limiter.check(Uuid::from_bytes(id), t0), Decision::Allowed);
        }
        assert_eq!(limiter.followed(), MAX_AGENTS);
        // Every bucket in use: a new agent is refused.
        assert_eq!(
            limiter.check(agent(0xff), t0),
            Decision::Refused { log: None }
        );
        // Once they are full again (idle), they are forgotten.
        let later = t0 + Duration::from_secs(10);
        assert_eq!(limiter.check(agent(0xff), later), Decision::Allowed);
        assert_eq!(limiter.followed(), 1);
    }
}
