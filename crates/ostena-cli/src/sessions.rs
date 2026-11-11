//! Session tracking and bounded shutdown (ADR-0007): on stop, sessions are
//! told to end, given the configured grace period, then aborted.

use std::future::Future;
use std::sync::Mutex;
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinSet;

/// Outcome of [`Sessions::shutdown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ShutdownReport {
    /// Sessions that ended within the grace period.
    pub finished: usize,
    /// Sessions aborted when the grace period ran out.
    pub aborted: usize,
}

/// Running sessions.
pub(crate) struct Sessions {
    stop: watch::Sender<bool>,
    tasks: Mutex<Option<JoinSet<()>>>,
}

impl Sessions {
    pub(crate) fn new() -> Self {
        Self {
            stop: watch::Sender::new(false),
            tasks: Mutex::new(Some(JoinSet::new())),
        }
    }

    /// Starts a session; it receives `true` on its stop channel when the agent
    /// stops. Returns `false` once shutdown has begun (new sessions refused).
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by the session drivers (next lots)")
    )]
    pub(crate) fn spawn<F, Fut>(&self, session: F) -> bool
    where
        F: FnOnce(watch::Receiver<bool>) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let mut tasks = self
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(set) = tasks.as_mut() else {
            return false;
        };
        while set.try_join_next().is_some() {}
        set.spawn(session(self.stop.subscribe()));
        true
    }

    /// Sessions still running.
    pub(crate) fn active(&self) -> usize {
        let mut tasks = self
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tasks.as_mut().map_or(0, |set| {
            while set.try_join_next().is_some() {}
            set.len()
        })
    }

    /// Refuses new sessions, asks the running ones to end, waits at most
    /// `grace`, then aborts what is left.
    pub(crate) async fn shutdown(&self, grace: Duration) -> ShutdownReport {
        let taken = self
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let Some(mut set) = taken else {
            return ShutdownReport {
                finished: 0,
                aborted: 0,
            };
        };
        let _ = self.stop.send(true);
        let mut finished = 0;
        let drained = tokio::time::timeout(grace, async {
            while set.join_next().await.is_some() {
                finished += 1;
            }
        })
        .await;
        let aborted = if drained.is_ok() { 0 } else { set.len() };
        set.abort_all();
        while set.join_next().await.is_some() {}
        ShutdownReport { finished, aborted }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn cooperative_sessions_finish_and_stubborn_ones_are_aborted() {
        runtime().block_on(async {
            let sessions = Sessions::new();
            for _ in 0..3 {
                assert!(sessions.spawn(|mut stop| async move {
                    let _ = stop.wait_for(|s| *s).await;
                }));
            }
            assert!(sessions.spawn(|_| async {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }));
            assert_eq!(sessions.active(), 4);
            let start = Instant::now();
            let report = sessions.shutdown(Duration::from_millis(200)).await;
            assert_eq!(
                report,
                ShutdownReport {
                    finished: 3,
                    aborted: 1
                }
            );
            // Bounded: the stubborn session did not hold the shutdown.
            assert!(start.elapsed() < Duration::from_secs(2));
            // New sessions are refused afterwards.
            assert!(!sessions.spawn(|_| async {}));
            assert_eq!(sessions.active(), 0);
        });
    }

    #[test]
    fn shutdown_without_sessions_is_immediate() {
        runtime().block_on(async {
            let sessions = Sessions::new();
            let report = sessions.shutdown(Duration::from_secs(30)).await;
            assert_eq!(
                report,
                ShutdownReport {
                    finished: 0,
                    aborted: 0
                }
            );
        });
    }
}
