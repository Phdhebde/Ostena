//! The session manager (ADR-0018).
//!
//! Every slot, reserved or open, lives in one table behind one mutex: the
//! check of the three quotas and the taking of the slot are a single step,
//! so that concurrent openings can never exceed a bound (`REG-SEC-06`).
//! The lock is held for a few hash map operations, never across an await
//! nor an observer call; it is not on the data path (the relay only
//! touches an atomic flag, [`Activity::touch`]).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::sync::{Notify, watch};
use tokio::time::Instant;

use crate::error::SessionError;

/// The protocol of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// Native SSH (ADR-0010).
    Ssh,
    /// RDP, native or through the browser.
    Rdp,
    /// VNC.
    Vnc,
    /// A web application.
    Web,
}

impl Protocol {
    /// Name in events.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Rdp => "rdp",
            Self::Vnc => "vnc",
            Self::Web => "web",
        }
    }
}

/// Bounds and delays of the sessions of an agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Sessions of the agent at once, reserved or open, all protocols.
    pub max_sessions: usize,
    /// Sessions of one user at once; `None`: only the agent bound.
    pub max_per_user: Option<usize>,
    /// Sessions towards one target at once; `None`: only the agent bound.
    pub max_per_target: Option<usize>,
    /// A session without traffic for this long is cut; `None`: never.
    pub idle_timeout: Option<Duration>,
    /// Ceiling of the length of a session, whatever the core allows;
    /// `None`: the core's length only.
    pub max_duration: Option<Duration>,
}

impl Limits {
    /// `max_sessions` at once, no other bound.
    pub fn new(max_sessions: usize) -> Self {
        Self {
            max_sessions,
            max_per_user: None,
            max_per_target: None,
            idle_timeout: None,
            max_duration: None,
        }
    }
}

/// Who asks for a session, towards what: the keys of the quotas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// Protocol.
    pub protocol: Protocol,
    /// The user (identifier given by the core).
    pub subject: [u8; 16],
    /// Their login session, cut on its revocation.
    pub login_session: [u8; 16],
    /// The target, as named in the request (resource name).
    pub target: Arc<str>,
}

/// A slot, reserved or open, as observers and cut predicates see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    /// The claim.
    pub claim: Claim,
    /// The identifier given by the core, once open.
    pub session_id: Option<[u8; 16]>,
}

/// Why a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndReason {
    /// The user or the target closed it.
    Closed,
    /// Its login session or its right was revoked.
    Revoked,
    /// Its maximum length was reached.
    Expired,
    /// No traffic for the idle delay.
    Idle,
    /// The agent stopped.
    Shutdown,
    /// The relay, the target or the recording failed.
    Error,
}

impl EndReason {
    /// Name in events.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Idle => "idle",
            Self::Shutdown => "shutdown",
            Self::Error => "error",
        }
    }
}

/// How a session ended, for observers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ending {
    /// Why.
    pub reason: EndReason,
    /// How long it was open.
    pub duration: Duration,
}

/// Told of the life of the sessions, for the audit and the recording.
/// Called outside the lock of the manager, on the task that opens or ends
/// the session: an observer must not block.
pub trait Observer: Send + Sync + 'static {
    /// A session opened (identifier given).
    fn opened(&self, _session: &SessionInfo) {}
    /// A slot or an identifier was refused.
    fn refused(&self, _claim: &Claim, _error: SessionError) {}
    /// An open session ended (its slot is released right after).
    fn closed(&self, _session: &SessionInfo, _ending: Ending) {}
}

/// What a slot shares with its holder.
struct SlotShared {
    /// The first cause of the end; `None` while the session may run.
    cut: watch::Sender<Option<EndReason>>,
    /// Traffic since the last idle check.
    active: AtomicBool,
}

impl SlotShared {
    /// Records `reason` unless a cause is already recorded; whether it was.
    fn cut(&self, reason: EndReason) -> bool {
        self.cut.send_if_modified(|current| {
            if current.is_none() {
                *current = Some(reason);
                true
            } else {
                false
            }
        })
    }
}

struct Slot {
    info: SessionInfo,
    shared: Arc<SlotShared>,
}

#[derive(Default)]
struct State {
    stopping: bool,
    next: u64,
    slots: HashMap<u64, Slot>,
    ids: HashSet<[u8; 16]>,
    users: HashMap<[u8; 16], usize>,
    targets: HashMap<Arc<str>, usize>,
}

struct Inner {
    limits: Limits,
    state: Mutex<State>,
    observers: Vec<Arc<dyn Observer>>,
    drained: Notify,
}

impl Inner {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn refused(&self, claim: &Claim, error: SessionError) {
        for observer in &self.observers {
            observer.refused(claim, error);
        }
    }
}

/// The sessions of an agent. Cheap to clone: one table shared by every
/// protocol.
#[derive(Clone)]
pub struct SessionManager {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for SessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionManager")
            .field("limits", &self.inner.limits)
            .field("slots", &self.len())
            .finish_non_exhaustive()
    }
}

impl SessionManager {
    /// A manager within `limits`, telling `observers`.
    pub fn new(limits: Limits, observers: Vec<Arc<dyn Observer>>) -> Self {
        Self {
            inner: Arc::new(Inner {
                limits,
                state: Mutex::new(State::default()),
                observers,
                drained: Notify::new(),
            }),
        }
    }

    /// The bounds and delays.
    pub fn limits(&self) -> Limits {
        self.inner.limits
    }

    /// Reserves a slot for `claim`, within the three quotas, in one step.
    /// Released when the [`Reservation`] (or the [`Session`] it becomes) is
    /// dropped.
    ///
    /// # Errors
    ///
    /// `SES-E001` to `SES-E003` (a quota), `SES-E005` (stopping).
    pub fn reserve(&self, claim: Claim) -> Result<Reservation, SessionError> {
        let limits = self.inner.limits;
        let taken = {
            let mut state = self.inner.state();
            let user = state.users.get(&claim.subject).copied().unwrap_or(0);
            let target = state.targets.get(&claim.target).copied().unwrap_or(0);
            if state.stopping {
                Err(SessionError::ShuttingDown)
            } else if state.slots.len() >= limits.max_sessions {
                Err(SessionError::AgentLimit(limits.max_sessions))
            } else if let Some(max) = limits.max_per_user.filter(|m| user >= *m) {
                Err(SessionError::UserLimit(max))
            } else if let Some(max) = limits.max_per_target.filter(|m| target >= *m) {
                Err(SessionError::TargetLimit(max))
            } else {
                let (cut, _) = watch::channel(None);
                let shared = Arc::new(SlotShared {
                    cut,
                    active: AtomicBool::new(false),
                });
                let key = state.next;
                state.next += 1;
                *state.users.entry(claim.subject).or_insert(0) += 1;
                *state.targets.entry(claim.target.clone()).or_insert(0) += 1;
                state.slots.insert(
                    key,
                    Slot {
                        info: SessionInfo {
                            claim: claim.clone(),
                            session_id: None,
                        },
                        shared: shared.clone(),
                    },
                );
                Ok((key, shared))
            }
        };
        match taken {
            Ok((key, shared)) => Ok(Reservation {
                guard: SlotGuard {
                    inner: self.inner.clone(),
                    key,
                },
                shared,
                claim,
            }),
            Err(error) => {
                self.inner.refused(&claim, error);
                Err(error)
            }
        }
    }

    /// [`reserve`](Self::reserve) then [`Reservation::activate`].
    ///
    /// # Errors
    ///
    /// `SES-E001` to `SES-E005`.
    pub fn open(
        &self,
        claim: Claim,
        session_id: [u8; 16],
        max_duration: Duration,
    ) -> Result<Session, SessionError> {
        self.reserve(claim)?.activate(session_id, max_duration)
    }

    /// Cuts every slot, reserved or open, that `select` designates, for
    /// `reason` (unless it is already ending for another one); returns how
    /// many were designated. A reserved slot ends as soon as it is open.
    pub fn cut_where(
        &self,
        mut select: impl FnMut(&SessionInfo) -> bool,
        reason: EndReason,
    ) -> usize {
        let state = self.inner.state();
        let mut count = 0;
        for slot in state.slots.values().filter(|s| select(&s.info)) {
            slot.shared.cut(reason);
            count += 1;
        }
        count
    }

    /// Slots, reserved or open, that `select` designates.
    pub fn count(&self, mut select: impl FnMut(&SessionInfo) -> bool) -> usize {
        self.inner
            .state()
            .slots
            .values()
            .filter(|s| select(&s.info))
            .count()
    }

    /// Slots, reserved or open.
    pub fn len(&self) -> usize {
        self.inner.state().slots.len()
    }

    /// No slot.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Refuses new slots (`SES-E005`) and cuts every slot for
    /// [`EndReason::Shutdown`]; returns how many.
    pub fn shutdown(&self) -> usize {
        self.inner.state().stopping = true;
        self.cut_where(|_| true, EndReason::Shutdown)
    }

    /// Waits until no slot is left.
    pub async fn drained(&self) {
        loop {
            let notified = self.inner.drained.notified();
            let mut notified = std::pin::pin!(notified);
            notified.as_mut().enable();
            if self.is_empty() {
                return;
            }
            notified.await;
        }
    }
}

/// Releases a slot when dropped.
struct SlotGuard {
    inner: Arc<Inner>,
    key: u64,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        let empty = {
            let mut state = self.inner.state();
            if let Some(slot) = state.slots.remove(&self.key) {
                if let Some(id) = slot.info.session_id {
                    state.ids.remove(&id);
                }
                decrement(&mut state.users, &slot.info.claim.subject);
                decrement(&mut state.targets, &slot.info.claim.target);
            }
            state.slots.is_empty()
        };
        if empty {
            self.inner.drained.notify_waiters();
        }
    }
}

fn decrement<K: Eq + std::hash::Hash + ?Sized, Q: std::borrow::Borrow<K> + Eq + std::hash::Hash>(
    counts: &mut HashMap<Q, usize>,
    key: &K,
) {
    if let Some(count) = counts.get_mut(key) {
        *count -= 1;
        if *count == 0 {
            counts.remove(key);
        }
    }
}

/// A slot taken before the core decides; released when dropped.
pub struct Reservation {
    guard: SlotGuard,
    shared: Arc<SlotShared>,
    claim: Claim,
}

impl std::fmt::Debug for Reservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reservation")
            .field("claim", &self.claim)
            .finish_non_exhaustive()
    }
}

impl Reservation {
    /// The claim.
    pub fn claim(&self) -> &Claim {
        &self.claim
    }

    /// Whether the slot was cut meanwhile (revocation, stop).
    pub fn is_cut(&self) -> bool {
        self.shared.cut.borrow().is_some()
    }

    /// Opens the session `session_id` (given by the core) on this slot, for
    /// at most `max_duration` (and the agent ceiling). A cut that arrived
    /// while reserved is kept: [`Session::ended`] returns it at once.
    ///
    /// # Errors
    ///
    /// `SES-E004`: a session with this identifier is already open; the slot
    /// is released.
    pub fn activate(
        self,
        session_id: [u8; 16],
        max_duration: Duration,
    ) -> Result<Session, SessionError> {
        let inner = self.guard.inner.clone();
        let info = {
            let mut state = inner.state();
            // The slot lives as long as its guard, held here.
            if state.ids.contains(&session_id) || !state.slots.contains_key(&self.guard.key) {
                None
            } else {
                state.ids.insert(session_id);
                state.slots.get_mut(&self.guard.key).map(|slot| {
                    slot.info.session_id = Some(session_id);
                    slot.info.clone()
                })
            }
        };
        let Some(info) = info else {
            inner.refused(&self.claim, SessionError::DuplicateId);
            return Err(SessionError::DuplicateId);
        };
        let limits = inner.limits;
        let length = limits
            .max_duration
            .map_or(max_duration, |ceiling| ceiling.min(max_duration));
        let now = Instant::now();
        for observer in &inner.observers {
            observer.opened(&info);
        }
        let cut = self.shared.cut.subscribe();
        Ok(Session {
            guard: self.guard,
            shared: self.shared,
            cut,
            info,
            opened: now,
            deadline: now.checked_add(length).unwrap_or_else(far_future),
            idle: limits.idle_timeout,
            last_active: now,
            reason: None,
        })
    }
}

/// About thirty years from now: a length that overflows the clock.
fn far_future() -> Instant {
    Instant::now() + Duration::from_hours(24 * 365 * 30)
}

/// Marks the traffic of a session, for its idle delay. Cheap to clone and
/// to call on every packet: one relaxed atomic store.
#[derive(Clone)]
pub struct Activity(Arc<SlotShared>);

impl std::fmt::Debug for Activity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Activity")
    }
}

impl Activity {
    /// Traffic now.
    pub fn touch(&self) {
        self.0.active.store(true, Ordering::Relaxed);
    }
}

/// An open session. Dropping it tells the observers that it ended and
/// releases its slot.
pub struct Session {
    guard: SlotGuard,
    shared: Arc<SlotShared>,
    cut: watch::Receiver<Option<EndReason>>,
    info: SessionInfo,
    opened: Instant,
    deadline: Instant,
    idle: Option<Duration>,
    last_active: Instant,
    reason: Option<EndReason>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// What observers see of it.
    pub fn info(&self) -> &SessionInfo {
        &self.info
    }

    /// When its maximum length is reached.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    /// The handle the relay marks the traffic with.
    pub fn activity(&self) -> Activity {
        Activity(self.shared.clone())
    }

    /// Asks the session to end for `reason` (unless it is already ending
    /// for another one).
    pub fn cut(&self, reason: EndReason) {
        self.shared.cut(reason);
    }

    /// Waits until the session must end, and tells why: a cut (revocation,
    /// stop, lost recording), its maximum length, or its idle delay. The
    /// first cause wins and is kept. Cancel safe.
    pub async fn ended(&mut self) -> EndReason {
        let period = self
            .idle
            .map(|idle| (idle / 8).max(Duration::from_millis(50)));
        loop {
            if let Some(reason) = *self.cut.borrow_and_update() {
                self.reason = Some(reason);
                return reason;
            }
            let now = Instant::now();
            if now >= self.deadline {
                self.end(EndReason::Expired);
                continue;
            }
            let mut wake = self.deadline;
            if let (Some(idle), Some(period)) = (self.idle, period) {
                if self.shared.active.swap(false, Ordering::Relaxed) {
                    self.last_active = now;
                }
                if now.saturating_duration_since(self.last_active) >= idle {
                    self.end(EndReason::Idle);
                    continue;
                }
                wake = wake.min(now + period);
            }
            // The sender lives in `shared`, held here: `changed` fails never.
            let _ = tokio::time::timeout_at(wake, self.cut.changed()).await;
        }
    }

    fn end(&self, reason: EndReason) {
        self.shared.cut(reason);
    }

    /// Ends the session for `reason`, unless a cause was already recorded
    /// (the first one is kept), then releases it.
    pub fn finish(mut self, reason: EndReason) {
        self.shared.cut(reason);
        self.reason = *self.cut.borrow();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let reason = self
            .reason
            .or(*self.cut.borrow())
            .unwrap_or(EndReason::Closed);
        let ending = Ending {
            reason,
            duration: self.opened.elapsed(),
        };
        for observer in &self.guard.inner.observers {
            observer.closed(&self.info, ending);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use super::*;

    fn claim(user: u8, target: &str) -> Claim {
        Claim {
            protocol: Protocol::Ssh,
            subject: [user; 16],
            login_session: [user; 16],
            target: Arc::from(target),
        }
    }

    fn id(n: u8) -> [u8; 16] {
        [n; 16]
    }

    const HOUR: Duration = Duration::from_secs(3600);

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
    }

    #[derive(Default)]
    struct Recorder(StdMutex<Vec<String>>);

    impl Observer for Recorder {
        fn opened(&self, s: &SessionInfo) {
            self.0
                .lock()
                .unwrap()
                .push(format!("opened {}", s.session_id.unwrap()[0]));
        }
        fn refused(&self, _: &Claim, e: SessionError) {
            self.0.lock().unwrap().push(format!("refused {}", e.code()));
        }
        fn closed(&self, s: &SessionInfo, e: Ending) {
            self.0.lock().unwrap().push(format!(
                "closed {} {}",
                s.session_id.unwrap()[0],
                e.reason.as_str()
            ));
        }
    }

    #[test]
    fn quotas_of_the_agent_the_user_and_the_target() {
        let limits = Limits {
            max_per_user: Some(2),
            max_per_target: Some(3),
            ..Limits::new(4)
        };
        let m = SessionManager::new(limits, Vec::new());
        let a1 = m.reserve(claim(1, "a")).unwrap();
        let a2 = m.reserve(claim(1, "b")).unwrap();
        assert_eq!(
            m.reserve(claim(1, "c")).unwrap_err(),
            SessionError::UserLimit(2)
        );
        let b1 = m.reserve(claim(2, "a")).unwrap();
        let c1 = m.reserve(claim(3, "a")).unwrap();
        assert_eq!(
            m.reserve(claim(4, "z")).unwrap_err(),
            SessionError::AgentLimit(4)
        );
        drop(a2);
        assert_eq!(
            m.reserve(claim(4, "a")).unwrap_err(),
            SessionError::TargetLimit(3)
        );
        let d1 = m.reserve(claim(4, "b")).unwrap();
        assert_eq!(m.len(), 4);
        drop((a1, b1, c1, d1));
        assert!(m.is_empty());
        let state = m.inner.state();
        assert!(state.users.is_empty() && state.targets.is_empty() && state.ids.is_empty());
    }

    #[test]
    fn duplicate_identifiers_are_refused_and_their_slot_released() {
        let recorder = Arc::new(Recorder::default());
        let m = SessionManager::new(Limits::new(8), vec![recorder.clone()]);
        let first = m.open(claim(1, "a"), id(7), HOUR).unwrap();
        assert_eq!(
            m.open(claim(2, "b"), id(7), HOUR).unwrap_err(),
            SessionError::DuplicateId
        );
        assert_eq!(m.len(), 1);
        drop(first);
        // Released with its session: the identifier is free again.
        let again = m.open(claim(2, "b"), id(7), HOUR).unwrap();
        again.finish(EndReason::Revoked);
        assert_eq!(
            *recorder.0.lock().unwrap(),
            [
                "opened 7",
                "refused SES-E004",
                "closed 7 closed",
                "opened 7",
                "closed 7 revoked"
            ]
        );
    }

    #[test]
    fn a_cut_while_reserved_is_seen_once_open() {
        runtime().block_on(async {
            let m = SessionManager::new(Limits::new(8), Vec::new());
            let r = m.reserve(claim(1, "a")).unwrap();
            let other = m.reserve(claim(2, "a")).unwrap();
            let cut = m.cut_where(|s| s.claim.login_session == [1; 16], EndReason::Revoked);
            assert_eq!(cut, 1);
            assert!(r.is_cut() && !other.is_cut());
            let mut s = r.activate(id(1), HOUR).unwrap();
            assert_eq!(s.ended().await, EndReason::Revoked);
            // The first cause is kept.
            s.cut(EndReason::Shutdown);
            assert_eq!(s.ended().await, EndReason::Revoked);
        });
    }

    #[test]
    fn maximum_length_and_agent_ceiling() {
        runtime().block_on(async {
            let limits = Limits {
                max_duration: Some(Duration::from_millis(60)),
                ..Limits::new(8)
            };
            let m = SessionManager::new(limits, Vec::new());
            let mut s = m.open(claim(1, "a"), id(1), HOUR).unwrap();
            let start = std::time::Instant::now();
            assert_eq!(s.ended().await, EndReason::Expired);
            assert!(start.elapsed() >= Duration::from_millis(60));
            assert!(start.elapsed() < Duration::from_secs(5));
            let mut s = m
                .open(claim(1, "a"), id(2), Duration::from_millis(20))
                .unwrap();
            assert_eq!(s.ended().await, EndReason::Expired);
        });
    }

    #[test]
    fn idle_delay_is_pushed_back_by_traffic() {
        runtime().block_on(async {
            let limits = Limits {
                idle_timeout: Some(Duration::from_millis(400)),
                ..Limits::new(8)
            };
            let m = SessionManager::new(limits, Vec::new());
            let mut s = m.open(claim(1, "a"), id(1), HOUR).unwrap();
            let activity = s.activity();
            let start = std::time::Instant::now();
            tokio::spawn(async move {
                for _ in 0..8 {
                    activity.touch();
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            });
            let reason = s.ended().await;
            assert_eq!(reason, EndReason::Idle);
            // Traffic for 800 ms, then 400 ms of silence (+ one check).
            let elapsed = start.elapsed();
            assert!(elapsed >= Duration::from_millis(1100), "{elapsed:?}");
            assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");
        });
    }

    #[test]
    fn shutdown_cuts_refuses_and_drains() {
        runtime().block_on(async {
            let m = SessionManager::new(Limits::new(8), Vec::new());
            let mut s = m.open(claim(1, "a"), id(1), HOUR).unwrap();
            let r = m.reserve(claim(2, "a")).unwrap();
            assert_eq!(m.shutdown(), 2);
            assert_eq!(
                m.reserve(claim(3, "a")).unwrap_err(),
                SessionError::ShuttingDown
            );
            assert_eq!(s.ended().await, EndReason::Shutdown);
            let waiter = m.clone();
            let drained = tokio::spawn(async move { waiter.drained().await });
            tokio::task::yield_now().await;
            assert!(!drained.is_finished());
            drop(s);
            drop(r);
            tokio::time::timeout(Duration::from_secs(5), drained)
                .await
                .unwrap()
                .unwrap();
        });
    }

    #[test]
    fn count_by_protocol_and_state() {
        let m = SessionManager::new(Limits::new(8), Vec::new());
        let _open = m.open(claim(1, "a"), id(1), HOUR).unwrap();
        let mut rdp = claim(2, "a");
        rdp.protocol = Protocol::Rdp;
        let _reserved = m.reserve(rdp).unwrap();
        assert_eq!(m.count(|s| s.claim.protocol == Protocol::Ssh), 1);
        assert_eq!(m.count(|s| s.session_id.is_some()), 1);
        assert_eq!(m.len(), 2);
    }
}
