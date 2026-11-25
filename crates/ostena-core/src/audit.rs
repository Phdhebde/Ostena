//! The audit chain of the core in PostgreSQL (ADR-0012).
//!
//! Records and heads use the formats of `ostena-audit`; this module stores
//! them, signs heads and exports the chain.
//!
//! # Writing records
//!
//! Every append takes the transaction-level advisory lock
//! [`AUDIT_LOCK_KEY`], reads the tip, and inserts the next record. The lock
//! is held until the transaction ends, so appends are serialised in commit
//! order and the seq never has a gap. Rules for the callers:
//!
//! - the transaction runs at the default `READ COMMITTED` level, so the tip
//!   read after the lock is the committed one;
//! - the append is the **last statement before `COMMIT`**: the lock then
//!   blocks other writers only for the time of the commit.
//!
//! Three classes of events (ADR-0012):
//!
//! - **granting** ([`append`]): the record is written in the transaction of
//!   the change; if it cannot be written, the change is rolled back and
//!   refused (`CORE-E010`). Enrolment, renewal, token issuance and
//!   consumption, start of the core.
//! - **protective** ([`append_protective`]): the record is written in a
//!   savepoint; if it cannot be written, the change still commits, the
//!   failure is logged (`audit.append_failed`) and counted. Revocation, a
//!   refused token.
//! - **best effort** ([`Recorder::emit`]): queued and written by one task,
//!   in batches; events that cannot be queued or written are counted, then
//!   reported by an `audit.events_lost` record once the chain is writable.
//!
//! # Heads
//!
//! [`HeadSigner`] signs the tip under the same lock, after checking the
//! segment since the previous head with the verifier of `ostena-audit`, and
//! the records the core itself appended since. A broken segment stops the
//! signer (`audit.chain_broken`, `CORE-E011`) until an administrator
//! acknowledges the break ([`acknowledge_break`]).

use std::collections::VecDeque;
use std::fmt;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ostena_audit::event::Appended as Encoded;
use ostena_audit::{
    ActorKind, ChainId, ChainTip, Digest, Event, EventKind, ExportWriter, Head, Kid, Options,
    Outcome, Record, Report, TrustedKeys, UnsignedHead, Value, Verifier, field, record_hash,
    unix_now_ms,
};
use ostena_common::config::CoreAuditConfig;
use ostena_crypto::p256::{SigningKey, VerifyingKey};
use sqlx::{Acquire, PgConnection, PgPool, Postgres, Transaction};
use tokio::sync::{Notify, mpsc};

use crate::error::CoreError;

/// Key of the transaction-level advisory lock of the chain. sqlx locks its
/// migrations with `0x3d32ad9e × CRC-32(database name)`, always below
/// 2^62: this key, above it, can never collide.
pub const AUDIT_LOCK_KEY: i64 = 0x6f73_7465_6e61_4155;
/// Rows read per query when streaming the chain.
pub const PAGE: i64 = 500;
/// Capacity of the best-effort queue.
pub const QUEUE_CAPACITY: usize = 256;
/// Largest batch written by the best-effort writer in one transaction.
const BATCH: usize = 64;
/// Attempts of the best-effort writer before it counts a batch as lost.
const WRITE_ATTEMPTS: u32 = 6;
/// Shortest interval between two heads signed by the loop.
const MIN_HEAD_INTERVAL: Duration = Duration::from_secs(1);
/// A heartbeat head is due this much before the heartbeat ends.
const HEARTBEAT_SLACK_MS: u64 = 1_000;
/// Actor of the events of the core itself.
pub const CORE_ACTOR: &str = "core";

/// A transaction of the core.
pub type Tx<'c> = Transaction<'c, Postgres>;

/// A record written to the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Appended {
    /// Its seq.
    pub seq: u64,
    /// Its hash.
    pub hash: Digest,
}

fn i64_of(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn u64_of(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

fn digest(bytes: &[u8]) -> Option<Digest> {
    bytes.try_into().ok()
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "used as map_err(write_error)"
)]
fn write_error(e: sqlx::Error) -> CoreError {
    CoreError::AuditWrite(e.to_string())
}

fn chain_error(message: impl Into<String>) -> CoreError {
    CoreError::AuditChain(message.into())
}

async fn lock(conn: &mut PgConnection) -> Result<(), CoreError> {
    sqlx::query!("SELECT pg_advisory_xact_lock($1)", AUDIT_LOCK_KEY)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(write_error)
}

/// The tip of the chain, checked against its body; `None` for an empty
/// chain.
async fn read_tip(conn: &mut PgConnection) -> Result<Option<ChainTip>, CoreError> {
    let Some(row) =
        sqlx::query!("SELECT seq, body, hash FROM audit_record ORDER BY seq DESC LIMIT 1")
            .fetch_optional(&mut *conn)
            .await
            .map_err(write_error)?
    else {
        return Ok(None);
    };
    let record = Record::decode(&row.body).map_err(|e| {
        chain_error(format!(
            "dernier enregistrement (n° {}) illisible : {e}",
            row.seq
        ))
    })?;
    let hash = record_hash(&row.body);
    if record.seq != u64_of(row.seq) || digest(&row.hash) != Some(hash) {
        return Err(chain_error(format!(
            "dernier enregistrement (n° {}) incohérent avec son contenu",
            row.seq
        )));
    }
    Ok(Some(ChainTip {
        chain_id: record.chain_id,
        seq: record.seq,
        hash,
    }))
}

async fn insert(
    conn: &mut PgConnection,
    kind: EventKind,
    encoded: &Encoded,
) -> Result<(), CoreError> {
    sqlx::query!(
        "INSERT INTO audit_record (seq, body, hash, event) VALUES ($1, $2, $3, $4)",
        i64_of(encoded.seq),
        &encoded.body,
        &encoded.hash[..],
        kind.name(),
    )
    .execute(&mut *conn)
    .await
    .map(|_| ())
    .map_err(write_error)
}

fn encode(tip: &mut ChainTip, event: Event) -> Result<(EventKind, Encoded), CoreError> {
    let kind = event.kind();
    tip.append(event, unix_now_ms())
        .map(|encoded| (kind, encoded))
        .map_err(|e| CoreError::AuditWrite(e.to_string()))
}

/// Starts a new chain: a random identifier and `audit.chain_started` at
/// seq 1. The lock must be held.
async fn genesis(conn: &mut PgConnection) -> Result<ChainTip, CoreError> {
    let chain_id = ChainId::random().map_err(|e| CoreError::AuditWrite(e.to_string()))?;
    let mut tip = ChainTip::empty(chain_id);
    let event = Event::new(
        EventKind::AuditChainStarted,
        Outcome::Success,
        ActorKind::Core,
        CORE_ACTOR,
    )
    .text(field::VERSION, env!("CARGO_PKG_VERSION"));
    let (kind, encoded) = encode(&mut tip, event)?;
    insert(conn, kind, &encoded).await?;
    // Warn level: a new chain where one was expected must be visible.
    tracing::warn!(
        event = "audit.chain_started",
        chain = %chain_id,
        "nouvelle chaîne d'audit créée : attendu à la première installation seulement"
    );
    Ok(tip)
}

/// Message of an append on an empty chain: only `ostena core run`
/// ([`ensure_genesis`]) starts a chain, never an append, so that wiped
/// tables are never silently replaced by a fresh chain.
pub const NOT_INITIALISED: &str = "chaîne d'audit non initialisée : démarrez le core";

/// Appends `events` in order under the lock; refuses an empty chain.
async fn append_locked(
    conn: &mut PgConnection,
    events: Vec<Event>,
) -> Result<Vec<Appended>, CoreError> {
    lock(conn).await?;
    let mut tip = read_tip(conn)
        .await?
        .ok_or_else(|| CoreError::AuditWrite(NOT_INITIALISED.into()))?;
    let mut out = Vec::with_capacity(events.len());
    for event in events {
        let (kind, encoded) = encode(&mut tip, event)?;
        insert(conn, kind, &encoded).await?;
        out.push(Appended {
            seq: encoded.seq,
            hash: encoded.hash,
        });
    }
    Ok(out)
}

/// Appends a **granting** event in `tx`: if it fails, the caller rolls back
/// and refuses. Must be the last statement before the commit (see the
/// module documentation).
///
/// # Errors
///
/// [`CoreError::AuditWrite`] (also for a chain not started yet:
/// [`NOT_INITIALISED`]), or [`CoreError::AuditChain`] if the tip does not
/// match its content.
pub async fn append(tx: &mut Tx<'_>, event: Event) -> Result<Appended, CoreError> {
    let mut appended = append_locked(tx, vec![event]).await?;
    appended
        .pop()
        .ok_or_else(|| CoreError::AuditWrite("aucun enregistrement écrit".into()))
}

/// Appends several granting events in `tx`, in order (same rules as
/// [`append`]).
///
/// # Errors
///
/// As [`append`].
pub async fn append_many(tx: &mut Tx<'_>, events: Vec<Event>) -> Result<Vec<Appended>, CoreError> {
    append_locked(tx, events).await
}

static PROTECTIVE_FAILURES: AtomicU64 = AtomicU64::new(0);

/// Protective records that could not be written since the process started.
pub fn protective_failures() -> u64 {
    PROTECTIVE_FAILURES.load(Ordering::Relaxed)
}

/// Appends a **protective** event in a savepoint of `tx`: the change it
/// audits commits even if the record cannot be written. Such a failure is
/// logged (`audit.append_failed`, error level) and counted
/// ([`protective_failures`]). Must be the last statement before the commit.
pub async fn append_protective(tx: &mut Tx<'_>, event: Event) -> Option<Appended> {
    let kind = event.kind();
    let failed = |e: &dyn fmt::Display| {
        PROTECTIVE_FAILURES.fetch_add(1, Ordering::Relaxed);
        tracing::error!(
            event = "audit.append_failed",
            audited = kind.name(),
            code = "CORE-E010",
            "enregistrement d'audit protecteur non écrit, le changement est conservé : {e}"
        );
    };
    let mut savepoint = match (&mut *tx).begin().await {
        Ok(savepoint) => savepoint,
        Err(e) => {
            failed(&e);
            return None;
        }
    };
    match append(&mut savepoint, event).await {
        Ok(appended) => match savepoint.commit().await {
            Ok(()) => Some(appended),
            Err(e) => {
                failed(&e);
                None
            }
        },
        Err(e) => {
            let _ = savepoint.rollback().await;
            failed(&e);
            None
        }
    }
}

/// The administrator behind `tx`: `system_user` (`peer:<account>` in
/// production, `trust` when the server reports none), at most 128 bytes.
///
/// # Errors
///
/// [`CoreError::Database`].
pub async fn admin_actor(tx: &mut Tx<'_>) -> Result<String, CoreError> {
    let user = sqlx::query_scalar!(r#"SELECT system_user AS "user""#)
        .fetch_one(&mut **tx)
        .await?;
    let mut actor = user.unwrap_or_else(|| "trust".into());
    actor.retain(|c| !c.is_control());
    let mut end = actor.len().min(ostena_audit::record::MAX_ACTOR_LEN);
    while !actor.is_char_boundary(end) {
        end -= 1;
    }
    actor.truncate(end);
    Ok(actor)
}

/// Starts the chain if it is empty (`audit.chain_started` at seq 1) and
/// returns its identifier. Idempotent, and safe when several processes
/// call it together (advisory lock). Only `ostena core run` calls it.
///
/// # Errors
///
/// [`CoreError::AuditChain`] if heads exist without any record (the records
/// were removed), [`CoreError::AuditWrite`].
pub async fn ensure_genesis(pool: &PgPool) -> Result<ChainId, CoreError> {
    let mut tx = pool.begin().await.map_err(write_error)?;
    lock(&mut tx).await?;
    let tip = if let Some(tip) = read_tip(&mut tx).await? {
        tip
    } else {
        let heads = sqlx::query_scalar!(r#"SELECT count(*) AS "n!" FROM audit_head"#)
            .fetch_one(&mut *tx)
            .await?;
        if heads > 0 {
            return Err(chain_error(format!(
                "{heads} tête(s) signée(s) mais aucun enregistrement : les enregistrements \
                 ont été supprimés, aucune nouvelle chaîne n'est créée"
            )));
        }
        genesis(&mut tx).await?
    };
    tx.commit().await.map_err(write_error)?;
    Ok(tip.chain_id)
}

// ------------------------------------------------------------- recorder

#[derive(Debug, Default, Clone, Copy)]
struct Lost {
    count: u64,
    first_ms: u64,
    last_ms: u64,
}

impl Lost {
    fn add(&mut self, count: u64, first_ms: u64, last_ms: u64) {
        if count == 0 {
            return;
        }
        if self.count == 0 {
            self.first_ms = first_ms;
        } else {
            self.first_ms = self.first_ms.min(first_ms);
        }
        self.last_ms = self.last_ms.max(last_ms);
        self.count = self.count.saturating_add(count);
    }

    fn event(self) -> Event {
        Event::new(
            EventKind::AuditEventsLost,
            Outcome::Failure,
            ActorKind::Core,
            CORE_ACTOR,
        )
        .u64(field::LOST_COUNT, self.count)
        .u64(field::FIRST_MS, self.first_ms)
        .u64(field::LAST_MS, self.last_ms)
    }
}

/// What links the writers of the chain to the head signer: the best-effort
/// queue, the records the core appended since the last head, and the wake
/// up of the signer.
pub struct Recorder {
    queue: mpsc::Sender<Event>,
    receiver: Mutex<Option<mpsc::Receiver<Event>>>,
    pending: AtomicUsize,
    lost: Mutex<Lost>,
    wake: Notify,
    critical: AtomicBool,
    own: Mutex<VecDeque<Appended>>,
    own_capacity: AtomicUsize,
}

impl fmt::Debug for Recorder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Recorder")
            .field("pending", &self.pending.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Default for Recorder {
    fn default() -> Self {
        let (queue, receiver) = mpsc::channel(QUEUE_CAPACITY);
        Self {
            queue,
            receiver: Mutex::new(Some(receiver)),
            pending: AtomicUsize::new(0),
            lost: Mutex::new(Lost::default()),
            wake: Notify::new(),
            critical: AtomicBool::new(false),
            own: Mutex::new(VecDeque::new()),
            own_capacity: AtomicUsize::new(1000),
        }
    }
}

impl Recorder {
    /// A recorder with an empty queue.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records written by a granting or protective append of the core:
    /// the signer checks them before its next head, which it signs soon.
    pub fn critical(&self, appended: &[Appended]) {
        if let Ok(mut own) = self.own.lock() {
            let capacity = self.own_capacity.load(Ordering::Relaxed).max(1);
            for a in appended {
                if own.len() >= capacity {
                    own.pop_front();
                }
                own.push_back(*a);
            }
        }
        self.critical.store(true, Ordering::Release);
        self.wake.notify_one();
    }

    /// Another process changed the chain (a notification): the signer
    /// looks at the tip soon.
    pub fn wake(&self) {
        self.critical.store(true, Ordering::Release);
        self.wake.notify_one();
    }

    /// Queues a **best-effort** event. If the queue is full or closed, the
    /// event is counted as lost.
    pub fn emit(&self, event: Event) {
        let kind = event.kind();
        // Counted before it is queued: the writer may write it at once.
        self.pending.fetch_add(1, Ordering::AcqRel);
        if self.queue.try_send(event).is_err() {
            self.pending.fetch_sub(1, Ordering::AcqRel);
            let now = unix_now_ms();
            if let Ok(mut lost) = self.lost.lock() {
                lost.add(1, now, now);
            }
            tracing::warn!(
                event = "audit.event_dropped",
                audited = kind.name(),
                "file d'audit pleine : événement compté comme perdu"
            );
        }
    }

    /// Events queued and not written yet.
    pub fn pending(&self) -> usize {
        self.pending.load(Ordering::Acquire)
    }

    /// Events lost and not reported yet.
    pub fn lost(&self) -> u64 {
        self.lost.lock().map_or(0, |l| l.count)
    }

    /// Waits until the queue is written, at most `timeout`; `true` if it is.
    pub async fn flush(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while self.pending() > 0 {
            if Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        true
    }

    fn take_lost(&self) -> Lost {
        self.lost
            .lock()
            .map(|mut l| std::mem::take(&mut *l))
            .unwrap_or_default()
    }

    fn restore_lost(&self, back: Lost) {
        if let Ok(mut lost) = self.lost.lock() {
            lost.add(back.count, back.first_ms, back.last_ms);
        }
    }

    fn own_after(&self, seq: u64) -> Vec<Appended> {
        self.own.lock().map_or_else(
            |_| Vec::new(),
            |own| {
                let mut out: Vec<Appended> = own.iter().filter(|a| a.seq > seq).copied().collect();
                out.sort_by_key(|a| a.seq);
                out
            },
        )
    }

    fn covered(&self, seq: u64) {
        if let Ok(mut own) = self.own.lock() {
            own.retain(|a| a.seq > seq);
        }
    }
}

async fn write_events(pool: &PgPool, events: Vec<Event>) -> Result<Vec<Appended>, CoreError> {
    let mut tx = pool.begin().await.map_err(write_error)?;
    let appended = append_many(&mut tx, events).await?;
    tx.commit().await.map_err(write_error)?;
    Ok(appended)
}

async fn write_batch(pool: &PgPool, recorder: &Recorder, batch: &mut Vec<Event>) {
    let mut delay = Duration::from_millis(100);
    for attempt in 1..=WRITE_ATTEMPTS {
        let lost = recorder.take_lost();
        let mut events = Vec::with_capacity(batch.len() + 1);
        if lost.count > 0 {
            events.push(lost.event());
        }
        events.extend(batch.iter().cloned());
        match write_events(pool, events).await {
            Ok(_) => {
                if lost.count > 0 {
                    tracing::warn!(
                        event = "audit.events_lost",
                        count = lost.count,
                        first_ms = lost.first_ms,
                        last_ms = lost.last_ms,
                        "événements d'audit perdus, consignés dans la chaîne"
                    );
                }
                recorder.pending.fetch_sub(batch.len(), Ordering::AcqRel);
                batch.clear();
                // Not a critical record: the signer looks at the backlog.
                recorder.wake.notify_one();
                return;
            }
            Err(e) => {
                recorder.restore_lost(lost);
                tracing::warn!(
                    event = "audit.append_failed",
                    code = e.code(),
                    attempt,
                    events = batch.len(),
                    "écriture d'audit différée en échec, nouvelle tentative : {e}"
                );
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(5));
            }
        }
    }
    let now = unix_now_ms();
    recorder.restore_lost(Lost {
        count: batch.len() as u64,
        first_ms: now,
        last_ms: now,
    });
    tracing::error!(
        event = "audit.append_failed",
        code = "CORE-E010",
        events = batch.len(),
        "événements d'audit perdus après {WRITE_ATTEMPTS} tentatives"
    );
    recorder.pending.fetch_sub(batch.len(), Ordering::AcqRel);
    batch.clear();
}

/// The best-effort writer: one task, batches of up to 64 events written
/// under one lock, retried with a backoff, then counted as lost. Returns
/// when the queue is closed, or at once if another writer runs.
pub async fn run_writer(pool: PgPool, recorder: Arc<Recorder>) {
    let Some(mut receiver) = recorder.receiver.lock().ok().and_then(|mut r| r.take()) else {
        return;
    };
    let mut batch = Vec::with_capacity(BATCH);
    while receiver.recv_many(&mut batch, BATCH).await > 0 {
        write_batch(&pool, &recorder, &mut batch).await;
    }
}

// ---------------------------------------------------------------- clock

/// Where the head signer reads the time (Unix ms): injectable for tests.
pub trait Clock: Send + Sync + fmt::Debug {
    /// The current time, Unix milliseconds.
    fn now_ms(&self) -> u64;
}

/// The system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        unix_now_ms()
    }
}

/// A clock set by hand (tests).
#[derive(Debug, Default)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    /// A clock at `now_ms`.
    pub fn new(now_ms: u64) -> Self {
        Self(AtomicU64::new(now_ms))
    }

    /// Moves it forward.
    pub fn advance(&self, by: Duration) {
        let ms = u64::try_from(by.as_millis()).unwrap_or(u64::MAX);
        self.0.fetch_add(ms, Ordering::AcqRel);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }
}

// --------------------------------------------------------------- signer

/// When heads are signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cadence {
    /// A head this long after the previous one if the tip moved.
    pub head_interval: Duration,
    /// A head at least this often, even without change; written in heads.
    pub heartbeat_secs: u32,
    /// A head as soon as this many records are not covered.
    pub max_records: u64,
}

impl From<&CoreAuditConfig> for Cadence {
    fn from(config: &CoreAuditConfig) -> Self {
        Self {
            head_interval: Duration::from_secs(u64::from(config.head_interval_secs)),
            heartbeat_secs: config.heartbeat_secs.max(1),
            max_records: u64::from(config.head_max_records.max(1)),
        }
    }
}

/// The last head stored, if any.
///
/// # Errors
///
/// [`CoreError::AuditChain`] if it does not decode, [`CoreError::Database`].
pub async fn last_head(pool: &PgPool) -> Result<Option<Head>, CoreError> {
    let mut conn = pool.acquire().await?;
    read_last_head(&mut conn).await
}

async fn read_last_head(conn: &mut PgConnection) -> Result<Option<Head>, CoreError> {
    let row = sqlx::query!(
        "SELECT head_no, record_seq, body FROM audit_head ORDER BY head_no DESC LIMIT 1"
    )
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let head = Head::decode(&row.body)
        .map_err(|e| chain_error(format!("tête n° {} illisible : {e}", row.head_no)))?;
    if head.head_no() != u64_of(row.head_no) || head.record_seq() != u64_of(row.record_seq) {
        return Err(chain_error(format!(
            "tête n° {} incohérente avec ses colonnes",
            row.head_no
        )));
    }
    Ok(Some(head))
}

/// The public key announced for `kid` by an `audit.signing_started`
/// record: the key of a previous signer, after a rotation.
async fn announced_key(
    conn: &mut PgConnection,
    kid: Kid,
) -> Result<Option<VerifyingKey>, CoreError> {
    let rows = sqlx::query!(
        "SELECT body FROM audit_record WHERE event = $1 ORDER BY seq DESC LIMIT 1000",
        EventKind::AuditSigningStarted.name(),
    )
    .fetch_all(&mut *conn)
    .await?;
    for row in rows {
        let Ok(record) = Record::decode(&row.body) else {
            continue;
        };
        if let Some(Value::Bytes(bytes)) = record.field(field::P256_PUBLIC)
            && let Ok(bytes) = <&[u8; 65]>::try_from(bytes.as_slice())
            && let Ok(key) = VerifyingKey::from_bytes(bytes)
            && Kid::of(&key) == kid
        {
            return Ok(Some(key));
        }
    }
    Ok(None)
}

/// The tip seen by a segment check.
#[derive(Debug, Clone, Copy)]
struct Tip {
    chain_id: ChainId,
    seq: u64,
    hash: Digest,
}

/// Where a segment check found problems.
#[derive(Debug, Default)]
struct Breaks {
    first: Option<u64>,
    last: Option<u64>,
    messages: Vec<String>,
}

impl Breaks {
    fn add(&mut self, seq: u64, message: impl fmt::Display) {
        self.first = Some(self.first.map_or(seq, |f| f.min(seq)));
        self.last = Some(self.last.map_or(seq, |l| l.max(seq)));
        if self.messages.len() < 5 {
            self.messages.push(message.to_string());
        }
    }
}

/// Signs the heads of the chain (ADR-0012).
pub struct HeadSigner {
    pool: PgPool,
    key: Arc<SigningKey>,
    kid: Kid,
    cadence: Cadence,
    clock: Arc<dyn Clock>,
    recorder: Arc<Recorder>,
    last: tokio::sync::Mutex<Option<Head>>,
    broken: AtomicBool,
}

impl fmt::Debug for HeadSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeadSigner")
            .field("kid", &self.kid)
            .field("cadence", &self.cadence)
            .finish_non_exhaustive()
    }
}

impl HeadSigner {
    /// A signer with `key`; it checks the records `recorder` was told
    /// about.
    pub fn new(
        pool: PgPool,
        key: Arc<SigningKey>,
        cadence: Cadence,
        clock: Arc<dyn Clock>,
        recorder: Arc<Recorder>,
    ) -> Self {
        let kid = Kid::of(&key.verifying_key());
        let capacity = usize::try_from(cadence.max_records).unwrap_or(usize::MAX);
        recorder.own_capacity.store(capacity, Ordering::Relaxed);
        Self {
            pool,
            key,
            kid,
            cadence,
            clock,
            recorder,
            last: tokio::sync::Mutex::new(None),
            broken: AtomicBool::new(false),
        }
    }

    /// Identifier of the signing key.
    pub fn kid(&self) -> Kid {
        self.kid
    }

    /// The public key, uncompressed SEC1.
    pub fn public_key(&self) -> [u8; 65] {
        self.key.verifying_key().to_bytes()
    }

    /// Whether a broken segment stopped the signer.
    pub fn is_broken(&self) -> bool {
        self.broken.load(Ordering::Acquire)
    }

    /// The `audit.signing_started` event of this signer.
    pub fn signing_started(&self) -> Event {
        Event::new(
            EventKind::AuditSigningStarted,
            Outcome::Success,
            ActorKind::Core,
            CORE_ACTOR,
        )
        .bytes(field::KID, self.kid.to_bytes())
        .bytes(field::P256_PUBLIC, self.public_key())
        .u64(
            field::HEARTBEAT_SECS,
            u64::from(self.cadence.heartbeat_secs),
        )
    }

    /// Checks the segment since the last head and signs the next head if
    /// the tip moved or the heartbeat is due (within one second). Returns
    /// the head signed, if any.
    ///
    /// # Errors
    ///
    /// [`CoreError::AuditChain`] if the segment is broken and the break is
    /// not acknowledged: the signer then stops for good
    /// (`audit.chain_broken`); [`CoreError::AuditWrite`] if the head cannot
    /// be written.
    pub async fn sign_now(&self) -> Result<Option<Head>, CoreError> {
        if self.is_broken() {
            return Err(chain_error(
                "signature des têtes arrêtée depuis une rupture constatée",
            ));
        }
        let mut last = self.last.lock().await;
        let result = self.check_and_sign(&mut last).await;
        if let Err(CoreError::AuditChain(message)) = &result {
            self.broken.store(true, Ordering::Release);
            tracing::error!(
                event = "audit.chain_broken",
                code = "CORE-E011",
                "chaîne d'audit incohérente, signature des têtes arrêtée : {message}"
            );
        }
        result
    }

    async fn check_and_sign(&self, last: &mut Option<Head>) -> Result<Option<Head>, CoreError> {
        let mut tx = self.pool.begin().await.map_err(write_error)?;
        lock(&mut tx).await?;
        let anchor = read_last_head(&mut tx).await?;
        *last = anchor;
        let Some(tip) = self.check_segment(&mut tx, anchor.as_ref()).await? else {
            return Ok(None);
        };
        let now = self.clock.now_ms();
        let heartbeat_ms = u64::from(self.cadence.heartbeat_secs) * 1000;
        let due = anchor.as_ref().is_none_or(|h| {
            tip.seq > h.record_seq()
                || now.saturating_sub(h.time_ms()) + HEARTBEAT_SLACK_MS >= heartbeat_ms
        });
        if !due {
            return Ok(None);
        }
        let head = UnsignedHead::after(
            anchor.as_ref(),
            tip.chain_id,
            tip.seq,
            tip.hash,
            now,
            self.cadence.heartbeat_secs,
        )
        .sign(&self.key)
        .map_err(|e| CoreError::AuditWrite(e.to_string()))?;
        sqlx::query!(
            "INSERT INTO audit_head (head_no, record_seq, body, hash) VALUES ($1, $2, $3, $4)",
            i64_of(head.head_no()),
            i64_of(head.record_seq()),
            &head.encode()[..],
            &head.hash()[..],
        )
        .execute(&mut *tx)
        .await
        .map_err(write_error)?;
        tx.commit().await.map_err(write_error)?;
        *last = Some(head);
        self.recorder.covered(tip.seq);
        tracing::info!(
            event = "audit.head_signed",
            head_no = head.head_no(),
            record_seq = head.record_seq(),
            head = %head.to_text(),
            "tête de la chaîne d'audit signée"
        );
        Ok(Some(head))
    }

    /// Streams the records after `anchor` through the verifier and checks
    /// the records the core appended since; returns the tip (`None` for an
    /// empty chain). The lock must be held.
    async fn check_segment(
        &self,
        conn: &mut PgConnection,
        anchor: Option<&Head>,
    ) -> Result<Option<Tip>, CoreError> {
        let mut keys = TrustedKeys::new();
        keys.insert(self.key.verifying_key())
            .map_err(|e| chain_error(e.to_string()))?;
        if let Some(head) = anchor
            && head.kid() != self.kid
            && let Some(previous) = announced_key(conn, head.kid()).await?
        {
            keys.insert(previous)
                .map_err(|e| chain_error(e.to_string()))?;
        }
        let mut verifier = Verifier::new(keys, Options::default());
        let mut breaks = Breaks::default();
        let mut tip = None;
        let mut after = 0;
        if let Some(head) = anchor {
            after = head.record_seq();
            tip = Some(Tip {
                chain_id: head.chain_id(),
                seq: head.record_seq(),
                hash: head.record_hash(),
            });
            check_anchor(conn, head, &mut verifier, &mut breaks).await?;
        }
        let own = self.recorder.own_after(after);
        let mut own = own.into_iter().peekable();
        loop {
            let page = sqlx::query!(
                "SELECT seq, body, hash FROM audit_record WHERE seq > $1 ORDER BY seq LIMIT $2",
                i64_of(after),
                PAGE,
            )
            .fetch_all(&mut *conn)
            .await?;
            if page.is_empty() {
                break;
            }
            for row in page {
                let seq = u64_of(row.seq);
                let hash = record_hash(&row.body);
                if digest(&row.hash) != Some(hash) {
                    breaks.add(
                        seq,
                        format!(
                            "colonne hash de l'enregistrement n° {seq} différente de son contenu"
                        ),
                    );
                }
                if let Err(finding) = verifier.push_record(&row.body) {
                    breaks.add(seq, finding);
                }
                while let Some(mine) = own.next_if(|a| a.seq < seq) {
                    breaks.add(
                        mine.seq,
                        format!("enregistrement n° {} écrit par le core absent", mine.seq),
                    );
                }
                if let Some(mine) = own.next_if(|a| a.seq == seq)
                    && mine.hash != hash
                {
                    breaks.add(
                        seq,
                        format!("enregistrement n° {seq} différent de celui écrit par le core"),
                    );
                }
                let chain_id = match tip {
                    Some(t) => t.chain_id,
                    None => Record::decode(&row.body)
                        .map_or(ChainId::from_bytes([0; 16]), |r| r.chain_id),
                };
                tip = Some(Tip {
                    chain_id,
                    seq,
                    hash,
                });
                after = seq;
            }
        }
        for mine in own {
            breaks.add(
                mine.seq,
                format!("enregistrement n° {} écrit par le core absent", mine.seq),
            );
        }
        drop(verifier.finish(None));
        settle(conn, &breaks).await?;
        Ok(tip)
    }

    /// Whether a head is due now, from the tip and the last head.
    async fn due(&self) -> Result<bool, CoreError> {
        let critical = self.recorder.critical.swap(false, Ordering::AcqRel);
        let tip = sqlx::query_scalar!("SELECT max(seq) FROM audit_record")
            .fetch_one(&self.pool)
            .await?
            .map(u64_of);
        let Some(tip) = tip else {
            return Ok(false);
        };
        let last = *self.last.lock().await;
        let Some(head) = last else {
            return Ok(true);
        };
        let now = self.clock.now_ms();
        let elapsed = now.saturating_sub(head.time_ms());
        let interval_ms = u64::try_from(self.cadence.head_interval.as_millis()).unwrap_or(u64::MAX);
        let heartbeat_ms = u64::from(self.cadence.heartbeat_secs) * 1000;
        let uncovered = tip.saturating_sub(head.record_seq());
        Ok((uncovered > 0
            && (critical || elapsed >= interval_ms || uncovered >= self.cadence.max_records))
            || elapsed + HEARTBEAT_SLACK_MS >= heartbeat_ms)
    }

    /// Time until the next periodic look: the interval, or the heartbeat
    /// if it ends sooner.
    async fn next_wait(&self) -> Duration {
        let last = *self.last.lock().await;
        let interval = self.cadence.head_interval;
        let Some(head) = last else {
            return interval;
        };
        let heartbeat_ms = u64::from(self.cadence.heartbeat_secs) * 1000;
        let elapsed = self.clock.now_ms().saturating_sub(head.time_ms());
        let left = heartbeat_ms.saturating_sub(elapsed + HEARTBEAT_SLACK_MS);
        interval
            .min(Duration::from_millis(left))
            .max(Duration::from_millis(50))
    }

    /// The signing loop: after each critical record or notification, every
    /// interval if the tip moved, after `max_records` records, and at every
    /// heartbeat; at most one head per second. Returns once the signer is
    /// stopped by a broken segment.
    pub async fn run(self: Arc<Self>) {
        let mut last_signed: Option<Instant> = None;
        loop {
            let wait = self.next_wait().await;
            let _ = tokio::time::timeout(wait, self.recorder.wake.notified()).await;
            if let Some(at) = last_signed {
                let since = at.elapsed();
                if since < MIN_HEAD_INTERVAL {
                    tokio::time::sleep(MIN_HEAD_INTERVAL.saturating_sub(since)).await;
                }
            }
            if self.is_broken() {
                return;
            }
            match self.due().await {
                Ok(true) => match self.sign_now().await {
                    Ok(Some(_)) => last_signed = Some(Instant::now()),
                    Ok(None) => {}
                    Err(_) if self.is_broken() => return,
                    Err(e) => {
                        tracing::warn!(event = "audit.head_failed", code = e.code(), "{e}");
                    }
                },
                Ok(false) => {}
                Err(e) => tracing::warn!(event = "audit.head_failed", code = e.code(), "{e}"),
            }
        }
    }
}

/// Accepts a segment without break, or whose breaks an administrator
/// acknowledged; refuses it otherwise.
async fn settle(conn: &mut PgConnection, breaks: &Breaks) -> Result<(), CoreError> {
    let (Some(first), Some(last)) = (breaks.first, breaks.last) else {
        return Ok(());
    };
    if !acknowledged(conn, first, last).await? {
        return Err(chain_error(format!(
            "enregistrements n° {first} à {last} : {}",
            breaks.messages.join(" ; ")
        )));
    }
    tracing::warn!(
        event = "audit.break_accepted",
        first_seq = first,
        last_seq = last,
        "rupture de la chaîne d'audit reconnue par un administrateur : signature reprise"
    );
    Ok(())
}

/// Checks the anchor of a segment: its signature, and the record it covers,
/// which must still be there with the same hash.
async fn check_anchor(
    conn: &mut PgConnection,
    head: &Head,
    verifier: &mut Verifier,
    breaks: &mut Breaks,
) -> Result<(), CoreError> {
    if let Err(finding) = verifier.anchor(head) {
        breaks.add(head.record_seq(), finding);
    }
    let covered = sqlx::query!(
        "SELECT body, hash FROM audit_record WHERE seq = $1",
        i64_of(head.record_seq()),
    )
    .fetch_optional(&mut *conn)
    .await?;
    let problem = match covered {
        None => Some("est absent"),
        Some(row)
            if record_hash(&row.body) != head.record_hash()
                || digest(&row.hash) != Some(head.record_hash()) =>
        {
            Some("ne lui correspond plus")
        }
        Some(_) => None,
    };
    if let Some(problem) = problem {
        breaks.add(
            head.record_seq(),
            format!(
                "l'enregistrement n° {} couvert par la tête n° {} {problem}",
                head.record_seq(),
                head.head_no()
            ),
        );
    }
    Ok(())
}

/// Whether the latest `audit.break_acknowledged` record covers breaks
/// found from `first` to `last`: written after them, from a seq at or
/// before the first.
async fn acknowledged(conn: &mut PgConnection, first: u64, last: u64) -> Result<bool, CoreError> {
    let row = sqlx::query!(
        "SELECT seq, body FROM audit_record WHERE event = $1 ORDER BY seq DESC LIMIT 1",
        EventKind::AuditBreakAcknowledged.name(),
    )
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    let Ok(record) = Record::decode(&row.body) else {
        return Ok(false);
    };
    Ok(match record.field(field::FIRST_SEQ) {
        Some(Value::U64(from)) => u64_of(row.seq) > last && *from <= first,
        _ => false,
    })
}

/// Records that an administrator acknowledged a break of the chain from
/// `first_bad_seq` (`audit.break_acknowledged`, granting); the signer
/// resumes at its next check. Returns the record.
///
/// # Errors
///
/// [`CoreError::AuditWrite`], [`CoreError::AuditChain`],
/// [`CoreError::Database`].
pub async fn acknowledge_break(pool: &PgPool, first_bad_seq: u64) -> Result<Appended, CoreError> {
    let mut tx = pool.begin().await?;
    let actor = admin_actor(&mut tx).await?;
    crate::store::notify_audit(&mut tx).await?;
    let appended = append(
        &mut tx,
        Event::new(
            EventKind::AuditBreakAcknowledged,
            Outcome::Success,
            ActorKind::Admin,
            actor,
        )
        .u64(field::FIRST_SEQ, first_bad_seq),
    )
    .await?;
    tx.commit().await.map_err(write_error)?;
    tracing::warn!(
        event = "audit.break_acknowledged",
        first_seq = first_bad_seq,
        seq = appended.seq,
        "rupture de la chaîne d'audit reconnue"
    );
    Ok(appended)
}

// --------------------------------------------------------------- export

/// A head as stored.
#[derive(Debug, Clone)]
struct StoredHead {
    head_no: u64,
    record_seq: u64,
    body: Vec<u8>,
}

/// What reads the chain in order.
trait Sink {
    fn begin(&mut self, chain_id: ChainId, first_seq: u64) -> Result<(), CoreError>;
    fn anchor(&mut self, head: &StoredHead) -> Result<(), CoreError>;
    fn record(&mut self, seq: u64, body: &[u8]) -> Result<(), CoreError>;
    fn head(&mut self, head: &StoredHead) -> Result<(), CoreError>;
}

/// The order of the frames, checked as they are produced: records by
/// increasing seq; heads by increasing (record seq, number), each after the
/// record it covers.
#[derive(Debug)]
struct FrameOrder {
    first_seq: u64,
    last_record: Option<u64>,
    last_head: Option<(u64, u64)>,
}

impl FrameOrder {
    fn record(&mut self, seq: u64) -> Result<(), CoreError> {
        let floor = self.last_record.unwrap_or(self.first_seq.saturating_sub(1));
        if seq <= floor {
            return Err(chain_error(format!(
                "ordre de l'export : enregistrement n° {seq} après le n° {floor}"
            )));
        }
        self.last_record = Some(seq);
        Ok(())
    }

    fn head(&mut self, head: &StoredHead) -> Result<(), CoreError> {
        let key = (head.record_seq, head.head_no);
        let floor = self.last_record.unwrap_or(self.first_seq.saturating_sub(1));
        if self.last_head.is_some_and(|last| key <= last) || head.record_seq < floor {
            return Err(chain_error(format!(
                "ordre de l'export : tête n° {} mal placée",
                head.head_no
            )));
        }
        self.last_head = Some(key);
        Ok(())
    }
}

/// Heads in (record seq, number) order, read page by page.
struct HeadCursor {
    after: (i64, i64),
    page: VecDeque<StoredHead>,
    done: bool,
}

impl HeadCursor {
    /// The next head, if any, without taking it.
    async fn peek(&mut self, conn: &mut PgConnection) -> Result<Option<&StoredHead>, CoreError> {
        if self.page.is_empty() && !self.done {
            let rows = sqlx::query!(
                "SELECT head_no, record_seq, body FROM audit_head
                 WHERE (record_seq, head_no) > ($1, $2)
                 ORDER BY record_seq, head_no LIMIT $3",
                self.after.0,
                self.after.1,
                PAGE,
            )
            .fetch_all(&mut *conn)
            .await?;
            self.done = rows.is_empty();
            for h in rows {
                self.after = (h.record_seq, h.head_no);
                self.page.push_back(StoredHead {
                    head_no: u64_of(h.head_no),
                    record_seq: u64_of(h.record_seq),
                    body: h.body,
                });
            }
        }
        Ok(self.page.front())
    }

    /// Hands to `sink` the heads whose record seq is below `limit`.
    async fn drain_below(
        &mut self,
        conn: &mut PgConnection,
        limit: u64,
        order: &mut FrameOrder,
        sink: &mut dyn Sink,
    ) -> Result<(), CoreError> {
        while self.peek(conn).await?.is_some_and(|h| h.record_seq < limit) {
            if let Some(h) = self.page.pop_front() {
                order.head(&h)?;
                sink.head(&h)?;
            }
        }
        Ok(())
    }
}

/// Where a walk starts: the chain, the first seq, the anchor head.
async fn walk_start(
    conn: &mut PgConnection,
    from_head: Option<u64>,
) -> Result<(ChainId, u64, Option<StoredHead>), CoreError> {
    if let Some(head_no) = from_head {
        let row = sqlx::query!(
            "SELECT record_seq, body FROM audit_head WHERE head_no = $1",
            i64_of(head_no),
        )
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| CoreError::NotFound(format!("tête d'audit n° {head_no}")))?;
        let head = Head::decode(&row.body)
            .map_err(|e| chain_error(format!("tête n° {head_no} illisible : {e}")))?;
        let stored = StoredHead {
            head_no,
            record_seq: u64_of(row.record_seq),
            body: row.body,
        };
        return Ok((
            head.chain_id(),
            stored.record_seq.saturating_add(1),
            Some(stored),
        ));
    }
    let row = sqlx::query!("SELECT seq, body FROM audit_record ORDER BY seq LIMIT 1")
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| CoreError::NotFound("chaîne d'audit (vide)".into()))?;
    let record = Record::decode(&row.body)
        .map_err(|e| chain_error(format!("enregistrement n° {} illisible : {e}", row.seq)))?;
    Ok((record.chain_id, 1, None))
}

/// Streams the chain to `sink` in a read-only snapshot, in constant memory:
/// the anchor head `from_head` if given, then records and heads merged by
/// record seq.
async fn walk(pool: &PgPool, from_head: Option<u64>, sink: &mut dyn Sink) -> Result<(), CoreError> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    let (chain_id, first_seq, anchor) = walk_start(&mut tx, from_head).await?;
    let mut order = FrameOrder {
        first_seq,
        last_record: None,
        last_head: None,
    };
    sink.begin(chain_id, first_seq)?;
    let mut heads = HeadCursor {
        after: (i64_of(first_seq.saturating_sub(1)), 0),
        page: VecDeque::new(),
        done: false,
    };
    if let Some(anchor) = &anchor {
        sink.anchor(anchor)?;
        heads.after = (i64_of(anchor.record_seq), i64_of(anchor.head_no));
    }
    let mut after = i64_of(first_seq.saturating_sub(1));
    loop {
        let records = sqlx::query!(
            "SELECT seq, body FROM audit_record WHERE seq > $1 ORDER BY seq LIMIT $2",
            after,
            PAGE,
        )
        .fetch_all(&mut *tx)
        .await?;
        if records.is_empty() {
            break;
        }
        for row in records {
            let seq = u64_of(row.seq);
            heads.drain_below(&mut tx, seq, &mut order, sink).await?;
            order.record(seq)?;
            sink.record(seq, &row.body)?;
            after = row.seq;
        }
    }
    // Heads after the last record: those of the tip, and any that cover a
    // record no longer there (the verifier reports them).
    heads
        .drain_below(&mut tx, u64::MAX, &mut order, sink)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// What an export holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportSummary {
    /// The chain.
    pub chain_id: ChainId,
    /// First seq of the export (1, or the seq after the anchor).
    pub first_seq: u64,
    /// Last record exported.
    pub last_seq: Option<u64>,
    /// Records exported.
    pub records: u64,
    /// Heads exported, the anchor included.
    pub heads: u64,
}

struct ExportSink<W: Write> {
    writer: Option<ExportWriter<W>>,
    inner: Option<W>,
    summary: ExportSummary,
}

fn export_error(e: &ostena_audit::AuditError) -> CoreError {
    CoreError::AuditWrite(format!("export : {e}"))
}

impl<W: Write> ExportSink<W> {
    fn writer(&mut self) -> Result<&mut ExportWriter<W>, CoreError> {
        self.writer
            .as_mut()
            .ok_or_else(|| CoreError::AuditWrite("export : en-tête non écrit".into()))
    }
}

impl<W: Write> Sink for ExportSink<W> {
    fn begin(&mut self, chain_id: ChainId, first_seq: u64) -> Result<(), CoreError> {
        let inner = self
            .inner
            .take()
            .ok_or_else(|| CoreError::AuditWrite("export : déjà commencé".into()))?;
        self.writer = Some(
            ExportWriter::new(inner, chain_id, unix_now_ms(), first_seq)
                .map_err(|e| export_error(&e))?,
        );
        self.summary.chain_id = chain_id;
        self.summary.first_seq = first_seq;
        Ok(())
    }

    fn anchor(&mut self, head: &StoredHead) -> Result<(), CoreError> {
        self.head(head)
    }

    fn record(&mut self, seq: u64, body: &[u8]) -> Result<(), CoreError> {
        self.writer()?.record(body).map_err(|e| export_error(&e))?;
        self.summary.records += 1;
        self.summary.last_seq = Some(seq);
        Ok(())
    }

    fn head(&mut self, head: &StoredHead) -> Result<(), CoreError> {
        self.writer()?
            .head_bytes(&head.body)
            .map_err(|e| export_error(&e))?;
        self.summary.heads += 1;
        Ok(())
    }
}

/// Writes the export container of the chain to `writer`, streamed in
/// constant memory: the whole chain, or from the head `from_head`, which
/// becomes the anchor of a partial export. Returns the writer, flushed.
///
/// # Errors
///
/// [`CoreError::NotFound`] for an empty chain or an unknown head,
/// [`CoreError::AuditWrite`] if writing fails, [`CoreError::AuditChain`] if
/// the anchor or the first record cannot be read,
/// [`CoreError::Database`].
pub async fn export<W: Write>(
    pool: &PgPool,
    writer: W,
    from_head: Option<u64>,
) -> Result<(W, ExportSummary), CoreError> {
    let mut sink = ExportSink {
        writer: None,
        inner: Some(writer),
        summary: ExportSummary {
            chain_id: ChainId::from_bytes([0; 16]),
            first_seq: 1,
            last_seq: None,
            records: 0,
            heads: 0,
        },
    };
    walk(pool, from_head, &mut sink).await?;
    let writer = sink
        .writer
        .take()
        .ok_or_else(|| CoreError::AuditWrite("export : en-tête non écrit".into()))?
        .finish()
        .map_err(|e| export_error(&e))?;
    Ok((writer, sink.summary))
}

/// Records an export made by an administrator (`audit.exported`, with its
/// first and last seq and its head count).
///
/// # Errors
///
/// [`CoreError::AuditWrite`], [`CoreError::AuditChain`],
/// [`CoreError::Database`].
pub async fn record_export(pool: &PgPool, summary: &ExportSummary) -> Result<Appended, CoreError> {
    let mut tx = pool.begin().await?;
    let actor = admin_actor(&mut tx).await?;
    crate::store::notify_audit(&mut tx).await?;
    let mut event = Event::new(
        EventKind::AuditExported,
        Outcome::Success,
        ActorKind::Admin,
        actor,
    )
    .u64(field::FIRST_SEQ, summary.first_seq)
    .u64(field::HEAD_COUNT, summary.heads);
    if let Some(last) = summary.last_seq {
        event = event.u64(field::LAST_SEQ, last);
    }
    let appended = append(&mut tx, event).await?;
    tx.commit().await.map_err(write_error)?;
    Ok(appended)
}

struct VerifySink {
    verifier: Verifier,
}

impl Sink for VerifySink {
    fn begin(&mut self, chain_id: ChainId, first_seq: u64) -> Result<(), CoreError> {
        self.verifier.expect(chain_id, first_seq);
        Ok(())
    }

    fn anchor(&mut self, head: &StoredHead) -> Result<(), CoreError> {
        match Head::decode(&head.body) {
            Ok(h) => {
                let _ = self.verifier.anchor(&h);
            }
            Err(e) => self.verifier.push_malformed(None, e),
        }
        Ok(())
    }

    fn record(&mut self, _seq: u64, body: &[u8]) -> Result<(), CoreError> {
        let _ = self.verifier.push_record(body);
        Ok(())
    }

    fn head(&mut self, head: &StoredHead) -> Result<(), CoreError> {
        match Head::decode(&head.body) {
            Ok(h) => {
                let _ = self.verifier.push_head(&h);
            }
            Err(e) => self.verifier.push_malformed(None, e),
        }
        Ok(())
    }
}

/// Verifies the whole chain in the database with `keys`, as `ostena audit
/// verify` would verify a full export made now.
///
/// # Errors
///
/// [`CoreError::NotFound`] for an empty chain, [`CoreError::AuditChain`] if
/// the first record cannot be read, [`CoreError::Database`].
pub async fn verify_online(pool: &PgPool, keys: TrustedKeys) -> Result<Report, CoreError> {
    let mut sink = VerifySink {
        verifier: Verifier::new(keys, Options::default()),
    };
    walk(pool, None, &mut sink).await?;
    Ok(sink.verifier.finish(Some(unix_now_ms())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_key_differs_from_any_sqlx_migration_lock() {
        // sqlx: 0x3d32ad9e * crc32(name), at most 0x3d32ad9e * 0xffffffff.
        let largest = 0x3d32_ad9e_i64 * 0xffff_ffff_i64;
        assert!(AUDIT_LOCK_KEY > largest);
    }

    #[test]
    fn lost_events_keep_their_range() {
        let mut lost = Lost::default();
        lost.add(0, 5, 5);
        assert_eq!(lost.count, 0);
        lost.add(2, 10, 20);
        lost.add(1, 5, 15);
        assert_eq!((lost.count, lost.first_ms, lost.last_ms), (3, 5, 20));
        let record = lost
            .event()
            .into_record(ChainId::from_bytes([1; 16]), 2, [1; 32], 1)
            .unwrap();
        assert_eq!(record.event, "audit.events_lost");
        assert_eq!(record.field(field::LOST_COUNT), Some(&Value::U64(3)));
    }

    #[test]
    fn recorder_counts_events_it_cannot_queue() {
        let recorder = Recorder::new();
        for _ in 0..QUEUE_CAPACITY + 3 {
            recorder.emit(Event::new(
                EventKind::TunnelAgentConnected,
                Outcome::Success,
                ActorKind::Agent,
                "a",
            ));
        }
        assert_eq!(recorder.pending(), QUEUE_CAPACITY);
        assert_eq!(recorder.lost(), 3);
        let taken = recorder.take_lost();
        assert_eq!((taken.count, recorder.lost()), (3, 0));
        recorder.restore_lost(taken);
        assert_eq!(recorder.lost(), 3);
    }

    #[test]
    fn own_records_are_bounded_and_dropped_once_covered() {
        let recorder = Recorder::new();
        recorder.own_capacity.store(3, Ordering::Relaxed);
        let records: Vec<Appended> = (1..=5).map(|seq| Appended { seq, hash: [0; 32] }).collect();
        recorder.critical(&records);
        assert_eq!(
            recorder
                .own_after(0)
                .iter()
                .map(|a| a.seq)
                .collect::<Vec<_>>(),
            [3, 4, 5]
        );
        recorder.covered(4);
        assert_eq!(recorder.own_after(0).len(), 1);
        assert!(recorder.critical.load(Ordering::Acquire));
    }

    #[test]
    fn frame_order_is_enforced() {
        let head = |head_no, record_seq| StoredHead {
            head_no,
            record_seq,
            body: Vec::new(),
        };
        let mut order = FrameOrder {
            first_seq: 1,
            last_record: None,
            last_head: None,
        };
        order.record(1).unwrap();
        order.head(&head(1, 1)).unwrap();
        order.head(&head(2, 1)).unwrap();
        assert!(order.head(&head(2, 1)).is_err());
        order.record(2).unwrap();
        assert!(order.record(2).is_err());
        assert!(order.head(&head(3, 1)).is_err());
        let mut partial = FrameOrder {
            first_seq: 5,
            last_record: None,
            last_head: None,
        };
        partial.head(&head(4, 4)).unwrap();
        assert!(partial.record(4).is_err());
        partial.record(5).unwrap();
    }

    #[test]
    fn manual_clock_moves_forward() {
        let clock = ManualClock::new(1000);
        clock.advance(Duration::from_secs(2));
        assert_eq!(clock.now_ms(), 3000);
        assert!(SystemClock.now_ms() > 1_700_000_000_000);
    }
}
