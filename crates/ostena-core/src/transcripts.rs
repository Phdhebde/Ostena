//! Session transcripts, core side (ADR-0016): reception of the stream of
//! an agent, asciicast file, seal in the audit chain.
//!
//! 1. A stream of class `Recording` names an access session. It is
//!    accepted only for an SSH session of this agent, still open, not yet
//!    recorded (`session_transcript`, one row per session); otherwise the
//!    stream is stopped (`REC-E002`, `transcript.refused`) and the agent
//!    cuts the session.
//! 2. The frames are decoded strictly (`ostena_recorder::Decoder`, size and
//!    duration limits) and written as they come to `<session>.cast`, a new
//!    file with private rights in `core.ssh.transcripts_dir`. The command
//!    of an `exec` is recorded in the audit chain by its keyed hash
//!    (HMAC-SHA-256, `access.ssh_exec`).
//! 3. A malformed stream, a limit or a write failure stops the stream
//!    (`REC-E001`, `REC-E003`, `REC-E004`): the agent cuts the session. A
//!    stream cut before its end frame is incomplete (`REC-E005`).
//! 4. Whatever the end, the file is synced, made read-only and **sealed**:
//!    its SHA-256 and size go to the row and to a `transcript.sealed`
//!    record, written in one transaction (granting).
//!
//! A transcript left unsealed by a stop of the core is sealed as
//! incomplete at the next start ([`recover`]), from the file as it is.
//!
//! **Acknowledgements and resumption.** The core acknowledges on the
//! stream the transcript bytes written to the file (flushed to the kernel,
//! synced at the end). When the stream of a session is lost with its
//! connection, the sealing is deferred: the decoder, the file and the
//! counts are kept for the grace the agent announced (bounded, plus
//! [`RESUME_MARGIN`]), and a stream that resumes the transcript, from the
//! same agent, goes on from the bytes received. Past the grace, the
//! transcript is sealed incomplete (`REC-E005`), as before.
//!
//! The stream is read and decoded on the async workers; the file is
//! written by a blocking task ([`tokio::task::spawn_blocking`]) fed through
//! a bounded queue, behind a 64 KiB buffer: a slow disk slows down the
//! stream of its session (back-pressure up to the agent), never the
//! workers. A write reaches the kernel cache, not the disk, until the
//! final sync; the directory is synced after the file is created.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use ostena_audit::{Event, EventKind, Outcome, field};
use ostena_crypto::hmac::HmacKey;
use ostena_recorder::{
    CastWriter, Decoder, EndReason, Frame, Limits, NoteKind, RecorderError, Sealed,
};
use ostena_tunnel::recording::{self, Preamble, RESET_STALLED, STOP_REPLACED, send_offset};
use ostena_tunnel::{Channel, StreamError, Uuid};
use sqlx::PgPool;
use tokio::sync::{mpsc, watch};

use crate::audit::{self, Recorder};
use crate::error::CoreError;
use crate::store::{agent_event, i64_of, truncate};

/// Code of a stream the core refuses to record: unknown session, of
/// another agent, closed, not SSH, already recorded.
pub const REFUSED: &str = "REC-E002";
/// Code of a transcript the core cannot write.
pub const WRITE_FAILED: &str = "REC-E004";
/// Code of a transcript cut before its end frame.
pub const INCOMPLETE: &str = "REC-E005";
/// Code of a malformed transcript stream.
const MALFORMED: &str = "REC-E001";

/// Added to the grace announced by the agent: the core and the agent do
/// not see a lost connection at the same instant (each after its idle
/// delay).
pub const RESUME_MARGIN: Duration = Duration::from_secs(30);

/// Domain of the keyed hash of a command: never the same input as another
/// use of the key.
const EXEC_DOMAIN: &[u8] = b"ostena/ssh-exec/v1\0";
/// Domain of the identifier of the command key: a short keyed hash of a
/// constant, which names the key without revealing it.
const KEY_ID_DOMAIN: &[u8] = b"ostena/ssh-exec/key-id/v1\0";
/// Bytes read from the stream at once.
const READ_CHUNK: usize = 16 * 1024;
/// Buffer of the file writer.
const WRITE_BUFFER: usize = 64 * 1024;
/// Frames queued between the stream and the file writer.
const WRITE_QUEUE: usize = 16;

/// The transcript directory and the key of the command hashes.
pub struct Transcripts {
    dir: PathBuf,
    mac: HmacKey,
    key_id: String,
    limits: Limits,
    /// The transcripts being recorded, by session: their agent, and where
    /// a stream that resumes one is handed over.
    recording: Mutex<HashMap<Uuid, (Uuid, mpsc::Sender<Channel>)>>,
}

/// Removes a transcript from the ones being recorded.
struct Recording<'a> {
    store: &'a Transcripts,
    session: Uuid,
}

impl Drop for Recording<'_> {
    fn drop(&mut self) {
        if let Ok(mut recording) = self.store.recording.lock() {
            recording.remove(&self.session);
        }
    }
}

/// What the reading loop hands to the file writer.
enum Item {
    Frame(Frame),
    /// The transcript bytes up to here are complete frames, queued before.
    Mark(u64),
}

/// The keyed hash of the command of an `exec`, its length and the
/// identifier of the key: what the audit chain keeps of it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Command {
    tag: [u8; 32],
    len: usize,
    kid: String,
}

impl std::fmt::Debug for Transcripts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transcripts")
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

/// Size and SHA-256 of `path` as it is on disk; `None` if it is absent.
fn measure(path: &Path) -> std::io::Result<Option<(u64, [u8; 32])>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut hasher = ostena_crypto::sha256::Hasher::new();
    let mut buf = vec![0u8; WRITE_BUFFER];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(Some((hasher.len(), hasher.finish())))
}

/// The seal of a file measured on disk; the counts of the writer are not
/// known then.
fn measured(size: u64, sha256: [u8; 32]) -> Sealed {
    Sealed {
        sha256,
        size,
        events: 0,
        invalid_utf8: 0,
    }
}

/// Makes a sealed file read-only (owner read only on Unix).
fn seal_rights(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))
    }
    #[cfg(not(unix))]
    {
        let mut permissions = std::fs::metadata(path)?.permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(path, permissions)
    }
}

impl Transcripts {
    /// The transcripts of `dir`, created if needed (private rights on
    /// Unix), with the command key `mac`.
    ///
    /// # Errors
    ///
    /// [`CoreError::Startup`] if the directory cannot be created or is not
    /// a directory.
    pub fn open(dir: &Path, mac: HmacKey) -> Result<Self, CoreError> {
        let fail = |e: &dyn std::fmt::Display| {
            CoreError::Startup(format!(
                "[{WRITE_FAILED}] core.ssh.transcripts_dir {} : {e}",
                dir.display()
            ))
        };
        if !dir.exists() {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(dir).map_err(|e| fail(&e))?;
        }
        if !std::fs::metadata(dir).map_err(|e| fail(&e))?.is_dir() {
            return Err(fail(&"pas un répertoire"));
        }
        let id = mac.tag(&[KEY_ID_DOMAIN]);
        let key_id = id[..8].iter().fold(String::with_capacity(16), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        });
        Ok(Self {
            dir: dir.to_path_buf(),
            mac,
            key_id,
            limits: Limits::default(),
            recording: Mutex::default(),
        })
    }

    /// The same, with other stream limits (tests).
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// The file of the transcript of `session`.
    pub fn path(&self, session: Uuid) -> PathBuf {
        self.dir.join(format!("{session}.cast"))
    }

    /// The keyed hash of the command of `session`.
    pub fn command_tag(&self, session: Uuid, command: &[u8]) -> [u8; 32] {
        self.mac.tag(&[EXEC_DOMAIN, &session.to_bytes(), command])
    }

    /// The identifier of the command key (16 hexadecimal digits), kept with
    /// each hash so that the key can be rotated.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

/// Writes a **protective** record (`transcript.refused`) at once, in its
/// own transaction: a failure is logged (`audit.append_failed`), never
/// silent.
async fn protect(pool: &PgPool, recorder: &Recorder, event: Option<Event>) {
    let Some(event) = event else { return };
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!(
                event = "audit.append_failed",
                audited = "transcript.refused",
                code = "CORE-E010",
                "{e}"
            );
            drop(event);
            return;
        }
    };
    if let Some(appended) = audit::append_protective(&mut tx, event).await {
        match tx.commit().await {
            Ok(()) => recorder.critical(&[appended]),
            Err(e) => tracing::error!(
                event = "audit.append_failed",
                audited = "transcript.refused",
                code = "CORE-E010",
                "{e}"
            ),
        }
    }
}

/// The `transcript.refused` record.
fn refused_event(agent: Uuid, session: Uuid, code: &str, reason: &str) -> Event {
    agent_event(EventKind::TranscriptRefused, Outcome::Refused, agent)
        .uuid(field::ACCESS_SESSION, session.to_bytes())
        .text(field::CODE, code)
        .text(field::REASON, truncate(reason))
}

/// How a transcript ended.
struct Ending {
    /// The file as written or measured; `None`: no file (it could not be
    /// created, or it is gone), which the seal says.
    sealed: Option<Sealed>,
    output_bytes: u64,
    reason: Option<EndReason>,
    /// `None`: complete.
    code: Option<&'static str>,
    command: Option<Command>,
}

/// Seals the transcript of `session`: row and `transcript.sealed` record in
/// one transaction.
async fn seal(
    pool: &PgPool,
    recorder: &Recorder,
    agent: Uuid,
    session: Uuid,
    ending: &Ending,
    now: u64,
) -> Result<(), CoreError> {
    let complete = ending.code.is_none();
    let state = if complete { "sealed" } else { "incomplete" };
    let mut tx = pool.begin().await?;
    let updated = sqlx::query!(
        "UPDATE session_transcript SET state = $2, sealed_at = $3, sha256 = $4, size = $5,
                events = $6, invalid_utf8 = $7, output_bytes = $8, end_reason = $9, code = $10,
                command_hmac = $11, command_len = $12, command_kid = $13
         WHERE session_id = $1::text::uuid AND state = 'recording'",
        session.to_string(),
        state,
        i64_of(now),
        ending.sealed.as_ref().map(|s| &s.sha256[..]),
        ending.sealed.as_ref().map(|s| i64_of(s.size)),
        ending.sealed.as_ref().map(|s| i64_of(s.events)),
        ending.sealed.as_ref().map(|s| i64_of(s.invalid_utf8)),
        i64_of(ending.output_bytes),
        ending.reason.map(EndReason::name),
        ending.code,
        ending.command.as_ref().map(|c| &c.tag[..]),
        ending
            .command
            .as_ref()
            .map(|c| i32::try_from(c.len).unwrap_or(i32::MAX)),
        ending.command.as_ref().map(|c| c.kid.as_str()),
    )
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if updated == 0 {
        return Err(CoreError::Database(format!(
            "transcript {session} déjà scellé"
        )));
    }
    let mut event = agent_event(
        EventKind::TranscriptSealed,
        if complete {
            Outcome::Success
        } else {
            Outcome::Failure
        },
        agent,
    )
    .uuid(field::ACCESS_SESSION, session.to_bytes());
    // Without a file, no digest: never a made-up value.
    if let Some(sealed) = &ending.sealed {
        event = event
            .bytes(field::SHA256, sealed.sha256)
            .u64(field::SIZE, sealed.size)
            .u64(field::EVENTS, sealed.events)
            .u64(field::INVALID_UTF8, sealed.invalid_utf8);
    }
    event = event
        .u64(field::OUTPUT_BYTES, ending.output_bytes)
        .bool(field::COMPLETE, complete);
    if let Some(command) = &ending.command {
        event = event
            .bytes(field::COMMAND_HMAC, command.tag)
            .u64(field::LENGTH, command.len as u64)
            .text(field::KID, command.kid.as_str());
    }
    if let Some(reason) = ending.reason {
        event = event.text(field::REASON, reason.name());
    }
    if let Some(code) = ending.code {
        event = event.text(field::CODE, code);
    }
    let appended = audit::append(&mut tx, event).await?;
    tx.commit()
        .await
        .map_err(|e| CoreError::AuditWrite(e.to_string()))?;
    recorder.critical(&[appended]);
    Ok(())
}

/// Registers the transcript of `session` for `agent`: an open SSH session
/// of this agent, not yet recorded.
async fn register(pool: &PgPool, agent: Uuid, session: Uuid, now: u64) -> Result<bool, CoreError> {
    let inserted = sqlx::query!(
        "INSERT INTO session_transcript (session_id, agent_id, started_at)
         SELECT s.id, s.agent_id, $3
         FROM access_session s JOIN access_grant g ON g.jti = s.jti
         WHERE s.id = $1::text::uuid AND s.agent_id = $2::text::uuid
           AND s.closed_at IS NULL AND g.protocol = 'ssh'
         ON CONFLICT (session_id) DO NOTHING",
        session.to_string(),
        agent.to_string(),
        i64_of(now.max(1)),
    )
    .execute(pool)
    .await?
    .rows_affected();
    Ok(inserted == 1)
}

/// Creates the file of a transcript, private, never over another, then
/// syncs its directory so that the file survives a crash.
fn create(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    if let Some(dir) = path.parent() {
        sync_dir(dir)?;
    }
    Ok(file)
}

/// Syncs a directory (its entries). Not possible on Windows, where the
/// metadata are journaled by NTFS.
#[cfg_attr(
    not(unix),
    expect(clippy::unnecessary_wraps, reason = "fallible on Unix only")
)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Writes the frames of `frames` to `file` until the queue is closed, then
/// flushes, syncs and makes the file read-only: blocking, run by
/// [`tokio::task::spawn_blocking`]. The buffer is flushed whenever the
/// queue is empty. Stops at the first error.
///
/// # Errors
///
/// [`RecorderError::Io`] (`REC-E004`), or an error of the writer.
fn write_file(
    file: File,
    path: &Path,
    session: Uuid,
    mut items: mpsc::Receiver<Item>,
    written: &watch::Sender<u64>,
) -> Result<Sealed, RecorderError> {
    let mut writer = CastWriter::new(
        BufWriter::with_capacity(WRITE_BUFFER, file),
        session.to_bytes(),
    );
    let mut mark = 0;
    while let Some(item) = items.blocking_recv() {
        match item {
            Item::Frame(frame) => writer.push(&frame)?,
            Item::Mark(at) => mark = at,
        }
        if items.is_empty() {
            writer.flush()?;
            written.send_if_modified(|w| std::mem::replace(w, mark) != mark);
        }
    }
    let (sealed, inner) = writer.finish()?;
    let file = inner
        .into_inner()
        .map_err(|e| RecorderError::Io(e.error().to_string()))?;
    file.sync_all()
        .map_err(|e| RecorderError::Io(e.to_string()))?;
    seal_rights(path).map_err(|e| RecorderError::Io(e.to_string()))?;
    written.send_replace(mark);
    Ok(sealed)
}

/// What the reading loop ended on.
struct Received {
    failure: Option<RecorderError>,
    reason: Option<EndReason>,
    command: Option<Command>,
    output_bytes: u64,
    /// Notes audited: transfers, refused requests.
    audited_notes: usize,
}

/// Most notes of one transcript recorded in the audit chain: the agent
/// sends few (one transfer per session, a bounded number of refusals), a
/// stream that sends more does not flood the chain; they all stay in the
/// sealed transcript.
const MAX_AUDITED_NOTES: usize = 32;

/// The audit record of a note of the transcript of `session`: a transfer
/// (`access.ssh_transfer`), a refused request
/// (`access.ssh_request_refused`) or a forwarding relayed
/// (`access.ssh_forward`); none for a file operation, which stays
/// in the transcript, nor past [`MAX_AUDITED_NOTES`].
fn note_event(
    agent: Uuid,
    session: Uuid,
    kind: NoteKind,
    text: &[u8],
    out: &mut Received,
) -> Option<Event> {
    let (event_kind, outcome, name) = match kind {
        NoteKind::Transfer => (
            EventKind::AccessSshTransfer,
            Outcome::Success,
            field::TRANSFER,
        ),
        NoteKind::Refused => (
            EventKind::AccessSshRequestRefused,
            Outcome::Refused,
            field::REQUEST,
        ),
        NoteKind::Forward => (
            EventKind::AccessSshForward,
            Outcome::Success,
            field::REQUEST,
        ),
        _ => return None,
    };
    if out.audited_notes >= MAX_AUDITED_NOTES {
        return None;
    }
    out.audited_notes += 1;
    // Printable ASCII, checked by the decoder.
    let text = String::from_utf8_lossy(text);
    tracing::info!(
        event = event_kind.name(),
        agent = %agent,
        session = %session,
        detail = %text,
    );
    Some(
        agent_event(event_kind, outcome, agent)
            .uuid(field::ACCESS_SESSION, session.to_bytes())
            .text(name, truncate(&text)),
    )
}

/// Keeps the hash of the command in the row as soon as it is known, so
/// that a transcript sealed at the next start still carries it.
async fn remember_command(pool: &PgPool, session: Uuid, command: &Command) {
    let kept = sqlx::query!(
        "UPDATE session_transcript SET command_hmac = $2, command_len = $3, command_kid = $4
         WHERE session_id = $1::text::uuid AND state = 'recording'",
        session.to_string(),
        &command.tag[..],
        i32::try_from(command.len).unwrap_or(i32::MAX),
        command.kid.as_str(),
    )
    .execute(pool)
    .await;
    if let Err(e) = kept {
        tracing::warn!(
            event = "transcript.command_unsaved",
            session = %session,
            "empreinte de la commande non gardée avant le scellement : {e}"
        );
    }
}

/// Where a transcript stream goes on after a loss.
struct Resumption<'a> {
    /// Streams that resume the transcript.
    streams: &'a mut mpsc::Receiver<Channel>,
    /// How long a lost stream waits for its resumption; zero: not at all.
    wait: Duration,
}

/// Whether a stream error may be followed by a resumption: the connection
/// is lost, or the agent gave up a stream the core no longer acknowledged.
fn resumable(error: &StreamError) -> bool {
    matches!(
        error,
        StreamError::ConnectionLost(_) | StreamError::Closed | StreamError::Reset(RESET_STALLED)
    )
}

/// Replaces the stream of a transcript by the one that resumes it, and
/// tells the agent where to resume from: the bytes received, a partial
/// frame included (the decoder keeps it).
async fn switch(
    channel: &mut Channel,
    resumed: Channel,
    received: u64,
    agent: Uuid,
    session: Uuid,
) {
    let mut old = std::mem::replace(channel, resumed);
    let _ = old.recv.stop(STOP_REPLACED);
    let _ = old.send.reset(STOP_REPLACED);
    drop(old);
    tracing::info!(
        event = "transcript.resumed",
        agent = %agent,
        session = %session,
        offset = received,
        "flux de transcript repris par l'agent"
    );
    // A failure shows on the next read.
    let _ = send_offset(channel, received).await;
}

/// Keeps what the seal needs from `frame`: the keyed hash of the command
/// of an `exec` (consigned at once, `access.ssh_exec`), the end reason.
async fn note(
    pool: &PgPool,
    store: &Transcripts,
    recorder: &Recorder,
    agent: Uuid,
    session: Uuid,
    frame: &Frame,
    out: &mut Received,
) {
    match &frame.event {
        ostena_recorder::Event::Start {
            command: Some(command),
            ..
        } => {
            let hashed = Command {
                tag: store.command_tag(session, command),
                len: command.len(),
                kid: store.key_id().to_owned(),
            };
            remember_command(pool, session, &hashed).await;
            recorder.emit(
                agent_event(EventKind::AccessSshExec, Outcome::Success, agent)
                    .uuid(field::ACCESS_SESSION, session.to_bytes())
                    .bytes(field::COMMAND_HMAC, hashed.tag)
                    .u64(field::LENGTH, command.len() as u64)
                    .text(field::KID, hashed.kid.as_str()),
            );
            out.command = Some(hashed);
            tracing::info!(
                event = "access.ssh_exec",
                agent = %agent,
                session = %session,
                length = command.len(),
                "commande d'une session SSH, empreinte à clé consignée"
            );
        }
        ostena_recorder::Event::Note { kind, text } => {
            if let Some(event) = note_event(agent, session, *kind, text, out) {
                recorder.emit(event);
            }
        }
        ostena_recorder::Event::End { reason, .. } => out.reason = Some(*reason),
        _ => {}
    }
}

/// Reads the stream into the queue of the file writer until its end or
/// the first failure, acknowledging what the writer wrote; a stream lost
/// with its connection waits for its resumption.
#[allow(clippy::too_many_arguments)]
async fn read_stream(
    pool: &PgPool,
    store: &Transcripts,
    recorder: &Recorder,
    agent: Uuid,
    session: Uuid,
    channel: &mut Channel,
    writer: &mpsc::Sender<Item>,
    written: &mut watch::Receiver<u64>,
    resumption: Resumption<'_>,
) -> Received {
    let Resumption { streams, wait } = resumption;
    let mut decoder = Decoder::new(store.limits);
    let mut buf = vec![0u8; READ_CHUNK];
    let mut received = 0u64;
    let mut out = Received {
        failure: None,
        reason: None,
        command: None,
        output_bytes: 0,
        audited_notes: 0,
    };
    'stream: loop {
        let read = tokio::select! {
            biased;
            Some(resumed) = streams.recv() => {
                switch(channel, resumed, received, agent, session).await;
                continue;
            }
            Ok(()) = written.changed() => {
                let acked = *written.borrow_and_update();
                // A failure shows on the next read.
                let _ = send_offset(channel, acked).await;
                continue;
            }
            read = channel.recv.read(&mut buf) => read,
        };
        match read {
            Ok(Some(n)) => {
                received += n as u64;
                decoder.feed(&buf[..n]);
                loop {
                    let frame = match decoder.next_frame() {
                        Ok(Some(frame)) => frame,
                        Ok(None) => break,
                        Err(e) => {
                            out.failure = Some(e);
                            break 'stream;
                        }
                    };
                    note(pool, store, recorder, agent, session, &frame, &mut out).await;
                    // Stopped on an error: it is told at the end.
                    if writer.send(Item::Frame(frame)).await.is_err() {
                        break 'stream;
                    }
                }
                let complete = received - decoder.pending() as u64;
                if writer.send(Item::Mark(complete)).await.is_err() {
                    break 'stream;
                }
                out.output_bytes = decoder.output_bytes();
            }
            Ok(None) => {
                out.failure = decoder.finish().err();
                break;
            }
            Err(e) if !wait.is_zero() && resumable(&e) => {
                tracing::warn!(
                    event = "transcript.interrupted",
                    agent = %agent,
                    session = %session,
                    wait_secs = wait.as_secs(),
                    "flux de transcript interrompu ({e}) : scellement différé, reprise attendue"
                );
                if let Ok(Some(resumed)) = tokio::time::timeout(wait, streams.recv()).await {
                    switch(channel, resumed, received, agent, session).await;
                } else {
                    out.failure = Some(RecorderError::Incomplete(
                        "flux interrompu, non repris pendant la grâce",
                    ));
                    break;
                }
            }
            Err(_) => {
                out.failure = Some(RecorderError::Incomplete("flux interrompu"));
                break;
            }
        }
    }
    out.output_bytes = decoder.output_bytes();
    out
}

/// Reads the stream of `session` into `file`, written by a blocking task;
/// returns what was read, what the writer sealed and the transcript bytes
/// it wrote. A writer error is the failure of the stream if it had none.
#[allow(clippy::too_many_arguments)]
async fn record(
    pool: &PgPool,
    store: &Transcripts,
    recorder: &Recorder,
    agent: Uuid,
    session: Uuid,
    channel: &mut Channel,
    file: File,
    resumption: Resumption<'_>,
) -> (Received, Result<Sealed, RecorderError>, u64) {
    let (items, queued) = mpsc::channel(WRITE_QUEUE);
    let (acked, mut written) = watch::channel(0u64);
    let writing = {
        let path = store.path(session);
        tokio::task::spawn_blocking(move || write_file(file, &path, session, queued, &acked))
    };
    let mut read = read_stream(
        pool,
        store,
        recorder,
        agent,
        session,
        channel,
        &items,
        &mut written,
        resumption,
    )
    .await;
    drop(items);
    let sealed = writing
        .await
        .unwrap_or_else(|e| Err(RecorderError::Io(e.to_string())));
    if read.failure.is_none()
        && let Err(e) = &sealed
    {
        read.failure = Some(e.clone());
    }
    let acked = *written.borrow();
    (read, sealed, acked)
}

/// Hands a stream that resumes the transcript of `session` to the task
/// that records it, if it is one of `agent`; otherwise gives it back.
fn hand_over(store: &Transcripts, agent: Uuid, session: Uuid, channel: Channel) -> Option<Channel> {
    let to = store.recording.lock().ok().and_then(|r| {
        r.get(&session)
            .filter(|(a, _)| *a == agent)
            .map(|(_, tx)| tx.clone())
    });
    match to {
        Some(tx) => tx.try_send(channel).err().map(|e| match e {
            mpsc::error::TrySendError::Full(c) | mpsc::error::TrySendError::Closed(c) => c,
        }),
        None => Some(channel),
    }
}

/// Receives the transcript stream of `session` from `agent`, writes it and
/// seals it (see the module documentation); a stream that resumes a
/// transcript is handed to the task recording it. Each refusal of the
/// stream is first counted by `refusal_allowed`, which closes the tunnel of
/// an agent beyond its limit: only refusals within the limit are reported
/// one by one.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub async fn receive(
    pool: &PgPool,
    recorder: &Recorder,
    store: &Transcripts,
    agent: Uuid,
    session: Uuid,
    mut channel: Channel,
    now: impl Fn() -> u64,
    refusal_allowed: impl Fn() -> bool,
) {
    // Stops the stream at once (the agent cuts the session), then gives the
    // record to write, within the limit of refusals.
    let refuse = |channel: &mut Channel, code: &str, reason: &str| {
        recording::refuse(channel);
        refusal_allowed().then(|| {
            tracing::warn!(
                event = "transcript.refused",
                agent = %agent,
                session = %session,
                code,
                "{reason}"
            );
            refused_event(agent, session, code, reason)
        })
    };
    let grace = match Preamble::read(&mut channel).await {
        Ok(Preamble::New { grace_secs }) => Duration::from_secs(grace_secs.into()),
        Ok(Preamble::Resume) => {
            if let Some(mut channel) = hand_over(store, agent, session, channel) {
                let event = refuse(
                    &mut channel,
                    REFUSED,
                    "reprise d'un transcript inconnu, terminé ou d'un autre agent",
                );
                protect(pool, recorder, event).await;
            }
            return;
        }
        Err(e) => {
            let event = refuse(&mut channel, MALFORMED, &e.to_string());
            protect(pool, recorder, event).await;
            return;
        }
    };
    let refusal = match register(pool, agent, session, now()).await {
        Ok(true) => None,
        Ok(false) => Some(refuse(
            &mut channel,
            REFUSED,
            "session inconnue, d'un autre agent, close, pas SSH ou déjà enregistrée",
        )),
        Err(e) => Some(refuse(&mut channel, REFUSED, &e.to_string())),
    };
    if let Some(event) = refusal {
        protect(pool, recorder, event).await;
        return;
    }
    let (resume_to, mut resumed) = mpsc::channel(1);
    if let Ok(mut recording) = store.recording.lock() {
        recording.insert(session, (agent, resume_to));
    }
    let registered = Recording { store, session };
    let path = store.path(session);
    let created = {
        let path = path.clone();
        tokio::task::spawn_blocking(move || create(&path))
            .await
            .unwrap_or_else(|e| Err(std::io::Error::other(e.to_string())))
    };
    let file = match created {
        Ok(file) => file,
        Err(e) => {
            drop(registered);
            let event = refuse(
                &mut channel,
                WRITE_FAILED,
                &format!("{} : {e}", path.display()),
            );
            protect(pool, recorder, event).await;
            // No file written: the seal says so, without a digest.
            let ending = Ending {
                sealed: None,
                output_bytes: 0,
                reason: None,
                code: Some(WRITE_FAILED),
                command: None,
            };
            if let Err(e) = seal(pool, recorder, agent, session, &ending, now()).await {
                tracing::warn!(event = "transcript.seal_failed", session = %session, code = e.code(), "{e}");
            }
            return;
        }
    };
    let resumption = Resumption {
        streams: &mut resumed,
        wait: if grace.is_zero() {
            Duration::ZERO
        } else {
            grace + RESUME_MARGIN
        },
    };
    let (read, written, acked) = record(
        pool,
        store,
        recorder,
        agent,
        session,
        &mut channel,
        file,
        resumption,
    )
    .await;
    drop(registered);
    let code = read.failure.as_ref().map(RecorderError::code);
    if let Some(failure) = &read.failure {
        if matches!(failure, RecorderError::Incomplete(_)) {
            tracing::warn!(event = "transcript.incomplete", agent = %agent, session = %session, code = failure.code(), "{failure}");
        } else {
            // The agent cuts the session.
            let event = refuse(&mut channel, failure.code(), &failure.to_string());
            protect(pool, recorder, event).await;
        }
    } else {
        // Written and synced: the agent may let the transcript go.
        let _ = send_offset(&mut channel, acked).await;
        let _ = channel.send.finish();
    }
    let Some((sealed, code)) = finish(written, &path, session, code).await else {
        // Left unsealed, sealed at the next start of the core (or the
        // start is refused): never a made-up digest.
        tracing::error!(
            event = "transcript.seal_failed",
            agent = %agent,
            session = %session,
            code = WRITE_FAILED,
            "fichier du transcript impossible à mesurer après une erreur d'écriture, laissé non scellé"
        );
        return;
    };
    let ending = Ending {
        sealed,
        output_bytes: read.output_bytes,
        reason: read.reason,
        code,
        command: read.command,
    };
    match seal(pool, recorder, agent, session, &ending, now()).await {
        Ok(()) => tracing::info!(
            event = "transcript.sealed",
            agent = %agent,
            session = %session,
            size = ending.sealed.as_ref().map_or(0, |s| s.size),
            complete = ending.code.is_none(),
            code = ending.code.unwrap_or_default(),
            "transcript scellé"
        ),
        Err(e) => {
            tracing::warn!(event = "transcript.seal_failed", session = %session, code = e.code(), "{e}");
        }
    }
}

/// The seal and the code of a transcript, from what the file writer
/// returned. If the file could not be finished, the file as it is on disk
/// is measured and sealed, incomplete; `None` if it cannot be measured:
/// the transcript is then left unsealed.
async fn finish(
    written: Result<Sealed, RecorderError>,
    path: &Path,
    session: Uuid,
    code: Option<&'static str>,
) -> Option<(Option<Sealed>, Option<&'static str>)> {
    match written {
        Ok(sealed) => Some((Some(sealed), code)),
        Err(e) => {
            tracing::warn!(event = "transcript.write_failed", session = %session, code = e.code(), "{e}");
            let path = path.to_path_buf();
            let on_disk = tokio::task::spawn_blocking(move || {
                let on_disk = measure(&path)?;
                if on_disk.is_some() {
                    seal_rights(&path)?;
                }
                Ok::<_, std::io::Error>(on_disk)
            })
            .await
            .ok()?
            .ok()?;
            Some((
                on_disk.map(|(size, sha256)| measured(size, sha256)),
                Some(code.unwrap_or(WRITE_FAILED)),
            ))
        }
    }
}

/// Seals as incomplete (`REC-E005`) the transcripts left unsealed by a stop
/// of the core, from their files as they are; returns how many.
///
/// # Errors
///
/// [`CoreError`] if they cannot be read or sealed: the start is refused,
/// an unsealed transcript must not stay unnoticed.
pub async fn recover(
    pool: &PgPool,
    recorder: &Recorder,
    store: &Transcripts,
    now: u64,
) -> Result<usize, CoreError> {
    let rows = sqlx::query!(
        r#"SELECT session_id::text AS "session!", agent_id::text AS "agent!",
                  command_hmac, command_len, command_kid
           FROM session_transcript WHERE state = 'recording'"#
    )
    .fetch_all(pool)
    .await?;
    for row in &rows {
        let session = crate::store::uuid(&row.session)?;
        let agent = crate::store::uuid(&row.agent)?;
        // The hash of a command, kept in the row as soon as it was known.
        let command = match (&row.command_hmac, row.command_len, &row.command_kid) {
            (Some(tag), Some(len), Some(kid)) => Some(Command {
                tag: <[u8; 32]>::try_from(tag.as_slice()).map_err(|_| {
                    CoreError::Database(format!("empreinte de commande invalide ({session})"))
                })?,
                len: usize::try_from(len).unwrap_or(0),
                kid: kid.clone(),
            }),
            _ => None,
        };
        let path = store.path(session);
        let on_disk =
            measure(&path).map_err(|e| CoreError::Startup(format!("{} : {e}", path.display())))?;
        if on_disk.is_some() {
            seal_rights(&path)
                .map_err(|e| CoreError::Startup(format!("{} : {e}", path.display())))?;
        }
        let size = on_disk.map_or(0, |(size, _)| size);
        let ending = Ending {
            sealed: on_disk.map(|(size, sha256)| measured(size, sha256)),
            output_bytes: 0,
            reason: None,
            code: Some(INCOMPLETE),
            command,
        };
        seal(pool, recorder, agent, session, &ending, now).await?;
        tracing::warn!(
            event = "transcript.sealed",
            agent = %agent,
            session = %session,
            size,
            complete = false,
            code = INCOMPLETE,
            "transcript interrompu par l'arrêt du core, scellé incomplet"
        );
    }
    Ok(rows.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ostena-core-transcripts-{label}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn frames() -> Vec<Frame> {
        vec![
            Frame {
                at_us: 0,
                event: ostena_recorder::Event::Start {
                    cols: 0,
                    rows: 0,
                    started_ms: 1_700_000_000_000,
                    term: String::new(),
                    command: Some(b"id".to_vec()),
                },
            },
            Frame {
                at_us: 10,
                event: ostena_recorder::Event::Output(b"uid=0(root)\n".to_vec()),
            },
            Frame {
                at_us: 20,
                event: ostena_recorder::Event::End {
                    reason: EndReason::Closed,
                    output_bytes: 12,
                },
            },
        ]
    }

    /// The file writer runs off the async workers, fed by a bounded queue:
    /// what it seals is what is on disk, read-only.
    #[test]
    fn the_file_writer_seals_what_it_wrote() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let dir = dir("writer");
        let session = Uuid::random().unwrap();
        let path = dir.join(format!("{session}.cast"));
        let file = create(&path).unwrap();
        assert!(create(&path).is_err(), "never over another file");
        let (acked, written_mark) = watch::channel(0u64);
        let sealed = rt.block_on(async {
            let (tx, rx) = mpsc::channel(1);
            let written = {
                let path = path.clone();
                tokio::task::spawn_blocking(move || write_file(file, &path, session, rx, &acked))
            };
            for (i, frame) in frames().into_iter().enumerate() {
                tx.send(Item::Frame(frame)).await.unwrap();
                tx.send(Item::Mark(i as u64 + 1)).await.unwrap();
            }
            drop(tx);
            written.await.unwrap().unwrap()
        });
        // Every mark is acknowledged once written, the last after the sync.
        assert_eq!(*written_mark.borrow(), frames().len() as u64);
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(sealed.size, bytes.len() as u64);
        assert_eq!(sealed.sha256, ostena_crypto::sha256::digest(&bytes));
        assert_eq!(measure(&path).unwrap(), Some((sealed.size, sealed.sha256)));
        assert_eq!(measure(&dir.join("absent.cast")).unwrap(), None);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o400);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// After a write error, what is sealed is the file as it is on disk;
    /// an absent file is sealed without a digest; a file that cannot be
    /// measured is not sealed at all.
    #[test]
    fn a_write_error_seals_the_file_on_disk_or_nothing() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let dir = dir("measure");
        let session = Uuid::random().unwrap();
        let failed = || Err(RecorderError::Io("disque plein".into()));
        rt.block_on(async {
            let path = dir.join("partial.cast");
            std::fs::write(&path, b"{\"version\":2,").unwrap();
            let (sealed, code) = finish(failed(), &path, session, None).await.unwrap();
            let sealed = sealed.unwrap();
            assert_eq!(sealed.size, 13);
            assert_eq!(
                sealed.sha256,
                ostena_crypto::sha256::digest(b"{\"version\":2,")
            );
            assert_eq!(code, Some(WRITE_FAILED));

            let absent = dir.join("absent.cast");
            let (sealed, code) = finish(failed(), &absent, session, Some("REC-E001"))
                .await
                .unwrap();
            assert!(sealed.is_none());
            assert_eq!(code, Some("REC-E001"));

            // A directory cannot be read as a file: nothing is sealed.
            #[cfg(unix)]
            assert!(finish(failed(), &dir, session, None).await.is_none());
        });
        let _ = std::fs::remove_dir_all(&dir);
    }
}
