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
//! The stream is read and decoded on the async workers; the file is
//! written by a blocking task ([`tokio::task::spawn_blocking`]) fed through
//! a bounded queue, behind a 64 KiB buffer: a slow disk slows down the
//! stream of its session (back-pressure up to the agent), never the
//! workers. A write reaches the kernel cache, not the disk, until the
//! final sync; the directory is synced after the file is created.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read};
use std::path::{Path, PathBuf};

use ostena_audit::{Event, EventKind, Outcome, field};
use ostena_crypto::hmac::HmacKey;
use ostena_recorder::{CastWriter, Decoder, EndReason, Frame, Limits, RecorderError, Sealed};
use ostena_tunnel::{Channel, Uuid};
use sqlx::PgPool;
use tokio::sync::mpsc;

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

/// Domain of the keyed hash of a command: never the same input as another
/// use of the key.
const EXEC_DOMAIN: &[u8] = b"ostena/ssh-exec/v1\0";
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
    limits: Limits,
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
        Ok(Self {
            dir: dir.to_path_buf(),
            mac,
            limits: Limits::default(),
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
    command: Option<([u8; 32], usize)>,
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
                command_hmac = $11, command_len = $12
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
        ending.command.as_ref().map(|(tag, _)| &tag[..]),
        ending
            .command
            .as_ref()
            .map(|(_, len)| i32::try_from(*len).unwrap_or(i32::MAX)),
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
    mut frames: mpsc::Receiver<Frame>,
) -> Result<Sealed, RecorderError> {
    let mut writer = CastWriter::new(
        BufWriter::with_capacity(WRITE_BUFFER, file),
        session.to_bytes(),
    );
    while let Some(frame) = frames.blocking_recv() {
        writer.push(&frame)?;
        if frames.is_empty() {
            writer.flush()?;
        }
    }
    let (sealed, inner) = writer.finish()?;
    let file = inner
        .into_inner()
        .map_err(|e| RecorderError::Io(e.error().to_string()))?;
    file.sync_all()
        .map_err(|e| RecorderError::Io(e.to_string()))?;
    seal_rights(path).map_err(|e| RecorderError::Io(e.to_string()))?;
    Ok(sealed)
}

/// What the reading loop ended on.
struct Received {
    failure: Option<RecorderError>,
    reason: Option<EndReason>,
    command: Option<([u8; 32], usize)>,
    output_bytes: u64,
}

/// Reads the stream into the queue of the file writer until its end or
/// the first failure.
async fn read_stream(
    store: &Transcripts,
    recorder: &Recorder,
    agent: Uuid,
    session: Uuid,
    channel: &mut Channel,
    writer: &mpsc::Sender<Frame>,
) -> Received {
    let mut decoder = Decoder::new(store.limits);
    let mut buf = vec![0u8; READ_CHUNK];
    let mut out = Received {
        failure: None,
        reason: None,
        command: None,
        output_bytes: 0,
    };
    'stream: loop {
        match channel.recv.read(&mut buf).await {
            Ok(Some(n)) => {
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
                    match &frame.event {
                        ostena_recorder::Event::Start {
                            command: Some(command),
                            ..
                        } => {
                            let tag = store.command_tag(session, command);
                            out.command = Some((tag, command.len()));
                            recorder.emit(
                                agent_event(EventKind::AccessSshExec, Outcome::Success, agent)
                                    .uuid(field::ACCESS_SESSION, session.to_bytes())
                                    .bytes(field::COMMAND_HMAC, tag)
                                    .u64(field::LENGTH, command.len() as u64),
                            );
                            tracing::info!(
                                event = "access.ssh_exec",
                                agent = %agent,
                                session = %session,
                                length = command.len(),
                                "commande d'une session SSH, empreinte à clé consignée"
                            );
                        }
                        ostena_recorder::Event::End { reason, .. } => out.reason = Some(*reason),
                        _ => {}
                    }
                    // Stopped on an error: it is told at the end.
                    if writer.send(frame).await.is_err() {
                        break 'stream;
                    }
                }
                out.output_bytes = decoder.output_bytes();
            }
            Ok(None) => {
                out.failure = decoder.finish().err();
                break;
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
/// returns what was read and what the writer sealed. A writer error is the
/// failure of the stream if it had none.
async fn record(
    store: &Transcripts,
    recorder: &Recorder,
    agent: Uuid,
    session: Uuid,
    channel: &mut Channel,
    file: File,
) -> (Received, Result<Sealed, RecorderError>) {
    let (frames, queued) = mpsc::channel(WRITE_QUEUE);
    let written = {
        let path = store.path(session);
        tokio::task::spawn_blocking(move || write_file(file, &path, session, queued))
    };
    let mut read = read_stream(store, recorder, agent, session, channel, &frames).await;
    drop(frames);
    let written = written
        .await
        .unwrap_or_else(|e| Err(RecorderError::Io(e.to_string())));
    if read.failure.is_none()
        && let Err(e) = &written
    {
        read.failure = Some(e.clone());
    }
    (read, written)
}

/// Receives the transcript stream of `session` from `agent`, writes it and
/// seals it (see the module documentation).
pub async fn receive(
    pool: &PgPool,
    recorder: &Recorder,
    store: &Transcripts,
    agent: Uuid,
    session: Uuid,
    mut channel: Channel,
    now: impl Fn() -> u64,
) {
    let refuse = |channel: &mut Channel, code: &str, reason: &str| {
        tracing::warn!(
            event = "transcript.refused",
            agent = %agent,
            session = %session,
            code,
            "{reason}"
        );
        recorder.emit(refused_event(agent, session, code, reason));
        ostena_tunnel::recording::refuse(channel);
    };
    match register(pool, agent, session, now()).await {
        Ok(true) => {}
        Ok(false) => {
            return refuse(
                &mut channel,
                REFUSED,
                "session inconnue, d'un autre agent, close, pas SSH ou déjà enregistrée",
            );
        }
        Err(e) => return refuse(&mut channel, REFUSED, &e.to_string()),
    }
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
            refuse(
                &mut channel,
                WRITE_FAILED,
                &format!("{} : {e}", path.display()),
            );
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
    let (read, written) = record(store, recorder, agent, session, &mut channel, file).await;
    let code = read.failure.as_ref().map(RecorderError::code);
    if let Some(failure) = &read.failure {
        if matches!(failure, RecorderError::Incomplete(_)) {
            tracing::warn!(event = "transcript.incomplete", agent = %agent, session = %session, code = failure.code(), "{failure}");
        } else {
            // The agent cuts the session.
            refuse(&mut channel, failure.code(), &failure.to_string());
        }
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
        r#"SELECT session_id::text AS "session!", agent_id::text AS "agent!"
           FROM session_transcript WHERE state = 'recording'"#
    )
    .fetch_all(pool)
    .await?;
    for row in &rows {
        let session = crate::store::uuid(&row.session)?;
        let agent = crate::store::uuid(&row.agent)?;
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
            command: None,
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
        let sealed = rt.block_on(async {
            let (tx, rx) = mpsc::channel(1);
            let written = {
                let path = path.clone();
                tokio::task::spawn_blocking(move || write_file(file, &path, session, rx))
            };
            for frame in frames() {
                tx.send(frame).await.unwrap();
            }
            drop(tx);
            written.await.unwrap().unwrap()
        });
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
