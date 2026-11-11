//! Gateway anti-replay journal, kept across restarts.
//!
//! Layout: a 16-byte header (`OSTRPL01` then the fence, u64 big-endian),
//! followed by 28-byte records: jti (16), expiry (u64 BE), CRC-32 of the first
//! 24 bytes (u32 BE). Records are appended and synced to disk before a jti is
//! reported fresh.
//!
//! On open, a truncated last record (a write that never completed, hence never
//! acknowledged) is cut off. Any other damage refuses to start: run
//! `ostena agent replay-store repair`, which keeps the original file and sets a
//! fence so that grants that may have been consumed in lost records are refused.
//!
//! A `.lock` file next to the journal prevents two processes from using it.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::{Freshness, ReplayStore, ReplayStoreError};
use crate::ids::Jti;

const MAGIC: [u8; 8] = *b"OSTRPL01";
const HEADER_LEN: usize = 16;
const RECORD_LEN: usize = 28;
/// Entries are kept this long after expiry, in case the clock steps back.
const RETENTION_MARGIN_SECS: u64 = 3600;
/// Compaction runs once at least this many dead records accumulate.
const COMPACT_MIN_DEAD: usize = 1024;

/// File-backed [`ReplayStore`] for a gateway.
#[derive(Debug)]
pub struct FileReplayStore {
    path: PathBuf,
    inner: Mutex<Inner>,
    _lock: File,
}

#[derive(Debug)]
struct Inner {
    file: File,
    len: u64,
    seen: HashMap<Jti, u64>,
    records: usize,
    fence: u64,
    /// A failed write could not be rolled back: refuse everything.
    poisoned: bool,
}

/// Outcome of [`repair`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairReport {
    /// Copy of the original file, left untouched.
    pub backup: PathBuf,
    /// Valid records kept.
    pub kept: usize,
    /// Damaged records dropped.
    pub dropped: usize,
    /// Bytes of a truncated last record dropped.
    pub truncated_bytes: usize,
    /// Grants expiring at or before this time (Unix seconds) are refused.
    pub fence: u64,
}

fn err(message: impl Into<String>) -> ReplayStoreError {
    ReplayStoreError(message.into())
}

fn io_err(what: &str, path: &Path, e: &std::io::Error) -> ReplayStoreError {
    err(format!("{what} {} : {e}", path.display()))
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// CRC-32 (IEEE 802.3, reflected), bitwise: records are tiny.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn encode_record(jti: Jti, expires_at: u64) -> [u8; RECORD_LEN] {
    let mut out = [0u8; RECORD_LEN];
    out[..16].copy_from_slice(&jti.to_bytes());
    out[16..24].copy_from_slice(&expires_at.to_be_bytes());
    let crc = crc32(&out[..24]);
    out[24..].copy_from_slice(&crc.to_be_bytes());
    out
}

fn decode_record(raw: &[u8; RECORD_LEN]) -> Option<(Jti, u64)> {
    let (data, crc) = raw.split_at(24);
    if crc32(data).to_be_bytes() != crc {
        return None;
    }
    let mut jti = [0u8; 16];
    jti.copy_from_slice(&data[..16]);
    let mut exp = [0u8; 8];
    exp.copy_from_slice(&data[16..24]);
    Some((Jti::from_bytes(jti), u64::from_be_bytes(exp)))
}

struct Parsed {
    fence: u64,
    records: Vec<(Jti, u64)>,
    valid_len: usize,
}

fn parse(bytes: &[u8]) -> Result<Parsed, String> {
    if bytes.len() < HEADER_LEN || bytes[..8] != MAGIC {
        return Err("en-tête absent ou invalide".into());
    }
    let mut fence = [0u8; 8];
    fence.copy_from_slice(&bytes[8..16]);
    let body = &bytes[HEADER_LEN..];
    let mut records = Vec::with_capacity(body.len() / RECORD_LEN);
    for (i, raw) in body.as_chunks::<RECORD_LEN>().0.iter().enumerate() {
        let record = decode_record(raw).ok_or_else(|| {
            format!(
                "enregistrement {i} (octet {}) : somme de contrôle invalide",
                HEADER_LEN + i * RECORD_LEN
            )
        })?;
        records.push(record);
    }
    Ok(Parsed {
        fence: u64::from_be_bytes(fence),
        valid_len: HEADER_LEN + records.len() * RECORD_LEN,
        records,
    })
}

fn acquire_lock(path: &Path) -> Result<File, ReplayStoreError> {
    let lock_path = sibling(path, ".lock");
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .map_err(|e| io_err("impossible d'ouvrir le verrou", &lock_path, &e))?;
    lock.try_lock().map_err(|_| {
        err(format!(
            "le journal anti-rejeu {} est déjà utilisé par un autre processus",
            path.display()
        ))
    })?;
    Ok(lock)
}

/// Writes a complete journal to `<path>.tmp`, synced, and renames it over
/// `path`. Returns a handle on the new file.
fn replace_with(path: &Path, fence: u64, records: &[(Jti, u64)]) -> Result<File, ReplayStoreError> {
    let tmp = sibling(path, ".tmp");
    let mut bytes = Vec::with_capacity(HEADER_LEN + records.len() * RECORD_LEN);
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&fence.to_be_bytes());
    for (jti, exp) in records {
        bytes.extend_from_slice(&encode_record(*jti, *exp));
    }
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&tmp)
        .map_err(|e| io_err("impossible de créer", &tmp, &e))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| io_err("impossible d'écrire", &tmp, &e))?;
    // The handle follows the file through the rename.
    fs::rename(&tmp, path).map_err(|e| io_err("impossible de remplacer", path, &e))?;
    sync_parent(path)?;
    Ok(file)
}

/// Makes a rename durable. NTFS journals metadata itself.
#[cfg_attr(
    not(unix),
    expect(clippy::unnecessary_wraps, reason = "same signature as on Unix")
)]
fn sync_parent(path: &Path) -> Result<(), ReplayStoreError> {
    #[cfg(unix)]
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        File::open(parent)
            .and_then(|d| d.sync_all())
            .map_err(|e| io_err("impossible de synchroniser le dossier", parent, &e))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

impl FileReplayStore {
    /// Opens (or creates) the journal at `path`.
    ///
    /// # Errors
    ///
    /// The journal is locked by another process, unreadable, or damaged
    /// beyond a truncated last record: starting is refused.
    pub fn open(path: &Path) -> Result<Self, ReplayStoreError> {
        let lock = acquire_lock(path)?;
        if !path.exists() {
            replace_with(path, 0, &[])?;
        }
        let bytes = fs::read(path).map_err(|e| io_err("impossible de lire", path, &e))?;
        let parsed = parse(&bytes).map_err(|reason| {
            err(format!(
                "journal anti-rejeu {} endommagé ({reason}) ; démarrage refusé. Reprise : \
                 `ostena agent replay-store repair --path {}`",
                path.display(),
                path.display()
            ))
        })?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| io_err("impossible d'ouvrir", path, &e))?;
        if parsed.valid_len < bytes.len() {
            tracing::warn!(
                event = "replay_store.truncated_tail",
                path = %path.display(),
                bytes = bytes.len() - parsed.valid_len,
                "dernier enregistrement incomplet supprimé (écriture jamais validée)"
            );
            file.set_len(parsed.valid_len as u64)
                .and_then(|()| file.sync_all())
                .map_err(|e| io_err("impossible de tronquer", path, &e))?;
        }
        let mut seen = HashMap::with_capacity(parsed.records.len());
        for (jti, exp) in &parsed.records {
            let kept = seen.entry(*jti).or_insert(*exp);
            *kept = (*kept).max(*exp);
        }
        Ok(Self {
            path: path.to_path_buf(),
            inner: Mutex::new(Inner {
                file,
                len: parsed.valid_len as u64,
                records: parsed.records.len(),
                seen,
                fence: parsed.fence,
                poisoned: false,
            }),
            _lock: lock,
        })
    }

    /// Forgets entries that expired more than an hour before `now`, and
    /// compacts the file when dead records dominate. Returns how many entries
    /// were forgotten.
    ///
    /// # Errors
    ///
    /// The compacted file cannot be written; the store is then poisoned.
    pub fn purge(&self, now: u64) -> Result<usize, ReplayStoreError> {
        let mut inner = self.lock()?;
        let before = inner.seen.len();
        inner
            .seen
            .retain(|_, exp| exp.saturating_add(RETENTION_MARGIN_SECS) >= now);
        let removed = before - inner.seen.len();
        let live = inner.seen.len();
        let dead = inner.records - live;
        if dead >= COMPACT_MIN_DEAD && dead > live {
            let records: Vec<(Jti, u64)> = inner.seen.iter().map(|(j, e)| (*j, *e)).collect();
            match replace_with(&self.path, inner.fence, &records) {
                Ok(file) => {
                    inner.file = file;
                    inner.len = (HEADER_LEN + live * RECORD_LEN) as u64;
                    inner.records = live;
                }
                Err(e) => {
                    inner.poisoned = true;
                    return Err(e);
                }
            }
        }
        Ok(removed)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Inner>, ReplayStoreError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| err("verrou de l'anti-rejeu empoisonné"))?;
        if inner.poisoned {
            return Err(err(format!(
                "journal anti-rejeu {} dans un état incertain après une erreur d'écriture ; \
                 redémarrage nécessaire",
                self.path.display()
            )));
        }
        Ok(inner)
    }

    fn consume_sync(&self, jti: Jti, expires_at: u64) -> Result<Freshness, ReplayStoreError> {
        let mut inner = self.lock()?;
        if expires_at <= inner.fence {
            return Ok(Freshness::Fenced);
        }
        if inner.seen.contains_key(&jti) {
            return Ok(Freshness::Replayed);
        }
        let record = encode_record(jti, expires_at);
        let at = inner.len;
        let written = inner
            .file
            .seek(SeekFrom::Start(at))
            .and_then(|_| inner.file.write_all(&record))
            .and_then(|()| inner.file.sync_data());
        if let Err(e) = written {
            // Roll back a partial record, or stop trusting the file.
            if inner
                .file
                .set_len(at)
                .and_then(|()| inner.file.sync_all())
                .is_err()
            {
                inner.poisoned = true;
            }
            return Err(io_err("impossible d'écrire dans", &self.path, &e));
        }
        inner.len += RECORD_LEN as u64;
        inner.records += 1;
        inner.seen.insert(jti, expires_at);
        Ok(Freshness::Fresh)
    }
}

impl ReplayStore for FileReplayStore {
    /// Synchronous append + fsync (about 1 to 10 ms), well within the session
    /// set-up budget.
    fn consume(
        &self,
        jti: Jti,
        expires_at: u64,
    ) -> impl Future<Output = Result<Freshness, ReplayStoreError>> + Send {
        std::future::ready(self.consume_sync(jti, expires_at))
    }
}

/// Rebuilds a damaged journal, keeping every record whose checksum is valid.
///
/// The original file is first copied to `<path>.corrupt-<now>` and never
/// modified. The new journal carries a fence (the larger of `fence` and the old
/// one): grants expiring at or before it are refused, since they may have been
/// consumed in a dropped record. Use at least now + maximum TTL + tolerance.
///
/// # Errors
///
/// The journal is in use by another process, or a file cannot be read or
/// written.
pub fn repair(path: &Path, now: u64, fence: u64) -> Result<RepairReport, ReplayStoreError> {
    let _lock = acquire_lock(path)?;
    let bytes = fs::read(path).map_err(|e| io_err("impossible de lire", path, &e))?;

    let backup = sibling(path, &format!(".corrupt-{now}"));
    fs::copy(path, &backup)
        .and_then(|_| OpenOptions::new().write(true).open(&backup)?.sync_all())
        .map_err(|e| io_err("impossible de sauvegarder vers", &backup, &e))?;

    let header_ok = bytes.len() >= HEADER_LEN && bytes[..8] == MAGIC;
    let (old_fence, body) = if header_ok {
        let mut f = [0u8; 8];
        f.copy_from_slice(&bytes[8..16]);
        (u64::from_be_bytes(f), &bytes[HEADER_LEN..])
    } else {
        // Without a valid header, the record alignment is unknown: keep nothing.
        (0, &[][..])
    };
    let (chunks, tail) = body.as_chunks::<RECORD_LEN>();
    let truncated_bytes = tail.len() + if header_ok { 0 } else { bytes.len() };
    let total = chunks.len();
    let records: Vec<(Jti, u64)> = chunks.iter().filter_map(decode_record).collect();
    let fence = fence.max(old_fence);
    replace_with(path, fence, &records)?;
    Ok(RepairReport {
        backup,
        kept: records.len(),
        dropped: total - records.len(),
        truncated_bytes,
        fence,
    })
}

#[cfg(test)]
mod tests {
    use super::super::tests::block_on;
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("ostena-replay-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn journal(&self) -> PathBuf {
            self.0.join("replay.journal")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn jti(n: u8) -> Jti {
        Jti::from_bytes([n; 16])
    }

    fn consume(store: &FileReplayStore, j: Jti, exp: u64) -> Freshness {
        block_on(store.consume(j, exp)).unwrap()
    }

    #[test]
    fn crc32_known_answer() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn survives_restart() {
        let dir = TempDir::new("restart");
        let path = dir.journal();
        {
            let store = FileReplayStore::open(&path).unwrap();
            assert_eq!(consume(&store, jti(1), 100), Freshness::Fresh);
            assert_eq!(consume(&store, jti(1), 100), Freshness::Replayed);
            assert_eq!(consume(&store, jti(2), 100), Freshness::Fresh);
        }
        let store = FileReplayStore::open(&path).unwrap();
        assert_eq!(consume(&store, jti(1), 100), Freshness::Replayed);
        assert_eq!(consume(&store, jti(2), 100), Freshness::Replayed);
        assert_eq!(consume(&store, jti(3), 100), Freshness::Fresh);
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            (HEADER_LEN + 3 * RECORD_LEN) as u64
        );
    }

    #[test]
    fn second_process_is_refused() {
        let dir = TempDir::new("lock");
        let _store = FileReplayStore::open(&dir.journal()).unwrap();
        let err = FileReplayStore::open(&dir.journal()).unwrap_err();
        assert!(err.0.contains("déjà utilisé"), "{err}");
    }

    #[test]
    fn truncated_tail_is_cut_off() {
        let dir = TempDir::new("tail");
        let path = dir.journal();
        consume(&FileReplayStore::open(&path).unwrap(), jti(1), 100);
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&[0xaa; 10]).unwrap();
        drop(f);
        let store = FileReplayStore::open(&path).unwrap();
        assert_eq!(consume(&store, jti(1), 100), Freshness::Replayed);
        assert_eq!(consume(&store, jti(2), 100), Freshness::Fresh);
        drop(store);
        assert!(FileReplayStore::open(&path).is_ok());
    }

    #[test]
    fn damaged_record_refuses_to_start() {
        let dir = TempDir::new("damaged");
        let path = dir.journal();
        consume(&FileReplayStore::open(&path).unwrap(), jti(1), 100);
        let mut bytes = fs::read(&path).unwrap();
        bytes[HEADER_LEN + 3] ^= 0x01;
        fs::write(&path, &bytes).unwrap();
        let err = FileReplayStore::open(&path).unwrap_err();
        assert!(err.0.contains("endommagé"), "{err}");
        assert!(err.0.contains("replay-store repair"), "{err}");
    }

    #[test]
    fn bad_header_refuses_to_start() {
        let dir = TempDir::new("header");
        let path = dir.journal();
        fs::write(&path, b"not a journal").unwrap();
        assert!(FileReplayStore::open(&path).is_err());
    }

    #[test]
    fn repair_keeps_original_and_fences() {
        let dir = TempDir::new("repair");
        let path = dir.journal();
        {
            let store = FileReplayStore::open(&path).unwrap();
            for n in 1..=3 {
                consume(&store, jti(n), 10_000);
            }
        }
        let mut bytes = fs::read(&path).unwrap();
        bytes[HEADER_LEN + RECORD_LEN + 5] ^= 0xff; // damage record 1 (jti 2)
        bytes.extend_from_slice(&[0; 7]); // and a torn tail
        fs::write(&path, &bytes).unwrap();
        assert!(FileReplayStore::open(&path).is_err());

        let report = repair(&path, 1_000, 1_305).unwrap();
        assert_eq!(report.kept, 2);
        assert_eq!(report.dropped, 1);
        assert_eq!(report.truncated_bytes, 7);
        assert_eq!(report.fence, 1_305);
        assert_eq!(fs::read(&report.backup).unwrap(), bytes);

        let store = FileReplayStore::open(&path).unwrap();
        assert_eq!(consume(&store, jti(1), 10_000), Freshness::Replayed);
        assert_eq!(consume(&store, jti(3), 10_000), Freshness::Replayed);
        // jti 9 may have been consumed in the dropped record: refused if it
        // expires at or before the fence.
        assert_eq!(consume(&store, jti(9), 1_305), Freshness::Fenced);
        assert_eq!(consume(&store, jti(9), 1_306), Freshness::Fresh);
    }

    #[test]
    fn repair_never_lowers_the_fence() {
        let dir = TempDir::new("fence");
        let path = dir.journal();
        drop(FileReplayStore::open(&path).unwrap());
        repair(&path, 1, 5_000).unwrap();
        let report = repair(&path, 2, 10).unwrap();
        assert_eq!(report.fence, 5_000);
    }

    #[test]
    fn repair_refuses_while_in_use() {
        let dir = TempDir::new("repair-lock");
        let path = dir.journal();
        let _store = FileReplayStore::open(&path).unwrap();
        assert!(repair(&path, 1, 1).is_err());
    }

    #[test]
    fn purge_compacts() {
        let dir = TempDir::new("purge");
        let path = dir.journal();
        let store = FileReplayStore::open(&path).unwrap();
        let count = u16::try_from(COMPACT_MIN_DEAD + 10).unwrap();
        for n in 0..count {
            let mut b = [0u8; 16];
            b[..2].copy_from_slice(&n.to_be_bytes());
            consume(&store, Jti::from_bytes(b), 100);
        }
        consume(&store, jti(0xff), 1_000_000);
        let removed = store.purge(100 + RETENTION_MARGIN_SECS + 1).unwrap();
        assert_eq!(removed, usize::from(count));
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            (HEADER_LEN + RECORD_LEN) as u64
        );
        assert_eq!(consume(&store, jti(0xff), 1_000_000), Freshness::Replayed);
        assert_eq!(consume(&store, jti(0xfe), 1_000_000), Freshness::Fresh);
        drop(store);
        let reopened = FileReplayStore::open(&path).unwrap();
        assert_eq!(
            consume(&reopened, jti(0xfe), 1_000_000),
            Freshness::Replayed
        );
    }
}
