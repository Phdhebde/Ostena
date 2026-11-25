//! Streaming verifier of an audit chain (ADR-0012).
//!
//! Records and heads are pushed in chain order; the verifier keeps only the
//! current tip, the last head and counters, so memory does not grow with the
//! chain. The same code checks an export offline (`ostena audit verify`) and,
//! later, segments of the chain inside the core.
//!
//! Exit codes of [`Report::exit_code`]: 0 intact and covered by a head,
//! 1 at least one error, 2 warnings only. The command line uses 3 for usage
//! and input/output errors.

use std::fmt;
use std::io::Read;

use crate::AuditError;
use crate::export::{ExportReader, Frame};
use crate::head::{Head, TrustedKeys};
use crate::ids::ChainId;
use crate::record::{Digest, Record, Value, ZERO_DIGEST, record_hash};

/// Largest number of findings kept in a report; the others are only counted.
pub const MAX_FINDINGS: usize = 1000;

/// Severity of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    /// The chain is not intact, or cannot be trusted.
    Error,
    /// The chain is intact, but its coverage or its clock is doubtful.
    Warning,
}

/// What the verifier found. Codes are stable: never renumber or reuse one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// A record, a head or the export is malformed, or a head does not
    /// verify (`AUD-E001` to `AUD-E004`, `AUD-E008`, `AUD-E009`).
    Invalid {
        /// Expected seq of the record concerned, if known.
        seq: Option<u64>,
        /// The error.
        error: AuditError,
    },
    /// `AUD-E005`: a record or head of another chain.
    ChainId {
        /// Chain of the export.
        expected: ChainId,
        /// Chain found.
        got: ChainId,
    },
    /// `AUD-E006`: the seq does not follow (deletion, reordering, duplicate).
    Sequence {
        /// Expected seq.
        expected: u64,
        /// Seq found.
        got: u64,
    },
    /// `AUD-E007`: the previous hash of a record is not the hash of the
    /// record before it.
    HashLink {
        /// Seq of the record.
        seq: u64,
    },
    /// `AUD-E011`: a head does not match the chain tip at its position.
    HeadMismatch {
        /// Head number.
        head_no: u64,
        /// Record seq announced by the head.
        record_seq: u64,
        /// Seq of the last record read, if any.
        tip_seq: Option<u64>,
    },
    /// `AUD-E012`: head number or previous head hash does not follow.
    HeadSequence {
        /// Expected head number.
        expected: u64,
        /// Head number found.
        got: u64,
    },
    /// `AUD-E013`: the export disagrees with an external head.
    External {
        /// Number of the external head.
        head_no: u64,
        /// Record seq it covers.
        record_seq: u64,
        /// `true`: the export has this record with another hash (fork);
        /// `false`: the export lacks it (truncation).
        fork: bool,
    },
    /// `AUD-E014`: a partial export without a trusted anchor head.
    NoAnchor {
        /// First seq of the export.
        first_seq: u64,
    },
    /// `AUD-W001`: records after the last head, covered by no signature.
    UncoveredTail {
        /// Number of records.
        count: u64,
    },
    /// `AUD-W002`: time goes backwards beyond the tolerance.
    ClockBackwards {
        /// Seq of the record (or record seq of the head).
        seq: u64,
        /// Previous time, Unix ms.
        previous_ms: u64,
        /// Time found, Unix ms.
        time_ms: u64,
    },
    /// `AUD-W003`: two heads further apart than heartbeat plus tolerance.
    HeadGap {
        /// Number of the later head.
        head_no: u64,
        /// Interval, seconds.
        gap_secs: u64,
        /// Accepted interval, seconds.
        allowed_secs: u64,
    },
    /// `AUD-W004`: last head older than twice its heartbeat at export time.
    StaleHead {
        /// Number of the last head.
        head_no: u64,
        /// Its age at export time, seconds.
        age_secs: u64,
        /// Accepted age, seconds.
        allowed_secs: u64,
    },
    /// `AUD-E017`: a transcript sealed in the chain is absent from the
    /// transcript directory.
    TranscriptMissing {
        /// Its file name.
        file: String,
        /// Seq of its seal.
        seq: u64,
    },
    /// `AUD-E018`: a transcript differs from its seal (size or SHA-256).
    TranscriptAltered {
        /// Its file name.
        file: String,
        /// Seq of its seal.
        seq: u64,
    },
    /// `AUD-W005`: a transcript file without a seal in the export (not
    /// sealed yet, sealed outside the export, or added).
    TranscriptUnsealed {
        /// Its file name.
        file: String,
    },
    /// `AUD-E019`: an SSH session opened in the export (`access.session_opened`)
    /// whose transcript is not sealed in it, though the session must have
    /// ended before the export.
    TranscriptNeverSealed {
        /// The file its transcript would have.
        file: String,
        /// Seq of `access.session_opened`.
        seq: u64,
    },
    /// `AUD-W007`: an SSH session opened in the export, not sealed in it,
    /// that may still have been running at export time.
    TranscriptPending {
        /// The file its transcript would have.
        file: String,
        /// Seq of `access.session_opened`.
        seq: u64,
    },
    /// `AUD-W006`: a transcript sealed as incomplete (stream cut, core
    /// stopped): it is intact, but the session may not be in full.
    TranscriptIncomplete {
        /// Its file name.
        file: String,
        /// Seq of its seal.
        seq: u64,
        /// Why (`REC-E…`).
        code: String,
    },
}

/// An SSH session opened in the export (`access.session_opened`): its
/// transcript must be sealed once it ends (ADR-0016).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshSession {
    /// Seq of the record.
    pub seq: u64,
    /// The access session.
    pub session: [u8; 16],
    /// Time of the record, Unix milliseconds.
    pub opened_ms: u64,
    /// Its maximum length, seconds.
    pub max_session_secs: u64,
}

impl SshSession {
    /// The SSH session opened by `record`, if it is an
    /// `access.session_opened` record of SSH (every session of the jalon
    /// M1; a record without a protocol is one).
    fn of(record: &Record) -> Option<Self> {
        if record.event != "access.session_opened" {
            return None;
        }
        let get = |name: &str| {
            record
                .fields
                .iter()
                .find(|f| f.name == name)
                .map(|f| &f.value)
        };
        match get(crate::field::PROTOCOL) {
            None => {}
            Some(Value::Text(p)) if p == "ssh" => {}
            Some(_) => return None,
        }
        let session = match get(crate::field::ACCESS_SESSION)? {
            Value::Uuid(u) => *u,
            _ => return None,
        };
        let max_session_secs = match get(crate::field::MAX_SESSION_SECS) {
            Some(Value::U64(n)) => *n,
            _ => u64::MAX,
        };
        Some(Self {
            seq: record.seq,
            session,
            opened_ms: record.time_ms,
            max_session_secs,
        })
    }

    /// When it ended at the latest, with `margin_ms` for the end of its
    /// transcript.
    pub fn ended_by_ms(&self, margin_ms: u64) -> u64 {
        self.opened_ms
            .saturating_add(self.max_session_secs.saturating_mul(1000))
            .saturating_add(margin_ms)
    }

    /// The file name of its transcript.
    pub fn file_name(&self) -> String {
        file_name(&self.session)
    }
}

/// The file name of the transcript of `session`: `<uuid>.cast`.
fn file_name(session: &[u8; 16]) -> String {
    let h = |range: std::ops::Range<usize>| {
        session[range].iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
            s
        })
    };
    format!(
        "{}-{}-{}-{}-{}.cast",
        h(0..4),
        h(4..6),
        h(6..8),
        h(8..10),
        h(10..16)
    )
}

/// A transcript seal read from a `transcript.sealed` record (ADR-0016).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptSeal {
    /// Seq of the record.
    pub seq: u64,
    /// The access session, which names the file (`<uuid>.cast`).
    pub session: [u8; 16],
    /// Size and SHA-256 of the file; `None` when the core wrote no file
    /// (it could not be created, or was gone): the file must then be
    /// absent.
    pub digest: Option<(u64, [u8; 32])>,
    /// Ended by its end frame.
    pub complete: bool,
    /// Why it is incomplete.
    pub code: Option<String>,
}

impl TranscriptSeal {
    /// The seal carried by `record`, if it is a well-formed
    /// `transcript.sealed` record.
    fn of(record: &Record) -> Option<Self> {
        if record.event != "transcript.sealed" {
            return None;
        }
        let get = |name: &str| {
            record
                .fields
                .iter()
                .find(|f| f.name == name)
                .map(|f| &f.value)
        };
        let session = match get(crate::field::ACCESS_SESSION)? {
            Value::Uuid(u) => *u,
            _ => return None,
        };
        let digest = match (get(crate::field::SIZE), get(crate::field::SHA256)) {
            (Some(Value::U64(size)), Some(Value::Bytes(b))) => {
                Some((*size, <[u8; 32]>::try_from(b.as_slice()).ok()?))
            }
            (None, None) => None,
            _ => return None,
        };
        let complete = matches!(get(crate::field::COMPLETE), Some(Value::Bool(true)));
        let code = match get(crate::field::CODE) {
            Some(Value::Text(t)) => Some(t.clone()),
            _ => None,
        };
        Some(Self {
            seq: record.seq,
            session,
            digest,
            complete,
            code,
        })
    }

    /// The file name of the transcript: `<uuid>.cast`.
    pub fn file_name(&self) -> String {
        file_name(&self.session)
    }
}

impl Finding {
    /// The stable code, e.g. `AUD-E007`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid { error, .. } => error.code(),
            Self::ChainId { .. } => "AUD-E005",
            Self::Sequence { .. } => "AUD-E006",
            Self::HashLink { .. } => "AUD-E007",
            Self::HeadMismatch { .. } => "AUD-E011",
            Self::HeadSequence { .. } => "AUD-E012",
            Self::External { .. } => "AUD-E013",
            Self::NoAnchor { .. } => "AUD-E014",
            Self::UncoveredTail { .. } => "AUD-W001",
            Self::ClockBackwards { .. } => "AUD-W002",
            Self::HeadGap { .. } => "AUD-W003",
            Self::StaleHead { .. } => "AUD-W004",
            Self::TranscriptMissing { .. } => "AUD-E017",
            Self::TranscriptAltered { .. } => "AUD-E018",
            Self::TranscriptUnsealed { .. } => "AUD-W005",
            Self::TranscriptIncomplete { .. } => "AUD-W006",
            Self::TranscriptNeverSealed { .. } => "AUD-E019",
            Self::TranscriptPending { .. } => "AUD-W007",
        }
    }

    /// Error or warning.
    pub fn severity(&self) -> Severity {
        match self {
            Self::UncoveredTail { .. }
            | Self::ClockBackwards { .. }
            | Self::HeadGap { .. }
            | Self::StaleHead { .. }
            | Self::TranscriptUnsealed { .. }
            | Self::TranscriptIncomplete { .. }
            | Self::TranscriptPending { .. } => Severity::Warning,
            _ => Severity::Error,
        }
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Self::Invalid {
                seq: Some(seq),
                error,
            } => {
                write!(f, "{error} (enregistrement attendu n° {seq})")
            }
            Self::Invalid { seq: None, error } => write!(f, "{error}"),
            Self::ChainId { expected, got } => write!(
                f,
                "[{code}] élément d'une autre chaîne : {got} au lieu de {expected}"
            ),
            Self::Sequence { expected, got } => write!(
                f,
                "[{code}] numéro d'enregistrement inattendu : {got} au lieu de {expected} \
                 (suppression, réordonnancement ou doublon)"
            ),
            Self::HashLink { seq } => write!(
                f,
                "[{code}] chaînage rompu : l'enregistrement n° {seq} ne référence pas le hash \
                 de l'enregistrement qui le précède"
            ),
            Self::HeadMismatch {
                head_no,
                record_seq,
                tip_seq: Some(tip),
            } => write!(
                f,
                "[{code}] la tête n° {head_no} couvre l'enregistrement n° {record_seq}, qui ne \
                 correspond pas à l'enregistrement n° {tip} lu juste avant"
            ),
            Self::HeadMismatch {
                head_no,
                record_seq,
                tip_seq: None,
            } => write!(
                f,
                "[{code}] la tête n° {head_no} couvre l'enregistrement n° {record_seq}, mais \
                 aucun enregistrement ne la précède"
            ),
            Self::HeadSequence { expected, got } => write!(
                f,
                "[{code}] suite des têtes rompue : tête n° {got} au lieu de la n° {expected}, ou \
                 hash de la tête précédente différent (tête supprimée ou rejouée)"
            ),
            Self::External {
                head_no,
                record_seq,
                fork: true,
            } => write!(
                f,
                "[{code}] divergence avec la tête externe n° {head_no} : l'enregistrement \
                 n° {record_seq} de l'export a un autre hash"
            ),
            Self::External {
                head_no,
                record_seq,
                fork: false,
            } => write!(
                f,
                "[{code}] troncature : la tête externe n° {head_no} couvre l'enregistrement \
                 n° {record_seq}, absent de l'export"
            ),
            Self::NoAnchor { first_seq } => write!(
                f,
                "[{code}] export partiel commençant à l'enregistrement n° {first_seq} sans tête \
                 d'ancrage de confiance qui le précède directement"
            ),
            Self::TranscriptMissing { file, seq } => write!(
                f,
                "[{code}] transcript {file} scellé par l'enregistrement n° {seq}, absent du \
                 répertoire"
            ),
            Self::TranscriptAltered { file, seq } => write!(
                f,
                "[{code}] transcript {file} différent de son sceau (enregistrement n° {seq}) : \
                 taille ou SHA-256"
            ),
            Self::TranscriptNeverSealed { file, seq } => write!(
                f,
                "[{code}] session SSH ouverte (enregistrement n° {seq}) sans transcript scellé \
                 dans l'export, alors qu'elle était forcément terminée : {file}"
            ),
            _ => self.fmt_warning(f, code),
        }
    }
}

impl Finding {
    fn fmt_warning(&self, f: &mut fmt::Formatter<'_>, code: &str) -> fmt::Result {
        match self {
            Self::UncoveredTail { count } => write!(
                f,
                "[{code}] {count} enregistrement(s) en fin de chaîne, après la dernière tête : \
                 non couverts par une signature"
            ),
            Self::ClockBackwards {
                seq,
                previous_ms,
                time_ms,
            } => write!(
                f,
                "[{code}] l'horloge recule à l'enregistrement n° {seq} : {time_ms} ms après \
                 {previous_ms} ms, au-delà de la tolérance"
            ),
            Self::HeadGap {
                head_no,
                gap_secs,
                allowed_secs,
            } => write!(
                f,
                "[{code}] {gap_secs} s entre la tête n° {head_no} et la précédente, plus que le \
                 battement et la tolérance ({allowed_secs} s)"
            ),
            Self::StaleHead {
                head_no,
                age_secs,
                allowed_secs,
            } => write!(
                f,
                "[{code}] la dernière tête (n° {head_no}) a {age_secs} s au moment de l'export, \
                 plus que deux battements ({allowed_secs} s) : fin de chaîne peut-être tronquée"
            ),
            Self::TranscriptUnsealed { file } => write!(
                f,
                "[{code}] transcript {file} sans sceau dans l'export (pas encore scellé, scellé \
                 hors de l'export, ou ajouté)"
            ),
            Self::TranscriptIncomplete {
                file,
                seq,
                code: why,
            } => write!(
                f,
                "[{code}] transcript {file} scellé incomplet (enregistrement n° {seq}, {why}) : \
                 intact, mais la session n'y est peut-être pas en entier"
            ),
            Self::TranscriptPending { file, seq } => write!(
                f,
                "[{code}] session SSH ouverte (enregistrement n° {seq}) sans transcript scellé \
                 dans l'export, peut-être encore en cours à l'export : {file}"
            ),
            // Errors are written by `Display::fmt`.
            _ => write!(f, "[{code}]"),
        }
    }
}

/// Verification options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// Heads kept outside the core (noted by an administrator, sent to a
    /// second system): each must verify, and the export must contain its
    /// record with the same hash, otherwise `AUD-E013`.
    pub external_heads: Vec<Head>,
    /// Accepted backward step of the clock between two records, ms.
    pub clock_tolerance_ms: u64,
    /// Accepted delay of a head beyond its heartbeat, seconds.
    pub head_gap_tolerance_secs: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            external_heads: Vec::new(),
            clock_tolerance_ms: 5_000,
            head_gap_tolerance_secs: 60,
        }
    }
}

/// Result of a verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Records read.
    pub records: u64,
    /// Heads read, the anchor included.
    pub heads: u64,
    /// First record seq.
    pub first_seq: Option<u64>,
    /// Last record seq.
    pub last_seq: Option<u64>,
    /// Last record seq covered by a valid head.
    pub covered_seq: Option<u64>,
    /// Findings, in order, at most [`MAX_FINDINGS`].
    pub findings: Vec<Finding>,
    /// Errors found, beyond the cap included.
    pub errors: u64,
    /// Warnings found, beyond the cap included.
    pub warnings: u64,
    /// The transcript seals of the export, in chain order, for
    /// [`crate::transcripts::check`].
    pub transcripts: Vec<TranscriptSeal>,
    /// The SSH sessions opened in the export, in chain order, for
    /// [`crate::transcripts::check`].
    pub ssh_sessions: Vec<SshSession>,
    /// Time of the export, Unix milliseconds, when known.
    pub export_time_ms: Option<u64>,
}

impl Report {
    /// Adds a finding found outside the chain (transcripts).
    pub fn add(&mut self, finding: Finding) {
        match finding.severity() {
            Severity::Error => self.errors += 1,
            Severity::Warning => self.warnings += 1,
        }
        if self.findings.len() < MAX_FINDINGS {
            self.findings.push(finding);
        }
    }

    /// 0: intact and covered; 1: at least one error; 2: warnings only.
    pub fn exit_code(&self) -> u8 {
        if self.errors > 0 {
            1
        } else if self.warnings > 0 {
            2
        } else {
            0
        }
    }

    /// Whether a finding with this code was kept.
    pub fn has(&self, code: &str) -> bool {
        self.findings.iter().any(|f| f.code() == code)
    }

    /// Findings beyond the cap, not kept.
    pub fn dropped(&self) -> u64 {
        (self.errors + self.warnings).saturating_sub(self.findings.len() as u64)
    }
}

/// The last valid head read.
#[derive(Debug, Clone, Copy)]
struct LastHead {
    head_no: u64,
    hash: Digest,
    time_ms: u64,
    heartbeat_secs: u32,
}

#[derive(Debug, Clone, Copy)]
struct External {
    head: Head,
    seen: bool,
}

/// Streaming verifier. Push the optional anchor, then records and heads in
/// chain order, then call [`Verifier::finish`].
#[derive(Debug)]
pub struct Verifier {
    keys: TrustedKeys,
    clock_tolerance_ms: u64,
    head_gap_tolerance_secs: u64,
    external: Vec<External>,
    chain_id: Option<ChainId>,
    expected_first: Option<u64>,
    /// Seq and hash of the last record read, or of the anchor.
    tip: Option<(u64, Digest)>,
    anchored: bool,
    last_time_ms: Option<u64>,
    last_head: Option<LastHead>,
    records: u64,
    heads: u64,
    first_seq: Option<u64>,
    last_seq: Option<u64>,
    covered_seq: Option<u64>,
    findings: Vec<Finding>,
    errors: u64,
    warnings: u64,
    transcripts: Vec<TranscriptSeal>,
    ssh_sessions: Vec<SshSession>,
}

impl Verifier {
    /// A verifier trusting `keys`. External heads that do not verify are
    /// reported and ignored.
    pub fn new(keys: TrustedKeys, options: Options) -> Self {
        let mut verifier = Self {
            keys,
            clock_tolerance_ms: options.clock_tolerance_ms,
            head_gap_tolerance_secs: options.head_gap_tolerance_secs,
            external: Vec::with_capacity(options.external_heads.len()),
            chain_id: None,
            expected_first: None,
            tip: None,
            anchored: false,
            last_time_ms: None,
            last_head: None,
            records: 0,
            heads: 0,
            first_seq: None,
            last_seq: None,
            covered_seq: None,
            findings: Vec::new(),
            errors: 0,
            warnings: 0,
            transcripts: Vec::new(),
            ssh_sessions: Vec::new(),
        };
        for head in options.external_heads {
            match head.verify(&verifier.keys) {
                Ok(()) => verifier.external.push(External { head, seen: false }),
                Err(error) => verifier.report(Finding::Invalid { seq: None, error }),
            }
        }
        verifier
    }

    /// Declares the chain and the first seq expected (from an export
    /// header). Optional: otherwise the first record sets the chain.
    pub fn expect(&mut self, chain_id: ChainId, first_seq: u64) {
        self.chain_id = Some(chain_id);
        self.expected_first = Some(first_seq);
    }

    /// Reports an element that could not even be decoded where the caller
    /// read it (a head stored in a database): an [`Finding::Invalid`] error;
    /// the state of the verifier is unchanged.
    pub fn push_malformed(&mut self, seq: Option<u64>, error: AuditError) {
        self.report(Finding::Invalid { seq, error });
    }

    fn report(&mut self, finding: Finding) {
        match finding.severity() {
            Severity::Error => self.errors += 1,
            Severity::Warning => self.warnings += 1,
        }
        if self.findings.len() < MAX_FINDINGS {
            self.findings.push(finding);
        }
    }

    /// Reports `finding`, keeping the first error of the current push.
    fn flag(&mut self, first: &mut Option<Finding>, finding: Finding) {
        if first.is_none() && finding.severity() == Severity::Error {
            *first = Some(finding.clone());
        }
        self.report(finding);
    }

    /// Checks the chain of a record or head; adopts it if none is known.
    fn check_chain(&mut self, first: &mut Option<Finding>, got: ChainId) {
        match self.chain_id {
            Some(expected) if expected != got => {
                self.flag(first, Finding::ChainId { expected, got });
            }
            Some(_) => {}
            None => self.chain_id = Some(got),
        }
    }

    fn check_external(&mut self, first: &mut Option<Finding>, seq: u64, hash: &Digest) {
        let mut forks = Vec::new();
        for external in self
            .external
            .iter_mut()
            .filter(|e| e.head.record_seq() == seq)
        {
            external.seen = true;
            if external.head.record_hash() != *hash {
                forks.push(external.head.head_no());
            }
        }
        for head_no in forks {
            self.flag(
                first,
                Finding::External {
                    head_no,
                    record_seq: seq,
                    fork: true,
                },
            );
        }
    }

    /// Sets the trusted starting point of a partial export: head N, with
    /// `record_seq + 1` equal to the first seq. Must come before any record.
    ///
    /// # Errors
    ///
    /// The finding that makes the anchor unusable (also kept in the report).
    pub fn anchor(&mut self, head: &Head) -> Result<(), Finding> {
        self.heads += 1;
        let mut first = None;
        if let Err(error) = head.verify(&self.keys) {
            self.flag(&mut first, Finding::Invalid { seq: None, error });
        } else if self.tip.is_some() || self.last_head.is_some() {
            self.flag(
                &mut first,
                Finding::Invalid {
                    seq: None,
                    error: AuditError::MalformedExport(
                        "la tête d'ancrage doit précéder tout autre élément".into(),
                    ),
                },
            );
        } else {
            self.check_chain(&mut first, head.chain_id());
            if let Some(first_seq) = self.expected_first
                && head.record_seq().checked_add(1) != Some(first_seq)
            {
                self.flag(&mut first, Finding::NoAnchor { first_seq });
            }
        }
        if let Some(finding) = first {
            return Err(finding);
        }
        self.anchored = true;
        self.tip = Some((head.record_seq(), head.record_hash()));
        self.covered_seq = Some(head.record_seq());
        self.last_head = Some(LastHead {
            head_no: head.head_no(),
            hash: head.hash(),
            time_ms: head.time_ms(),
            heartbeat_secs: head.heartbeat_secs(),
        });
        let mut ignored = None;
        self.check_external(&mut ignored, head.record_seq(), &head.record_hash());
        Ok(())
    }

    /// Checks the next record and returns its hash.
    ///
    /// # Errors
    ///
    /// The first error found on this record (every finding is also kept in
    /// the report). Verification goes on with the next record.
    pub fn push_record(&mut self, body: &[u8]) -> Result<Digest, Finding> {
        let hash = record_hash(body);
        let expected = self
            .tip
            .map(|(seq, _)| seq.saturating_add(1))
            .or(self.expected_first);
        let mut first = None;
        let seq = match Record::decode(body) {
            Err(error) => {
                self.flag(
                    &mut first,
                    Finding::Invalid {
                        seq: expected,
                        error,
                    },
                );
                // Assume it holds the expected place: the next record then
                // shows whether the chain goes on.
                expected.unwrap_or(1)
            }
            Ok(record) => {
                self.check_chain(&mut first, record.chain_id);
                if let (Some((_, prev)), Some(expected)) = (self.tip, expected) {
                    if record.seq != expected {
                        self.flag(
                            &mut first,
                            Finding::Sequence {
                                expected,
                                got: record.seq,
                            },
                        );
                    }
                    if record.prev_hash != prev {
                        self.flag(&mut first, Finding::HashLink { seq: record.seq });
                    }
                } else {
                    // First record, no trusted anchor.
                    if let Some(expected) = expected
                        && record.seq != expected
                    {
                        self.flag(
                            &mut first,
                            Finding::Sequence {
                                expected,
                                got: record.seq,
                            },
                        );
                    }
                    if record.seq != 1 {
                        self.flag(
                            &mut first,
                            Finding::NoAnchor {
                                first_seq: record.seq,
                            },
                        );
                    } else if record.prev_hash != ZERO_DIGEST {
                        self.flag(&mut first, Finding::HashLink { seq: 1 });
                    }
                }
                if let Some(previous_ms) = self.last_time_ms
                    && record.time_ms.saturating_add(self.clock_tolerance_ms) < previous_ms
                {
                    self.flag(
                        &mut first,
                        Finding::ClockBackwards {
                            seq: record.seq,
                            previous_ms,
                            time_ms: record.time_ms,
                        },
                    );
                }
                self.last_time_ms = Some(record.time_ms);
                self.check_external(&mut first, record.seq, &hash);
                if let Some(seal) = TranscriptSeal::of(&record) {
                    self.transcripts.push(seal);
                }
                if let Some(opened) = SshSession::of(&record) {
                    self.ssh_sessions.push(opened);
                }
                record.seq
            }
        };
        self.records += 1;
        self.first_seq.get_or_insert(seq);
        self.last_seq = Some(seq);
        self.tip = Some((seq, hash));
        first.map_or(Ok(hash), Err)
    }

    /// Checks a head read after the record it covers.
    ///
    /// # Errors
    ///
    /// The first error found on this head (every finding is also kept in the
    /// report). An invalid signature leaves the verifier state unchanged.
    pub fn push_head(&mut self, head: &Head) -> Result<(), Finding> {
        self.heads += 1;
        let mut first = None;
        if let Err(error) = head.verify(&self.keys) {
            self.flag(&mut first, Finding::Invalid { seq: None, error });
            return first.map_or(Ok(()), Err);
        }
        self.check_chain(&mut first, head.chain_id());
        let matches_tip = self
            .tip
            .is_some_and(|(seq, hash)| seq == head.record_seq() && hash == head.record_hash());
        if !matches_tip {
            self.flag(
                &mut first,
                Finding::HeadMismatch {
                    head_no: head.head_no(),
                    record_seq: head.record_seq(),
                    tip_seq: self.tip.map(|(seq, _)| seq),
                },
            );
        }
        match self.last_head {
            Some(previous) => {
                let expected = previous.head_no.saturating_add(1);
                if head.head_no() != expected || head.prev_head_hash() != previous.hash {
                    self.flag(
                        &mut first,
                        Finding::HeadSequence {
                            expected,
                            got: head.head_no(),
                        },
                    );
                }
                let allowed_secs =
                    u64::from(previous.heartbeat_secs).saturating_add(self.head_gap_tolerance_secs);
                let gap_ms = head.time_ms().saturating_sub(previous.time_ms);
                if gap_ms > allowed_secs.saturating_mul(1000) {
                    self.flag(
                        &mut first,
                        Finding::HeadGap {
                            head_no: head.head_no(),
                            gap_secs: gap_ms / 1000,
                            allowed_secs,
                        },
                    );
                }
                if head.time_ms().saturating_add(self.clock_tolerance_ms) < previous.time_ms {
                    self.flag(
                        &mut first,
                        Finding::ClockBackwards {
                            seq: head.record_seq(),
                            previous_ms: previous.time_ms,
                            time_ms: head.time_ms(),
                        },
                    );
                }
            }
            // A full export starts with head 1; a partial one without
            // anchor is already reported (AUD-E014).
            None if !self.anchored && self.first_seq == Some(1) && head.head_no() != 1 => {
                self.flag(
                    &mut first,
                    Finding::HeadSequence {
                        expected: 1,
                        got: head.head_no(),
                    },
                );
            }
            None => {}
        }
        self.last_head = Some(LastHead {
            head_no: head.head_no(),
            hash: head.hash(),
            time_ms: head.time_ms(),
            heartbeat_secs: head.heartbeat_secs(),
        });
        if matches_tip {
            self.covered_seq = Some(head.record_seq());
        }
        first.map_or(Ok(()), Err)
    }

    /// Ends the verification. `export_time_ms`, when known, checks that the
    /// last head is fresh (`AUD-W004`).
    pub fn finish(mut self, export_time_ms: Option<u64>) -> Report {
        if let (Some(first), Some(last)) = (self.first_seq, self.last_seq) {
            let covered = self.covered_seq.unwrap_or(first.saturating_sub(1));
            if last > covered {
                self.report(Finding::UncoveredTail {
                    count: last - covered,
                });
            }
        }
        if let (Some(now), Some(head)) = (export_time_ms, self.last_head) {
            let allowed_secs = u64::from(head.heartbeat_secs).saturating_mul(2);
            let age_ms = now.saturating_sub(head.time_ms);
            if age_ms > allowed_secs.saturating_mul(1000) {
                self.report(Finding::StaleHead {
                    head_no: head.head_no,
                    age_secs: age_ms / 1000,
                    allowed_secs,
                });
            }
        }
        let external = std::mem::take(&mut self.external);
        for e in external {
            if let Some(expected) = self.chain_id
                && e.head.chain_id() != expected
            {
                self.report(Finding::ChainId {
                    expected,
                    got: e.head.chain_id(),
                });
                continue;
            }
            if e.seen {
                continue;
            }
            let record_seq = e.head.record_seq();
            // Before the start of a partial export (and not its anchor):
            // nothing to compare.
            if self
                .first_seq
                .is_some_and(|first| record_seq.saturating_add(1) < first)
            {
                continue;
            }
            let fork = self.last_seq.is_some_and(|last| record_seq <= last);
            self.report(Finding::External {
                head_no: e.head.head_no(),
                record_seq,
                fork,
            });
        }
        Report {
            records: self.records,
            heads: self.heads,
            first_seq: self.first_seq,
            last_seq: self.last_seq,
            covered_seq: self.covered_seq,
            findings: self.findings,
            errors: self.errors,
            warnings: self.warnings,
            transcripts: self.transcripts,
            ssh_sessions: self.ssh_sessions,
            export_time_ms,
        }
    }
}

/// Verifies a whole export.
///
/// A malformed or truncated export is a finding (`AUD-E004`), and
/// verification stops there.
///
/// # Errors
///
/// [`AuditError::Io`] only, when the export cannot be read.
pub fn verify_export<R: Read>(
    reader: R,
    keys: TrustedKeys,
    options: Options,
) -> Result<Report, AuditError> {
    let mut verifier = Verifier::new(keys, options);
    let mut export = match ExportReader::new(reader) {
        Ok(export) => export,
        Err(error @ AuditError::Io(_)) => return Err(error),
        Err(error) => {
            verifier.report(Finding::Invalid { seq: None, error });
            return Ok(verifier.finish(None));
        }
    };
    let first_seq = export.first_seq();
    let export_time_ms = export.export_time_ms();
    verifier.expect(export.chain_id(), first_seq);
    let mut first_frame = true;
    for frame in export.by_ref() {
        match frame {
            Ok(Frame::Head(head)) if first_frame && first_seq > 1 => {
                let _ = verifier.anchor(&head);
            }
            Ok(Frame::Head(head)) => {
                let _ = verifier.push_head(&head);
            }
            Ok(Frame::Record(body)) => {
                let _ = verifier.push_record(&body);
            }
            Ok(Frame::End { .. }) => {}
            Err(error @ AuditError::Io(_)) => return Err(error),
            Err(error) => verifier.report(Finding::Invalid { seq: None, error }),
        }
        first_frame = false;
    }
    Ok(verifier.finish(Some(export_time_ms)))
}

#[cfg(test)]
mod tests;
