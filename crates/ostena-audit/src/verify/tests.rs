use ostena_crypto::p256::SigningKey;

use super::*;
use crate::event::{ChainTip, Event, EventKind};
use crate::export::ExportWriter;
use crate::head::UnsignedHead;
use crate::record::{ActorKind, Outcome};

const HEARTBEAT: u32 = 60;

/// Builds a chain: records every second from `t0`, heads on demand.
struct Chain {
    key: SigningKey,
    tip: ChainTip,
    last_head: Option<Head>,
    time_ms: u64,
    records: Vec<(u64, Vec<u8>)>,
    heads: Vec<Head>,
}

#[derive(Clone)]
enum Item {
    Record(Vec<u8>),
    Head(Head),
}

impl Chain {
    fn new() -> Self {
        Self {
            key: SigningKey::generate().unwrap().0,
            tip: ChainTip::empty(ChainId::from_bytes([0x5a; 16])),
            last_head: None,
            time_ms: 1_800_000_000_000,
            records: Vec::new(),
            heads: Vec::new(),
        }
    }

    fn record(&mut self) -> Item {
        self.time_ms += 1000;
        let appended = self
            .tip
            .append(
                Event::new(
                    EventKind::CoreStarted,
                    Outcome::Success,
                    ActorKind::Core,
                    "core",
                )
                .u64("version", self.tip.seq),
                self.time_ms,
            )
            .unwrap();
        self.records.push((appended.seq, appended.body.clone()));
        Item::Record(appended.body)
    }

    fn head(&mut self) -> Item {
        self.time_ms += 1;
        let head = UnsignedHead::after(
            self.last_head.as_ref(),
            self.tip.chain_id,
            self.tip.seq,
            self.tip.hash,
            self.time_ms,
            HEARTBEAT,
        )
        .sign(&self.key)
        .unwrap();
        self.last_head = Some(head);
        self.heads.push(head);
        Item::Head(head)
    }

    fn keys(&self) -> TrustedKeys {
        let mut keys = TrustedKeys::new();
        keys.insert(self.key.verifying_key()).unwrap();
        keys
    }

    /// `n` records with a head after each record listed in `heads_after`.
    fn build(n: u64, heads_after: &[u64]) -> (Self, Vec<Item>) {
        let mut chain = Self::new();
        let mut items = Vec::new();
        for seq in 1..=n {
            items.push(chain.record());
            if heads_after.contains(&seq) {
                items.push(chain.head());
            }
        }
        (chain, items)
    }

    fn export(&self, items: &[Item], first_seq: u64, export_time_ms: u64) -> Vec<u8> {
        let mut writer =
            ExportWriter::new(Vec::new(), self.tip.chain_id, export_time_ms, first_seq).unwrap();
        for item in items {
            match item {
                Item::Record(body) => writer.record(body).unwrap(),
                Item::Head(head) => writer.head(head).unwrap(),
            }
        }
        writer.finish().unwrap()
    }

    fn verify(&self, items: &[Item], first_seq: u64, options: Options) -> Report {
        let bytes = self.export(items, first_seq, self.time_ms + 1000);
        verify_export(bytes.as_slice(), self.keys(), options).unwrap()
    }
}

fn codes(report: &Report) -> Vec<&'static str> {
    report.findings.iter().map(Finding::code).collect()
}

#[test]
fn intact_and_covered_chain_passes() {
    let (chain, items) = Chain::build(5, &[2, 5]);
    let report = chain.verify(&items, 1, Options::default());
    assert_eq!(codes(&report), Vec::<&str>::new());
    assert_eq!(report.exit_code(), 0);
    assert_eq!(
        (
            report.records,
            report.heads,
            report.first_seq,
            report.last_seq,
            report.covered_seq
        ),
        (5, 2, Some(1), Some(5), Some(5))
    );
}

#[test]
fn malformed_elements_pushed_by_the_caller_are_errors() {
    let (chain, items) = Chain::build(2, &[2]);
    let mut verifier = Verifier::new(chain.keys(), Options::default());
    for item in &items {
        match item {
            Item::Record(body) => verifier.push_record(body).unwrap(),
            Item::Head(head) => verifier.push_head(head).map(|()| [0; 32]).unwrap(),
        };
    }
    verifier.push_malformed(None, AuditError::MalformedHead("x"));
    let report = verifier.finish(None);
    assert_eq!(codes(&report), ["AUD-E003"]);
    assert_eq!((report.errors, report.covered_seq), (1, Some(2)));
}

#[test]
fn several_heads_on_the_same_record_are_fine() {
    let (mut chain, mut items) = Chain::build(3, &[3]);
    items.push(chain.head());
    items.push(chain.head());
    assert_eq!(chain.verify(&items, 1, Options::default()).exit_code(), 0);
}

#[test]
fn uncovered_tail_is_a_warning() {
    let (chain, items) = Chain::build(5, &[2]);
    let report = chain.verify(&items, 1, Options::default());
    assert_eq!(codes(&report), ["AUD-W001"]);
    assert_eq!(report.findings[0], Finding::UncoveredTail { count: 3 });
    assert_eq!(report.exit_code(), 2);
    let (chain, items) = Chain::build(2, &[]);
    let report = chain.verify(&items, 1, Options::default());
    assert_eq!(report.findings, [Finding::UncoveredTail { count: 2 }]);
}

#[test]
fn partial_export_needs_its_anchor() {
    let (chain, items) = Chain::build(6, &[3, 6]);
    // Items after record 3: head 1 (anchor), records 4..=6, head 2.
    let anchored = &items[3..];
    assert!(matches!(anchored[0], Item::Head(_)));
    let report = chain.verify(anchored, 4, Options::default());
    assert_eq!(codes(&report), Vec::<&str>::new());
    assert_eq!((report.first_seq, report.covered_seq), (Some(4), Some(6)));

    let report = chain.verify(&anchored[1..], 4, Options::default());
    assert!(report.has("AUD-E014"), "{:?}", report.findings);
    assert_eq!(report.exit_code(), 1);

    // An anchor that does not precede the first record.
    let report = chain.verify(anchored, 5, Options::default());
    assert!(report.has("AUD-E014"), "{:?}", report.findings);
}

#[test]
fn anchor_signed_by_an_unknown_key_is_refused() {
    let (chain, items) = Chain::build(6, &[3, 6]);
    let stranger = Chain::new();
    let bytes = chain.export(&items[3..], 4, chain.time_ms);
    let report = verify_export(bytes.as_slice(), stranger.keys(), Options::default()).unwrap();
    assert!(report.has("AUD-E009"));
    assert!(report.has("AUD-E014"));
}

#[test]
fn deleted_record_breaks_sequence_and_link() {
    let (chain, mut items) = Chain::build(5, &[5]);
    items.remove(2);
    let report = chain.verify(&items, 1, Options::default());
    assert!(report.has("AUD-E006"));
    assert!(report.has("AUD-E007"));
}

#[test]
fn edited_record_is_detected() {
    let (chain, mut items) = Chain::build(4, &[4]);
    if let Item::Record(body) = &mut items[1] {
        // The time field: still a valid record, with another hash.
        let at = 1 + 16 + 8 + 32 + 7;
        body[at] ^= 0x01;
    }
    let report = chain.verify(&items, 1, Options::default());
    assert_eq!(codes(&report), ["AUD-E007"]);
}

#[test]
fn last_record_edit_is_caught_by_its_head() {
    let (chain, mut items) = Chain::build(3, &[3]);
    if let Item::Record(body) = &mut items[2] {
        let at = 1 + 16 + 8 + 32 + 7;
        body[at] ^= 0x01;
    }
    let report = chain.verify(&items, 1, Options::default());
    assert_eq!(codes(&report), ["AUD-E011", "AUD-W001"]);
}

#[test]
fn malformed_record_is_reported_and_verification_goes_on() {
    let (chain, mut items) = Chain::build(4, &[4]);
    if let Item::Record(body) = &mut items[1] {
        body[0] = 9;
    }
    let report = chain.verify(&items, 1, Options::default());
    assert_eq!(codes(&report), ["AUD-E002", "AUD-E007"]);
    assert!(
        report.findings[0]
            .to_string()
            .contains("enregistrement attendu n° 2")
    );
    assert_eq!(report.covered_seq, Some(4));
}

#[test]
fn head_sequence_is_checked() {
    let (chain, items) = Chain::build(4, &[1, 2, 3, 4]);
    // Head 2 deleted.
    let mut deleted = items.clone();
    deleted.remove(3);
    let report = chain.verify(&deleted, 1, Options::default());
    assert_eq!(
        report.findings,
        [Finding::HeadSequence {
            expected: 2,
            got: 3
        }]
    );
    // First head missing from a full export.
    let mut no_first = items.clone();
    no_first.remove(1);
    let report = chain.verify(&no_first, 1, Options::default());
    assert_eq!(codes(&report), ["AUD-E012"]);
    // An old head replayed at the end.
    let mut replayed = items;
    replayed.push(Item::Head(chain.heads[0]));
    let report = chain.verify(&replayed, 1, Options::default());
    assert!(report.has("AUD-E011"));
    assert!(report.has("AUD-E012"));
}

#[test]
fn head_before_any_record_is_refused() {
    let (chain, items) = Chain::build(2, &[2]);
    let mut moved = vec![items[2].clone()];
    moved.extend_from_slice(&items[..2]);
    let report = chain.verify(&moved, 1, Options::default());
    assert!(matches!(
        report.findings[0],
        Finding::HeadMismatch { tip_seq: None, .. }
    ));
}

#[test]
fn other_chain_is_refused() {
    let (chain, items) = Chain::build(2, &[2]);
    let mut bytes = chain.export(&items, 1, chain.time_ms);
    bytes[8] ^= 0xff;
    let report = verify_export(bytes.as_slice(), chain.keys(), Options::default()).unwrap();
    assert!(report.has("AUD-E005"));
    assert_eq!(report.exit_code(), 1);
}

#[test]
fn external_heads_detect_truncation_and_forks() {
    let (chain, items) = Chain::build(6, &[3, 6]);
    let last = chain.heads[1];
    let options = Options {
        external_heads: vec![last],
        ..Options::default()
    };
    assert_eq!(chain.verify(&items, 1, options.clone()).exit_code(), 0);
    // Truncated after the first head: internally consistent.
    let truncated = &items[..4];
    assert_eq!(
        chain.verify(truncated, 1, Options::default()).exit_code(),
        0
    );
    let report = chain.verify(truncated, 1, options);
    assert_eq!(
        report.findings,
        [Finding::External {
            head_no: 2,
            record_seq: 6,
            fork: false
        }]
    );
    // A fork: another chain history signed by the same key.
    let mut other = Chain::new();
    other.key = SigningKey::from_scalar(&chain.key.scalar().unwrap()).unwrap();
    other.time_ms += 7;
    let mut forked = Vec::new();
    for seq in 1..=6 {
        forked.push(other.record());
        if seq == 6 {
            forked.push(other.head());
        }
    }
    let report = other.verify(
        &forked,
        1,
        Options {
            external_heads: vec![last],
            ..Options::default()
        },
    );
    assert_eq!(
        report.findings,
        [Finding::External {
            head_no: 2,
            record_seq: 6,
            fork: true
        }]
    );
}

#[test]
fn external_head_must_verify() {
    let (chain, items) = Chain::build(2, &[2]);
    let stranger = Chain::build(2, &[2]).0;
    let report = chain.verify(
        &items,
        1,
        Options {
            external_heads: vec![stranger.heads[0]],
            ..Options::default()
        },
    );
    assert_eq!(codes(&report), ["AUD-E009"]);
}

#[test]
fn external_head_before_a_partial_export_is_ignored_unless_it_is_the_anchor() {
    let (chain, items) = Chain::build(6, &[1, 3, 6]);
    let options = Options {
        external_heads: vec![chain.heads[0], chain.heads[1]],
        ..Options::default()
    };
    // Partial export from seq 4, anchored on head 2 (record 3).
    let start = items
        .iter()
        .position(|i| matches!(i, Item::Head(h) if h.head_no() == 2))
        .unwrap();
    let report = chain.verify(&items[start..], 4, options);
    assert_eq!(codes(&report), Vec::<&str>::new());
}

#[test]
fn clock_going_backwards_is_a_warning() {
    let mut chain = Chain::new();
    let mut items = vec![chain.record()];
    chain.time_ms -= 10_000;
    items.push(chain.record());
    items.push(chain.head());
    let report = chain.verify(&items, 1, Options::default());
    assert_eq!(codes(&report), ["AUD-W002"]);
    assert_eq!(report.exit_code(), 2);
    let tolerant = Options {
        clock_tolerance_ms: 20_000,
        ..Options::default()
    };
    assert_eq!(chain.verify(&items, 1, tolerant).exit_code(), 0);
}

#[test]
fn late_and_stale_heads_are_warnings() {
    let mut chain = Chain::new();
    let mut items = vec![chain.record(), chain.head()];
    chain.time_ms += 1000 * u64::from(HEARTBEAT + 61);
    items.push(chain.record());
    items.push(chain.head());
    let report = chain.verify(&items, 1, Options::default());
    assert_eq!(codes(&report), ["AUD-W003"]);

    let (chain, items) = Chain::build(2, &[2]);
    let bytes = chain.export(
        &items,
        1,
        chain.time_ms + 2 * 1000 * u64::from(HEARTBEAT) + 1,
    );
    let report = verify_export(bytes.as_slice(), chain.keys(), Options::default()).unwrap();
    assert_eq!(codes(&report), ["AUD-W004"]);
}

#[test]
fn malformed_export_is_a_finding() {
    let (chain, items) = Chain::build(2, &[2]);
    let bytes = chain.export(&items, 1, chain.time_ms);
    let report =
        verify_export(&bytes[..bytes.len() - 1], chain.keys(), Options::default()).unwrap();
    assert!(report.has("AUD-E004"));
    assert_eq!(report.exit_code(), 1);
    let report = verify_export(&b"not an export"[..], chain.keys(), Options::default()).unwrap();
    assert_eq!(codes(&report), ["AUD-E004"]);
}

#[test]
fn push_api_reports_the_first_error() {
    let (chain, items) = Chain::build(3, &[3]);
    let mut verifier = Verifier::new(chain.keys(), Options::default());
    let Item::Record(first) = &items[0] else {
        unreachable!()
    };
    assert_eq!(verifier.push_record(first), Ok(record_hash(first)));
    let Item::Record(third) = &items[2] else {
        unreachable!()
    };
    assert_eq!(
        verifier.push_record(third),
        Err(Finding::Sequence {
            expected: 2,
            got: 3
        })
    );
    let Item::Head(head) = &items[3] else {
        unreachable!()
    };
    assert_eq!(verifier.push_head(head), Ok(()));
    let report = verifier.finish(None);
    assert_eq!(codes(&report), ["AUD-E006", "AUD-E007"]);
}

#[test]
fn findings_are_capped_but_counted() {
    let chain = Chain::new();
    let mut verifier = Verifier::new(chain.keys(), Options::default());
    for _ in 0..1200 {
        let _ = verifier.push_record(b"garbage");
    }
    let report = verifier.finish(None);
    assert_eq!(report.findings.len(), MAX_FINDINGS);
    assert_eq!(report.errors, 1200);
    assert_eq!(report.warnings, 1);
    assert_eq!(report.dropped(), 201);
    assert_eq!(report.exit_code(), 1);
}

#[test]
fn every_finding_displays_its_code() {
    let chain = ChainId::from_bytes([1; 16]);
    let samples = [
        Finding::Invalid {
            seq: Some(3),
            error: AuditError::MalformedRecord("x"),
        },
        Finding::ChainId {
            expected: chain,
            got: chain,
        },
        Finding::Sequence {
            expected: 1,
            got: 2,
        },
        Finding::HashLink { seq: 1 },
        Finding::HeadMismatch {
            head_no: 1,
            record_seq: 1,
            tip_seq: Some(1),
        },
        Finding::HeadMismatch {
            head_no: 1,
            record_seq: 1,
            tip_seq: None,
        },
        Finding::HeadSequence {
            expected: 1,
            got: 2,
        },
        Finding::External {
            head_no: 1,
            record_seq: 1,
            fork: true,
        },
        Finding::External {
            head_no: 1,
            record_seq: 1,
            fork: false,
        },
        Finding::NoAnchor { first_seq: 2 },
        Finding::UncoveredTail { count: 1 },
        Finding::ClockBackwards {
            seq: 1,
            previous_ms: 2,
            time_ms: 1,
        },
        Finding::HeadGap {
            head_no: 2,
            gap_secs: 100,
            allowed_secs: 90,
        },
        Finding::StaleHead {
            head_no: 2,
            age_secs: 200,
            allowed_secs: 120,
        },
    ];
    let expected = [
        "AUD-E001", "AUD-E005", "AUD-E006", "AUD-E007", "AUD-E011", "AUD-E011", "AUD-E012",
        "AUD-E013", "AUD-E013", "AUD-E014", "AUD-W001", "AUD-W002", "AUD-W003", "AUD-W004",
    ];
    for (finding, code) in samples.iter().zip(expected) {
        assert_eq!(finding.code(), code);
        assert!(
            finding.to_string().starts_with(&format!("[{code}]")),
            "{finding}"
        );
        assert_eq!(
            finding.severity() == Severity::Warning,
            code.starts_with("AUD-W")
        );
    }
}

impl Chain {
    fn event(&mut self, event: Event) -> Item {
        self.time_ms += 1000;
        let appended = self.tip.append(event, self.time_ms).unwrap();
        self.records.push((appended.seq, appended.body.clone()));
        Item::Record(appended.body)
    }
}

fn sealed(session: u8) -> Event {
    Event::new(
        EventKind::TranscriptSealed,
        Outcome::Success,
        ActorKind::Agent,
        "agent",
    )
    .uuid(crate::field::ACCESS_SESSION, [session; 16])
    .bytes(crate::field::SHA256, [0u8; 32])
    .u64(crate::field::SIZE, 0)
    .bool(crate::field::COMPLETE, true)
}

/// A malformed seal, or a second seal for one session, is an error; the
/// sessions opened and the seals are collected for the transcript check.
#[test]
fn transcript_seals_are_well_formed_and_unique() {
    let mut chain = Chain::new();
    let opened = Event::new(
        EventKind::AccessSessionOpened,
        Outcome::Success,
        ActorKind::User,
        "user",
    )
    .uuid(crate::field::ACCESS_SESSION, [1; 16])
    .text(crate::field::PROTOCOL, "ssh")
    .u64(crate::field::MAX_SESSION_SECS, 60);
    // Half a digest: a size without a SHA-256.
    let half = Event::new(
        EventKind::TranscriptSealed,
        Outcome::Success,
        ActorKind::Agent,
        "agent",
    )
    .uuid(crate::field::ACCESS_SESSION, [2; 16])
    .u64(crate::field::SIZE, 3);
    let items = vec![
        chain.event(opened),
        chain.event(sealed(1)),
        chain.event(sealed(1)),
        chain.event(half),
        chain.head(),
    ];
    let report = chain.verify(&items, 1, Options::default());
    assert_eq!(codes(&report), ["AUD-E020", "AUD-E020"]);
    assert_eq!(report.transcripts.len(), 1);
    assert_eq!(report.ssh_sessions.len(), 1);
    assert_eq!(report.ssh_sessions[0].session, [1; 16]);
    assert!(report.export_time_ms.is_some());
}
