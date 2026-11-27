//! Chain model: random chains of up to 64 records with heads at random
//! positions, exported, then tampered with in one random way. Every tamper
//! must give its expected finding; an untouched export must pass.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside #[test] functions"
)]

use ostena_audit::{
    ActorKind, ChainId, ChainTip, Event, EventKind, ExportWriter, Head, Options, Outcome, Report,
    TrustedKeys, UnsignedHead, field, verify_export,
};
use ostena_crypto::p256::SigningKey;
use proptest::prelude::*;

const T0: u64 = 1_800_000_000_000;
const HEARTBEAT: u32 = 3600;

#[derive(Debug, Clone)]
enum Item {
    Record(Vec<u8>),
    Head(Head),
}

struct Model {
    key: SigningKey,
    chain_id: ChainId,
    items: Vec<Item>,
    records: Vec<Vec<u8>>,
    heads: Vec<Head>,
    tip: ChainTip,
    end_ms: u64,
}

fn event(seq: u64) -> Event {
    let kinds = EventKind::ALL;
    let mut kind = kinds[usize::try_from(seq).unwrap() % kinds.len()];
    // A time-stamp names a real head (tests of the verifier cover it).
    if kind == EventKind::AuditHeadTimestamped {
        kind = EventKind::AuditExported;
    }
    let event = Event::new(kind, Outcome::Success, ActorKind::Admin, "alice")
        .u64(field::FIRST_SEQ, seq)
        .text(field::REASON, "modèle");
    // A transcript seal is checked for its fields, one per session.
    if kind == EventKind::TranscriptSealed {
        let mut session = [0u8; 16];
        session[..8].copy_from_slice(&seq.to_be_bytes());
        return event
            .uuid(field::ACCESS_SESSION, session)
            .bytes(field::SHA256, [0u8; 32])
            .u64(field::SIZE, 0);
    }
    event
}

/// `n` records; a head after record 1, after the last record, and after
/// every record flagged in `heads`.
fn build(n: usize, heads: &[bool]) -> Model {
    let key = SigningKey::generate().unwrap().0;
    let chain_id = ChainId::random().unwrap();
    let mut tip = ChainTip::empty(chain_id);
    let mut model = Model {
        key,
        chain_id,
        items: Vec::new(),
        records: Vec::new(),
        heads: Vec::new(),
        tip,
        end_ms: T0,
    };
    let mut time = T0;
    for (i, &flagged) in heads.iter().take(n).enumerate() {
        time += 1000;
        let appended = tip.append(event(tip.seq + 1), time).unwrap();
        model.records.push(appended.body.clone());
        model.items.push(Item::Record(appended.body));
        if i == 0 || i == n - 1 || flagged {
            time += 1;
            let head = UnsignedHead::after(
                model.heads.last(),
                chain_id,
                tip.seq,
                tip.hash,
                time,
                HEARTBEAT,
            )
            .sign(&model.key)
            .unwrap();
            model.heads.push(head);
            model.items.push(Item::Head(head));
        }
    }
    model.tip = tip;
    model.end_ms = time + 1000;
    model
}

fn keys_of(key: &SigningKey) -> TrustedKeys {
    let mut keys = TrustedKeys::new();
    keys.insert(key.verifying_key()).unwrap();
    keys
}

fn export(chain_id: ChainId, items: &[Item], export_ms: u64) -> Vec<u8> {
    let mut writer = ExportWriter::new(Vec::new(), chain_id, export_ms, 1).unwrap();
    for item in items {
        match item {
            Item::Record(body) => writer.record(body).unwrap(),
            Item::Head(head) => writer.head(head).unwrap(),
        }
    }
    writer.finish().unwrap()
}

fn record_positions(items: &[Item]) -> Vec<usize> {
    (0..items.len())
        .filter(|&i| matches!(items[i], Item::Record(_)))
        .collect()
}

fn head_positions(items: &[Item]) -> Vec<usize> {
    (0..items.len())
        .filter(|&i| matches!(items[i], Item::Head(_)))
        .collect()
}

#[derive(Debug, Clone)]
enum Tamper {
    None,
    EditByte { record: usize, byte: usize, xor: u8 },
    DeleteRecord { record: usize },
    Swap { record: usize },
    InsertForged { after: usize },
    DeleteHead { head: usize },
    ReplayOldHead { head: usize },
    TruncateTail { keep: usize },
    ChangeChainId,
    UntrustedKey,
}

fn tamper() -> impl Strategy<Value = Tamper> {
    prop_oneof![
        Just(Tamper::None),
        (any::<usize>(), any::<usize>(), 1u8..=255)
            .prop_map(|(record, byte, xor)| Tamper::EditByte { record, byte, xor }),
        any::<usize>().prop_map(|record| Tamper::DeleteRecord { record }),
        any::<usize>().prop_map(|record| Tamper::Swap { record }),
        any::<usize>().prop_map(|after| Tamper::InsertForged { after }),
        any::<usize>().prop_map(|head| Tamper::DeleteHead { head }),
        any::<usize>().prop_map(|head| Tamper::ReplayOldHead { head }),
        any::<usize>().prop_map(|keep| Tamper::TruncateTail { keep }),
        Just(Tamper::ChangeChainId),
        Just(Tamper::UntrustedKey),
    ]
}

/// Applies `tamper` and returns the export bytes, the keys to verify with,
/// and the codes of which at least one must be reported (empty: none).
fn apply(model: &Model, tamper: &Tamper) -> (Vec<u8>, TrustedKeys, &'static [&'static str]) {
    let mut items = model.items.clone();
    let mut keys = keys_of(&model.key);
    let mut chain_id = model.chain_id;
    let records = record_positions(&items);
    let heads = head_positions(&items);
    let n = records.len();
    let expected: &'static [&'static str] = match *tamper {
        Tamper::None => &[],
        Tamper::EditByte { record, byte, xor } => {
            let at = records[record % n];
            if let Item::Record(body) = &mut items[at] {
                let i = byte % body.len();
                body[i] ^= xor;
            }
            // Malformed, other version, other chain, broken order or link,
            // or a head that no longer matches.
            &[
                "AUD-E001", "AUD-E002", "AUD-E005", "AUD-E006", "AUD-E007", "AUD-E011",
            ]
        }
        Tamper::DeleteRecord { record } => {
            items.remove(records[record % n]);
            &["AUD-E006", "AUD-E011", "AUD-E014"]
        }
        Tamper::Swap { record } => {
            if n < 2 {
                return apply(model, &Tamper::None);
            }
            let i = record % (n - 1);
            items.swap(records[i], records[i + 1]);
            &["AUD-E006", "AUD-E007", "AUD-E011", "AUD-E014"]
        }
        Tamper::InsertForged { after } => {
            // A well-formed record correctly linked to its predecessor:
            // everything after it no longer fits.
            let i = after % n;
            let prev = ostena_audit::record_hash(&model.records[i]);
            let forged = event(0)
                .into_record(model.chain_id, u64::try_from(i).unwrap() + 2, prev, T0)
                .unwrap()
                .encode()
                .unwrap();
            items.insert(records[i] + 1, Item::Record(forged));
            &["AUD-E006", "AUD-E007", "AUD-E011"]
        }
        Tamper::DeleteHead { head } => {
            // Any head but the last (deleting the last one only uncovers
            // the tail, a warning, or shows against the external head).
            if heads.len() < 2 {
                return apply(model, &Tamper::None);
            }
            items.remove(heads[head % (heads.len() - 1)]);
            &["AUD-E012"]
        }
        Tamper::ReplayOldHead { head } => {
            let old = model.heads[head % model.heads.len()];
            items.push(Item::Head(old));
            &["AUD-E012"]
        }
        Tamper::TruncateTail { keep } => {
            if n < 2 {
                return apply(model, &Tamper::None);
            }
            // Keep records 1..=k (k < n) and the heads that follow them.
            let k = 1 + keep % (n - 1);
            let cut = records[k];
            items.truncate(cut);
            &["AUD-E013"]
        }
        Tamper::ChangeChainId => {
            let mut bytes = model.chain_id.to_bytes();
            bytes[0] ^= 0xff;
            chain_id = ChainId::from_bytes(bytes);
            &["AUD-E005"]
        }
        Tamper::UntrustedKey => {
            keys = keys_of(&SigningKey::generate().unwrap().0);
            &["AUD-E009"]
        }
    };
    (export(chain_id, &items, model.end_ms), keys, expected)
}

fn verify(model: &Model, tamper: &Tamper) -> (Report, &'static [&'static str]) {
    let (bytes, keys, expected) = apply(model, tamper);
    // The last head is kept outside the core (an external copy).
    let options = Options {
        external_heads: vec![*model.heads.last().unwrap()],
        ..Options::default()
    };
    (
        verify_export(bytes.as_slice(), keys, options).unwrap(),
        expected,
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn prop_tampering_is_detected(
        heads in prop::collection::vec(any::<bool>(), 64),
        n in 1usize..=64,
        tamper in tamper(),
    ) {
        let model = build(n, &heads);
        let (report, expected) = verify(&model, &tamper);
        if expected.is_empty() {
            prop_assert!(report.exit_code() == 0 || report.exit_code() == 2,
                "untouched export refused: {:?}", report.findings);
            prop_assert_eq!(report.records, u64::try_from(n).unwrap());
        } else {
            prop_assert_eq!(report.exit_code(), 1, "{:?}: {:?}", tamper, report.findings);
            prop_assert!(
                expected.iter().any(|code| report.has(code)),
                "{:?}: expected one of {:?}, got {:?}", tamper, expected, report.findings
            );
        }
    }
}

#[test]
fn untouched_chain_with_a_final_head_is_intact() {
    let model = build(10, &[false; 64]);
    let (report, _) = verify(&model, &Tamper::None);
    assert_eq!(report.exit_code(), 0, "{:?}", report.findings);
    assert_eq!(report.covered_seq, Some(10));
    assert_eq!(model.tip.seq, 10);
}

#[test]
fn truncation_without_an_external_head_is_invisible_but_flagged_by_freshness() {
    let model = build(10, &[true; 64]);
    let mut items = model.items.clone();
    // Drop record 10 and its head: internally consistent.
    items.truncate(items.len() - 2);
    let bytes = export(model.chain_id, &items, model.end_ms);
    let report = verify_export(bytes.as_slice(), keys_of(&model.key), Options::default()).unwrap();
    assert_eq!(report.exit_code(), 0, "{:?}", report.findings);
    // An export made long after the last head is flagged (AUD-W004).
    let late = model.end_ms + 3 * 1000 * u64::from(HEARTBEAT);
    let bytes = export(model.chain_id, &items, late);
    let report = verify_export(bytes.as_slice(), keys_of(&model.key), Options::default()).unwrap();
    assert!(report.has("AUD-W004"));
    assert_eq!(report.exit_code(), 2);
}
