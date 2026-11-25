//! `ostena audit verify` with the real binary, on exports generated here
//! and signed with a key generated through ostena-crypto.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside #[test] functions"
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ostena_audit::{
    ActorKind, ChainId, ChainTip, Event, EventKind, ExportWriter, Head, Outcome, UnsignedHead,
    field,
};
use ostena_crypto::p256::SigningKey;
use ostena_crypto::pki;

const T0: u64 = 1_800_000_000_000;

fn ostena(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ostena"))
        .args(args)
        .output()
        .unwrap()
}

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ostena-audit-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

enum Item {
    Record(Vec<u8>),
    Head(Head),
}

/// A chain of `n` records with a head after each record in `heads_after`;
/// writes the public key file and returns the items, the key file and the
/// heads.
struct Fixture {
    dir: PathBuf,
    chain_id: ChainId,
    items: Vec<Item>,
    heads: Vec<Head>,
    key_file: PathBuf,
}

impl Fixture {
    fn new(name: &str, n: u64, heads_after: &[u64]) -> Self {
        let dir = temp(name);
        let key = SigningKey::generate().unwrap().0;
        let key_file = dir.join("audit.pub");
        std::fs::write(&key_file, pki::encode_public_key(&key.verifying_key())).unwrap();
        let chain_id = ChainId::random().unwrap();
        let mut tip = ChainTip::empty(chain_id);
        let mut items = Vec::new();
        let mut heads: Vec<Head> = Vec::new();
        for seq in 1..=n {
            let event = Event::new(
                EventKind::AgentRevoked,
                Outcome::Success,
                ActorKind::Admin,
                "alice",
            )
            .uuid(field::AGENT_ID, [7; 16])
            .text(field::REASON, "poste perdu");
            let appended = tip.append(event, T0 + seq * 1000).unwrap();
            items.push(Item::Record(appended.body));
            if heads_after.contains(&seq) {
                let head = UnsignedHead::after(
                    heads.last(),
                    chain_id,
                    tip.seq,
                    tip.hash,
                    T0 + seq * 1000 + 1,
                    3600,
                )
                .sign(&key)
                .unwrap();
                heads.push(head);
                items.push(Item::Head(head));
            }
        }
        Self {
            dir,
            chain_id,
            items,
            heads,
            key_file,
        }
    }

    /// Writes the items, minus those at `skip`, as an export file.
    fn export(&self, name: &str, skip: &[usize]) -> PathBuf {
        let path = self.dir.join(name);
        let mut writer = ExportWriter::new(Vec::new(), self.chain_id, T0 + 3_600_000, 1).unwrap();
        for (i, item) in self.items.iter().enumerate() {
            if skip.contains(&i) {
                continue;
            }
            match item {
                Item::Record(body) => writer.record(body).unwrap(),
                Item::Head(head) => writer.head(head).unwrap(),
            }
        }
        std::fs::write(&path, writer.finish().unwrap()).unwrap();
        path
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

/// `--transcripts` (ADR-0016): the transcript sealed in the export is
/// checked against the file; an altered file exits 1 with its code.
#[test]
fn transcripts_are_checked_against_their_seals() {
    let dir = temp("transcripts");
    let key = SigningKey::generate().unwrap().0;
    let key_file = dir.join("audit.pub");
    std::fs::write(&key_file, pki::encode_public_key(&key.verifying_key())).unwrap();
    let content = b"{\"version\":2}\n";
    let chain_id = ChainId::random().unwrap();
    let mut tip = ChainTip::empty(chain_id);
    let event = Event::new(
        EventKind::TranscriptSealed,
        Outcome::Success,
        ActorKind::Agent,
        "a",
    )
    .uuid(field::ACCESS_SESSION, [9; 16])
    .bytes(field::SHA256, ostena_crypto::sha256::digest(content))
    .u64(field::SIZE, content.len() as u64)
    .bool(field::COMPLETE, true);
    let appended = tip.append(event, T0 + 1000).unwrap();
    let head = UnsignedHead::after(None, chain_id, tip.seq, tip.hash, T0 + 1001, 3600)
        .sign(&key)
        .unwrap();
    let mut writer = ExportWriter::new(Vec::new(), chain_id, T0 + 2000, 1).unwrap();
    writer.record(&appended.body).unwrap();
    writer.head(&head).unwrap();
    let export = dir.join("export.bin");
    std::fs::write(&export, writer.finish().unwrap()).unwrap();
    let transcripts = dir.join("transcripts");
    std::fs::create_dir_all(&transcripts).unwrap();
    let file = transcripts.join("09090909-0909-0909-0909-090909090909.cast");
    std::fs::write(&file, content).unwrap();
    let args = |t: &Path| {
        ostena(&[
            "audit",
            "verify",
            s(&export),
            "--key",
            s(&key_file),
            "--transcripts",
            s(t),
        ])
    };
    let out = args(&transcripts);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    assert!(
        stdout(&out).contains("Transcripts scellés : 1"),
        "{}",
        stdout(&out)
    );
    std::fs::write(&file, b"{\"version\":3}\n").unwrap();
    let out = args(&transcripts);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(stdout(&out).contains("[AUD-E018]"), "{}", stdout(&out));
    std::fs::remove_file(&file).unwrap();
    let out = args(&transcripts);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(stdout(&out).contains("[AUD-E017]"), "{}", stdout(&out));
    // Without the option, the transcripts are not looked at.
    let out = ostena(&["audit", "verify", s(&export), "--key", s(&key_file)]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn intact_export_exits_0() {
    let f = Fixture::new("intact", 4, &[2, 4]);
    let export = f.export("export.bin", &[]);
    let out = ostena(&["audit", "verify", s(&export), "--key", s(&f.key_file)]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    let text = stdout(&out);
    assert!(
        text.contains("Enregistrements : 4 (premier : n° 1, dernier : n° 4)"),
        "{text}"
    );
    assert!(text.contains("chaîne intacte et couverte"), "{text}");
}

#[test]
fn deleted_record_exits_1_with_its_code() {
    let f = Fixture::new("deleted", 4, &[4]);
    let export = f.export("export.bin", &[1]);
    let out = ostena(&["audit", "verify", s(&export), "--key", s(&f.key_file)]);
    assert_eq!(out.status.code(), Some(1));
    let text = stdout(&out);
    assert!(text.contains("[AUD-E006]"), "{text}");
    assert!(text.contains("CHAÎNE NON INTÈGRE"), "{text}");
}

#[test]
fn uncovered_tail_exits_2() {
    let f = Fixture::new("tail", 4, &[2]);
    let export = f.export("export.bin", &[]);
    let out = ostena(&["audit", "verify", s(&export), "--key", s(&f.key_file)]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stdout(&out).contains("[AUD-W001] 2 enregistrement(s)"));
}

#[test]
fn json_report() {
    let f = Fixture::new("json", 3, &[3]);
    let export = f.export("export.bin", &[1]);
    let out = ostena(&[
        "audit",
        "verify",
        s(&export),
        "--key",
        s(&f.key_file),
        "--json",
    ]);
    assert_eq!(out.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(report["exit_code"], 1);
    assert_eq!(report["records"], 2);
    assert_eq!(report["findings"][0]["code"], "AUD-E006");
    assert_eq!(report["findings"][0]["severity"], "error");
}

#[test]
fn external_head_reveals_truncation() {
    let f = Fixture::new("external", 4, &[2, 4]);
    // Records 3 and 4 and the second head dropped: internally consistent.
    let export = f.export("export.bin", &[3, 4, 5]);
    let base = ["audit", "verify", s(&export), "--key", s(&f.key_file)];
    assert_eq!(ostena(&base).status.code(), Some(0));

    let text = f.heads[1].to_text();
    let mut args = base.to_vec();
    args.extend_from_slice(&["--head", &text]);
    let out = ostena(&args);
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains("[AUD-E013]"), "{}", stdout(&out));

    // The same head from a file, with a trailing newline.
    let head_file = f.dir.join("head.txt");
    std::fs::write(&head_file, format!("{text}\n")).unwrap();
    let mut args = base.to_vec();
    args.extend_from_slice(&["--head", s(&head_file)]);
    assert_eq!(ostena(&args).status.code(), Some(1));
}

#[test]
fn untrusted_key_exits_1() {
    let f = Fixture::new("untrusted", 2, &[2]);
    let other = Fixture::new("untrusted-other", 1, &[]);
    let export = f.export("export.bin", &[]);
    let out = ostena(&["audit", "verify", s(&export), "--key", s(&other.key_file)]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains("[AUD-E009]"));
}

#[test]
fn usage_and_input_errors_exit_3() {
    let f = Fixture::new("usage", 1, &[1]);
    let export = f.export("export.bin", &[]);
    let missing = f.dir.join("missing.bin");
    let not_a_key = f.dir.join("not-a-key.pub");
    std::fs::write(&not_a_key, "hello").unwrap();
    for args in [
        vec!["audit", "verify", s(&export)],
        vec!["audit", "verify", "--key", s(&f.key_file)],
        vec![
            "audit",
            "verify",
            s(&export),
            "--key",
            s(&f.key_file),
            "--nope",
        ],
        vec!["audit", "verify", s(&missing), "--key", s(&f.key_file)],
        vec!["audit", "verify", s(&export), "--key", s(&missing)],
        vec!["audit", "verify", s(&export), "--key", s(&not_a_key)],
        vec![
            "audit",
            "verify",
            s(&export),
            "--key",
            s(&f.key_file),
            "--head",
            "ostena-audit-head-v1:00",
        ],
        vec![
            "audit",
            "verify",
            s(&export),
            "--key",
            s(&f.key_file),
            "--head",
            s(&missing),
        ],
    ] {
        let out = ostena(&args);
        assert_eq!(
            out.status.code(),
            Some(3),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    // Help is not an error.
    assert_eq!(
        ostena(&["audit", "verify", "--help"]).status.code(),
        Some(0)
    );
    // Elsewhere, usage errors keep clap's code.
    assert_eq!(ostena(&["ca", "--nope"]).status.code(), Some(2));
}

#[test]
fn file_that_is_not_an_export_exits_1() {
    let f = Fixture::new("not-export", 1, &[1]);
    let path = f.dir.join("random.bin");
    std::fs::write(&path, b"definitely not an export").unwrap();
    let out = ostena(&["audit", "verify", s(&path), "--key", s(&f.key_file)]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains("[AUD-E004]"));
}
