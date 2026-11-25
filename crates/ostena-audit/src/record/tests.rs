use proptest::prelude::*;

use super::*;

/// Lays a record out byte by byte, without any check: the reference the
/// encoder must match, and the source of malformed inputs.
#[derive(Clone)]
struct Raw {
    version: u8,
    seq: u64,
    prev: [u8; 32],
    outcome: u8,
    actor_kind: u8,
    actor: Vec<u8>,
    event: Vec<u8>,
    fields: Vec<(Vec<u8>, u8, Vec<u8>)>,
}

impl Raw {
    fn valid() -> Self {
        Self {
            version: 1,
            seq: 1,
            prev: [0; 32],
            outcome: 0,
            actor_kind: 0,
            actor: b"core".to_vec(),
            event: b"audit.chain_started".to_vec(),
            fields: vec![
                (b"heartbeat_secs".to_vec(), 2, 60u64.to_be_bytes().to_vec()),
                (b"kid".to_vec(), 3, vec![0xab; 8]),
            ],
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut out = vec![self.version];
        out.extend_from_slice(&[0x11; 16]);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.prev);
        out.extend_from_slice(&1_800_000_000_000u64.to_be_bytes());
        out.push(self.outcome);
        out.push(self.actor_kind);
        out.push(u8::try_from(self.actor.len()).unwrap());
        out.extend_from_slice(&self.actor);
        out.push(u8::try_from(self.event.len()).unwrap());
        out.extend_from_slice(&self.event);
        out.push(u8::try_from(self.fields.len()).unwrap());
        for (name, kind, value) in &self.fields {
            out.push(u8::try_from(name.len()).unwrap());
            out.extend_from_slice(name);
            out.push(*kind);
            out.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
            out.extend_from_slice(value);
        }
        out
    }

    fn with(mut self, change: impl FnOnce(&mut Self)) -> Self {
        change(&mut self);
        self
    }
}

fn vector() -> Record {
    Record {
        chain_id: ChainId::from_bytes([0x11; 16]),
        seq: 1,
        prev_hash: ZERO_DIGEST,
        time_ms: 1_800_000_000_000,
        outcome: Outcome::Success,
        actor_kind: ActorKind::Core,
        actor: "core".into(),
        event: "audit.chain_started".into(),
        fields: vec![
            Field {
                name: "heartbeat_secs".into(),
                value: Value::U64(60),
            },
            Field {
                name: "kid".into(),
                value: Value::Bytes(vec![0xab; 8]),
            },
        ],
    }
}

/// The encoding of [`vector`], written out by hand.
const VECTOR_BODY: &str = concat!(
    "0111111111111111111111111111111111000000000000000100000000000000",
    "00000000000000000000000000000000000000000000000000000001a3185c50",
    "00000004636f72651361756469742e636861696e5f73746172746564020e6865",
    "617274626561745f73656373020008000000000000003c036b6964030008abab",
    "abababababab",
);

/// SHA-256("ostena-audit-record-v1" ‖ 0x00 ‖ body), computed with an
/// independent tool (`sha256sum`).
const VECTOR_HASH: &str = "fce60dfa1931aff3058fd0f2c98b3dfdd0c6782d0765b15715c937aa133092a1";

#[test]
fn known_vector() {
    let bytes = Raw::valid().bytes();
    assert_eq!(bytes.len(), 134);
    assert_eq!(crate::ids::to_hex(&bytes), VECTOR_BODY);
    assert_eq!(vector().encode().unwrap(), bytes);
    assert_eq!(Record::decode(&bytes).unwrap(), vector());
    assert_eq!(crate::ids::to_hex(&record_hash(&bytes)), VECTOR_HASH);
}

#[test]
fn every_value_type_round_trips() {
    let mut record = vector();
    record.seq = 7;
    record.prev_hash = [9; 32];
    record.outcome = Outcome::Failure;
    record.actor_kind = ActorKind::Peer;
    record.actor = "192.0.2.1:4433 é".into();
    record.fields = vec![
        Field {
            name: "a".into(),
            value: Value::Text("texte accentué".into()),
        },
        Field {
            name: "b".into(),
            value: Value::U64(u64::MAX),
        },
        Field {
            name: "c".into(),
            value: Value::Bytes(Vec::new()),
        },
        Field {
            name: "d".into(),
            value: Value::Uuid([5; 16]),
        },
        Field {
            name: "e".into(),
            value: Value::Bool(true),
        },
        Field {
            name: "f".into(),
            value: Value::Bool(false),
        },
    ];
    let bytes = record.encode().unwrap();
    assert_eq!(Record::decode(&bytes).unwrap(), record);
}

fn refused(raw: &Raw) -> AuditError {
    Record::decode(&raw.bytes()).expect_err("must be refused")
}

#[test]
fn refuses_another_version() {
    assert_eq!(
        refused(&Raw::valid().with(|r| r.version = 2)),
        AuditError::Unsupported {
            what: "version d'enregistrement",
            value: 2
        }
    );
    assert_eq!(Record::decode(&[]).unwrap_err().code(), "AUD-E001");
}

#[test]
fn refuses_inconsistent_sequence_and_previous_hash() {
    for raw in [
        Raw::valid().with(|r| r.seq = 0),
        Raw::valid().with(|r| r.prev = [1; 32]),
        Raw::valid().with(|r| r.seq = 2),
    ] {
        assert_eq!(refused(&raw).code(), "AUD-E001");
    }
    assert!(
        Record::decode(
            &Raw::valid()
                .with(|r| {
                    r.seq = 2;
                    r.prev = [1; 32];
                })
                .bytes()
        )
        .is_ok()
    );
}

#[test]
fn refuses_unknown_outcome_and_actor_kind() {
    assert_eq!(
        refused(&Raw::valid().with(|r| r.outcome = 3)).code(),
        "AUD-E001"
    );
    assert_eq!(
        refused(&Raw::valid().with(|r| r.actor_kind = 5)).code(),
        "AUD-E001"
    );
    for (outcome, kind) in [(0, 0), (1, 1), (2, 2), (2, 3), (0, 4)] {
        let raw = Raw::valid().with(|r| {
            r.outcome = outcome;
            r.actor_kind = kind;
        });
        assert!(Record::decode(&raw.bytes()).is_ok());
    }
}

#[test]
fn refuses_bad_actors() {
    for actor in [
        vec![b'a'; 129],
        b"a\nb".to_vec(),
        b"\x1b[31m".to_vec(),
        vec![0xff, 0xfe],
        "a\u{85}b".as_bytes().to_vec(),
    ] {
        assert_eq!(
            refused(&Raw::valid().with(|r| r.actor = actor)).code(),
            "AUD-E001"
        );
    }
    for actor in [Vec::new(), vec![b'a'; 128]] {
        assert!(Record::decode(&Raw::valid().with(|r| r.actor = actor).bytes()).is_ok());
    }
}

#[test]
fn refuses_bad_event_names() {
    for event in [
        b"ab".to_vec(),
        vec![b'a'; 65],
        b"Core.started".to_vec(),
        b"core-started".to_vec(),
        b"core started".to_vec(),
        "é.started".as_bytes().to_vec(),
    ] {
        assert_eq!(
            refused(&Raw::valid().with(|r| r.event = event)).code(),
            "AUD-E001"
        );
    }
    for event in [b"a.b".to_vec(), vec![b'z'; 64], b"x_1.y".to_vec()] {
        assert!(Record::decode(&Raw::valid().with(|r| r.event = event).bytes()).is_ok());
    }
}

#[test]
fn refuses_bad_field_lists() {
    let many: Vec<_> = (0..33u8)
        .map(|i| (format!("f{i:02}").into_bytes(), 5, vec![1]))
        .collect();
    assert_eq!(
        refused(&Raw::valid().with(|r| r.fields = many.clone())).code(),
        "AUD-E001"
    );
    assert!(
        Record::decode(
            &Raw::valid()
                .with(|r| r.fields = many[..32].to_vec())
                .bytes()
        )
        .is_ok()
    );
    let bool_field = |name: &[u8]| (name.to_vec(), 5, vec![1]);
    for fields in [
        vec![bool_field(b"")],
        vec![bool_field(b"Name")],
        vec![bool_field(b"na-me")],
        vec![bool_field(&[b'a'; 33])],
        vec![bool_field(b"b"), bool_field(b"a")],
        vec![bool_field(b"a"), bool_field(b"a")],
        vec![bool_field(b"ab"), bool_field(b"a")],
    ] {
        assert_eq!(
            refused(&Raw::valid().with(|r| r.fields = fields)).code(),
            "AUD-E001"
        );
    }
    assert!(
        Record::decode(
            &Raw::valid()
                .with(|r| r.fields =
                    vec![bool_field(b"a"), bool_field(b"ab"), bool_field(&[b'b'; 32])])
                .bytes()
        )
        .is_ok()
    );
}

#[test]
fn refuses_bad_values() {
    let one = |kind: u8, value: Vec<u8>| {
        Raw::valid().with(|r| r.fields = vec![(b"v".to_vec(), kind, value)])
    };
    for raw in [
        one(0, vec![]),
        one(6, vec![]),
        one(0xff, vec![1]),
        one(1, vec![b'a'; 1025]),
        one(1, b"a\tb".to_vec()),
        one(1, vec![0xc3]),
        one(2, vec![0; 7]),
        one(2, vec![0; 9]),
        one(3, vec![0; 257]),
        one(4, vec![0; 15]),
        one(4, vec![0; 17]),
        one(5, vec![2]),
        one(5, vec![]),
        one(5, vec![0, 0]),
    ] {
        assert_eq!(refused(&raw).code(), "AUD-E001", "{:?}", raw.fields);
    }
    for raw in [
        one(1, vec![b'a'; 1024]),
        one(1, Vec::new()),
        one(3, vec![0; 256]),
        one(5, vec![0]),
    ] {
        assert!(Record::decode(&raw.bytes()).is_ok());
    }
}

#[test]
fn refuses_trailing_bytes_and_every_truncation() {
    let bytes = Raw::valid().bytes();
    let mut longer = bytes.clone();
    longer.push(0);
    assert_eq!(
        Record::decode(&longer),
        Err(AuditError::MalformedRecord(
            "octets en trop après les champs"
        ))
    );
    for cut in 0..bytes.len() {
        assert_eq!(
            Record::decode(&bytes[..cut]).unwrap_err().code(),
            "AUD-E001"
        );
    }
}

#[test]
fn enforces_the_size_limit() {
    // 32 fields of 1024-byte text exceed 8192 bytes.
    let fields: Vec<Field> = (0..32)
        .map(|i| Field {
            name: format!("f{i:02}"),
            value: Value::Text("x".repeat(1024)),
        })
        .collect();
    let mut record = vector();
    record.fields = fields;
    assert_eq!(
        record.encode(),
        Err(AuditError::MalformedRecord("plus de 8192 octets"))
    );
    let raw = Raw::valid().with(|r| {
        r.fields = (0..32)
            .map(|i| (format!("f{i:02}").into_bytes(), 1, vec![b'x'; 1024]))
            .collect();
    });
    assert!(Record::decode(&raw.bytes()).is_err());
    assert!(Record::decode(&vec![1; MAX_RECORD_LEN + 1]).is_err());
}

#[test]
fn smallest_record_is_min_record_len() {
    let raw = Raw::valid().with(|r| {
        r.actor.clear();
        r.event = b"a.b".to_vec();
        r.fields.clear();
    });
    let bytes = raw.bytes();
    assert_eq!(bytes.len(), MIN_RECORD_LEN);
    assert_eq!(MIN_RECORD_LEN, 73);
    let record = Record::decode(&bytes).unwrap();
    assert_eq!(record.encode().unwrap(), bytes);
    // Anything shorter is refused, whatever it holds.
    for len in 0..MIN_RECORD_LEN {
        assert!(Record::decode(&bytes[..len]).is_err(), "{len}");
    }
    let shorter = Raw::valid().with(|r| {
        r.actor.clear();
        r.event = b"ab".to_vec();
        r.fields.clear();
    });
    assert!(Record::decode(&shorter.bytes()).is_err());
}

#[test]
fn encoder_applies_the_same_rules() {
    let mut record = vector();
    record.fields.reverse();
    assert!(record.encode().is_err(), "unsorted fields");
    let mut record = vector();
    record.seq = 2;
    assert!(record.encode().is_err(), "zero previous hash after seq 1");
    let mut record = vector();
    record.event = "Bad".into();
    assert!(record.encode().is_err());
    let mut record = vector();
    record.fields[0].value = Value::Text("\u{7f}".into());
    assert!(record.encode().is_err());
    let mut record = vector();
    record.fields[1].value = Value::Bytes(vec![0; 257]);
    assert!(record.encode().is_err());
}

fn value() -> impl Strategy<Value = Value> {
    prop_oneof![
        "[a-zA-Z0-9 éàü@:/._-]{0,64}".prop_map(Value::Text),
        any::<u64>().prop_map(Value::U64),
        prop::collection::vec(any::<u8>(), 0..=256).prop_map(Value::Bytes),
        any::<[u8; 16]>().prop_map(Value::Uuid),
        any::<bool>().prop_map(Value::Bool),
    ]
}

fn record() -> impl Strategy<Value = Record> {
    (
        any::<[u8; 16]>(),
        1u64..=u64::MAX,
        any::<[u8; 32]>(),
        any::<u64>(),
        0u8..3,
        0u8..5,
        "[a-zA-Z0-9 é@.:-]{0,40}",
        "[a-z0-9_.]{3,64}",
        prop::collection::btree_map("[a-z0-9_]{1,32}", value(), 0..=8),
    )
        .prop_map(
            |(chain, seq, prev, time_ms, outcome, kind, actor, event, fields)| Record {
                chain_id: ChainId::from_bytes(chain),
                seq,
                prev_hash: if seq == 1 {
                    ZERO_DIGEST
                } else if prev == ZERO_DIGEST {
                    [1; 32]
                } else {
                    prev
                },
                time_ms,
                outcome: Outcome::from_code(outcome).unwrap(),
                actor_kind: ActorKind::from_code(kind).unwrap(),
                actor,
                event,
                fields: fields
                    .into_iter()
                    .map(|(name, value)| Field { name, value })
                    .collect(),
            },
        )
}

proptest! {
    #[test]
    fn prop_round_trip(record in record()) {
        let bytes = record.encode().unwrap();
        prop_assert!(bytes.len() <= MAX_RECORD_LEN);
        let decoded = Record::decode(&bytes).unwrap();
        prop_assert_eq!(&decoded, &record);
        prop_assert_eq!(decoded.encode().unwrap(), bytes);
    }

    /// Whatever a single byte change gives, an accepted input is canonical.
    #[test]
    fn prop_accepted_inputs_are_canonical(record in record(), at in any::<prop::sample::Index>(), byte in any::<u8>()) {
        let mut bytes = record.encode().unwrap();
        let i = at.index(bytes.len());
        bytes[i] = byte;
        if let Ok(decoded) = Record::decode(&bytes) {
            prop_assert_eq!(decoded.encode().unwrap(), bytes);
        }
    }

    #[test]
    fn prop_decoder_never_panics(data in prop::collection::vec(any::<u8>(), 0..512)) {
        if let Ok(decoded) = Record::decode(&data) {
            prop_assert_eq!(decoded.encode().unwrap(), data);
        }
    }
}
