use proptest::prelude::*;

use super::*;
use crate::{ChainId, Field, ZERO_DIGEST};

fn record() -> Record {
    Record {
        chain_id: ChainId::from_bytes([0xab; 16]),
        seq: 42,
        prev_hash: ZERO_DIGEST,
        time_ms: 1_795_782_896_500,
        outcome: Outcome::Refused,
        actor_kind: ActorKind::User,
        actor: "élise \"admin\"".into(),
        event: "access.session_refused".into(),
        fields: vec![
            Field {
                name: "agent_id".into(),
                value: Value::Uuid([1; 16]),
            },
            Field {
                name: "complete".into(),
                value: Value::Bool(true),
            },
            Field {
                name: "hmac".into(),
                value: Value::Bytes(vec![0, 0xff]),
            },
            Field {
                name: "port".into(),
                value: Value::U64(22),
            },
            Field {
                name: "reason".into(),
                value: Value::Text("a\\b 🔑".into()),
            },
        ],
    }
}

#[test]
fn the_ocsf_event_of_a_record() {
    let json = ocsf(&record(), "0.2.0");
    assert!(json.is_ascii());
    let chain = "abababab-abab-abab-abab-abababababab";
    for part in [
        "\"class_uid\":0",
        "\"activity_id\":99",
        "\"type_uid\":99",
        "\"message\":\"access.session_refused\"",
        "\"event_code\":\"access.session_refused\"",
        &format!("\"uid\":\"{chain}:42\""),
        &format!("\"correlation_uid\":\"{chain}\""),
        "\"sequence\":42",
        "\"version\":\"1.3.0\"",
        "\"product\":{\"name\":\"Ostena\",\"vendor_name\":\"Ostena\",\"version\":\"0.2.0\"}",
        "\"severity_id\":3",
        "\"status\":\"Failure\"",
        "\"status_detail\":\"refused\"",
        "\"status_id\":2",
        "\"time\":1795782896500",
        "\"actor\":{\"user\":{\"name\":\"\\u00e9lise \\\"admin\\\"\",\"type\":\"User\",\"type_id\":1}}",
        "\"agent_id\":\"01010101-0101-0101-0101-010101010101\"",
        "\"complete\":true",
        "\"hmac\":\"00ff\"",
        "\"port\":22",
        "\"reason\":\"a\\\\b \\ud83d\\udd11\"",
    ] {
        assert!(json.contains(part), "{part} absent de {json}");
    }
    assert!(json.starts_with('{') && json.ends_with("}}"));
}

#[test]
fn the_syslog_message_of_a_record() {
    let mut r = record();
    let m = message(&r, "core 01\u{e9}.example", "0.2.0");
    let parsed = parse_message(&m).unwrap();
    assert_eq!((parsed.facility, parsed.severity), (13, 5));
    assert_eq!(parsed.timestamp, "2026-11-27T12:34:56.500Z");
    assert_eq!(parsed.hostname, "core01.example");
    assert_eq!(
        (
            parsed.app_name,
            parsed.proc_id,
            parsed.msg_id,
            parsed.structured_data
        ),
        ("ostena", "-", "audit", "-")
    );
    assert_eq!(parsed.msg, ocsf(&r, "0.2.0").as_bytes());
    r.outcome = Outcome::Success;
    assert!(message(&r, "", "v").starts_with(b"<110>1 "));
    r.outcome = Outcome::Failure;
    assert!(message(&r, "", "v").starts_with(b"<108>1 "));
    assert_eq!(parse_message(&message(&r, "", "v")).unwrap().hostname, "-");
}

#[test]
fn rfc5424_headers_are_strict() {
    for good in [
        &b"<0>1 - - - - - -"[..],
        b"<191>1 2026-11-27T00:00:00Z h a p m [id@1 k=\"v\\\"]\"][x] msg",
        b"<13>1 - h a p m - ",
    ] {
        assert!(
            parse_message(good).is_ok(),
            "{}",
            String::from_utf8_lossy(good)
        );
    }
    let sd = parse_message(b"<13>1 - h a p m [a b=\"]\"] x").unwrap();
    assert_eq!((sd.structured_data, sd.msg), ("[a b=\"]\"]", &b"x"[..]));
    for bad in [
        &b""[..],
        b"<192>1 - - - - - -",
        b"<013>1 - - - - - -",
        b"<>1 - - - - - -",
        b"<13>2 - - - - - -",
        b"<13>1 - - - - -",
        b"<13>1 - - - - - [unterminated",
        b"<13>1 - - - - - [a b=\"\\x\"]",
        b"<13>1 - - - - - [a][b",
        b"<13>1 - - - - - -x",
        b"<13>1  - - - - -",
        b"<13>1 - - - - 012345678901234567890123456789012 -",
    ] {
        assert!(
            parse_message(bad).is_err(),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
}

#[test]
fn frames_are_octet_counted() {
    assert_eq!(frame(b"<13>1 x"), b"7 <13>1 x");
    let mut d = FrameDecoder::new();
    d.push(b"3 abc4 de");
    assert_eq!(d.next_message().unwrap().unwrap(), b"abc");
    assert_eq!(d.next_message().unwrap(), None);
    d.push(b"fg");
    assert_eq!(d.next_message().unwrap().unwrap(), b"defg");
    assert_eq!(d.pending(), 0);
    d.push(b"12");
    assert_eq!(d.next_message().unwrap(), None);
    for bad in [
        &b"0 "[..],
        b"03 abc",
        b" abc",
        b"x",
        b"999999 ",
        b"65537 ",
        b"12x",
    ] {
        let mut d = FrameDecoder::new();
        d.push(bad);
        assert!(
            d.next_message().is_err(),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
    let mut d = FrameDecoder::new();
    d.push(format!("{MAX_MESSAGE} ").as_bytes());
    assert_eq!(d.next_message().unwrap(), None);
}

#[test]
fn rfc3339_and_hostnames() {
    assert_eq!(rfc3339_ms(0), "1970-01-01T00:00:00.000Z");
    assert_eq!(rfc3339_ms(951_868_799_123), "2000-02-29T23:59:59.123Z");
    assert_eq!(hostname(&"x".repeat(300)).len(), 255);
    assert_eq!(hostname(" \t"), "-");
}

fn value() -> impl Strategy<Value = Value> {
    prop_oneof![
        "\\PC{0,40}".prop_map(Value::Text),
        any::<u64>().prop_map(Value::U64),
        prop::collection::vec(any::<u8>(), 0..64).prop_map(Value::Bytes),
        any::<[u8; 16]>().prop_map(Value::Uuid),
        any::<bool>().prop_map(Value::Bool),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Every record gives an ASCII message that reads back with its JSON,
    /// and framed messages read back whatever the chunks.
    #[test]
    fn prop_messages_and_frames_round_trip(
        actor in "\\PC{0,40}",
        values in prop::collection::vec(value(), 0..6),
        outcome in prop::sample::select(Outcome::ALL.to_vec()),
        kind in prop::sample::select(ActorKind::ALL.to_vec()),
        time_ms in 0u64..253_402_300_799_999,
        host in "\\PC{0,20}",
        cuts in prop::collection::vec(1usize..64, 1..20),
    ) {
        let mut r = record();
        r.actor = actor;
        r.outcome = outcome;
        r.actor_kind = kind;
        r.time_ms = time_ms;
        r.fields = values
            .into_iter()
            .enumerate()
            .map(|(i, value)| Field { name: format!("f{i}"), value })
            .collect();
        let m = message(&r, &host, "1");
        prop_assert!(m.is_ascii());
        let parsed = parse_message(&m).unwrap();
        let json = ocsf(&r, "1");
        prop_assert_eq!(parsed.msg, json.as_bytes());
        prop_assert_eq!(parsed.timestamp, rfc3339_ms(time_ms));
        let mut stream = frame(&m);
        stream.extend_from_slice(&frame(b"second"));
        let mut d = FrameDecoder::new();
        let mut out = Vec::new();
        let mut rest = stream.as_slice();
        for cut in cuts.iter().cycle() {
            if rest.is_empty() {
                break;
            }
            let (chunk, tail) = rest.split_at((*cut).min(rest.len()));
            d.push(chunk);
            rest = tail;
            while let Some(message) = d.next_message().unwrap() {
                out.push(message);
            }
        }
        prop_assert_eq!(out, vec![m, b"second".to_vec()]);
    }

    /// The readers never panic on arbitrary bytes.
    #[test]
    fn prop_readers_do_not_panic(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        crate::fuzz::syslog(&bytes);
    }
}
