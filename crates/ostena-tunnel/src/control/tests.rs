use ostena_common::config::scope::AllowRuleSpec;
use ostena_crypto::p256::SigningKey;
use proptest::prelude::*;

use super::*;

const GROUP: &str = "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6";

fn hello() -> AgentMessage {
    AgentMessage::Hello {
        protocol: PROTOCOL_VERSION,
        agent_version: "0.1.0".into(),
        gateway_group: GROUP.into(),
        config_fingerprint: format!("sha256:{}", "ab".repeat(32)),
    }
}

fn grant_key() -> GrantKey {
    let key = SigningKey::generate().unwrap().0.verifying_key();
    GrantKey {
        kid: Kid::of(&key).to_string(),
        public_key: URL_SAFE_NO_PAD.encode(key.to_bytes()),
        retire_at: None,
    }
}

fn policy() -> PolicySpec {
    PolicySpec {
        gateway_group: GROUP.into(),
        allow: vec![AllowRuleSpec {
            label: Some("admin".into()),
            networks: vec!["10.0.0.0/24".into()],
            ports: vec!["22".into(), "3389".into()],
        }],
        ..PolicySpec::default()
    }
}

fn valid_core_messages() -> Vec<CoreMessage> {
    vec![
        CoreMessage::HelloAck {
            protocol: PROTOCOL_VERSION,
            core_version: "0.1.0".into(),
            heartbeat_secs: 10,
        },
        CoreMessage::Ping { seq: 1 },
        CoreMessage::Pong { seq: 1 },
        CoreMessage::Policy {
            version: 3,
            policy: policy(),
        },
        CoreMessage::KeySet {
            version: 2,
            keys: vec![grant_key(), grant_key()],
        },
        CoreMessage::SessionParams {
            request_id: 7,
            session_id: GROUP.into(),
            protocol: SessionProtocol::Rdp,
            host: "srv-01.example.test".into(),
            port: 3389,
            max_session_secs: 3600,
        },
        CoreMessage::SessionRefused {
            request_id: 7,
            code: "GRT-E010".into(),
            message: "grant déjà utilisé".into(),
        },
        CoreMessage::Certificate {
            certificate: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".into(),
            not_before: 1,
            not_after: 2,
        },
        CoreMessage::Shutdown {
            reason: "maintenance".into(),
        },
    ]
}

fn payload<M: Message>(m: &M) -> Vec<u8> {
    encode(m).unwrap()[4..].to_vec()
}

fn refused_core(m: &CoreMessage) -> bool {
    matches!(m.validate(), Err(TunnelError::Protocol(_)))
}

#[test]
fn every_valid_core_message_round_trips() {
    for m in valid_core_messages() {
        assert_eq!(decode::<CoreMessage>(&payload(&m)), Ok(m.clone()), "{m:?}");
    }
}

#[test]
fn every_valid_agent_message_round_trips() {
    let grant = "A".repeat(224);
    let messages = [
        hello(),
        AgentMessage::Ping { seq: 9 },
        AgentMessage::Pong { seq: 9 },
        AgentMessage::SessionRequest {
            request_id: 1,
            grant,
        },
        AgentMessage::SessionClosed {
            session_id: GROUP.into(),
            reason: "fin normale".into(),
            bytes_to_target: 10,
            bytes_from_target: 20,
        },
        AgentMessage::Renew {
            request: URL_SAFE_NO_PAD.encode([1u8; 100]),
        },
    ];
    for m in messages {
        assert_eq!(decode::<AgentMessage>(&payload(&m)), Ok(m.clone()), "{m:?}");
    }
}

#[test]
fn frame_has_a_big_endian_length_prefix() {
    let frame = encode(&CoreMessage::Ping { seq: 1 }).unwrap();
    let len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    assert_eq!(len, frame.len() - 4);
}

#[test]
fn unknown_type_and_unknown_field_are_refused() {
    for json in [
        r#"{"type":"reboot"}"#,
        r#"{"type":"ping","seq":1,"extra":true}"#,
        r#"{"seq":1}"#,
        r#"{"type":"ping"}"#,
        r#"{"type":"ping","seq":-1}"#,
        "[]",
        "",
    ] {
        assert!(
            matches!(
                decode::<CoreMessage>(json.as_bytes()),
                Err(TunnelError::Protocol(_))
            ),
            "{json}"
        );
    }
    let policy_with_extra = r#"{"type":"policy","version":1,"policy":{"allow":[],"backdoor":1}}"#;
    assert!(decode::<CoreMessage>(policy_with_extra.as_bytes()).is_err());
}

#[test]
fn other_protocol_versions_are_refused() {
    let ack = CoreMessage::HelloAck {
        protocol: 2,
        core_version: "x".into(),
        heartbeat_secs: 10,
    };
    assert_eq!(ack.validate(), Err(TunnelError::Version(2)));
    let AgentMessage::Hello {
        agent_version,
        gateway_group,
        config_fingerprint,
        ..
    } = hello()
    else {
        unreachable!()
    };
    let old = AgentMessage::Hello {
        protocol: 0,
        agent_version,
        gateway_group,
        config_fingerprint,
    };
    assert_eq!(old.validate(), Err(TunnelError::Version(0)));
}

#[test]
fn oversized_messages_are_refused() {
    let big = CoreMessage::Shutdown {
        reason: "x".repeat(MAX_MESSAGE),
    };
    assert!(encode(&big).is_err());
    let raw = format!(
        r#"{{"type":"shutdown","reason":"{}"}}"#,
        "x".repeat(MAX_MESSAGE)
    );
    assert!(decode::<CoreMessage>(raw.as_bytes()).is_err());
    assert!(decode::<CoreMessage>(&vec![b' '; MAX_FRAME + 1]).is_err());
}

#[test]
fn hello_fields_are_checked() {
    let with = |edit: fn(&mut AgentMessage)| {
        let mut m = hello();
        edit(&mut m);
        m.validate()
    };
    let cases: [fn(&mut AgentMessage); 4] = [
        |m| {
            if let AgentMessage::Hello { gateway_group, .. } = m {
                *gateway_group = "not-a-uuid".into();
            }
        },
        |m| {
            if let AgentMessage::Hello {
                config_fingerprint, ..
            } = m
            {
                *config_fingerprint = format!("md5:{}", "a".repeat(32));
            }
        },
        |m| {
            if let AgentMessage::Hello {
                config_fingerprint, ..
            } = m
            {
                *config_fingerprint = format!("sha256:{}", "A".repeat(64));
            }
        },
        |m| {
            if let AgentMessage::Hello { agent_version, .. } = m {
                *agent_version = "1.0\n[INFO] faux".into();
            }
        },
    ];
    for edit in cases {
        assert!(matches!(with(edit), Err(TunnelError::Protocol(_))));
    }
}

#[test]
fn grant_and_renewal_are_checked() {
    for grant in ["", "short", &"*".repeat(224)] {
        let m = AgentMessage::SessionRequest {
            request_id: 1,
            grant: grant.to_owned(),
        };
        assert!(m.validate().is_err(), "{grant}");
    }
    for request in ["not base64!", &"A".repeat(1025)] {
        let m = AgentMessage::Renew {
            request: request.to_owned(),
        };
        assert!(m.validate().is_err());
    }
}

#[test]
fn key_set_is_checked() {
    let mut wrong_kid = grant_key();
    wrong_kid.kid = "0000000000000000".into();
    let mut off_curve = grant_key();
    let mut raw = URL_SAFE_NO_PAD.decode(&off_curve.public_key).unwrap();
    raw[64] ^= 1;
    off_curve.public_key = URL_SAFE_NO_PAD.encode(raw);
    let mut short = grant_key();
    short.public_key = URL_SAFE_NO_PAD.encode([4u8; 33]);
    let dup = grant_key();
    for keys in [
        vec![],
        vec![wrong_kid],
        vec![off_curve],
        vec![short],
        vec![dup.clone(), dup],
        (0..=MAX_KEYS).map(|_| grant_key()).collect(),
    ] {
        assert!(refused_core(&CoreMessage::KeySet { version: 1, keys }));
    }
    assert!(refused_core(&CoreMessage::KeySet {
        version: 0,
        keys: vec![grant_key()]
    }));
}

#[test]
fn pushed_policy_is_compiled_as_for_production() {
    let mut bad_network = policy();
    bad_network.allow[0].networks = vec!["10.0.0.0/33".into()];
    assert!(refused_core(&CoreMessage::Policy {
        version: 1,
        policy: bad_network
    }));
    let mut short_names = policy();
    short_names.allow_short_names = true;
    assert!(refused_core(&CoreMessage::Policy {
        version: 1,
        policy: short_names
    }));
    let mut floor = policy();
    floor.floor_exceptions = vec![ostena_common::config::scope::FloorExceptionSpec {
        network: "127.0.0.1/32".into(),
        reason: "x".repeat(30),
    }];
    assert!(refused_core(&CoreMessage::Policy {
        version: 1,
        policy: floor
    }));
}

#[test]
fn session_params_are_checked() {
    let params = |host: &str, port: u16, max: u32, id: &str| CoreMessage::SessionParams {
        request_id: 1,
        session_id: id.into(),
        protocol: SessionProtocol::Ssh,
        host: host.into(),
        port,
        max_session_secs: max,
    };
    assert!(params("10.0.0.1", 22, 60, GROUP).validate().is_ok());
    assert!(refused_core(&params("", 22, 60, GROUP)));
    assert!(refused_core(&params("bad host", 22, 60, GROUP)));
    assert!(refused_core(&params("10.0.0.1", 0, 60, GROUP)));
    assert!(refused_core(&params("10.0.0.1", 22, 0, GROUP)));
    assert!(refused_core(&params("10.0.0.1", 22, 60, "x")));
}

#[test]
fn refusal_code_and_certificate_are_checked() {
    for code in [
        "",
        "GRT-E01",
        "grt-e010",
        "GRT_E010",
        "GRT-E01x",
        "GRTT-E010",
    ] {
        assert!(refused_core(&CoreMessage::SessionRefused {
            request_id: 1,
            code: code.into(),
            message: "x".into()
        }));
    }
    assert!(refused_core(&CoreMessage::Certificate {
        certificate: "MIIB".into(),
        not_before: 1,
        not_after: 2,
    }));
    assert!(refused_core(&CoreMessage::Certificate {
        certificate: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".into(),
        not_before: 2,
        not_after: 2,
    }));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn prop_decode_never_panics(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = decode::<CoreMessage>(&data);
        let _ = decode::<AgentMessage>(&data);
    }

    #[test]
    fn prop_ping_round_trip(seq in any::<u64>()) {
        let m = CoreMessage::Ping { seq };
        prop_assert_eq!(decode::<CoreMessage>(&payload(&m)), Ok(m));
    }
}
