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
            account: None,
            target_p256_public: None,
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
    let grant = "A".repeat(246);
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
    for grant in ["", "short", &"*".repeat(246)] {
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
        account: Some("root".into()),
        target_p256_public: Some(point()),
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

fn point() -> String {
    URL_SAFE_NO_PAD.encode(SigningKey::generate().unwrap().0.verifying_key().to_bytes())
}

/// A blob that passes the structural check of a host certificate.
fn host_certificate_blob() -> String {
    let name = b"ecdsa-sha2-nistp256-cert-v01@openssh.com";
    let mut blob = u32::try_from(name.len()).unwrap().to_be_bytes().to_vec();
    blob.extend_from_slice(name);
    blob.extend_from_slice(&[0u8; 200]);
    URL_SAFE_NO_PAD.encode(blob)
}

fn ssh_grant_request() -> AgentMessage {
    AgentMessage::SshGrantRequest {
        request_id: 3,
        subject: GROUP.into(),
        login_session: "7a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d".into(),
        certificate_sha256: "ab".repeat(32),
        account: "admin@corp.local".into(),
        resource: "srv-lab01".into(),
        client_address: "10.1.2.3:51000".into(),
    }
}

#[test]
fn ssh_messages_round_trip() {
    let agent = [
        ssh_grant_request(),
        crate::ssh::host_key_message(&SigningKey::generate().unwrap().0, &[1; 32]).unwrap(),
    ];
    for m in agent {
        assert_eq!(decode::<AgentMessage>(&payload(&m)), Ok(m.clone()), "{m:?}");
    }
    let core = [
        CoreMessage::SshTrust {
            version: 1,
            user_ca_p256_public: vec![point(), point()],
            host_ca_p256_public: vec![point()],
            host_certificate: Some(host_certificate_blob()),
        },
        CoreMessage::SshTrust {
            version: 2,
            user_ca_p256_public: vec![point()],
            host_ca_p256_public: vec![point(), point(), point(), point()],
            host_certificate: None,
        },
        CoreMessage::SshGrant {
            request_id: 3,
            grant: "A".repeat(246),
        },
        CoreMessage::LoginRevoked {
            login_session: GROUP.into(),
        },
        CoreMessage::SessionParams {
            request_id: 3,
            session_id: GROUP.into(),
            protocol: SessionProtocol::Ssh,
            host: "10.0.0.1".into(),
            port: 22,
            max_session_secs: 60,
            account: Some("root".into()),
            target_p256_public: Some(point()),
        },
    ];
    for m in core {
        assert_eq!(decode::<CoreMessage>(&payload(&m)), Ok(m.clone()), "{m:?}");
    }
    // Absent optional fields are not written.
    let json = String::from_utf8(payload(&valid_core_messages()[5])).unwrap();
    assert!(!json.contains("account"), "{json}");
}

/// Account, resource and client address of an SSH grant request.
fn field(m: &mut AgentMessage) -> (&mut String, &mut String, &mut String) {
    let AgentMessage::SshGrantRequest {
        account,
        resource,
        client_address,
        ..
    } = m
    else {
        unreachable!()
    };
    (account, resource, client_address)
}

#[test]
fn ssh_grant_request_values_are_checked() {
    let refused = |change: fn(&mut AgentMessage)| {
        let mut m = ssh_grant_request();
        change(&mut m);
        matches!(m.validate(), Err(TunnelError::Protocol(_)))
    };
    assert!(ssh_grant_request().validate().is_ok());
    assert!(refused(|m| *field(m).0 = String::new()));
    assert!(refused(|m| *field(m).0 = " root".into()));
    assert!(refused(|m| *field(m).0 = "ro\not".into()));
    assert!(refused(|m| *field(m).0 = "x".repeat(257)));
    assert!(refused(|m| *field(m).1 = "Srv".into()));
    assert!(refused(|m| *field(m).1 = "a".repeat(64)));
    assert!(refused(|m| *field(m).1 = "-srv".into()));
    assert!(refused(|m| *field(m).2 = "10.1.2.3".into()));
    assert!(refused(|m| {
        let AgentMessage::SshGrantRequest { subject, .. } = m else {
            unreachable!()
        };
        *subject = "root".into();
    }));
    assert!(refused(|m| {
        let AgentMessage::SshGrantRequest {
            certificate_sha256, ..
        } = m
        else {
            unreachable!()
        };
        *certificate_sha256 = "AB".repeat(32);
    }));
}

#[test]
fn ssh_trust_and_host_key_are_checked() {
    let trust = |cas: Vec<String>, certificate: Option<String>| CoreMessage::SshTrust {
        version: 1,
        user_ca_p256_public: cas,
        host_ca_p256_public: vec![point()],
        host_certificate: certificate,
    };
    let host = |cas: Vec<String>| CoreMessage::SshTrust {
        version: 1,
        user_ca_p256_public: vec![point()],
        host_ca_p256_public: cas,
        host_certificate: None,
    };
    let h = point();
    assert!(host(vec![h.clone()]).validate().is_ok());
    assert!(refused_core(&host(vec![])));
    assert!(refused_core(&host(vec![point(); 5])));
    assert!(refused_core(&host(vec![h.clone(), h])));
    assert!(refused_core(&host(vec![URL_SAFE_NO_PAD.encode([4u8; 65])])));
    // The field is required.
    let json = format!(
        r#"{{"type":"ssh_trust","version":1,"user_ca_p256_public":["{}"]}}"#,
        point()
    );
    assert!(matches!(
        decode::<CoreMessage>(json.as_bytes()),
        Err(TunnelError::Protocol(_))
    ));
    let p = point();
    assert!(refused_core(&trust(vec![], None)));
    assert!(refused_core(&trust(vec![point(); 5], None)));
    assert!(refused_core(&trust(vec![p.clone(), p], None)));
    assert!(refused_core(&trust(
        vec![URL_SAFE_NO_PAD.encode([4u8; 65])],
        None
    )));
    assert!(refused_core(&trust(vec![point()], Some("AAAA".into()))));
    assert!(refused_core(&trust(
        vec![point()],
        Some(URL_SAFE_NO_PAD.encode([0u8; 5000]))
    )));
    assert!(refused_core(&CoreMessage::SshTrust {
        version: 0,
        user_ca_p256_public: vec![point()],
        host_ca_p256_public: vec![point()],
        host_certificate: None,
    }));
    assert!(refused_core(&CoreMessage::LoginRevoked {
        login_session: "x".into()
    }));
    assert!(refused_core(&CoreMessage::SshGrant {
        request_id: 1,
        grant: "x".into()
    }));
    for (p256_public, proof) in [
        (point(), URL_SAFE_NO_PAD.encode([1u8; 63])),
        ("AAAA".to_owned(), URL_SAFE_NO_PAD.encode([1u8; 64])),
    ] {
        let m = AgentMessage::SshHostKey { p256_public, proof };
        assert!(matches!(m.validate(), Err(TunnelError::Protocol(_))));
    }
}

#[test]
fn ssh_session_params_need_account_and_host_key() {
    let params =
        |protocol, account: Option<&str>, target: Option<String>| CoreMessage::SessionParams {
            request_id: 1,
            session_id: GROUP.into(),
            protocol,
            host: "10.0.0.1".into(),
            port: 22,
            max_session_secs: 60,
            account: account.map(str::to_owned),
            target_p256_public: target,
        };
    assert!(
        params(SessionProtocol::Ssh, Some("root"), Some(point()))
            .validate()
            .is_ok()
    );
    assert!(refused_core(&params(
        SessionProtocol::Ssh,
        None,
        Some(point())
    )));
    assert!(refused_core(&params(
        SessionProtocol::Ssh,
        Some("root"),
        None
    )));
    assert!(refused_core(&params(
        SessionProtocol::Ssh,
        Some(" root"),
        Some(point())
    )));
    assert!(refused_core(&params(
        SessionProtocol::Ssh,
        Some("root"),
        Some(URL_SAFE_NO_PAD.encode([4u8; 65]))
    )));
    assert!(refused_core(&params(
        SessionProtocol::Rdp,
        Some("root"),
        Some(point())
    )));
    assert!(params(SessionProtocol::Rdp, None, None).validate().is_ok());
    // A missing field decodes as absent, then is refused for SSH.
    let json = br#"{"type":"session_params","request_id":1,"session_id":"2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6","protocol":"ssh","host":"10.0.0.1","port":22,"max_session_secs":60}"#;
    assert!(matches!(
        decode::<CoreMessage>(json),
        Err(TunnelError::Protocol(_))
    ));
}

/// REG-SEC-03: an SSH session whose parameters would loosen the host key
/// verification of the target is refused. There is no way to ask for it:
/// the pinned key is mandatory (no key means no session, never "accept
/// what the target presents"), and any extra field, such as a request to
/// skip or relax the check, is refused by the strict decoding. Then the
/// driver compares the key exactly (`driver_pins_the_target_host_key_and_
/// authenticates_with_the_agent_key`, `SSH-E014`), and the core issues no
/// grant for a resource without a pinned key (`INV-E004`).
#[test]
fn reg_sec_03_session_params_cannot_loosen_the_host_key_check() {
    let base = r#"{"type":"session_params","request_id":1,"session_id":"2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6","protocol":"ssh","host":"10.0.0.1","port":22,"max_session_secs":60,"account":"root""#;
    let pinned = format!(r#"{base},"target_p256_public":"{}""#, point());
    assert!(decode::<CoreMessage>(format!("{pinned}}}").as_bytes()).is_ok());
    for json in [
        // No pinned key, or an empty one.
        format!("{base}}}"),
        format!(r#"{base},"target_p256_public":null}}"#),
        format!(r#"{base},"target_p256_public":""}}"#),
        // A pinned key plus a request to relax the check.
        format!(r#"{pinned},"strict_host_key_checking":false}}"#),
        format!(r#"{pinned},"host_key_check":"accept-new"}}"#),
        format!(r#"{pinned},"known_hosts":"none"}}"#),
    ] {
        assert!(
            matches!(
                decode::<CoreMessage>(json.as_bytes()),
                Err(TunnelError::Protocol(_))
            ),
            "{json}"
        );
    }
}

#[test]
fn ssh_field_names_are_not_redacted() {
    for name in [
        "p256_public",
        "proof",
        "subject",
        "login_session",
        "certificate_sha256",
        "account",
        "resource",
        "client_address",
        "user_ca_p256_public",
        "host_ca_p256_public",
        "host_authorities",
        "host_certificate",
        "target_p256_public",
        "authorities",
    ] {
        assert!(
            !ostena_common::logging::is_sensitive_field(name),
            "{name} would be redacted"
        );
    }
}
