use proptest::prelude::*;

use super::*;

const KEY: &str =
    "BMk7TbSdl7gYKqG8Ewp_3Hs1Y1vYwSN9i0B5v2jYb2ZgL2uRk0Xh0y3Kt0hY1n3b5T1dH0rWg9z8Qp1VbYp9c0A";

fn request(extra: &str) -> String {
    format!(
        r#"{{"protocol":1,"username":"jdupont","password":"p4ss","totp":"123456","p256_public":"{KEY}"{extra}}}"#
    )
}

fn shown(s: &SecretString) -> String {
    // SECRET-EXPOSURE: test assertion on a throwaway value.
    #[expect(clippy::disallowed_methods)]
    let v = s.expose_secret().to_owned();
    v
}

#[test]
fn login_request_accepted() {
    assert_eq!(KEY.len(), 87);
    let r = LoginRequest::parse(request("").as_bytes()).unwrap();
    assert_eq!(r.username, "jdupont");
    assert_eq!(shown(&r.password), "p4ss");
    assert_eq!(shown(&r.totp), "123456");
    assert_eq!(r.ttl_secs, None);
    let r = LoginRequest::parse(request(r#","ttl_secs":3600"#).as_bytes()).unwrap();
    assert_eq!(r.ttl_secs, Some(3600));
    // Serialised by the client, parsed by the core.
    let body = serde_json::to_vec(&r).unwrap();
    let back = LoginRequest::parse(&body).unwrap();
    assert_eq!(shown(&back.password), "p4ss");
    assert_eq!(back.ttl_secs, Some(3600));
}

#[test]
fn login_request_refusals() {
    for (body, want) in [
        (request(r#","extra":1"#), "json"),
        (request(r#","username":"x""#), "json"),
        (
            request("").replace(r#""protocol":1"#, r#""protocol":2"#),
            "protocol",
        ),
        (request("").replace("jdupont", "JDupont"), "username"),
        (request("").replace("jdupont", "-x"), "username"),
        (request("").replace("jdupont", &"a".repeat(65)), "username"),
        (request("").replace("jdupont", ""), "username"),
        (request("").replace(r#""p4ss""#, r#""""#), "password"),
        (request("").replace("p4ss", &"a".repeat(1025)), "password"),
        (request("").replace("123456", ""), "totp"),
        (request("").replace("123456", &"1".repeat(17)), "totp"),
        (request("").replace(KEY, &KEY[1..]), "p256_public"),
        (
            request("").replace(KEY, &KEY.replace('_', "/")),
            "p256_public",
        ),
        (request(r#","ttl_secs":59"#), "ttl_secs"),
        (request(r#","ttl_secs":28801"#), "ttl_secs"),
        ("[]".to_owned(), "json"),
        (String::new(), "json"),
    ] {
        let err = LoginRequest::parse(body.as_bytes()).err().unwrap();
        let kind = match err {
            WireError::Json(_) => "json",
            WireError::TooLarge => "large",
            WireError::Protocol(_) => "protocol",
            WireError::Field(f, _) => f,
        };
        assert_eq!(kind, want, "{body}");
    }
    let big = request(&format!(r#","ttl_secs":{}"#, "0".repeat(MAX_BODY)));
    assert_eq!(
        LoginRequest::parse(big.as_bytes()).err(),
        Some(WireError::TooLarge)
    );
}

fn response() -> LoginResponse {
    LoginResponse {
        protocol: 1,
        login_session: "0b8f4c1e-7a52-4d0e-9f3b-2c6d1a9e8f70".into(),
        user: "5a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d".into(),
        certificate: "ecdsa-sha2-nistp256-cert-v01@openssh.com AAAA jdupont".into(),
        valid_after: 1_800_000_000,
        valid_before: 1_800_028_800,
        host_ca: "ecdsa-sha2-nistp256 AAAA ostena-host-ca".into(),
        ssh_hosts: vec!["bastion.example".into(), "*.bastion.example".into()],
        ssh_port: 2222,
    }
}

#[test]
fn login_response_round_trips_and_is_checked() {
    let ok = response();
    let body = serde_json::to_vec(&ok).unwrap();
    assert_eq!(LoginResponse::parse(&body).unwrap(), ok);
    let mutations: [fn(&mut LoginResponse); 14] = [
        |r| r.protocol = 0,
        |r| r.login_session = r.login_session.to_uppercase(),
        |r| r.user = "x".into(),
        |r| r.certificate = "ssh-rsa-cert-v01@openssh.com AAAA".into(),
        |r| r.certificate.push('\n'),
        |r| r.host_ca = "ssh-ed25519 AAAA".into(),
        |r| r.valid_before = r.valid_after,
        |r| r.valid_before = r.valid_after + MAX_SESSION_SECS + VALIDITY_MARGIN_SECS + 1,
        |r| r.ssh_hosts.clear(),
        |r| r.ssh_hosts = vec!["a b".into()],
        |r| r.ssh_hosts = vec!["*".into()],
        |r| r.ssh_hosts = vec!["*.*".into()],
        |r| r.ssh_hosts = vec!["bastion.example".into(), "?*.-".into()],
        |r| r.ssh_port = 0,
    ];
    for (i, mutate) in mutations.iter().enumerate() {
        let mut r = response();
        mutate(&mut r);
        let body = serde_json::to_vec(&r).unwrap();
        assert!(LoginResponse::parse(&body).is_err(), "mutation {i}");
    }
}

#[test]
fn error_and_logout_messages() {
    let e = ErrorResponse {
        protocol: 1,
        code: "AUTH-E001".into(),
        message: "identifiants invalides".into(),
    };
    let body = serde_json::to_vec(&e).unwrap();
    assert_eq!(ErrorResponse::parse(&body).unwrap(), e);
    for code in ["AUTH-E01", "auth-E001", "AUTHE0001", "AUTH-X001"] {
        let mut bad = e.clone();
        bad.code = code.into();
        assert!(
            ErrorResponse::parse(&serde_json::to_vec(&bad).unwrap()).is_err(),
            "{code}"
        );
    }
    let mut bad = e.clone();
    bad.message = "a\u{1b}[31m".into();
    assert!(ErrorResponse::parse(&serde_json::to_vec(&bad).unwrap()).is_err());

    let l = LogoutRequest {
        protocol: 1,
        login_session: "0b8f4c1e-7a52-4d0e-9f3b-2c6d1a9e8f70".into(),
        certificate: "ecdsa-sha2-nistp256-cert-v01@openssh.com AAAA".into(),
        issued_at: 1_800_000_000,
        signature: "A".repeat(86),
    };
    let body = serde_json::to_vec(&l).unwrap();
    assert_eq!(LogoutRequest::parse(&body).unwrap(), l);
    let mut bad = l.clone();
    bad.signature.pop();
    assert!(LogoutRequest::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
    let message = logout_message(&l.login_session, l.issued_at);
    assert!(message.starts_with(b"ostena-logout-v1\0"));
    assert_eq!(message.len(), 17 + 36 + 8);
}

#[test]
fn names() {
    for ok in [
        "a",
        "jdupont",
        "j.dupont",
        "j_dupont-2",
        "0ps",
        "corp/jdupont",
        "local/admin",
        "jdupont@corp.example",
    ] {
        assert!(is_username(ok), "{ok}");
    }
    let long = "a".repeat(65);
    for bad in [
        "",
        ".a",
        "_a",
        "A",
        "a b",
        "é",
        "Corp/jdupont",
        "/jdupont",
        "corp/",
        "corp/a/b",
        "corp.x/a",
        "a@",
        "@corp",
        "a@b@c",
        "a@Corp.example",
        "a@b/c",
        long.as_str(),
    ] {
        assert!(!is_username(bad), "{bad}");
    }
    assert!(is_uuid("0b8f4c1e-7a52-4d0e-9f3b-2c6d1a9e8f70"));
    assert!(!is_uuid("0b8f4c1e-7a52-4d0e-9f3b-2c6d1a9e8f7"));
    assert!(!is_uuid("0b8f4c1e_7a52-4d0e-9f3b-2c6d1a9e8f70"));
    assert!(!is_uuid("0B8F4C1E-7A52-4D0E-9F3B-2C6D1A9E8F70"));
}

proptest! {
    #[test]
    fn parsers_never_panic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        fuzz(&data);
    }

    #[test]
    fn valid_responses_round_trip(
        after in 0u64..4_000_000_000,
        len in 1u64..=MAX_SESSION_SECS,
        port in 1u16..,
        host in "[*?]{0,3}[a-z0-9][a-z0-9.*?-]{0,30}",
    ) {
        let mut r = response();
        r.valid_after = after;
        r.valid_before = after + len;
        r.ssh_port = port;
        r.ssh_hosts = vec![host];
        let body = serde_json::to_vec(&r).unwrap();
        prop_assert_eq!(LoginResponse::parse(&body).unwrap(), r.clone());
        fuzz(&body);
    }
}

fn access(resource: &str, account: &str) -> SshAccess {
    SshAccess {
        resource: resource.into(),
        account: account.into(),
        host: "bastion.corp".into(),
        valid_until: 2_000_000_000,
    }
}

fn hosts(accesses: Vec<SshAccess>) -> SshHostsResponse {
    SshHostsResponse {
        protocol: PROTOCOL,
        ssh_port: 2222,
        accesses,
    }
}

fn refused(r: &SshHostsResponse) -> WireError {
    SshHostsResponse::parse(&serde_json::to_vec(r).unwrap()).unwrap_err()
}

#[test]
fn ssh_hosts_response_round_trips_and_is_checked() {
    let ok = hosts(vec![
        access("srv-lab01", "admin"),
        access("srv-lab01", "root"),
        access("srv-lab02", "DOMAIN\\svc ops"),
    ]);
    let body = serde_json::to_vec(&ok).unwrap();
    assert_eq!(SshHostsResponse::parse(&body).unwrap(), ok);
    // Not sorted, or twice the same pair.
    for unsorted in [
        vec![access("b", "root"), access("a", "root")],
        vec![access("a", "root"), access("a", "root")],
    ] {
        assert!(matches!(
            refused(&hosts(unsorted)),
            WireError::Field("accesses", _)
        ));
    }
    for (resource, account, field) in [
        ("Srv", "root", "resource"),
        ("-srv", "root", "resource"),
        ("srv", "", "account"),
        ("srv", " root", "account"),
        ("srv", "ro\not", "account"),
    ] {
        let error = refused(&hosts(vec![access(resource, account)]));
        assert!(
            matches!(error, WireError::Field(f, _) if f == field),
            "{resource} {account}"
        );
    }
    let mut pattern = access("srv", "root");
    pattern.host = "bastion*.corp".into();
    assert!(matches!(
        refused(&hosts(vec![pattern])),
        WireError::Field("host", _)
    ));
    let mut zero = hosts(Vec::new());
    zero.ssh_port = 0;
    assert!(matches!(refused(&zero), WireError::Field("ssh_port", _)));
    // More than 16 KiB is fine here, up to 256 KiB.
    let many: Vec<SshAccess> = (0..MAX_SSH_ACCESSES)
        .map(|i| access(&format!("srv-{i:04}"), "root"))
        .collect();
    let body = serde_json::to_vec(&hosts(many)).unwrap();
    assert!(body.len() > MAX_BODY);
    assert!(SshHostsResponse::parse(&body).is_ok());
    let too_many: Vec<SshAccess> = (0..=MAX_SSH_ACCESSES)
        .map(|i| access(&format!("srv-{i:04}"), "root"))
        .collect();
    assert!(matches!(
        refused(&hosts(too_many)),
        WireError::Field("accesses", _)
    ));
    // The listing and the logout sign different bytes.
    assert_ne!(
        ssh_hosts_message(&"0".repeat(36), 1),
        logout_message(&"0".repeat(36), 1)
    );
}
