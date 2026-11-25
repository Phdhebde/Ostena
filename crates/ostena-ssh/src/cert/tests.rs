use proptest::prelude::*;

use super::*;

const SUBJECT: &str = "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6";
const LOGIN: &str = "7a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
const NOW: u64 = 1_800_000_000;

fn key() -> SigningKey {
    SigningKey::generate().unwrap().0
}

fn user_template(public: VerifyingKey) -> Template {
    Template {
        kind: Kind::User,
        public,
        serial: 7,
        key_id: LOGIN.into(),
        principals: vec![SUBJECT.into()],
        valid_after: NOW - 60,
        valid_before: NOW + 3600,
        critical_options: vec![],
        extensions: vec![(PERMIT_PTY.into(), vec![])],
    }
}

/// Every field as raw bytes, to build blobs the encoder would never write.
#[derive(Clone)]
struct Raw {
    cert_type: Vec<u8>,
    nonce: Vec<u8>,
    curve: Vec<u8>,
    public: Vec<u8>,
    serial: u64,
    kind: u32,
    key_id: Vec<u8>,
    principals: Vec<u8>,
    valid_after: u64,
    valid_before: u64,
    critical: Vec<u8>,
    extensions: Vec<u8>,
    reserved: Vec<u8>,
    authority: Vec<u8>,
    signature: Vec<u8>,
    trailer: Vec<u8>,
}

impl Raw {
    fn from(blob: &[u8]) -> Self {
        let mut r = Reader(blob);
        Self {
            cert_type: r.string().unwrap().to_vec(),
            nonce: r.string().unwrap().to_vec(),
            curve: r.string().unwrap().to_vec(),
            public: r.string().unwrap().to_vec(),
            serial: r.u64().unwrap(),
            kind: r.u32().unwrap(),
            key_id: r.string().unwrap().to_vec(),
            principals: r.string().unwrap().to_vec(),
            valid_after: r.u64().unwrap(),
            valid_before: r.u64().unwrap(),
            critical: r.string().unwrap().to_vec(),
            extensions: r.string().unwrap().to_vec(),
            reserved: r.string().unwrap().to_vec(),
            authority: r.string().unwrap().to_vec(),
            signature: r.string().unwrap().to_vec(),
            trailer: Vec::new(),
        }
    }

    fn signed(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_string(&mut out, &self.cert_type);
        put_string(&mut out, &self.nonce);
        put_string(&mut out, &self.curve);
        put_string(&mut out, &self.public);
        out.extend_from_slice(&self.serial.to_be_bytes());
        out.extend_from_slice(&self.kind.to_be_bytes());
        put_string(&mut out, &self.key_id);
        put_string(&mut out, &self.principals);
        out.extend_from_slice(&self.valid_after.to_be_bytes());
        out.extend_from_slice(&self.valid_before.to_be_bytes());
        put_string(&mut out, &self.critical);
        put_string(&mut out, &self.extensions);
        put_string(&mut out, &self.reserved);
        put_string(&mut out, &self.authority);
        out
    }

    fn bytes(&self) -> Vec<u8> {
        let mut out = self.signed();
        put_string(&mut out, &self.signature);
        out.extend_from_slice(&self.trailer);
        out
    }
}

/// A named change of the raw fields and the refusal it must cause.
type Case = (&'static str, Box<dyn Fn(&mut Raw)>, CertError);

fn names(list: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (n, d) in list {
        put_string(&mut out, n.as_bytes());
        put_string(&mut out, d);
    }
    out
}

#[test]
fn issued_certificate_round_trips_and_verifies() {
    let ca = key();
    let user = key();
    let blob = issue(&user_template(user.verifying_key()), &ca).unwrap();
    let cert = parse(&blob).unwrap();
    assert_eq!(cert.encode(), blob);
    assert_eq!(cert.public, user.verifying_key());
    assert_eq!(cert.nonce.len(), 32);
    assert_eq!(
        cert.verify(&[key().verifying_key(), ca.verifying_key()])
            .unwrap(),
        Kid::of(&ca.verifying_key())
    );
    let id = check_user(&cert, NOW).unwrap();
    assert_eq!(format_uuid(&id.subject), SUBJECT);
    assert_eq!(format_uuid(&id.login_session), LOGIN);
    assert!(id.allow_pty);
    assert_eq!(id.certificate_sha256, ostena_crypto::sha256::digest(&blob));
}

#[test]
fn other_authority_or_altered_signature_is_refused() {
    let ca = key();
    let blob = issue(&user_template(key().verifying_key()), &ca).unwrap();
    let cert = parse(&blob).unwrap();
    assert_eq!(
        cert.verify(&[key().verifying_key()]),
        Err(CertError::UnknownAuthority)
    );
    assert_eq!(cert.verify(&[]), Err(CertError::UnknownAuthority));
    // Same authority named, another signer: the signature fails.
    let mut raw = Raw::from(&blob);
    let other = key();
    let forged = other.sign(&raw.signed()).unwrap();
    raw.signature = signature_blob(&forged);
    let bytes = raw.bytes();
    assert_eq!(
        parse(&bytes).unwrap().verify(&[ca.verifying_key()]),
        Err(CertError::BadSignature)
    );
    // A field changed after signing.
    let mut raw = Raw::from(&blob);
    raw.serial += 1;
    let bytes = raw.bytes();
    assert_eq!(
        parse(&bytes).unwrap().verify(&[ca.verifying_key()]),
        Err(CertError::BadSignature)
    );
}

#[test]
fn high_s_signature_is_refused_by_the_strict_verifier() {
    let ca = key();
    let blob = issue(&user_template(key().verifying_key()), &ca).unwrap();
    let cert = parse(&blob).unwrap();
    // s' = n - s: the other valid ECDSA form, refused (low-S only).
    let n: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    let mut sig = cert.signature.to_bytes();
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = i16::from(n[i]) - i16::from(sig[32 + i]) - borrow;
        borrow = 0;
        if d < 0 {
            d += 256;
            borrow = 1;
        }
        sig[32 + i] = d.to_be_bytes()[1];
    }
    let mut raw = Raw::from(&blob);
    raw.signature = signature_blob(&Signature::from_bytes(&sig));
    let bytes = raw.bytes();
    assert_eq!(
        parse(&bytes).unwrap().verify(&[ca.verifying_key()]),
        Err(CertError::BadSignature)
    );
}

#[test]
#[expect(clippy::too_many_lines, reason = "one table of cases")]
fn format_refusals() {
    let ca = key();
    let blob = issue(&user_template(key().verifying_key()), &ca).unwrap();
    let base = Raw::from(&blob);
    let p384_like = {
        let mut b = Vec::new();
        put_string(&mut b, b"ecdsa-sha2-nistp384");
        put_string(&mut b, b"nistp384");
        put_string(&mut b, &[4u8; 97]);
        b
    };
    let cases: Vec<Case> = vec![
        (
            "ed25519 certificate",
            Box::new(|r| r.cert_type = b"ssh-ed25519-cert-v01@openssh.com".to_vec()),
            CertError::UnsupportedType,
        ),
        (
            "other curve",
            Box::new(|r| r.curve = b"nistp384".to_vec()),
            CertError::UnsupportedType,
        ),
        (
            "point not on the curve",
            Box::new(|r| r.public = vec![4u8; 65]),
            CertError::Malformed("clé certifiée invalide"),
        ),
        (
            "compressed point",
            Box::new(|r| r.public.truncate(33)),
            CertError::Malformed("clé certifiée invalide"),
        ),
        (
            "unknown type",
            Box::new(|r| r.kind = 3),
            CertError::Malformed("type inconnu"),
        ),
        (
            "short nonce",
            Box::new(|r| r.nonce = vec![1; 8]),
            CertError::Malformed("nonce de longueur invalide"),
        ),
        (
            "reserved field",
            Box::new(|r| r.reserved = vec![0]),
            CertError::Malformed("champ réservé non vide"),
        ),
        (
            "P-384 authority",
            Box::new(move |r| r.authority = p384_like.clone()),
            CertError::UnsupportedType,
        ),
        (
            "trailing bytes",
            Box::new(|r| r.trailer = vec![0]),
            CertError::Malformed("octets en trop"),
        ),
        (
            "unsorted extensions",
            Box::new(|r| {
                r.extensions = names(&[("permit-pty", b""), ("permit-agent-forwarding", b"")]);
            }),
            CertError::Malformed("options non triées ou répétées"),
        ),
        (
            "repeated extension",
            Box::new(|r| r.extensions = names(&[("permit-pty", b""), ("permit-pty", b"")])),
            CertError::Malformed("options non triées ou répétées"),
        ),
        (
            "repeated critical option",
            Box::new(|r| {
                r.critical = names(&[("force-command", b"\0\0\0\x01x"), ("force-command", b"")]);
            }),
            CertError::Malformed("options non triées ou répétées"),
        ),
        (
            "control character in key id",
            Box::new(|r| r.key_id = b"a\nb".to_vec()),
            CertError::Malformed("identifiant de clé invalide"),
        ),
        (
            "empty principal",
            Box::new(|r| {
                r.principals = Vec::new();
                put_string(&mut r.principals, b"");
            }),
            CertError::Malformed("principal vide"),
        ),
        (
            "too many principals",
            Box::new(|r| {
                r.principals = Vec::new();
                for i in 0..=MAX_PRINCIPALS {
                    put_string(&mut r.principals, format!("p{i}").as_bytes());
                }
            }),
            CertError::Malformed("trop de principaux"),
        ),
        (
            "rsa signature",
            Box::new(|r| {
                let mut sig = Vec::new();
                put_string(&mut sig, b"rsa-sha2-256");
                put_string(&mut sig, &[1; 256]);
                r.signature = sig;
            }),
            CertError::UnsupportedType,
        ),
    ];
    for (name, change, expected) in cases {
        let mut raw = base.clone();
        change(&mut raw);
        assert_eq!(parse(&raw.bytes()), Err(expected), "{name}");
    }
}

/// A signature blob with the given encodings of r and s.
fn signature_with(r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut inner = Vec::new();
    put_string(&mut inner, r);
    put_string(&mut inner, s);
    let mut blob = Vec::new();
    put_string(&mut blob, KEY_TYPE.as_bytes());
    put_string(&mut blob, &inner);
    blob
}

#[test]
fn non_minimal_or_negative_mpints_are_refused() {
    let ca = key();
    let blob = issue(&user_template(key().verifying_key()), &ca).unwrap();
    let base = Raw::from(&blob);
    let noncanonical = CertError::Malformed("entier de la signature non canonique");
    for (r, s, expected) in [
        // Superfluous leading zero.
        (vec![0, 1], vec![1], noncanonical.clone()),
        // Negative.
        (vec![0x80], vec![1], noncanonical.clone()),
        // Too long.
        (
            [vec![1u8], vec![0; 32]].concat(),
            vec![1],
            noncanonical.clone(),
        ),
        // Zero.
        (vec![], vec![1], CertError::BadSignature),
        (vec![0], vec![1], noncanonical),
    ] {
        let mut raw = base.clone();
        raw.signature = signature_with(&r, &s);
        assert_eq!(parse(&raw.bytes()), Err(expected), "{r:?}");
    }
    // Trailing bytes inside the signature.
    let mut raw = base.clone();
    let mut sig = signature_with(&[1], &[1]);
    sig.push(0);
    let len = u32::try_from(sig.len() - 4).unwrap().to_be_bytes();
    sig[..4].copy_from_slice(&len);
    raw.signature = sig;
    assert!(parse(&raw.bytes()).is_err());
}

#[test]
fn too_large_certificate_is_refused() {
    let ca = key();
    let blob = issue(&user_template(key().verifying_key()), &ca).unwrap();
    let mut raw = Raw::from(&blob);
    raw.critical = names(&[("x", &[0u8; MAX_CERTIFICATE])]);
    assert_eq!(parse(&raw.bytes()), Err(CertError::TooLarge));
}

fn checked(change: impl Fn(&mut Template)) -> Result<UserIdentity, CertError> {
    let ca = key();
    let mut template = user_template(key().verifying_key());
    change(&mut template);
    let blob = issue(&template, &ca).unwrap();
    let cert = parse(&blob).unwrap();
    cert.verify(&[ca.verifying_key()]).unwrap();
    check_user(&cert, NOW)
}

#[test]
fn user_policy_refusals() {
    let refused = |what| Err(CertError::Refused(what));
    assert_eq!(
        checked(|t| t.kind = Kind::Host),
        refused("certificat d'hôte présenté par un client")
    );
    assert_eq!(
        checked(|t| t.principals = vec![]),
        refused("un et un seul principal attendu")
    );
    assert_eq!(
        checked(|t| t.principals.push(LOGIN.into())),
        refused("un et un seul principal attendu")
    );
    assert_eq!(
        checked(|t| t.principals = vec!["root".into()]),
        refused("le principal n'est pas un UUID")
    );
    assert_eq!(
        checked(|t| t.principals = vec![SUBJECT.to_uppercase()]),
        refused("le principal n'est pas un UUID")
    );
    assert_eq!(
        checked(|t| t.key_id = "session".into()),
        refused("l'identifiant de clé n'est pas un UUID")
    );
    assert_eq!(
        checked(|t| t.critical_options = vec![("source-address".into(), vec![0, 0, 0, 0])]),
        refused("option critique présente")
    );
    for extension in [
        "permit-port-forwarding",
        "permit-agent-forwarding",
        "permit-X11-forwarding",
        "permit-user-rc",
        "no-touch-required",
    ] {
        assert_eq!(
            checked(|t| t.extensions.push((extension.into(), vec![]))),
            refused("extension interdite (redirection ou permit-user-rc)"),
            "{extension}"
        );
    }
    assert_eq!(
        checked(|t| t.extensions = vec![(PERMIT_PTY.into(), vec![1])]),
        refused("extension interdite (redirection ou permit-user-rc)")
    );
    assert_eq!(
        checked(|t| t.valid_before = NOW),
        refused("expiré"),
        "valid_before is exclusive"
    );
    assert_eq!(
        checked(|t| t.valid_after = NOW + CLOCK_SKEW_SECS + 1),
        refused("pas encore valide")
    );
    assert!(checked(|t| t.valid_after = NOW + CLOCK_SKEW_SECS).is_ok());
    assert_eq!(
        checked(|t| {
            t.valid_after = NOW - 10;
            t.valid_before = NOW - 10 + MAX_USER_VALIDITY_SECS + 1;
        }),
        refused("validité de plus de 8 heures")
    );
    assert!(
        checked(|t| {
            t.valid_after = NOW - 10;
            t.valid_before = NOW - 10 + MAX_USER_VALIDITY_SECS;
        })
        .is_ok()
    );
    assert_eq!(
        checked(|t| t.valid_after = t.valid_before),
        refused("période de validité vide")
    );
    // Without permit-pty: allowed, without a terminal.
    assert!(!checked(|t| t.extensions = vec![]).unwrap().allow_pty);
}

#[test]
fn host_policy() {
    let ca = key();
    let host = key();
    let template = Template {
        kind: Kind::Host,
        principals: vec!["gw01.example.test".into()],
        key_id: "gw01".into(),
        extensions: vec![],
        ..user_template(host.verifying_key())
    };
    let blob = issue(&template, &ca).unwrap();
    let cert = parse(&blob).unwrap();
    assert_eq!(check_host(&cert, &host.verifying_key(), NOW), Ok(()));
    assert_eq!(
        check_host(&cert, &key().verifying_key(), NOW),
        Err(CertError::Refused("certificat d'une autre clé d'hôte"))
    );
    assert_eq!(
        check_host(&cert, &host.verifying_key(), NOW + 3600),
        Err(CertError::Refused("expiré"))
    );
    let user = issue(&user_template(host.verifying_key()), &ca).unwrap();
    assert!(check_host(&parse(&user).unwrap(), &host.verifying_key(), NOW).is_err());
}

#[test]
fn issue_refuses_what_parse_would_refuse() {
    let ca = key();
    let mut t = user_template(key().verifying_key());
    t.extensions = vec![("a".into(), vec![]), ("a".into(), vec![])];
    assert_eq!(issue(&t, &ca), Err(CertError::Refused("option répétée")));
    let mut t = user_template(key().verifying_key());
    t.principals = (0..=MAX_PRINCIPALS).map(|i| format!("p{i}")).collect();
    assert!(matches!(issue(&t, &ca), Err(CertError::Refused(_))));
    // Unsorted input is sorted.
    let mut t = user_template(key().verifying_key());
    t.extensions = vec![("permit-pty".into(), vec![]), ("a-flag".into(), vec![])];
    let blob = issue(&t, &ca).unwrap();
    let names: Vec<_> = parse(&blob)
        .unwrap()
        .extensions
        .iter()
        .map(|e| e.0)
        .collect();
    assert_eq!(names, ["a-flag", "permit-pty"]);
}

#[test]
fn uuids() {
    assert_eq!(format_uuid(&parse_uuid(SUBJECT).unwrap()), SUBJECT);
    for bad in [
        "",
        "2f6c9a4e1b2c4d5e8f90a1b2c3d4e5f6",
        "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5fg",
        "2F6C9A4E-1B2C-4D5E-8F90-A1B2C3D4E5F6",
        "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6 ",
        "2f6c9a4e+1b2c-4d5e-8f90-a1b2c3d4e5f6",
    ] {
        assert_eq!(parse_uuid(bad), None, "{bad}");
    }
}

fn arb_text() -> impl Strategy<Value = String> {
    "[ -~]{0,40}"
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Whatever the fields, what we issue parses back to the same bytes and
    /// verifies.
    #[test]
    fn prop_issue_parse_encode_round_trip(
        serial in any::<u64>(),
        host in any::<bool>(),
        key_id in arb_text(),
        principals in proptest::collection::vec("[a-z0-9.-]{1,30}", 0..=MAX_PRINCIPALS),
        valid_after in any::<u64>(),
        valid_before in any::<u64>(),
        critical in proptest::collection::btree_map("[a-z-]{1,20}", proptest::collection::vec(any::<u8>(), 0..40), 0..4),
        extensions in proptest::collection::btree_map("[a-z@.-]{1,20}", proptest::collection::vec(any::<u8>(), 0..8), 0..6),
    ) {
        let ca = key();
        let template = Template {
            kind: if host { Kind::Host } else { Kind::User },
            public: key().verifying_key(),
            serial,
            key_id,
            principals,
            valid_after,
            valid_before,
            critical_options: critical.into_iter().collect(),
            extensions: extensions.into_iter().collect(),
        };
        let blob = issue(&template, &ca).unwrap();
        let cert = parse(&blob).unwrap();
        prop_assert_eq!(cert.encode(), blob.clone());
        prop_assert_eq!(cert.serial, serial);
        prop_assert!(cert.verify(&[ca.verifying_key()]).is_ok());
    }

    /// Any change of one byte is refused, or parses to a certificate whose
    /// encoding is that changed blob and whose signature fails.
    #[test]
    fn prop_one_byte_change_never_verifies(at in any::<prop::sample::Index>(), xor in 1u8..) {
        let ca = key();
        let mut blob = issue(&user_template(key().verifying_key()), &ca).unwrap();
        let i = at.index(blob.len());
        blob[i] ^= xor;
        if let Ok(cert) = parse(&blob) {
            prop_assert_eq!(cert.encode(), blob.clone());
            prop_assert!(cert.verify(&[ca.verifying_key()]).is_err());
        }
    }

    /// Arbitrary input never panics, and whatever parses is canonical.
    #[test]
    fn prop_arbitrary_input(data in proptest::collection::vec(any::<u8>(), 0..600)) {
        if let Ok(cert) = parse(&data) {
            prop_assert_eq!(cert.encode(), data);
        }
    }
}
