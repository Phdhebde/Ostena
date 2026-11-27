use proptest::prelude::*;

use super::*;

fn search() -> SearchRequest {
    SearchRequest {
        base: "dc=corp,dc=test".into(),
        scope: Scope::Subtree,
        size_limit: 10,
        time_limit: 30,
        filter: Filter::in_chain("member", "cn=alice,dc=corp,dc=test"),
        attributes: vec!["cn".into(), "objectGUID".into()],
    }
}

#[test]
fn bind_request_round_trip_and_exact_size() {
    let mut out = Vec::new();
    encode_bind(&mut out, 1, "cn=svc,dc=corp", b"secret").unwrap();
    // Sized once: the password is never moved by a reallocation.
    assert_eq!(out.len(), out.capacity());
    let back = decode_request(&out).unwrap();
    assert_eq!(back.id, 1);
    assert_eq!(
        back.op,
        Request::Bind {
            name: "cn=svc,dc=corp".into(),
            password: b"secret".to_vec(),
        }
    );
    // A long password takes the long length form.
    let long = vec![b'x'; 300];
    encode_bind(&mut out, 2, "cn=svc", &long).unwrap();
    assert_eq!(out.len(), out.capacity());
    assert!(matches!(
        decode_request(&out).unwrap().op,
        Request::Bind { password, .. } if password == long
    ));
}

#[test]
fn bind_refuses_unauthenticated() {
    let mut out = Vec::new();
    assert_eq!(
        encode_bind(&mut out, 1, "cn=svc", b""),
        Err(LdapError::EmptyCredentials)
    );
    assert_eq!(
        encode_bind(&mut out, 1, "", b"x"),
        Err(LdapError::EmptyCredentials)
    );
    assert_eq!(out, Vec::<u8>::new());
}

#[test]
fn search_round_trip_with_paging() {
    let mut out = Vec::new();
    let paged = Control::paged(500, b"cookie");
    encode_search(&mut out, 9, &search(), std::slice::from_ref(&paged));
    let back = decode_request(&out).unwrap();
    assert_eq!(back.id, 9);
    assert_eq!(back.op, Request::Search(search()));
    assert_eq!(back.controls, vec![paged.clone()]);
    assert_eq!(paged.as_paged().unwrap(), (500, b"cookie".to_vec()));
}

#[test]
fn responses_round_trip() {
    let entry = Entry {
        dn: "cn=alice,dc=corp".into(),
        attributes: vec![
            Attribute {
                name: "objectGUID".into(),
                values: vec![vec![0, 1, 2, 255]],
            },
            Attribute {
                name: "member;range=0-1".into(),
                values: vec![b"cn=a".to_vec(), b"cn=b".to_vec()],
            },
        ],
    };
    for response in [
        Response::Bind(LdapResult::success()),
        Response::Done(LdapResult::with(49, "data 52e")),
        Response::Entry(entry.clone()),
        Response::Reference(vec!["ldaps://other/dc=x".into()]),
        Response::Extended {
            result: LdapResult::with(52, ""),
            name: Some(NOTICE_OF_DISCONNECTION_OID.into()),
        },
    ] {
        let mut out = Vec::new();
        encode_response(&mut out, 3, &response, &[Control::paged(0, b"")]);
        let back = decode_response(&out).unwrap();
        assert_eq!(back.op, response);
        assert_eq!(back.id, 3);
    }
    assert_eq!(entry.values("MEMBER").count(), 2);
    assert_eq!(entry.first("member"), Some("cn=a"));
    assert!(!entry.has("mail"));
}

#[test]
fn active_directory_long_lengths() {
    // A bind response written with 4-byte lengths everywhere.
    let bytes = [
        0x30, 0x84, 0, 0, 0, 0x10, 0x02, 0x01, 0x01, 0x61, 0x84, 0, 0, 0, 0x07, 0x0a, 0x01, 0x00,
        0x04, 0x00, 0x04, 0x00,
    ];
    let back = decode_response(&bytes).unwrap();
    assert_eq!(back.op, Response::Bind(LdapResult::success()));
}

#[test]
fn diagnostics_are_cleaned() {
    let r = LdapResult::with(49, "bad\n\u{1b}[31mthing");
    assert!(!r.diagnostic.chars().any(char::is_control));
    let long = "x".repeat(1000);
    assert_eq!(LdapResult::with(1, &long).diagnostic.len(), MAX_DIAGNOSTIC);
}

#[test]
fn strict_decoding() {
    let mut out = Vec::new();
    encode_response(&mut out, 1, &Response::Bind(LdapResult::success()), &[]);
    // Trailing byte after the message.
    let mut trailing = out.clone();
    trailing.push(0);
    assert!(decode_response(&trailing).is_err());
    // A request is not a response.
    let mut req = Vec::new();
    encode_unbind(&mut req, 1);
    assert!(decode_response(&req).is_err());
    // Negative message id.
    let neg = [0x30, 0x05, 0x02, 0x01, 0xff, 0x42, 0x00];
    assert!(decode_request(&neg).is_err());
    // Bind of version 2.
    let v2 = [
        0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x02, 0x04, 0x00, 0x80, 0x00,
    ];
    assert!(decode_request(&v2).is_err());
    // A non-UTF-8 DN in an entry.
    let mut bad = Vec::new();
    encode_response(
        &mut bad,
        1,
        &Response::Entry(Entry {
            dn: "cn=é".into(),
            attributes: vec![],
        }),
        &[],
    );
    let pos = bad.iter().position(|b| *b == 0xc3).unwrap();
    bad[pos] = 0xff;
    assert!(decode_response(&bad).is_err());
}

proptest! {
    #[test]
    fn decoders_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..128)) {
        let _ = decode_response(&bytes);
        let _ = decode_request(&bytes);
    }

    #[test]
    fn entry_round_trip(
        dn in "[a-z=,]{0,20}",
        attrs in proptest::collection::vec(
            ("[a-zA-Z]{1,8}", proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..16), 0..3)),
            0..4,
        ),
    ) {
        let entry = Entry {
            dn,
            attributes: attrs.into_iter().map(|(name, values)| Attribute { name, values }).collect(),
        };
        let mut out = Vec::new();
        encode_response(&mut out, 5, &Response::Entry(entry.clone()), &[]);
        prop_assert_eq!(decode_response(&out).unwrap().op, Response::Entry(entry));
    }
}
