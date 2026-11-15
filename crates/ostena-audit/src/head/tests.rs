use ostena_crypto::p256::SigningKey;

use super::*;

fn key() -> SigningKey {
    SigningKey::generate().unwrap().0
}

fn trusting(key: &SigningKey) -> TrustedKeys {
    let mut keys = TrustedKeys::new();
    keys.insert(key.verifying_key()).unwrap();
    keys
}

fn unsigned() -> UnsignedHead {
    UnsignedHead {
        chain_id: ChainId::from_bytes([0x22; 16]),
        head_no: 2,
        record_seq: 9,
        record_hash: [0x33; 32],
        prev_head_hash: [0x44; 32],
        time_ms: 0x0102_0304_0506_0708,
        heartbeat_secs: 0x0a0b_0c0d,
    }
}

#[test]
fn layout_is_fixed() {
    let key = key();
    let head = unsigned().sign(&key).unwrap();
    let bytes = head.encode();
    assert_eq!(bytes.len(), 182);
    assert_eq!(bytes[0], 1);
    assert_eq!(bytes[1..17], [0x22; 16]);
    assert_eq!(bytes[17..25], 2u64.to_be_bytes());
    assert_eq!(bytes[25..33], 9u64.to_be_bytes());
    assert_eq!(bytes[33..65], [0x33; 32]);
    assert_eq!(bytes[65..97], [0x44; 32]);
    assert_eq!(bytes[97..105], [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(bytes[105..109], [0x0a, 0x0b, 0x0c, 0x0d]);
    assert_eq!(bytes[109], 2);
    assert_eq!(bytes[110..118], Kid::of(&key.verifying_key()).to_bytes());
    // The signature covers the domain prefix and the 118 first bytes.
    let mut message = b"ostena-audit-head-v1\0".to_vec();
    message.extend_from_slice(&bytes[..118]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&bytes[118..]);
    assert!(
        key.verifying_key()
            .verify(&message, &Signature::from_bytes(&signature))
            .is_ok()
    );
    // The hash covers the domain prefix, the TBS and the signature.
    let mut hashed = b"ostena-audit-head-hash-v1\0".to_vec();
    hashed.extend_from_slice(&bytes);
    assert_eq!(head.hash(), ostena_crypto::sha256::digest(&hashed));
}

#[test]
fn sign_decode_verify_round_trip() {
    let key = key();
    let head = unsigned().sign(&key).unwrap();
    let decoded = Head::decode(&head.encode()).unwrap();
    assert_eq!(decoded, head);
    assert_eq!(decoded.fields(), &unsigned());
    assert!(decoded.verify(&trusting(&key)).is_ok());
    let text = head.to_text();
    assert_eq!(text.len(), TEXT_PREFIX.len() + 364);
    assert!(text.starts_with("ostena-audit-head-v1:"));
    assert_eq!(Head::from_text(&text).unwrap(), head);
}

#[test]
fn any_changed_byte_breaks_the_signature_or_the_format() {
    let key = key();
    let keys = trusting(&key);
    let bytes = unsigned().sign(&key).unwrap().encode();
    for i in 0..HEAD_LEN {
        let mut changed = bytes;
        changed[i] ^= 0x01;
        let verdict = Head::decode(&changed).and_then(|h| h.verify(&keys));
        assert!(verdict.is_err(), "byte {i}");
    }
}

#[test]
fn unknown_kid_and_bad_signature_are_distinct() {
    let key = key();
    let head = unsigned().sign(&key).unwrap();
    let other = trusting(&self::key());
    assert_eq!(
        head.verify(&other),
        Err(AuditError::UnknownKid {
            head_no: 2,
            kid: Kid::of(&key.verifying_key())
        })
    );
    let mut bytes = head.encode();
    bytes[HEAD_LEN - 1] ^= 0x01;
    assert_eq!(
        Head::decode(&bytes).unwrap().verify(&trusting(&key)),
        Err(AuditError::BadSignature { head_no: 2 })
    );
}

#[test]
fn refuses_other_versions_algorithms_and_lengths() {
    let bytes = unsigned().sign(&key()).unwrap().encode();
    let mut v2 = bytes;
    v2[0] = 2;
    assert_eq!(Head::decode(&v2).unwrap_err().code(), "AUD-E002");
    for alg in [0u8, 1, 3, 0xff] {
        let mut other = bytes;
        other[109] = alg;
        assert_eq!(Head::decode(&other).unwrap_err().code(), "AUD-E002");
    }
    assert_eq!(Head::decode(&bytes[..181]).unwrap_err().code(), "AUD-E003");
    let mut longer = bytes.to_vec();
    longer.push(0);
    assert_eq!(Head::decode(&longer).unwrap_err().code(), "AUD-E003");
    assert_eq!(Head::decode(&[]).unwrap_err().code(), "AUD-E003");
}

#[test]
fn refuses_inconsistent_fields() {
    let key = key();
    let cases = [
        UnsignedHead {
            head_no: 0,
            ..unsigned()
        },
        UnsignedHead {
            head_no: 1,
            ..unsigned()
        },
        UnsignedHead {
            prev_head_hash: ZERO_DIGEST,
            ..unsigned()
        },
        UnsignedHead {
            record_seq: 0,
            ..unsigned()
        },
        UnsignedHead {
            heartbeat_secs: 0,
            ..unsigned()
        },
    ];
    for case in cases {
        assert_eq!(case.sign(&key).unwrap_err().code(), "AUD-E003", "{case:?}");
        // The same fields, encoded by hand, are refused by the decoder.
        let mut bytes = unsigned().sign(&key).unwrap().encode();
        bytes[..HEAD_TBS_LEN].copy_from_slice(&case.tbs(Kid::of(&key.verifying_key())));
        assert_eq!(Head::decode(&bytes).unwrap_err().code(), "AUD-E003");
    }
    let first = UnsignedHead {
        head_no: 1,
        prev_head_hash: ZERO_DIGEST,
        ..unsigned()
    };
    assert!(first.sign(&key).is_ok());
}

#[test]
fn text_form_is_strict() {
    let text = unsigned().sign(&key()).unwrap().to_text();
    let digits = &text[TEXT_PREFIX.len()..];
    for bad in [
        digits.to_owned(),
        format!("OSTENA-AUDIT-HEAD-V1:{digits}"),
        format!("{TEXT_PREFIX}{}", digits.to_uppercase()),
        format!("{TEXT_PREFIX}{}", &digits[2..]),
        format!("{text}00"),
        format!("{text}\n"),
        format!(" {text}"),
    ] {
        assert_eq!(
            Head::from_text(&bad).unwrap_err().code(),
            "AUD-E003",
            "{bad}"
        );
    }
}

#[test]
fn after_links_to_the_previous_head() {
    let key = key();
    let chain = ChainId::from_bytes([1; 16]);
    let first = UnsignedHead::after(None, chain, 1, [7; 32], 10, 60);
    assert_eq!((first.head_no, first.prev_head_hash), (1, ZERO_DIGEST));
    let first = first.sign(&key).unwrap();
    let second = UnsignedHead::after(Some(&first), chain, 2, [8; 32], 20, 60);
    assert_eq!((second.head_no, second.prev_head_hash), (2, first.hash()));
}

#[test]
fn trusted_keys_are_bounded_and_deduplicated() {
    let mut keys = TrustedKeys::new();
    assert!(keys.is_empty());
    let first = key().verifying_key();
    keys.insert(first).unwrap();
    keys.insert(first).unwrap();
    assert_eq!(keys.len(), 1);
    for _ in 1..MAX_TRUSTED_KEYS {
        keys.insert(key().verifying_key()).unwrap();
    }
    assert_eq!(keys.len(), MAX_TRUSTED_KEYS);
    assert_eq!(
        keys.insert(key().verifying_key()),
        Err(AuditError::TooManyKeys)
    );
    keys.insert(first).unwrap();
    assert_eq!(keys.get(Kid::of(&first)), Some(&first));
}
