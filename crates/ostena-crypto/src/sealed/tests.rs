use super::*;

fn secret(text: &str) -> SecretBytes {
    SecretBytes::from(text.as_bytes().to_vec())
}

fn reparse(share: &Share) -> Share {
    Share::parse(&secret(&share.to_text())).unwrap()
}

fn plain(bytes: &SecretBytes) -> Vec<u8> {
    // SECRET-EXPOSURE: test assertion on a throwaway value.
    #[expect(clippy::disallowed_methods)]
    let v = bytes.expose_secret().to_vec();
    v
}

#[test]
fn any_two_shares_open_the_seal() {
    let (root, shares) = RootSecret::generate().unwrap();
    let sealed = seal(&secret("pkcs8 bytes"), &root).unwrap();
    for (a, b) in [(0, 1), (0, 2), (1, 2), (1, 0), (2, 0)] {
        let rebuilt = RootSecret::combine(&[reparse(&shares[a]), reparse(&shares[b])]).unwrap();
        assert_eq!(plain(&open(&sealed, &rebuilt).unwrap()), b"pkcs8 bytes");
    }
    // All three work too.
    let all: Vec<Share> = shares.iter().map(reparse).collect();
    assert!(open(&sealed, &RootSecret::combine(&all).unwrap()).is_ok());
}

#[test]
fn one_share_alone_is_refused() {
    let (_, shares) = RootSecret::generate().unwrap();
    for share in &shares {
        assert_eq!(
            RootSecret::combine(&[reparse(share)]).err(),
            Some(SealError::NotEnoughShares)
        );
    }
    assert_eq!(
        RootSecret::combine(&[]).err(),
        Some(SealError::NotEnoughShares)
    );
}

#[test]
fn the_same_share_twice_is_refused() {
    let (_, shares) = RootSecret::generate().unwrap();
    assert_eq!(
        RootSecret::combine(&[reparse(&shares[0]), reparse(&shares[0])]).err(),
        Some(SealError::NotEnoughShares)
    );
}

#[test]
fn shares_of_another_root_do_not_open() {
    let (root, shares) = RootSecret::generate().unwrap();
    let (_, others) = RootSecret::generate().unwrap();
    let sealed = seal(&secret("key"), &root).unwrap();
    let mixed = RootSecret::combine(&[reparse(&shares[0]), reparse(&others[1])]).unwrap();
    assert_eq!(open(&sealed, &mixed).err(), Some(SealError::Open));
}

#[test]
fn shares_are_37_base32_characters_with_ids_1_to_3() {
    let (_, shares) = RootSecret::generate().unwrap();
    let ids: Vec<u8> = shares.iter().map(Share::id).collect();
    assert_eq!(ids, vec![1, 2, 3]);
    for share in &shares {
        let text = share.to_text();
        let chars: String = text.chars().filter(|c| *c != '-').collect();
        assert_eq!(chars.len(), SHARE_CHARS);
        assert!(chars.bytes().all(|c| ALPHABET.contains(&c)));
        // Typed back in lower case, with spaces: accepted.
        let typed = text.to_lowercase().replace('-', " ");
        assert_eq!(Share::parse(&secret(&typed)).unwrap().id(), share.id());
    }
}

#[test]
fn transcription_mistakes_are_caught() {
    let (_, shares) = RootSecret::generate().unwrap();
    let text: Vec<u8> = shares[0].to_text().into_bytes();
    // Every single-character substitution is caught by the checksum (or the
    // alphabet), whatever the position.
    for i in (0..text.len()).filter(|&i| text[i] != b'-') {
        let mut bad = text.clone();
        bad[i] = if bad[i] == b'Z' { b'Y' } else { b'Z' };
        assert_eq!(
            Share::parse(&SecretBytes::from(bad)).err(),
            Some(SealError::Share),
            "position {i}"
        );
    }
    for bad in ["", "ABC", &"U".repeat(37), &"A".repeat(38)] {
        assert_eq!(Share::parse(&secret(bad)).err(), Some(SealError::Share));
    }
}

#[test]
fn tampering_is_refused() {
    let (root, _) = RootSecret::generate().unwrap();
    let sealed = seal(&secret("key"), &root).unwrap();
    for i in [0, 9, 20, 35, sealed.len() - 1] {
        let mut bad = sealed.clone();
        bad[i] ^= 1;
        assert!(open(&bad, &root).is_err(), "byte {i}");
    }
    assert_eq!(open(&sealed[..30], &root).err(), Some(SealError::Format));
    let mut weak = sealed.clone();
    weak[8..12].copy_from_slice(&1000u32.to_be_bytes());
    assert_eq!(open(&weak, &root).err(), Some(SealError::Format));
    let mut v1 = sealed.clone();
    v1[..8].copy_from_slice(b"OSTSEAL1");
    assert_eq!(open(&v1, &root).err(), Some(SealError::Format));
}

#[test]
fn crc_matches_the_ccitt_reference() {
    // CRC-16/CCITT-FALSE check value.
    assert_eq!(crc16(b"123456789".iter()), 0x29b1);
}
