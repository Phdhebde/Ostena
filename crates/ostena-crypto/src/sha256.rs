//! SHA-256 digests.

/// SHA-256 digest of `data`.
pub fn digest(data: &[u8]) -> [u8; 32] {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// SHA-256 digest of the concatenation of `parts`, without copying them
/// (domain-separated hashes: a prefix, then the data).
pub fn digest_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut context = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    for part in parts {
        context.update(part);
    }
    let d = context.finish();
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answer() {
        // FIPS 180-2, appendix B.1.
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(digest(b"abc"), expected);
    }

    #[test]
    fn concatenation_matches_one_shot() {
        assert_eq!(digest_concat(&[b"a", b"", b"bc"]), digest(b"abc"));
        assert_eq!(digest_concat(&[]), digest(b""));
    }
}
