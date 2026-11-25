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

/// An incremental SHA-256, for data read or written in a stream (a session
/// transcript). Cloning it gives the digest of a prefix without stopping.
#[derive(Clone)]
pub struct Hasher {
    context: aws_lc_rs::digest::Context,
    len: u64,
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    /// An empty hasher.
    pub fn new() -> Self {
        Self {
            context: aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256),
            len: 0,
        }
    }

    /// Adds `data`.
    pub fn update(&mut self, data: &[u8]) {
        self.context.update(data);
        self.len = self.len.saturating_add(data.len() as u64);
    }

    /// Bytes hashed so far.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether nothing was hashed yet.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The digest of what was hashed so far; the hasher goes on.
    pub fn digest(&self) -> [u8; 32] {
        self.clone().finish()
    }

    /// The digest of everything hashed.
    pub fn finish(self) -> [u8; 32] {
        let d = self.context.finish();
        let mut out = [0u8; 32];
        out.copy_from_slice(d.as_ref());
        out
    }
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
    fn incremental_matches_one_shot_and_prefixes() {
        let mut h = Hasher::new();
        assert!(h.is_empty());
        h.update(b"a");
        let prefix = h.digest();
        h.update(b"");
        h.update(b"bc");
        assert_eq!(h.len(), 3);
        assert_eq!(prefix, digest(b"a"));
        assert_eq!(h.digest(), digest(b"abc"));
        assert_eq!(h.finish(), digest(b"abc"));
        assert_eq!(Hasher::default().finish(), digest(b""));
    }

    #[test]
    fn concatenation_matches_one_shot() {
        assert_eq!(digest_concat(&[b"a", b"", b"bc"]), digest(b"abc"));
        assert_eq!(digest_concat(&[]), digest(b""));
    }
}
