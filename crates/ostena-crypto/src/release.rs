//! Signed release manifests (ADR-0017): the SHA-256 of each deliverable
//! (binaries, SBOMs) in a strict text manifest, signed with ECDSA P-256 /
//! SHA-256. The manifest and its signature are verified offline, with the
//! public key only.
//!
//! Manifest, one line per file, sorted by name, each line ending in `\n`:
//!
//! ```text
//! ostena-release-manifest-v1
//! <SHA-256, 64 lowercase hex>  <name>
//! ```
//!
//! The lines after the header are those of `sha256sum`. Signature file, one
//! line: `ostena-release-signature-v1:<kid, 16 hex>:<signature, base64url>`.
//! The signed message is [`DOMAIN`] followed by the manifest bytes.
//!
//! The decoders accept only the canonical encoding: `encode(decode(b)) == b`.

use std::io::{self, Read};

use base64::Engine;

use crate::CryptoError;
use crate::p256::{self, Signature, SigningKey, VerifyingKey};

/// First line of a manifest.
pub const MANIFEST_HEADER: &str = "ostena-release-manifest-v1";
/// Prefix of a signature line.
pub const SIGNATURE_PREFIX: &str = "ostena-release-signature-v1:";
/// Domain separation of the signed message.
pub const DOMAIN: &[u8] = b"ostena/release-manifest/v1\0";
/// Most files in one manifest.
pub const MAX_ENTRIES: usize = 256;
/// Longest file name, in bytes.
pub const MAX_NAME_LEN: usize = 128;
/// Largest manifest, in bytes: header and [`MAX_ENTRIES`] longest lines.
pub const MAX_MANIFEST_LEN: usize =
    MANIFEST_HEADER.len() + 1 + MAX_ENTRIES * (64 + 2 + MAX_NAME_LEN + 1);
/// Largest signature file, in bytes.
pub const MAX_SIGNATURE_LEN: usize = SIGNATURE_PREFIX.len() + 16 + 1 + 86 + 1;
/// Most trusted keys given to [`verify`].
pub const MAX_TRUSTED_KEYS: usize = 16;

/// Why a manifest or a signature is refused. Codes are stable: never
/// renumber or reuse one (ADR-0017).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReleaseError {
    /// The manifest is not in the canonical v1 encoding.
    #[error("[REL-E001] manifeste mal formé : {0}")]
    MalformedManifest(&'static str),
    /// The signature file is not in the canonical v1 encoding.
    #[error("[REL-E002] signature mal formée : {0}")]
    MalformedSignature(&'static str),
    /// The manifest is signed by a key that is not trusted.
    #[error("[REL-E003] manifeste signé par une clé inconnue : kid {0}")]
    UnknownKey(String),
    /// The signature does not verify.
    #[error("[REL-E004] signature du manifeste invalide")]
    BadSignature,
    /// The signing key cannot sign.
    #[error("[REL-E007] échec de la signature : {0}")]
    Signing(CryptoError),
    /// No trusted key, or more than [`MAX_TRUSTED_KEYS`].
    #[error("[REL-E009] une à {MAX_TRUSTED_KEYS} clés de confiance attendues")]
    TrustedKeys,
}

impl ReleaseError {
    /// The stable code, e.g. `REL-E001`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MalformedManifest(_) => "REL-E001",
            Self::MalformedSignature(_) => "REL-E002",
            Self::UnknownKey(_) => "REL-E003",
            Self::BadSignature => "REL-E004",
            Self::Signing(_) => "REL-E007",
            Self::TrustedKeys => "REL-E009",
        }
    }
}

/// One deliverable: its name and its SHA-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    name: String,
    digest: [u8; 32],
}

impl Entry {
    /// An entry, if `name` is acceptable ([`check_name`]).
    ///
    /// # Errors
    ///
    /// [`ReleaseError::MalformedManifest`] for an unacceptable name.
    pub fn new(name: &str, digest: [u8; 32]) -> Result<Self, ReleaseError> {
        check_name(name)?;
        Ok(Self {
            name: name.to_owned(),
            digest,
        })
    }

    /// The file name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The SHA-256 of the file.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// Checks a file name: 1 to [`MAX_NAME_LEN`] bytes of `A-Z a-z 0-9 . _ + -`,
/// starting with a letter or a digit. No directory, no hidden file, nothing
/// a terminal or a shell would interpret.
///
/// # Errors
///
/// [`ReleaseError::MalformedManifest`] otherwise.
pub fn check_name(name: &str) -> Result<(), ReleaseError> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_NAME_LEN {
        return Err(ReleaseError::MalformedManifest("longueur du nom"));
    }
    if !bytes[0].is_ascii_alphanumeric() {
        return Err(ReleaseError::MalformedManifest(
            "le nom doit commencer par une lettre ou un chiffre",
        ));
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
    {
        return Err(ReleaseError::MalformedManifest(
            "caractère interdit dans le nom",
        ));
    }
    Ok(())
}

/// A release manifest: 1 to [`MAX_ENTRIES`] entries, sorted by name, names
/// unique.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    entries: Vec<Entry>,
}

impl Manifest {
    /// Sorts the entries by name.
    ///
    /// # Errors
    ///
    /// [`ReleaseError::MalformedManifest`] for no entry, too many, or a name
    /// given twice.
    pub fn new(mut entries: Vec<Entry>) -> Result<Self, ReleaseError> {
        if entries.is_empty() || entries.len() > MAX_ENTRIES {
            return Err(ReleaseError::MalformedManifest("nombre de fichiers"));
        }
        entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        if entries.windows(2).any(|w| w[0].name == w[1].name) {
            return Err(ReleaseError::MalformedManifest("nom en double"));
        }
        Ok(Self { entries })
    }

    /// The entries, sorted by name.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The canonical text.
    pub fn encode(&self) -> String {
        let mut out = String::with_capacity(
            MANIFEST_HEADER.len() + 1 + self.entries.len() * (64 + 2 + 32 + 1),
        );
        out.push_str(MANIFEST_HEADER);
        out.push('\n');
        for entry in &self.entries {
            push_hex(&mut out, &entry.digest);
            out.push_str("  ");
            out.push_str(&entry.name);
            out.push('\n');
        }
        out
    }

    /// Reads a manifest in its canonical encoding only.
    ///
    /// # Errors
    ///
    /// [`ReleaseError::MalformedManifest`] for anything else.
    pub fn decode(bytes: &[u8]) -> Result<Self, ReleaseError> {
        if bytes.len() > MAX_MANIFEST_LEN {
            return Err(ReleaseError::MalformedManifest("trop long"));
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| ReleaseError::MalformedManifest("UTF-8 invalide"))?;
        let body = text
            .strip_suffix('\n')
            .ok_or(ReleaseError::MalformedManifest(
                "fin de ligne finale absente",
            ))?;
        let mut lines = body.split('\n');
        if lines.next() != Some(MANIFEST_HEADER) {
            return Err(ReleaseError::MalformedManifest("en-tête attendu"));
        }
        let mut entries: Vec<Entry> = Vec::new();
        for line in lines {
            if entries.len() == MAX_ENTRIES {
                return Err(ReleaseError::MalformedManifest("nombre de fichiers"));
            }
            let (hex, name) = line
                .split_at_checked(64)
                .ok_or(ReleaseError::MalformedManifest("ligne trop courte"))?;
            let name = name
                .strip_prefix("  ")
                .ok_or(ReleaseError::MalformedManifest("séparateur attendu"))?;
            let digest =
                parse_hex(hex).ok_or(ReleaseError::MalformedManifest("empreinte invalide"))?;
            let entry = Entry::new(name, digest)?;
            if let Some(previous) = entries.last()
                && previous.name >= entry.name
            {
                return Err(ReleaseError::MalformedManifest(
                    "noms non triés ou en double",
                ));
            }
            entries.push(entry);
        }
        if entries.is_empty() {
            return Err(ReleaseError::MalformedManifest("nombre de fichiers"));
        }
        Ok(Self { entries })
    }
}

/// The identifier of a public key: the first 8 bytes of the SHA-256 of its
/// uncompressed SEC1 encoding, as for the grants and the audit heads.
pub fn kid(key: &VerifyingKey) -> [u8; 8] {
    let digest = crate::sha256::digest(&key.to_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

/// The signature of a manifest, with the kid of its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseSignature {
    kid: [u8; 8],
    signature: Signature,
}

impl ReleaseSignature {
    /// The kid of the signing key.
    pub fn kid(&self) -> [u8; 8] {
        self.kid
    }

    /// The canonical signature line, ending in `\n`.
    pub fn to_text(&self) -> String {
        let mut out = String::with_capacity(MAX_SIGNATURE_LEN);
        out.push_str(SIGNATURE_PREFIX);
        push_hex(&mut out, &self.kid);
        out.push(':');
        out.push_str(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.signature.to_bytes()),
        );
        out.push('\n');
        out
    }

    /// Reads a signature line in its canonical encoding only.
    ///
    /// # Errors
    ///
    /// [`ReleaseError::MalformedSignature`] for anything else.
    pub fn from_text(text: &str) -> Result<Self, ReleaseError> {
        let malformed = ReleaseError::MalformedSignature;
        if text.len() > MAX_SIGNATURE_LEN {
            return Err(malformed("trop longue"));
        }
        let line = text
            .strip_suffix('\n')
            .and_then(|l| l.strip_prefix(SIGNATURE_PREFIX))
            .ok_or(malformed("en-tête ou fin de ligne absent"))?;
        let (kid, signature) = line.split_once(':').ok_or(malformed("séparateur absent"))?;
        let kid: [u8; 8] = parse_hex(kid).ok_or(malformed("kid invalide"))?;
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| malformed("base64url invalide"))?;
        let bytes: [u8; p256::SIGNATURE_LEN] = raw
            .try_into()
            .map_err(|_| malformed("taille de signature"))?;
        let parsed = Self {
            kid,
            signature: Signature::from_bytes(&bytes),
        };
        // base64url without padding may carry non-zero trailing bits: only
        // the canonical text is accepted.
        if parsed.to_text() != text {
            return Err(malformed("encodage non canonique"));
        }
        Ok(parsed)
    }
}

/// Signs the canonical text of `manifest`.
///
/// # Errors
///
/// [`ReleaseError::Signing`] if the library fails.
pub fn sign(manifest: &Manifest, key: &SigningKey) -> Result<ReleaseSignature, ReleaseError> {
    let message = [DOMAIN, manifest.encode().as_bytes()].concat();
    let signature = key.sign(&message).map_err(ReleaseError::Signing)?;
    Ok(ReleaseSignature {
        kid: kid(&key.verifying_key()),
        signature,
    })
}

/// Verifies the signature of the manifest bytes with one of the trusted
/// keys (selected by kid), then decodes the manifest. The signature is
/// checked before the manifest is parsed.
///
/// # Errors
///
/// [`ReleaseError::TrustedKeys`], [`ReleaseError::MalformedSignature`],
/// [`ReleaseError::UnknownKey`], [`ReleaseError::BadSignature`] or
/// [`ReleaseError::MalformedManifest`].
pub fn verify(
    manifest: &[u8],
    signature: &str,
    trusted: &[VerifyingKey],
) -> Result<Manifest, ReleaseError> {
    if trusted.is_empty() || trusted.len() > MAX_TRUSTED_KEYS {
        return Err(ReleaseError::TrustedKeys);
    }
    let signature = ReleaseSignature::from_text(signature)?;
    if manifest.len() > MAX_MANIFEST_LEN {
        return Err(ReleaseError::MalformedManifest("trop long"));
    }
    let key = trusted
        .iter()
        .find(|k| kid(k) == signature.kid)
        .ok_or_else(|| ReleaseError::UnknownKey(hex(&signature.kid)))?;
    let message = [DOMAIN, manifest].concat();
    key.verify(&message, &signature.signature)
        .map_err(|_| ReleaseError::BadSignature)?;
    Manifest::decode(manifest)
}

/// SHA-256 of everything `reader` yields, read by blocks.
///
/// # Errors
///
/// The read error.
pub fn digest_reader(mut reader: impl Read) -> io::Result<[u8; 32]> {
    let mut context = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => context.update(&buffer[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(context.finish().as_ref());
    Ok(out)
}

/// Lowercase hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    push_hex(&mut out, bytes);
    out
}

fn push_hex(out: &mut String, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
}

/// Lowercase hexadecimal of exactly `N` bytes.
fn parse_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let bytes = text.as_bytes();
    if bytes.len() != 2 * N {
        return None;
    }
    let mut out = [0u8; N];
    for (o, [high, low]) in out.iter_mut().zip(bytes.as_chunks::<2>().0) {
        *o = (digit(*high)? << 4) | digit(*low)?;
    }
    Some(out)
}

/// Entry point of the cargo-fuzz target `release_manifest` and of the
/// stable test that replays its corpus. Not part of the API.
#[doc(hidden)]
pub mod fuzz {
    use super::{Manifest, ReleaseSignature, verify};
    use crate::p256::VerifyingKey;

    /// RFC 6979 appendix A.2.5 P-256 public key (uncompressed SEC1), as in
    /// the other harnesses.
    pub const FUZZ_KEY: [u8; 65] = [
        0x04, 0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35,
        0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60,
        0xf2, 0x9f, 0xb6, 0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9,
        0x56, 0x28, 0xbc, 0x64, 0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2,
        0x94, 0xd4, 0x46, 0x22, 0x99,
    ];

    /// Runs the decoders on untrusted input. Must never panic; checks that
    /// only canonical encodings are accepted. The input is a manifest, or
    /// a signature line, a NUL byte and a manifest.
    pub fn decode(data: &[u8]) {
        if let Ok(manifest) = Manifest::decode(data) {
            assert_eq!(manifest.encode().as_bytes(), data, "canonical manifest");
        }
        if let Ok(text) = std::str::from_utf8(data)
            && let Ok(signature) = ReleaseSignature::from_text(text)
        {
            assert_eq!(signature.to_text(), text, "canonical signature");
        }
        if let Some(split) = data.iter().position(|b| *b == 0)
            && let Ok(signature) = std::str::from_utf8(&data[..split])
            && let Ok(key) = VerifyingKey::from_bytes(&FUZZ_KEY)
            && let Ok(manifest) = verify(&data[split + 1..], signature, &[key])
        {
            assert_eq!(manifest.encode().as_bytes(), &data[split + 1..]);
        }
    }
}

#[cfg(test)]
mod tests;
