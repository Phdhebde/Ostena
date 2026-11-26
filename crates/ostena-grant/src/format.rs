//! Binary format v2 (ADR-0004). Big-endian, fixed layout, 184 bytes:
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0 | 3 | magic `OSG` |
//! | 3 | 1 | version = 2 (version 1 is refused) |
//! | 4 | 1 | algorithm = 2 (ECDSA P-256 / SHA-256) |
//! | 5 | 1 | protocol |
//! | 6 | 2 | reserved, 0 |
//! | 8 | 8 | kid |
//! | 16 | 16 | jti |
//! | 32 | 16 | subject |
//! | 48 | 16 | resource |
//! | 64 | 16 | audience (gateway group) |
//! | 80 | 4 | rights |
//! | 84 | 4 | maximum session length (s) |
//! | 88 | 8 | issued at (Unix s) |
//! | 96 | 8 | expires at (Unix s) |
//! | 104 | 16 | binding: login session and account ([`Binding`]) |
//! | 120 | 64 | ECDSA P-256 / SHA-256 signature over `DOMAIN ‖ bytes[0..120]`, raw `r ‖ s`, low-S |
//!
//! Text form: base64url without padding, 246 characters.
//!
//! Algorithm 1 (Ed25519, the first draft) is refused like any other value.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use ostena_crypto::p256::SIGNATURE_LEN;

use crate::error::GrantError;
use crate::ids::{Binding, GatewayGroupId, Jti, Kid, ResourceId, SubjectId};

/// Length of an encoded grant.
pub const GRANT_LEN: usize = 184;
/// Length of the text form.
pub const TEXT_LEN: usize = 246;

// The text form must fit the TS_INFO_PACKET Password field: at most 512 bytes
// including the null terminator, UTF-16 when INFO_UNICODE is set
// ([MS-RDPBCGR] 2.2.1.11.1.1). 246 characters take 494 bytes: 18 to spare.
const _: () = assert!(TEXT_LEN * 2 + 2 <= 512);
// The raw P-256 signature keeps the grant at 184 bytes (246 characters).
const _: () = assert!(SIGNED_LEN + SIGNATURE_LEN == GRANT_LEN);
// base64url without padding: 4 characters per 3 bytes, 2 for the last byte.
const _: () = assert!(GRANT_LEN % 3 == 1 && GRANT_LEN / 3 * 4 + 2 == TEXT_LEN);
/// Length of the signed part (everything before the signature).
pub(crate) const SIGNED_LEN: usize = 120;
/// Domain separation prefix, signed but not transmitted.
pub(crate) const DOMAIN: &[u8; 16] = b"ostena-grant-v2\0";

const MAGIC: [u8; 3] = *b"OSG";
const VERSION: u8 = 2;
/// ECDSA P-256 / SHA-256, the only accepted value.
const ALG_ECDSA_P256_SHA256: u8 = 2;

/// Protocol a grant opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Protocol {
    /// SSH.
    Ssh = 1,
    /// RDP.
    Rdp = 2,
    /// VNC (RFB).
    Vnc = 3,
    /// Proxied web application.
    Web = 4,
}

impl Protocol {
    /// Every protocol.
    pub const ALL: [Self; 4] = [Self::Ssh, Self::Rdp, Self::Vnc, Self::Web];

    fn from_u8(v: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|p| *p as u8 == v)
    }
}

/// Rights granted for the session, as a bit set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Rights(u32);

impl Rights {
    /// Clipboard from the user to the target.
    pub const CLIPBOARD_TO_TARGET: Self = Self(1 << 0);
    /// Clipboard from the target to the user.
    pub const CLIPBOARD_FROM_TARGET: Self = Self(1 << 1);
    /// File upload to the target.
    pub const FILE_UPLOAD: Self = Self(1 << 2);
    /// File download from the target.
    pub const FILE_DOWNLOAD: Self = Self(1 << 3);
    /// RDP drive redirection.
    pub const DRIVE_REDIRECTION: Self = Self(1 << 4);
    /// RDP printer redirection.
    pub const PRINTER_REDIRECTION: Self = Self(1 << 5);
    /// RDP audio redirection.
    pub const AUDIO_REDIRECTION: Self = Self(1 << 6);
    /// SSH port forwarding.
    pub const SSH_PORT_FORWARDING: Self = Self(1 << 7);
    /// SSH agent forwarding.
    pub const SSH_AGENT_FORWARDING: Self = Self(1 << 8);
    /// SSH X11 forwarding.
    pub const SSH_X11_FORWARDING: Self = Self(1 << 9);

    /// No right.
    pub const NONE: Self = Self(0);
    const KNOWN: u32 = (1 << 10) - 1;

    /// Parses a bit set; `None` if an unknown bit is set.
    pub const fn from_bits(bits: u32) -> Option<Self> {
        if bits & !Self::KNOWN == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// The raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether every right in `other` is granted.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Union of two sets.
    #[must_use]
    pub const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// What the core authorises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Claims {
    /// User.
    pub subject: SubjectId,
    /// Target.
    pub resource: ResourceId,
    /// Gateway group allowed to open the session.
    pub audience: GatewayGroupId,
    /// Protocol.
    pub protocol: Protocol,
    /// Rights.
    pub rights: Rights,
    /// Maximum session length, in seconds (> 0).
    pub max_session_secs: u32,
    /// The login session and the target account the grant is bound to.
    pub binding: Binding,
}

/// The content of a grant (only trusted once returned by the verifier).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grant {
    /// Signing key.
    pub kid: Kid,
    /// Unique identifier.
    pub jti: Jti,
    /// Authorisation.
    pub claims: Claims,
    /// Issue time, also the start of validity (Unix seconds).
    pub issued_at: u64,
    /// Expiry time (Unix seconds, exclusive).
    pub expires_at: u64,
}

/// An encoded, signed grant, not verified.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SignedGrant([u8; GRANT_LEN]);

impl std::fmt::Debug for SignedGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SignedGrant({})", self.to_text())
    }
}

impl SignedGrant {
    /// Takes exactly [`GRANT_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// [`GrantError::Malformed`] on any other length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GrantError> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| GrantError::Malformed("longueur différente de 184 octets"))
    }

    /// Parses the text form.
    ///
    /// # Errors
    ///
    /// [`GrantError::Malformed`] unless the text is exactly 246 canonical
    /// base64url characters, without padding.
    pub fn from_text(text: &str) -> Result<Self, GrantError> {
        if text.len() != TEXT_LEN {
            return Err(GrantError::Malformed(
                "longueur différente de 246 caractères",
            ));
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|_| GrantError::Malformed("encodage base64url invalide"))?;
        Self::from_bytes(&bytes)
    }

    /// The binary form.
    pub fn as_bytes(&self) -> &[u8; GRANT_LEN] {
        &self.0
    }

    /// The text form.
    pub fn to_text(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
}

/// Header fields checked before the key lookup.
pub(crate) fn parse_header(bytes: &[u8; GRANT_LEN]) -> Result<Kid, GrantError> {
    if bytes[0..3] != MAGIC {
        return Err(GrantError::Malformed("en-tête OSG absent"));
    }
    if bytes[3] != VERSION {
        return Err(GrantError::UnsupportedVersion(bytes[3]));
    }
    if bytes[4] != ALG_ECDSA_P256_SHA256 {
        return Err(GrantError::AlgorithmNotAllowed(bytes[4]));
    }
    Ok(Kid::from_bytes(array(bytes, 8)))
}

/// The remaining fields, read only after the signature is verified.
pub(crate) fn parse_body(bytes: &[u8; GRANT_LEN]) -> Result<Grant, GrantError> {
    let kid = parse_header(bytes)?;
    let protocol =
        Protocol::from_u8(bytes[5]).ok_or(GrantError::InvalidField("protocole inconnu"))?;
    if bytes[6..8] != [0, 0] {
        return Err(GrantError::Malformed("octets réservés non nuls"));
    }
    let rights = Rights::from_bits(u32::from_be_bytes(array(bytes, 80)))
        .ok_or(GrantError::InvalidField("droit inconnu"))?;
    let max_session_secs = u32::from_be_bytes(array(bytes, 84));
    if max_session_secs == 0 {
        return Err(GrantError::InvalidField("durée de session maximale nulle"));
    }
    let issued_at = u64::from_be_bytes(array(bytes, 88));
    let expires_at = u64::from_be_bytes(array(bytes, 96));
    if expires_at <= issued_at {
        return Err(GrantError::InvalidField(
            "expiration antérieure à l'émission",
        ));
    }
    Ok(Grant {
        kid,
        jti: Jti::from_bytes(array(bytes, 16)),
        claims: Claims {
            subject: SubjectId::from_bytes(array(bytes, 32)),
            resource: ResourceId::from_bytes(array(bytes, 48)),
            audience: GatewayGroupId::from_bytes(array(bytes, 64)),
            protocol,
            rights,
            max_session_secs,
            binding: Binding::from_bytes(array(bytes, 104)),
        },
        issued_at,
        expires_at,
    })
}

/// The signed part of a grant.
pub(crate) fn encode_unsigned(grant: &Grant) -> [u8; SIGNED_LEN] {
    let mut out = [0u8; SIGNED_LEN];
    out[0..3].copy_from_slice(&MAGIC);
    out[3] = VERSION;
    out[4] = ALG_ECDSA_P256_SHA256;
    out[5] = grant.claims.protocol as u8;
    out[8..16].copy_from_slice(&grant.kid.to_bytes());
    out[16..32].copy_from_slice(&grant.jti.to_bytes());
    out[32..48].copy_from_slice(&grant.claims.subject.to_bytes());
    out[48..64].copy_from_slice(&grant.claims.resource.to_bytes());
    out[64..80].copy_from_slice(&grant.claims.audience.to_bytes());
    out[80..84].copy_from_slice(&grant.claims.rights.bits().to_be_bytes());
    out[84..88].copy_from_slice(&grant.claims.max_session_secs.to_be_bytes());
    out[88..96].copy_from_slice(&grant.issued_at.to_be_bytes());
    out[96..104].copy_from_slice(&grant.expires_at.to_be_bytes());
    out[104..120].copy_from_slice(&grant.claims.binding.to_bytes());
    out
}

/// `DOMAIN ‖ signed part`: the exact message signed.
pub(crate) fn signed_message(signed: &[u8]) -> [u8; DOMAIN.len() + SIGNED_LEN] {
    let mut out = [0u8; DOMAIN.len() + SIGNED_LEN];
    out[..DOMAIN.len()].copy_from_slice(DOMAIN);
    out[DOMAIN.len()..].copy_from_slice(&signed[..SIGNED_LEN]);
    out
}

/// Assembles a signed grant.
pub(crate) fn assemble(signed: &[u8; SIGNED_LEN], signature: &[u8; SIGNATURE_LEN]) -> SignedGrant {
    let mut out = [0u8; GRANT_LEN];
    out[..SIGNED_LEN].copy_from_slice(signed);
    out[SIGNED_LEN..].copy_from_slice(signature);
    SignedGrant(out)
}

/// `N` bytes at `offset`; the offsets are constants within `GRANT_LEN`.
fn array<const N: usize>(bytes: &[u8; GRANT_LEN], offset: usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[offset..offset + N]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths() {
        assert_eq!(SIGNED_LEN + SIGNATURE_LEN, GRANT_LEN);
        assert_eq!(TEXT_LEN * 2 + 2, 494);
        assert_eq!(URL_SAFE_NO_PAD.encode([0u8; GRANT_LEN]).len(), TEXT_LEN);
    }

    #[test]
    fn rights() {
        let r = Rights::CLIPBOARD_TO_TARGET.with(Rights::FILE_DOWNLOAD);
        assert!(r.contains(Rights::FILE_DOWNLOAD));
        assert!(!r.contains(Rights::FILE_UPLOAD));
        assert_eq!(Rights::from_bits(r.bits()), Some(r));
        assert_eq!(Rights::from_bits(1 << 9), Some(Rights::SSH_X11_FORWARDING));
        assert_eq!(Rights::from_bits(1 << 10), None);
        assert_eq!(Rights::from_bits(u32::MAX), None);
    }

    #[test]
    fn text_must_be_canonical() {
        let text = URL_SAFE_NO_PAD.encode([7u8; GRANT_LEN]);
        assert!(SignedGrant::from_text(&text).is_ok());
        assert!(SignedGrant::from_text(&format!("{text}=")).is_err());
        assert!(SignedGrant::from_text(&text[1..]).is_err());
        // Standard alphabet characters are refused.
        let std_alphabet = text.replace('_', "/").replace('-', "+");
        if std_alphabet != text {
            assert!(SignedGrant::from_text(&std_alphabet).is_err());
        }
        // 184 bytes = 61 groups of 3 and one byte: the last character
        // carries 4 unused bits, which must be zero.
        let mut last = text.clone().into_bytes();
        let end = last.len() - 1;
        // 0x07: last character 0b11_0000 (48, 'w'); 'x' sets an unused bit.
        assert_eq!(last[end], b'w');
        last[end] = b'x';
        assert!(SignedGrant::from_text(std::str::from_utf8(&last).unwrap()).is_err());
        let mut bytes = text.into_bytes();
        bytes[0] = b'*';
        assert!(SignedGrant::from_text(std::str::from_utf8(&bytes).unwrap()).is_err());
    }
}
