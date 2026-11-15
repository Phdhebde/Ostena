//! Head v1: the signed tip of an audit chain (ADR-0012).
//!
//! Fixed 182 bytes, big-endian. The part to be signed (TBS, 118 bytes):
//!
//! | Offset | Size | Field | Rule |
//! |---|---|---|---|
//! | 0 | 1 | version | 1 |
//! | 1 | 16 | chain id | |
//! | 17 | 8 | head number | from 1, no gap |
//! | 25 | 8 | record seq | last record covered, at least 1 |
//! | 33 | 32 | record hash | hash of that record |
//! | 65 | 32 | previous head hash | zeros if and only if head number = 1 |
//! | 97 | 8 | time (Unix ms) | |
//! | 105 | 4 | heartbeat (s) | at least 1: a new head comes at least that often |
//! | 109 | 1 | algorithm | 2 (ECDSA P-256 / SHA-256), as for grants |
//! | 110 | 8 | kid | |
//!
//! then the 64-byte low-S signature `r ‖ s` over
//! `"ostena-audit-head-v1" ‖ 0x00 ‖ TBS`. The head hash, which the next head
//! carries, is SHA-256(`"ostena-audit-head-hash-v1" ‖ 0x00 ‖ TBS ‖ signature`).

use ostena_crypto::p256::{SIGNATURE_LEN, Signature, SigningKey, VerifyingKey};

use crate::AuditError;
use crate::ids::{ChainId, Kid, from_hex, to_hex};
use crate::record::{Digest, ZERO_DIGEST};

/// Head format version.
pub const HEAD_VERSION: u8 = 1;
/// The only signature algorithm: ECDSA P-256 / SHA-256.
pub const ALG_ECDSA_P256_SHA256: u8 = 2;
/// Length of the signed part.
pub const HEAD_TBS_LEN: usize = 118;
/// Length of an encoded head.
pub const HEAD_LEN: usize = HEAD_TBS_LEN + SIGNATURE_LEN;
/// Prefix of the text form, followed by the lowercase hexadecimal encoding.
pub const TEXT_PREFIX: &str = "ostena-audit-head-v1:";
/// Largest number of trusted keys.
pub const MAX_TRUSTED_KEYS: usize = 16;

const SIGN_DOMAIN: &[u8] = b"ostena-audit-head-v1\0";
const HASH_DOMAIN: &[u8] = b"ostena-audit-head-hash-v1\0";

const _: () = assert!(HEAD_LEN == 182);
const _: () = assert!(1 + 16 + 8 + 8 + 32 + 32 + 8 + 4 + 1 + 8 == HEAD_TBS_LEN);

/// The content of a head, before signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnsignedHead {
    /// The chain.
    pub chain_id: ChainId,
    /// Head number, from 1.
    pub head_no: u64,
    /// Seq of the last record covered.
    pub record_seq: u64,
    /// Hash of that record.
    pub record_hash: Digest,
    /// Hash of the previous head ([`ZERO_DIGEST`] for head 1).
    pub prev_head_hash: Digest,
    /// Signing time, Unix milliseconds.
    pub time_ms: u64,
    /// Longest interval between two heads announced by the signer, seconds.
    pub heartbeat_secs: u32,
}

impl UnsignedHead {
    /// The head that follows `previous` (head 1 if `None`), covering the
    /// record `record_seq` whose hash is `record_hash`.
    pub fn after(
        previous: Option<&Head>,
        chain_id: ChainId,
        record_seq: u64,
        record_hash: Digest,
        time_ms: u64,
        heartbeat_secs: u32,
    ) -> Self {
        let (head_no, prev_head_hash) = previous.map_or((1, ZERO_DIGEST), |p| {
            (p.fields.head_no.saturating_add(1), p.hash())
        });
        Self {
            chain_id,
            head_no,
            record_seq,
            record_hash,
            prev_head_hash,
            time_ms,
            heartbeat_secs,
        }
    }

    fn check(&self) -> Result<(), AuditError> {
        if self.head_no == 0 {
            return Err(AuditError::MalformedHead("numéro de tête nul"));
        }
        if (self.head_no == 1) != (self.prev_head_hash == ZERO_DIGEST) {
            return Err(AuditError::MalformedHead(
                "hash de la tête précédente nul si et seulement si le numéro vaut 1",
            ));
        }
        if self.record_seq == 0 {
            return Err(AuditError::MalformedHead("numéro d'enregistrement nul"));
        }
        if self.heartbeat_secs == 0 {
            return Err(AuditError::MalformedHead("battement nul"));
        }
        Ok(())
    }

    fn tbs(&self, kid: Kid) -> [u8; HEAD_TBS_LEN] {
        let mut out = [0u8; HEAD_TBS_LEN];
        out[0] = HEAD_VERSION;
        out[1..17].copy_from_slice(&self.chain_id.to_bytes());
        out[17..25].copy_from_slice(&self.head_no.to_be_bytes());
        out[25..33].copy_from_slice(&self.record_seq.to_be_bytes());
        out[33..65].copy_from_slice(&self.record_hash);
        out[65..97].copy_from_slice(&self.prev_head_hash);
        out[97..105].copy_from_slice(&self.time_ms.to_be_bytes());
        out[105..109].copy_from_slice(&self.heartbeat_secs.to_be_bytes());
        out[109] = ALG_ECDSA_P256_SHA256;
        out[110..118].copy_from_slice(&kid.to_bytes());
        out
    }

    /// Signs the head.
    ///
    /// # Errors
    ///
    /// [`AuditError::MalformedHead`] if a field breaks a rule of the format,
    /// [`AuditError::Crypto`] if signing fails.
    pub fn sign(&self, key: &SigningKey) -> Result<Head, AuditError> {
        self.check()?;
        let kid = Kid::of(&key.verifying_key());
        let tbs = self.tbs(kid);
        let signature = key
            .sign(&signed_message(&tbs))
            .map_err(AuditError::Crypto)?
            .to_bytes();
        Ok(Head {
            fields: *self,
            kid,
            signature,
        })
    }
}

fn signed_message(tbs: &[u8; HEAD_TBS_LEN]) -> [u8; SIGN_DOMAIN.len() + HEAD_TBS_LEN] {
    let mut message = [0u8; SIGN_DOMAIN.len() + HEAD_TBS_LEN];
    message[..SIGN_DOMAIN.len()].copy_from_slice(SIGN_DOMAIN);
    message[SIGN_DOMAIN.len()..].copy_from_slice(tbs);
    message
}

/// A signed head. Decoding checks the format only: [`Head::verify`] checks
/// the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Head {
    fields: UnsignedHead,
    kid: Kid,
    signature: [u8; SIGNATURE_LEN],
}

impl Head {
    /// The signed content.
    pub fn fields(&self) -> &UnsignedHead {
        &self.fields
    }

    /// The chain.
    pub fn chain_id(&self) -> ChainId {
        self.fields.chain_id
    }

    /// Head number.
    pub fn head_no(&self) -> u64 {
        self.fields.head_no
    }

    /// Seq of the last record covered.
    pub fn record_seq(&self) -> u64 {
        self.fields.record_seq
    }

    /// Hash of the last record covered.
    pub fn record_hash(&self) -> Digest {
        self.fields.record_hash
    }

    /// Hash of the previous head.
    pub fn prev_head_hash(&self) -> Digest {
        self.fields.prev_head_hash
    }

    /// Signing time, Unix milliseconds.
    pub fn time_ms(&self) -> u64 {
        self.fields.time_ms
    }

    /// Announced heartbeat, seconds.
    pub fn heartbeat_secs(&self) -> u32 {
        self.fields.heartbeat_secs
    }

    /// Identifier of the signing key.
    pub fn kid(&self) -> Kid {
        self.kid
    }

    /// The 182-byte encoding.
    pub fn encode(&self) -> [u8; HEAD_LEN] {
        let mut out = [0u8; HEAD_LEN];
        out[..HEAD_TBS_LEN].copy_from_slice(&self.fields.tbs(self.kid));
        out[HEAD_TBS_LEN..].copy_from_slice(&self.signature);
        out
    }

    /// Decodes a head (format only, see [`Head::verify`]).
    ///
    /// # Errors
    ///
    /// [`AuditError::MalformedHead`] for a wrong length or field,
    /// [`AuditError::Unsupported`] for another version or algorithm.
    pub fn decode(data: &[u8]) -> Result<Self, AuditError> {
        let data: &[u8; HEAD_LEN] = data
            .try_into()
            .map_err(|_| AuditError::MalformedHead("longueur différente de 182 octets"))?;
        if data[0] != HEAD_VERSION {
            return Err(AuditError::Unsupported {
                what: "version de tête",
                value: data[0],
            });
        }
        if data[109] != ALG_ECDSA_P256_SHA256 {
            return Err(AuditError::Unsupported {
                what: "algorithme de signature de tête (seul ECDSA P-256 / SHA-256, valeur 2, est accepté)",
                value: data[109],
            });
        }
        let array = |range: std::ops::Range<usize>| -> [u8; 32] {
            let mut out = [0u8; 32];
            out.copy_from_slice(&data[range]);
            out
        };
        let u64_at = |at: usize| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&data[at..at + 8]);
            u64::from_be_bytes(b)
        };
        let mut chain_id = [0u8; 16];
        chain_id.copy_from_slice(&data[1..17]);
        let mut heartbeat = [0u8; 4];
        heartbeat.copy_from_slice(&data[105..109]);
        let mut kid = [0u8; 8];
        kid.copy_from_slice(&data[110..118]);
        let mut signature = [0u8; SIGNATURE_LEN];
        signature.copy_from_slice(&data[HEAD_TBS_LEN..]);
        let fields = UnsignedHead {
            chain_id: ChainId::from_bytes(chain_id),
            head_no: u64_at(17),
            record_seq: u64_at(25),
            record_hash: array(33..65),
            prev_head_hash: array(65..97),
            time_ms: u64_at(97),
            heartbeat_secs: u32::from_be_bytes(heartbeat),
        };
        fields.check()?;
        Ok(Self {
            fields,
            kid: Kid::from_bytes(kid),
            signature,
        })
    }

    /// Hash of the head, carried by the next one; also what a future RFC 3161
    /// timestamp would cover.
    pub fn hash(&self) -> Digest {
        let tbs = self.fields.tbs(self.kid);
        ostena_crypto::sha256::digest_concat(&[HASH_DOMAIN, &tbs, &self.signature])
    }

    /// Checks the signature with the trusted key of its kid.
    ///
    /// # Errors
    ///
    /// [`AuditError::UnknownKid`] if no trusted key has this kid,
    /// [`AuditError::BadSignature`] if the signature does not verify.
    pub fn verify(&self, keys: &TrustedKeys) -> Result<(), AuditError> {
        let key = keys.get(self.kid).ok_or(AuditError::UnknownKid {
            head_no: self.fields.head_no,
            kid: self.kid,
        })?;
        let tbs = self.fields.tbs(self.kid);
        key.verify(
            &signed_message(&tbs),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| AuditError::BadSignature {
            head_no: self.fields.head_no,
        })
    }

    /// Text form: `ostena-audit-head-v1:` then 364 lowercase hexadecimal
    /// digits. Short enough to note down or to send to a second system.
    pub fn to_text(&self) -> String {
        format!("{TEXT_PREFIX}{}", to_hex(&self.encode()))
    }

    /// Parses the text form, strictly (prefix, lowercase digits, length).
    ///
    /// # Errors
    ///
    /// [`AuditError::MalformedHead`] for another text, or the errors of
    /// [`Head::decode`].
    pub fn from_text(text: &str) -> Result<Self, AuditError> {
        let digits = text
            .strip_prefix(TEXT_PREFIX)
            .ok_or(AuditError::MalformedHead(
                "préfixe ostena-audit-head-v1: absent",
            ))?;
        let mut raw = [0u8; HEAD_LEN];
        if !from_hex(digits, &mut raw) {
            return Err(AuditError::MalformedHead(
                "forme texte : 364 chiffres hexadécimaux minuscules attendus",
            ));
        }
        Self::decode(&raw)
    }
}

/// Public keys trusted to sign heads, by kid (at most [`MAX_TRUSTED_KEYS`]:
/// the current key and the previous ones of the chain).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedKeys {
    keys: Vec<(Kid, VerifyingKey)>,
}

impl TrustedKeys {
    /// No key.
    pub fn new() -> Self {
        Self::default()
    }

    /// Trusts `key`; inserting it again changes nothing.
    ///
    /// # Errors
    ///
    /// [`AuditError::TooManyKeys`] beyond [`MAX_TRUSTED_KEYS`].
    pub fn insert(&mut self, key: VerifyingKey) -> Result<(), AuditError> {
        let kid = Kid::of(&key);
        if self.get(kid).is_some() {
            return Ok(());
        }
        if self.keys.len() >= MAX_TRUSTED_KEYS {
            return Err(AuditError::TooManyKeys);
        }
        self.keys.push((kid, key));
        Ok(())
    }

    /// The key of `kid`.
    pub fn get(&self, kid: Kid) -> Option<&VerifyingKey> {
        self.keys
            .iter()
            .find(|(k, _)| *k == kid)
            .map(|(_, key)| key)
    }

    /// Number of keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether there is no key.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

#[cfg(test)]
mod tests;
