//! Record v1: the canonical binary encoding of one audit event (ADR-0012).
//!
//! Big-endian, in this order:
//!
//! | Size | Field | Rule |
//! |---|---|---|
//! | 1 | version | 1 |
//! | 16 | chain id | |
//! | 8 | seq | from 1, no gap |
//! | 32 | prev hash | hash of record `seq − 1`; zeros if and only if `seq = 1` |
//! | 8 | time (Unix ms) | |
//! | 1 | outcome | 0 success, 1 refused, 2 failure |
//! | 1 | actor kind | 0 core, 1 admin, 2 agent, 3 peer |
//! | 1 + n | actor | UTF-8, at most 128 bytes, no control character |
//! | 1 + n | event | ASCII `[a-z0-9_.]`, 3 to 64 bytes |
//! | 1 | field count | at most 32 |
//! | … | fields | `u8` name length, name `[a-z0-9_]` (1 to 32 bytes, strictly increasing bytewise), `u8` type, `u16` length, value |
//!
//! Field types: 1 text (UTF-8, at most 1024 bytes, no control character),
//! 2 `u64` (8 bytes), 3 bytes (at most 256), 4 UUID (16 bytes), 5 boolean
//! (1 byte, 0 or 1). No trailing byte; at most [`MAX_RECORD_LEN`] bytes.
//!
//! The decoder refuses anything that is not the unique canonical encoding,
//! so `encode(decode(b)) == b` for every accepted `b`.

use crate::AuditError;
use crate::ids::ChainId;

/// Record format version.
pub const RECORD_VERSION: u8 = 1;
/// Largest encoded record.
pub const MAX_RECORD_LEN: usize = 8192;
/// Smallest encoded record: the fixed part (67 bytes), an empty actor, a
/// 3-byte event name and no field. The core's table checks it.
pub const MIN_RECORD_LEN: usize = 67 + 1 + 1 + MIN_EVENT_LEN + 1;
/// Largest actor, in bytes.
pub const MAX_ACTOR_LEN: usize = 128;
/// Shortest event name.
pub const MIN_EVENT_LEN: usize = 3;
/// Longest event name.
pub const MAX_EVENT_LEN: usize = 64;
/// Largest number of fields.
pub const MAX_FIELDS: usize = 32;
/// Longest field name.
pub const MAX_FIELD_NAME_LEN: usize = 32;
/// Largest text value, in bytes.
pub const MAX_TEXT_LEN: usize = 1024;
/// Largest bytes value.
pub const MAX_BYTES_LEN: usize = 256;

/// Domain separation prefix of the record hash.
const RECORD_HASH_DOMAIN: &[u8] = b"ostena-audit-record-v1\0";

/// A SHA-256 digest.
pub type Digest = [u8; 32];
/// The previous hash of the first record, and of the first head.
pub const ZERO_DIGEST: Digest = [0; 32];

/// Hash of an encoded record: SHA-256(`"ostena-audit-record-v1" ‖ 0x00 ‖ body`).
/// The next record carries it as its previous hash.
pub fn record_hash(body: &[u8]) -> Digest {
    ostena_crypto::sha256::digest_concat(&[RECORD_HASH_DOMAIN, body])
}

/// How the audited operation ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// It succeeded.
    Success,
    /// It was refused (authorisation, validation).
    Refused,
    /// It failed (internal error, unavailable dependency).
    Failure,
}

impl Outcome {
    /// Every outcome, in code order.
    pub const ALL: [Self; 3] = [Self::Success, Self::Refused, Self::Failure];

    /// The encoded value.
    pub const fn code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::Refused => 1,
            Self::Failure => 2,
        }
    }

    /// The outcome of an encoded value.
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Success),
            1 => Some(Self::Refused),
            2 => Some(Self::Failure),
            _ => None,
        }
    }
}

/// Who performed the audited operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActorKind {
    /// The core itself.
    Core,
    /// An administrator (command line, API).
    Admin,
    /// A gateway agent.
    Agent,
    /// An unauthenticated peer (an address).
    Peer,
}

impl ActorKind {
    /// Every actor kind, in code order.
    pub const ALL: [Self; 4] = [Self::Core, Self::Admin, Self::Agent, Self::Peer];

    /// The encoded value.
    pub const fn code(self) -> u8 {
        match self {
            Self::Core => 0,
            Self::Admin => 1,
            Self::Agent => 2,
            Self::Peer => 3,
        }
    }

    /// The actor kind of an encoded value.
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Core),
            1 => Some(Self::Admin),
            2 => Some(Self::Agent),
            3 => Some(Self::Peer),
            _ => None,
        }
    }
}

/// A typed field value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Value {
    /// UTF-8 text, at most [`MAX_TEXT_LEN`] bytes, no control character.
    Text(String),
    /// An unsigned integer.
    U64(u64),
    /// Raw bytes, at most [`MAX_BYTES_LEN`].
    Bytes(Vec<u8>),
    /// A UUID, binary form.
    Uuid([u8; 16]),
    /// A boolean.
    Bool(bool),
}

impl Value {
    const fn type_code(&self) -> u8 {
        match self {
            Self::Text(_) => 1,
            Self::U64(_) => 2,
            Self::Bytes(_) => 3,
            Self::Uuid(_) => 4,
            Self::Bool(_) => 5,
        }
    }
}

/// A named field of a record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Field {
    /// Name: `[a-z0-9_]`, 1 to [`MAX_FIELD_NAME_LEN`] bytes.
    pub name: String,
    /// Value.
    pub value: Value,
}

/// One audit record, decoded.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Record {
    /// Chain the record belongs to.
    pub chain_id: ChainId,
    /// Position in the chain, from 1.
    pub seq: u64,
    /// Hash of the previous record ([`ZERO_DIGEST`] for `seq = 1`).
    pub prev_hash: Digest,
    /// Time of the event, Unix milliseconds (core clock).
    pub time_ms: u64,
    /// How the operation ended.
    pub outcome: Outcome,
    /// Kind of actor.
    pub actor_kind: ActorKind,
    /// Actor identity (user name, agent UUID, address).
    pub actor: String,
    /// Event name, e.g. `agent.revoked`.
    pub event: String,
    /// Fields, sorted by name, without duplicates.
    pub fields: Vec<Field>,
}

fn is_event_name(name: &[u8]) -> bool {
    (MIN_EVENT_LEN..=MAX_EVENT_LEN).contains(&name.len())
        && name
            .iter()
            .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.'))
}

pub(crate) fn is_field_name(name: &[u8]) -> bool {
    (1..=MAX_FIELD_NAME_LEN).contains(&name.len())
        && name
            .iter()
            .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

fn is_clean_text(text: &str, max: usize) -> bool {
    text.len() <= max && !text.chars().any(char::is_control)
}

/// Checks a record against every rule of the format.
fn check(record: &Record) -> Result<(), AuditError> {
    if record.seq == 0 {
        return Err(AuditError::MalformedRecord("numéro de séquence nul"));
    }
    if (record.seq == 1) != (record.prev_hash == ZERO_DIGEST) {
        return Err(AuditError::MalformedRecord(
            "hash précédent nul si et seulement si le numéro vaut 1",
        ));
    }
    if !is_clean_text(&record.actor, MAX_ACTOR_LEN) {
        return Err(AuditError::MalformedRecord(
            "acteur trop long ou avec un caractère de contrôle",
        ));
    }
    if !is_event_name(record.event.as_bytes()) {
        return Err(AuditError::MalformedRecord(
            "nom d'événement invalide ([a-z0-9_.], 3 à 64 octets)",
        ));
    }
    if record.fields.len() > MAX_FIELDS {
        return Err(AuditError::MalformedRecord("plus de 32 champs"));
    }
    let mut previous: Option<&[u8]> = None;
    for field in &record.fields {
        let name = field.name.as_bytes();
        if !is_field_name(name) {
            return Err(AuditError::MalformedRecord(
                "nom de champ invalide ([a-z0-9_], 1 à 32 octets)",
            ));
        }
        if previous.is_some_and(|p| p >= name) {
            return Err(AuditError::MalformedRecord(
                "champs non triés par nom ou en double",
            ));
        }
        previous = Some(name);
        match &field.value {
            Value::Text(t) if !is_clean_text(t, MAX_TEXT_LEN) => {
                return Err(AuditError::MalformedRecord(
                    "texte trop long ou avec un caractère de contrôle",
                ));
            }
            Value::Bytes(b) if b.len() > MAX_BYTES_LEN => {
                return Err(AuditError::MalformedRecord("valeur binaire trop longue"));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Length prefixes: the checks above bound every length.
fn len_u8(len: usize) -> Result<u8, AuditError> {
    u8::try_from(len).map_err(|_| AuditError::MalformedRecord("longueur hors limites"))
}

impl Record {
    /// The canonical encoding.
    ///
    /// # Errors
    ///
    /// [`AuditError::MalformedRecord`] if a rule of the format is broken,
    /// including an encoding longer than [`MAX_RECORD_LEN`].
    pub fn encode(&self) -> Result<Vec<u8>, AuditError> {
        check(self)?;
        let mut out = Vec::with_capacity(128);
        out.push(RECORD_VERSION);
        out.extend_from_slice(&self.chain_id.to_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.prev_hash);
        out.extend_from_slice(&self.time_ms.to_be_bytes());
        out.push(self.outcome.code());
        out.push(self.actor_kind.code());
        out.push(len_u8(self.actor.len())?);
        out.extend_from_slice(self.actor.as_bytes());
        out.push(len_u8(self.event.len())?);
        out.extend_from_slice(self.event.as_bytes());
        out.push(len_u8(self.fields.len())?);
        for field in &self.fields {
            out.push(len_u8(field.name.len())?);
            out.extend_from_slice(field.name.as_bytes());
            out.push(field.value.type_code());
            let value: std::borrow::Cow<'_, [u8]> = match &field.value {
                Value::Text(t) => t.as_bytes().into(),
                Value::U64(v) => v.to_be_bytes().to_vec().into(),
                Value::Bytes(b) => b.as_slice().into(),
                Value::Uuid(u) => u.as_slice().into(),
                Value::Bool(b) => vec![u8::from(*b)].into(),
            };
            let len = u16::try_from(value.len())
                .map_err(|_| AuditError::MalformedRecord("valeur trop longue"))?;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&value);
            if out.len() > MAX_RECORD_LEN {
                return Err(AuditError::MalformedRecord("plus de 8192 octets"));
            }
        }
        if out.len() > MAX_RECORD_LEN {
            return Err(AuditError::MalformedRecord("plus de 8192 octets"));
        }
        Ok(out)
    }

    /// Decodes a record, refusing anything but the canonical encoding.
    ///
    /// # Errors
    ///
    /// [`AuditError::Unsupported`] for another version,
    /// [`AuditError::MalformedRecord`] for any other deviation.
    pub fn decode(data: &[u8]) -> Result<Self, AuditError> {
        if data.len() > MAX_RECORD_LEN {
            return Err(AuditError::MalformedRecord("plus de 8192 octets"));
        }
        let mut r = Cursor { data };
        let version = r.u8()?;
        if version != RECORD_VERSION {
            return Err(AuditError::Unsupported {
                what: "version d'enregistrement",
                value: version,
            });
        }
        let chain_id = ChainId::from_bytes(r.array()?);
        let seq = r.u64()?;
        let prev_hash = r.array()?;
        let time_ms = r.u64()?;
        let outcome =
            Outcome::from_code(r.u8()?).ok_or(AuditError::MalformedRecord("résultat inconnu"))?;
        let actor_kind = ActorKind::from_code(r.u8()?)
            .ok_or(AuditError::MalformedRecord("type d'acteur inconnu"))?;
        let actor_len = usize::from(r.u8()?);
        if actor_len > MAX_ACTOR_LEN {
            return Err(AuditError::MalformedRecord("acteur trop long"));
        }
        let actor = r.text(actor_len)?;
        let event_len = usize::from(r.u8()?);
        let event = r.take(event_len)?;
        if !is_event_name(event) {
            return Err(AuditError::MalformedRecord(
                "nom d'événement invalide ([a-z0-9_.], 3 à 64 octets)",
            ));
        }
        let event = String::from_utf8(event.to_vec())
            .map_err(|_| AuditError::MalformedRecord("nom d'événement invalide"))?;
        let count = usize::from(r.u8()?);
        if count > MAX_FIELDS {
            return Err(AuditError::MalformedRecord("plus de 32 champs"));
        }
        let mut fields = Vec::with_capacity(count);
        for _ in 0..count {
            let name_len = usize::from(r.u8()?);
            let name = r.take(name_len)?;
            if !is_field_name(name) {
                return Err(AuditError::MalformedRecord(
                    "nom de champ invalide ([a-z0-9_], 1 à 32 octets)",
                ));
            }
            let name = String::from_utf8(name.to_vec())
                .map_err(|_| AuditError::MalformedRecord("nom de champ invalide"))?;
            let kind = r.u8()?;
            let len = usize::from(r.u16()?);
            let value = match (kind, len) {
                (1, _) if len <= MAX_TEXT_LEN => Value::Text(r.text(len)?),
                (2, 8) => Value::U64(r.u64()?),
                (3, _) if len <= MAX_BYTES_LEN => Value::Bytes(r.take(len)?.to_vec()),
                (4, 16) => Value::Uuid(r.array()?),
                (5, 1) => match r.u8()? {
                    0 => Value::Bool(false),
                    1 => Value::Bool(true),
                    _ => return Err(AuditError::MalformedRecord("booléen autre que 0 ou 1")),
                },
                (1..=5, _) => {
                    return Err(AuditError::MalformedRecord(
                        "longueur de valeur invalide pour son type",
                    ));
                }
                _ => return Err(AuditError::MalformedRecord("type de champ inconnu")),
            };
            fields.push(Field { name, value });
        }
        if !r.data.is_empty() {
            return Err(AuditError::MalformedRecord(
                "octets en trop après les champs",
            ));
        }
        let record = Self {
            chain_id,
            seq,
            prev_hash,
            time_ms,
            outcome,
            actor_kind,
            actor,
            event,
            fields,
        };
        check(&record)?;
        Ok(record)
    }

    /// The value of a field, if present.
    pub fn field(&self, name: &str) -> Option<&Value> {
        self.fields
            .binary_search_by(|f| f.name.as_str().cmp(name))
            .ok()
            .map(|i| &self.fields[i].value)
    }
}

/// Reads the encoding front to back; every read is bounds-checked.
struct Cursor<'a> {
    data: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], AuditError> {
        if self.data.len() < n {
            return Err(AuditError::MalformedRecord("enregistrement tronqué"));
        }
        let (head, rest) = self.data.split_at(n);
        self.data = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], AuditError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, AuditError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, AuditError> {
        self.array().map(u16::from_be_bytes)
    }

    fn u64(&mut self) -> Result<u64, AuditError> {
        self.array().map(u64::from_be_bytes)
    }

    fn text(&mut self, len: usize) -> Result<String, AuditError> {
        let raw = self.take(len)?;
        let text = std::str::from_utf8(raw)
            .map_err(|_| AuditError::MalformedRecord("texte qui n'est pas de l'UTF-8"))?;
        if text.chars().any(char::is_control) {
            return Err(AuditError::MalformedRecord(
                "texte avec un caractère de contrôle",
            ));
        }
        Ok(text.to_owned())
    }
}

#[cfg(test)]
mod tests;
