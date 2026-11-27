//! RFC 3161 time-stamps of the heads, kept in the chain itself (ADR-0012,
//! « Horodatage RFC 3161 des têtes »).
//!
//! The core asks a time-stamping authority to stamp the hash of a head,
//! verifies the token, and appends an `audit.head_timestamped` record:
//! the head number and hash, `genTime`, the policy, and the token (DER)
//! split in [`TOKEN_FIELDS`] bytes fields of at most 256 bytes, in order.
//! The token then travels with the chain (exports, partial exports) and
//! the verifier checks it with the trusted certificates of the authority.

use ostena_crypto::tsp::{self, TimeStamp, TsaTrust};

use crate::event::{Event, EventKind, field};
use crate::record::{ActorKind, Digest, Outcome, Record, Value};

/// Bytes of the token per field.
pub const CHUNK: usize = 256;

/// The fields that carry the token, in order: `tst_01` to `tst_24`, enough
/// for [`tsp::MAX_TOKEN`] bytes.
pub const TOKEN_FIELDS: [&str; 24] = [
    "tst_01", "tst_02", "tst_03", "tst_04", "tst_05", "tst_06", "tst_07", "tst_08", "tst_09",
    "tst_10", "tst_11", "tst_12", "tst_13", "tst_14", "tst_15", "tst_16", "tst_17", "tst_18",
    "tst_19", "tst_20", "tst_21", "tst_22", "tst_23", "tst_24",
];

const _: () = assert!(TOKEN_FIELDS.len() * CHUNK >= tsp::MAX_TOKEN);

/// The record of a verified time-stamp of head `head_no` (hash
/// `head_hash`), written by the core.
///
/// # Errors
///
/// [`tsp::TspError::Malformed`] for a token above [`tsp::MAX_TOKEN`].
pub fn event(
    head_no: u64,
    head_hash: &Digest,
    token: &[u8],
    stamp: &TimeStamp,
) -> Result<Event, tsp::TspError> {
    if token.is_empty() || token.len() > tsp::MAX_TOKEN {
        return Err(tsp::TspError::Malformed("jeton trop grand"));
    }
    let mut event = Event::new(
        EventKind::AuditHeadTimestamped,
        Outcome::Success,
        ActorKind::Core,
        "core",
    )
    .u64(field::HEAD_NO, head_no)
    .bytes(field::HEAD_HASH, *head_hash)
    .u64(field::STAMPED_AT, stamp.gen_time_ms)
    .text(field::POLICY, stamp.policy.clone());
    for (name, chunk) in TOKEN_FIELDS.iter().zip(token.chunks(CHUNK)) {
        event = event.bytes(name, chunk.to_vec());
    }
    Ok(event)
}

/// A time-stamp record read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamped {
    /// Seq of the record.
    pub seq: u64,
    /// The head stamped.
    pub head_no: u64,
    /// Its hash.
    pub head_hash: Digest,
    /// `genTime` as the core recorded it, Unix milliseconds.
    pub stamped_at: u64,
    /// The token (DER).
    pub token: Vec<u8>,
}

impl Stamped {
    /// The time-stamp of `record`, if it is an `audit.head_timestamped`
    /// record; `Some(Err(why))` if it is one but malformed.
    pub fn of(record: &Record) -> Option<Result<Self, &'static str>> {
        if record.event != EventKind::AuditHeadTimestamped.name() {
            return None;
        }
        let get = |name: &str| {
            record
                .fields
                .iter()
                .find(|f| f.name == name)
                .map(|f| &f.value)
        };
        let parsed = (|| {
            let head_no = match get(field::HEAD_NO) {
                Some(Value::U64(n)) => *n,
                _ => return Err("numéro de tête absent"),
            };
            let head_hash = match get(field::HEAD_HASH) {
                Some(Value::Bytes(b)) => {
                    <Digest>::try_from(b.as_slice()).map_err(|_| "hash de tête mal formé")?
                }
                _ => return Err("hash de tête absent"),
            };
            let stamped_at = match get(field::STAMPED_AT) {
                Some(Value::U64(n)) => *n,
                _ => return Err("heure d'horodatage absente"),
            };
            let mut token = Vec::new();
            let mut ended = false;
            for name in TOKEN_FIELDS {
                match get(name) {
                    Some(Value::Bytes(b)) if !ended => {
                        if b.is_empty() {
                            return Err("morceau de jeton vide");
                        }
                        token.extend_from_slice(b);
                        if b.len() < CHUNK {
                            ended = true;
                        }
                    }
                    None => ended = true,
                    Some(_) => return Err("morceaux de jeton mal formés"),
                }
            }
            if token.is_empty() {
                return Err("jeton absent");
            }
            Ok(Self {
                seq: record.seq,
                head_no,
                head_hash,
                stamped_at,
                token,
            })
        })();
        Some(parsed)
    }

    /// Verifies the token against `trust`: it must stamp the head hash, at
    /// the time recorded.
    ///
    /// # Errors
    ///
    /// The error of [`tsp::verify`], or [`tsp::TspError::Mismatch`] if
    /// `genTime` differs from the time recorded.
    pub fn verify(&self, trust: &TsaTrust) -> Result<TimeStamp, tsp::TspError> {
        let stamp = tsp::verify(&self.token, &self.head_hash, trust)?;
        if stamp.gen_time_ms != self.stamped_at {
            return Err(tsp::TspError::Mismatch(
                "heure enregistrée différente du jeton",
            ));
        }
        Ok(stamp)
    }
}

#[cfg(test)]
mod tests {
    use ostena_crypto::tsp::testing::{TestTsa, TokenOptions};

    use super::*;
    use crate::ids::ChainId;
    use crate::record::ZERO_DIGEST;

    fn now_ms() -> u64 {
        u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap()
    }

    #[test]
    fn a_stamp_round_trips_through_a_record() {
        let tsa = TestTsa::new();
        let hash = [9u8; 32];
        let t = now_ms();
        let token = tsa.token(&hash, None, t, &TokenOptions::default());
        let stamp = tsp::verify(&token, &hash, &tsa.trust()).unwrap();
        let record = event(7, &hash, &token, &stamp)
            .unwrap()
            .into_record(ChainId::from_bytes([1; 16]), 1, ZERO_DIGEST, t)
            .unwrap();
        let encoded = record.encode().unwrap();
        let record = Record::decode(&encoded).unwrap();
        let read = Stamped::of(&record).unwrap().unwrap();
        assert_eq!(
            (read.head_no, read.head_hash, read.token.clone()),
            (7, hash, token.clone())
        );
        assert_eq!(read.verify(&tsa.trust()).unwrap(), stamp);
        // Another head hash: the token does not stamp it.
        let mut other = read.clone();
        other.head_hash = [8; 32];
        assert_eq!(other.verify(&tsa.trust()).unwrap_err().code(), "TSP-E006");
        let mut late = read;
        late.stamped_at += 1;
        assert_eq!(late.verify(&tsa.trust()).unwrap_err().code(), "TSP-E006");
    }

    #[test]
    fn the_largest_token_fits_in_one_record() {
        let token = vec![0x30; tsp::MAX_TOKEN];
        let stamp = TimeStamp {
            gen_time_ms: 1,
            accuracy_ms: None,
            serial: vec![1],
            policy: "1.2.3.4.5.6.7.8.9.10".into(),
            nonce: None,
            signer_sha256: [0; 32],
        };
        let record = event(u64::MAX, &[0xff; 32], &token, &stamp)
            .unwrap()
            .into_record(ChainId::from_bytes([1; 16]), u64::MAX, [1; 32], u64::MAX)
            .unwrap();
        assert_eq!(Stamped::of(&record).unwrap().unwrap().token, token);
        assert!(event(1, &[0; 32], &vec![0; tsp::MAX_TOKEN + 1], &stamp).is_err());
    }
}
