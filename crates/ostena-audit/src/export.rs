//! Export container v1: records and heads of a chain, streamed (ADR-0012).
//!
//! Header (40 bytes): magic `OSTAUD\0\x01` | chain id (16) | export time,
//! Unix ms (`u64`) | first seq (`u64`, from 1). Then frames:
//! `u8` type | `u32` length (at most [`MAX_RECORD_LEN`]) | payload.
//!
//! | Type | Payload |
//! |---|---|
//! | 1 | a record body |
//! | 2 | a head (182 bytes) |
//! | 3 | reserved for an RFC 3161 timestamp over a head hash, refused in v1 |
//! | `0xFF` | end: record count (`u64`), head count (`u64`) |
//!
//! Order: record k, then the heads whose record seq is k. A partial export
//! (first seq above 1) starts with its anchor: the head N with
//! `record_seq + 1 == first_seq`. Nothing may follow the end frame.

use std::io::{Read, Write};

use crate::AuditError;
use crate::head::{HEAD_LEN, Head};
use crate::ids::ChainId;
use crate::record::MAX_RECORD_LEN;

/// Magic bytes and container version.
pub const MAGIC: [u8; 8] = *b"OSTAUD\0\x01";
/// Length of the header.
pub const HEADER_LEN: usize = 8 + 16 + 8 + 8;

const FRAME_RECORD: u8 = 1;
const FRAME_HEAD: u8 = 2;
const FRAME_TIMESTAMP: u8 = 3;
const FRAME_END: u8 = 0xFF;
const END_LEN: usize = 16;

const _: () = assert!(HEAD_LEN <= MAX_RECORD_LEN);

/// One frame of an export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// A record body, not decoded yet (the verifier decodes it).
    Record(Vec<u8>),
    /// A head, decoded but not verified.
    Head(Head),
    /// The end frame, whose counts match the frames read.
    End {
        /// Number of records.
        record_count: u64,
        /// Number of heads, the anchor included.
        head_count: u64,
    },
}

/// Writes an export.
#[derive(Debug)]
pub struct ExportWriter<W: Write> {
    inner: W,
    records: u64,
    heads: u64,
}

fn frame_len(len: usize) -> Result<[u8; 4], AuditError> {
    if len > MAX_RECORD_LEN {
        return Err(AuditError::MalformedRecord("plus de 8192 octets"));
    }
    u32::try_from(len)
        .map(u32::to_be_bytes)
        .map_err(|_| AuditError::MalformedRecord("plus de 8192 octets"))
}

impl<W: Write> ExportWriter<W> {
    /// Writes the header.
    ///
    /// # Errors
    ///
    /// [`AuditError::MalformedExport`] if `first_seq` is 0,
    /// [`AuditError::Io`] if writing fails.
    pub fn new(
        mut inner: W,
        chain_id: ChainId,
        export_time_ms: u64,
        first_seq: u64,
    ) -> Result<Self, AuditError> {
        if first_seq == 0 {
            return Err(AuditError::MalformedExport(
                "premier numéro d'enregistrement nul".into(),
            ));
        }
        let mut header = [0u8; HEADER_LEN];
        header[..8].copy_from_slice(&MAGIC);
        header[8..24].copy_from_slice(&chain_id.to_bytes());
        header[24..32].copy_from_slice(&export_time_ms.to_be_bytes());
        header[32..40].copy_from_slice(&first_seq.to_be_bytes());
        inner.write_all(&header).map_err(|e| AuditError::io(&e))?;
        Ok(Self {
            inner,
            records: 0,
            heads: 0,
        })
    }

    fn frame(&mut self, kind: u8, payload: &[u8]) -> Result<(), AuditError> {
        let len = frame_len(payload.len())?;
        let mut prefix = [0u8; 5];
        prefix[0] = kind;
        prefix[1..].copy_from_slice(&len);
        self.inner
            .write_all(&prefix)
            .and_then(|()| self.inner.write_all(payload))
            .map_err(|e| AuditError::io(&e))
    }

    /// Writes a record body as stored.
    ///
    /// # Errors
    ///
    /// [`AuditError::MalformedRecord`] above [`MAX_RECORD_LEN`],
    /// [`AuditError::Io`] if writing fails.
    pub fn record(&mut self, body: &[u8]) -> Result<(), AuditError> {
        self.frame(FRAME_RECORD, body)?;
        self.records += 1;
        Ok(())
    }

    /// Writes a head.
    ///
    /// # Errors
    ///
    /// [`AuditError::Io`] if writing fails.
    pub fn head(&mut self, head: &Head) -> Result<(), AuditError> {
        self.frame(FRAME_HEAD, &head.encode())?;
        self.heads += 1;
        Ok(())
    }

    /// Writes a head as stored, without decoding it: a head that does not
    /// decode any more (altered in the database) stays in the export, where
    /// the verifier reports it.
    ///
    /// # Errors
    ///
    /// [`AuditError::MalformedRecord`] above [`MAX_RECORD_LEN`],
    /// [`AuditError::Io`] if writing fails.
    pub fn head_bytes(&mut self, head: &[u8]) -> Result<(), AuditError> {
        self.frame(FRAME_HEAD, head)?;
        self.heads += 1;
        Ok(())
    }

    /// Writes the end frame, flushes, and returns the writer.
    ///
    /// # Errors
    ///
    /// [`AuditError::Io`] if writing fails.
    pub fn finish(mut self) -> Result<W, AuditError> {
        let mut end = [0u8; END_LEN];
        end[..8].copy_from_slice(&self.records.to_be_bytes());
        end[8..].copy_from_slice(&self.heads.to_be_bytes());
        self.frame(FRAME_END, &end)?;
        self.inner.flush().map_err(|e| AuditError::io(&e))?;
        Ok(self.inner)
    }
}

/// Reads an export, frame by frame, in constant memory. An iterator of
/// frames that stops after the end frame or the first error.
#[derive(Debug)]
pub struct ExportReader<R: Read> {
    inner: R,
    chain_id: ChainId,
    export_time_ms: u64,
    first_seq: u64,
    records: u64,
    heads: u64,
    done: bool,
}

fn malformed(message: &str) -> AuditError {
    AuditError::MalformedExport(message.to_owned())
}

impl<R: Read> ExportReader<R> {
    /// Reads and checks the header.
    ///
    /// # Errors
    ///
    /// [`AuditError::MalformedExport`] for another file or a truncated
    /// header, [`AuditError::Io`] if reading fails.
    pub fn new(mut inner: R) -> Result<Self, AuditError> {
        let mut header = [0u8; HEADER_LEN];
        inner
            .read_exact(&mut header)
            .map_err(|e| AuditError::io(&e))?;
        if header[..8] != MAGIC {
            return Err(malformed(
                "en-tête OSTAUD v1 absent : ce n'est pas un export d'audit Ostena v1",
            ));
        }
        let mut chain_id = [0u8; 16];
        chain_id.copy_from_slice(&header[8..24]);
        let mut time = [0u8; 8];
        time.copy_from_slice(&header[24..32]);
        let mut first = [0u8; 8];
        first.copy_from_slice(&header[32..40]);
        let first_seq = u64::from_be_bytes(first);
        if first_seq == 0 {
            return Err(malformed("premier numéro d'enregistrement nul"));
        }
        Ok(Self {
            inner,
            chain_id: ChainId::from_bytes(chain_id),
            export_time_ms: u64::from_be_bytes(time),
            first_seq,
            records: 0,
            heads: 0,
            done: false,
        })
    }

    /// The chain in the header.
    pub fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Export time in the header, Unix milliseconds.
    pub fn export_time_ms(&self) -> u64 {
        self.export_time_ms
    }

    /// First record seq in the header.
    pub fn first_seq(&self) -> u64 {
        self.first_seq
    }

    fn next_frame(&mut self) -> Result<Frame, AuditError> {
        let mut prefix = [0u8; 5];
        self.inner.read_exact(&mut prefix).map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                malformed("export tronqué : trame de fin absente")
            } else {
                AuditError::io(&e)
            }
        })?;
        let kind = prefix[0];
        let mut len = [0u8; 4];
        len.copy_from_slice(&prefix[1..]);
        let len = usize::try_from(u32::from_be_bytes(len)).unwrap_or(usize::MAX);
        if len > MAX_RECORD_LEN {
            return Err(malformed("trame de plus de 8192 octets"));
        }
        match kind {
            FRAME_RECORD | FRAME_HEAD | FRAME_END => {}
            FRAME_TIMESTAMP => {
                return Err(malformed(
                    "trame 3 (jeton d'horodatage RFC 3161) non prise en charge en v1",
                ));
            }
            _ => return Err(malformed("type de trame inconnu")),
        }
        let mut payload = vec![0u8; len];
        self.inner
            .read_exact(&mut payload)
            .map_err(|e| AuditError::io(&e))?;
        match kind {
            FRAME_RECORD => {
                self.records += 1;
                Ok(Frame::Record(payload))
            }
            FRAME_HEAD => {
                let head = Head::decode(&payload)?;
                self.heads += 1;
                Ok(Frame::Head(head))
            }
            _ => {
                if len != END_LEN {
                    return Err(malformed("trame de fin de longueur invalide"));
                }
                let mut records = [0u8; 8];
                records.copy_from_slice(&payload[..8]);
                let mut heads = [0u8; 8];
                heads.copy_from_slice(&payload[8..]);
                let record_count = u64::from_be_bytes(records);
                let head_count = u64::from_be_bytes(heads);
                if record_count != self.records || head_count != self.heads {
                    return Err(AuditError::MalformedExport(format!(
                        "la trame de fin annonce {record_count} enregistrement(s) et {head_count} \
                         tête(s), l'export en contient {} et {}",
                        self.records, self.heads
                    )));
                }
                let mut extra = [0u8; 1];
                match self.inner.read(&mut extra) {
                    Ok(0) => Ok(Frame::End {
                        record_count,
                        head_count,
                    }),
                    Ok(_) => Err(malformed("données après la trame de fin")),
                    Err(e) => Err(AuditError::io(&e)),
                }
            }
        }
    }
}

impl<R: Read> Iterator for ExportReader<R> {
    type Item = Result<Frame, AuditError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let frame = self.next_frame();
        if matches!(frame, Ok(Frame::End { .. }) | Err(_)) {
            self.done = true;
        }
        Some(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::ZERO_DIGEST;
    use crate::{ActorKind, ChainTip, Outcome};
    use crate::{Event, EventKind, UnsignedHead};
    use ostena_crypto::p256::SigningKey;

    fn sample() -> (ChainId, Vec<u8>, Head) {
        let chain = ChainId::from_bytes([3; 16]);
        let mut tip = ChainTip::empty(chain);
        let record = tip
            .append(
                Event::new(
                    EventKind::AuditChainStarted,
                    Outcome::Success,
                    ActorKind::Core,
                    "core",
                ),
                1,
            )
            .unwrap();
        let key = SigningKey::generate().unwrap().0;
        let head = UnsignedHead::after(None, chain, 1, record.hash, 2, 60)
            .sign(&key)
            .unwrap();
        let mut writer = ExportWriter::new(Vec::new(), chain, 3, 1).unwrap();
        writer.record(&record.body).unwrap();
        writer.head(&head).unwrap();
        (chain, writer.finish().unwrap(), head)
    }

    fn read_all(data: &[u8]) -> Result<Vec<Frame>, AuditError> {
        ExportReader::new(data)?.collect()
    }

    #[test]
    fn round_trip() {
        let (chain, bytes, head) = sample();
        let reader = ExportReader::new(bytes.as_slice()).unwrap();
        assert_eq!(
            (
                reader.chain_id(),
                reader.export_time_ms(),
                reader.first_seq()
            ),
            (chain, 3, 1)
        );
        let frames = read_all(&bytes).unwrap();
        assert_eq!(frames.len(), 3);
        assert!(matches!(&frames[0], Frame::Record(b) if crate::Record::decode(b).is_ok()));
        assert_eq!(frames[1], Frame::Head(head));
        assert_eq!(
            frames[2],
            Frame::End {
                record_count: 1,
                head_count: 1
            }
        );
        assert_ne!(head.prev_head_hash(), [1; 32]);
        assert_eq!(head.prev_head_hash(), ZERO_DIGEST);
    }

    #[test]
    fn raw_head_frames_match_decoded_ones_and_are_checked_by_the_reader() {
        let (chain, bytes, head) = sample();
        let reader = ExportReader::new(bytes.as_slice()).unwrap();
        let mut writer = ExportWriter::new(Vec::new(), chain, 3, 1).unwrap();
        for frame in reader {
            match frame.unwrap() {
                Frame::Record(body) => writer.record(&body).unwrap(),
                Frame::Head(head) => writer.head_bytes(&head.encode()).unwrap(),
                Frame::End { .. } => {}
            }
        }
        assert_eq!(writer.finish().unwrap(), bytes);
        let mut writer = ExportWriter::new(Vec::new(), chain, 3, 1).unwrap();
        let mut broken = head.encode();
        broken[0] = 9;
        writer.head_bytes(&broken).unwrap();
        let rewritten = writer.finish().unwrap();
        assert!(matches!(
            read_all(&rewritten),
            Err(AuditError::Unsupported { .. })
        ));
        let mut writer = ExportWriter::new(Vec::new(), chain, 3, 1).unwrap();
        assert!(writer.head_bytes(&[0; MAX_RECORD_LEN + 1]).is_err());
    }

    #[test]
    fn refuses_another_magic_or_a_short_header() {
        let (_, mut bytes, _) = sample();
        assert!(matches!(
            ExportReader::new(&bytes[..10]),
            Err(AuditError::MalformedExport(_))
        ));
        bytes[7] = 2;
        assert!(matches!(
            ExportReader::new(bytes.as_slice()),
            Err(AuditError::MalformedExport(_))
        ));
    }

    #[test]
    fn refuses_a_zero_first_seq() {
        let (_, mut bytes, _) = sample();
        bytes[32..40].copy_from_slice(&[0; 8]);
        assert!(ExportReader::new(bytes.as_slice()).is_err());
        assert!(ExportWriter::new(Vec::new(), ChainId::from_bytes([0; 16]), 0, 0).is_err());
    }

    #[test]
    fn refuses_truncation_at_every_length() {
        let (_, bytes, _) = sample();
        for cut in HEADER_LEN..bytes.len() {
            let result = read_all(&bytes[..cut]);
            assert!(
                matches!(result, Err(AuditError::MalformedExport(_))),
                "cut at {cut}: {result:?}"
            );
        }
    }

    #[test]
    fn refuses_data_after_the_end() {
        let (_, mut bytes, _) = sample();
        bytes.push(0);
        let error = read_all(&bytes).unwrap_err();
        assert!(
            error.to_string().contains("après la trame de fin"),
            "{error}"
        );
    }

    #[test]
    fn refuses_wrong_end_counts() {
        let (_, mut bytes, _) = sample();
        let at = bytes.len() - 1;
        bytes[at] = 2;
        assert!(read_all(&bytes).is_err());
    }

    #[test]
    fn refuses_reserved_unknown_and_oversized_frames() {
        let (_, bytes, _) = sample();
        let mut header = bytes[..HEADER_LEN].to_vec();
        for (kind, len) in [
            (3u8, 4u32),
            (0, 0),
            (4, 0),
            (0xFE, 0),
            (1, 8193),
            (2, u32::MAX),
        ] {
            let mut data = header.clone();
            data.push(kind);
            data.extend_from_slice(&len.to_be_bytes());
            data.extend_from_slice(&[0; 4]);
            assert!(
                matches!(read_all(&data), Err(AuditError::MalformedExport(_))),
                "type {kind} length {len}"
            );
        }
        // A head frame whose payload is not a head.
        header.push(2);
        header.extend_from_slice(&3u32.to_be_bytes());
        header.extend_from_slice(&[1, 2, 3]);
        assert!(matches!(
            read_all(&header),
            Err(AuditError::MalformedHead(_))
        ));
    }

    #[test]
    fn writer_refuses_oversized_records() {
        let mut writer = ExportWriter::new(Vec::new(), ChainId::from_bytes([0; 16]), 0, 1).unwrap();
        assert!(writer.record(&vec![0; MAX_RECORD_LEN + 1]).is_err());
        assert!(writer.record(&vec![0; MAX_RECORD_LEN]).is_ok());
    }

    #[test]
    fn iterator_stops_after_an_error() {
        let (_, bytes, _) = sample();
        let mut reader = ExportReader::new(&bytes[..bytes.len() - 3]).unwrap();
        let mut errors = 0;
        for frame in reader.by_ref() {
            errors += usize::from(frame.is_err());
        }
        assert_eq!(errors, 1);
        assert!(reader.next().is_none());
    }
}
