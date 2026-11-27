//! Whether a target requires SMB signing (ADR-0026): one SMB 2 NEGOTIATE
//! exchange on port 445 ([MS-SMB2] 2.2.3 and 2.2.4), nothing else (no
//! session, no authentication).
//!
//! The sessions of a target are managed by RPC over its named pipes, that
//! is over SMB: a target that does not require signing leaves the channel
//! open to an NTLM relay. The agent asks before opening it.
//!
//! The request offers the dialects 2.0.2 to 3.0.2, which need no
//! negotiation context; the answer is the server's `SecurityMode`, where
//! `SMB2_NEGOTIATE_SIGNING_REQUIRED` says whether signing is required.

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// The port of SMB over TCP ([MS-SMB2] 2.1).
pub const PORT: u16 = 445;

/// `0xFE 'S' 'M' 'B'`.
const PROTOCOL_ID: [u8; 4] = [0xFE, b'S', b'M', b'B'];
/// `0xFF 'S' 'M' 'B'`: an SMB 1 answer.
const SMB1_ID: [u8; 4] = [0xFF, b'S', b'M', b'B'];
/// Size of the SMB 2 header.
const HEADER: usize = 64;
/// `SMB2_NEGOTIATE_SIGNING_ENABLED`.
const SIGNING_ENABLED: u16 = 0x0001;
/// `SMB2_NEGOTIATE_SIGNING_REQUIRED`.
const SIGNING_REQUIRED: u16 = 0x0002;
/// `SMB2_FLAGS_SERVER_TO_REDIR`.
const SERVER_TO_REDIR: u32 = 0x0000_0001;
/// The dialects offered: 2.0.2, 2.1, 3.0, 3.0.2.
const DIALECTS: [u16; 4] = [0x0202, 0x0210, 0x0300, 0x0302];
const DIALECT_COUNT: u16 = 4;
/// Fixed client GUID: the probe holds no state on the server.
const CLIENT_GUID: [u8; 16] = *b"ostena-smb-probe";
/// Largest answer read: a negotiate response with its security buffer.
const MAX_FRAME: usize = 64 * 1024;

/// Why the answer cannot be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SmbError {
    /// Too short for an SMB 2 negotiate response.
    #[error("réponse SMB tronquée")]
    Truncated,
    /// The server answered in SMB 1 only.
    #[error("la cible ne parle que SMB 1")]
    Smb1,
    /// Not an SMB 2 negotiate response.
    #[error("réponse SMB 2 invalide : {0}")]
    Invalid(&'static str),
    /// The server refused the negotiation.
    #[error("négociation SMB refusée par la cible (statut 0x{0:08x})")]
    Status(u32),
}

/// The NEGOTIATE request, with its Direct TCP header.
pub fn negotiate_request() -> Vec<u8> {
    let mut body = Vec::with_capacity(HEADER + 36 + 2 * DIALECTS.len());
    // Header ([MS-SMB2] 2.2.1.2), synchronous.
    body.extend_from_slice(&PROTOCOL_ID);
    body.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
    body.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
    body.extend_from_slice(&0u32.to_le_bytes()); // Status
    body.extend_from_slice(&0u16.to_le_bytes()); // Command: NEGOTIATE
    body.extend_from_slice(&1u16.to_le_bytes()); // CreditRequest
    body.extend_from_slice(&0u32.to_le_bytes()); // Flags
    body.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    body.extend_from_slice(&0u64.to_le_bytes()); // MessageId
    body.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    body.extend_from_slice(&0u32.to_le_bytes()); // TreeId
    body.extend_from_slice(&0u64.to_le_bytes()); // SessionId
    body.extend_from_slice(&[0u8; 16]); // Signature
    // NEGOTIATE request ([MS-SMB2] 2.2.3).
    body.extend_from_slice(&36u16.to_le_bytes()); // StructureSize
    body.extend_from_slice(&DIALECT_COUNT.to_le_bytes());
    body.extend_from_slice(&SIGNING_ENABLED.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    body.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    body.extend_from_slice(&CLIENT_GUID);
    body.extend_from_slice(&0u64.to_le_bytes()); // ClientStartTime
    for dialect in DIALECTS {
        body.extend_from_slice(&dialect.to_le_bytes());
    }
    let mut frame = Vec::with_capacity(4 + body.len());
    // Direct TCP transport ([MS-SMB2] 2.1): a zero byte, a 24-bit length.
    let len = u32::try_from(body.len()).unwrap_or(u32::MAX);
    frame.push(0);
    frame.extend_from_slice(&len.to_be_bytes()[1..]);
    frame.extend_from_slice(&body);
    frame
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// Whether the NEGOTIATE response `message` (SMB 2 message, without the
/// Direct TCP header) says the server requires signing.
///
/// # Errors
///
/// [`SmbError`] when it is not a successful negotiate response to the
/// request of [`negotiate_request`].
pub fn signing_required(message: &[u8]) -> Result<bool, SmbError> {
    let id = message.get(..4).ok_or(SmbError::Truncated)?;
    if id == SMB1_ID {
        return Err(SmbError::Smb1);
    }
    if id != PROTOCOL_ID {
        return Err(SmbError::Invalid("identifiant de protocole"));
    }
    if message.len() < HEADER + 8 {
        return Err(SmbError::Truncated);
    }
    let field = |v: Option<u16>| v.ok_or(SmbError::Truncated);
    if field(u16_at(message, 4))? != 64 {
        return Err(SmbError::Invalid("taille de l'en-tête"));
    }
    let status = u32_at(message, 8).ok_or(SmbError::Truncated)?;
    if field(u16_at(message, 12))? != 0 {
        return Err(SmbError::Invalid("commande"));
    }
    let flags = u32_at(message, 16).ok_or(SmbError::Truncated)?;
    if flags & SERVER_TO_REDIR == 0 {
        return Err(SmbError::Invalid("message du client"));
    }
    if status != 0 {
        return Err(SmbError::Status(status));
    }
    // NEGOTIATE response ([MS-SMB2] 2.2.4).
    if field(u16_at(message, HEADER))? != 65 {
        return Err(SmbError::Invalid("taille de la réponse NEGOTIATE"));
    }
    let mode = field(u16_at(message, HEADER + 2))?;
    let dialect = field(u16_at(message, HEADER + 4))?;
    if !DIALECTS.contains(&dialect) {
        return Err(SmbError::Invalid("dialecte non proposé"));
    }
    Ok(mode & SIGNING_REQUIRED != 0)
}

/// Asks `addr` (pinned address, port 445) whether it requires signing,
/// each step bounded by `timeout`. Blocking.
///
/// # Errors
///
/// Why the answer could not be had (unreachable, closed, invalid).
pub fn probe(addr: SocketAddr, timeout: Duration) -> Result<bool, String> {
    let io = |e: std::io::Error| format!("SMB sur {addr} : {e}");
    let mut tcp = TcpStream::connect_timeout(&addr, timeout).map_err(io)?;
    tcp.set_read_timeout(Some(timeout)).map_err(io)?;
    tcp.set_write_timeout(Some(timeout)).map_err(io)?;
    tcp.write_all(&negotiate_request()).map_err(io)?;
    let mut head = [0u8; 4];
    tcp.read_exact(&mut head).map_err(io)?;
    let len = usize::from(head[1]) << 16 | usize::from(head[2]) << 8 | usize::from(head[3]);
    if head[0] != 0 || len > MAX_FRAME {
        return Err(format!("SMB sur {addr} : trame invalide"));
    }
    let mut message = vec![0u8; len];
    tcp.read_exact(&mut message).map_err(io)?;
    signing_required(&message).map_err(|e| format!("SMB sur {addr} : {e}"))
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]

    use proptest::prelude::*;

    use super::*;

    /// A negotiate response of `dialect` with `mode`.
    pub(crate) fn response(mode: u16, dialect: u16, status: u32) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&PROTOCOL_ID);
        m.extend_from_slice(&64u16.to_le_bytes());
        m.extend_from_slice(&0u16.to_le_bytes());
        m.extend_from_slice(&status.to_le_bytes());
        m.extend_from_slice(&0u16.to_le_bytes());
        m.extend_from_slice(&1u16.to_le_bytes());
        m.extend_from_slice(&SERVER_TO_REDIR.to_le_bytes());
        m.extend_from_slice(&[0u8; 44]);
        m.extend_from_slice(&65u16.to_le_bytes());
        m.extend_from_slice(&mode.to_le_bytes());
        m.extend_from_slice(&dialect.to_le_bytes());
        m.extend_from_slice(&[0u8; 58]);
        m
    }

    #[test]
    fn the_request_offers_four_dialects_with_signing_enabled() {
        let frame = negotiate_request();
        assert_eq!(frame[0], 0);
        let len = usize::from(frame[1]) << 16 | usize::from(frame[2]) << 8 | usize::from(frame[3]);
        assert_eq!(len, frame.len() - 4);
        let m = &frame[4..];
        assert_eq!(&m[..4], &PROTOCOL_ID);
        assert_eq!(u16_at(m, HEADER), Some(36));
        assert_eq!(u16_at(m, HEADER + 2), Some(4));
        assert_eq!(u16_at(m, HEADER + 4), Some(SIGNING_ENABLED));
        assert_eq!(m.len(), HEADER + 36 + 8);
        assert_eq!(u16_at(m, HEADER + 36), Some(0x0202));
        assert_eq!(u16_at(m, HEADER + 42), Some(0x0302));
    }

    #[test]
    fn signing_required_is_read() {
        assert_eq!(signing_required(&response(0x0003, 0x0302, 0)), Ok(true));
        assert_eq!(signing_required(&response(0x0001, 0x0210, 0)), Ok(false));
    }

    #[test]
    fn invalid_answers_are_refused() {
        assert_eq!(signing_required(&[]), Err(SmbError::Truncated));
        let mut smb1 = response(3, 0x0302, 0);
        smb1[0] = 0xFF;
        assert_eq!(signing_required(&smb1), Err(SmbError::Smb1));
        assert_eq!(
            signing_required(&response(3, 0x0302, 0xC000_0022)),
            Err(SmbError::Status(0xC000_0022))
        );
        assert!(matches!(
            signing_required(&response(3, 0x0311, 0)),
            Err(SmbError::Invalid(_))
        ));
        assert!(matches!(
            signing_required(&response(3, 0x02FF, 0)),
            Err(SmbError::Invalid(_))
        ));
        let mut from_client = response(3, 0x0302, 0);
        from_client[16] = 0;
        assert!(matches!(
            signing_required(&from_client),
            Err(SmbError::Invalid(_))
        ));
        let short = response(3, 0x0302, 0);
        assert_eq!(
            signing_required(&short[..HEADER + 4]),
            Err(SmbError::Truncated)
        );
    }

    #[test]
    fn a_closed_port_is_an_error() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        assert!(probe(addr, Duration::from_secs(2)).is_err());
    }

    #[test]
    fn the_probe_reads_the_answer_of_a_server() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut tcp, _) = listener.accept().unwrap();
            let mut request = vec![0u8; negotiate_request().len()];
            tcp.read_exact(&mut request).unwrap();
            assert_eq!(request, negotiate_request());
            let answer = response(0x0003, 0x0300, 0);
            let len = u32::try_from(answer.len()).unwrap().to_be_bytes();
            tcp.write_all(&[0, len[1], len[2], len[3]]).unwrap();
            tcp.write_all(&answer).unwrap();
        });
        assert_eq!(probe(addr, Duration::from_secs(5)), Ok(true));
        server.join().unwrap();
    }

    proptest! {
        #[test]
        fn arbitrary_answers_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..200)) {
            let _ = signing_required(&bytes);
        }

        #[test]
        fn the_required_bit_decides(mode in any::<u16>(), d in 0usize..4) {
            prop_assert_eq!(
                signing_required(&response(mode, DIALECTS[d], 0)),
                Ok(mode & SIGNING_REQUIRED != 0)
            );
        }
    }
}
