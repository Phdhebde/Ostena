//! Pre-check of the SSH peer before the SSH library sees a byte (ADR-0010).
//!
//! The SSH library negotiates strict KEX only when both sides offer it, and
//! falls back silently otherwise (CVE-2023-48795). This module reads, in
//! clear, the peer identification line and its first binary packet, which
//! must be `SSH_MSG_KEXINIT`, and refuses the connection:
//! - without the strict KEX marker of the peer role
//!   (`kex-strict-c-v00@openssh.com` from a client,
//!   `kex-strict-s-v00@openssh.com` from a server);
//! - when the peer offers none of the frozen algorithms, for the key
//!   exchange, the host key, the cipher (each direction) or compression.
//!
//! The parser is pure and bounded: an identification line of at most 255
//! bytes (CR LF included, RFC 4253 §4.2), a first packet of at most
//! [`MAX_PACKET`] bytes. It depends on nothing else, so that it can be
//! fuzzed alone. [`stream`] applies it to a connection and replays the bytes
//! read, unchanged.

pub mod stream;

use crate::algorithms;

/// Longest identification line, CR LF included (RFC 4253 §4.2).
pub const MAX_LINE: usize = 255;
/// Lines a server may send before its identification line.
pub const MAX_PREFACE_LINES: usize = 16;
/// Largest first packet accepted (`packet_length`). A KEXINIT from OpenSSH
/// 9.x is about 1.5 KiB.
pub const MAX_PACKET: usize = 16 * 1024;
/// Longest algorithm name (RFC 4251 §6).
const MAX_NAME: usize = 64;
/// `SSH_MSG_KEXINIT`.
const MSG_KEXINIT: u8 = 20;

/// Which end of the connection we are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// We are the server: the peer is a client.
    Server,
    /// We are the client: the peer is a server.
    Client,
}

impl Role {
    /// The strict KEX marker the peer must offer.
    pub fn peer_strict_marker(self) -> &'static str {
        match self {
            Self::Server => algorithms::STRICT_KEX_CLIENT,
            Self::Client => algorithms::STRICT_KEX_SERVER,
        }
    }

    /// For events.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Client => "client",
        }
    }
}

/// Why the peer is refused. Codes are stable: never renumber or reuse one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrecheckError {
    /// Invalid identification line.
    #[error("[SSH-E001] ligne d'identification SSH invalide : {0}")]
    Banner(&'static str),
    /// Invalid first packet.
    #[error("[SSH-E002] premier paquet SSH invalide : {0}")]
    Packet(&'static str),
    /// Nothing complete within the deadline.
    #[error("[SSH-E003] identification et KEXINIT du pair non reçus à temps")]
    Timeout,
    /// No strict KEX (CVE-2023-48795).
    #[error("[SSH-E004] le pair ne propose pas le strict KEX ({0}) : refusé")]
    NoStrictKex(&'static str),
    /// No frozen algorithm offered for one kind.
    #[error("[SSH-E005] aucun algorithme commun pour {kind} (attendu : {expected})")]
    NoCommonAlgorithm {
        /// Algorithm kind.
        kind: &'static str,
        /// What the frozen list requires.
        expected: &'static str,
    },
    /// The connection failed or closed early.
    #[error("[SSH-E006] connexion interrompue avant la négociation : {0}")]
    Io(String),
}

impl PrecheckError {
    /// The stable code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Banner(_) => "SSH-E001",
            Self::Packet(_) => "SSH-E002",
            Self::Timeout => "SSH-E003",
            Self::NoStrictKex(_) => "SSH-E004",
            Self::NoCommonAlgorithm { .. } => "SSH-E005",
            Self::Io(_) => "SSH-E006",
        }
    }
}

/// The name-lists of a KEXINIT, in protocol order (RFC 4253 §7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KexInit<'a> {
    /// Key exchange algorithms (and extension markers).
    pub kex: Vec<&'a str>,
    /// Host key algorithms.
    pub host_key: Vec<&'a str>,
    /// Ciphers, client to server.
    pub cipher_c2s: Vec<&'a str>,
    /// Ciphers, server to client.
    pub cipher_s2c: Vec<&'a str>,
    /// MACs, client to server.
    pub mac_c2s: Vec<&'a str>,
    /// MACs, server to client.
    pub mac_s2c: Vec<&'a str>,
    /// Compression, client to server.
    pub compression_c2s: Vec<&'a str>,
    /// Compression, server to client.
    pub compression_s2c: Vec<&'a str>,
    /// A guessed key exchange packet follows.
    pub first_kex_follows: bool,
}

/// Where the inspection stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    /// More bytes are needed.
    NeedMore,
    /// The identification line and the first packet are complete and
    /// accepted; they span `consumed` bytes.
    Accepted {
        /// Bytes of the identification (and preface) and the first packet.
        consumed: usize,
    },
}

/// Inspects what the peer sent so far. Pure: call it again with more bytes
/// after [`Progress::NeedMore`].
///
/// # Errors
///
/// The [`PrecheckError`] that refuses the peer.
pub fn inspect(buf: &[u8], role: Role) -> Result<Progress, PrecheckError> {
    let Some(packet_start) = identification(buf, role)? else {
        return Ok(Progress::NeedMore);
    };
    let rest = &buf[packet_start..];
    let Some((payload, len)) = packet(rest)? else {
        return Ok(Progress::NeedMore);
    };
    let kexinit = parse_kexinit(payload)?;
    check(&kexinit, role)?;
    Ok(Progress::Accepted {
        consumed: packet_start + len,
    })
}

/// Finds the end of the identification line (after any preface lines from
/// a server); `None` while incomplete.
///
/// # Errors
///
/// [`PrecheckError::Banner`].
pub fn identification(buf: &[u8], role: Role) -> Result<Option<usize>, PrecheckError> {
    let mut start = 0;
    for line_number in 0.. {
        let rest = &buf[start..];
        let window = &rest[..rest.len().min(MAX_LINE)];
        let Some(lf) = window.iter().position(|&b| b == b'\n') else {
            if rest.len() >= MAX_LINE {
                return Err(PrecheckError::Banner("ligne de plus de 255 octets"));
            }
            return Ok(None);
        };
        let line = &rest[..=lf];
        if line.len() < 2 || line[line.len() - 2] != b'\r' {
            return Err(PrecheckError::Banner("ligne non terminée par CR LF"));
        }
        let text = &line[..line.len() - 2];
        if text.starts_with(b"SSH-") {
            if !text.starts_with(b"SSH-2.0-") {
                return Err(PrecheckError::Banner("version du protocole autre que 2.0"));
            }
            if text.len() == 8 || !text.iter().all(|&b| (0x20..=0x7e).contains(&b)) {
                return Err(PrecheckError::Banner(
                    "logiciel absent ou caractère non imprimable",
                ));
            }
            return Ok(Some(start + line.len()));
        }
        // Only a server may send lines before its identification.
        if role == Role::Server {
            return Err(PrecheckError::Banner(
                "le client doit commencer par SSH-2.0-",
            ));
        }
        if line_number + 1 >= MAX_PREFACE_LINES {
            return Err(PrecheckError::Banner(
                "trop de lignes avant l'identification",
            ));
        }
        start += line.len();
    }
    unreachable!("the loop returns")
}

/// An unencrypted binary packet (RFC 4253 §6): its payload and total length;
/// `None` while incomplete.
fn packet(buf: &[u8]) -> Result<Option<(&[u8], usize)>, PrecheckError> {
    let Some(header) = buf.get(..5) else {
        return Ok(None);
    };
    let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    let padding = usize::from(header[4]);
    if length > MAX_PACKET {
        return Err(PrecheckError::Packet("paquet trop grand"));
    }
    if !(length + 4).is_multiple_of(8) {
        return Err(PrecheckError::Packet("longueur non multiple de 8"));
    }
    if padding < 4 || padding + 1 >= length {
        return Err(PrecheckError::Packet("bourrage invalide"));
    }
    let Some(body) = buf.get(5..4 + length) else {
        return Ok(None);
    };
    let payload = &body[..length - 1 - padding];
    Ok(Some((payload, 4 + length)))
}

/// Reads one name-list.
fn name_list<'a>(input: &mut &'a [u8]) -> Result<Vec<&'a str>, PrecheckError> {
    let bad = PrecheckError::Packet("liste de noms invalide");
    let len_bytes = input.get(..4).ok_or_else(|| bad.clone())?;
    let len = u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
    let bytes = input.get(4..4 + len).ok_or_else(|| bad.clone())?;
    *input = &input[4 + len..];
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| bad.clone())?;
    text.split(',')
        .map(|name| {
            let ok = !name.is_empty()
                && name.len() <= MAX_NAME
                && name.bytes().all(|b| (0x21..=0x7e).contains(&b));
            if ok { Ok(name) } else { Err(bad.clone()) }
        })
        .collect()
}

/// Parses a KEXINIT payload (RFC 4253 §7.1), with nothing left over.
///
/// # Errors
///
/// [`PrecheckError::Packet`].
pub fn parse_kexinit(payload: &[u8]) -> Result<KexInit<'_>, PrecheckError> {
    let (&kind, rest) = payload
        .split_first()
        .ok_or(PrecheckError::Packet("charge utile vide"))?;
    if kind != MSG_KEXINIT {
        return Err(PrecheckError::Packet(
            "le premier paquet n'est pas un KEXINIT",
        ));
    }
    let mut input = rest
        .get(16..)
        .ok_or(PrecheckError::Packet("cookie tronqué"))?;
    let kex = name_list(&mut input)?;
    let host_key = name_list(&mut input)?;
    let cipher_c2s = name_list(&mut input)?;
    let cipher_s2c = name_list(&mut input)?;
    let mac_c2s = name_list(&mut input)?;
    let mac_s2c = name_list(&mut input)?;
    let compression_c2s = name_list(&mut input)?;
    let compression_s2c = name_list(&mut input)?;
    // Languages, client to server and server to client: read and ignored.
    name_list(&mut input)?;
    name_list(&mut input)?;
    let [follows, _, _, _, _] = *input else {
        return Err(PrecheckError::Packet("fin du KEXINIT invalide"));
    };
    if follows > 1 {
        return Err(PrecheckError::Packet("booléen invalide"));
    }
    Ok(KexInit {
        kex,
        host_key,
        cipher_c2s,
        cipher_s2c,
        mac_c2s,
        mac_s2c,
        compression_c2s,
        compression_s2c,
        first_kex_follows: follows == 1,
    })
}

/// Applies the frozen list to what the peer offers.
///
/// # Errors
///
/// [`PrecheckError::NoStrictKex`] or [`PrecheckError::NoCommonAlgorithm`].
pub fn check(offer: &KexInit<'_>, role: Role) -> Result<(), PrecheckError> {
    let marker = role.peer_strict_marker();
    if !offer.kex.contains(&marker) {
        return Err(PrecheckError::NoStrictKex(marker));
    }
    let require = |list: &[&str], wanted: &[&'static str], kind: &'static str, expected| {
        if list.iter().any(|name| wanted.contains(name)) {
            Ok(())
        } else {
            Err(PrecheckError::NoCommonAlgorithm { kind, expected })
        }
    };
    require(
        &offer.kex,
        &[algorithms::KEX],
        "l'échange de clés",
        algorithms::KEX,
    )?;
    require(
        &offer.host_key,
        &[algorithms::HOST_KEY, algorithms::HOST_KEY_CERTIFICATE],
        "la clé hôte",
        algorithms::HOST_KEY,
    )?;
    require(
        &offer.cipher_c2s,
        &[algorithms::CIPHER],
        "le chiffrement client vers serveur",
        algorithms::CIPHER,
    )?;
    require(
        &offer.cipher_s2c,
        &[algorithms::CIPHER],
        "le chiffrement serveur vers client",
        algorithms::CIPHER,
    )?;
    require(
        &offer.compression_c2s,
        &["none"],
        "la compression client vers serveur",
        "none",
    )?;
    require(
        &offer.compression_s2c,
        &["none"],
        "la compression serveur vers client",
        "none",
    )
}

#[cfg(test)]
mod tests;
