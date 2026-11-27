//! Browser streams (ADR-0020, § 4): the core opens one tunnel channel per
//! browser session, towards the agent of the group it chose when it issued
//! the grant.
//!
//! On the channel, after the tunnel header:
//!
//! - core → agent: `[version = 1][grant length, u16 big endian][grant]`,
//!   the grant in text form (ADR-0004) as the browser presented it;
//! - agent → core: `[status][text length, u8][text]`: status 0 and the
//!   session identifier the core gave (`opened`), or status 1 and the code
//!   of the refusal (`refused`, the stream then ends);
//! - then `ostena-frame` frames back to back, self-delimiting, in both
//!   directions, until one side finishes its half.
//!
//! The core opens the channel with the class [`StreamClass::Interactive`]:
//! the keyboard and mouse inputs of the browser go first towards the
//! agent. The agent sends its half with the class [`StreamClass::Display`],
//! below the interactive streams and the transcripts. Backpressure is the
//! flow control of the stream: a reader that stops reading stops the
//! writer at the other end.
//!
//! The agent verifies the grant and consumes its jti like for any other
//! session, asks the core (`session_request`), then hands the session to a
//! [`BrowserDriver`]; at the end, it reports the session (`session_closed`).

use std::future::Future;
use std::time::Duration;

use ostena_grant::{Protocol, ReplayStore};

use crate::channel::StreamClass;
use crate::error::TunnelError;
use crate::gateway::{Gateway, Session, SessionError};
use crate::ids::Uuid;
use crate::transport::{ChannelRecv, ChannelSend};
use crate::tunnel::Channel;

/// Version of the opening message.
pub const VERSION: u8 = 1;

/// Longest grant accepted on a browser stream (the text form is 246 bytes).
pub const MAX_GRANT: usize = 512;

/// Longest wait for the opening message, then for the answer of the agent
/// (which includes the round trip of `session_request` to the core).
pub const OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// Status byte of an opened session.
const OPENED: u8 = 0;
/// Status byte of a refusal.
const REFUSED: u8 = 1;

/// The opening message for `grant`.
///
/// # Errors
///
/// [`TunnelError::Protocol`] for an empty grant or one over [`MAX_GRANT`].
pub fn encode_open(grant: &str) -> Result<Vec<u8>, TunnelError> {
    let len = u16::try_from(grant.len())
        .ok()
        .filter(|&l| l > 0 && usize::from(l) <= MAX_GRANT)
        .ok_or_else(|| TunnelError::Protocol("grant de taille invalide".into()))?;
    let mut out = Vec::with_capacity(3 + grant.len());
    out.push(VERSION);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(grant.as_bytes());
    Ok(out)
}

/// Decodes a complete opening message.
///
/// # Errors
///
/// [`TunnelError::Version`] for another version, [`TunnelError::Protocol`]
/// for a bad length or a grant that is not ASCII.
pub fn decode_open(bytes: &[u8]) -> Result<String, TunnelError> {
    let (&version, rest) = bytes
        .split_first()
        .ok_or_else(|| TunnelError::Protocol("ouverture vide".into()))?;
    if version != VERSION {
        return Err(TunnelError::Version(u16::from(version)));
    }
    let (len, grant) = rest
        .split_first_chunk::<2>()
        .ok_or_else(|| TunnelError::Protocol("ouverture tronquée".into()))?;
    let len = usize::from(u16::from_be_bytes(*len));
    if len == 0 || len > MAX_GRANT || grant.len() != len || !grant.is_ascii() {
        return Err(TunnelError::Protocol("grant de taille invalide".into()));
    }
    String::from_utf8(grant.to_vec()).map_err(|_| TunnelError::Protocol("grant non ASCII".into()))
}

/// Reads the opening message within [`OPEN_TIMEOUT`].
///
/// # Errors
///
/// As [`decode_open`], or [`TunnelError::Protocol`] for a stream that ends
/// or a message that does not come in time.
pub async fn read_open(recv: &mut ChannelRecv) -> Result<String, TunnelError> {
    let read = async {
        let mut head = [0u8; 3];
        recv.read_exact(&mut head).await?;
        let len = usize::from(u16::from_be_bytes([head[1], head[2]]));
        if head[0] != VERSION || len == 0 || len > MAX_GRANT {
            return Ok(head.to_vec());
        }
        let mut message = vec![0u8; 3 + len];
        message[..3].copy_from_slice(&head);
        recv.read_exact(&mut message[3..]).await?;
        Ok::<_, crate::StreamError>(message)
    };
    match tokio::time::timeout(OPEN_TIMEOUT, read).await {
        Ok(Ok(message)) => decode_open(&message),
        Ok(Err(e)) => Err(TunnelError::Protocol(format!("ouverture : {e}"))),
        Err(_) => Err(TunnelError::Protocol("ouverture non reçue à temps".into())),
    }
}

/// The answer of the agent to an opening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// Session opened by the core, with this identifier.
    Opened {
        /// Session identifier.
        session: Uuid,
    },
    /// Refused, with this stable code.
    Refused {
        /// Code of the refusal (`GTW-E006`, `GRT-E…`, `TUN-E…`, `ACC-E…`…).
        code: String,
    },
}

impl Answer {
    /// The answer on the wire.
    pub fn encode(&self) -> Vec<u8> {
        let (status, text) = match self {
            Self::Opened { session } => (OPENED, session.to_string()),
            Self::Refused { code } => (REFUSED, code.clone()),
        };
        let text = &text.as_bytes()[..text.len().min(usize::from(u8::MAX))];
        let mut out = Vec::with_capacity(2 + text.len());
        out.push(status);
        out.push(u8::try_from(text.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(text);
        out
    }

    /// Decodes a complete answer.
    ///
    /// # Errors
    ///
    /// [`TunnelError::Protocol`] for an unknown status, a bad length or a
    /// text that is not a session identifier or a code.
    pub fn decode(bytes: &[u8]) -> Result<Self, TunnelError> {
        let bad = || TunnelError::Protocol("réponse du flux navigateur invalide".into());
        let [status, len, text @ ..] = bytes else {
            return Err(bad());
        };
        if text.len() != usize::from(*len) {
            return Err(bad());
        }
        let text = std::str::from_utf8(text).map_err(|_| bad())?;
        match *status {
            OPENED => Uuid::parse(text)
                .map(|session| Self::Opened { session })
                .ok_or_else(bad),
            REFUSED if is_code(text) => Ok(Self::Refused {
                code: text.to_owned(),
            }),
            _ => Err(bad()),
        }
    }
}

/// A stable code: `ABC-E001`, or `ABCD-P010`.
fn is_code(text: &str) -> bool {
    let Some((prefix, number)) = text.split_once('-') else {
        return false;
    };
    (2..=5).contains(&prefix.len())
        && prefix.bytes().all(|b| b.is_ascii_uppercase())
        && number.len() == 4
        && number.as_bytes()[0].is_ascii_uppercase()
        && number.bytes().skip(1).all(|b| b.is_ascii_digit())
}

/// Reads the answer of the agent within [`OPEN_TIMEOUT`].
///
/// # Errors
///
/// As [`Answer::decode`], or [`TunnelError::Protocol`] for a stream that
/// ends or an answer that does not come in time.
pub async fn read_answer(recv: &mut ChannelRecv) -> Result<Answer, TunnelError> {
    let read = async {
        let mut head = [0u8; 2];
        recv.read_exact(&mut head).await?;
        let mut message = vec![0u8; 2 + usize::from(head[1])];
        message[..2].copy_from_slice(&head);
        recv.read_exact(&mut message[2..]).await?;
        Ok::<_, crate::StreamError>(message)
    };
    match tokio::time::timeout(OPEN_TIMEOUT, read).await {
        Ok(Ok(message)) => Answer::decode(&message),
        Ok(Err(e)) => Err(TunnelError::Protocol(format!("réponse : {e}"))),
        Err(_) => Err(TunnelError::Protocol("réponse non reçue à temps".into())),
    }
}

/// How a browser session ended, for the report to the core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ended {
    /// Why, in French.
    pub reason: String,
    /// Bytes sent to the target.
    pub bytes_to_target: u64,
    /// Bytes received from the target.
    pub bytes_from_target: u64,
}

/// What serves browser sessions on the agent: the protocol drivers that
/// turn an `ostena-frame` stream into a session on the target.
pub trait BrowserDriver: Send + Sync + 'static {
    /// Whether this agent serves `protocol` in the browser.
    fn serves(&self, protocol: Protocol) -> bool;

    /// Runs `session` over the browser stream until it ends.
    fn run(&self, session: Session, channel: Channel) -> impl Future<Output = Ended> + Send;
}

/// No protocol served in the browser: every browser session is refused
/// with `GTW-E006` once its grant is consumed.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoDriver;

impl BrowserDriver for NoDriver {
    fn serves(&self, _: Protocol) -> bool {
        false
    }

    fn run(&self, _: Session, _: Channel) -> impl Future<Output = Ended> + Send {
        std::future::ready(Ended {
            reason: "protocole non servi dans le navigateur".into(),
            bytes_to_target: 0,
            bytes_from_target: 0,
        })
    }
}

/// Serves one browser stream opened by the core: reads the grant, opens the
/// session ([`Gateway::open_browser_session`]), answers, runs `driver`,
/// then reports the end to the core.
pub async fn serve<S: ReplayStore, D: BrowserDriver>(
    gateway: &Gateway,
    channel: Channel,
    store: &S,
    driver: &D,
    now: u64,
) {
    let mut channel = channel;
    let grant = match read_open(&mut channel.recv).await {
        Ok(grant) => grant,
        Err(e) => {
            tracing::warn!(event = "agent.browser_refused", code = e.code(), "{e}");
            let _ = channel.recv.stop(crate::tunnel::CLOSE_ERROR);
            let _ = channel.send.reset(crate::tunnel::CLOSE_ERROR);
            return;
        }
    };
    let session = match gateway
        .open_browser_session(&grant, now, store, |p| driver.serves(p))
        .await
    {
        Ok(session) => session,
        Err(e) => {
            refuse(&mut channel.send, &e).await;
            return;
        }
    };
    let session_id = session.session_id;
    let _ = channel.send.set_priority(StreamClass::Display.priority());
    if let Err(e) = channel
        .send
        .write_all(
            &Answer::Opened {
                session: session_id,
            }
            .encode(),
        )
        .await
    {
        gateway
            .report_closed(session_id, format!("flux navigateur perdu : {e}"), 0, 0)
            .await;
        return;
    }
    tracing::info!(event = "agent.browser_opened", session = %session_id);
    let ended = driver.run(session, channel).await;
    tracing::info!(
        event = "agent.browser_closed",
        session = %session_id,
        bytes_to_target = ended.bytes_to_target,
        bytes_from_target = ended.bytes_from_target,
        "{}",
        ended.reason
    );
    gateway
        .report_closed(
            session_id,
            ended.reason,
            ended.bytes_to_target,
            ended.bytes_from_target,
        )
        .await;
}

async fn refuse(send: &mut ChannelSend, error: &SessionError) {
    let code = error.code();
    tracing::warn!(event = "agent.browser_refused", code = %code, "{error}");
    let _ = send.write_all(&Answer::Refused { code }.encode()).await;
    let _ = send.finish();
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn opening_round_trips_and_is_strict() {
        let grant = "A".repeat(246);
        let open = encode_open(&grant).unwrap();
        assert_eq!(open.len(), 249);
        assert_eq!(decode_open(&open).unwrap(), grant);
        assert!(encode_open("").is_err());
        assert!(encode_open(&"A".repeat(MAX_GRANT + 1)).is_err());
        let mut other = open.clone();
        other[0] = 2;
        assert!(matches!(decode_open(&other), Err(TunnelError::Version(_))));
        assert!(decode_open(&open[..open.len() - 1]).is_err());
        let mut longer = open.clone();
        longer.push(b'A');
        assert!(decode_open(&longer).is_err());
        let mut binary = open;
        binary[10] = 0xff;
        assert!(decode_open(&binary).is_err());
        assert!(decode_open(&[]).is_err());
    }

    #[test]
    fn answers_round_trip_and_are_strict() {
        let session = Uuid::from_bytes([7; 16]);
        for answer in [
            Answer::Opened { session },
            Answer::Refused {
                code: "GTW-E006".into(),
            },
        ] {
            assert_eq!(Answer::decode(&answer.encode()).unwrap(), answer);
        }
        for bad in [
            &b""[..],
            b"\x00",
            b"\x00\x03abc",
            b"\x01\x08gtw-e006",
            b"\x01\x05GTW-E",
            b"\x02\x08GTW-E006",
            b"\x01\x09GTW-E006",
        ] {
            assert!(Answer::decode(bad).is_err(), "{bad:?}");
        }
        assert!(is_code("CFG-P010") && is_code("ACC-E006") && !is_code("ACC-E06"));
    }

    proptest! {
        #[test]
        fn decoders_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
            let _ = decode_open(&bytes);
            let _ = Answer::decode(&bytes);
        }
    }
}
