//! The browser gateway (ADR-0020, § 4): the WebSocket `/api/v1/gateway`,
//! authenticated by the cookie of the browser session and by the grant the
//! portal obtained from `POST /api/v1/access`, relayed to the agent over a
//! browser stream of the tunnel ([`ostena_tunnel::browser`]).
//!
//! The core is the first to receive what the browser sends: each WebSocket
//! message must be exactly one `ostena-frame` frame towards the gateway,
//! decoded and checked (bounds, consecutive sequence) before it is relayed
//! unchanged. Towards the browser, only the header of each frame is
//! checked. Each session has a bounded queue towards the browser: when it is
//! full, the core stops reading the tunnel stream and the flow control of
//! the stream slows the agent down. A browser that reads nothing for the
//! stall delay is closed (`GTW-E004`, close code 4003).

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

use ostena_frame::{Direction, FrameType, HEADER_LEN, Header, Payload, Receiver, decode_message};
use ostena_tunnel::browser::{self, Answer};
use ostena_tunnel::{Channel, ChannelRecv, ChannelSend, CoreTunnel, StreamClass, Uuid};
use ostena_ws::{CloseCode, Event, Opcode, Parser};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch};

/// The sub-protocol of the frames, the only one the `101` selects.
pub const FRAME_PROTOCOL: &str = "ostena-frame.v1";

/// Prefix of the sub-protocol that carries the grant (never the URL).
pub const GRANT_PREFIX: &str = "ostena-grant.";

/// Frames waiting for the browser, per session.
pub const TO_BROWSER_QUEUE: usize = 64;

/// A browser that reads nothing for this long is closed (`GTW-E004`).
pub const STALL: Duration = Duration::from_secs(30);

/// Close code of a browser too slow (ADR-0020).
pub const STALLED: CloseCode = CloseCode(4003);

/// Reads from the browser and from the tunnel.
const READ_BUFFER: usize = 16 * 1024;

/// The gateway sessions of each login session, cut when it is revoked.
#[derive(Debug, Default)]
pub struct Relays(Mutex<HashMap<Uuid, watch::Sender<bool>>>);

impl Relays {
    /// The signal that cuts the gateway sessions of `login_session`.
    pub fn watch(&self, login_session: Uuid) -> watch::Receiver<bool> {
        let Ok(mut map) = self.0.lock() else {
            // A poisoned registry cuts at once rather than never.
            return watch::channel(true).1;
        };
        map.retain(|_, sender| sender.receiver_count() > 0);
        map.entry(login_session)
            .or_insert_with(|| watch::channel(false).0)
            .subscribe()
    }

    /// Cuts the gateway sessions of `login_session`; returns how many.
    pub fn cut(&self, login_session: Uuid) -> usize {
        let sender = self
            .0
            .lock()
            .ok()
            .and_then(|mut m| m.remove(&login_session));
        sender.map_or(0, |s| {
            let _ = s.send(true);
            s.receiver_count()
        })
    }

    /// Gateway sessions open.
    pub fn open(&self) -> usize {
        self.0
            .lock()
            .map_or(0, |m| m.values().map(watch::Sender::receiver_count).sum())
    }
}

/// A gateway session accepted: the agent opened the session.
#[derive(Debug)]
pub struct GatewayStream {
    /// Session identifier given by the core to the agent.
    pub session: Uuid,
    /// The jti of the grant.
    pub jti: Uuid,
    /// The agent that serves it.
    pub agent: Uuid,
    /// The browser stream of the tunnel.
    pub channel: Channel,
    /// Turns `true` when the login session is revoked.
    pub cut: watch::Receiver<bool>,
}

/// How the agent answered a browser stream.
#[derive(Debug)]
pub enum Opening {
    /// Opened: the session and the stream.
    Opened(Uuid, Channel),
    /// Refused by the agent, with its code.
    Refused(String),
}

/// Opens a browser stream to the agent of `tunnel` and presents `grant`
/// (the stream is identified by `jti` in the tunnel header).
///
/// # Errors
///
/// The tunnel or the stream fails, or the agent does not answer in time.
pub async fn open_stream(
    tunnel: &CoreTunnel,
    jti: Uuid,
    grant: &str,
) -> Result<Opening, ostena_tunnel::TunnelError> {
    let mut channel = tunnel.open_channel(jti, StreamClass::Interactive).await?;
    channel
        .send
        .write_all(&browser::encode_open(grant)?)
        .await
        .map_err(|e| ostena_tunnel::TunnelError::ConnectionLost(e.to_string()))?;
    Ok(match browser::read_answer(&mut channel.recv).await? {
        Answer::Opened { session } => Opening::Opened(session, channel),
        Answer::Refused { code } => Opening::Refused(code),
    })
}

/// How a relay ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relayed {
    /// Why, in French.
    pub reason: &'static str,
    /// The stable code, for an end the core decided.
    pub code: Option<&'static str>,
    /// Bytes of frames received from the browser and relayed.
    pub from_browser: u64,
    /// Bytes of frames relayed to the browser.
    pub to_browser: u64,
}

/// What the writer sends to the browser.
enum Out {
    Frame(Vec<u8>),
    Pong(Vec<u8>),
    Close(CloseCode, &'static str),
}

/// Why one side of the relay ended: reason, code, close code.
type Ending = (&'static str, Option<&'static str>, CloseCode);

/// Relays the WebSocket `io` and the browser stream `channel` until one
/// side ends, the login session is revoked (`cut`) or the browser stalls
/// for `stall`. `touch` is called on each frame from the browser.
pub async fn relay<IO>(
    io: IO,
    channel: Channel,
    mut cut: watch::Receiver<bool>,
    stall: Duration,
    touch: impl Fn() + Send,
) -> Relayed
where
    IO: AsyncRead + AsyncWrite + Send,
{
    let (reader, writer) = tokio::io::split(io);
    let Channel { send, recv, .. } = channel;
    let counts = (AtomicU64::new(0), AtomicU64::new(0));
    // The version the agent chose (its HelloAck), 0 before: the frames of
    // the browser carry it once negotiated.
    let negotiated = AtomicU8::new(0);
    let (tx, rx) = mpsc::channel(TO_BROWSER_QUEUE);
    let writing = write_loop(writer, rx, stall);
    let up = uplink(reader, send, tx.clone(), (&counts.0, &negotiated), touch);
    let down = downlink(recv, tx.clone(), (&counts.1, &negotiated));
    tokio::pin!(writing, up, down);
    let (mut up_done, mut down_done) = (false, false);
    let mut ending: Option<Ending> = None;
    let stalled = loop {
        tokio::select! {
            stalled = &mut writing => break stalled,
            end = &mut up, if !up_done => {
                up_done = true;
                ending.get_or_insert(end);
                let _ = tx.try_send(Out::Close(end.2, end.0));
            }
            end = &mut down, if !down_done => {
                down_done = true;
                ending.get_or_insert(end);
                let _ = tx.try_send(Out::Close(end.2, end.0));
            }
            changed = cut.changed(), if ending.is_none() => {
                if changed.is_err() || *cut.borrow() {
                    let end = ("session de connexion révoquée", Some("WEB-E001"), CloseCode::POLICY);
                    ending = Some(end);
                    let _ = tx.try_send(Out::Close(end.2, end.0));
                }
            }
        }
    };
    let (reason, code, _) = if stalled {
        ("navigateur trop lent", Some("GTW-E004"), STALLED)
    } else {
        ending.unwrap_or(("WebSocket fermée", None, CloseCode::NORMAL))
    };
    Relayed {
        reason,
        code,
        from_browser: counts.0.load(Ordering::Relaxed),
        to_browser: counts.1.load(Ordering::Relaxed),
    }
}

/// Writes to the browser until a close is sent; `true` if the browser
/// stalled for `stall` (then closed with 4003 when possible).
async fn write_loop<W: AsyncWrite>(
    writer: W,
    mut rx: mpsc::Receiver<Out>,
    stall: Duration,
) -> bool {
    tokio::pin!(writer);
    let mut buf = Vec::with_capacity(READ_BUFFER);
    while let Some(out) = rx.recv().await {
        buf.clear();
        let last = match &out {
            Out::Frame(frame) => {
                ostena_ws::frame::encode(Opcode::Binary, frame, &mut buf);
                false
            }
            Out::Pong(data) => {
                ostena_ws::frame::encode(Opcode::Pong, data, &mut buf);
                false
            }
            Out::Close(code, reason) => {
                ostena_ws::frame::encode_close(*code, reason, &mut buf);
                true
            }
        };
        let written = async {
            writer.write_all(&buf).await?;
            writer.flush().await
        };
        match tokio::time::timeout(stall, written).await {
            Ok(Ok(())) if !last => {}
            Ok(_) => return false,
            Err(_) => {
                buf.clear();
                ostena_ws::frame::encode_close(STALLED, "GTW-E004", &mut buf);
                let _ = tokio::time::timeout(Duration::from_secs(1), writer.write_all(&buf)).await;
                return true;
            }
        }
    }
    false
}

/// Browser → agent: each message decoded as one frame towards the gateway,
/// in sequence, then written to the stream (whose flow control applies).
async fn uplink<R: AsyncRead>(
    reader: R,
    mut send: ChannelSend,
    tx: mpsc::Sender<Out>,
    (relayed, negotiated): (&AtomicU64, &AtomicU8),
    touch: impl Fn(),
) -> Ending {
    tokio::pin!(reader);
    let mut parser = Parser::default();
    let mut frames = Receiver::default();
    let mut buf = vec![0u8; READ_BUFFER];
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) | Err(_) => {
                let _ = send.finish();
                return (
                    "WebSocket coupée par le navigateur",
                    None,
                    CloseCode::GOING_AWAY,
                );
            }
            Ok(n) => n,
        };
        let mut input = &buf[..n];
        while !input.is_empty() {
            let (used, event) = match parser.parse(input) {
                Ok(parsed) => parsed,
                Err(e) => {
                    let _ = send.finish();
                    return (
                        "message WebSocket invalide",
                        Some("GTW-E005"),
                        e.close_code(),
                    );
                }
            };
            if used == 0 {
                break;
            }
            input = &input[used..];
            match event {
                None | Some(Event::Pong(_)) => {}
                Some(Event::Binary(message)) => {
                    if frames.version().is_none() {
                        let version = negotiated.load(Ordering::Acquire);
                        if version != 0 {
                            frames.set_version(version);
                        }
                    }
                    let checked = decode_message(message, Direction::ToGateway)
                        .and_then(|frame| frames.accept(&frame));
                    if checked.is_err() {
                        let _ = send.finish();
                        return ("trame refusée", Some("GTW-E005"), CloseCode::PROTOCOL);
                    }
                    touch();
                    if send.write_all(message).await.is_err() {
                        return ("flux de l'agent perdu", None, CloseCode::GOING_AWAY);
                    }
                    relayed.fetch_add(message.len() as u64, Ordering::Relaxed);
                }
                Some(Event::Ping(data)) => {
                    let _ = tx.try_send(Out::Pong(data.to_vec()));
                }
                Some(Event::Close(_)) => {
                    let _ = send.finish();
                    return (
                        "WebSocket fermée par le navigateur",
                        None,
                        CloseCode::NORMAL,
                    );
                }
            }
        }
    }
}

/// Agent → browser: frames cut from the stream by their header (checked),
/// queued for the browser; a full queue stops the reading.
async fn downlink(
    mut recv: ChannelRecv,
    tx: mpsc::Sender<Out>,
    (relayed, negotiated): (&AtomicU64, &AtomicU8),
) -> Ending {
    let mut pending: Vec<u8> = Vec::with_capacity(READ_BUFFER);
    let mut buf = vec![0u8; READ_BUFFER];
    loop {
        while pending.len() >= HEADER_LEN {
            let Ok(header) = Header::parse(&pending, Direction::ToBrowser) else {
                return (
                    "trame de l'agent refusée",
                    Some("GTW-E005"),
                    CloseCode::INTERNAL,
                );
            };
            let end = HEADER_LEN + usize::from(header.length);
            if pending.len() < end {
                break;
            }
            let rest = pending.split_off(end);
            let frame = std::mem::replace(&mut pending, rest);
            // Known before the browser can answer it.
            if header.frame_type == FrameType::HelloAck
                && let Ok(decoded) = decode_message(&frame, Direction::ToBrowser)
                && let Payload::HelloAck { version, .. } = decoded.payload
            {
                negotiated.store(version, Ordering::Release);
            }
            relayed.fetch_add(frame.len() as u64, Ordering::Relaxed);
            if tx.send(Out::Frame(frame)).await.is_err() {
                return ("WebSocket fermée", None, CloseCode::NORMAL);
            }
        }
        match recv.read(&mut buf).await {
            Ok(Some(n)) => pending.extend_from_slice(&buf[..n]),
            Ok(None) if pending.is_empty() => {
                return ("session terminée par l'agent", None, CloseCode::NORMAL);
            }
            Ok(None) => {
                return (
                    "trame de l'agent tronquée",
                    Some("GTW-E005"),
                    CloseCode::INTERNAL,
                );
            }
            Err(_) => return ("flux de l'agent perdu", None, CloseCode::GOING_AWAY),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relays_are_cut_by_login_session() {
        let relays = Relays::default();
        let (a, b) = (Uuid::from_bytes([1; 16]), Uuid::from_bytes([2; 16]));
        let first = relays.watch(a);
        let second = relays.watch(a);
        let other = relays.watch(b);
        assert_eq!(relays.open(), 3);
        assert_eq!(relays.cut(a), 2);
        assert!(*first.borrow() && *second.borrow() && !*other.borrow());
        assert_eq!(relays.cut(a), 0);
        drop(other);
        let _again = relays.watch(a);
        // The entry of `b` without receivers is pruned.
        assert_eq!(relays.open(), 1);
    }
}
