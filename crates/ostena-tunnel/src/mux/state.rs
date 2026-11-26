//! State of a multiplexed connection, without I/O: the reader feeds it the
//! frames it decodes ([`State::on_frame`]), the streams read and write
//! through it, and the writer drains it ([`State::next_batch`]). Kept free of
//! I/O so that the fuzzer drives it as the network would.
//!
//! **Flow control, end to end.** A writer queues bytes only within the credit
//! the peer granted, for the stream and for the connection; the peer grants
//! more only once its application has read them. What a tunnel buffers is
//! therefore bounded by the windows, as with QUIC, and a reader that stops
//! reading stops its writer, up to the target's TCP window.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Notify;

use super::frame::{self, Frame, MAX_DATA};
use crate::error::TunnelError;
use crate::limits::Limits;

/// Which end of the connection this is: the agent opens odd streams, the
/// core even ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The agent (TCP client).
    Agent,
    /// The core (TCP server).
    Core,
}

impl Side {
    const fn first_stream(self) -> u32 {
        match self {
            Self::Agent => 1,
            Self::Core => 2,
        }
    }

    const fn peer(self) -> Self {
        match self {
            Self::Agent => Self::Core,
            Self::Core => Self::Agent,
        }
    }
}

/// Largest stream count a side may announce: 4096 sessions of four streams
/// and the control stream ([`Limits::validate`]).
const MAX_STREAMS: u32 = 4096 * 4 + 1;

/// Why a stream operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StreamError {
    /// The peer reset its direction with this code.
    #[error("flux réinitialisé par le pair (code {0})")]
    Reset(u32),
    /// The peer asked to stop with this code.
    #[error("flux arrêté par le pair (code {0})")]
    Stopped(u32),
    /// This direction is already finished or reset.
    #[error("flux déjà fermé")]
    Closed,
    /// The stream ended before the bytes expected.
    #[error("fin du flux avant les octets attendus")]
    FinishedEarly,
    /// The connection is gone.
    #[error("connexion perdue : {0}")]
    ConnectionLost(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendEnd {
    Open,
    /// FIN to send once the queue is empty.
    Finishing,
    FinSent,
    FinAcked,
    Reset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecvEnd {
    Open,
    Fin,
    Reset(u32),
    /// We sent STOP: further data is dropped.
    Stopped,
}

#[derive(Debug)]
struct Stream {
    notify: Arc<Notify>,
    priority: i32,
    queue: VecDeque<Vec<u8>>,
    queued: usize,
    send_credit: u64,
    send: SendEnd,
    stopped: Option<u32>,
    buf: VecDeque<Vec<u8>>,
    front: usize,
    unread: usize,
    recv_left: u64,
    consumed: u64,
    recv: RecvEnd,
    send_handle: bool,
    recv_handle: bool,
    by_peer: bool,
}

/// A control frame waiting for the writer.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Control {
    Open(u32),
    Reset(u32, u32),
    Stop(u32, u32),
    Credit(u32, u32),
    FinAck(u32),
}

/// Outcome of a write attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum Write {
    /// So many bytes were queued.
    Queued(usize),
    /// No credit: wait.
    Blocked,
}

/// Outcome of a read attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum Read {
    /// So many bytes were copied.
    Data(usize),
    /// End of the stream.
    Fin,
    /// Nothing yet: wait.
    Blocked,
}

/// The state of one connection.
#[derive(Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent flags of the connection, not a state machine"
)]
pub struct State {
    side: Side,
    local: Limits,
    peer_ready: bool,
    streams: HashMap<u32, Stream>,
    next_local: u32,
    local_opened: u32,
    peer_max_total: u32,
    peer_stream_window: u32,
    next_peer: u32,
    peer_opened: u32,
    local_max_total: u32,
    conn_send_credit: u64,
    conn_recv_left: u64,
    conn_consumed: u64,
    control: VecDeque<Control>,
    max_streams_due: bool,
    pong: Option<u64>,
    ping: Option<(u64, Instant)>,
    ping_sent: bool,
    rtt: Option<Duration>,
    accept: VecDeque<u32>,
    closed: Option<TunnelError>,
    close_frame: Option<(u32, Vec<u8>)>,
    close_sent: bool,
    cursor: u32,
    writer: Arc<Notify>,
    conn: Arc<Notify>,
}

fn violation(what: impl Into<String>) -> Result<(), TunnelError> {
    Err(TunnelError::Protocol(format!(
        "multiplexeur TCP : {}",
        what.into()
    )))
}

impl State {
    /// A new connection state; `writer` wakes the writer task, `conn` the
    /// tasks waiting on the connection (credit, new stream, close).
    pub fn new(side: Side, local: Limits, writer: Arc<Notify>, conn: Arc<Notify>) -> Self {
        Self {
            side,
            local,
            peer_ready: false,
            streams: HashMap::new(),
            next_local: side.first_stream(),
            local_opened: 0,
            peer_max_total: 0,
            peer_stream_window: 0,
            next_peer: side.peer().first_stream(),
            peer_opened: 0,
            local_max_total: local.max_streams(),
            conn_send_credit: 0,
            conn_recv_left: u64::from(local.connection_window),
            conn_consumed: 0,
            control: VecDeque::new(),
            max_streams_due: false,
            pong: None,
            ping: None,
            ping_sent: false,
            rtt: None,
            accept: VecDeque::new(),
            closed: None,
            close_frame: None,
            close_sent: false,
            cursor: 0,
            writer,
            conn,
        }
    }

    /// The settings frame this side sends first.
    pub fn settings(&self) -> Frame<'static> {
        Frame::Settings {
            version: frame::VERSION,
            max_streams: self.local.max_streams(),
            stream_window: self.local.stream_window,
            connection_window: self.local.connection_window,
        }
    }

    /// Whether the peer's settings arrived.
    pub fn peer_ready(&self) -> bool {
        self.peer_ready
    }

    /// Why the connection is closed, if it is.
    pub fn closed(&self) -> Option<&TunnelError> {
        self.closed.as_ref()
    }

    /// Smoothed round-trip time of the pings.
    pub fn rtt(&self) -> Option<Duration> {
        self.rtt
    }

    fn lost_error(&self) -> StreamError {
        StreamError::ConnectionLost(
            self.closed
                .as_ref()
                .map_or_else(|| "fermée".to_owned(), ToString::to_string),
        )
    }

    fn wake_all(&self) {
        for s in self.streams.values() {
            s.notify.notify_waiters();
        }
        self.conn.notify_waiters();
        self.writer.notify_one();
    }

    fn push(&mut self, c: Control) {
        self.control.push_back(c);
        self.writer.notify_one();
    }

    /// Closes the connection on `error`, sending its message to the peer.
    pub fn close(&mut self, error: TunnelError, code: u32) {
        if self.closed.is_some() {
            return;
        }
        let reason = error.to_string().into_bytes();
        let reason = reason[..reason.len().min(frame::MAX_REASON)].to_vec();
        self.close_frame = Some((code, reason));
        self.closed = Some(error);
        self.wake_all();
    }

    /// The connection was lost (I/O error, end of the TCP stream, silence).
    pub fn lost(&mut self, error: TunnelError) {
        if self.closed.is_none() {
            self.closed = Some(error);
        }
        // Nothing more can be written.
        self.close_sent = true;
        self.wake_all();
    }

    /// Whether the writer has nothing more to do.
    pub fn writer_done(&self) -> bool {
        self.closed.is_some() && self.close_sent
    }

    /// Records a ping to send; the next [`State::next_batch`] carries it.
    pub fn ping(&mut self, opaque: u64, now: Instant) {
        if self.ping.is_none() {
            self.ping = Some((opaque, now));
            self.ping_sent = false;
            self.writer.notify_one();
        }
    }

    fn new_stream(&self, by_peer: bool, peer_window: u32) -> Stream {
        Stream {
            notify: Arc::new(Notify::new()),
            priority: 0,
            queue: VecDeque::new(),
            queued: 0,
            send_credit: u64::from(peer_window),
            send: SendEnd::Open,
            stopped: None,
            buf: VecDeque::new(),
            front: 0,
            unread: 0,
            recv_left: u64::from(self.local.stream_window),
            consumed: 0,
            recv: RecvEnd::Open,
            send_handle: true,
            recv_handle: true,
            by_peer,
        }
    }

    // ---- frames from the peer ----

    /// Applies one frame received from the peer.
    ///
    /// # Errors
    ///
    /// [`TunnelError::Protocol`] or [`TunnelError::Version`]: the connection
    /// must be closed with it.
    pub fn on_frame(&mut self, frame: &Frame<'_>, now: Instant) -> Result<(), TunnelError> {
        if self.closed.is_some() {
            return Ok(());
        }
        if !self.peer_ready {
            return self.on_settings(frame);
        }
        match *frame {
            Frame::Settings { .. } => violation("paramètres reçus deux fois"),
            Frame::Open { stream } => self.on_open(stream),
            Frame::Data { stream, payload } => self.on_data(stream, payload),
            Frame::Fin { stream } => self.on_fin(stream),
            Frame::Reset { stream, code } => self.on_reset(stream, code),
            Frame::Stop { stream, code } => self.on_stop(stream, code),
            Frame::Credit { stream, increment } => self.on_credit(stream, increment),
            Frame::FinAck { stream } => self.on_fin_ack(stream),
            Frame::MaxStreams { total } => {
                if total < self.peer_max_total {
                    return violation("limite de flux en baisse");
                }
                self.peer_max_total = total;
                self.conn.notify_waiters();
                Ok(())
            }
            Frame::Ping { opaque } => {
                self.pong = Some(opaque);
                self.writer.notify_one();
                Ok(())
            }
            Frame::Pong { opaque } => {
                if let Some((sent, at)) = self.ping
                    && sent == opaque
                {
                    let sample = now.saturating_duration_since(at);
                    self.rtt = Some(self.rtt.map_or(sample, |r| (r * 7 + sample) / 8));
                    self.ping = None;
                }
                Ok(())
            }
            Frame::Close { reason, .. } => {
                let reason = String::from_utf8_lossy(reason);
                self.closed = Some(TunnelError::from_peer_close(&reason));
                self.close_sent = true;
                self.wake_all();
                Ok(())
            }
        }
    }

    fn on_settings(&mut self, frame: &Frame<'_>) -> Result<(), TunnelError> {
        let Frame::Settings {
            version,
            max_streams,
            stream_window,
            connection_window,
        } = *frame
        else {
            return violation("la première trame n'est pas celle des paramètres");
        };
        if version != frame::VERSION {
            return Err(TunnelError::Version(u16::from(version)));
        }
        let peer = Limits {
            stream_window,
            connection_window,
            ..self.local
        };
        if !(1..=MAX_STREAMS).contains(&max_streams) || peer.validate().is_err() {
            return violation("paramètres du pair hors bornes");
        }
        self.peer_ready = true;
        self.peer_max_total = max_streams;
        self.conn_send_credit = u64::from(connection_window);
        self.peer_stream_window = stream_window;
        self.conn.notify_waiters();
        Ok(())
    }

    fn on_open(&mut self, stream: u32) -> Result<(), TunnelError> {
        if stream != self.next_peer {
            return violation(format!(
                "ouverture du flux {stream}, attendu {}",
                self.next_peer
            ));
        }
        if self.peer_opened >= self.local_max_total {
            return violation("limite de flux dépassée");
        }
        self.peer_opened += 1;
        self.next_peer = self.next_peer.saturating_add(2);
        let entry = self.new_stream(true, self.peer_stream_window);
        self.streams.insert(stream, entry);
        self.accept.push_back(stream);
        self.conn.notify_waiters();
        Ok(())
    }

    /// Whether `stream` was opened once (by either side) and is gone now.
    fn known_closed(&self, stream: u32) -> bool {
        let next = if stream % 2 == self.side.first_stream() % 2 {
            self.next_local
        } else {
            self.next_peer
        };
        stream < next && !self.streams.contains_key(&stream)
    }

    fn take_conn_window(&mut self, len: u64) -> Result<(), TunnelError> {
        if len > self.conn_recv_left {
            return violation("fenêtre de la connexion dépassée");
        }
        self.conn_recv_left -= len;
        Ok(())
    }

    fn release_conn(&mut self, len: u64) {
        self.conn_consumed += len;
        if self.conn_consumed >= u64::from(self.local.connection_window / 4) {
            let increment = u32::try_from(self.conn_consumed).unwrap_or(u32::MAX);
            self.conn_consumed -= u64::from(increment);
            self.conn_recv_left += u64::from(increment);
            self.push(Control::Credit(0, increment));
        }
    }

    fn on_data(&mut self, stream: u32, payload: &[u8]) -> Result<(), TunnelError> {
        let len = payload.len() as u64;
        if self.known_closed(stream) {
            // Sent before our STOP or our end reached the peer.
            self.take_conn_window(len)?;
            self.release_conn(len);
            return Ok(());
        }
        let Some(s) = self.streams.get_mut(&stream) else {
            return violation(format!("données sur le flux {stream} jamais ouvert"));
        };
        match s.recv {
            RecvEnd::Open => {
                if len > s.recv_left {
                    return violation(format!("fenêtre du flux {stream} dépassée"));
                }
                s.recv_left -= len;
                s.unread += payload.len();
                s.buf.push_back(payload.to_vec());
                s.notify.notify_waiters();
                self.take_conn_window(len)
            }
            RecvEnd::Stopped => {
                self.take_conn_window(len)?;
                self.release_conn(len);
                Ok(())
            }
            RecvEnd::Fin | RecvEnd::Reset(_) => {
                violation(format!("données après la fin du flux {stream}"))
            }
        }
    }

    fn on_fin(&mut self, stream: u32) -> Result<(), TunnelError> {
        if self.known_closed(stream) {
            return Ok(());
        }
        let Some(s) = self.streams.get_mut(&stream) else {
            return violation(format!("fin du flux {stream} jamais ouvert"));
        };
        match s.recv {
            RecvEnd::Open => {
                s.recv = RecvEnd::Fin;
                s.notify.notify_waiters();
                self.push(Control::FinAck(stream));
                self.maybe_remove(stream);
                Ok(())
            }
            RecvEnd::Stopped => Ok(()),
            RecvEnd::Fin | RecvEnd::Reset(_) => violation(format!("fin du flux {stream} répétée")),
        }
    }

    fn on_reset(&mut self, stream: u32, code: u32) -> Result<(), TunnelError> {
        if self.known_closed(stream) {
            return Ok(());
        }
        let Some(s) = self.streams.get_mut(&stream) else {
            return violation(format!("réinitialisation du flux {stream} jamais ouvert"));
        };
        match s.recv {
            RecvEnd::Open | RecvEnd::Stopped => {
                let unread = s.unread as u64;
                s.buf.clear();
                s.front = 0;
                s.unread = 0;
                if s.recv == RecvEnd::Open {
                    s.recv = RecvEnd::Reset(code);
                } else {
                    s.recv = RecvEnd::Reset(0);
                }
                s.notify.notify_waiters();
                self.release_conn(unread);
                self.maybe_remove(stream);
                Ok(())
            }
            // A reset after the end may cross our FIN_ACK: harmless.
            RecvEnd::Fin | RecvEnd::Reset(_) => Ok(()),
        }
    }

    fn on_stop(&mut self, stream: u32, code: u32) -> Result<(), TunnelError> {
        if self.known_closed(stream) {
            return Ok(());
        }
        let Some(s) = self.streams.get_mut(&stream) else {
            return violation(format!("arrêt du flux {stream} jamais ouvert"));
        };
        if s.stopped.is_some() {
            return Ok(());
        }
        s.stopped = Some(code);
        s.notify.notify_waiters();
        if matches!(s.send, SendEnd::Open | SendEnd::Finishing) {
            // What was queued and never sent goes back to the connection.
            let unsent = s.queued as u64;
            s.queue.clear();
            s.queued = 0;
            s.send = SendEnd::Reset;
            self.conn_send_credit += unsent;
            self.conn.notify_waiters();
            self.push(Control::Reset(stream, code));
        }
        self.maybe_remove(stream);
        Ok(())
    }

    fn on_credit(&mut self, stream: u32, increment: u32) -> Result<(), TunnelError> {
        if stream == 0 {
            self.conn_send_credit = self.conn_send_credit.saturating_add(u64::from(increment));
            self.conn.notify_waiters();
            return Ok(());
        }
        if self.known_closed(stream) {
            return Ok(());
        }
        let Some(s) = self.streams.get_mut(&stream) else {
            return violation(format!("crédit pour le flux {stream} jamais ouvert"));
        };
        s.send_credit = s.send_credit.saturating_add(u64::from(increment));
        s.notify.notify_waiters();
        Ok(())
    }

    fn on_fin_ack(&mut self, stream: u32) -> Result<(), TunnelError> {
        if self.known_closed(stream) {
            return Ok(());
        }
        let Some(s) = self.streams.get_mut(&stream) else {
            return violation(format!("acquittement du flux {stream} jamais ouvert"));
        };
        if s.send != SendEnd::FinSent {
            return violation(format!("acquittement d'une fin non envoyée ({stream})"));
        }
        s.send = SendEnd::FinAcked;
        s.notify.notify_waiters();
        self.maybe_remove(stream);
        Ok(())
    }

    /// Forgets a stream once both handles are dropped and both directions
    /// are over; a stream the peer opened gives it one more stream.
    fn maybe_remove(&mut self, stream: u32) {
        let Some(s) = self.streams.get(&stream) else {
            return;
        };
        let send_over = matches!(
            s.send,
            SendEnd::FinSent | SendEnd::FinAcked | SendEnd::Reset
        );
        let recv_over = !matches!(s.recv, RecvEnd::Open);
        if s.send_handle || s.recv_handle || !send_over || !recv_over {
            return;
        }
        let by_peer = s.by_peer;
        let unread = s.unread as u64;
        self.streams.remove(&stream);
        self.release_conn(unread);
        if by_peer {
            self.local_max_total = self.local_max_total.saturating_add(1);
            self.max_streams_due = true;
            self.writer.notify_one();
        }
    }

    // ---- local operations ----

    /// Opens a local stream; `None` while the peer's stream limit is
    /// reached (or its settings not received).
    ///
    /// # Errors
    ///
    /// [`StreamError::ConnectionLost`] if the connection is closed.
    pub fn open(&mut self) -> Result<Option<(u32, Arc<Notify>)>, StreamError> {
        if self.closed.is_some() {
            return Err(self.lost_error());
        }
        if !self.peer_ready || self.local_opened >= self.peer_max_total {
            return Ok(None);
        }
        let id = self.next_local;
        self.next_local = self.next_local.saturating_add(2);
        self.local_opened += 1;
        let entry = self.new_stream(false, self.peer_stream_window);
        let notify = entry.notify.clone();
        self.streams.insert(id, entry);
        self.push(Control::Open(id));
        Ok(Some((id, notify)))
    }

    /// The next stream the peer opened, if any.
    ///
    /// # Errors
    ///
    /// [`StreamError::ConnectionLost`] if the connection is closed.
    pub fn accept(&mut self) -> Result<Option<(u32, Arc<Notify>)>, StreamError> {
        while let Some(id) = self.accept.pop_front() {
            if let Some(s) = self.streams.get(&id) {
                return Ok(Some((id, s.notify.clone())));
            }
        }
        if self.closed.is_some() {
            return Err(self.lost_error());
        }
        Ok(None)
    }

    /// Queues up to `data.len()` bytes on `stream`, within the credit.
    ///
    /// # Errors
    ///
    /// The stream or the connection is closed.
    pub fn write(&mut self, stream: u32, data: &[u8]) -> Result<Write, StreamError> {
        if self.closed.is_some() {
            return Err(self.lost_error());
        }
        let conn_credit = self.conn_send_credit;
        let Some(s) = self.streams.get_mut(&stream) else {
            return Err(StreamError::Closed);
        };
        if let Some(code) = s.stopped {
            return Err(StreamError::Stopped(code));
        }
        if s.send != SendEnd::Open {
            return Err(StreamError::Closed);
        }
        let room = s.send_credit.min(conn_credit);
        let n = usize::try_from(room).unwrap_or(usize::MAX).min(data.len());
        if n == 0 {
            return Ok(if data.is_empty() {
                Write::Queued(0)
            } else {
                Write::Blocked
            });
        }
        let mut rest = &data[..n];
        // Fill the last chunk first: small writes share a frame.
        if let Some(last) = s.queue.back_mut() {
            let take = (MAX_DATA - last.len().min(MAX_DATA)).min(rest.len());
            last.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
        }
        for chunk in rest.chunks(MAX_DATA) {
            s.queue.push_back(chunk.to_vec());
        }
        s.queued += n;
        s.send_credit -= n as u64;
        self.conn_send_credit -= n as u64;
        self.writer.notify_one();
        Ok(Write::Queued(n))
    }

    /// Ends the direction once the queued bytes are sent.
    ///
    /// # Errors
    ///
    /// [`StreamError::Closed`] if it is already finished or reset.
    pub fn finish(&mut self, stream: u32) -> Result<(), StreamError> {
        let Some(s) = self.streams.get_mut(&stream) else {
            return Err(StreamError::Closed);
        };
        if s.send != SendEnd::Open {
            return Err(StreamError::Closed);
        }
        s.send = SendEnd::Finishing;
        self.writer.notify_one();
        Ok(())
    }

    /// Abandons the direction with `code`.
    ///
    /// # Errors
    ///
    /// [`StreamError::Closed`] if it is already over.
    pub fn reset(&mut self, stream: u32, code: u32) -> Result<(), StreamError> {
        let Some(s) = self.streams.get_mut(&stream) else {
            return Err(StreamError::Closed);
        };
        if !matches!(s.send, SendEnd::Open | SendEnd::Finishing) {
            return Err(StreamError::Closed);
        }
        let unsent = s.queued as u64;
        s.queue.clear();
        s.queued = 0;
        s.send = SendEnd::Reset;
        s.notify.notify_waiters();
        self.conn_send_credit += unsent;
        self.conn.notify_waiters();
        self.push(Control::Reset(stream, code));
        self.maybe_remove(stream);
        Ok(())
    }

    /// Asks the peer to stop sending, with `code`; what is buffered is
    /// dropped.
    ///
    /// # Errors
    ///
    /// [`StreamError::Closed`] if the direction is already over.
    pub fn stop(&mut self, stream: u32, code: u32) -> Result<(), StreamError> {
        let Some(s) = self.streams.get_mut(&stream) else {
            return Err(StreamError::Closed);
        };
        if s.recv != RecvEnd::Open {
            return Err(StreamError::Closed);
        }
        let unread = s.unread as u64;
        s.buf.clear();
        s.front = 0;
        s.unread = 0;
        s.recv = RecvEnd::Stopped;
        s.notify.notify_waiters();
        self.release_conn(unread);
        self.push(Control::Stop(stream, code));
        self.maybe_remove(stream);
        Ok(())
    }

    /// Copies buffered bytes of `stream` into `out`.
    ///
    /// # Errors
    ///
    /// Reset by the peer, stopped here, or the connection closed.
    pub fn read(&mut self, stream: u32, out: &mut [u8]) -> Result<Read, StreamError> {
        let lost = self.lost_error();
        let closed = self.closed.is_some();
        let Some(s) = self.streams.get_mut(&stream) else {
            return Err(StreamError::Closed);
        };
        if s.unread == 0 || out.is_empty() {
            return match s.recv {
                RecvEnd::Fin => Ok(Read::Fin),
                RecvEnd::Reset(code) => Err(StreamError::Reset(code)),
                RecvEnd::Stopped => Err(StreamError::Closed),
                RecvEnd::Open if closed => Err(lost),
                RecvEnd::Open => Ok(Read::Blocked),
            };
        }
        let mut n = 0;
        while n < out.len() {
            let Some(front) = s.buf.front() else { break };
            let avail = &front[s.front..];
            let take = avail.len().min(out.len() - n);
            out[n..n + take].copy_from_slice(&avail[..take]);
            n += take;
            s.front += take;
            if s.front == front.len() {
                s.buf.pop_front();
                s.front = 0;
            }
        }
        s.unread -= n;
        s.consumed += n as u64;
        let mut credit = None;
        if s.recv == RecvEnd::Open && s.consumed >= u64::from(self.local.stream_window / 2) {
            let increment = u32::try_from(s.consumed).unwrap_or(u32::MAX);
            s.consumed -= u64::from(increment);
            s.recv_left += u64::from(increment);
            credit = Some(increment);
        }
        if let Some(increment) = credit {
            self.push(Control::Credit(stream, increment));
        }
        self.release_conn(n as u64);
        Ok(Read::Data(n))
    }

    /// What `stopped` resolves to, once known: the peer's STOP code, `None`
    /// once the end is acknowledged.
    pub fn stopped(&self, stream: u32) -> Option<Result<Option<u32>, StreamError>> {
        let Some(s) = self.streams.get(&stream) else {
            return Some(Err(StreamError::Closed));
        };
        if let Some(code) = s.stopped {
            return Some(Ok(Some(code)));
        }
        if s.send == SendEnd::FinAcked {
            return Some(Ok(None));
        }
        if self.closed.is_some() {
            return Some(Err(self.lost_error()));
        }
        if s.send == SendEnd::Reset {
            return Some(Err(StreamError::Closed));
        }
        None
    }

    /// Sets the send priority of `stream` (higher first).
    pub fn set_priority(&mut self, stream: u32, priority: i32) {
        if let Some(s) = self.streams.get_mut(&stream) {
            s.priority = priority;
        }
    }

    /// The send priority of `stream`.
    pub fn priority(&self, stream: u32) -> Option<i32> {
        self.streams.get(&stream).map(|s| s.priority)
    }

    /// The send handle of `stream` is dropped: like QUIC, an open direction
    /// is finished.
    pub fn drop_send(&mut self, stream: u32) {
        if let Some(s) = self.streams.get_mut(&stream) {
            s.send_handle = false;
            if s.send == SendEnd::Open && s.stopped.is_none() {
                s.send = SendEnd::Finishing;
                self.writer.notify_one();
            }
        }
        self.maybe_remove(stream);
    }

    /// The receive handle of `stream` is dropped: like QUIC, a direction
    /// not read to its end is stopped (code 0).
    pub fn drop_recv(&mut self, stream: u32) {
        let open = self.streams.get_mut(&stream).is_some_and(|s| {
            s.recv_handle = false;
            s.recv == RecvEnd::Open
        });
        if open && self.closed.is_none() {
            let _ = self.stop(stream, 0);
        }
        self.maybe_remove(stream);
    }

    /// Whether the connection credit is exhausted (for the writers to wait
    /// on the connection as well as on their stream).
    pub fn conn_blocked(&self) -> bool {
        self.conn_send_credit == 0
    }

    // ---- the writer ----

    /// Picks the next stream to serve: highest priority first, round robin
    /// among equals, starting after the last one served.
    fn pick(&self) -> Option<u32> {
        let mut best: Option<(i32, bool, u32)> = None;
        for (&id, s) in &self.streams {
            let ready = !s.queue.is_empty() || (s.send == SendEnd::Finishing);
            if !ready {
                continue;
            }
            // Ids after the cursor come first among equals, then by id.
            let key = (s.priority, id > self.cursor, id);
            let better = match best {
                None => true,
                Some((p, after, bid)) => {
                    key.0 > p || (key.0 == p && ((key.1 && !after) || (key.1 == after && id < bid)))
                }
            };
            if better {
                best = Some(key);
            }
        }
        best.map(|(_, _, id)| id)
    }

    /// Encodes what is due into `out`, up to about `budget` bytes: control
    /// frames first, then stream data by priority, one frame at a time.
    pub fn next_batch(&mut self, out: &mut Vec<u8>, budget: usize) {
        if self.close_sent {
            return;
        }
        if let Some((code, reason)) = self.close_frame.take() {
            frame::encode(
                &Frame::Close {
                    code,
                    reason: &reason,
                },
                out,
            );
            self.close_sent = true;
            return;
        }
        if self.closed.is_some() {
            return;
        }
        if let Some(opaque) = self.pong.take() {
            frame::encode(&Frame::Pong { opaque }, out);
        }
        if let Some((opaque, _)) = self.ping
            && !self.ping_sent
        {
            frame::encode(&Frame::Ping { opaque }, out);
            self.ping_sent = true;
        }
        while let Some(c) = self.control.pop_front() {
            let f = match c {
                Control::Open(stream) => Frame::Open { stream },
                Control::Reset(stream, code) => Frame::Reset { stream, code },
                Control::Stop(stream, code) => Frame::Stop { stream, code },
                Control::Credit(stream, increment) => Frame::Credit { stream, increment },
                Control::FinAck(stream) => Frame::FinAck { stream },
            };
            frame::encode(&f, out);
        }
        while out.len() < budget {
            let Some(id) = self.pick() else { break };
            self.cursor = id;
            let Some(s) = self.streams.get_mut(&id) else {
                break;
            };
            if let Some(chunk) = s.queue.pop_front() {
                s.queued -= chunk.len();
                frame::encode(
                    &Frame::Data {
                        stream: id,
                        payload: &chunk,
                    },
                    out,
                );
                // A writer waits for room in the queue.
                s.notify.notify_waiters();
            } else {
                s.send = SendEnd::FinSent;
                frame::encode(&Frame::Fin { stream: id }, out);
                self.maybe_remove(id);
            }
        }
        // Last: the FINs just sent may have freed streams.
        if self.max_streams_due {
            self.max_streams_due = false;
            frame::encode(
                &Frame::MaxStreams {
                    total: self.local_max_total,
                },
                out,
            );
        }
    }

    /// Streams currently tracked (tests and fuzzing: the state stays
    /// bounded).
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Bytes buffered for reading and queued for sending (tests and
    /// fuzzing).
    pub fn buffered(&self) -> usize {
        self.streams.values().map(|s| s.unread + s.queued).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits {
            max_sessions: 1,
            stream_window: 16 * 1024,
            connection_window: 64 * 1024,
            ..Limits::default()
        }
    }

    fn state(side: Side) -> State {
        let mut s = State::new(side, limits(), Arc::default(), Arc::default());
        let peer = State::new(side.peer(), limits(), Arc::default(), Arc::default());
        s.on_frame(&peer.settings(), Instant::now()).unwrap();
        s
    }

    fn frames(out: &[u8]) -> Vec<Frame<'_>> {
        let mut at = 0;
        let mut v = Vec::new();
        while let Ok(Some((f, used))) = frame::decode(&out[at..]) {
            v.push(f);
            at += used;
        }
        assert_eq!(at, out.len());
        v
    }

    #[test]
    fn higher_priority_overtakes_a_queued_transfer() {
        let mut s = state(Side::Agent);
        let (bulk, _) = s.open().unwrap().unwrap();
        let (keys, _) = s.open().unwrap().unwrap();
        s.set_priority(bulk, 10);
        s.set_priority(keys, 30);
        assert_eq!(s.write(bulk, &[0; 16 * 1024]), Ok(Write::Queued(16 * 1024)));
        assert_eq!(s.write(keys, b"ls\n"), Ok(Write::Queued(3)));
        let mut out = Vec::new();
        s.next_batch(&mut out, 20);
        let f = frames(&out);
        // The two opens, then the keystrokes before any of the transfer.
        assert_eq!(f[0], Frame::Open { stream: bulk });
        assert_eq!(f[1], Frame::Open { stream: keys });
        assert_eq!(
            f[2],
            Frame::Data {
                stream: keys,
                payload: b"ls\n"
            }
        );
        assert_eq!(f.len(), 3, "one data frame per pick within the budget");
    }

    #[test]
    fn equal_priorities_take_turns() {
        let mut s = state(Side::Agent);
        let (a, _) = s.open().unwrap().unwrap();
        let (b, _) = s.open().unwrap().unwrap();
        for id in [a, b] {
            s.write(id, &[1; 8 * 1024]).unwrap();
            s.write(id, &[1; 8 * 1024]).unwrap();
            s.write(id, &[1; 8 * 1024]).unwrap();
        }
        let mut out = Vec::new();
        s.next_batch(&mut out, usize::MAX);
        let order: Vec<u32> = frames(&out)
            .into_iter()
            .filter_map(|f| match f {
                Frame::Data { stream, .. } => Some(stream),
                _ => None,
            })
            .collect();
        // Sixteen KiB per window: one full chunk each, in turn.
        assert_eq!(order, vec![a, b]);
    }

    #[test]
    fn writes_stop_at_the_peer_window() {
        let mut s = state(Side::Agent);
        let (id, _) = s.open().unwrap().unwrap();
        assert_eq!(s.write(id, &vec![0; 20_000]), Ok(Write::Queued(16 * 1024)));
        assert_eq!(s.write(id, b"x"), Ok(Write::Blocked));
        s.on_frame(
            &Frame::Credit {
                stream: id,
                increment: 10,
            },
            Instant::now(),
        )
        .unwrap();
        assert_eq!(s.write(id, &[0; 20]), Ok(Write::Queued(10)));
    }

    #[test]
    fn a_peer_beyond_the_window_is_refused() {
        let mut s = state(Side::Core);
        s.on_frame(&Frame::Open { stream: 1 }, Instant::now())
            .unwrap();
        let chunk = [0u8; MAX_DATA];
        s.on_frame(
            &Frame::Data {
                stream: 1,
                payload: &chunk,
            },
            Instant::now(),
        )
        .unwrap();
        let over = s.on_frame(
            &Frame::Data {
                stream: 1,
                payload: b"x",
            },
            Instant::now(),
        );
        assert!(matches!(over, Err(TunnelError::Protocol(_))), "{over:?}");
    }

    #[test]
    fn reading_returns_credit() {
        let mut s = state(Side::Core);
        let now = Instant::now();
        s.on_frame(&Frame::Open { stream: 1 }, now).unwrap();
        let chunk = [5u8; MAX_DATA];
        s.on_frame(
            &Frame::Data {
                stream: 1,
                payload: &chunk,
            },
            now,
        )
        .unwrap();
        let mut buf = vec![0; MAX_DATA];
        assert_eq!(s.read(1, &mut buf), Ok(Read::Data(MAX_DATA)));
        let mut out = Vec::new();
        s.next_batch(&mut out, usize::MAX);
        let f = frames(&out);
        assert!(f.contains(&Frame::Credit {
            stream: 1,
            increment: 16 * 1024
        }));
        assert!(f.contains(&Frame::Credit {
            stream: 0,
            increment: 16 * 1024
        }));
    }

    #[test]
    fn stream_rules_are_enforced() {
        let now = Instant::now();
        let refused = |frames: &[Frame<'_>]| {
            let mut s = state(Side::Core);
            frames
                .iter()
                .map(|f| s.on_frame(f, now))
                .any(|r| r.is_err())
        };
        // Not the next identifier, wrong parity, never opened.
        assert!(refused(&[Frame::Open { stream: 3 }]));
        assert!(refused(&[Frame::Open { stream: 2 }]));
        assert!(refused(&[Frame::Data {
            stream: 1,
            payload: b"x"
        }]));
        assert!(refused(&[Frame::Fin { stream: 9 }]));
        // Data after the end, end twice, an unsent FIN acknowledged.
        assert!(refused(&[
            Frame::Open { stream: 1 },
            Frame::Fin { stream: 1 },
            Frame::Data {
                stream: 1,
                payload: b"x"
            }
        ]));
        assert!(refused(&[
            Frame::Open { stream: 1 },
            Frame::Fin { stream: 1 },
            Frame::Fin { stream: 1 }
        ]));
        assert!(refused(&[
            Frame::Open { stream: 1 },
            Frame::FinAck { stream: 1 }
        ]));
        // Settings twice, a stream limit going down.
        assert!(refused(&[state(Side::Agent).settings()]));
        assert!(refused(&[Frame::MaxStreams { total: 1 }]));
        // Beyond the stream limit (one session: five streams).
        let opens: Vec<Frame<'_>> = (0..6).map(|i| Frame::Open { stream: 1 + 2 * i }).collect();
        assert!(refused(&opens));
        assert!(!refused(&opens[..5]));
    }

    #[test]
    fn settings_come_first_and_are_checked() {
        let now = Instant::now();
        let fresh = || State::new(Side::Core, limits(), Arc::default(), Arc::default());
        assert!(fresh().on_frame(&Frame::Open { stream: 1 }, now).is_err());
        let bad = |version, max_streams, stream_window, connection_window| {
            fresh()
                .on_frame(
                    &Frame::Settings {
                        version,
                        max_streams,
                        stream_window,
                        connection_window,
                    },
                    now,
                )
                .is_err()
        };
        assert!(bad(2, 5, 16_384, 65_536));
        assert!(bad(1, 0, 16_384, 65_536));
        assert!(bad(1, 5, 1024, 65_536));
        assert!(bad(1, 5, 16_384, 1024));
        assert!(!bad(1, 5, 16_384, 65_536));
    }

    #[test]
    fn closed_streams_free_a_slot_for_the_peer() {
        let mut s = state(Side::Core);
        let now = Instant::now();
        s.on_frame(&Frame::Open { stream: 1 }, now).unwrap();
        let (id, _) = s.accept().unwrap().unwrap();
        s.on_frame(&Frame::Fin { stream: 1 }, now).unwrap();
        s.finish(id).unwrap();
        s.drop_send(id);
        s.drop_recv(id);
        let mut out = Vec::new();
        s.next_batch(&mut out, usize::MAX);
        assert_eq!(s.stream_count(), 0);
        assert!(frames(&out).contains(&Frame::MaxStreams { total: 6 }));
        // Late frames for the forgotten stream are ignored.
        s.on_frame(&Frame::Reset { stream: 1, code: 0 }, now)
            .unwrap();
    }

    #[test]
    fn stop_and_reset_reach_the_other_side() {
        let mut s = state(Side::Agent);
        let now = Instant::now();
        let (id, _) = s.open().unwrap().unwrap();
        s.write(id, b"abc").unwrap();
        s.on_frame(
            &Frame::Stop {
                stream: id,
                code: 7,
            },
            now,
        )
        .unwrap();
        assert_eq!(s.write(id, b"d"), Err(StreamError::Stopped(7)));
        assert_eq!(s.stopped(id), Some(Ok(Some(7))));
        let mut out = Vec::new();
        s.next_batch(&mut out, usize::MAX);
        assert!(frames(&out).contains(&Frame::Reset {
            stream: id,
            code: 7
        }));
        s.on_frame(
            &Frame::Reset {
                stream: id,
                code: 9,
            },
            now,
        )
        .unwrap();
        assert_eq!(s.read(id, &mut [0; 4]), Err(StreamError::Reset(9)));
    }

    #[test]
    fn the_peer_close_carries_its_code() {
        let mut s = state(Side::Agent);
        s.on_frame(
            &Frame::Close {
                code: 1,
                reason: b"[TUN-E005] revoked",
            },
            Instant::now(),
        )
        .unwrap();
        assert_eq!(s.closed(), Some(&TunnelError::Revoked));
        assert!(matches!(s.open(), Err(StreamError::ConnectionLost(_))));
    }
}
