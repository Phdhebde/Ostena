//! The multiplexed connection over one byte stream (TLS 1.3 over TCP in
//! production, an in-memory pipe in the tests): a reader task, a writer
//! task and a keep-alive task around a [`State`].

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::task::AbortHandle;

use super::frame::{self, MAX_FRAME};
use super::state::{Read, Side, State, StreamError, Write};
use crate::error::TunnelError;
use crate::limits::Limits;

/// Bytes the writer encodes before it writes them out: small enough that a
/// keystroke queued meanwhile waits for at most this much.
const BATCH: usize = 32 * 1024;
/// How long the writer waits, after sending its close frame, for the peer
/// to close before the reader is dropped.
const LINGER: Duration = Duration::from_secs(2);

/// Maps an I/O error of the underlying stream (a TLS alert, for example).
pub type IoMapper = fn(&std::io::Error) -> TunnelError;

#[derive(Debug)]
struct Inner {
    state: Mutex<State>,
    writer: Arc<Notify>,
    conn: Arc<Notify>,
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        // A panic while holding the lock leaves a consistent state: every
        // method updates it before it can panic.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Waits until `check` gives a value, re-checking on every wake-up of
    /// the stream or of the connection.
    async fn wait<T>(
        &self,
        stream: Option<&Notify>,
        mut check: impl FnMut(&mut State) -> Option<T>,
    ) -> T {
        loop {
            let on_conn = self.conn.notified();
            tokio::pin!(on_conn);
            on_conn.as_mut().enable();
            let on_stream = stream.map(Notify::notified);
            let mut on_stream = on_stream.map(Box::pin);
            if let Some(f) = on_stream.as_mut() {
                f.as_mut().enable();
            }
            if let Some(v) = check(&mut self.lock()) {
                return v;
            }
            match on_stream {
                Some(f) => {
                    tokio::select! {
                        () = f => {}
                        () = on_conn => {}
                    }
                }
                None => on_conn.await,
            }
        }
    }
}

/// One multiplexed connection. Cloning it shares it.
#[derive(Debug, Clone)]
pub struct Connection {
    inner: Arc<Inner>,
}

impl Connection {
    /// Sends the settings, waits for the peer's, then starts the reader,
    /// writer and keep-alive tasks. The caller bounds the wait.
    ///
    /// # Errors
    ///
    /// The peer's settings are invalid ([`TunnelError::Protocol`],
    /// [`TunnelError::Version`]), or the stream failed (mapped by
    /// `map_io`).
    pub async fn establish<S>(
        stream: S,
        side: Side,
        limits: Limits,
        map_io: IoMapper,
    ) -> Result<Self, TunnelError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        limits.validate()?;
        let writer = Arc::new(Notify::new());
        let conn = Arc::new(Notify::new());
        let mut state = State::new(side, limits, writer.clone(), conn.clone());
        let (mut rd, mut wr) = tokio::io::split(stream);
        let mut out = Vec::with_capacity(32);
        frame::encode(&state.settings(), &mut out);
        let io = |e: std::io::Error| map_io(&e);
        wr.write_all(&out).await.map_err(io)?;
        wr.flush().await.map_err(io)?;

        let mut buf = Vec::with_capacity(2 * MAX_FRAME);
        let used = loop {
            match frame::decode(&buf) {
                Ok(Some((f, used))) => {
                    state.on_frame(&f, Instant::now())?;
                    break used;
                }
                Ok(None) => {}
                Err(e) => {
                    return Err(TunnelError::Protocol(format!("multiplexeur TCP : {e}")));
                }
            }
            if read_more(&mut rd, &mut buf).await.map_err(io)? == 0 {
                return Err(TunnelError::ConnectionLost(
                    "connexion fermée par le pair avant ses paramètres".into(),
                ));
            }
        };
        buf.drain(..used);

        let inner = Arc::new(Inner {
            state: Mutex::new(state),
            writer,
            conn,
        });
        let last_rx = Arc::new(Mutex::new(tokio::time::Instant::now()));
        let reader = tokio::spawn(read_loop(inner.clone(), rd, buf, last_rx.clone(), map_io));
        tokio::spawn(write_loop(inner.clone(), wr, reader.abort_handle()));
        tokio::spawn(keep_alive(inner.clone(), limits, last_rx));
        Ok(Self { inner })
    }

    /// Opens a stream, waiting while the peer's stream limit is reached.
    ///
    /// # Errors
    ///
    /// [`StreamError::ConnectionLost`] if the connection is closed.
    pub async fn open(&self) -> Result<(SendStream, RecvStream), StreamError> {
        let opened = self.inner.wait(None, |s| s.open().transpose()).await?;
        Ok(self.halves(opened))
    }

    /// The next stream the peer opens.
    ///
    /// # Errors
    ///
    /// [`StreamError::ConnectionLost`] once the connection is closed.
    pub async fn accept(&self) -> Result<(SendStream, RecvStream), StreamError> {
        let accepted = self.inner.wait(None, |s| s.accept().transpose()).await?;
        Ok(self.halves(accepted))
    }

    fn halves(&self, (id, notify): (u32, Arc<Notify>)) -> (SendStream, RecvStream) {
        (
            SendStream {
                inner: self.inner.clone(),
                id,
                notify: notify.clone(),
            },
            RecvStream {
                inner: self.inner.clone(),
                id,
                notify,
            },
        )
    }

    /// Closes the connection on `error`, which the peer receives.
    pub fn close(&self, error: TunnelError, code: u32) {
        self.inner.lock().close(error, code);
    }

    /// Waits until the connection is closed and says why.
    pub async fn closed(&self) -> TunnelError {
        self.inner.wait(None, |s| s.closed().cloned()).await
    }

    /// Whether the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.inner.lock().closed().is_some()
    }

    /// Smoothed round-trip time of the keep-alive pings (zero before the
    /// first answer).
    pub fn rtt(&self) -> Duration {
        self.inner.lock().rtt().unwrap_or_default()
    }
}

async fn read_more<R: AsyncRead + Unpin>(rd: &mut R, buf: &mut Vec<u8>) -> std::io::Result<usize> {
    let start = buf.len();
    buf.resize(start + MAX_FRAME, 0);
    let n = rd.read(&mut buf[start..]).await;
    buf.truncate(start + *n.as_ref().unwrap_or(&0));
    n
}

async fn read_loop<R: AsyncRead + Unpin>(
    inner: Arc<Inner>,
    mut rd: R,
    mut buf: Vec<u8>,
    last_rx: Arc<Mutex<tokio::time::Instant>>,
    map_io: IoMapper,
) {
    loop {
        let mut at = 0;
        loop {
            match frame::decode(&buf[at..]) {
                Ok(Some((f, used))) => {
                    at += used;
                    let mut state = inner.lock();
                    if let Err(e) = state.on_frame(&f, Instant::now()) {
                        refuse(&mut state, e);
                        return;
                    }
                    if state.closed().is_some() {
                        return;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    let e = TunnelError::Protocol(format!("multiplexeur TCP : {e}"));
                    refuse(&mut inner.lock(), e);
                    return;
                }
            }
        }
        buf.drain(..at);
        match read_more(&mut rd, &mut buf).await {
            Ok(0) => {
                inner.lock().lost(TunnelError::ConnectionLost(
                    "connexion TCP fermée par le pair".into(),
                ));
                return;
            }
            Ok(_) => {
                if let Ok(mut t) = last_rx.lock() {
                    *t = tokio::time::Instant::now();
                }
            }
            Err(e) => {
                inner.lock().lost(map_io(&e));
                return;
            }
        }
    }
}

fn refuse(state: &mut State, error: TunnelError) {
    tracing::warn!(
        event = "tunnel.message_refused",
        code = error.code(),
        "{error}"
    );
    state.close(error, 1);
}

async fn write_loop<W: AsyncWrite + Unpin>(inner: Arc<Inner>, mut wr: W, reader: AbortHandle) {
    let mut batch = Vec::with_capacity(BATCH + MAX_FRAME);
    loop {
        inner.writer.notified().await;
        loop {
            batch.clear();
            let done = {
                let mut state = inner.lock();
                state.next_batch(&mut batch, BATCH);
                state.writer_done()
            };
            if !batch.is_empty() {
                let written = async {
                    wr.write_all(&batch).await?;
                    wr.flush().await
                }
                .await;
                if let Err(e) = written {
                    inner
                        .lock()
                        .lost(TunnelError::ConnectionLost(format!("écriture TCP : {e}")));
                    reader.abort();
                    return;
                }
            }
            if done {
                // The close frame is out: say goodbye at the TLS level, give
                // the peer a moment to close, then stop reading.
                let _ = tokio::time::timeout(LINGER, wr.shutdown()).await;
                tokio::time::sleep(LINGER).await;
                reader.abort();
                return;
            }
            if batch.is_empty() {
                break;
            }
        }
    }
}

async fn keep_alive(inner: Arc<Inner>, limits: Limits, last_rx: Arc<Mutex<tokio::time::Instant>>) {
    let mut seq = 0u64;
    loop {
        tokio::time::sleep(limits.keep_alive).await;
        let silent = last_rx.lock().map_or(Duration::MAX, |t| t.elapsed());
        let mut state = inner.lock();
        if state.closed().is_some() {
            return;
        }
        if silent > limits.idle_timeout {
            state.lost(TunnelError::ConnectionLost(format!(
                "aucune trame reçue depuis {} s",
                silent.as_secs()
            )));
            return;
        }
        seq += 1;
        state.ping(seq, Instant::now());
    }
}

/// The sending half of a stream.
#[derive(Debug)]
pub struct SendStream {
    inner: Arc<Inner>,
    id: u32,
    notify: Arc<Notify>,
}

impl SendStream {
    /// Writes all of `data`, waiting for credit.
    ///
    /// # Errors
    ///
    /// The peer stopped the stream, it is finished, or the connection is
    /// lost.
    pub async fn write_all(&mut self, mut data: &[u8]) -> Result<(), StreamError> {
        while !data.is_empty() {
            let id = self.id;
            let n = self
                .inner
                .wait(Some(&self.notify), |s| match s.write(id, data) {
                    Ok(Write::Queued(n)) => Some(Ok(n)),
                    Ok(Write::Blocked) => None,
                    Err(e) => Some(Err(e)),
                })
                .await?;
            data = &data[n..];
        }
        Ok(())
    }

    /// Ends the stream once the bytes written are sent.
    ///
    /// # Errors
    ///
    /// [`StreamError::Closed`] if it is already finished or reset.
    pub fn finish(&mut self) -> Result<(), StreamError> {
        self.inner.lock().finish(self.id)
    }

    /// Abandons the stream with `code`.
    ///
    /// # Errors
    ///
    /// [`StreamError::Closed`] if it is already over.
    pub fn reset(&mut self, code: u32) -> Result<(), StreamError> {
        self.inner.lock().reset(self.id, code)
    }

    /// Sets the send priority (higher first).
    pub fn set_priority(&self, priority: i32) {
        self.inner.lock().set_priority(self.id, priority);
    }

    /// The send priority.
    ///
    /// # Errors
    ///
    /// [`StreamError::Closed`] if the stream is gone.
    pub fn priority(&self) -> Result<i32, StreamError> {
        self.inner
            .lock()
            .priority(self.id)
            .ok_or(StreamError::Closed)
    }

    /// Resolves when the peer stops the stream (its code) or acknowledges
    /// its end (`None`). Independent of `self`, like QUIC's.
    pub fn stopped(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<u32>, StreamError>> + Send + 'static>> {
        let inner = self.inner.clone();
        let notify = self.notify.clone();
        let id = self.id;
        Box::pin(async move { inner.wait(Some(&notify), |s| s.stopped(id)).await })
    }
}

impl Drop for SendStream {
    fn drop(&mut self) {
        self.inner.lock().drop_send(self.id);
    }
}

/// The receiving half of a stream.
#[derive(Debug)]
pub struct RecvStream {
    inner: Arc<Inner>,
    id: u32,
    notify: Arc<Notify>,
}

impl RecvStream {
    /// Reads into `buf`; `None` at the end of the stream.
    ///
    /// # Errors
    ///
    /// Reset by the peer, stopped here, or the connection lost.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, StreamError> {
        let id = self.id;
        self.inner
            .wait(Some(&self.notify), |s| match s.read(id, buf) {
                Ok(Read::Data(n)) => Some(Ok(Some(n))),
                Ok(Read::Fin) => Some(Ok(None)),
                Ok(Read::Blocked) => None,
                Err(e) => Some(Err(e)),
            })
            .await
    }

    /// Fills `buf` exactly.
    ///
    /// # Errors
    ///
    /// As [`RecvStream::read`], or [`StreamError::FinishedEarly`].
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), StreamError> {
        let mut at = 0;
        while at < buf.len() {
            match self.read(&mut buf[at..]).await? {
                Some(n) => at += n,
                None => return Err(StreamError::FinishedEarly),
            }
        }
        Ok(())
    }

    /// Asks the peer to stop sending, with `code`.
    ///
    /// # Errors
    ///
    /// [`StreamError::Closed`] if the direction is already over.
    pub fn stop(&mut self, code: u32) -> Result<(), StreamError> {
        self.inner.lock().stop(self.id, code)
    }
}

impl Drop for RecvStream {
    fn drop(&mut self) {
        self.inner.lock().drop_recv(self.id);
    }
}
