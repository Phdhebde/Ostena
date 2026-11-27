//! The tunnel: the agent dials the core (QUIC, or TLS 1.3 over TCP with the
//! multiplexer of [`crate::mux`]), opens the control stream and says hello;
//! then both sides exchange control messages, answer each other's heartbeat
//! and open prioritised session channels.

use std::marker::PhantomData;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ostena_crypto::tls::{self, CertificateDer, ClientConfig, ServerConfig, ServerName};
use quinn::crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig};
use quinn::{Connection, Endpoint, VarInt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::channel::{self, CONTROL_PRIORITY, StreamClass};
use crate::control::{self, AgentMessage, CoreMessage, MAX_FRAME, MAX_MESSAGE, Message};
use crate::error::TunnelError;
use crate::ids::Uuid;
use crate::limits::Limits;
use crate::mux::{self, Side};
use crate::transport::{ChannelRecv, ChannelSend, Conn, Transport, TransportMode};

/// Application protocol of the tunnel (ALPN).
pub const ALPN: &[u8] = b"ostena-tunnel/1";

/// QUIC application close code when a side closes on an error.
pub(crate) const CLOSE_ERROR: u32 = 1;
/// Messages buffered for the application before the reader waits.
const INBOX: usize = 64;
/// TLS handshakes over TCP the core runs at once; more connections wait.
const TCP_HANDSHAKES: usize = 32;

/// A session channel: one bidirectional stream (QUIC, or the TCP
/// multiplexer).
#[derive(Debug)]
pub struct Channel {
    /// Towards the peer.
    pub send: ChannelSend,
    /// From the peer.
    pub recv: ChannelRecv,
    _open: OpenChannel,
}

/// Counts a channel as open until it is dropped.
#[derive(Debug)]
struct OpenChannel(Arc<Shared>);

impl OpenChannel {
    fn new(shared: &Arc<Shared>) -> Self {
        shared.open_channels.fetch_add(1, Ordering::Relaxed);
        Self(shared.clone())
    }
}

impl Drop for OpenChannel {
    fn drop(&mut self) {
        self.0.open_channels.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug)]
struct Shared {
    conn: Conn,
    control: tokio::sync::Mutex<ChannelSend>,
    failure: Mutex<Option<TunnelError>>,
    last_pong: Mutex<Instant>,
    /// Test core only: stop answering pings.
    muted: AtomicBool,
    /// Session channels not dropped yet.
    open_channels: AtomicUsize,
}

impl Shared {
    /// Records the first failure and closes the connection with its message.
    fn fail(&self, error: TunnelError) {
        // Recorded before the close: `closed` reads it once the close is seen.
        let reason = error.clone();
        if let Ok(mut failure) = self.failure.lock() {
            failure.get_or_insert(error);
        }
        self.conn.close(CLOSE_ERROR, &reason);
    }

    async fn send<M: Message>(&self, message: &M) -> Result<(), TunnelError> {
        let frame = control::encode(message)?;
        self.control
            .lock()
            .await
            .write_all(&frame)
            .await
            .map_err(|e| TunnelError::ConnectionLost(e.to_string()))
    }
}

/// One end of a tunnel. `Out` is what this side sends, `In` what it
/// receives. Dropping it closes the connection.
#[derive(Debug)]
pub struct Tunnel<Out: Message, In: Message> {
    shared: Arc<Shared>,
    inbox: tokio::sync::Mutex<mpsc::Receiver<In>>,
    tasks: Vec<JoinHandle<()>>,
    endpoint: Option<Endpoint>,
    _out: PhantomData<fn(Out)>,
}

/// The agent end.
pub type AgentTunnel = Tunnel<AgentMessage, CoreMessage>;
/// The core end.
pub type CoreTunnel = Tunnel<CoreMessage, AgentMessage>;

pub(crate) async fn read_frame(recv: &mut ChannelRecv, max: usize) -> Result<Vec<u8>, TunnelError> {
    let lost = |e: crate::transport::StreamError| TunnelError::ConnectionLost(e.to_string());
    let mut len = [0u8; 4];
    recv.read_exact(&mut len).await.map_err(lost)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > max {
        return Err(TunnelError::Protocol(format!(
            "trame de {len} octets, maximum {max}"
        )));
    }
    let mut payload = vec![0u8; len];
    recv.read_exact(&mut payload).await.map_err(lost)?;
    Ok(payload)
}

impl<Out: Message, In: Message> Tunnel<Out, In> {
    fn start(
        conn: Conn,
        control: ChannelSend,
        mut recv: ChannelRecv,
        heartbeat: Duration,
        timeout: Duration,
        endpoint: Option<Endpoint>,
    ) -> Self {
        let shared = Arc::new(Shared {
            conn,
            control: tokio::sync::Mutex::new(control),
            failure: Mutex::new(None),
            last_pong: Mutex::new(Instant::now()),
            muted: AtomicBool::new(false),
            open_channels: AtomicUsize::new(0),
        });
        let (tx, inbox) = mpsc::channel(INBOX);

        let reader = {
            let shared = shared.clone();
            tokio::spawn(async move {
                loop {
                    let message = match read_frame(&mut recv, MAX_FRAME).await {
                        Ok(frame) => control::decode::<In>(&frame),
                        Err(TunnelError::Protocol(e)) => Err(TunnelError::Protocol(e)),
                        // The connection went away: `closed()` tells why.
                        Err(_) => break,
                    };
                    match message {
                        Ok(m) => {
                            if let Some(seq) = m.as_ping() {
                                if shared.muted.load(Ordering::Relaxed) {
                                    continue;
                                }
                                if shared.send(&Out::pong(seq)).await.is_err() {
                                    break;
                                }
                            } else if m.as_pong().is_some() {
                                if let Ok(mut t) = shared.last_pong.lock() {
                                    *t = Instant::now();
                                }
                            } else if tx.send(m).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                event = "tunnel.message_refused",
                                code = e.code(),
                                "{e}"
                            );
                            shared.fail(e);
                            break;
                        }
                    }
                }
            })
        };

        let heart = {
            let shared = shared.clone();
            tokio::spawn(async move {
                let mut seq = 0u64;
                loop {
                    tokio::time::sleep(heartbeat).await;
                    let silent = shared
                        .last_pong
                        .lock()
                        .map_or(Duration::MAX, |t| t.elapsed());
                    if silent > timeout {
                        shared.fail(TunnelError::HeartbeatTimeout);
                        break;
                    }
                    seq += 1;
                    if shared.send(&Out::ping(seq)).await.is_err() {
                        break;
                    }
                }
            })
        };

        Self {
            shared,
            inbox: tokio::sync::Mutex::new(inbox),
            tasks: vec![reader, heart],
            endpoint,
            _out: PhantomData,
        }
    }

    /// Sends a control message.
    ///
    /// # Errors
    ///
    /// [`TunnelError::Protocol`] if it is too long,
    /// [`TunnelError::ConnectionLost`] if the tunnel is gone.
    pub async fn send(&self, message: &Out) -> Result<(), TunnelError> {
        self.shared.send(message).await
    }

    /// The next control message from the peer (heartbeats excluded); `None`
    /// once the tunnel is closed.
    pub async fn recv(&self) -> Option<In> {
        self.inbox.lock().await.recv().await
    }

    /// Opens a session channel of `class`, sent with its priority.
    ///
    /// # Errors
    ///
    /// [`TunnelError::ConnectionLost`] if the tunnel is gone. Waits while the
    /// peer's stream limit is reached.
    pub async fn open_channel(
        &self,
        session: Uuid,
        class: StreamClass,
    ) -> Result<Channel, TunnelError> {
        let (mut send, recv) = self.shared.conn.open_bi().await?;
        send.set_priority(class.priority())
            .map_err(|e| TunnelError::ConnectionLost(e.to_string()))?;
        send.write_all(&channel::encode_header(session, class))
            .await
            .map_err(|e| TunnelError::ConnectionLost(e.to_string()))?;
        Ok(Channel {
            send,
            recv,
            _open: OpenChannel::new(&self.shared),
        })
    }

    /// Accepts the next session channel opened by the peer.
    ///
    /// # Errors
    ///
    /// [`TunnelError::ConnectionLost`], or [`TunnelError::Protocol`] /
    /// [`TunnelError::Version`] for a bad header (the stream is refused, the
    /// tunnel stays up).
    pub async fn accept_channel(&self) -> Result<(Uuid, StreamClass, Channel), TunnelError> {
        let (mut send, mut recv) = self.shared.conn.accept_bi().await?;
        let mut header = [0u8; channel::HEADER_LEN];
        let read =
            tokio::time::timeout(Duration::from_secs(10), recv.read_exact(&mut header)).await;
        let decoded = match read {
            Ok(Ok(())) => channel::decode_header(&header),
            Ok(Err(e)) => Err(TunnelError::Protocol(format!("en-tête de flux : {e}"))),
            Err(_) => Err(TunnelError::Protocol(
                "en-tête de flux non reçu à temps".into(),
            )),
        };
        let (session, class) = match decoded {
            Ok(v) => v,
            Err(e) => {
                let _ = recv.stop(CLOSE_ERROR);
                let _ = send.reset(CLOSE_ERROR);
                return Err(e);
            }
        };
        send.set_priority(class.priority())
            .map_err(|e| TunnelError::ConnectionLost(e.to_string()))?;
        Ok((
            session,
            class,
            Channel {
                send,
                recv,
                _open: OpenChannel::new(&self.shared),
            },
        ))
    }

    /// Session channels opened or accepted and not dropped yet.
    pub fn open_channels(&self) -> usize {
        self.shared.open_channels.load(Ordering::Relaxed)
    }

    /// Smoothed round-trip time, measured by QUIC or by the pings of the
    /// TCP multiplexer.
    pub fn rtt(&self) -> Duration {
        self.shared.conn.rtt()
    }

    /// The transport carrying this tunnel.
    pub fn transport(&self) -> Transport {
        self.shared.conn.transport()
    }

    /// The certificate presented by the peer, if any.
    pub fn peer_certificate(&self) -> Option<CertificateDer<'static>> {
        self.shared.conn.peer_certificate()
    }

    /// Waits until the tunnel is closed and says why.
    pub async fn closed(&self) -> TunnelError {
        let error = self.shared.conn.closed().await;
        let own = self.shared.failure.lock().ok().and_then(|f| f.clone());
        own.unwrap_or(error)
    }

    /// Closes the tunnel on `error`.
    pub fn close(&self, error: TunnelError) {
        self.shared.fail(error);
    }

    /// Test core only: stop answering the peer's heartbeat.
    #[cfg(feature = "testing")]
    pub(crate) fn mute_for_tests(&self) {
        self.shared.muted.store(true, Ordering::Relaxed);
    }

    /// Whether the tunnel is closed.
    pub fn is_closed(&self) -> bool {
        self.shared.conn.is_closed()
    }
}

impl<Out: Message, In: Message> Drop for Tunnel<Out, In> {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        match &self.shared.conn {
            Conn::Quic(c) => c.close(VarInt::from_u32(0), b""),
            Conn::Tcp { .. } => self
                .shared
                .conn
                .close(0, &TunnelError::ConnectionLost("tunnel fermé".into())),
        }
        if let Some(endpoint) = &self.endpoint {
            endpoint.close(VarInt::from_u32(0), b"");
        }
    }
}

pub(crate) fn peer_certificate(conn: &Connection) -> Option<CertificateDer<'static>> {
    conn.peer_identity()?
        .downcast::<Vec<CertificateDer<'static>>>()
        .ok()?
        .into_iter()
        .next()
}

fn check_alpn(conn: &Connection) -> Result<(), TunnelError> {
    check_protocol(conn, ALPN)
}

/// The connection negotiated `expected` (ALPN), or it is closed.
pub(crate) fn check_protocol(conn: &Connection, expected: &[u8]) -> Result<(), TunnelError> {
    let protocol = conn
        .handshake_data()
        .and_then(|d| d.downcast::<HandshakeData>().ok())
        .and_then(|d| d.protocol);
    if protocol.as_deref() == Some(expected) {
        Ok(())
    } else {
        conn.close(VarInt::from_u32(CLOSE_ERROR), b"ALPN");
        Err(TunnelError::ApplicationProtocol)
    }
}

pub(crate) async fn within<T>(
    limit: Duration,
    what: &str,
    future: impl Future<Output = Result<T, TunnelError>>,
) -> Result<T, TunnelError> {
    tokio::time::timeout(limit, future)
        .await
        .map_err(|_| TunnelError::ConnectionLost(format!("{what} : délai dépassé")))?
}

/// What the agent announces in its hello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    /// Agent version.
    pub agent_version: String,
    /// Gateway group.
    pub gateway_group: Uuid,
    /// `sha256:<hex>` of the configuration file.
    pub config_fingerprint: String,
}

/// How the agent reaches the core.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Core address (already resolved and checked).
    pub core: SocketAddr,
    /// Name expected in the core certificate (DNS name or IP address).
    pub server_name: String,
    /// TLS client configuration from [`ostena_crypto::tls::client_config`],
    /// with [`ALPN`]. The same for both transports.
    pub tls: Arc<ClientConfig>,
    /// Transport to dial.
    pub transport: Transport,
    /// Bounds.
    pub limits: Limits,
    /// Hello content.
    pub hello: Hello,
}

/// What the core answered to the hello.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelloAck {
    /// Heartbeat interval used.
    pub heartbeat: Duration,
}

async fn dial_quic(config: &AgentConfig) -> Result<(Conn, Endpoint), TunnelError> {
    let limits = config.limits;
    let quic = QuicClientConfig::with_initial(config.tls.clone(), tls::quic_initial_suite())
        .map_err(|e| TunnelError::Config(e.to_string()))?;
    let mut client = quinn::ClientConfig::new(Arc::new(quic));
    client.transport_config(limits.transport()?);
    let bind: SocketAddr = if config.core.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let endpoint = Endpoint::client(bind).map_err(|e| TunnelError::Io(e.to_string()))?;
    let connecting = endpoint
        .connect_with(client, config.core, &config.server_name)
        .map_err(|e| TunnelError::Config(e.to_string()))?;
    let conn = within(limits.handshake_timeout, "connexion au core", async {
        connecting.await.map_err(TunnelError::from)
    })
    .await?;
    check_alpn(&conn)?;
    Ok((Conn::Quic(conn), endpoint))
}

async fn dial_tcp(config: &AgentConfig) -> Result<Conn, TunnelError> {
    let limits = config.limits;
    let name = ServerName::try_from(config.server_name.clone())
        .map_err(|e| TunnelError::Config(format!("nom du core : {e}")))?;
    within(limits.handshake_timeout, "connexion TCP au core", async {
        let tcp = TcpStream::connect(config.core)
            .await
            .map_err(|e| TunnelError::ConnectionLost(format!("{} : {e}", config.core)))?;
        tcp.set_nodelay(true)
            .map_err(|e| TunnelError::Io(e.to_string()))?;
        let stream = TlsConnector::from(config.tls.clone())
            .connect(name, tcp)
            .await
            .map_err(|e| TunnelError::from_tls_io(&e))?;
        let session = stream.get_ref().1;
        if session.alpn_protocol() != Some(ALPN) {
            return Err(TunnelError::ApplicationProtocol);
        }
        let peer = session
            .peer_certificates()
            .and_then(|c| c.first())
            .map(|c| c.clone().into_owned());
        // A refusal of our certificate by the core arrives here, as a TLS
        // alert on the first read.
        let conn =
            mux::Connection::establish(stream, Side::Agent, limits, TunnelError::from_tls_io)
                .await?;
        Ok(Conn::Tcp { conn, peer })
    })
    .await
}

/// Dials the core over `config.transport`, says hello and returns the agent
/// end of the tunnel.
///
/// # Errors
///
/// A TLS refusal (`TUN-E001` to `TUN-E009`, `TUN-E016`), a protocol error,
/// a timeout or a local failure.
pub async fn connect(config: &AgentConfig) -> Result<(AgentTunnel, HelloAck), TunnelError> {
    let (conn, endpoint) = match config.transport {
        Transport::Quic => {
            let (conn, endpoint) = dial_quic(config).await?;
            (conn, Some(endpoint))
        }
        Transport::Tcp => (dial_tcp(config).await?, None),
    };
    let limits = config.limits;

    // In TLS 1.3 the core checks the agent certificate after the agent has
    // finished its handshake: a refusal shows up here as a lost connection.
    // Report the reason the core gave instead.
    let refused = |error: TunnelError| async {
        match error {
            TunnelError::ConnectionLost(_) => {
                match tokio::time::timeout(Duration::from_secs(1), conn.closed()).await {
                    Ok(reason) => reason,
                    Err(_) => error,
                }
            }
            other => other,
        }
    };
    let hello = AgentMessage::Hello {
        protocol: control::PROTOCOL_VERSION,
        agent_version: config.hello.agent_version.clone(),
        gateway_group: config.hello.gateway_group.to_string(),
        config_fingerprint: config.hello.config_fingerprint.clone(),
    };
    let hello = control::encode(&hello)?;
    let opened = async {
        let (mut send, recv) = conn.open_bi().await?;
        send.set_priority(CONTROL_PRIORITY)
            .map_err(|e| TunnelError::ConnectionLost(e.to_string()))?;
        send.write_all(&hello)
            .await
            .map_err(|e| TunnelError::ConnectionLost(e.to_string()))?;
        Ok::<_, TunnelError>((send, recv))
    }
    .await;
    let (send, mut recv) = match opened {
        Ok(v) => v,
        Err(e) => return Err(refused(e).await),
    };
    let answer = within(limits.handshake_timeout, "réponse au hello", async {
        match read_frame(&mut recv, MAX_MESSAGE).await {
            Ok(frame) => control::decode::<CoreMessage>(&frame),
            Err(e) => Err(refused(e).await),
        }
    })
    .await;
    let heartbeat_secs = match answer {
        Ok(CoreMessage::HelloAck { heartbeat_secs, .. }) => heartbeat_secs,
        Ok(_) => {
            let e = TunnelError::Protocol("réponse au hello inattendue".into());
            conn.close(CLOSE_ERROR, &e);
            return Err(e);
        }
        Err(e) => {
            conn.close(CLOSE_ERROR, &e);
            return Err(e);
        }
    };
    let heartbeat = Duration::from_secs(u64::from(heartbeat_secs))
        .min(limits.heartbeat_interval)
        .min(limits.heartbeat_timeout / 2);
    let transport = conn.transport();
    let tunnel = Tunnel::start(
        conn,
        send,
        recv,
        heartbeat,
        limits.heartbeat_timeout,
        endpoint,
    );
    tracing::info!(
        event = "tunnel.connected",
        core = %config.core,
        transport = transport.as_str()
    );
    Ok((tunnel, HelloAck { heartbeat }))
}

/// How long `auto` waits for QUIC before it dials TCP in parallel.
pub const FALLBACK_AFTER: Duration = Duration::from_secs(1);

/// Whether QUIC failing with `error` is worth trying TCP: the path, not the
/// peer, refused. A TLS refusal (certificate, group, suite, ALPN) would be
/// the same over TCP.
fn worth_tcp(error: &TunnelError) -> bool {
    matches!(
        error,
        TunnelError::ConnectionLost(_) | TunnelError::Io(_) | TunnelError::Handshake(_)
    )
}

fn fell_back(config: &AgentConfig, why: &str) {
    tracing::warn!(
        event = "tunnel.fallback",
        core = %config.core,
        transport = "tcp",
        "repli TLS 1.3 sur TCP : {why} ; performance moindre, sécurité identique"
    );
}

/// Dials the core as `mode` says: QUIC, TCP, or `auto`: QUIC first, and TCP
/// in parallel if QUIC has not answered within [`FALLBACK_AFTER`] or failed
/// on the path; the first tunnel up wins. Falling back is logged
/// (`tunnel.fallback`).
///
/// # Errors
///
/// As [`connect`]; with `auto`, a refusal by the peer rather than a
/// transport failure when there is one.
pub async fn connect_with(
    config: &AgentConfig,
    mode: TransportMode,
) -> Result<(AgentTunnel, HelloAck), TunnelError> {
    let quic = AgentConfig {
        transport: Transport::Quic,
        ..config.clone()
    };
    let tcp = AgentConfig {
        transport: Transport::Tcp,
        ..config.clone()
    };
    match mode {
        TransportMode::Quic => return connect(&quic).await,
        TransportMode::Tcp => return connect(&tcp).await,
        TransportMode::Auto => {}
    }
    // Boxed: each attempt holds a whole handshake.
    let mut first = Box::pin(connect(&quic));
    match tokio::time::timeout(FALLBACK_AFTER, &mut first).await {
        Ok(Ok(up)) => return Ok(up),
        Ok(Err(e)) if !worth_tcp(&e) => return Err(e),
        Ok(Err(e)) => {
            let up = connect(&tcp)
                .await
                .map_err(|t| if worth_tcp(&t) { e } else { t })?;
            fell_back(config, "QUIC a échoué");
            return Ok(up);
        }
        Err(_) => {}
    }
    let mut second = Box::pin(connect(&tcp));
    tokio::select! {
        q = &mut first => match q {
            Ok(up) => Ok(up),
            Err(e) if !worth_tcp(&e) => Err(e),
            Err(e) => {
                let up = second.await.map_err(|t| if worth_tcp(&t) { e } else { t })?;
                fell_back(config, "QUIC a échoué");
                Ok(up)
            }
        },
        t = &mut second => match t {
            Ok(up) => {
                fell_back(config, "QUIC sans réponse en 1 s");
                Ok(up)
            }
            Err(t) => match first.await {
                Ok(up) => Ok(up),
                Err(e) => Err(if worth_tcp(&t) { e } else { t }),
            },
        },
    }
}

/// A connection the core accepted: the tunnel, the hello and the agent
/// certificate.
#[derive(Debug)]
pub struct Accepted {
    /// The core end.
    pub tunnel: CoreTunnel,
    /// What the agent announced.
    pub hello: Hello,
    /// SHA-256 of the agent certificate: its identity in the registry.
    pub fingerprint: [u8; 32],
}

/// The TCP side of the core listener: an accept task that runs the TLS
/// handshakes (a bounded number at once) and queues the results.
#[derive(Debug)]
struct TcpSide {
    addr: SocketAddr,
    accepted: tokio::sync::Mutex<mpsc::Receiver<Result<Accepted, TunnelError>>>,
    task: JoinHandle<()>,
}

/// The core listener of the tunnel: QUIC, and TLS 1.3 over TCP for the
/// agents that fall back to it.
#[derive(Debug)]
pub struct CoreListener {
    endpoint: Endpoint,
    limits: Limits,
    tcp: TcpSide,
    /// Test core only: drop every QUIC connection attempt unanswered, as a
    /// firewall that blocks UDP.
    quic_dropped: AtomicBool,
}

impl CoreListener {
    /// Listens on `addr` with a TLS server configuration from
    /// [`ostena_crypto::tls::server_config`] (client certificate required,
    /// [`ALPN`]): QUIC on UDP, and TLS 1.3 over TCP on the same port for the
    /// agents that fall back to it, with the same TLS configuration.
    ///
    /// # Errors
    ///
    /// [`TunnelError::Config`] or [`TunnelError::Io`] (the UDP or the TCP
    /// port is taken).
    ///
    /// # Panics
    ///
    /// Outside a Tokio runtime.
    pub fn bind(
        addr: SocketAddr,
        tls: Arc<ServerConfig>,
        limits: Limits,
    ) -> Result<Self, TunnelError> {
        let quic = QuicServerConfig::with_initial(tls.clone(), tls::quic_initial_suite())
            .map_err(|e| TunnelError::Config(e.to_string()))?;
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(quic));
        server.transport_config(limits.transport()?);
        server.migration(false);
        let endpoint =
            Endpoint::server(server, addr).map_err(|e| TunnelError::Io(e.to_string()))?;
        let bound = endpoint
            .local_addr()
            .map_err(|e| TunnelError::Io(e.to_string()))?;
        let tcp = match bind_tcp(bound, tls, limits) {
            Ok(tcp) => tcp,
            Err(e) => {
                endpoint.close(VarInt::from_u32(0), b"");
                return Err(e);
            }
        };
        Ok(Self {
            endpoint,
            limits,
            tcp,
            quic_dropped: AtomicBool::new(false),
        })
    }

    /// The bound address (QUIC).
    ///
    /// # Errors
    ///
    /// [`TunnelError::Io`].
    pub fn local_addr(&self) -> Result<SocketAddr, TunnelError> {
        self.endpoint
            .local_addr()
            .map_err(|e| TunnelError::Io(e.to_string()))
    }

    /// The bound TCP address (the port of the QUIC one).
    pub fn tcp_local_addr(&self) -> SocketAddr {
        self.tcp.addr
    }

    /// The next agent connection, over either transport; `None` once the
    /// listener is closed.
    pub async fn accept(&self) -> Option<Result<Accepted, TunnelError>> {
        let tcp = &self.tcp;
        let result = loop {
            break tokio::select! {
                incoming = self.endpoint.accept() => {
                    let incoming = incoming?;
                    if self.quic_dropped.load(Ordering::Relaxed) {
                        incoming.ignore();
                        continue;
                    }
                    self.handshake(incoming).await
                }
                accepted = async { tcp.accepted.lock().await.recv().await } => accepted?,
            };
        };
        if let Err(e) = &result {
            tracing::warn!(event = "tunnel.refused", code = e.code(), "{e}");
        }
        Some(result)
    }

    async fn handshake(&self, incoming: quinn::Incoming) -> Result<Accepted, TunnelError> {
        let limits = self.limits;
        let connecting = incoming.accept().map_err(TunnelError::from)?;
        let conn = within(limits.handshake_timeout, "poignée de main", async {
            connecting.await.map_err(TunnelError::from)
        })
        .await?;
        check_alpn(&conn)?;
        accept_hello(Conn::Quic(conn), limits).await
    }

    /// Test core only: drop QUIC connection attempts unanswered.
    #[cfg(feature = "testing")]
    pub(crate) fn drop_quic_for_tests(&self) {
        self.quic_dropped.store(true, Ordering::Relaxed);
    }

    /// Stops accepting and closes every connection.
    pub fn close(&self) {
        self.endpoint.close(VarInt::from_u32(0), b"");
        self.tcp.task.abort();
    }
}

impl Drop for CoreListener {
    fn drop(&mut self) {
        self.tcp.task.abort();
    }
}

fn bind_tcp(
    addr: SocketAddr,
    tls: Arc<ServerConfig>,
    limits: Limits,
) -> Result<TcpSide, TunnelError> {
    let io = |e: std::io::Error| TunnelError::Io(format!("écoute TCP {addr} : {e}"));
    let std_listener = std::net::TcpListener::bind(addr).map_err(io)?;
    std_listener.set_nonblocking(true).map_err(io)?;
    let listener = TcpListener::from_std(std_listener).map_err(io)?;
    let bound = listener.local_addr().map_err(io)?;
    let (tx, rx) = mpsc::channel(16);
    let acceptor = TlsAcceptor::from(tls);
    let permits = Arc::new(Semaphore::new(TCP_HANDSHAKES));
    let task = tokio::spawn(async move {
        loop {
            let Ok(permit) = permits.clone().acquire_owned().await else {
                return;
            };
            let (tcp, _) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(event = "tunnel.accept_failed", "écoute TCP : {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let acceptor = acceptor.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let result = accept_tcp(tcp, acceptor, limits).await;
                drop(permit);
                let _ = tx.send(result).await;
            });
        }
    });
    Ok(TcpSide {
        addr: bound,
        accepted: tokio::sync::Mutex::new(rx),
        task,
    })
}

/// How long a refused TCP connection is drained before it is closed.
const LINGER: Duration = Duration::from_secs(1);

/// Closes a connection whose handshake the core refused, once the alert is
/// sent: end of the write side, then what the agent already sent is read
/// and dropped, for at most [`LINGER`]. A socket closed with unread data is
/// reset (always on Windows), and a reset can discard the alert before the
/// agent reads it: the agent would see a lost connection instead of the
/// reason (`TUN-E004`, `TUN-E012`…).
async fn linger(mut tcp: TcpStream) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let _ = tcp.shutdown().await;
    let mut sink = [0u8; 4096];
    let _ = tokio::time::timeout(LINGER, async {
        while matches!(tcp.read(&mut sink).await, Ok(n) if n > 0) {}
    })
    .await;
}

async fn accept_tcp(
    tcp: TcpStream,
    acceptor: TlsAcceptor,
    limits: Limits,
) -> Result<Accepted, TunnelError> {
    let conn = within(limits.handshake_timeout, "poignée de main TCP", async {
        tcp.set_nodelay(true)
            .map_err(|e| TunnelError::Io(e.to_string()))?;
        let stream = match acceptor.accept(tcp).into_fallible().await {
            Ok(stream) => stream,
            Err((e, tcp)) => {
                linger(tcp).await;
                return Err(TunnelError::from_tls_io(&e));
            }
        };
        let session = stream.get_ref().1;
        if session.alpn_protocol() != Some(ALPN) {
            return Err(TunnelError::ApplicationProtocol);
        }
        let peer = session
            .peer_certificates()
            .and_then(|c| c.first())
            .map(|c| c.clone().into_owned());
        let conn = mux::Connection::establish(stream, Side::Core, limits, TunnelError::from_tls_io)
            .await?;
        Ok(Conn::Tcp { conn, peer })
    })
    .await?;
    accept_hello(conn, limits).await
}

/// The common end of the handshake on the core: the agent certificate, then
/// the control stream and its hello.
async fn accept_hello(conn: Conn, limits: Limits) -> Result<Accepted, TunnelError> {
    let certificate = conn
        .peer_certificate()
        .ok_or(TunnelError::NoClientCertificate)?;
    let fingerprint = tls::fingerprint(&certificate);
    let hello = within(limits.handshake_timeout, "hello de l'agent", async {
        let (send, mut recv) = conn.accept_bi().await?;
        let frame = read_frame(&mut recv, MAX_MESSAGE).await?;
        let hello = control::decode::<AgentMessage>(&frame)?;
        Ok((send, recv, hello))
    })
    .await;
    let (send, recv, hello) = match hello {
        Ok(v) => v,
        Err(e) => {
            conn.close(CLOSE_ERROR, &e);
            return Err(e);
        }
    };
    let AgentMessage::Hello {
        agent_version,
        gateway_group,
        config_fingerprint,
        ..
    } = hello
    else {
        let e = TunnelError::Protocol("le premier message n'est pas un hello".into());
        conn.close(CLOSE_ERROR, &e);
        return Err(e);
    };
    send.set_priority(CONTROL_PRIORITY)
        .map_err(|e| TunnelError::ConnectionLost(e.to_string()))?;
    let hello = Hello {
        agent_version,
        // Checked by `validate`.
        gateway_group: Uuid::parse(&gateway_group).unwrap_or(Uuid::from_bytes([0; 16])),
        config_fingerprint,
    };
    let tunnel = Tunnel::start(
        conn,
        send,
        recv,
        limits.heartbeat_interval,
        limits.heartbeat_timeout,
        None,
    );
    Ok(Accepted {
        tunnel,
        hello,
        fingerprint,
    })
}
