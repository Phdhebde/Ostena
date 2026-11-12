//! The QUIC tunnel: the agent dials the core, opens the control stream and
//! says hello; then both sides exchange control messages, answer each
//! other's heartbeat and open prioritised session channels.

use std::marker::PhantomData;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ostena_crypto::tls::{self, CertificateDer, ClientConfig, ServerConfig};
use quinn::crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig};
use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::channel::{self, CONTROL_PRIORITY, StreamClass};
use crate::control::{self, AgentMessage, CoreMessage, MAX_FRAME, MAX_MESSAGE, Message};
use crate::error::TunnelError;
use crate::ids::Uuid;
use crate::limits::Limits;

/// Application protocol of the tunnel (ALPN).
pub const ALPN: &[u8] = b"ostena-tunnel/1";

/// QUIC application close code when a side closes on an error.
const CLOSE_ERROR: u32 = 1;
/// Messages buffered for the application before the reader waits.
const INBOX: usize = 64;

/// A session channel: one bidirectional QUIC stream.
#[derive(Debug)]
pub struct Channel {
    /// Towards the peer.
    pub send: SendStream,
    /// From the peer.
    pub recv: RecvStream,
}

#[derive(Debug)]
struct Shared {
    conn: Connection,
    control: tokio::sync::Mutex<SendStream>,
    failure: Mutex<Option<TunnelError>>,
    last_pong: Mutex<Instant>,
    /// Test core only: stop answering pings.
    muted: AtomicBool,
}

impl Shared {
    /// Records the first failure and closes the connection with its message.
    fn fail(&self, error: TunnelError) {
        let reason = error.to_string();
        if let Ok(mut failure) = self.failure.lock() {
            failure.get_or_insert(error);
        }
        let reason = &reason.as_bytes()[..reason.len().min(200)];
        self.conn.close(VarInt::from_u32(CLOSE_ERROR), reason);
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

pub(crate) async fn read_frame(recv: &mut RecvStream, max: usize) -> Result<Vec<u8>, TunnelError> {
    let lost = |e: quinn::ReadExactError| TunnelError::ConnectionLost(e.to_string());
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
        conn: Connection,
        control: SendStream,
        mut recv: RecvStream,
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
        let (mut send, recv) = self
            .shared
            .conn
            .open_bi()
            .await
            .map_err(TunnelError::from)?;
        send.set_priority(class.priority())
            .map_err(|e| TunnelError::ConnectionLost(e.to_string()))?;
        send.write_all(&channel::encode_header(session, class))
            .await
            .map_err(|e| TunnelError::ConnectionLost(e.to_string()))?;
        Ok(Channel { send, recv })
    }

    /// Accepts the next session channel opened by the peer.
    ///
    /// # Errors
    ///
    /// [`TunnelError::ConnectionLost`], or [`TunnelError::Protocol`] /
    /// [`TunnelError::Version`] for a bad header (the stream is refused, the
    /// tunnel stays up).
    pub async fn accept_channel(&self) -> Result<(Uuid, StreamClass, Channel), TunnelError> {
        let (mut send, mut recv) = self
            .shared
            .conn
            .accept_bi()
            .await
            .map_err(TunnelError::from)?;
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
                let _ = recv.stop(VarInt::from_u32(CLOSE_ERROR));
                let _ = send.reset(VarInt::from_u32(CLOSE_ERROR));
                return Err(e);
            }
        };
        send.set_priority(class.priority())
            .map_err(|e| TunnelError::ConnectionLost(e.to_string()))?;
        Ok((session, class, Channel { send, recv }))
    }

    /// Smoothed round-trip time measured by QUIC.
    pub fn rtt(&self) -> Duration {
        self.shared.conn.rtt()
    }

    /// The certificate presented by the peer, if any.
    pub fn peer_certificate(&self) -> Option<CertificateDer<'static>> {
        peer_certificate(&self.shared.conn)
    }

    /// Waits until the tunnel is closed and says why.
    pub async fn closed(&self) -> TunnelError {
        let error = self.shared.conn.closed().await;
        let own = self.shared.failure.lock().ok().and_then(|f| f.clone());
        own.unwrap_or_else(|| error.into())
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
        self.shared.conn.close_reason().is_some()
    }
}

impl<Out: Message, In: Message> Drop for Tunnel<Out, In> {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        self.shared.conn.close(VarInt::from_u32(0), b"");
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
    /// with [`ALPN`].
    pub tls: Arc<ClientConfig>,
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

/// Dials the core, says hello and returns the agent end of the tunnel.
///
/// # Errors
///
/// A TLS refusal (`TUN-E001` to `TUN-E009`, `TUN-E016`), a protocol error,
/// a timeout or a local failure.
pub async fn connect(config: &AgentConfig) -> Result<(AgentTunnel, HelloAck), TunnelError> {
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

    // In TLS 1.3 the core checks the agent certificate after the agent has
    // finished its handshake: a refusal shows up here as a lost connection.
    // Report the reason the core gave instead.
    let refused = |error: TunnelError| async {
        match error {
            TunnelError::ConnectionLost(_) => {
                match tokio::time::timeout(Duration::from_secs(1), conn.closed()).await {
                    Ok(reason) => reason.into(),
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
        let (mut send, recv) = conn.open_bi().await.map_err(TunnelError::from)?;
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
            conn.close(VarInt::from_u32(CLOSE_ERROR), e.to_string().as_bytes());
            return Err(e);
        }
        Err(e) => {
            conn.close(VarInt::from_u32(CLOSE_ERROR), e.to_string().as_bytes());
            return Err(e);
        }
    };
    let heartbeat = Duration::from_secs(u64::from(heartbeat_secs))
        .min(limits.heartbeat_interval)
        .min(limits.heartbeat_timeout / 2);
    let tunnel = Tunnel::start(
        conn,
        send,
        recv,
        heartbeat,
        limits.heartbeat_timeout,
        Some(endpoint),
    );
    tracing::info!(event = "tunnel.connected", core = %config.core, transport = "quic");
    Ok((tunnel, HelloAck { heartbeat }))
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

/// The core listener of the tunnel.
#[derive(Debug)]
pub struct CoreListener {
    endpoint: Endpoint,
    limits: Limits,
}

impl CoreListener {
    /// Listens on `addr` with a TLS server configuration from
    /// [`ostena_crypto::tls::server_config`] (client certificate required,
    /// [`ALPN`]).
    ///
    /// # Errors
    ///
    /// [`TunnelError::Config`] or [`TunnelError::Io`].
    pub fn bind(
        addr: SocketAddr,
        tls: Arc<ServerConfig>,
        limits: Limits,
    ) -> Result<Self, TunnelError> {
        let quic = QuicServerConfig::with_initial(tls, tls::quic_initial_suite())
            .map_err(|e| TunnelError::Config(e.to_string()))?;
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(quic));
        server.transport_config(limits.transport()?);
        server.migration(false);
        let endpoint =
            Endpoint::server(server, addr).map_err(|e| TunnelError::Io(e.to_string()))?;
        Ok(Self { endpoint, limits })
    }

    /// The bound address.
    ///
    /// # Errors
    ///
    /// [`TunnelError::Io`].
    pub fn local_addr(&self) -> Result<SocketAddr, TunnelError> {
        self.endpoint
            .local_addr()
            .map_err(|e| TunnelError::Io(e.to_string()))
    }

    /// The next agent connection; `None` once the listener is closed.
    pub async fn accept(&self) -> Option<Result<Accepted, TunnelError>> {
        let incoming = self.endpoint.accept().await?;
        let result = self.handshake(incoming).await;
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
        let certificate = peer_certificate(&conn).ok_or(TunnelError::NoClientCertificate)?;
        let fingerprint = tls::fingerprint(&certificate);
        let hello = within(limits.handshake_timeout, "hello de l'agent", async {
            let (send, mut recv) = conn.accept_bi().await.map_err(TunnelError::from)?;
            let frame = read_frame(&mut recv, MAX_MESSAGE).await?;
            let hello = control::decode::<AgentMessage>(&frame)?;
            Ok((send, recv, hello))
        })
        .await;
        let (send, recv, hello) = match hello {
            Ok(v) => v,
            Err(e) => {
                conn.close(VarInt::from_u32(CLOSE_ERROR), e.to_string().as_bytes());
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
            conn.close(VarInt::from_u32(CLOSE_ERROR), e.to_string().as_bytes());
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

    /// Stops accepting and closes every connection.
    pub fn close(&self) {
        self.endpoint.close(VarInt::from_u32(0), b"");
    }
}
