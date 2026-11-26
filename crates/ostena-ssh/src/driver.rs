//! The driver to the targets (ADR-0010): the agent joins a target with its
//! own key, behind the pre-check, and verifies the target host key against
//! the one pinned in the inventory, exactly.
//!
//! Only a [`PinnedTarget`] can be dialled: its addresses passed the scope
//! control (anti-SSRF by type, no name resolution here). They are tried in
//! order within the deadline.
//!
//! [`SshDriver`] is the [`Driver`] of the session manager (ADR-0018).
//!
//! A target opens channels towards the agent only for what the user asked
//! and the right allows (ADR-0010): a connection to a port it listens on
//! for the user (`forwarded-tcpip`, `-R`), the user's agent, an X11 client.
//! Each is offered to the [`TargetChannels`] of the session, which relays
//! it or gives it back; any other channel, or one given back, is refused.
//!
//! Events: `ssh.target_host_key_mismatch` (`SSH-E014`),
//! `ssh.target_auth_failed` (`SSH-E015`), `ssh.target_unreachable`
//! (`SSH-E016`), `ssh.target_channel_refused` (`SSH-E017`: a channel opened
//! by the target, which the library would accept by default).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ostena_crypto::p256::VerifyingKey;
use ostena_scope::PinnedTarget;
use ostena_session::{Driver, DriverConnection, Protocol};
use russh::client::{self, Handle};
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{Channel, Disconnect};
use tokio::net::TcpStream;

use crate::config;
use crate::error::SshError;
use crate::precheck::Role;
use crate::precheck::stream::Prechecked;

/// The client side: trusts the pinned host key only, as a bare key.
struct Pinned {
    host_key: [u8; ostena_crypto::p256::PUBLIC_KEY_LEN],
    mismatch: Arc<AtomicBool>,
    label: String,
    channels: Option<Arc<dyn TargetChannels>>,
}

/// A channel the target opens towards the agent, as the target describes
/// it (texts not checked: the [`TargetChannels`] decides).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetChannel {
    /// A connection to `address:port`, where the target listens for the
    /// user (`tcpip-forward`, `-R`), from `originator:originator_port`.
    ForwardedTcpip {
        /// Address the target listens on, as the forward asked it.
        address: String,
        /// Port the target listens on.
        port: u32,
        /// Address of the program that connected.
        originator: String,
        /// Its port.
        originator_port: u32,
    },
    /// A program on the target asks the user's agent.
    Agent,
    /// An X11 client on the target, from `originator:originator_port`.
    X11 {
        /// Address of the X11 client.
        originator: String,
        /// Its port.
        originator_port: u32,
    },
}

/// Takes the channels a target opens: relays those the user asked for
/// under the functions of the right.
pub trait TargetChannels: std::fmt::Debug + Send + Sync + 'static {
    /// Takes `channel` and answers `reply`, or gives `reply` back to refuse
    /// it (the driver refuses and logs it).
    ///
    /// # Errors
    ///
    /// `reply`, given back, when the channel is not relayed.
    fn offer(
        &self,
        kind: TargetChannel,
        channel: Channel<client::Msg>,
        reply: client::ChannelOpenHandle,
    ) -> Result<(), client::ChannelOpenHandle>;
}

/// The SEC1 point of an ECDSA P-256 public key, if it is one.
pub fn sec1_point(key: &russh::keys::PublicKey) -> Option<&[u8]> {
    key.key_data()
        .ecdsa()
        .map(ssh_key::public::EcdsaPublicKey::as_sec1_bytes)
}

#[allow(
    clippy::unused_async_trait_impl,
    reason = "the SSH handler methods are async by trait"
)]
impl client::Handler for Pinned {
    type Error = russh::Error;

    #[allow(clippy::manual_async_fn, reason = "the trait asks for a Send future")]
    fn check_server_key(
        &mut self,
        server: &PublicKeyOrCertificate,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        let matches = match server {
            PublicKeyOrCertificate::PublicKey { key, .. } => {
                sec1_point(key) == Some(self.host_key.as_slice())
            }
            PublicKeyOrCertificate::Certificate(_) => false,
        };
        if !matches {
            self.mismatch.store(true, Ordering::Relaxed);
        }
        async move { Ok(matches) }
    }

    // The library accepts the channels a server opens by default: a target
    // opens one towards the agent only for what the user asked (forwarded
    // ports, agent, X11), offered to the session; anything else (sessions,
    // direct channels, Unix sockets) is refused and audited.

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<client::Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let kind = TargetChannel::ForwardedTcpip {
            address: connected_address.to_owned(),
            port: connected_port,
            originator: originator_address.to_owned(),
            originator_port,
        };
        self.offer("forwarded-tcpip", kind, channel, reply);
        Ok(())
    }

    async fn server_channel_open_forwarded_streamlocal(
        &mut self,
        _channel: Channel<client::Msg>,
        _socket_path: &str,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.refuse("forwarded-streamlocal", reply);
        Ok(())
    }

    async fn server_channel_open_agent_forward(
        &mut self,
        channel: Channel<client::Msg>,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.offer("agent", TargetChannel::Agent, channel, reply);
        Ok(())
    }

    async fn server_channel_open_unknown(
        &mut self,
        _channel: Channel<client::Msg>,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.refuse("inconnu", reply);
        Ok(())
    }

    async fn server_channel_open_session(
        &mut self,
        _channel: Channel<client::Msg>,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.refuse("session", reply);
        Ok(())
    }

    async fn server_channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<client::Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.refuse("direct-tcpip", reply);
        Ok(())
    }

    async fn server_channel_open_direct_streamlocal(
        &mut self,
        _channel: Channel<client::Msg>,
        _socket_path: &str,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.refuse("direct-streamlocal", reply);
        Ok(())
    }

    async fn server_channel_open_x11(
        &mut self,
        channel: Channel<client::Msg>,
        originator_address: &str,
        originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let kind = TargetChannel::X11 {
            originator: originator_address.to_owned(),
            originator_port,
        };
        self.offer("x11", kind, channel, reply);
        Ok(())
    }
}

impl Pinned {
    /// Offers a channel to the session; refused if it gives it back.
    fn offer(
        &self,
        name: &str,
        kind: TargetChannel,
        channel: Channel<client::Msg>,
        reply: client::ChannelOpenHandle,
    ) {
        let reply = match &self.channels {
            Some(channels) => match channels.offer(kind, channel, reply) {
                Ok(()) => return,
                Err(reply) => reply,
            },
            None => reply,
        };
        self.refuse(name, reply);
    }

    /// Refuses a channel opened by the target (dropping the handle sends the
    /// refusal) and audits it.
    fn refuse(&self, kind: &str, reply: client::ChannelOpenHandle) {
        drop(reply);
        let error = SshError::Refused("canal ouvert par la cible");
        tracing::warn!(
            event = "ssh.target_channel_refused",
            code = error.code(),
            target = %self.label,
            kind,
            "{error}"
        );
    }
}

/// An authenticated connection to a target.
pub struct TargetSession {
    handle: Handle<Pinned>,
    label: String,
}

impl std::fmt::Debug for TargetSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TargetSession")
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

impl TargetSession {
    /// Opens the session channel on the target.
    ///
    /// # Errors
    ///
    /// [`SshError::TargetUnreachable`] if the target refuses or the
    /// connection is gone.
    pub async fn open_session(&self) -> Result<Channel<client::Msg>, SshError> {
        self.handle
            .channel_open_session()
            .await
            .map_err(|e| SshError::TargetUnreachable(format!("canal refusé par la cible : {e}")))
    }

    /// Opens a `direct-tcpip` channel on the target, to `host:port` as the
    /// target reaches it (local forwarding, `-W`, `ProxyJump`). The target
    /// decides too: the `restrict` option of the agent key forbids it
    /// unless `port-forwarding` is added there.
    ///
    /// # Errors
    ///
    /// [`SshError::Refused`] if the target refuses or the connection is
    /// gone.
    pub async fn open_direct_tcpip(
        &self,
        host: &str,
        port: u32,
        originator: &str,
        originator_port: u32,
    ) -> Result<Channel<client::Msg>, SshError> {
        self.handle
            .channel_open_direct_tcpip(host, port, originator, originator_port)
            .await
            .map_err(|_| SshError::Refused("redirection refusée par la cible"))
    }

    /// Asks the target to listen on `address:port` for the user (`-R`);
    /// the port it listens on (chosen by the target when `port` is 0).
    ///
    /// # Errors
    ///
    /// [`SshError::Refused`] if the target refuses (its configuration, or
    /// the `restrict` option of the agent key) or the connection is gone.
    pub async fn tcpip_forward(&self, address: &str, port: u32) -> Result<u32, SshError> {
        let listening = self
            .handle
            .tcpip_forward(address, port)
            .await
            .map_err(|_| SshError::Refused("redirection distante refusée par la cible"))?;
        Ok(if port == 0 { listening } else { port })
    }

    /// Asks the target to stop listening on `address:port`.
    ///
    /// # Errors
    ///
    /// [`SshError::Refused`] if the target refuses or the connection is
    /// gone.
    pub async fn cancel_tcpip_forward(&self, address: &str, port: u32) -> Result<(), SshError> {
        self.handle
            .cancel_tcpip_forward(address, port)
            .await
            .map_err(|_| SshError::Refused("fin de redirection refusée par la cible"))
    }

    /// Closes the connection.
    pub async fn close(&self) {
        let _ = self
            .handle
            .disconnect(Disconnect::ByApplication, "", "fr")
            .await;
    }

    /// Whether the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }
}

fn unreachable(label: &str, error: SshError) -> SshError {
    tracing::warn!(
        event = "ssh.target_unreachable",
        code = error.code(),
        target = label,
        "{error}"
    );
    error
}

async fn dial(target: &PinnedTarget) -> Result<TcpStream, SshError> {
    let mut last = String::from("aucune adresse");
    for addr in target.addrs() {
        match TcpStream::connect(addr).await {
            Ok(tcp) => {
                // The library sets it only on the sockets it opens itself.
                let _ = tcp.set_nodelay(true);
                return Ok(tcp);
            }
            Err(e) => last = format!("{addr} : {e}"),
        }
    }
    Err(SshError::TargetUnreachable(last))
}

/// Connects to `target` behind the pre-check, checks that its host key is
/// exactly `host_key`, and authenticates as `account` with `agent_key`,
/// all within `timeout`. `label` names the target in events.
///
/// # Errors
///
/// [`SshError::TargetHostKey`] (`SSH-E014`), [`SshError::TargetAuth`]
/// (`SSH-E015`), [`SshError::TargetUnreachable`] (`SSH-E016`), each with
/// its event.
pub async fn connect(
    target: &PinnedTarget,
    host_key: &VerifyingKey,
    account: &str,
    agent_key: Arc<PrivateKey>,
    timeout: Duration,
    label: &str,
    channels: Option<Arc<dyn TargetChannels>>,
) -> Result<TargetSession, SshError> {
    let attempt = async {
        let tcp = dial(target).await?;
        let stream = Prechecked::new(tcp, Role::Client, label, timeout);
        let mismatch = Arc::new(AtomicBool::new(false));
        let handler = Pinned {
            host_key: host_key.to_bytes(),
            mismatch: mismatch.clone(),
            label: label.to_owned(),
            channels,
        };
        let mut handle = match client::connect_stream(config::client(), stream, handler).await {
            Ok(handle) => handle,
            Err(_) if mismatch.load(Ordering::Relaxed) => {
                let error = SshError::TargetHostKey;
                tracing::warn!(
                    event = "ssh.target_host_key_mismatch",
                    code = error.code(),
                    target = label,
                    "{error}"
                );
                return Err(error);
            }
            Err(e) => {
                return Err(SshError::TargetUnreachable(format!(
                    "négociation impossible : {e}"
                )));
            }
        };
        let auth = handle
            .authenticate_publickey(account, PrivateKeyWithHashAlg::new(agent_key, None))
            .await
            .map_err(|e| SshError::TargetUnreachable(e.to_string()))?;
        if !auth.success() {
            let error = SshError::TargetAuth;
            tracing::warn!(
                event = "ssh.target_auth_failed",
                code = error.code(),
                target = label,
                "{error}"
            );
            let _ = handle.disconnect(Disconnect::ByApplication, "", "fr").await;
            return Err(error);
        }
        Ok(TargetSession {
            handle,
            label: label.to_owned(),
        })
    };
    match tokio::time::timeout(timeout, attempt).await {
        Ok(Ok(session)) => Ok(session),
        Ok(Err(e @ SshError::TargetUnreachable(_))) => Err(unreachable(label, e)),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(unreachable(
            label,
            SshError::TargetUnreachable(format!("pas de session en {} s", timeout.as_secs())),
        )),
    }
}

/// What the SSH driver needs besides the target.
#[derive(Debug, Clone)]
pub struct TargetParams {
    /// Takes the channels the target opens (none: all refused).
    pub channels: Option<Arc<dyn TargetChannels>>,
    /// The target host key, pinned in the inventory.
    pub host_key: VerifyingKey,
    /// Account on the target.
    pub account: String,
    /// Names the target in events (`account@resource`, sanitised).
    pub label: String,
}

/// The SSH driver of the session manager: joins the targets with the key
/// of the agent ([`connect`]).
#[derive(Clone)]
pub struct SshDriver {
    key: Arc<PrivateKey>,
}

impl std::fmt::Debug for SshDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SshDriver")
    }
}

impl SshDriver {
    /// A driver authenticating with `key` on the targets.
    pub fn new(key: Arc<PrivateKey>) -> Self {
        Self { key }
    }
}

impl Driver for SshDriver {
    type Params = TargetParams;
    type Connection = TargetSession;
    type Error = SshError;

    const PROTOCOL: Protocol = Protocol::Ssh;

    fn connect(
        &self,
        target: &PinnedTarget,
        params: TargetParams,
        timeout: Duration,
    ) -> impl Future<Output = Result<TargetSession, SshError>> + Send {
        let key = self.key.clone();
        async move {
            connect(
                target,
                &params.host_key,
                &params.account,
                key,
                timeout,
                &params.label,
                params.channels,
            )
            .await
        }
    }
}

impl DriverConnection for TargetSession {
    fn close(&self) -> impl Future<Output = ()> + Send {
        TargetSession::close(self)
    }

    fn is_closed(&self) -> bool {
        TargetSession::is_closed(self)
    }
}
