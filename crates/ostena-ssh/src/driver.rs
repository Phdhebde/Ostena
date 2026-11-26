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
    // must never open one towards the agent (forwarded ports, agent, X11,
    // sessions). Each is refused and audited.

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        _channel: Channel<client::Msg>,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.refuse("forwarded-tcpip", reply);
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
        _channel: Channel<client::Msg>,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.refuse("agent", reply);
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
        _channel: Channel<client::Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.refuse("x11", reply);
        Ok(())
    }
}

impl Pinned {
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
) -> Result<TargetSession, SshError> {
    let attempt = async {
        let tcp = dial(target).await?;
        let stream = Prechecked::new(tcp, Role::Client, label, timeout);
        let mismatch = Arc::new(AtomicBool::new(false));
        let handler = Pinned {
            host_key: host_key.to_bytes(),
            mismatch: mismatch.clone(),
            label: label.to_owned(),
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
