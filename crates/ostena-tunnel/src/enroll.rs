//! Enrolment (ADR-0008): the first contact of an agent with the core.
//!
//! The core issues a single-use, short-lived token bound to a gateway group.
//! The agent generates its key locally, connects to the **enrolment
//! listener** (TLS 1.3, the core authenticated by the pinned root, no client
//! certificate, ALPN `ostena-enroll/1`) and proves possession of the token and
//! of its new key; the core consumes the token atomically and issues a
//! certificate for that key, bound to the group.
//!
//! The listener is **closed by default**: it is bound only while at least one
//! valid token exists, and closed as soon as none is left (used or expired).
//! It serves the enrolment protocol only: any other ALPN fails the TLS
//! handshake, and any other message closes the connection.
//!
//! Protocol, on one bidirectional stream (length-prefixed strict JSON, at most
//! 16 KiB): core → `challenge` (fresh nonce); agent → `request`; core →
//! `accepted` or `refused`.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ostena_common::secret::SecretBytes;
use ostena_crypto::p256::{self, Signature, SigningKey, VerifyingKey};
use ostena_crypto::pki::{IssuingAuthority, Validity};
use ostena_crypto::tls::{self, ClientAuth, Identity, ServerConfig, TrustAnchor};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{Connection, Endpoint, VarInt};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use crate::error::TunnelError;
use crate::ids::Uuid;
use crate::limits::Limits;
use crate::link::{Clock, SystemClock};
use crate::transport::ChannelRecv;
use crate::tunnel::{check_protocol, peer_certificate, read_frame, within};

/// Application protocol of the enrolment listener.
pub const ENROLL_ALPN: &[u8] = b"ostena-enroll/1";
/// Version of the enrolment protocol.
pub const ENROLL_PROTOCOL: u16 = 1;
/// Largest enrolment message.
pub const MAX_ENROLL_MESSAGE: usize = 16 * 1024;
/// Default token lifetime.
pub const DEFAULT_TOKEN_TTL: Duration = Duration::from_mins(15);
/// Longest token lifetime.
pub const MAX_TOKEN_TTL: Duration = Duration::from_hours(1);
/// Failed attempts after which a token is burned, whatever their cause.
pub const MAX_TOKEN_FAILURES: u8 = 3;
/// Default validity of an agent certificate.
pub const DEFAULT_CERTIFICATE_LIFETIME: Duration = Duration::from_hours(30 * 24);

const TOKEN_PREFIX: &str = "ostena-enroll-v1.";
const POP_DOMAIN: &[u8] = b"ostena-enroll-pop-v1\0";
const CLOSE_ERROR: u32 = 1;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn invalid(what: impl Into<String>) -> TunnelError {
    TunnelError::Protocol(what.into())
}

fn b64<const N: usize>(field: &str, text: &str) -> Result<[u8; N], TunnelError> {
    URL_SAFE_NO_PAD
        .decode(text)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| invalid(format!("{field} : base64url de {N} octets attendu")))
}

/// An enrolment token: an identifier and a 256-bit secret. No `Debug`.
pub struct EnrollmentToken {
    id: [u8; 16],
    secret: SecretBytes,
}

impl EnrollmentToken {
    /// Draws a token.
    ///
    /// # Errors
    ///
    /// If the system random generator fails.
    pub fn generate() -> Result<Self, TunnelError> {
        let random = |e: ostena_crypto::CryptoError| TunnelError::Io(e.to_string());
        Ok(Self {
            id: ostena_crypto::rand::array().map_err(random)?,
            secret: SecretBytes::from(ostena_crypto::rand::array::<32>().map_err(random)?.to_vec()),
        })
    }

    /// The text form handed to the agent operator:
    /// `ostena-enroll-v1.<id>.<secret>`, base64url. It is a secret.
    pub fn to_text(&self) -> SecretBytes {
        // SECRET-EXPOSURE: encoded into a new secret, written once to a token file.
        #[expect(clippy::disallowed_methods)]
        let secret = URL_SAFE_NO_PAD.encode(self.secret.expose_secret());
        let text = format!("{TOKEN_PREFIX}{}.{secret}", URL_SAFE_NO_PAD.encode(self.id));
        SecretBytes::from(text.into_bytes())
    }

    /// Parses the text form; surrounding whitespace is ignored.
    ///
    /// # Errors
    ///
    /// [`TunnelError::TokenUnknown`] for anything else.
    pub fn parse(text: &SecretBytes) -> Result<Self, TunnelError> {
        // SECRET-EXPOSURE: the token text is decoded into a new secret.
        #[expect(clippy::disallowed_methods)]
        let text =
            std::str::from_utf8(text.expose_secret()).map_err(|_| TunnelError::TokenUnknown)?;
        let rest = text
            .trim()
            .strip_prefix(TOKEN_PREFIX)
            .ok_or(TunnelError::TokenUnknown)?;
        let (id, secret) = rest.split_once('.').ok_or(TunnelError::TokenUnknown)?;
        let id = b64::<16>("id", id).map_err(|_| TunnelError::TokenUnknown)?;
        let secret = b64::<32>("secret", secret).map_err(|_| TunnelError::TokenUnknown)?;
        Ok(Self {
            id,
            secret: SecretBytes::from(secret.to_vec()),
        })
    }

    /// The token identifier (not secret).
    pub fn id(&self) -> [u8; 16] {
        self.id
    }

    /// The SHA-256 of the secret: all the core keeps.
    pub fn secret_digest(&self) -> [u8; 32] {
        // SECRET-EXPOSURE: hashed; the core keeps only the digest.
        #[expect(clippy::disallowed_methods)]
        let secret = self.secret.expose_secret();
        ostena_crypto::sha256::digest(secret)
    }
}

/// Messages from the core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnrollServer {
    /// First message: a fresh nonce to sign.
    Challenge {
        /// [`ENROLL_PROTOCOL`].
        protocol: u16,
        /// 32 random bytes, base64url.
        nonce: String,
    },
    /// The certificate.
    Accepted {
        /// Agent certificate (PEM).
        certificate: String,
        /// Agent identifier (UUID).
        agent_id: String,
        /// Start of validity (Unix seconds).
        not_before: u64,
        /// End of validity (Unix seconds).
        not_after: u64,
    },
    /// Refused, with a stable code (`TUN-E018` to `TUN-E022`).
    Refused {
        /// Code.
        code: String,
        /// Explanation.
        message: String,
    },
}

/// The agent request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnrollClient {
    /// The enrolment request.
    Request {
        /// [`ENROLL_PROTOCOL`].
        protocol: u16,
        /// Token identifier (16 bytes, base64url).
        token_id: String,
        /// Token secret (32 bytes, base64url), only inside TLS.
        token_secret: String,
        /// Gateway group of the agent configuration (UUID).
        gateway_group: String,
        /// New public key, uncompressed SEC1 (65 bytes, base64url).
        public_key: String,
        /// Proof of possession: ECDSA P-256 signature (64 bytes, base64url)
        /// over the domain, the nonce, the token id, the group, the public key
        /// and the SHA-256 of the core certificate seen by the agent.
        signature: String,
    },
}

fn text_field(field: &str, value: &str, max: usize) -> Result<(), TunnelError> {
    if value.len() > max || value.chars().any(char::is_control) {
        return Err(invalid(format!(
            "{field} trop long ou avec des caractères de contrôle"
        )));
    }
    Ok(())
}

impl EnrollServer {
    fn validate(&self) -> Result<(), TunnelError> {
        match self {
            Self::Challenge { protocol, nonce } => {
                if *protocol != ENROLL_PROTOCOL {
                    return Err(TunnelError::Version(*protocol));
                }
                b64::<32>("nonce", nonce).map(|_| ())
            }
            Self::Accepted {
                certificate,
                agent_id,
                not_before,
                not_after,
            } => {
                let pem_chars = certificate
                    .bytes()
                    .all(|b| b.is_ascii_graphic() || matches!(b, b' ' | b'\n' | b'\r'));
                if certificate.len() > 8 * 1024
                    || !pem_chars
                    || !certificate.starts_with("-----BEGIN CERTIFICATE-----")
                {
                    return Err(invalid("certificate n'est pas un certificat PEM"));
                }
                Uuid::parse(agent_id).ok_or_else(|| invalid("agent_id n'est pas un UUID"))?;
                if not_after <= not_before {
                    return Err(invalid("validité incohérente"));
                }
                Ok(())
            }
            Self::Refused { code, message } => {
                text_field("code", code, 8)?;
                text_field("message", message, 256)
            }
        }
    }
}

impl EnrollClient {
    fn validate(&self) -> Result<(), TunnelError> {
        let Self::Request {
            protocol,
            token_id,
            token_secret,
            gateway_group,
            public_key,
            signature,
        } = self;
        if *protocol != ENROLL_PROTOCOL {
            return Err(TunnelError::Version(*protocol));
        }
        b64::<16>("token_id", token_id)?;
        b64::<32>("token_secret", token_secret)?;
        Uuid::parse(gateway_group).ok_or_else(|| invalid("gateway_group n'est pas un UUID"))?;
        let key = b64::<{ p256::PUBLIC_KEY_LEN }>("public_key", public_key)?;
        VerifyingKey::from_bytes(&key).map_err(|_| invalid("public_key invalide"))?;
        b64::<{ p256::SIGNATURE_LEN }>("signature", signature)?;
        Ok(())
    }
}

fn decode<M: DeserializeOwned>(payload: &[u8]) -> Result<M, TunnelError> {
    if payload.len() > MAX_ENROLL_MESSAGE {
        return Err(invalid("message trop long"));
    }
    serde_json::from_slice(payload).map_err(|e| invalid(format!("JSON refusé : {e}")))
}

/// Decodes and checks a core message (also the fuzz entry point).
///
/// # Errors
///
/// [`TunnelError::Protocol`] or [`TunnelError::Version`].
pub fn decode_server(payload: &[u8]) -> Result<EnrollServer, TunnelError> {
    let m: EnrollServer = decode(payload)?;
    m.validate()?;
    Ok(m)
}

/// Decodes and checks an agent message (also the fuzz entry point).
///
/// # Errors
///
/// [`TunnelError::Protocol`] or [`TunnelError::Version`].
pub fn decode_client(payload: &[u8]) -> Result<EnrollClient, TunnelError> {
    let m: EnrollClient = decode(payload)?;
    m.validate()?;
    Ok(m)
}

fn frame<M: Serialize>(message: &M) -> Result<Vec<u8>, TunnelError> {
    let payload = serde_json::to_vec(message).map_err(|e| invalid(e.to_string()))?;
    if payload.len() > MAX_ENROLL_MESSAGE {
        return Err(invalid("message trop long"));
    }
    let len = u32::try_from(payload.len()).map_err(|_| invalid("message trop long"))?;
    let mut out = len.to_be_bytes().to_vec();
    out.extend_from_slice(&payload);
    Ok(out)
}

fn proof_message(
    nonce: &[u8; 32],
    token_id: &[u8; 16],
    group: Uuid,
    public_key: &[u8; p256::PUBLIC_KEY_LEN],
    core_certificate: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(POP_DOMAIN.len() + 32 + 16 + 16 + 65 + 32);
    m.extend_from_slice(POP_DOMAIN);
    m.extend_from_slice(nonce);
    m.extend_from_slice(token_id);
    m.extend_from_slice(&group.to_bytes());
    m.extend_from_slice(public_key);
    m.extend_from_slice(core_certificate);
    m
}

// ------------------------------------------------------------------ agent

/// What an agent needs to enrol.
pub struct EnrollParams<'a> {
    /// Enrolment listener address (resolved).
    pub address: SocketAddr,
    /// Name expected in the core certificate.
    pub server_name: String,
    /// The root the agent pins.
    pub root: &'a TrustAnchor,
    /// The token.
    pub token: &'a EnrollmentToken,
    /// Gateway group of the agent configuration.
    pub gateway_group: Uuid,
    /// The new key, generated by the agent.
    pub key: &'a SigningKey,
    /// Deadline for the whole exchange.
    pub timeout: Duration,
}

/// The result of an enrolment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrolled {
    /// Agent certificate (PEM).
    pub certificate: String,
    /// Agent identifier.
    pub agent_id: Uuid,
    /// Start of validity (Unix seconds).
    pub not_before: u64,
    /// End of validity (Unix seconds).
    pub not_after: u64,
}

/// Enrols the agent: proves the token and the new key, returns the
/// certificate. The private key never leaves the agent.
///
/// # Errors
///
/// `TUN-E018` to `TUN-E022` when the core refuses, a TLS refusal, a protocol
/// error, or a timeout (also when the listener is closed).
pub async fn enroll(params: &EnrollParams<'_>) -> Result<Enrolled, TunnelError> {
    let tls = tls::client_config(params.root, None, &[ENROLL_ALPN])
        .map_err(|e| TunnelError::Config(e.to_string()))?;
    let quic = QuicClientConfig::with_initial(tls, tls::quic_initial_suite())
        .map_err(|e| TunnelError::Config(e.to_string()))?;
    let mut client = quinn::ClientConfig::new(Arc::new(quic));
    let limits = Limits {
        handshake_timeout: params.timeout,
        ..Limits::default()
    };
    client.transport_config(limits.transport()?);
    let bind: SocketAddr = if params.address.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let endpoint = Endpoint::client(bind).map_err(|e| TunnelError::Io(e.to_string()))?;
    let result = within(params.timeout, "enrôlement", async {
        let conn = endpoint
            .connect_with(client, params.address, &params.server_name)
            .map_err(|e| TunnelError::Config(e.to_string()))?
            .await
            .map_err(TunnelError::from)?;
        let out = exchange(&conn, params).await;
        conn.close(VarInt::from_u32(0), b"");
        out
    })
    .await;
    endpoint.close(VarInt::from_u32(0), b"");
    // Let the close reach the core before the process may exit: the core
    // then frees the listener at once instead of waiting for a timeout.
    let _ = tokio::time::timeout(Duration::from_secs(1), endpoint.wait_idle()).await;
    result
}

async fn exchange(conn: &Connection, params: &EnrollParams<'_>) -> Result<Enrolled, TunnelError> {
    check_protocol(conn, ENROLL_ALPN)?;
    let core_certificate = peer_certificate(conn)
        .map(|c| tls::fingerprint(&c))
        .ok_or(TunnelError::NoClientCertificate)?;
    let lost = |e: quinn::WriteError| TunnelError::ConnectionLost(e.to_string());
    // The core opens the stream and sends the challenge.
    let (mut send, recv) = conn.accept_bi().await.map_err(TunnelError::from)?;
    let mut recv = ChannelRecv::Quic(recv);
    let challenge = decode_server(&read_frame(&mut recv, MAX_ENROLL_MESSAGE).await?)?;
    let EnrollServer::Challenge { nonce, .. } = challenge else {
        return Err(invalid("défi attendu"));
    };
    let nonce = b64::<32>("nonce", &nonce)?;
    let public_key = params.key.verifying_key().to_bytes();
    let proof = proof_message(
        &nonce,
        &params.token.id,
        params.gateway_group,
        &public_key,
        &core_certificate,
    );
    let signature = params
        .key
        .sign(&proof)
        .map_err(|e| TunnelError::Io(e.to_string()))?;
    // SECRET-EXPOSURE: the token secret is sent once, inside TLS.
    #[expect(clippy::disallowed_methods)]
    let token_secret = URL_SAFE_NO_PAD.encode(params.token.secret.expose_secret());
    let request = EnrollClient::Request {
        protocol: ENROLL_PROTOCOL,
        token_id: URL_SAFE_NO_PAD.encode(params.token.id),
        token_secret,
        gateway_group: params.gateway_group.to_string(),
        public_key: URL_SAFE_NO_PAD.encode(public_key),
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    };
    send.write_all(&frame(&request)?).await.map_err(lost)?;
    let _ = send.finish();
    match decode_server(&read_frame(&mut recv, MAX_ENROLL_MESSAGE).await?)? {
        EnrollServer::Accepted {
            certificate,
            agent_id,
            not_before,
            not_after,
        } => {
            // The certificate must be for our key.
            let der = TrustAnchor::from_pem(certificate.as_bytes())
                .map_err(|_| invalid("certificat illisible"))?;
            if !der
                .certificate()
                .windows(public_key.len())
                .any(|w| w == public_key)
            {
                return Err(invalid("certificat émis pour une autre clé"));
            }
            Ok(Enrolled {
                certificate,
                agent_id: Uuid::parse(&agent_id).ok_or_else(|| invalid("agent_id"))?,
                not_before,
                not_after,
            })
        }
        EnrollServer::Refused { code, message } => Err(TunnelError::from_code(&code)
            .unwrap_or_else(|| invalid(format!("refus du core : {code} {message}")))),
        EnrollServer::Challenge { .. } => Err(invalid("second défi inattendu")),
    }
}

// ------------------------------------------------------------------- core

/// What the core stores return: a boxed future, so that the traits stay
/// usable as `dyn` (the real core answers from PostgreSQL).
pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, TunnelError>> + Send + 'a>>;

/// Where the core records enrolled agents (its registry).
pub trait AgentRegistry: Send + Sync {
    /// Records the certificate `fingerprint` of `agent` in `group`. Nothing
    /// is handed to the agent unless it succeeds.
    fn register(&self, fingerprint: [u8; 32], group: Uuid, agent: Uuid) -> StoreFuture<'_, ()>;
}

/// An enrolment token as the core keeps it: never the secret, only its
/// SHA-256.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenRecord {
    /// SHA-256 of the secret.
    pub digest: [u8; 32],
    /// Gateway group the token enrols into.
    pub group: Uuid,
    /// Expiry, Unix seconds.
    pub expires_at: u64,
    /// Spent by a successful enrolment.
    pub used: bool,
    /// Failed attempts so far.
    pub failures: u8,
    /// Invalidated after [`MAX_TOKEN_FAILURES`] failures.
    pub burned: bool,
}

impl TokenRecord {
    /// A fresh token for `group`, expiring at `expires_at`.
    pub fn new(digest: [u8; 32], group: Uuid, expires_at: u64) -> Self {
        Self {
            digest,
            group,
            expires_at,
            used: false,
            failures: 0,
            burned: false,
        }
    }

    /// Whether the token can still enrol an agent at `now`.
    pub fn valid_at(&self, now: u64) -> bool {
        !self.used && !self.burned && now < self.expires_at
    }
}

/// The checks on one token, run while the store holds it.
pub type TokenDecision = Box<dyn FnOnce(&mut TokenRecord) -> Result<(), TunnelError> + Send>;

/// Where the core keeps the enrolment tokens.
pub trait TokenStore: Send + Sync {
    /// Stores a new token.
    fn insert(&self, id: [u8; 16], record: TokenRecord) -> StoreFuture<'_, ()>;

    /// Runs `decide` on token `id` while no other attempt can read it, then
    /// stores the record as `decide` left it, whether it succeeded or not
    /// (spent token, failure counter). Returns what `decide` returned, or
    /// [`TunnelError::TokenUnknown`] if there is no such token.
    fn decide(&self, id: [u8; 16], decide: TokenDecision) -> StoreFuture<'_, ()>;

    /// The earliest expiry among the tokens still valid at `now`.
    fn next_expiry(&self, now: u64) -> StoreFuture<'_, Option<u64>>;
}

/// Tokens in memory: the test core, and any core that does not need them to
/// outlive the process.
#[derive(Debug, Default)]
pub struct MemoryTokenStore(Mutex<HashMap<[u8; 16], TokenRecord>>);

fn poisoned() -> TunnelError {
    TunnelError::Io("verrou empoisonné".into())
}

impl TokenStore for MemoryTokenStore {
    fn insert(&self, id: [u8; 16], record: TokenRecord) -> StoreFuture<'_, ()> {
        let stored = self
            .0
            .lock()
            .map(|mut tokens| {
                tokens.insert(id, record);
            })
            .map_err(|_| poisoned());
        Box::pin(std::future::ready(stored))
    }

    fn decide(&self, id: [u8; 16], decide: TokenDecision) -> StoreFuture<'_, ()> {
        let decided = self
            .0
            .lock()
            .map_err(|_| poisoned())
            .and_then(|mut tokens| {
                let record = tokens.get_mut(&id).ok_or(TunnelError::TokenUnknown)?;
                decide(record)
            });
        Box::pin(std::future::ready(decided))
    }

    fn next_expiry(&self, now: u64) -> StoreFuture<'_, Option<u64>> {
        let next = self
            .0
            .lock()
            .map(|tokens| {
                tokens
                    .values()
                    .filter(|t| t.valid_at(now))
                    .map(|t| t.expires_at)
                    .min()
            })
            .map_err(|_| poisoned());
        Box::pin(std::future::ready(next))
    }
}

/// Discards what reached the kept socket while the listener was closed:
/// handshakes of agents that have given up since. At most 1024 datagrams, so
/// that a flood cannot hold the caller.
fn drain(socket: &std::net::UdpSocket) {
    if socket.set_nonblocking(true).is_err() {
        return;
    }
    let mut buf = [0u8; 1500];
    for _ in 0..1024 {
        match socket.recv_from(&mut buf) {
            Ok(_) => {}
            // Windows reports an ICMP "port unreachable" on the next read.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            Err(_) => break,
        }
    }
}

/// Counts a failed attempt on a known token, whatever its cause, and burns
/// the token at the third; raises `tunnel.enrollment_suspicious` for a token
/// of another group, an invalid proof or a burned token. Never logs the
/// secret.
fn record_failure(
    entry: &mut TokenRecord,
    mut error: TunnelError,
    peer: SocketAddr,
    group: Uuid,
    token_id: &[u8; 16],
) -> TunnelError {
    if !matches!(error, TunnelError::TokenBurned | TunnelError::TokenUsed) {
        entry.failures = entry.failures.saturating_add(1);
        if entry.failures >= MAX_TOKEN_FAILURES {
            entry.burned = true;
            error = TunnelError::TokenBurned;
        }
    }
    if matches!(
        error,
        TunnelError::TokenGroup | TunnelError::ProofOfPossession | TunnelError::TokenBurned
    ) {
        tracing::warn!(
            event = "tunnel.enrollment_suspicious",
            peer = %peer,
            requested_group = %group,
            token_id = %hex(token_id),
            failures = entry.failures,
            code = error.code(),
            "{error}"
        );
    }
    error
}

struct Inner {
    addr: SocketAddr,
    tls: Arc<ServerConfig>,
    server_fingerprint: [u8; 32],
    issuer: Arc<IssuingAuthority>,
    registry: Arc<dyn AgentRegistry>,
    lifetime: Duration,
    handshake_timeout: Duration,
    tokens: Arc<dyn TokenStore>,
    listener: Mutex<Option<(Endpoint, JoinHandle<()>)>>,
    clock: Arc<dyn Clock>,
    /// A socket bound once for the life of the service: the listener opens
    /// on a copy of it instead of binding `addr` again, so no other socket
    /// can take the port while the listener is closed.
    socket: Option<std::net::UdpSocket>,
}

/// The core enrolment service: tokens, listener lifecycle, issuance.
#[derive(Clone)]
pub struct EnrollmentService {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for EnrollmentService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollmentService")
            .field("addr", &self.inner.addr)
            .field("open", &self.is_open())
            .finish_non_exhaustive()
    }
}

/// The outcome of one enrolment attempt, for the core audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Certificate issued.
    Enrolled {
        /// Agent identifier.
        agent: Uuid,
        /// Gateway group.
        group: Uuid,
        /// Certificate fingerprint.
        fingerprint: [u8; 32],
    },
    /// Refused.
    Refused(TunnelError),
}

impl EnrollmentService {
    /// A service listening on `addr` when a token is valid, presenting
    /// `server` (the core certificate signed by the root) and issuing with
    /// `issuer`. Nothing is bound yet.
    ///
    /// # Errors
    ///
    /// [`TunnelError::Config`] if the TLS configuration is refused.
    pub fn new(
        addr: SocketAddr,
        server: &Identity,
        issuer: Arc<IssuingAuthority>,
        registry: Arc<dyn AgentRegistry>,
        tokens: Arc<dyn TokenStore>,
        lifetime: Duration,
        handshake_timeout: Duration,
    ) -> Result<Self, TunnelError> {
        let tls = tls::server_config(server, ClientAuth::None, &[ENROLL_ALPN])
            .map_err(|e| TunnelError::Config(e.to_string()))?;
        Ok(Self {
            inner: Arc::new(Inner {
                addr,
                tls,
                server_fingerprint: tls::fingerprint(server.certificate()),
                issuer,
                registry,
                lifetime,
                handshake_timeout,
                tokens,
                listener: Mutex::new(None),
                clock: Arc::new(SystemClock),
                socket: None,
            }),
        })
    }

    /// The same service on another wall clock (tests). Call it before any
    /// token is issued.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.clock = clock;
        }
        self
    }

    /// The same service on `socket`, kept bound for the life of the
    /// service: the listener opens on it and its address replaces the one
    /// given to [`EnrollmentService::new`]. Binding a port, releasing it and
    /// binding it again when the first token is issued lets another socket
    /// take it in between (tests on an ephemeral port). Call it before any
    /// token is issued.
    ///
    /// # Errors
    ///
    /// [`TunnelError::Io`] if the address of `socket` cannot be read.
    pub fn with_socket(mut self, socket: std::net::UdpSocket) -> Result<Self, TunnelError> {
        let addr = socket
            .local_addr()
            .map_err(|e| TunnelError::Io(e.to_string()))?;
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.addr = addr;
            inner.socket = Some(socket);
        }
        Ok(self)
    }

    fn now(&self) -> u64 {
        self.inner.clock.now()
    }

    /// A new token for `group`, valid `ttl` (at most one hour) from `now`,
    /// and the record the core stores for it. Nothing is stored.
    ///
    /// # Errors
    ///
    /// [`TunnelError::Config`] for a lifetime out of bounds, or if the random
    /// generator fails.
    pub fn new_token(
        group: Uuid,
        ttl: Duration,
        now: u64,
    ) -> Result<(EnrollmentToken, TokenRecord), TunnelError> {
        if ttl.is_zero() || ttl > MAX_TOKEN_TTL {
            return Err(TunnelError::Config(
                "durée du jeton hors de 1 s..=1 h".into(),
            ));
        }
        let token = EnrollmentToken::generate()?;
        let record = TokenRecord::new(token.secret_digest(), group, now + ttl.as_secs().max(1));
        Ok((token, record))
    }

    /// Issues a token for `group`, valid `ttl` (at most one hour), and opens
    /// the listener if it is closed.
    ///
    /// # Errors
    ///
    /// [`TunnelError::Config`] for a lifetime out of bounds, a store error,
    /// or if the listener cannot be bound.
    ///
    /// # Panics
    ///
    /// Outside a Tokio runtime.
    pub async fn issue_token(
        &self,
        group: Uuid,
        ttl: Duration,
    ) -> Result<EnrollmentToken, TunnelError> {
        let (token, record) = Self::new_token(group, ttl, self.now())?;
        self.inner.tokens.insert(token.id, record).await?;
        self.open()?;
        tracing::info!(event = "enroll.token_issued", group = %group, ttl_secs = ttl.as_secs());
        Ok(token)
    }

    /// Opens the listener if the store holds a valid token: a token issued
    /// by another process (`ostena core agent token`).
    ///
    /// # Errors
    ///
    /// A store error, or if the listener cannot be bound.
    ///
    /// # Panics
    ///
    /// Outside a Tokio runtime.
    pub async fn wake(&self) -> Result<(), TunnelError> {
        if self.inner.tokens.next_expiry(self.now()).await?.is_some() {
            self.open()?;
        }
        Ok(())
    }

    /// Whether the listener is bound.
    pub fn is_open(&self) -> bool {
        self.inner.listener.lock().is_ok_and(|l| l.is_some())
    }

    /// The listener address.
    pub fn addr(&self) -> SocketAddr {
        self.inner.addr
    }

    /// Closes the listener now, whatever the tokens (core shutdown).
    pub fn close(&self) {
        if let Ok(mut listener) = self.inner.listener.lock()
            && let Some((endpoint, task)) = listener.take()
        {
            endpoint.close(VarInt::from_u32(0), b"");
            task.abort();
            tracing::info!(event = "enroll.listener_closed", addr = %self.inner.addr);
        }
    }

    fn open(&self) -> Result<(), TunnelError> {
        let mut listener = self
            .inner
            .listener
            .lock()
            .map_err(|_| TunnelError::Io("verrou empoisonné".into()))?;
        if listener.is_some() {
            return Ok(());
        }
        let quic =
            QuicServerConfig::with_initial(self.inner.tls.clone(), tls::quic_initial_suite())
                .map_err(|e| TunnelError::Config(e.to_string()))?;
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(quic));
        let limits = Limits {
            max_sessions: 1,
            handshake_timeout: self.inner.handshake_timeout,
            ..Limits::default()
        };
        server.transport_config(limits.transport()?);
        let io = |e: std::io::Error| TunnelError::Io(e.to_string());
        let endpoint = match &self.inner.socket {
            Some(socket) => {
                drain(socket);
                let runtime = quinn::default_runtime()
                    .ok_or_else(|| TunnelError::Io("pas de moteur Tokio".into()))?;
                Endpoint::new(
                    quinn::EndpointConfig::default(),
                    Some(server),
                    socket.try_clone().map_err(io)?,
                    runtime,
                )
                .map_err(io)?
            }
            None => Endpoint::server(server, self.inner.addr).map_err(io)?,
        };
        let service = self.clone();
        let accepting = endpoint.clone();
        let task = tokio::spawn(async move {
            // Closes the listener when the earliest token expires and none is
            // left; runs alongside the accept loop.
            let watcher = {
                let service = service.clone();
                tokio::spawn(async move {
                    loop {
                        // No valid token left, even before the first look (a
                        // token can expire within the second it was issued):
                        // close now rather than leave the listener open.
                        let Some(at) = service.next_expiry().await else {
                            service.refresh().await;
                            break;
                        };
                        let wait = at.saturating_sub(service.now());
                        tokio::time::sleep(Duration::from_secs(wait.max(1))).await;
                        if !service.refresh().await {
                            break;
                        }
                    }
                })
            };
            while let Some(incoming) = accepting.accept().await {
                let service = service.clone();
                tokio::spawn(async move {
                    let outcome = service.handle(incoming).await;
                    Self::audit(&outcome);
                    service.refresh().await;
                });
            }
            watcher.abort();
        });
        tracing::info!(event = "enroll.listener_opened", addr = %self.inner.addr);
        *listener = Some((endpoint, task));
        Ok(())
    }

    /// The earliest expiry of a valid token; none if the store cannot be
    /// read, which closes the listener (the safe side).
    async fn next_expiry(&self) -> Option<u64> {
        match self.inner.tokens.next_expiry(self.now()).await {
            Ok(next) => next,
            Err(e) => {
                tracing::warn!(event = "enroll.store_unavailable", code = e.code(), "{e}");
                None
            }
        }
    }

    /// Closes the listener if no valid token is left. Returns whether it is
    /// still open.
    async fn refresh(&self) -> bool {
        if self.next_expiry().await.is_some() {
            return true;
        }
        if let Ok(mut listener) = self.inner.listener.lock()
            && let Some((endpoint, task)) = listener.take()
        {
            endpoint.close(VarInt::from_u32(0), b"");
            task.abort();
            tracing::info!(event = "enroll.listener_closed", addr = %self.inner.addr);
        }
        false
    }

    fn audit(outcome: &Outcome) {
        match outcome {
            Outcome::Enrolled {
                agent,
                group,
                fingerprint,
            } => tracing::info!(
                event = "enroll.accepted",
                agent = %agent,
                group = %group,
                fingerprint = %hex(fingerprint),
            ),
            Outcome::Refused(e) => tracing::warn!(event = "enroll.refused", code = e.code(), "{e}"),
        }
    }

    async fn handle(&self, incoming: quinn::Incoming) -> Outcome {
        match self.try_handle(incoming).await {
            Ok(outcome) => outcome,
            Err(e) => Outcome::Refused(e),
        }
    }

    async fn try_handle(&self, incoming: quinn::Incoming) -> Result<Outcome, TunnelError> {
        let timeout = self.inner.handshake_timeout;
        let conn = within(timeout, "poignée de main", async {
            incoming
                .accept()
                .map_err(TunnelError::from)?
                .await
                .map_err(TunnelError::from)
        })
        .await?;
        check_protocol(&conn, ENROLL_ALPN)?;
        let outcome = within(timeout, "enrôlement", self.serve(&conn)).await;
        let code = if matches!(outcome, Ok(Outcome::Enrolled { .. })) {
            0
        } else {
            CLOSE_ERROR
        };
        conn.close(VarInt::from_u32(code), b"");
        outcome
    }

    /// Sends the challenge, reads the request, answers. Any message other
    /// than a well-formed request is refused (`TUN-E010`).
    async fn serve(&self, conn: &Connection) -> Result<Outcome, TunnelError> {
        let lost = |e: quinn::WriteError| TunnelError::ConnectionLost(e.to_string());
        let (mut send, recv) = conn.open_bi().await.map_err(TunnelError::from)?;
        let mut recv = ChannelRecv::Quic(recv);
        let nonce =
            ostena_crypto::rand::array::<32>().map_err(|e| TunnelError::Io(e.to_string()))?;
        let challenge = EnrollServer::Challenge {
            protocol: ENROLL_PROTOCOL,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
        };
        send.write_all(&frame(&challenge)?).await.map_err(lost)?;
        let decided = match read_frame(&mut recv, MAX_ENROLL_MESSAGE)
            .await
            .and_then(|f| decode_client(&f))
        {
            Ok(request) => self.decide(&nonce, &request, conn.remote_address()).await,
            Err(e) => Err(e),
        };
        let (reply, outcome) = match decided {
            Ok(v) => v,
            Err(e) => (
                EnrollServer::Refused {
                    code: e.code().to_owned(),
                    message: e.to_string(),
                },
                Outcome::Refused(e),
            ),
        };
        send.write_all(&frame(&reply)?).await.map_err(lost)?;
        let _ = send.finish();
        // Let the agent read the answer: it closes the connection once done.
        let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
        Ok(outcome)
    }

    /// Checks the request and, if every check passes, consumes the token
    /// atomically and issues the certificate.
    async fn decide(
        &self,
        nonce: &[u8; 32],
        request: &EnrollClient,
        peer: SocketAddr,
    ) -> Result<(EnrollServer, Outcome), TunnelError> {
        let EnrollClient::Request {
            token_id,
            token_secret,
            gateway_group,
            public_key,
            signature,
            ..
        } = request;
        let token_id = b64::<16>("token_id", token_id)?;
        let secret = b64::<32>("token_secret", token_secret)?;
        let group = Uuid::parse(gateway_group).ok_or_else(|| invalid("gateway_group"))?;
        let key_bytes = b64::<{ p256::PUBLIC_KEY_LEN }>("public_key", public_key)?;
        let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| invalid("public_key"))?;
        let signature =
            Signature::from_bytes(&b64::<{ p256::SIGNATURE_LEN }>("signature", signature)?);
        let token_now = self.now();
        let proof = proof_message(
            nonce,
            &token_id,
            group,
            &key_bytes,
            &self.inner.server_fingerprint,
        );
        self.inner
            .tokens
            .decide(
                token_id,
                Box::new(move |entry: &mut TokenRecord| {
                    let checked = (|| {
                        if entry.burned {
                            return Err(TunnelError::TokenBurned);
                        }
                        if !ostena_crypto::constant_time_eq(
                            &ostena_crypto::sha256::digest(&secret),
                            &entry.digest,
                        ) {
                            return Err(TunnelError::TokenUnknown);
                        }
                        if entry.used {
                            return Err(TunnelError::TokenUsed);
                        }
                        if token_now >= entry.expires_at {
                            return Err(TunnelError::TokenExpired);
                        }
                        if entry.group != group {
                            return Err(TunnelError::TokenGroup);
                        }
                        key.verify(&proof, &signature)
                            .map_err(|_| TunnelError::ProofOfPossession)
                    })();
                    if let Err(error) = checked {
                        return Err(record_failure(entry, error, peer, group, &token_id));
                    }
                    // Every check passed: the token is spent before anything
                    // is issued.
                    entry.used = true;
                    Ok(())
                }),
            )
            .await?;
        let agent = Uuid::random().map_err(|e| TunnelError::Io(e.to_string()))?;
        // The certificate follows the real time, whatever clock the tokens use.
        let now = now();
        let validity = Validity {
            not_before: now.saturating_sub(300),
            not_after: now + self.inner.lifetime.as_secs(),
        };
        let cert = self
            .inner
            .issuer
            .issue_agent(&key, &group.to_string(), &agent.to_string(), validity)
            .map_err(|e| TunnelError::Io(e.to_string()))?;
        let fingerprint = tls::fingerprint(&cert);
        self.inner
            .registry
            .register(fingerprint, group, agent)
            .await?;
        Ok((
            EnrollServer::Accepted {
                certificate: ostena_crypto::pki::pem_certificate(&cert),
                agent_id: agent.to_string(),
                not_before: validity.not_before,
                not_after: validity.not_after,
            },
            Outcome::Enrolled {
                agent,
                group,
                fingerprint,
            },
        ))
    }
}

/// Test helpers (feature `testing`).
#[cfg(feature = "testing")]
pub mod testing {
    use super::{
        Arc, Duration, Endpoint, EnrollServer, Ipv4Addr, Limits, MAX_ENROLL_MESSAGE,
        QuicClientConfig, SocketAddr, TrustAnchor, TunnelError, VarInt, decode_server, read_frame,
        tls, within,
    };
    use crate::transport::ChannelRecv;

    /// Connects to an enrolment listener offering `alpn`, waits for the
    /// challenge and sends `payload` as the request frame; returns the core
    /// answer.
    ///
    /// # Errors
    ///
    /// The connection or protocol error.
    pub async fn raw_request(
        address: SocketAddr,
        root: &TrustAnchor,
        alpn: &[u8],
        payload: &[u8],
    ) -> Result<EnrollServer, TunnelError> {
        let tls = tls::client_config(root, None, &[alpn])
            .map_err(|e| TunnelError::Config(e.to_string()))?;
        let quic = QuicClientConfig::with_initial(tls, tls::quic_initial_suite())
            .map_err(|e| TunnelError::Config(e.to_string()))?;
        let mut client = quinn::ClientConfig::new(Arc::new(quic));
        client.transport_config(Limits::default().transport()?);
        let endpoint = Endpoint::client((Ipv4Addr::LOCALHOST, 0).into())
            .map_err(|e| TunnelError::Io(e.to_string()))?;
        let result = within(Duration::from_secs(5), "requête brute", async {
            let conn = endpoint
                .connect_with(client, address, "localhost")
                .map_err(|e| TunnelError::Config(e.to_string()))?
                .await
                .map_err(TunnelError::from)?;
            let (mut send, recv) = conn.accept_bi().await.map_err(TunnelError::from)?;
            let mut recv = ChannelRecv::Quic(recv);
            decode_server(&read_frame(&mut recv, MAX_ENROLL_MESSAGE).await?)?;
            let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
            let mut frame = len.to_be_bytes().to_vec();
            frame.extend_from_slice(payload);
            send.write_all(&frame)
                .await
                .map_err(|e| TunnelError::ConnectionLost(e.to_string()))?;
            let _ = send.finish();
            let answer = decode_server(&read_frame(&mut recv, MAX_ENROLL_MESSAGE).await?);
            conn.close(VarInt::from_u32(0), b"");
            answer
        })
        .await;
        endpoint.close(VarInt::from_u32(0), b"");
        result
    }
}
