//! The HTTPS login API of `ostena login` (ADR-0010 step 1, ADR-0015).
//!
//! HTTP/1.1 on hyper, one request per connection, over TLS 1.3 built by
//! `ostena-crypto::tls` (server certificate signed by the root, no client
//! certificate, ALPN `http/1.1`). Two routes:
//!
//! - `POST /v1/login`: [`LoginRequest`] → [`LoginResponse`];
//! - `POST /v1/logout`: [`LogoutRequest`] → `204`.
//!
//! The listener bounds connections, handshake, headers, body and the whole
//! exchange, and limits attempts per source address before any work on the
//! request. The decision belongs to an [`Authenticator`]: in production,
//! the PostgreSQL store (passwords, TOTP, sessions, audit).
//!
//! Every refusal is a JSON [`ErrorResponse`] with a stable code
//! ([`ApiCode`]). A failed authentication is always `AUTH-E001` with the
//! same message, whatever the reason, so as not to tell which accounts
//! exist; the reason goes to the audit chain.

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{CACHE_CONTROL, CONTENT_TYPE, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use ostena_common::api::login::{
    self, ErrorResponse, LoginRequest, LoginResponse, LogoutRequest, WireError,
};
use ostena_common::config::CoreLoginConfig;
use ostena_crypto::tls::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroize;

use crate::error::CoreError;

/// Stable codes of the login API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApiCode {
    /// Invalid credentials: unknown user, wrong password or code, replayed
    /// code, locked, disabled or not enrolled account. One message for all.
    InvalidCredentials,
    /// Too many attempts from this address.
    RateLimited,
    /// Malformed request (route, method, type, size, JSON, field).
    BadRequest,
    /// Public key refused (not a P-256 point).
    PublicKey,
    /// Unsupported protocol version.
    Protocol,
    /// The core cannot decide now (database unavailable).
    Unavailable,
}

impl ApiCode {
    /// The code, e.g. `AUTH-E001`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidCredentials => "AUTH-E001",
            Self::RateLimited => "AUTH-E002",
            Self::BadRequest => "AUTH-E003",
            Self::PublicKey => "AUTH-E004",
            Self::Protocol => "AUTH-E005",
            Self::Unavailable => "AUTH-E006",
        }
    }

    fn status(self) -> StatusCode {
        match self {
            Self::InvalidCredentials => StatusCode::UNAUTHORIZED,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::BadRequest | Self::PublicKey | Self::Protocol => StatusCode::BAD_REQUEST,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

/// The message of every failed authentication.
pub const INVALID_CREDENTIALS: &str = "identifiants invalides ou compte indisponible";

/// A refusal of the API.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("[{}] {message}", code.as_str())]
pub struct ApiError {
    /// Stable code.
    pub code: ApiCode,
    /// Message for the client, in French, without detail on the account.
    pub message: String,
    status: Option<StatusCode>,
}

impl ApiError {
    /// A refusal with its code and message.
    pub fn new(code: ApiCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            status: None,
        }
    }

    /// `AUTH-E001`, with its fixed message.
    pub fn invalid_credentials() -> Self {
        Self::new(ApiCode::InvalidCredentials, INVALID_CREDENTIALS)
    }

    /// `AUTH-E006`.
    pub fn unavailable() -> Self {
        Self::new(
            ApiCode::Unavailable,
            "le core ne peut pas répondre maintenant, réessayez",
        )
    }

    fn with_status(mut self, status: StatusCode) -> Self {
        self.status = Some(status);
        self
    }

    fn status(&self) -> StatusCode {
        self.status.unwrap_or_else(|| self.code.status())
    }
}

/// Decides logins and logouts. The listener has already checked the
/// address limit and parsed the message.
pub trait Authenticator: Send + Sync + 'static {
    /// Authenticates `request` from `peer` and opens a login session.
    fn login(
        &self,
        request: LoginRequest,
        peer: SocketAddr,
    ) -> impl Future<Output = Result<LoginResponse, ApiError>> + Send;

    /// Closes the session of a signed `request` from `peer`.
    fn logout(
        &self,
        request: LogoutRequest,
        peer: SocketAddr,
    ) -> impl Future<Output = Result<(), ApiError>> + Send;
}

/// Bounds of the listener (ADR-0015).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Simultaneous connections; beyond, a connection is closed at once.
    pub max_connections: usize,
    /// Attempts per source address and minute.
    pub attempts_per_minute: u32,
    /// TLS handshake.
    pub handshake_timeout: Duration,
    /// Reading the request headers.
    pub header_timeout: Duration,
    /// The whole exchange.
    pub exchange_timeout: Duration,
}

impl Limits {
    /// The limits of `config`, with the fixed timeouts.
    pub fn from_config(config: &CoreLoginConfig) -> Self {
        Self {
            max_connections: usize::try_from(config.max_connections).unwrap_or(64),
            attempts_per_minute: config.attempts_per_minute,
            ..Self::default()
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 64,
            attempts_per_minute: 10,
            handshake_timeout: Duration::from_secs(10),
            header_timeout: Duration::from_secs(10),
            exchange_timeout: Duration::from_secs(30),
        }
    }
}

/// Most source addresses followed by the attempt limiter.
pub const MAX_TRACKED_ADDRESSES: usize = 10_000;
/// Most request headers.
const MAX_HEADERS: usize = 32;
/// Read buffer of a connection (hyper's minimum is 8 KiB).
const MAX_BUFFER: usize = 16 * 1024;

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Attempts per source address, in fixed one-minute windows.
#[derive(Debug)]
pub struct Attempts {
    per_minute: u32,
    map: Mutex<HashMap<IpAddr, (u64, u32)>>,
}

/// The decision of the limiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Go on.
    Allowed,
    /// Refused; `first` is set for the first refusal of the window, which
    /// is the only one logged.
    Refused {
        /// First refusal of this address in this window.
        first: bool,
    },
}

impl Attempts {
    /// A limiter of `per_minute` attempts.
    pub fn new(per_minute: u32) -> Self {
        Self {
            per_minute,
            map: Mutex::new(HashMap::new()),
        }
    }

    /// Counts an attempt of `ip` at `now` (Unix seconds).
    ///
    /// When [`MAX_TRACKED_ADDRESSES`] addresses are followed in the current
    /// window, a new address is refused: the limiter fails closed rather
    /// than forget the counts.
    pub fn admit(&self, ip: IpAddr, now: u64) -> Admission {
        let window = now / 60;
        let Ok(mut map) = self.map.lock() else {
            return Admission::Refused { first: false };
        };
        if !map.contains_key(&ip) && map.len() >= MAX_TRACKED_ADDRESSES {
            map.retain(|_, (w, _)| *w == window);
            if map.len() >= MAX_TRACKED_ADDRESSES {
                return Admission::Refused { first: false };
            }
        }
        let entry = map.entry(ip).or_insert((window, 0));
        if entry.0 != window {
            *entry = (window, 0);
        }
        entry.1 = entry.1.saturating_add(1);
        if entry.1 <= self.per_minute {
            Admission::Allowed
        } else {
            Admission::Refused {
                first: entry.1 == self.per_minute + 1,
            }
        }
    }
}

struct Shared<A> {
    authenticator: Arc<A>,
    attempts: Attempts,
    limits: Limits,
}

/// The bound login listener. Dropping it does not stop it: call
/// [`LoginListener::close`].
#[derive(Debug)]
pub struct LoginListener {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl LoginListener {
    /// Binds `addr` and serves the API with `tls` (from
    /// `ostena_crypto::tls::server_config`, ALPN `http/1.1`).
    ///
    /// # Errors
    ///
    /// [`CoreError::Startup`] if the address cannot be bound.
    pub async fn bind<A: Authenticator>(
        addr: SocketAddr,
        tls: Arc<ServerConfig>,
        limits: Limits,
        authenticator: Arc<A>,
    ) -> Result<Self, CoreError> {
        let startup =
            |e: std::io::Error| CoreError::Startup(format!("écouteur de connexion {addr} : {e}"));
        let listener = TcpListener::bind(addr).await.map_err(startup)?;
        let addr = listener.local_addr().map_err(startup)?;
        let shared = Arc::new(Shared {
            authenticator,
            attempts: Attempts::new(limits.attempts_per_minute),
            limits,
        });
        let task = tokio::spawn(accept(listener, TlsAcceptor::from(tls), shared));
        tracing::info!(
            event = "login.listener_started",
            listener = %addr,
            "écouteur de connexion démarré"
        );
        Ok(Self { addr, task })
    }

    /// The bound address.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stops accepting; exchanges in progress end within their bounds.
    pub fn close(&self) {
        self.task.abort();
    }
}

async fn accept<A: Authenticator>(listener: TcpListener, tls: TlsAcceptor, shared: Arc<Shared<A>>) {
    let slots = Arc::new(Semaphore::new(shared.limits.max_connections));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(event = "login.accept_failed", error = %e, "acceptation impossible");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            tracing::warn!(
                event = "login.connection_limited",
                peer = %peer,
                limit = shared.limits.max_connections,
                "connexion refusée : limite de connexions atteinte"
            );
            drop(stream);
            continue;
        };
        let tls = tls.clone();
        let shared = shared.clone();
        tokio::spawn(async move {
            serve(stream, peer, tls, shared).await;
            drop(slot);
        });
    }
}

async fn serve<A: Authenticator>(
    stream: TcpStream,
    peer: SocketAddr,
    tls: TlsAcceptor,
    shared: Arc<Shared<A>>,
) {
    let _ = stream.set_nodelay(true);
    let limits = shared.limits;
    let stream = match tokio::time::timeout(limits.handshake_timeout, tls.accept(stream)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            tracing::info!(
                event = "login.tls_refused",
                peer = %peer,
                error = %e,
                "poignée de main TLS refusée"
            );
            return;
        }
        Err(_) => {
            tracing::info!(event = "login.tls_refused", peer = %peer, error = "délai dépassé", "poignée de main TLS refusée");
            return;
        }
    };
    let service = hyper::service::service_fn(move |request| {
        let shared = shared.clone();
        async move { Ok::<_, Infallible>(route(request, peer, &shared).await) }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_timeout)
        .keep_alive(false)
        .max_headers(MAX_HEADERS)
        .max_buf_size(MAX_BUFFER);
    let connection = builder.serve_connection(TokioIo::new(stream), service);
    if tokio::time::timeout(limits.exchange_timeout, connection)
        .await
        .is_err()
    {
        tracing::info!(event = "login.exchange_timeout", peer = %peer, "échange interrompu : délai dépassé");
    }
}

fn json_response(status: StatusCode, body: Vec<u8>) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn error_response(error: &ApiError) -> Response<Full<Bytes>> {
    let body = ErrorResponse {
        protocol: login::PROTOCOL,
        code: error.code.as_str().to_owned(),
        message: error.message.clone(),
    };
    json_response(
        error.status(),
        serde_json::to_vec(&body).unwrap_or_default(),
    )
}

fn bad_request(message: impl Into<String>, status: StatusCode) -> ApiError {
    ApiError::new(ApiCode::BadRequest, message).with_status(status)
}

fn wire_error(error: &WireError) -> ApiError {
    match error {
        WireError::TooLarge => bad_request(error.to_string(), StatusCode::PAYLOAD_TOO_LARGE),
        WireError::Protocol(_) => ApiError::new(ApiCode::Protocol, error.to_string()),
        WireError::Field("p256_public", _) => ApiError::new(ApiCode::PublicKey, error.to_string()),
        WireError::Json(_) | WireError::Field(..) => {
            bad_request(error.to_string(), StatusCode::BAD_REQUEST)
        }
    }
}

/// Reads the body into a buffer the caller wipes, refusing more than
/// [`login::MAX_BODY`] bytes.
async fn read_body(body: Incoming, out: &mut Vec<u8>) -> Result<(), ApiError> {
    let mut body = body;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| bad_request(e.to_string(), StatusCode::BAD_REQUEST))?;
        if let Ok(data) = frame.into_data() {
            if out.len() + data.len() > login::MAX_BODY {
                return Err(bad_request(
                    WireError::TooLarge.to_string(),
                    StatusCode::PAYLOAD_TOO_LARGE,
                ));
            }
            out.extend_from_slice(&data);
        }
    }
    Ok(())
}

async fn route<A: Authenticator>(
    request: Request<Incoming>,
    peer: SocketAddr,
    shared: &Shared<A>,
) -> Response<Full<Bytes>> {
    match handle(request, peer, shared).await {
        Ok(response) => response,
        Err(error) => error_response(&error),
    }
}

async fn handle<A: Authenticator>(
    request: Request<Incoming>,
    peer: SocketAddr,
    shared: &Shared<A>,
) -> Result<Response<Full<Bytes>>, ApiError> {
    let path = request.uri().path();
    let is_login = path == login::LOGIN_PATH;
    if !is_login && path != login::LOGOUT_PATH {
        return Err(bad_request("route inconnue", StatusCode::NOT_FOUND));
    }
    if request.method() != Method::POST {
        return Err(bad_request(
            "méthode non permise : POST attendu",
            StatusCode::METHOD_NOT_ALLOWED,
        ));
    }
    let json = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';')
                .next()
                .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/json"))
        });
    if !json {
        return Err(bad_request(
            "type de contenu application/json attendu",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ));
    }
    if let Admission::Refused { first } = shared.attempts.admit(peer.ip(), unix_now()) {
        if first {
            tracing::warn!(
                event = "login.rate_limited",
                peer = %peer,
                limit = shared.limits.attempts_per_minute,
                "tentatives refusées pour cette adresse jusqu'à la minute suivante"
            );
        }
        return Err(ApiError::new(
            ApiCode::RateLimited,
            "trop de tentatives depuis cette adresse, réessayez dans une minute",
        ));
    }
    let mut body = Vec::new();
    let read = read_body(request.into_body(), &mut body).await;
    let result = match read {
        Err(e) => Err(e),
        Ok(()) if is_login => match LoginRequest::parse(&body) {
            Ok(request) => shared
                .authenticator
                .login(request, peer)
                .await
                .and_then(|response| {
                    serde_json::to_vec(&response)
                        .map(|b| json_response(StatusCode::OK, b))
                        .map_err(|_| ApiError::unavailable())
                }),
            Err(e) => Err(wire_error(&e)),
        },
        Ok(()) => match LogoutRequest::parse(&body) {
            Ok(request) => shared.authenticator.logout(request, peer).await.map(|()| {
                let mut response = Response::new(Full::new(Bytes::new()));
                *response.status_mut() = StatusCode::NO_CONTENT;
                response
                    .headers_mut()
                    .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
                response
            }),
            Err(e) => Err(wire_error(&e)),
        },
    };
    body.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_stable() {
        let all = [
            ApiCode::InvalidCredentials,
            ApiCode::RateLimited,
            ApiCode::BadRequest,
            ApiCode::PublicKey,
            ApiCode::Protocol,
            ApiCode::Unavailable,
        ];
        let codes: Vec<_> = all.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            codes,
            [
                "AUTH-E001",
                "AUTH-E002",
                "AUTH-E003",
                "AUTH-E004",
                "AUTH-E005",
                "AUTH-E006"
            ]
        );
        assert_eq!(
            ApiError::invalid_credentials().to_string(),
            "[AUTH-E001] identifiants invalides ou compte indisponible"
        );
    }

    #[test]
    fn attempts_per_window() {
        let a = Attempts::new(3);
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let other: IpAddr = "192.0.2.2".parse().unwrap();
        for _ in 0..3 {
            assert_eq!(a.admit(ip, 600), Admission::Allowed);
        }
        assert_eq!(a.admit(ip, 610), Admission::Refused { first: true });
        assert_eq!(a.admit(ip, 619), Admission::Refused { first: false });
        assert_eq!(a.admit(other, 619), Admission::Allowed);
        // The next minute starts afresh.
        assert_eq!(a.admit(ip, 660), Admission::Allowed);
    }

    #[test]
    fn attempts_fail_closed_when_full() {
        let a = Attempts::new(1);
        for i in 0..MAX_TRACKED_ADDRESSES {
            let ip = IpAddr::from(u32::try_from(i).unwrap().to_be_bytes());
            assert_eq!(a.admit(ip, 60), Admission::Allowed);
        }
        let late: IpAddr = "198.51.100.7".parse().unwrap();
        assert_eq!(a.admit(late, 60), Admission::Refused { first: false });
        // A known address is still counted, and the next window purges.
        assert_eq!(
            a.admit(IpAddr::from([0, 0, 0, 1]), 60),
            Admission::Refused { first: true }
        );
        assert_eq!(a.admit(late, 120), Admission::Allowed);
    }
}
