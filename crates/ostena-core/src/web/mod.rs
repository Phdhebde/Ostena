//! The web listener of the core: the REST API of the portal and, from
//! PR 8c, the portal itself (ADR-0020).
//!
//! HTTP/1.1 on hyper, persistent connections, over TLS 1.3 built by
//! `ostena_crypto::tls::web_server_config` (hybrid groups only in
//! production). The routes are the static table of [`routes::ROUTES`]. For
//! each request, in this order:
//!
//! 1. the route is looked up; an unknown `/api/…` path answers `401`
//!    without a valid session, `404` only with one, so that an anonymous
//!    client cannot discover the routes;
//! 2. the session cookie is checked ([`session::decide`]): absent, unknown,
//!    revoked or expired is `WEB-E001`; idle or seen from another source
//!    also revokes the session;
//! 3. a method that changes state passes the CSRF checks: `Origin` exactly
//!    `core.web.origin` (`WEB-E002`), `Sec-Fetch-Site` `same-origin` when
//!    present and `Content-Type: application/json` (`WEB-E003`);
//! 4. the role (`WEB-E004`), then for a sensitive action an authentication
//!    of less than five minutes (`WEB-E007`);
//! 5. the activity is recorded unless the request is a background one,
//!    the body is read within its bound (`WEB-E006`) and the handler runs.
//!
//! Every response, refusals included, carries the security headers and
//! the CSP of [`SECURITY_HEADERS`], and no `Server` header. API responses
//! are never compressed and never cached. Logins and re-authentications
//! share the attempt limiter of `ostena login` (same counter per source);
//! the lockout is the account's, in the database.

pub mod gateway;
pub mod pg;
pub mod routes;
pub mod session;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{
    CACHE_CONTROL, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, ORIGIN, SET_COOKIE,
};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use ostena_common::api::web::{
    AccessRequest, ErrorBody, ReauthenticateRequest, RevokeRequest, SessionRequest, WireError,
};
use ostena_common::config::CoreWebConfig;
use ostena_crypto::tls::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroize;

use crate::api::{Admission, ApiCode, ApiError, Attempts, LogBudget, Sources, source_of};
use crate::error::CoreError;
use crate::store::unix_now;
use routes::{Access, Handler, Params, Route};
use session::{SessionEnd, SessionRecord, Verdict, WebBackend};

/// The `OpenAPI` document of the API (ADR-0020), served to sessions.
pub const OPENAPI: &str = include_str!("../../api/openapi.json");

/// The content security policy of every response (ADR-0020, § 3).
pub const CSP: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; \
    style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; worker-src 'self'; \
    manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; \
    require-trusted-types-for 'script'; trusted-types svelte-trusted-html; report-to csp";

/// Every browser feature refused, except the clipboard, full screen and
/// the keyboard map, for the portal itself.
pub const PERMISSIONS_POLICY: &str = "accelerometer=(), ambient-light-sensor=(), \
    autoplay=(), battery=(), bluetooth=(), camera=(), display-capture=(), \
    document-domain=(), encrypted-media=(), gamepad=(), geolocation=(), gyroscope=(), \
    hid=(), idle-detection=(), local-fonts=(), magnetometer=(), microphone=(), midi=(), \
    payment=(), picture-in-picture=(), publickey-credentials-create=(), \
    publickey-credentials-get=(), screen-wake-lock=(), serial=(), usb=(), web-share=(), \
    xr-spatial-tracking=(), clipboard-read=(self), clipboard-write=(self), \
    fullscreen=(self), keyboard-map=(self)";

/// The headers of every response.
pub const SECURITY_HEADERS: &[(&str, &str)] = &[
    (
        "strict-transport-security",
        "max-age=63072000; includeSubDomains",
    ),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "no-referrer"),
    ("cross-origin-opener-policy", "same-origin"),
    ("cross-origin-embedder-policy", "require-corp"),
    ("cross-origin-resource-policy", "same-origin"),
    ("origin-agent-cluster", "?1"),
    ("x-frame-options", "DENY"),
    ("permissions-policy", PERMISSIONS_POLICY),
    ("content-security-policy", CSP),
    ("reporting-endpoints", "csp=\"/api/v1/csp-report\""),
];

/// Stable codes of the web listener (ADR-0020).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebCode {
    /// Session absent, unknown, expired or revoked.
    NoSession,
    /// `Origin` absent or foreign.
    Origin,
    /// Cross-site request (`Sec-Fetch-Site`, content type).
    CrossSite,
    /// Role missing.
    Role,
    /// Unknown route (with a session only).
    NotFound,
    /// Invalid or too large body.
    Body,
    /// Fresh authentication required.
    Reauthenticate,
    /// No portal in this binary.
    NoPortal,
}

impl WebCode {
    /// Every code.
    pub const ALL: [Self; 8] = [
        Self::NoSession,
        Self::Origin,
        Self::CrossSite,
        Self::Role,
        Self::NotFound,
        Self::Body,
        Self::Reauthenticate,
        Self::NoPortal,
    ];

    /// The code, e.g. `WEB-E001`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoSession => "WEB-E001",
            Self::Origin => "WEB-E002",
            Self::CrossSite => "WEB-E003",
            Self::Role => "WEB-E004",
            Self::NotFound => "WEB-E005",
            Self::Body => "WEB-E006",
            Self::Reauthenticate => "WEB-E007",
            Self::NoPortal => "WEB-E008",
        }
    }

    /// Its HTTP status (`WEB-E006` is 413 for a body too large).
    pub fn status(self) -> StatusCode {
        match self {
            Self::NoSession | Self::Reauthenticate => StatusCode::UNAUTHORIZED,
            Self::Origin | Self::CrossSite | Self::Role => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Body => StatusCode::BAD_REQUEST,
            Self::NoPortal => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::NoSession => "session absente, expirée ou révoquée",
            Self::Origin => "origine de la requête absente ou étrangère au portail",
            Self::CrossSite => "requête intersite refusée",
            Self::Role => "rôle insuffisant",
            Self::NotFound => "route inconnue",
            Self::Body => "corps de requête invalide",
            Self::Reauthenticate => "authentification de moins de 5 minutes exigée",
            Self::NoPortal => "portail absent de ce binaire",
        }
    }
}

/// A refusal of the web listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl WebError {
    /// A refusal with its status, stable code and message (generic: the
    /// reason, if any, is for the audit chain).
    pub fn refused(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    /// The stable code.
    pub fn code(&self) -> &'static str {
        self.code
    }

    fn body(error: &WireError) -> Self {
        let status = if *error == WireError::TooLarge {
            StatusCode::PAYLOAD_TOO_LARGE
        } else {
            StatusCode::BAD_REQUEST
        };
        Self {
            status,
            code: WebCode::Body.as_str(),
            message: error.to_string(),
        }
    }

    fn response(&self) -> Response<Full<Bytes>> {
        let body = ErrorBody {
            code: self.code.to_owned(),
            message: self.message.clone(),
        };
        json(self.status, &body)
    }
}

impl From<WebCode> for WebError {
    fn from(code: WebCode) -> Self {
        Self {
            status: code.status(),
            code: code.as_str(),
            message: code.message().to_owned(),
        }
    }
}

impl From<ApiError> for WebError {
    fn from(e: ApiError) -> Self {
        Self {
            status: e.status(),
            code: e.code.as_str(),
            message: e.message,
        }
    }
}

/// Settings of the web listener, from `[core.web]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSettings {
    /// The exact origin of the portal.
    pub origin: String,
    /// Longest browser session, seconds.
    pub session_secs: u64,
    /// Inactivity before a session ends, seconds.
    pub idle_secs: u64,
    /// Sessions are bound to their source.
    pub bind_source: bool,
    /// Simultaneous connections.
    pub max_connections: usize,
    /// Simultaneous connections from one source.
    pub connections_per_source: usize,
    /// TLS handshake.
    pub handshake_timeout: Duration,
    /// Reading the headers of a request.
    pub header_timeout: Duration,
    /// Longest connection, requests included.
    pub connection_timeout: Duration,
    /// A browser that reads nothing from its gateway session for this long
    /// is closed (`GTW-E004`).
    pub gateway_stall: Duration,
    /// How often the idle browser sessions are revoked.
    pub sweep_interval: Duration,
}

impl WebSettings {
    /// The settings of `config`, with the fixed timeouts.
    pub fn from_config(config: &CoreWebConfig) -> Self {
        Self {
            origin: config.origin.clone(),
            session_secs: u64::from(config.session_max_hours.clamp(1, 8)) * 3600,
            idle_secs: u64::from(config.idle_minutes.clamp(5, 60)) * 60,
            bind_source: config.bind_source,
            max_connections: usize::try_from(config.max_connections).unwrap_or(256),
            connections_per_source: usize::try_from(config.connections_per_source).unwrap_or(16),
            ..Self::new(config.origin.clone())
        }
    }

    /// Default settings for `origin`.
    pub fn new(origin: String) -> Self {
        Self {
            origin,
            session_secs: 8 * 3600,
            idle_secs: 15 * 60,
            bind_source: true,
            max_connections: 256,
            connections_per_source: 16,
            handshake_timeout: Duration::from_secs(10),
            header_timeout: Duration::from_secs(10),
            connection_timeout: Duration::from_secs(300),
            gateway_stall: gateway::STALL,
            sweep_interval: Duration::from_secs(30),
        }
    }
}

/// Most request headers.
const MAX_HEADERS: usize = 48;
/// Read buffer of a connection.
const MAX_BUFFER: usize = 16 * 1024;

struct Shared<B> {
    backend: Arc<B>,
    settings: WebSettings,
    attempts: Arc<Attempts>,
    sources: Arc<Sources>,
    connection_logs: LogBudget,
    tls_logs: LogBudget,
    csrf_logs: LogBudget,
    csp_logs: LogBudget,
}

/// The bound web listener. Dropping it does not stop it: call
/// [`WebListener::close`].
#[derive(Debug)]
pub struct WebListener {
    addr: SocketAddr,
    task: JoinHandle<()>,
    sweeper: JoinHandle<()>,
}

impl WebListener {
    /// Binds `addr` and serves the API with `tls` (from
    /// `ostena_crypto::tls::web_server_config`). `attempts` is the limiter
    /// shared with the login listener of `ostena login`.
    ///
    /// # Errors
    ///
    /// [`CoreError::Startup`] if the address cannot be bound.
    pub async fn bind<B: WebBackend>(
        addr: SocketAddr,
        tls: Arc<ServerConfig>,
        settings: WebSettings,
        backend: Arc<B>,
        attempts: Arc<Attempts>,
    ) -> Result<Self, CoreError> {
        let startup = |e: std::io::Error| CoreError::Startup(format!("écouteur web {addr} : {e}"));
        let listener = TcpListener::bind(addr).await.map_err(startup)?;
        let addr = listener.local_addr().map_err(startup)?;
        let shared = Arc::new(Shared {
            backend,
            settings,
            attempts,
            sources: Arc::default(),
            connection_logs: LogBudget::default(),
            tls_logs: LogBudget::default(),
            csrf_logs: LogBudget::default(),
            csp_logs: LogBudget::default(),
        });
        let sweeper = tokio::spawn(sweep(shared.clone()));
        let task = tokio::spawn(accept(listener, TlsAcceptor::from(tls), shared));
        tracing::info!(event = "web.listener_started", listener = %addr, "écouteur web démarré");
        Ok(Self {
            addr,
            task,
            sweeper,
        })
    }

    /// The bound address.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stops accepting; connections in progress end within their bounds.
    pub fn close(&self) {
        self.task.abort();
        self.sweeper.abort();
    }
}

/// Revokes the idle browser sessions every `sweep_interval`: their gateway
/// sessions are cut by the revocation, without waiting for a request.
async fn sweep<B: WebBackend>(shared: Arc<Shared<B>>) {
    let mut tick = tokio::time::interval(shared.settings.sweep_interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    loop {
        tick.tick().await;
        match shared
            .backend
            .sweep(unix_now(), shared.settings.idle_secs)
            .await
        {
            Ok(0) => {}
            Ok(revoked) => tracing::info!(
                event = "web.sessions_swept",
                revoked,
                "sessions du portail inactives révoquées"
            ),
            Err(e) => tracing::warn!(event = "web.sweep_failed", "{e}"),
        }
    }
}

/// The relays of the upgraded connections of one TCP connection: awaited
/// before the connection releases its slot.
type Upgrades = Arc<Mutex<Vec<JoinHandle<()>>>>;

async fn accept<B: WebBackend>(listener: TcpListener, tls: TlsAcceptor, shared: Arc<Shared<B>>) {
    let slots = Arc::new(Semaphore::new(shared.settings.max_connections));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(event = "web.accept_failed", error = %e, "acceptation impossible");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let source = shared
            .sources
            .take(peer.ip(), shared.settings.connections_per_source);
        let slot = slots.clone().try_acquire_owned().ok();
        let (Some(source), Some(slot)) = (source, slot) else {
            if let Some(unlogged) = shared.connection_logs.take(unix_now()) {
                tracing::warn!(
                    event = "web.connection_limited",
                    peer = %peer,
                    unlogged,
                    "connexion refusée : limite de connexions atteinte (au plus une ligne par minute)"
                );
            }
            continue;
        };
        let tls = tls.clone();
        let shared = shared.clone();
        tokio::spawn(async move {
            serve(stream, peer, tls, shared).await;
            drop(slot);
            drop(source);
        });
    }
}

async fn serve<B: WebBackend>(
    stream: TcpStream,
    peer: SocketAddr,
    tls: TlsAcceptor,
    shared: Arc<Shared<B>>,
) {
    let _ = stream.set_nodelay(true);
    let settings = shared.settings.clone();
    let stream = match tokio::time::timeout(settings.handshake_timeout, tls.accept(stream)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            tls_refused(&shared, peer, &e);
            return;
        }
        Err(_) => {
            tls_refused(&shared, peer, &"délai dépassé");
            return;
        }
    };
    let upgrades = Upgrades::default();
    let relays = upgrades.clone();
    let service = hyper::service::service_fn(move |request| {
        let shared = shared.clone();
        let upgrades = upgrades.clone();
        async move { Ok::<_, Infallible>(respond(request, peer, &shared, &upgrades).await) }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(settings.header_timeout)
        .keep_alive(true)
        .max_headers(MAX_HEADERS)
        .max_buf_size(MAX_BUFFER);
    let connection = builder
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades();
    let _ = tokio::time::timeout(settings.connection_timeout, connection).await;
    // A gateway session keeps the connection slot and the source slot.
    let pending = relays.lock().map(|mut r| std::mem::take(&mut *r));
    for relay in pending.unwrap_or_default() {
        let _ = relay.await;
    }
}

fn tls_refused<B>(shared: &Shared<B>, peer: SocketAddr, error: &dyn std::fmt::Display) {
    if let Some(unlogged) = shared.tls_logs.take(unix_now()) {
        tracing::info!(
            event = "web.tls_refused",
            peer = %peer,
            error = %error,
            unlogged,
            "poignée de main TLS refusée (au plus une ligne par minute)"
        );
    }
}

fn json<T: serde::Serialize>(status: StatusCode, body: &T) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(
        serde_json::to_vec(body).unwrap_or_default(),
    )));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

fn empty(status: StatusCode) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = status;
    response
}

/// Adds the security headers, and `Cache-Control: no-store` unless the
/// handler set another policy.
fn secure(response: &mut Response<Full<Bytes>>) {
    let headers = response.headers_mut();
    for (name, value) in SECURITY_HEADERS {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    if !headers.contains_key(CACHE_CONTROL) {
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
}

async fn respond<B: WebBackend>(
    request: Request<Incoming>,
    peer: SocketAddr,
    shared: &Arc<Shared<B>>,
    upgrades: &Upgrades,
) -> Response<Full<Bytes>> {
    let mut response = match handle(request, peer, shared, upgrades).await {
        Ok(response) => response,
        Err(error) => error.response(),
    };
    secure(&mut response);
    response
}

/// Whether the media type of `headers` is one of `types`.
fn content_type_is(headers: &HeaderMap, types: &[&str]) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|t| types.iter().any(|w| t.trim().eq_ignore_ascii_case(w)))
}

/// The CSRF checks of a method that changes state.
fn csrf<B>(headers: &HeaderMap, shared: &Shared<B>, peer: SocketAddr) -> Result<(), WebCode> {
    let mut origins = headers.get_all(ORIGIN).iter();
    let origin_ok = matches!(
        (origins.next(), origins.next()),
        (Some(o), None) if o.as_bytes() == shared.settings.origin.as_bytes()
    );
    let refusal = if !origin_ok {
        Some(WebCode::Origin)
    } else if headers
        .get("sec-fetch-site")
        .is_some_and(|s| s.as_bytes() != b"same-origin")
        || !content_type_is(headers, &["application/json"])
    {
        Some(WebCode::CrossSite)
    } else {
        None
    };
    let Some(code) = refusal else {
        return Ok(());
    };
    if let Some(unlogged) = shared.csrf_logs.take(unix_now()) {
        let event = if code == WebCode::Origin {
            "web.origin_refused"
        } else {
            "web.csrf_refused"
        };
        tracing::warn!(
            event,
            code = code.as_str(),
            peer = %peer,
            origin = ?headers.get(ORIGIN),
            sec_fetch_site = ?headers.get("sec-fetch-site"),
            unlogged,
            "requête refusée (au plus une ligne par minute)"
        );
    }
    Err(code)
}

/// The session presented by `headers`, decided at `now`; an idle session
/// or one seen from another source is revoked.
async fn authenticate<B: WebBackend>(
    headers: &HeaderMap,
    shared: &Shared<B>,
    peer: SocketAddr,
    now: u64,
) -> Result<SessionRecord, WebError> {
    let Some(digest) = session::presented(headers) else {
        return Err(WebCode::NoSession.into());
    };
    let Some(record) = shared.backend.find(digest).await? else {
        return Err(WebCode::NoSession.into());
    };
    let settings = &shared.settings;
    let verdict = session::decide(
        &record,
        now,
        settings.idle_secs,
        settings.bind_source,
        source_of(peer.ip()),
    );
    let end = match verdict {
        Verdict::Valid => return Ok(record),
        Verdict::Revoked | Verdict::Expired => None,
        Verdict::Idle => Some(SessionEnd::Idle),
        Verdict::SourceChanged => Some(SessionEnd::SourceChanged),
    };
    if let Some(end) = end
        && let Err(e) = shared.backend.end(&record, end, peer).await
    {
        tracing::error!(
            event = "web_session.end_failed",
            login_session = %record.login_session,
            error = %e,
            "session du portail non révoquée"
        );
    }
    Err(WebCode::NoSession.into())
}

/// Reads the body, refusing more than `max` bytes. Bodies that hold secrets
/// get their whole buffer at once, so that no reallocation leaves a copy;
/// the caller wipes it.
async fn read_body(body: Incoming, max: usize, secrets: bool) -> Result<Vec<u8>, WebError> {
    let mut out = if secrets {
        Vec::with_capacity(max)
    } else {
        Vec::new()
    };
    let mut body = body;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| WebError::from(WebCode::Body))?;
        if let Ok(data) = frame.into_data() {
            if out.len() + data.len() > max {
                out.zeroize();
                return Err(WebError::body(&WireError::TooLarge));
            }
            out.extend_from_slice(&data);
        }
    }
    Ok(out)
}

/// The portal outside the route table (its files, from PR 8c).
fn portal(method: &Method) -> Result<Response<Full<Bytes>>, WebError> {
    if method == Method::GET {
        Err(WebCode::NoPortal.into())
    } else {
        Err(WebCode::NotFound.into())
    }
}

async fn handle<B: WebBackend>(
    request: Request<Incoming>,
    peer: SocketAddr,
    shared: &Arc<Shared<B>>,
    upgrades: &Upgrades,
) -> Result<Response<Full<Bytes>>, WebError> {
    let now = unix_now();
    let path = request.uri().path();
    let Some((route, params)) = routes::find(request.method(), path) else {
        if !path.starts_with("/api/") {
            return portal(request.method());
        }
        // An anonymous client cannot tell an unknown route from a known one.
        authenticate(request.headers(), shared, peer, now).await?;
        return Err(WebCode::NotFound.into());
    };
    if route.handler == Handler::Gateway {
        return open_gateway(request, peer, shared, upgrades, now).await;
    }
    let mut session = match route.access {
        Access::Public => None,
        Access::Session | Access::Role(_) => {
            Some(authenticate(request.headers(), shared, peer, now).await?)
        }
    };
    if route.csrf && route.method != routes::Verb::Get {
        csrf(request.headers(), shared, peer)?;
    }
    if let (Access::Role(role), Some(s)) = (route.access, &session)
        && !s.roles.contains(&role)
    {
        return Err(WebCode::Role.into());
    }
    if let Some(s) = &mut session {
        if route.fresh && now.saturating_sub(s.authenticated_at) > session::REAUTH_SECS {
            return Err(WebCode::Reauthenticate.into());
        }
        let background = request
            .headers()
            .get(session::BACKGROUND_HEADER)
            .is_some_and(|v| v.as_bytes() == b"1");
        if !background && now >= s.last_activity_at.saturating_add(session::TOUCH_SECS) {
            shared.backend.touch(s.login_session, now).await?;
            s.last_activity_at = now;
        }
    }
    let secrets = matches!(route.handler, Handler::Login | Handler::Reauthenticate);
    let headers = request.headers().clone();
    let mut body = read_body(request.into_body(), route.max_body, secrets).await?;
    let context = Context {
        shared,
        peer,
        now,
        params,
        session,
        headers: &headers,
    };
    let result = run(route, context, &body).await;
    body.zeroize();
    result
}

struct Context<'a, B> {
    shared: &'a Shared<B>,
    peer: SocketAddr,
    now: u64,
    params: Params,
    session: Option<SessionRecord>,
    headers: &'a HeaderMap,
}

impl<B> Context<'_, B> {
    /// The session of a route that requires one (checked before).
    fn session(&self) -> Result<&SessionRecord, WebError> {
        self.session
            .as_ref()
            .ok_or_else(|| WebCode::NoSession.into())
    }

    /// The attempt limiter of the logins, shared with `ostena login`.
    fn admit(&self) -> Result<(), WebError> {
        match self.shared.attempts.admit(self.peer.ip(), self.now) {
            Admission::Allowed => Ok(()),
            Admission::Refused { first } => {
                if first {
                    tracing::warn!(
                        event = "login.rate_limited",
                        channel = "web",
                        peer = %self.peer,
                        "tentatives refusées pour cette source : limite atteinte sur la dernière minute"
                    );
                }
                Err(ApiError::new(
                    ApiCode::RateLimited,
                    "trop de tentatives depuis cette adresse, réessayez dans une minute",
                )
                .into())
            }
        }
    }
}

/// A refusal of the gateway, with its code and generic label.
fn gateway_refused(status: StatusCode, code: &'static str, label: &'static str) -> WebError {
    WebError::refused(status, code, label)
}

/// `GET /api/v1/gateway` (ADR-0020, § 4), checked in this order: `Origin`,
/// the session cookie, the WebSocket handshake and the `ostena-frame.v1`
/// sub-protocol, then the grant (sub-protocol `ostena-grant.<grant>`),
/// checked and marked presented by the store, and the agent answer. The
/// `101` selects `ostena-frame.v1` only; the relay runs on the upgraded
/// connection.
async fn open_gateway<B: WebBackend>(
    mut request: Request<Incoming>,
    peer: SocketAddr,
    shared: &Arc<Shared<B>>,
    upgrades: &Upgrades,
    now: u64,
) -> Result<Response<Full<Bytes>>, WebError> {
    let mut origins = request.headers().get_all(ORIGIN).iter();
    let origin_ok = matches!(
        (origins.next(), origins.next()),
        (Some(o), None) if o.as_bytes() == shared.settings.origin.as_bytes()
    );
    if !origin_ok {
        if let Some(unlogged) = shared.csrf_logs.take(now) {
            tracing::warn!(
                event = "web.origin_refused",
                code = WebCode::Origin.as_str(),
                peer = %peer,
                origin = ?request.headers().get(ORIGIN),
                unlogged,
                "WebSocket refusée (au plus une ligne par minute)"
            );
        }
        return Err(WebCode::Origin.into());
    }
    let session = authenticate(request.headers(), shared, peer, now).await?;
    let (accept, grant) = check_upgrade(&request)?;
    let stream = shared.backend.open_gateway(&session, &grant, peer).await?;
    let on_upgrade = hyper::upgrade::on(&mut request);
    let backend = shared.backend.clone();
    let stall = shared.settings.gateway_stall;
    let relay = tokio::spawn(async move {
        let gateway::GatewayStream {
            session: id,
            jti,
            channel,
            cut,
            ..
        } = stream;
        let ended = match on_upgrade.await {
            Ok(io) => {
                relay_touching(&*backend, &session, TokioIo::new(io), channel, cut, stall).await
            }
            Err(_) => gateway::Relayed {
                reason: "poignée de main WebSocket interrompue",
                code: None,
                from_browser: 0,
                to_browser: 0,
            },
        };
        backend
            .gateway_closed(&session, peer, (id, jti), &ended)
            .await;
    });
    if let Ok(mut relays) = upgrades.lock() {
        relays.push(relay);
    }
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    let headers = response.headers_mut();
    headers.insert(
        hyper::header::UPGRADE,
        HeaderValue::from_static("websocket"),
    );
    headers.insert(
        hyper::header::CONNECTION,
        HeaderValue::from_static("Upgrade"),
    );
    headers.insert(
        hyper::header::SEC_WEBSOCKET_PROTOCOL,
        HeaderValue::from_static(gateway::FRAME_PROTOCOL),
    );
    if let Ok(value) = HeaderValue::from_str(&accept) {
        headers.insert(hyper::header::SEC_WEBSOCKET_ACCEPT, value);
    }
    Ok(response)
}

/// The WebSocket handshake of the gateway: its `Sec-WebSocket-Accept` and
/// the grant of its `ostena-grant.` sub-protocol (exactly one).
fn check_upgrade(request: &Request<Incoming>) -> Result<(String, String), WebError> {
    let headers = request
        .headers()
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_bytes()));
    let upgrade = ostena_ws::handshake::check(
        request.method().as_str(),
        request.version() == hyper::Version::HTTP_11,
        headers,
    )
    .map_err(|_| {
        gateway_refused(
            StatusCode::BAD_REQUEST,
            "GTW-E002",
            "poignée de main WebSocket invalide",
        )
    })?;
    if !upgrade.offers(gateway::FRAME_PROTOCOL) {
        return Err(gateway_refused(
            StatusCode::BAD_REQUEST,
            "GTW-E002",
            "sous-protocole ostena-frame.v1 absent",
        ));
    }
    let mut grants = upgrade.with_prefix(gateway::GRANT_PREFIX);
    let (Some(grant), None) = (grants.next(), grants.next()) else {
        return Err(gateway_refused(
            StatusCode::FORBIDDEN,
            crate::access::GATEWAY_GRANT,
            "grant refusé",
        ));
    };
    let grant = grant.to_owned();
    Ok((
        ostena_crypto::websocket::accept_key(upgrade.key.as_bytes()),
        grant,
    ))
}

/// Runs the relay; the frames of the browser keep its session active
/// (recorded at most every `TOUCH_SECS`).
async fn relay_touching<B: WebBackend, IO>(
    backend: &B,
    session: &SessionRecord,
    io: IO,
    channel: ostena_tunnel::Channel,
    cut: tokio::sync::watch::Receiver<bool>,
    stall: Duration,
) -> gateway::Relayed
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send,
{
    let inputs = AtomicBool::new(false);
    let relay = gateway::relay(io, channel, cut, stall, || {
        inputs.store(true, Ordering::Relaxed);
    });
    tokio::pin!(relay);
    let mut tick = tokio::time::interval(Duration::from_secs(session::TOUCH_SECS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            ended = &mut relay => return ended,
            _ = tick.tick() => {
                if inputs.swap(false, Ordering::Relaxed) {
                    let _ = backend.touch(session.login_session, unix_now()).await;
                }
            }
        }
    }
}

fn with_cookie(mut response: Response<Full<Bytes>>, cookie: &str) -> Response<Full<Bytes>> {
    if let Ok(value) = HeaderValue::from_str(cookie) {
        response.headers_mut().insert(SET_COOKIE, value);
    }
    response
}

async fn run<B: WebBackend>(
    route: &Route,
    c: Context<'_, B>,
    body: &[u8],
) -> Result<Response<Full<Bytes>>, WebError> {
    let idle = c.shared.settings.idle_secs;
    match route.handler {
        Handler::Portal => Err(WebCode::NoPortal.into()),
        Handler::Health => Ok(empty(StatusCode::NO_CONTENT)),
        Handler::CspReport => csp_report(&c, body),
        Handler::Login => {
            c.admit()?;
            let request = SessionRequest::parse(body).map_err(|e| WebError::body(&e))?;
            let (cookie, digest) = session::new_cookie()?;
            let record = c
                .shared
                .backend
                .open(
                    request,
                    digest,
                    source_of(c.peer.ip()),
                    c.shared.settings.session_secs,
                    c.peer,
                )
                .await?;
            let response = json(StatusCode::OK, &record.info(idle));
            Ok(with_cookie(response, &session::set_cookie(&cookie)))
        }
        Handler::WhoAmI => Ok(json(StatusCode::OK, &c.session()?.info(idle))),
        Handler::Logout => {
            c.shared
                .backend
                .end(c.session()?, SessionEnd::Logout, c.peer)
                .await?;
            let mut response = empty(StatusCode::NO_CONTENT);
            response.headers_mut().insert(
                HeaderName::from_static("clear-site-data"),
                HeaderValue::from_static("\"cookies\", \"storage\""),
            );
            Ok(with_cookie(response, &session::clear_cookie()))
        }
        Handler::Reauthenticate => {
            c.admit()?;
            let request = ReauthenticateRequest::parse(body).map_err(|e| WebError::body(&e))?;
            let (cookie, digest) = session::new_cookie()?;
            let record = c
                .shared
                .backend
                .reauthenticate(c.session()?, request, digest, c.peer)
                .await?;
            let response = json(StatusCode::OK, &record.info(idle));
            Ok(with_cookie(response, &session::set_cookie(&cookie)))
        }
        Handler::OpenApi => {
            let mut response = Response::new(Full::new(Bytes::from_static(OPENAPI.as_bytes())));
            response
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            Ok(response)
        }
        Handler::ListLoginSessions => {
            let list = c.shared.backend.login_sessions().await?;
            Ok(json(StatusCode::OK, &list))
        }
        // Answered by `open_gateway` before the body is read.
        Handler::Gateway => Err(WebCode::NotFound.into()),
        Handler::Access => {
            let request = AccessRequest::parse(body).map_err(|e| WebError::body(&e))?;
            let grant = c
                .shared
                .backend
                .grant_access(c.session()?, request, c.peer)
                .await?;
            Ok(json(StatusCode::OK, &grant))
        }
        Handler::RevokeLoginSession => {
            let request = RevokeRequest::parse(body).map_err(|e| WebError::body(&e))?;
            let id = c
                .params
                .id
                .ok_or_else(|| WebError::from(WebCode::NotFound))?;
            if c.shared
                .backend
                .revoke(c.session()?, id, &request.reason)
                .await?
            {
                Ok(empty(StatusCode::NO_CONTENT))
            } else {
                Err(WebError {
                    status: StatusCode::NOT_FOUND,
                    code: WebCode::NotFound.as_str(),
                    message: "session de connexion inconnue".into(),
                })
            }
        }
    }
}

/// A CSP violation report: logged at most once a minute, never in the
/// audit chain (anyone can send one).
fn csp_report<B>(c: &Context<'_, B>, body: &[u8]) -> Result<Response<Full<Bytes>>, WebError> {
    if !content_type_is(
        c.headers,
        &["application/csp-report", "application/reports+json"],
    ) {
        return Err(WebError {
            status: StatusCode::UNSUPPORTED_MEDIA_TYPE,
            code: WebCode::Body.as_str(),
            message: "type de contenu de rapport CSP attendu".into(),
        });
    }
    if let Some(unlogged) = c.shared.csp_logs.take(c.now) {
        let text = String::from_utf8_lossy(&body[..body.len().min(512)]);
        tracing::warn!(
            event = "web.csp_report",
            peer = %c.peer,
            report = %text.escape_debug(),
            unlogged,
            "violation de la CSP signalée par un navigateur (au plus une ligne par minute)"
        );
    }
    Ok(empty(StatusCode::NO_CONTENT))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_stable() {
        let codes: Vec<_> = WebCode::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            codes,
            [
                "WEB-E001", "WEB-E002", "WEB-E003", "WEB-E004", "WEB-E005", "WEB-E006", "WEB-E007",
                "WEB-E008"
            ]
        );
        let statuses: Vec<_> = WebCode::ALL.iter().map(|c| c.status().as_u16()).collect();
        assert_eq!(statuses, [401, 403, 403, 403, 404, 400, 401, 503]);
    }

    #[test]
    fn the_policy_has_no_unsafe_source() {
        assert!(!CSP.contains("'unsafe-inline'") && !CSP.contains("'unsafe-eval'"));
        assert!(CSP.contains("default-src 'none'") && CSP.contains("frame-ancestors 'none'"));
        assert!(!CSP.contains("  "));
        assert!(!PERMISSIONS_POLICY.contains("  "));
        for (name, value) in SECURITY_HEADERS {
            assert_eq!(HeaderName::from_static(name).as_str(), *name);
            assert!(HeaderValue::from_str(value).is_ok(), "{name}");
        }
    }

    #[test]
    fn the_openapi_document_is_json() {
        let doc: serde_json::Value = serde_json::from_str(OPENAPI).unwrap();
        assert_eq!(doc["openapi"], "3.1.0");
    }
}
