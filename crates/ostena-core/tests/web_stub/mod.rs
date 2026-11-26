//! An in-memory store of browser sessions for the tests and the benchmark
//! of the web listener, and a TLS client like a browser. No database: the
//! decision on a session is the listener's own ([`session::decide`]).

#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    clippy::unused_async_trait_impl,
    reason = "test helpers, shared by several test binaries; the stub does not await"
)]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{HeaderMap, Request, StatusCode};
use hyper_util::rt::TokioIo;
use ostena_common::api::web::{
    Channel, LoginSessionItem, LoginSessionList, ReauthenticateRequest, Role, SessionRequest,
};
use ostena_core::api::{ApiError, Attempts};
use ostena_core::web::session::{SessionEnd, SessionRecord, WebBackend};
use ostena_core::web::{WebListener, WebSettings};
use ostena_crypto::pki::testing::TestPki;
use ostena_crypto::tls::testing::{Offer, browser_client_config};
use ostena_crypto::tls::{self, ClientConfig, ServerName, WebGroups};
use ostena_tunnel::Uuid;
use tokio::net::{TcpSocket, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// The origin of the test portal.
pub const ORIGIN: &str = "https://core.test";
/// The password of every stub user.
pub const PASSWORD: &str = "good";
/// The TOTP code of every stub user.
pub const TOTP: &str = "123456";

/// Users: `alice` (no role) and `root` (admin).
#[derive(Default)]
pub struct Stub {
    pub sessions: Mutex<HashMap<[u8; 32], SessionRecord>>,
    /// Calls that change something on behalf of a request: open,
    /// re-authentication, touch, logout, revocation.
    pub effects: AtomicUsize,
    /// Revocations decided by the listener (idle time, source change).
    pub ended: Mutex<Vec<(Uuid, SessionEnd)>>,
    pub revoked: Mutex<Vec<(Uuid, String)>>,
}

pub fn user_of(name: &str) -> Option<(Uuid, Vec<Role>)> {
    match name {
        "alice" => Some((Uuid::from_bytes([0xa1; 16]), vec![])),
        "root" => Some((Uuid::from_bytes([0xb2; 16]), vec![Role::Admin])),
        _ => None,
    }
}

fn exposed(secret: &ostena_common::secret::SecretString) -> String {
    // SECRET-EXPOSURE: test stub compares the factors.
    #[expect(clippy::disallowed_methods)]
    let text = secret.expose_secret().to_owned();
    text
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

impl Stub {
    /// Inserts a session of `name` under `digest`, changed by `edit`.
    pub fn insert(&self, digest: [u8; 32], name: &str, edit: impl FnOnce(&mut SessionRecord)) {
        let (user, roles) = user_of(name).unwrap();
        let now = now();
        let mut record = SessionRecord {
            login_session: Uuid::random().unwrap(),
            user,
            username: name.into(),
            display_name: name.to_uppercase(),
            roles,
            source: "127.0.0.1".parse().unwrap(),
            expires_at: now + 3600,
            authenticated_at: now,
            last_activity_at: now,
            revoked: false,
            user_active: true,
        };
        edit(&mut record);
        self.sessions.lock().unwrap().insert(digest, record);
    }

    pub fn effects(&self) -> usize {
        self.effects.load(Ordering::SeqCst)
    }

    fn effect(&self) {
        self.effects.fetch_add(1, Ordering::SeqCst);
    }
}

impl WebBackend for Stub {
    async fn open(
        &self,
        request: SessionRequest,
        cookie_sha256: [u8; 32],
        source: IpAddr,
        session_secs: u64,
        _peer: SocketAddr,
    ) -> Result<SessionRecord, ApiError> {
        self.effect();
        let ok = exposed(&request.password) == PASSWORD && exposed(&request.totp) == TOTP;
        if !ok || user_of(&request.username).is_none() {
            return Err(ApiError::invalid_credentials());
        }
        self.insert(cookie_sha256, &request.username, |r| {
            r.source = source;
            r.expires_at = now() + session_secs;
        });
        Ok(self.sessions.lock().unwrap()[&cookie_sha256].clone())
    }

    async fn reauthenticate(
        &self,
        session: &SessionRecord,
        request: ReauthenticateRequest,
        cookie_sha256: [u8; 32],
        _peer: SocketAddr,
    ) -> Result<SessionRecord, ApiError> {
        self.effect();
        if exposed(&request.password) != PASSWORD || exposed(&request.totp) != TOTP {
            return Err(ApiError::invalid_credentials());
        }
        let mut map = self.sessions.lock().unwrap();
        let old = map
            .iter()
            .find(|(_, r)| r.login_session == session.login_session)
            .map(|(k, _)| *k)
            .unwrap();
        let mut record = map.remove(&old).unwrap();
        record.authenticated_at = now();
        record.last_activity_at = now();
        map.insert(cookie_sha256, record.clone());
        Ok(record)
    }

    async fn find(&self, cookie_sha256: [u8; 32]) -> Result<Option<SessionRecord>, ApiError> {
        Ok(self.sessions.lock().unwrap().get(&cookie_sha256).cloned())
    }

    async fn touch(&self, session: Uuid, now: u64) -> Result<(), ApiError> {
        self.effect();
        for r in self.sessions.lock().unwrap().values_mut() {
            if r.login_session == session {
                r.last_activity_at = now;
            }
        }
        Ok(())
    }

    async fn end(
        &self,
        session: &SessionRecord,
        end: SessionEnd,
        _peer: SocketAddr,
    ) -> Result<(), ApiError> {
        if end == SessionEnd::Logout {
            self.effect();
        } else {
            self.ended
                .lock()
                .unwrap()
                .push((session.login_session, end));
        }
        for r in self.sessions.lock().unwrap().values_mut() {
            if r.login_session == session.login_session {
                r.revoked = true;
            }
        }
        Ok(())
    }

    async fn login_sessions(&self) -> Result<LoginSessionList, ApiError> {
        let sessions = self
            .sessions
            .lock()
            .unwrap()
            .values()
            .filter(|r| !r.revoked)
            .map(|r| LoginSessionItem {
                id: r.login_session.to_string(),
                user: r.user.to_string(),
                username: r.username.clone(),
                channel: Channel::Web,
                started_at: r.authenticated_at,
                expires_at: r.expires_at,
            })
            .collect();
        Ok(LoginSessionList { sessions })
    }

    async fn revoke(&self, _by: &SessionRecord, id: Uuid, reason: &str) -> Result<bool, ApiError> {
        self.effect();
        let mut found = false;
        for r in self.sessions.lock().unwrap().values_mut() {
            if r.login_session == id {
                r.revoked = true;
                found = true;
            }
        }
        if found {
            self.revoked.lock().unwrap().push((id, reason.into()));
        }
        Ok(found)
    }
}

/// A running web listener on the stub.
pub struct Fixture {
    pub pki: TestPki,
    pub listener: WebListener,
    pub stub: Arc<Stub>,
    pub attempts: Arc<Attempts>,
}

impl Fixture {
    pub async fn start(settings: WebSettings, attempts_per_minute: u32) -> Self {
        Self::start_with(settings, attempts_per_minute, WebGroups::Hybrid).await
    }

    pub async fn start_with(
        settings: WebSettings,
        attempts_per_minute: u32,
        groups: WebGroups,
    ) -> Self {
        let pki = TestPki::new("web").unwrap();
        let server = pki.server(&["core.test", "127.0.0.1"]).unwrap();
        let tls = tls::web_server_config(&server, groups).unwrap();
        let stub = Arc::new(Stub::default());
        let attempts = Arc::new(Attempts::new(attempts_per_minute));
        let listener = WebListener::bind(
            "127.0.0.1:0".parse().unwrap(),
            tls,
            settings,
            stub.clone(),
            attempts.clone(),
        )
        .await
        .unwrap();
        Self {
            pki,
            listener,
            stub,
            attempts,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.listener.local_addr()
    }

    /// A browser-like TLS configuration (X25519MLKEM768).
    pub fn browser(&self) -> Arc<ClientConfig> {
        browser_client_config(Offer::X25519MlKem768, &self.pki.root_anchor()).unwrap()
    }

    /// One connection from the local address `from`.
    pub async fn connect_from(&self, from: IpAddr) -> Connection {
        Connection::open(self.addr(), from, self.browser())
            .await
            .unwrap()
    }

    /// One request on a new connection from 127.0.0.1.
    pub async fn send(&self, request: Request<Full<Bytes>>) -> Reply {
        self.connect_from("127.0.0.1".parse().unwrap())
            .await
            .send(request)
            .await
    }
}

/// A persistent HTTP/1.1 connection over TLS.
pub struct Connection {
    sender: hyper::client::conn::http1::SendRequest<Full<Bytes>>,
}

impl Connection {
    pub async fn open(
        addr: SocketAddr,
        from: IpAddr,
        config: Arc<ClientConfig>,
    ) -> std::io::Result<Self> {
        let socket = TcpSocket::new_v4()?;
        socket.bind(SocketAddr::new(from, 0))?;
        let tcp: TcpStream = socket.connect(addr).await?;
        tcp.set_nodelay(true)?;
        let tls: TlsStream<TcpStream> = TlsConnector::from(config)
            .connect(ServerName::try_from("core.test").unwrap(), tcp)
            .await?;
        let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(std::io::Error::other)?;
        tokio::spawn(connection);
        Ok(Self { sender })
    }

    pub async fn send(&mut self, request: Request<Full<Bytes>>) -> Reply {
        self.sender.ready().await.unwrap();
        let response = self.sender.send_request(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        Reply {
            status,
            headers,
            body,
        }
    }
}

/// A response, read whole.
#[derive(Debug)]
pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Reply {
    /// The code of an error body.
    pub fn code(&self) -> String {
        ostena_common::api::web::ErrorBody::parse(&self.body)
            .map_or_else(|e| format!("not an error body: {e}"), |e| e.code)
    }

    /// The cookie value set by the response.
    pub fn cookie(&self) -> Option<String> {
        let set = self.headers.get("set-cookie")?.to_str().ok()?;
        let value = set
            .strip_prefix("__Host-ostena_session=")?
            .split(';')
            .next()?;
        (!value.is_empty()).then(|| value.to_owned())
    }
}

/// A request builder with the headers of the portal: host, origin,
/// same-origin fetch, JSON.
pub fn request(method: &str, path: &str, cookie: Option<&str>, body: &str) -> Request<Full<Bytes>> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "core.test")
        .header("origin", ORIGIN)
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/json");
    if let Some(c) = cookie {
        builder = builder.header("cookie", format!("__Host-ostena_session={c}"));
    }
    builder
        .body(Full::new(Bytes::from(body.to_owned())))
        .unwrap()
}

/// A request with only a host header and the cookie.
pub fn bare(method: &str, path: &str, cookie: Option<&str>) -> Request<Full<Bytes>> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "core.test");
    if let Some(c) = cookie {
        builder = builder.header("cookie", format!("__Host-ostena_session={c}"));
    }
    builder.body(Full::new(Bytes::new())).unwrap()
}

/// A cookie value and the digest the store keeps.
pub fn cookie() -> (String, [u8; 32]) {
    let (value, digest) = ostena_core::web::session::new_cookie().unwrap();
    (value.to_string(), digest)
}

/// The login body of `name` with the right factors.
pub fn login_body(name: &str) -> String {
    format!(r#"{{"username":"{name}","password":"{PASSWORD}","totp":"{TOTP}"}}"#)
}
