//! The HTTPS login listener against a stub authenticator: routes, bounds,
//! limiter and TLS policy. No database.

#![allow(
    clippy::unwrap_used,
    clippy::unused_async_trait_impl,
    reason = "test helpers outside #[test] functions; the stub does not await"
)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use ostena_common::api::login::{
    ErrorResponse, LOGIN_PATH, LOGOUT_PATH, LoginRequest, LoginResponse, LogoutRequest,
};
use ostena_core::api::{ApiError, Authenticator, Limits, LoginListener};
use ostena_crypto::pki::testing::TestPki;
use ostena_crypto::tls::{self, ClientAuth, ClientConfig, ServerName, TrustAnchor};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const KEY: &str =
    "BMk7TbSdl7gYKqG8Ewp_3Hs1Y1vYwSN9i0B5v2jYb2ZgL2uRk0Xh0y3Kt0hY1n3b5T1dH0rWg9z8Qp1VbYp9c0A";

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

/// Accepts `jdupont` with the password `good`; records what it saw.
#[derive(Default)]
struct Stub {
    seen: Mutex<Vec<(String, SocketAddr)>>,
    logouts: Mutex<Vec<String>>,
}

impl Authenticator for Stub {
    async fn login(
        &self,
        request: LoginRequest,
        peer: SocketAddr,
    ) -> Result<LoginResponse, ApiError> {
        self.seen
            .lock()
            .unwrap()
            .push((request.username.clone(), peer));
        // SECRET-EXPOSURE: test stub compares the password.
        #[expect(clippy::disallowed_methods)]
        let good = request.password.expose_secret() == "good";
        if request.username != "jdupont" || !good {
            return Err(ApiError::invalid_credentials());
        }
        Ok(LoginResponse {
            protocol: 1,
            login_session: "0b8f4c1e-7a52-4d0e-9f3b-2c6d1a9e8f70".into(),
            user: "5a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d".into(),
            certificate: "ecdsa-sha2-nistp256-cert-v01@openssh.com AAAA jdupont".into(),
            valid_after: 1_800_000_000,
            valid_before: 1_800_028_800,
            host_ca: "ecdsa-sha2-nistp256 AAAA host-ca".into(),
            ssh_hosts: vec!["bastion.example".into()],
            ssh_port: 2222,
        })
    }

    async fn logout(&self, request: LogoutRequest, _peer: SocketAddr) -> Result<(), ApiError> {
        self.logouts.lock().unwrap().push(request.login_session);
        Ok(())
    }
}

struct Fixture {
    pki: TestPki,
    listener: LoginListener,
    stub: Arc<Stub>,
}

async fn start(limits: Limits) -> Fixture {
    let pki = TestPki::new("login").unwrap();
    let server = pki.server(&["core.test", "127.0.0.1"]).unwrap();
    let tls = tls::server_config(&server, ClientAuth::None, &[b"http/1.1"]).unwrap();
    let stub = Arc::new(Stub::default());
    let listener = LoginListener::bind("127.0.0.1:0".parse().unwrap(), tls, limits, stub.clone())
        .await
        .unwrap();
    Fixture {
        pki,
        listener,
        stub,
    }
}

fn client(root: &TrustAnchor) -> Arc<ClientConfig> {
    tls::client_config(root, None, &[b"http/1.1"]).unwrap()
}

async fn connect(
    addr: SocketAddr,
    config: Arc<ClientConfig>,
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    TlsConnector::from(config)
        .connect(ServerName::try_from("core.test").unwrap(), tcp)
        .await
}

/// One request; returns the status and the body.
async fn send(
    addr: SocketAddr,
    root: &TrustAnchor,
    method: &str,
    path: &str,
    content_type: Option<&str>,
    body: Vec<u8>,
) -> (StatusCode, Vec<u8>) {
    let tls = connect(addr, client(root)).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(connection);
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "core.test");
    if let Some(t) = content_type {
        request = request.header("content-type", t);
    }
    let response = sender
        .send_request(request.body(Full::new(Bytes::from(body))).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, body)
}

fn login_body(username: &str, password: &str) -> Vec<u8> {
    format!(
        r#"{{"protocol":1,"username":"{username}","password":"{password}","totp":"123456","p256_public":"{KEY}"}}"#
    )
    .into_bytes()
}

fn code(body: &[u8]) -> String {
    ErrorResponse::parse(body).unwrap().code
}

const JSON: Option<&str> = Some("application/json");

#[test]
fn login_succeeds_and_failures_are_uniform() {
    runtime().block_on(async {
        let f = start(Limits::default()).await;
        let addr = f.listener.local_addr();
        let root = f.pki.root_anchor();
        let (status, body) = send(
            addr,
            &root,
            "POST",
            LOGIN_PATH,
            JSON,
            login_body("jdupont", "good"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let response = LoginResponse::parse(&body).unwrap();
        assert_eq!(response.ssh_port, 2222);
        let (status, wrong_password) = send(
            addr,
            &root,
            "POST",
            LOGIN_PATH,
            JSON,
            login_body("jdupont", "bad"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (_, unknown_user) = send(
            addr,
            &root,
            "POST",
            LOGIN_PATH,
            Some("application/json; charset=utf-8"),
            login_body("nobody", "good"),
        )
        .await;
        // Same code and same message: nothing tells the accounts apart.
        assert_eq!(wrong_password, unknown_user);
        assert_eq!(code(&wrong_password), "AUTH-E001");
        let seen = f.stub.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 3);
        assert!(seen.iter().all(|(_, peer)| peer.ip().is_loopback()));
        f.listener.close();
    });
}

#[test]
fn logout_is_routed() {
    runtime().block_on(async {
        let f = start(Limits::default()).await;
        let body = format!(
            r#"{{"protocol":1,"login_session":"0b8f4c1e-7a52-4d0e-9f3b-2c6d1a9e8f70","certificate":"ecdsa-sha2-nistp256-cert-v01@openssh.com AAAA","issued_at":1,"signature":"{}"}}"#,
            "A".repeat(86)
        );
        let (status, _) = send(f.listener.local_addr(), &f.pki.root_anchor(), "POST", LOGOUT_PATH, JSON, body.into_bytes()).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(f.stub.logouts.lock().unwrap().len(), 1);
    });
}

#[test]
fn malformed_requests_are_refused_before_the_authenticator() {
    runtime().block_on(async {
        let f = start(Limits {
            attempts_per_minute: 100,
            ..Limits::default()
        })
        .await;
        let addr = f.listener.local_addr();
        let root = f.pki.root_anchor();
        let ok = login_body("jdupont", "good");
        for (method, path, content_type, body, status, want) in [
            (
                "POST",
                "/v1/other",
                JSON,
                ok.clone(),
                StatusCode::NOT_FOUND,
                "AUTH-E003",
            ),
            (
                "GET",
                LOGIN_PATH,
                JSON,
                Vec::new(),
                StatusCode::METHOD_NOT_ALLOWED,
                "AUTH-E003",
            ),
            (
                "POST",
                LOGIN_PATH,
                Some("text/plain"),
                ok.clone(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "AUTH-E003",
            ),
            (
                "POST",
                LOGIN_PATH,
                None,
                ok.clone(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "AUTH-E003",
            ),
            (
                "POST",
                LOGIN_PATH,
                JSON,
                b"{".to_vec(),
                StatusCode::BAD_REQUEST,
                "AUTH-E003",
            ),
            (
                "POST",
                LOGIN_PATH,
                JSON,
                vec![b' '; 16 * 1024 + 1],
                StatusCode::PAYLOAD_TOO_LARGE,
                "AUTH-E003",
            ),
            (
                "POST",
                LOGIN_PATH,
                JSON,
                String::from_utf8(ok.clone())
                    .unwrap()
                    .replace("\"protocol\":1", "\"protocol\":2")
                    .into_bytes(),
                StatusCode::BAD_REQUEST,
                "AUTH-E005",
            ),
            (
                "POST",
                LOGIN_PATH,
                JSON,
                String::from_utf8(ok.clone())
                    .unwrap()
                    .replace(KEY, "short")
                    .into_bytes(),
                StatusCode::BAD_REQUEST,
                "AUTH-E004",
            ),
        ] {
            let (got, body) = send(addr, &root, method, path, content_type, body).await;
            assert_eq!(got, status, "{method} {path} {content_type:?}");
            assert_eq!(code(&body), want, "{method} {path}");
        }
        assert!(f.stub.seen.lock().unwrap().is_empty());
    });
}

#[test]
fn attempts_are_limited_per_address() {
    runtime().block_on(async {
        let f = start(Limits {
            attempts_per_minute: 2,
            ..Limits::default()
        })
        .await;
        let addr = f.listener.local_addr();
        let root = f.pki.root_anchor();
        for _ in 0..2 {
            let (status, _) = send(
                addr,
                &root,
                "POST",
                LOGIN_PATH,
                JSON,
                login_body("jdupont", "bad"),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        // The right password does not get through either.
        let (status, body) = send(
            addr,
            &root,
            "POST",
            LOGIN_PATH,
            JSON,
            login_body("jdupont", "good"),
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(code(&body), "AUTH-E002");
        assert_eq!(f.stub.seen.lock().unwrap().len(), 2);
    });
}

#[test]
fn only_the_hybrid_group_and_the_pinned_root_are_accepted() {
    use ostena_crypto::tls::testing::{Offer, foreign_client_config};
    runtime().block_on(async {
        let f = start(Limits::default()).await;
        let addr = f.listener.local_addr();
        let root = f.pki.root_anchor();
        let identity = f.pki.server(&["client.test"]).unwrap();
        for offer in [
            Offer::X25519,
            Offer::Secp256r1,
            Offer::X25519MlKem768,
            Offer::Aes128Suite,
        ] {
            let config = foreign_client_config(offer, &root, &identity, &[b"http/1.1"]).unwrap();
            assert!(connect(addr, config).await.is_err(), "{offer:?}");
        }
        // Another root: the core certificate is refused by the client.
        let other = TestPki::new("other").unwrap();
        assert!(connect(addr, client(&other.root_anchor())).await.is_err());
        // The pinned root with the fixed parameters works.
        assert!(connect(addr, client(&root)).await.is_ok());
    });
}

#[test]
fn connections_and_idle_clients_are_bounded() {
    runtime().block_on(async {
        let f = start(Limits {
            max_connections: 1,
            header_timeout: Duration::from_millis(300),
            ..Limits::default()
        })
        .await;
        let addr = f.listener.local_addr();
        let root = f.pki.root_anchor();
        // An idle client holds the only slot...
        let mut idle = connect(addr, client(&root)).await.unwrap();
        // ...so another connection is closed at once.
        assert!(connect(addr, client(&root)).await.is_err());
        // The idle client is dropped once the header timeout passes.
        let mut buf = [0u8; 64];
        let read = tokio::time::timeout(Duration::from_secs(5), idle.read(&mut buf)).await;
        assert!(matches!(read, Ok(Ok(0) | Err(_))), "{read:?}");
        // And the slot is free again.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let (status, _) = send(
            addr,
            &root,
            "POST",
            LOGIN_PATH,
            JSON,
            login_body("jdupont", "good"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let _ = idle.shutdown().await;
    });
}

#[test]
fn connections_are_capped_per_source_from_accept() {
    runtime().block_on(async {
        let f = start(Limits::default()).await;
        let addr = f.listener.local_addr();
        let root = f.pki.root_anchor();
        // Four idle connections from 127.0.0.1 hold the slots of the source...
        let mut idle = Vec::new();
        for _ in 0..ostena_core::api::CONNECTIONS_PER_SOURCE {
            idle.push(connect(addr, client(&root)).await.unwrap());
        }
        // ...so a fifth is closed before the handshake, though the total
        // limit (64) is far.
        assert!(connect(addr, client(&root)).await.is_err());
        // One closes: a slot is free again.
        let mut first = idle.remove(0);
        let _ = first.shutdown().await;
        drop(first);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (status, _) = send(
            addr,
            &root,
            "POST",
            LOGIN_PATH,
            JSON,
            login_body("jdupont", "good"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    });
}
