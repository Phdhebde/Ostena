//! The browser gateway end to end (ADR-0020, § 4): the real core with its
//! web listener on a PostgreSQL server, an agent of `ostena-tunnel` that
//! serves browser streams with a test driver, and a WebSocket client in
//! Rust. Login, `POST /api/v1/access`, `GET /api/v1/gateway`, frames relayed
//! both ways (round-trip time measured), refusals, and the cut of the
//! gateway session when its login session is revoked.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test helpers and scenarios"
)]

mod common;
mod web_stub;

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{TestDb, block_on};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use ostena_common::api::web::{AccessGrant, SessionInfo};
use ostena_common::config::scope::{AllowRuleSpec, PolicySpec};
use ostena_common::config::{CoreConfig, Mode};
use ostena_common::secret::{SecretBytes, SecretString};
use ostena_core::cache::AgentCache;
use ostena_core::credential::{self, TotpKey};
use ostena_core::functions::Functions;
use ostena_core::inventory;
use ostena_core::server::{Keys, RunningCore, StartInfo};
use ostena_core::ssh_ca::SshAuthorities;
use ostena_core::store::PgStore;
use ostena_core::transcripts::Transcripts;
use ostena_crypto::hmac::HmacKey;
use ostena_crypto::p256::SigningKey;
use ostena_crypto::pki::testing::{TestPki, valid};
use ostena_crypto::pki::{pem_certificate, pem_private_key};
use ostena_crypto::tls::testing::{Offer, browser_client_config};
use ostena_crypto::tls::{self, Identity};
use ostena_crypto::totp::{TotpAlgorithm, step_at};
use ostena_frame::{Decoded, Direction, Flags, Payload, decode_stream};
use ostena_grant::{Issuer, MemoryReplayStore, Protocol};
use ostena_platform::private_file::{self, Reader};
use ostena_scope::{LocalAddresses, SharedLocalAddresses};
use ostena_tunnel::browser::{self, BrowserDriver, Ended};
use ostena_tunnel::enroll::AgentRegistry;
use ostena_tunnel::gateway::{Gateway, GatewayParams, GatewayState, Session};
use ostena_tunnel::link::{AgentLink, Backoff, LinkParams, SystemClock};
use ostena_tunnel::{Channel, Hello, Limits, Uuid};
use ostena_ws::Opcode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use web_stub::{Connection, ORIGIN, request};

const GROUP: &str = "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6";
const PASSWORD: &str = "correct horse battery";
const WAIT: Duration = Duration::from_secs(15);
const PINGS: usize = 500;

fn now() -> u64 {
    ostena_grant::unix_now()
}

fn free_port() -> u16 {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn config(port: u16) -> CoreConfig {
    toml::from_str(&format!(
        "tunnel_listen = \"127.0.0.1:{port}\"\n\
         enrollment_listen = \"127.0.0.1:{}\"\n\
         tls_root_ca = \"/unused/root.pem\"\n\
         tls_certificate = \"/unused/server.pem\"\n\
         tls_private_key = {{ credential = \"server.key\" }}\n\
         issuing_certificate = \"/unused/issuing.pem\"\n\
         issuing_private_key = {{ credential = \"issuing.key\" }}\n\
         grant_signing_key = {{ credential = \"grant.key\" }}\n\
         [audit]\nsigning_key = {{ credential = \"audit.key\" }}\nhead_interval_secs = 1\n\
         [login]\nlisten = \"127.0.0.1:0\"\ntotp_key = {{ credential = \"totp.key\" }}\n\
         ssh_hosts = [\"bastion.lab\"]\nmax_failures = 3\nlockout_minutes = 15\n\
         [web]\nlisten = \"127.0.0.1:0\"\norigin = \"{ORIGIN}\"\n",
        free_port()
    ))
    .unwrap()
}

fn keys(pki: TestPki, totp: Arc<TotpKey>, transcripts: &Path) -> Keys {
    let (server_key, server_pkcs8) = SigningKey::generate().unwrap();
    let server = pki
        .root
        .sign_server(
            &server_key.verifying_key(),
            &["127.0.0.1", "core.test"],
            valid(),
        )
        .unwrap();
    Keys {
        root: pki.root_anchor(),
        server: Identity::new(vec![server], server_pkcs8).unwrap(),
        issuing: Arc::new(pki.issuing),
        audit: Arc::new(SigningKey::generate().unwrap().0),
        grant: Arc::new(Issuer::new(SigningKey::generate().unwrap().0)),
        ssh: Some(Arc::new(
            SshAuthorities::new(
                SigningKey::generate().unwrap().0,
                SigningKey::generate().unwrap().0,
                30,
            )
            .unwrap(),
        )),
        totp: Some(totp),
        transcripts: Some(Arc::new(
            Transcripts::open(
                transcripts,
                HmacKey::new(&HmacKey::generate().unwrap()).unwrap(),
            )
            .unwrap(),
        )),
        directories: None,
    }
}

fn allow_lab() -> PolicySpec {
    PolicySpec {
        allow: vec![AllowRuleSpec {
            label: None,
            networks: vec!["10.20.0.0/16".into()],
            ports: vec!["22".into()],
        }],
        ..PolicySpec::default()
    }
}

/// The agent: its link and gateway, files in `dir`.
fn agent(dir: &Path, port: u16, keys: &Keys, cert_pem: &str, key_pem: &[u8]) -> Arc<Gateway> {
    let certificate = dir.join("agent.crt");
    let private_key = dir.join("agent.key");
    std::fs::write(&certificate, cert_pem).unwrap();
    private_file::create(&private_key, key_pem, Reader::CurrentProcess).unwrap();
    let group = Uuid::parse(GROUP).unwrap();
    let link = Arc::new(AgentLink::spawn(LinkParams {
        core_address: format!("127.0.0.1:{port}"),
        certificate,
        private_key,
        root: tls::TrustAnchor::from_der(keys.root.certificate().clone()),
        hello: Hello {
            agent_version: "test".into(),
            gateway_group: group,
            config_fingerprint: format!("sha256:{}", "0".repeat(64)),
        },
        transport: ostena_tunnel::TransportMode::Auto,
        limits: Limits::default(),
        backoff: Backoff {
            base: Duration::from_millis(100),
            max: Duration::from_millis(400),
            stable_after: Duration::from_secs(60),
        },
        clock: Arc::new(SystemClock),
        write_key: |path, bytes| private_file::create(path, bytes, Reader::CurrentProcess),
    }));
    let state = GatewayState::open(GatewayParams {
        gateway_group: group,
        mode: Mode::Production,
        local_policy: PolicySpec {
            gateway_group: GROUP.into(),
            ..allow_lab()
        },
        infrastructure: Arc::new(Mutex::new(Vec::new())),
        local_addresses: SharedLocalAddresses::new(LocalAddresses::from_addrs([])),
        keyset_state: dir.join("keyset.version"),
        write_private: |path, bytes| private_file::create(path, bytes, Reader::CurrentProcess),
        grant_policy: ostena_grant::Policy::default(),
    })
    .unwrap();
    Arc::new(Gateway::start(Arc::new(state), link).unwrap())
}

/// The test driver of the agent: answers Hello with HelloAck (version 1)
/// and each Ping with its Pong, as a protocol driver answers the browser.
struct Pinger;

impl BrowserDriver for Pinger {
    fn serves(&self, protocol: Protocol) -> bool {
        protocol == Protocol::Ssh
    }

    async fn run(&self, _: Session, mut channel: Channel) -> Ended {
        let mut pending: Vec<u8> = Vec::new();
        let mut buf = vec![0u8; 16 * 1024];
        let mut sequence = 0u64;
        let mut received = 0u64;
        let reason = 'session: loop {
            loop {
                let (reply, used) = match decode_stream(&pending, Direction::ToGateway) {
                    Ok(Decoded::Frame(frame, used)) => {
                        let reply = match frame.payload {
                            Payload::Hello { .. } => Some((
                                Payload::HelloAck {
                                    version: 1,
                                    capabilities: 0,
                                },
                                0,
                            )),
                            Payload::Ping { token } => Some((Payload::Pong { token }, 1)),
                            _ => None,
                        };
                        (reply, used)
                    }
                    Ok(Decoded::Incomplete { .. }) => break,
                    Err(_) => break 'session "trame refusée par l'agent",
                };
                pending.drain(..used);
                if let Some((payload, version)) = reply {
                    let mut out = Vec::new();
                    ostena_frame::encode(
                        &payload,
                        Direction::ToBrowser,
                        version,
                        0,
                        Flags::NONE,
                        sequence,
                        &mut out,
                    )
                    .unwrap();
                    sequence += 1;
                    if channel.send.write_all(&out).await.is_err() {
                        break 'session "flux perdu";
                    }
                }
            }
            match channel.recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    received += n as u64;
                    pending.extend_from_slice(&buf[..n]);
                }
                _ => break "fin du flux navigateur",
            }
        };
        let _ = channel.send.finish();
        Ended {
            reason: reason.into(),
            bytes_to_target: received,
            bytes_from_target: 0,
        }
    }
}

/// A WebSocket client over the upgraded connection.
struct Ws {
    io: TokioIo<hyper::upgrade::Upgraded>,
    buf: Vec<u8>,
    sequence: u64,
}

impl Ws {
    async fn send(&mut self, opcode: Opcode, payload: &[u8]) {
        let mut out = Vec::new();
        ostena_ws::client::encode(opcode, true, payload, [7, 1, 9, 3], &mut out);
        self.io.write_all(&out).await.unwrap();
    }

    /// Sends one frame towards the gateway, with the next sequence number.
    async fn frame(&mut self, payload: &Payload<'_>, version: u8) {
        let mut out = Vec::new();
        ostena_frame::encode(
            payload,
            Direction::ToGateway,
            version,
            0,
            Flags::NONE,
            self.sequence,
            &mut out,
        )
        .unwrap();
        self.sequence += 1;
        self.send(Opcode::Binary, &out).await;
    }

    /// The next message: opcode and payload.
    async fn recv(&mut self) -> (u8, Vec<u8>) {
        loop {
            if let Some((used, frame)) = ostena_ws::client::decode(&self.buf) {
                let message = (frame.opcode, frame.payload.to_vec());
                self.buf.drain(..used);
                return message;
            }
            let mut chunk = vec![0u8; 16 * 1024];
            let n = tokio::time::timeout(WAIT, self.io.read(&mut chunk))
                .await
                .expect("message attendu")
                .unwrap();
            assert!(n > 0, "connexion fermée sans trame de fermeture");
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }
}

/// The close code of a close frame payload.
fn close_code(payload: &[u8]) -> u16 {
    u16::from_be_bytes([payload[0], payload[1]])
}

/// The answer to a WebSocket handshake on `/api/v1/gateway`.
enum Upgrade {
    Open(Ws),
    Refused(StatusCode, String),
}

async fn open_ws(
    addr: SocketAddr,
    cookie: &str,
    protocols: &str,
    origin: &str,
    root: &tls::TrustAnchor,
) -> Upgrade {
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tcp.set_nodelay(true).unwrap();
    let config = browser_client_config(Offer::X25519MlKem768, root).unwrap();
    let tls = tokio_rustls::TlsConnector::from(config)
        .connect(
            tokio_rustls::rustls::pki_types::ServerName::try_from("core.test").unwrap(),
            tcp,
        )
        .await
        .unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(connection.with_upgrades());
    let request = Request::builder()
        .method("GET")
        .uri("/api/v1/gateway")
        .header("host", "core.test")
        .header("origin", origin)
        .header("cookie", format!("__Host-ostena_session={cookie}"))
        .header("upgrade", "websocket")
        .header("connection", "Upgrade")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .header("sec-websocket-protocol", protocols)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status();
    if status != StatusCode::SWITCHING_PROTOCOLS {
        use http_body_util::BodyExt;
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let code = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v["code"].as_str().map(str::to_owned))
            .unwrap_or_default();
        return Upgrade::Refused(status, code);
    }
    let headers = response.headers();
    assert_eq!(headers["sec-websocket-protocol"], "ostena-frame.v1");
    assert_eq!(
        headers["sec-websocket-accept"],
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    );
    let upgraded = hyper::upgrade::on(response).await.unwrap();
    Upgrade::Open(Ws {
        io: TokioIo::new(upgraded),
        buf: Vec::new(),
        sequence: 0,
    })
}

fn percentile(sorted: &[Duration], p: usize) -> Duration {
    sorted[(sorted.len() * p / 100).min(sorted.len() - 1)]
}

#[test]
fn browser_gateway_end_to_end() {
    block_on(async {
        let Some(db) = TestDb::create("browser_gateway_end_to_end").await else {
            return;
        };
        db.migrate().await;
        let pool = db.pool().await;
        let dir =
            Dir(std::env::temp_dir()
                .join(format!("ostena-core-web-gateway-{}", std::process::id())));
        let _ = std::fs::remove_dir_all(&dir.0);
        std::fs::create_dir_all(&dir.0).unwrap();

        // PKI, agent registered, inventory, alice with both factors.
        let pki = TestPki::new("Ostena gateway").unwrap();
        let group = Uuid::parse(GROUP).unwrap();
        let agent_id = Uuid::random().unwrap();
        let (agent_key, agent_pkcs8) = SigningKey::generate().unwrap();
        let agent_cert = pki
            .issuing
            .issue_agent(
                &agent_key.verifying_key(),
                GROUP,
                &agent_id.to_string(),
                valid(),
            )
            .unwrap();
        let bytes: [u8; 32] = ostena_crypto::rand::array().unwrap();
        let totp_key =
            Arc::new(TotpKey::from_bytes(&SecretBytes::from(bytes.to_vec()), &[]).unwrap());
        let keys = keys(pki, totp_key.clone(), &dir.0.join("transcripts"));
        let store = PgStore::new(pool.clone(), Arc::new(AgentCache::default()));
        ostena_core::audit::ensure_genesis(&pool).await.unwrap();
        store
            .register(tls::fingerprint(&agent_cert), group, agent_id)
            .await
            .unwrap();
        inventory::create_group(&pool, Some(group), "lab", &["bastion.lab".into()])
            .await
            .unwrap();
        inventory::set_group_policy(&pool, "lab", &allow_lab())
            .await
            .unwrap();
        inventory::add_user(&pool, "alice", "Alice").await.unwrap();
        credential::set_password(&pool, "alice", SecretString::from(PASSWORD.to_owned()))
            .await
            .unwrap();
        let totp = credential::enroll_totp(&pool, &totp_key, "alice", TotpAlgorithm::Sha1)
            .await
            .unwrap();
        credential::confirm_totp(&pool, &totp_key, "alice", &totp.code(step_at(now())))
            .await
            .unwrap();
        let target = SigningKey::generate().unwrap().0.verifying_key();
        inventory::add_resource(&pool, "srv-lab01", "10.20.0.5", 22, "lab", &target)
            .await
            .unwrap();
        inventory::add_account(&pool, "srv-lab01", "root")
            .await
            .unwrap();
        inventory::grant_right(
            &pool,
            "alice",
            "srv-lab01",
            "root",
            now() + 86_400,
            1800,
            Functions::NONE,
        )
        .await
        .unwrap();

        // The core, then the agent with its browser driver.
        let port = free_port();
        let running = RunningCore::start(
            &config(port),
            PgStore::new(pool.clone(), Arc::new(AgentCache::default())),
            &keys,
            &StartInfo::default(),
        )
        .await
        .unwrap();
        let web = running.web_addr().unwrap();
        // SECRET-EXPOSURE: test only, the key file `agent enroll` would write.
        #[expect(clippy::disallowed_methods)]
        let key_pem = pem_private_key(&agent_pkcs8).expose_secret().to_vec();
        let gateway = agent(&dir.0, port, &keys, &pem_certificate(&agent_cert), &key_pem);
        let deadline = Instant::now() + WAIT;
        while gateway.state().versions().policy.is_none()
            || gateway.state().versions().keyset.is_none()
        {
            assert!(Instant::now() < deadline, "poussées du core non reçues");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let journal = Arc::new(MemoryReplayStore::new());
        let mut incoming = gateway.link().take_incoming().unwrap();
        {
            let gateway = gateway.clone();
            tokio::spawn(async move {
                while let Some((_, _, channel)) = incoming.recv().await {
                    let (gateway, journal) = (gateway.clone(), journal.clone());
                    tokio::spawn(async move {
                        browser::serve(&gateway, channel, &*journal, &Pinger, now()).await;
                    });
                }
            });
        }

        // Login on the portal, then an access.
        let root = keys.root.clone();
        let connect = || async {
            let config = browser_client_config(Offer::X25519MlKem768, &root).unwrap();
            Connection::open(web, "127.0.0.1".parse().unwrap(), config)
                .await
                .unwrap()
        };
        // The step used by the confirmation is forgotten (one use each).
        sqlx::query("UPDATE user_credential SET totp_last_step = 0")
            .execute(&pool)
            .await
            .unwrap();
        // SECRET-EXPOSURE: test builds the request body.
        #[expect(clippy::disallowed_methods)]
        let code = totp.code(step_at(now())).expose_secret().to_owned();
        let body = format!(r#"{{"username":"alice","password":"{PASSWORD}","totp":"{code}"}}"#);
        let reply = connect()
            .await
            .send(request("POST", "/api/v1/session", None, &body))
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.code());
        let cookie = reply.cookie().unwrap();
        let info = SessionInfo::parse(&reply.body).unwrap();
        let ask = || async {
            let body = r#"{"resource":"srv-lab01","account":"root","protocol":"ssh"}"#;
            let reply = connect()
                .await
                .send(request("POST", "/api/v1/access", Some(&cookie), body))
                .await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.code());
            AccessGrant::parse(&reply.body).unwrap().grant
        };
        let grant = ask().await;
        let protocols = |grant: &str| format!("ostena-frame.v1, ostena-grant.{grant}");

        // Refusals before the upgrade: origin, sub-protocol, grant.
        let refused = |u: Upgrade| match u {
            Upgrade::Refused(status, code) => (status, code),
            Upgrade::Open(_) => panic!("WebSocket ouverte"),
        };
        assert_eq!(
            refused(open_ws(web, &cookie, &protocols(&grant), "https://evil.test", &root).await),
            (StatusCode::FORBIDDEN, "WEB-E002".into())
        );
        assert_eq!(
            refused(
                open_ws(
                    web,
                    &cookie,
                    &format!("ostena-grant.{grant}"),
                    ORIGIN,
                    &root
                )
                .await
            ),
            (StatusCode::BAD_REQUEST, "GTW-E002".into())
        );
        assert_eq!(
            refused(open_ws(web, "AAAA", &protocols(&grant), ORIGIN, &root).await).0,
            StatusCode::UNAUTHORIZED
        );
        let forged = format!("{}B", &grant[..grant.len() - 1]);
        assert_eq!(
            refused(open_ws(web, &cookie, &protocols(&forged), ORIGIN, &root).await),
            (StatusCode::FORBIDDEN, "GTW-E001".into())
        );

        // The gateway session: negotiation, then pings measured.
        let Upgrade::Open(mut ws) = open_ws(web, &cookie, &protocols(&grant), ORIGIN, &root).await
        else {
            panic!("WebSocket refusée");
        };
        ws.frame(
            &Payload::Hello {
                versions: 1,
                capabilities: 0,
            },
            0,
        )
        .await;
        let (opcode, ack) = ws.recv().await;
        assert_eq!(opcode, Opcode::Binary as u8);
        let decoded = ostena_frame::decode_message(&ack, Direction::ToBrowser).unwrap();
        assert!(matches!(
            decoded.payload,
            Payload::HelloAck { version: 1, .. }
        ));
        let mut rtts = Vec::with_capacity(PINGS);
        for token in 0..PINGS as u64 {
            let started = Instant::now();
            ws.frame(&Payload::Ping { token }, 1).await;
            let (_, pong) = ws.recv().await;
            rtts.push(started.elapsed());
            let decoded = ostena_frame::decode_message(&pong, Direction::ToBrowser).unwrap();
            assert_eq!(decoded.payload, Payload::Pong { token });
        }
        rtts.sort();
        let (p50, p99) = (percentile(&rtts, 50), percentile(&rtts, 99));
        eprintln!(
            "gateway.rtt: {PINGS} allers-retours navigateur → core → agent → core → navigateur, \
             p50 {} µs, p99 {} µs",
            p50.as_micros(),
            p99.as_micros()
        );
        assert!(p99 < Duration::from_millis(100), "p99 {p99:?}");

        // The same grant again: already presented.
        assert_eq!(
            refused(open_ws(web, &cookie, &protocols(&grant), ORIGIN, &root).await),
            (StatusCode::FORBIDDEN, "GTW-E001".into())
        );

        // A frame out of sequence closes the session (1002).
        ws.sequence += 5;
        ws.frame(&Payload::Ping { token: 1 }, 1).await;
        let (opcode, payload) = ws.recv().await;
        assert_eq!((opcode, close_code(&payload)), (Opcode::Close as u8, 1002));

        // A text message closes the session (1003).
        let Upgrade::Open(mut ws) =
            open_ws(web, &cookie, &protocols(&ask().await), ORIGIN, &root).await
        else {
            panic!("WebSocket refusée");
        };
        ws.send(Opcode::Text, b"hello").await;
        let (opcode, payload) = ws.recv().await;
        assert_eq!((opcode, close_code(&payload)), (Opcode::Close as u8, 1003));

        // The logout revokes the login session: its gateway session is cut.
        let Upgrade::Open(mut ws) =
            open_ws(web, &cookie, &protocols(&ask().await), ORIGIN, &root).await
        else {
            panic!("WebSocket refusée");
        };
        ws.frame(
            &Payload::Hello {
                versions: 1,
                capabilities: 0,
            },
            0,
        )
        .await;
        let _ = ws.recv().await;
        let reply = connect()
            .await
            .send(request("DELETE", "/api/v1/session", Some(&cookie), ""))
            .await;
        assert!(reply.status.is_success(), "{}", reply.code());
        let (opcode, payload) = ws.recv().await;
        assert_eq!((opcode, close_code(&payload)), (Opcode::Close as u8, 1008));

        // The records: opened (granting), refused, closed.
        let count = |event: &'static str| {
            let pool = pool.clone();
            async move {
                let deadline = Instant::now() + WAIT;
                loop {
                    let n: i64 =
                        sqlx::query_scalar("SELECT count(*) FROM audit_record WHERE event = $1")
                            .bind(event)
                            .fetch_one(&pool)
                            .await
                            .unwrap();
                    if n > 0 || Instant::now() > deadline {
                        return n;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        };
        assert_eq!(count("gateway.opened").await, 3);
        assert!(count("gateway.refused").await >= 2);
        assert!(count("gateway.closed").await >= 2);
        let presented: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM access_grant WHERE channel = 'web' AND presented_at IS NOT NULL",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(presented, 3);
        let _ = info;
        running.stop().await;
        pool.close().await;
        db.drop_database().await;
    });
}
