//! Shared by the SSH integration tests: OpenSSH tools, keys, a test server
//! and client behind the pre-check, and the capture of events.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    dead_code,
    unreachable_pub,
    clippy::unused_async_trait_impl,
    clippy::print_stderr,
    clippy::panic,
    reason = "test helpers, not every test binary uses every helper; the SSH handler methods are async by trait; skip notices go to stderr"
)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use ostena_ssh::config;
use ostena_ssh::precheck::Role;
use ostena_ssh::precheck::stream::Prechecked;
use russh::keys::{PrivateKey, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use russh::server::{Auth, ChannelOpenHandle, Msg, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId, ChannelMsg};
use tokio::net::{TcpListener, TcpStream};
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, SubscriberExt};

/// Deadline of the pre-check in the tests.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// An OpenSSH tool (`ssh`, `ssh-keygen`): the Windows built-in one, or the
/// one on the path. `None` when absent; with `OSTENA_REQUIRE_OPENSSH=1` (CI)
/// its absence fails the test.
pub fn openssh(tool: &str) -> Option<PathBuf> {
    let candidates = if cfg!(windows) {
        vec![
            PathBuf::from(format!(r"C:\Windows\System32\OpenSSH\{tool}.exe")),
            PathBuf::from(format!("{tool}.exe")),
        ]
    } else {
        vec![PathBuf::from(tool)]
    };
    let found = candidates
        .into_iter()
        .find(|c| Command::new(c).arg("-V").output().is_ok());
    if found.is_none() {
        assert!(
            std::env::var("OSTENA_REQUIRE_OPENSSH").as_deref() != Ok("1"),
            "{tool} introuvable alors que OSTENA_REQUIRE_OPENSSH=1"
        );
        eprintln!("{tool} introuvable : test sauté");
    }
    found
}

/// A temporary directory removed on drop.
pub struct Dir(pub PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A fresh directory for `name`.
pub fn dir(name: &str) -> Dir {
    let dir = std::env::temp_dir().join(format!("ostena-ssh-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Dir(dir)
}

/// An ECDSA P-256 key pair made by `ssh-keygen`: the private key file and
/// the public key line.
///
/// ssh-key 0.7.0-rc.11 refuses a P-256 private key whose scalar OpenSSH
/// encodes on 31 bytes (about one key in 512; ADR-0010): such a key is made
/// again, so that the tests do not fail at random.
pub fn keygen(keygen: &Path, dir: &Path, name: &str) -> (PathBuf, String) {
    let path = dir.join(name);
    let public_path = PathBuf::from(format!("{}.pub", path.display()));
    for _ in 0..16 {
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&public_path);
        let status = Command::new(keygen)
            .args([
                "-q", "-t", "ecdsa", "-b", "256", "-N", "", "-C", "test", "-f",
            ])
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success());
        if russh::keys::load_secret_key(&path, None).is_ok() {
            let public = std::fs::read_to_string(&public_path).unwrap();
            return (path, public.trim().to_owned());
        }
    }
    panic!("no loadable key in 16 attempts")
}

/// Loads a private key written by `ssh-keygen`.
pub fn load(path: &Path) -> PrivateKey {
    russh::keys::load_secret_key(path, None).unwrap()
}

/// Parses a public key line.
pub fn public(line: &str) -> PublicKey {
    PublicKey::from_openssh(line).unwrap()
}

/// The test server: accepts the one `allowed` key, answers `ok` to any
/// command.
#[derive(Clone)]
pub struct TestServer {
    pub allowed: PublicKey,
}

impl russh::server::Handler for TestServer {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        if key.public_key.key_data() == self.allowed.key_data() {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(channel, b"ok\n".to_vec())?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

/// Serves `handler` behind the pre-check on 127.0.0.1; events carry
/// `label` as their peer, so that each test finds its own.
pub async fn serve(host_key: PrivateKey, handler: TestServer, label: &str) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = config::server(vec![host_key]);
    let label = label.to_owned();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let stream = Prechecked::new(tcp, Role::Server, label.clone(), TIMEOUT);
            let config = config.clone();
            let handler = handler.clone();
            tokio::spawn(async move {
                if let Ok(session) = russh::server::run_stream(config, stream, handler).await {
                    let _ = session.await;
                }
            });
        }
    });
    addr
}

/// The client side: trusts only `host_key`.
pub struct TestClient {
    pub host_key: PublicKey,
}

impl russh::client::Handler for TestClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(
            matches!(server, PublicKeyOrCertificate::PublicKey { key, .. }
            if key.key_data() == self.host_key.key_data()),
        )
    }
}

/// Connects behind the pre-check, authenticates with `key` and runs
/// `command`; returns what it printed.
pub async fn run_command(
    addr: &str,
    label: &str,
    host_key: PublicKey,
    user: &str,
    key: PrivateKey,
    command: &str,
) -> Result<String, String> {
    let tcp = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let stream = Prechecked::new(tcp, Role::Client, label, TIMEOUT);
    let mut handle =
        russh::client::connect_stream(config::client(), stream, TestClient { host_key })
            .await
            .map_err(|e| e.to_string())?;
    let auth = handle
        .authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), None))
        .await
        .map_err(|e| e.to_string())?;
    if !auth.success() {
        return Err("authentification refusée".into());
    }
    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|e| e.to_string())?;
    channel
        .exec(true, command)
        .await
        .map_err(|e| e.to_string())?;
    let mut output = Vec::new();
    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Data { data } => output.extend_from_slice(&data),
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    Ok(String::from_utf8_lossy(&output).into_owned())
}

/// One event: name, code, peer, and every field as text.
#[derive(Debug, Clone, Default)]
pub struct Event {
    pub name: String,
    pub code: String,
    pub peer: String,
    pub fields: std::collections::HashMap<String, String>,
}

impl Event {
    /// A field as text, empty if absent.
    pub fn field(&self, name: &str) -> &str {
        self.fields.get(name).map_or("", String::as_str)
    }
}

struct Capture(Arc<Mutex<Vec<Event>>>);

struct Fields(Event);

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0
            .fields
            .insert(field.name().to_owned(), value.to_owned());
        match field.name() {
            "event" => value.clone_into(&mut self.0.name),
            "code" => value.clone_into(&mut self.0.code),
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .fields
            .insert(field.name().to_owned(), format!("{value:?}"));
        if field.name() == "peer" {
            self.0.peer = format!("{value:?}");
        }
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Capture {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        let mut fields = Fields(Event::default());
        event.record(&mut fields);
        if !fields.0.name.is_empty() {
            self.0.lock().unwrap().push(fields.0);
        }
    }
}

/// The events of the whole test binary (installed once, before any server
/// starts).
pub fn events() -> Arc<Mutex<Vec<Event>>> {
    static EVENTS: OnceLock<Arc<Mutex<Vec<Event>>>> = OnceLock::new();
    EVENTS
        .get_or_init(|| {
            let events = Arc::new(Mutex::new(Vec::new()));
            let subscriber = tracing_subscriber::registry().with(Capture(events.clone()));
            tracing::subscriber::set_global_default(subscriber).unwrap();
            events
        })
        .clone()
}

/// The refusal codes recorded for `label`.
pub fn refusals(label: &str) -> Vec<String> {
    events()
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.name == "ssh.precheck_refused" && e.peer == label)
        .map(|e| e.code.clone())
        .collect()
}

/// A runtime for one test.
pub fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

/// An identification line and a KEXINIT from a peer, with these key
/// exchange names (the other lists follow the frozen list).
pub fn raw_offer(kex: &str) -> Vec<u8> {
    let mut payload = vec![20u8];
    payload.extend_from_slice(&[7; 16]);
    for list in [
        kex,
        "ecdsa-sha2-nistp256",
        "aes256-gcm@openssh.com",
        "aes256-gcm@openssh.com",
        "",
        "",
        "none",
        "none",
        "",
        "",
    ] {
        payload.extend_from_slice(&u32::try_from(list.len()).unwrap().to_be_bytes());
        payload.extend_from_slice(list.as_bytes());
    }
    payload.extend_from_slice(&[0, 0, 0, 0, 0]);
    let mut padding = 8 - (payload.len() + 5) % 8;
    if padding < 4 {
        padding += 8;
    }
    let mut out = b"SSH-2.0-test\r\n".to_vec();
    out.extend_from_slice(
        &u32::try_from(payload.len() + padding + 1)
            .unwrap()
            .to_be_bytes(),
    );
    out.push(u8::try_from(padding).unwrap());
    out.extend_from_slice(&payload);
    out.extend(std::iter::repeat_n(0u8, padding));
    out
}

// ------------------------------------------------- native session helpers

/// The events named `name` on the server listening on `listener`.
pub fn events_on(listener: std::net::SocketAddr, name: &str) -> Vec<Event> {
    let listener = listener.to_string();
    events()
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.name == name && e.field("listener") == listener)
        .cloned()
        .collect()
}

/// Waits up to 10 s for an event named `name` on `listener`.
pub fn wait_event(listener: std::net::SocketAddr, name: &str) -> Vec<Event> {
    for _ in 0..200 {
        let found = events_on(listener, name);
        if !found.is_empty() {
            return found;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Vec::new()
}

/// The events named `name` whose field `field` is `value`.
pub fn events_with(name: &str, field: &str, value: &str) -> Vec<Event> {
    events()
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.name == name && e.field(field) == value)
        .cloned()
        .collect()
}

/// The P-256 point of a public key.
pub fn point(key: &PublicKey) -> ostena_crypto::p256::VerifyingKey {
    let bytes: [u8; 65] = ostena_ssh::driver::sec1_point(key)
        .unwrap()
        .try_into()
        .unwrap();
    ostena_crypto::p256::VerifyingKey::from_bytes(&bytes).unwrap()
}

/// A target for the driver: accepts the one `allowed` key; `exec` answers
/// `ran:<command>` and exit status 0, except `hold`, which keeps the
/// channel open; a shell echoes what it receives; every request succeeds.
#[derive(Clone)]
pub struct EchoTarget {
    pub allowed: PublicKey,
}

impl russh::server::Handler for EchoTarget {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        if key.public_key.key_data() == self.allowed.key_data() {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        _variable_name: &str,
        _variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        if data == b"hold" {
            return Ok(());
        }
        if data == b"open-channels" {
            // A hostile target opens channels towards the agent.
            let handle = session.handle();
            tokio::spawn(async move {
                let _ = handle.channel_open_x11("10.0.0.1", 6000).await;
                let _ = handle
                    .channel_open_forwarded_tcpip("127.0.0.1", 80, "10.0.0.1", 4000)
                    .await;
                let _ = handle.channel_open_agent().await;
                let _ = handle.channel_open_session().await;
            });
        }
        let mut out = b"ran:".to_vec();
        out.extend_from_slice(data);
        out.push(b'\n');
        session.data(channel, out)?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.data(channel, data.to_vec())
    }
}

/// Serves `handler` behind the pre-check on 127.0.0.1.
pub async fn serve_handler<H>(host_key: PrivateKey, handler: H, label: &str) -> std::net::SocketAddr
where
    H: russh::server::Handler<Error = russh::Error> + Clone + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = config::server(vec![host_key]);
    let label = label.to_owned();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let stream = Prechecked::new(tcp, Role::Server, label.clone(), TIMEOUT);
            let config = config.clone();
            let handler = handler.clone();
            tokio::spawn(async move {
                if let Ok(session) = russh::server::run_stream(config, stream, handler).await {
                    let _ = session.await;
                }
            });
        }
    });
    addr
}

/// A pinned target on the loopback: a development policy with the floor
/// lifted for 127.0.0.0/8 (tests only).
pub async fn loopback(port: u16) -> ostena_scope::PinnedTarget {
    use ostena_common::config::Mode;
    use ostena_common::config::scope::{AllowRuleSpec, FloorExceptionSpec, PolicySpec};
    let spec = PolicySpec {
        gateway_group: SUBJECT.into(),
        allow: vec![AllowRuleSpec {
            label: None,
            networks: vec!["127.0.0.0/8".into()],
            ports: vec![port.to_string()],
        }],
        floor_exceptions: vec![FloorExceptionSpec {
            network: "127.0.0.0/8".into(),
            reason: "tests: cible sur la boucle locale".into(),
        }],
        ..PolicySpec::default()
    };
    let policy = ostena_scope::CompiledPolicy::compile(&spec, Mode::Development).unwrap();
    let scope = ostena_scope::Scope::new(
        Arc::new(policy),
        ostena_scope::SharedLocalAddresses::new(ostena_scope::LocalAddresses::from_addrs([])),
        ostena_scope::SystemResolver::new(Duration::from_secs(5), 4),
    );
    scope.pin("127.0.0.1", port).await.unwrap()
}

type Targets = std::collections::HashMap<
    String,
    (
        ostena_scope::PinnedTarget,
        ostena_crypto::p256::VerifyingKey,
    ),
>;

/// An authoriser for tests: maps resources to targets, refuses on demand,
/// records what it saw.
#[derive(Default)]
pub struct TestAuthorizer {
    pub targets: Mutex<Targets>,
    pub refuse: Mutex<Option<ostena_ssh::server::Refusal>>,
    pub max_session: Mutex<Option<Duration>>,
    pub requests: Mutex<Vec<ostena_ssh::server::AccessRequest>>,
    pub closed: Mutex<Vec<ostena_ssh::server::SessionSummary>>,
}

impl ostena_ssh::server::Authorizer for TestAuthorizer {
    async fn authorize(
        &self,
        request: ostena_ssh::server::AccessRequest,
    ) -> Result<ostena_ssh::server::Authorized, ostena_ssh::server::Refusal> {
        self.requests.lock().unwrap().push(request.clone());
        if let Some(refusal) = self.refuse.lock().unwrap().clone() {
            return Err(refusal);
        }
        let found = self.targets.lock().unwrap().get(&request.resource).cloned();
        let Some((target, host_key)) = found else {
            return Err(ostena_ssh::server::Refusal {
                code: "INV-E001".into(),
                message: "ressource inconnue".into(),
            });
        };
        let max_session = self
            .max_session
            .lock()
            .unwrap()
            .unwrap_or(Duration::from_secs(3600));
        Ok(ostena_ssh::server::Authorized {
            session_id: ostena_crypto::rand::array().unwrap(),
            target,
            target_host_key: host_key,
            account: request.account,
            max_session,
        })
    }

    fn closed(&self, summary: ostena_ssh::server::SessionSummary) {
        self.closed.lock().unwrap().push(summary);
    }
}

pub const SUBJECT: &str = "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6";
pub const LOGIN: &str = "7a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";

/// A user certificate template for `public`, valid for an hour, with
/// `permit-pty`.
pub fn user_template(public: ostena_crypto::p256::VerifyingKey) -> ostena_ssh::cert::Template {
    let now = ostena_grant::unix_now();
    ostena_ssh::cert::Template {
        kind: ostena_ssh::cert::Kind::User,
        public,
        serial: 1,
        key_id: LOGIN.into(),
        principals: vec![SUBJECT.into()],
        valid_after: now - 60,
        valid_before: now + 3600,
        critical_options: vec![],
        extensions: vec![(ostena_ssh::cert::PERMIT_PTY.into(), vec![])],
    }
}

/// A host certificate for `host_key`, valid for 127.0.0.1, signed by `ca`.
pub fn host_certificate(host_key: &PublicKey, ca: &ostena_crypto::p256::SigningKey) -> Vec<u8> {
    let now = ostena_grant::unix_now();
    ostena_ssh::cert::issue(
        &ostena_ssh::cert::Template {
            kind: ostena_ssh::cert::Kind::Host,
            public: point(host_key),
            serial: 1,
            key_id: "agent-test".into(),
            principals: vec!["127.0.0.1".into(), "localhost".into()],
            valid_after: now - 60,
            valid_before: now + 86_400,
            critical_options: vec![],
            extensions: vec![],
        },
        ca,
    )
    .unwrap()
}

/// The OpenSSH public key line of a P-256 point.
pub fn public_line(key: &ostena_crypto::p256::VerifyingKey) -> String {
    use base64::Engine;
    let mut blob = Vec::new();
    for part in [&b"ecdsa-sha2-nistp256"[..], b"nistp256", &key.to_bytes()] {
        blob.extend_from_slice(&u32::try_from(part.len()).unwrap().to_be_bytes());
        blob.extend_from_slice(part);
    }
    format!(
        "ecdsa-sha2-nistp256 {}",
        base64::engine::general_purpose::STANDARD.encode(blob)
    )
}

/// The OpenSSH line of a certificate blob.
pub fn certificate_line(blob: &[u8]) -> String {
    use base64::Engine;
    format!(
        "{} {} test",
        ostena_ssh::cert::CERT_TYPE,
        base64::engine::general_purpose::STANDARD.encode(blob)
    )
}

/// The agent SSH server with a test identity, listening on 127.0.0.1.
pub struct Agent {
    pub addr: std::net::SocketAddr,
    pub server: ostena_ssh::server::SshServer<TestAuthorizer>,
    pub authorizer: Arc<TestAuthorizer>,
    pub user_ca: ostena_crypto::p256::SigningKey,
    pub host_ca: ostena_crypto::p256::SigningKey,
    pub stop: tokio::sync::watch::Sender<bool>,
}

/// Starts an agent server: host key `host_key`, joining the targets with
/// `agent_key`, with fresh user and host authorities.
pub async fn agent(
    host_key: PrivateKey,
    agent_key: PrivateKey,
    settings: ostena_ssh::server::ServerSettings,
) -> Agent {
    let user_ca = ostena_crypto::p256::SigningKey::generate().unwrap().0;
    let host_ca = ostena_crypto::p256::SigningKey::generate().unwrap().0;
    let certificate = host_certificate(host_key.public_key(), &host_ca);
    let identity = ostena_ssh::server::SshIdentity::new(
        host_key,
        &certificate,
        vec![user_ca.verifying_key()],
        ostena_grant::unix_now(),
    )
    .unwrap();
    let (identity_tx, identity_rx) = tokio::sync::watch::channel(Some(Arc::new(identity)));
    let authorizer = Arc::new(TestAuthorizer::default());
    let server = ostena_ssh::server::SshServer::new(
        settings,
        identity_rx,
        Arc::new(agent_key),
        authorizer.clone(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stop_rx) = tokio::sync::watch::channel(false);
    let serving = server.clone();
    tokio::spawn(async move {
        let keep = identity_tx;
        let _ = serving.serve(listener, stop_rx).await;
        drop(keep);
    });
    Agent {
        addr,
        server,
        authorizer,
        user_ca,
        host_ca,
        stop,
    }
}
