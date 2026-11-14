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

/// One event: name, code, peer.
#[derive(Debug, Clone, Default)]
pub struct Event {
    pub name: String,
    pub code: String,
    pub peer: String,
}

struct Capture(Arc<Mutex<Vec<Event>>>);

struct Fields(Event);

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "event" => value.clone_into(&mut self.0.name),
            "code" => value.clone_into(&mut self.0.code),
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
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
