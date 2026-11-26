//! Latency added by the agent SSH server and its driver on 127.0.0.1:
//! 64-byte round trips in a shell channel to an echo target, through the
//! agent (client → server → driver → target) against the same round trips
//! straight to the target; then the time to set up a session (connection,
//! certificate checks, authorisation, connection to the target, channel and
//! shell) against a direct session. Prints p50 and p99; target: at most
//! 3 ms added at p99 (CLAUDE.md). Not a gate (ADR-0005).
//!
//! `cargo bench -p ostena-ssh --bench relay`; with `OSTENA_BENCH_OUT`, the
//! results are also appended there as JSON Lines (`cargo xtask bench-ssh`).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stdout,
    clippy::unused_async_trait_impl,
    reason = "benchmark binary: prints its results, fixed inputs; the SSH handler methods are async by trait"
)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use ostena_common::config::Mode;
use ostena_common::config::scope::{AllowRuleSpec, FloorExceptionSpec, PolicySpec};
use ostena_crypto::p256::{SigningKey, VerifyingKey};
use ostena_ssh::cert::{self, Kind, Template};
use ostena_ssh::config;
use ostena_ssh::driver::sec1_point;
use ostena_ssh::server::{
    AccessRequest, Authorized, Authorizer, Refusal, ServerSettings, SessionSummary, SshIdentity,
    SshServer,
};
use russh::keys::{
    Certificate, PrivateKey, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate,
};
use russh::server::{Auth, ChannelOpenHandle, Msg, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId, ChannelMsg};
use tokio::net::{TcpListener, TcpStream};

const ROUND_TRIPS: usize = 3_000;
const WARM_UP: usize = 300;
const SETUPS: usize = 30;
const MESSAGE: [u8; 64] = [0x5a; 64];

fn percentile(sorted: &[Duration], per_mille: usize) -> Duration {
    sorted[(sorted.len() - 1) * per_mille / 1000]
}

fn micros(d: Duration) -> f64 {
    d.as_secs_f64() * 1e6
}

fn key() -> PrivateKey {
    let generated = ostena_ssh::keys::generate("bench").expect("key");
    ostena_ssh::keys::load(&generated.private).expect("load")
}

fn point(key: &PublicKey) -> VerifyingKey {
    VerifyingKey::from_bytes(&sec1_point(key).unwrap().try_into().unwrap()).unwrap()
}

/// The target: accepts one key, echoes the data of a shell.
#[derive(Clone)]
struct Echo {
    allowed: PublicKey,
}

impl russh::server::Handler for Echo {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(if key.public_key.key_data() == self.allowed.key_data() {
            Auth::Accept
        } else {
            Auth::reject()
        })
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

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)
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

struct AnyHost;

impl russh::client::Handler for AnyHost {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

struct Bench {
    target: ostena_scope::PinnedTarget,
    target_key: VerifyingKey,
    /// A fresh session identifier per access, as the core gives (a
    /// duplicate is refused by the session manager, ADR-0018).
    next: std::sync::atomic::AtomicU64,
}

impl Bench {
    fn new(target: ostena_scope::PinnedTarget, target_key: VerifyingKey) -> Self {
        Self {
            target,
            target_key,
            next: std::sync::atomic::AtomicU64::new(1),
        }
    }
}

impl Authorizer for Bench {
    async fn authorize(&self, request: AccessRequest) -> Result<Authorized, Refusal> {
        // The transcript is encoded and queued as in the agent; the queue is
        // drained here instead of the tunnel stream.
        let (transcript, mut rx) = ostena_ssh::transcript::Transcript::channel(8);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        let mut session_id = [7; 16];
        session_id[..8].copy_from_slice(
            &self
                .next
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                .to_be_bytes(),
        );
        Ok(Authorized {
            session_id,
            target: self.target.clone(),
            target_host_key: self.target_key,
            account: request.account,
            max_session: Duration::from_secs(3600),
            transcript,
        })
    }

    fn closed(&self, _: SessionSummary) {}
}

async fn pinned(port: u16) -> ostena_scope::PinnedTarget {
    let spec = PolicySpec {
        gateway_group: "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6".into(),
        allow: vec![AllowRuleSpec {
            label: None,
            networks: vec!["127.0.0.0/8".into()],
            ports: vec![port.to_string()],
        }],
        floor_exceptions: vec![FloorExceptionSpec {
            network: "127.0.0.0/8".into(),
            reason: "banc : cible sur la boucle locale".into(),
        }],
        ..PolicySpec::default()
    };
    let policy = ostena_scope::CompiledPolicy::compile(&spec, Mode::Development).unwrap();
    ostena_scope::Scope::new(
        Arc::new(policy),
        ostena_scope::SharedLocalAddresses::new(ostena_scope::LocalAddresses::from_addrs([])),
        ostena_scope::SystemResolver::new(Duration::from_secs(5), 4),
    )
    .pin("127.0.0.1", port)
    .await
    .unwrap()
}

enum Login {
    Key(Arc<PrivateKey>),
    Certificate(Arc<PrivateKey>, Box<Certificate>),
}

/// Connects, authenticates and opens a shell; returns the channel.
type Shell = (russh::client::Handle<AnyHost>, Channel<russh::client::Msg>);

async fn shell(addr: std::net::SocketAddr, user: &str, login: &Login) -> Shell {
    let tcp = TcpStream::connect(addr).await.unwrap();
    tcp.set_nodelay(true).unwrap();
    let mut handle = russh::client::connect_stream(config::client(), tcp, AnyHost)
        .await
        .unwrap();
    let auth = match login {
        Login::Key(key) => handle
            .authenticate_publickey(user, PrivateKeyWithHashAlg::new(key.clone(), None))
            .await
            .unwrap(),
        Login::Certificate(key, cert) => handle
            .authenticate_openssh_cert(user, key.clone(), (**cert).clone())
            .await
            .unwrap(),
    };
    assert!(auth.success(), "authentication refused");
    let channel = handle.channel_open_session().await.unwrap();
    channel.request_shell(true).await.unwrap();
    (handle, channel)
}

async fn round_trips((_handle, mut channel): Shell) -> Vec<Duration> {
    // Wait for the shell answer.
    while let Some(message) = channel.wait().await {
        if matches!(message, ChannelMsg::Success) {
            break;
        }
    }
    let mut samples = Vec::with_capacity(ROUND_TRIPS);
    for i in 0..WARM_UP + ROUND_TRIPS {
        let start = Instant::now();
        channel.data_bytes(MESSAGE.to_vec()).await.unwrap();
        let mut got = 0;
        while got < MESSAGE.len() {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => got += data.len(),
                Some(_) => {}
                None => unreachable!("channel closed"),
            }
        }
        if i >= WARM_UP {
            samples.push(start.elapsed());
        }
    }
    samples
}

async fn setups(addr: std::net::SocketAddr, user: &str, login: &Login) -> Vec<Duration> {
    let mut samples = Vec::with_capacity(SETUPS);
    for _ in 0..SETUPS {
        let start = Instant::now();
        let (_handle, mut channel) = shell(addr, user, login).await;
        while let Some(message) = channel.wait().await {
            if matches!(message, ChannelMsg::Success) {
                break;
            }
        }
        samples.push(start.elapsed());
    }
    samples
}

/// Appends one result to `$OSTENA_BENCH_OUT` (JSON Lines), read by
/// `cargo xtask bench-ssh`; durations in microseconds.
fn record(case: &str, samples: usize, direct: [Duration; 2], through: [Duration; 2]) {
    use std::io::Write as _;
    let Some(path) = std::env::var_os("OSTENA_BENCH_OUT") else {
        return;
    };
    let line = format!(
        "{{\"bench\":\"ssh-relay\",\"case\":\"{case}\",\"samples\":{samples},\
         \"direct_p50_us\":{},\"direct_p99_us\":{},\"through_p50_us\":{},\"through_p99_us\":{}}}\n",
        direct[0].as_micros(),
        direct[1].as_micros(),
        through[0].as_micros(),
        through[1].as_micros(),
    );
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut f| f.write_all(line.as_bytes()))
        .expect("OSTENA_BENCH_OUT");
}

fn report(name: &str, case: &str, through: &mut [Duration], direct: &mut [Duration]) {
    through.sort_unstable();
    direct.sort_unstable();
    let (t50, t99) = (percentile(through, 500), percentile(through, 990));
    let (d50, d99) = (percentile(direct, 500), percentile(direct, 990));
    println!(
        "{name}: direct p50 {:.0} µs p99 {:.0} µs | via l'agent p50 {:.0} µs p99 {:.0} µs | ajouté p50 {:.0} µs p99 {:.0} µs",
        micros(d50),
        micros(d99),
        micros(t50),
        micros(t99),
        micros(t50.saturating_sub(d50)),
        micros(t99.saturating_sub(d99)),
    );
    record(case, through.len(), [d50, d99], [t50, t99]);
}

async fn bench() {
    let agent_key = Arc::new(key());
    let target_host = key();
    let target_key = point(target_host.public_key());
    let host = key();
    let user = Arc::new(key());

    // The target.
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    let target_config = config::server(vec![target_host]);
    let echo = Echo {
        allowed: agent_key.public_key().clone(),
    };
    tokio::spawn(async move {
        while let Ok((tcp, _)) = target_listener.accept().await {
            tcp.set_nodelay(true).unwrap();
            let (config, echo) = (target_config.clone(), echo.clone());
            tokio::spawn(async move {
                if let Ok(session) = russh::server::run_stream(config, tcp, echo).await {
                    let _ = session.await;
                }
            });
        }
    });

    // The agent.
    let user_ca = SigningKey::generate().unwrap().0;
    let host_ca = SigningKey::generate().unwrap().0;
    let now = ostena_grant::unix_now();
    let host_certificate = cert::issue(
        &Template {
            kind: Kind::Host,
            public: point(host.public_key()),
            serial: 1,
            key_id: "bench".into(),
            principals: vec!["127.0.0.1".into()],
            valid_after: now - 60,
            valid_before: now + 3600,
            critical_options: vec![],
            extensions: vec![],
        },
        &host_ca,
    )
    .unwrap();
    let identity = SshIdentity::new(
        host,
        &host_certificate,
        &[host_ca.verifying_key()],
        vec![user_ca.verifying_key()],
        now,
    )
    .unwrap();
    let (_identity, identity_rx) = tokio::sync::watch::channel(Some(Arc::new(identity)));
    let server = SshServer::new(
        ServerSettings::default(),
        identity_rx,
        agent_key.clone(),
        Arc::new(Bench::new(pinned(target_addr.port()).await, target_key)),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let agent_addr = listener.local_addr().unwrap();
    let (_stop, stop) = tokio::sync::watch::channel(false);
    tokio::spawn(async move { server.serve(listener, stop).await });

    let user_certificate = cert::issue(
        &Template {
            kind: Kind::User,
            public: point(user.public_key()),
            serial: 1,
            key_id: "7a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d".into(),
            principals: vec!["2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6".into()],
            valid_after: now - 60,
            valid_before: now + 3600,
            critical_options: vec![],
            extensions: vec![(cert::PERMIT_PTY.into(), vec![])],
        },
        &user_ca,
    )
    .unwrap();
    let certificate = Login::Certificate(
        user.clone(),
        Box::new(Certificate::from_bytes(&user_certificate).unwrap()),
    );
    let direct = Login::Key(agent_key.clone());

    let mut via = round_trips(shell(agent_addr, "ostena@bench", &certificate).await).await;
    let mut straight = round_trips(shell(target_addr, "ostena", &direct).await).await;
    report(
        "aller-retour 64 octets",
        "round_trip_64",
        &mut via,
        &mut straight,
    );
    let mut via = setups(agent_addr, "ostena@bench", &certificate).await;
    let mut straight = setups(target_addr, "ostena", &direct).await;
    report(
        "établissement de session",
        "session_setup",
        &mut via,
        &mut straight,
    );
}

fn main() {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(bench());
}
