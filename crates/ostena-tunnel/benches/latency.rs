//! Latency added by the tunnel on 127.0.0.1: 64-byte round trips on an
//! interactive channel to the test core (echo), over QUIC and over the TLS
//! 1.3 on TCP fallback, against the same round trips on a plain TCP
//! loopback. Prints p50 and p99; indicative target: < 1 ms added at p99.
//! Not a gate (ADR-0005).
//!
//! `cargo bench -p ostena-tunnel`; with `OSTENA_BENCH_OUT`, the results are
//! also appended there as JSON Lines (`cargo xtask bench-ssh`).

#![allow(
    clippy::expect_used,
    clippy::print_stdout,
    reason = "benchmark binary: prints its results, fixed inputs"
)]

use std::time::{Duration, Instant};

use ostena_tunnel::testing::{Behaviour, TestCore, valid};
use ostena_tunnel::{Limits, StreamClass, Transport, Uuid, connect};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const ROUND_TRIPS: usize = 5_000;
const WARM_UP: usize = 200;
const MESSAGE: [u8; 64] = [0x5a; 64];

/// Nearest-rank percentile, `per_mille` in thousandths.
fn percentile(sorted: &[Duration], per_mille: usize) -> Duration {
    sorted[(sorted.len() - 1) * per_mille / 1000]
}

fn micros(d: Duration) -> f64 {
    d.as_secs_f64() * 1e6
}

async fn tunnel_round_trips(transport: Transport) -> Vec<Duration> {
    let limits = Limits::default();
    let core = TestCore::start(limits, Behaviour::default()).expect("test core");
    let group = Uuid::from_bytes([1; 16]);
    let id = core.agent_identity(group, valid(), true).expect("identity");
    let mut config = core.agent_config(&id, group, limits).expect("config");
    config.transport = transport;
    let (tunnel, _) = connect(&config).await.expect("tunnel");
    let mut ch = tunnel
        .open_channel(Uuid::random().expect("random"), StreamClass::Interactive)
        .await
        .expect("channel");
    let mut buf = [0u8; 64];
    let mut samples = Vec::with_capacity(ROUND_TRIPS);
    for i in 0..WARM_UP + ROUND_TRIPS {
        let start = Instant::now();
        ch.send.write_all(&MESSAGE).await.expect("write");
        ch.recv.read_exact(&mut buf).await.expect("read");
        if i >= WARM_UP {
            samples.push(start.elapsed());
        }
    }
    samples
}

async fn tcp_round_trips() -> Vec<Duration> {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.expect("accept");
        s.set_nodelay(true).expect("nodelay");
        let mut buf = [0u8; 64];
        while s.read_exact(&mut buf).await.is_ok() {
            if s.write_all(&buf).await.is_err() {
                break;
            }
        }
    });
    let mut s = TcpStream::connect(addr).await.expect("connect");
    s.set_nodelay(true).expect("nodelay");
    let mut buf = [0u8; 64];
    let mut samples = Vec::with_capacity(ROUND_TRIPS);
    for i in 0..WARM_UP + ROUND_TRIPS {
        let start = Instant::now();
        s.write_all(&MESSAGE).await.expect("write");
        s.read_exact(&mut buf).await.expect("read");
        if i >= WARM_UP {
            samples.push(start.elapsed());
        }
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
        "{{\"bench\":\"tunnel\",\"case\":\"{case}\",\"samples\":{samples},\
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

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let mut tcp = rt.block_on(tcp_round_trips());
    tcp.sort_unstable();
    for (transport, case) in [
        (Transport::Quic, "round_trip_64"),
        (Transport::Tcp, "round_trip_64_tcp"),
    ] {
        let mut tunnel = rt.block_on(tunnel_round_trips(transport));
        tunnel.sort_unstable();
        let name = transport.as_str().to_uppercase();
        for (label, p) in [("p50", 500), ("p99", 990)] {
            let t = percentile(&tunnel, p);
            let base = percentile(&tcp, p);
            println!(
                "{name} round trip {label}: tunnel {:.0} µs, TCP loopback {:.0} µs, added {:.0} µs",
                micros(t),
                micros(base),
                micros(t.saturating_sub(base))
            );
        }
        let added_p99 = percentile(&tunnel, 990).saturating_sub(percentile(&tcp, 990));
        println!(
            "{name} added latency p99: {:.3} ms (indicative target < 1 ms)",
            added_p99.as_secs_f64() * 1e3
        );
        record(
            case,
            tunnel.len(),
            [percentile(&tcp, 500), percentile(&tcp, 990)],
            [percentile(&tunnel, 500), percentile(&tunnel, 990)],
        );
    }
}
