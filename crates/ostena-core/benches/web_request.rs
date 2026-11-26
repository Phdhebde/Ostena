//! Cost of one authenticated request on the portal API (ADR-0020): round
//! trips `GET /api/v1/session` with a session cookie on one keep-alive TLS
//! connection (X25519MLKEM768) to the web listener on 127.0.0.1, against
//! `GET /api/v1/health` (public, no session) on the same kind of connection.
//! The difference is the authentication: cookie digest, session lookup,
//! decision, CSRF and role checks. The store is the in-memory stub of the
//! tests, so the PostgreSQL lookup is not counted. Prints p50 and p99. Not a
//! gate (ADR-0005).
//!
//! `cargo bench -p ostena-core --bench web_request`.

#![allow(
    clippy::expect_used,
    clippy::print_stdout,
    reason = "benchmark binary: prints its results, fixed inputs"
)]

#[path = "../tests/web_stub/mod.rs"]
mod web_stub;

use std::time::{Duration, Instant};

use hyper::StatusCode;
use ostena_core::web::WebSettings;
use web_stub::{Fixture, ORIGIN, bare, cookie, request};

const ROUND_TRIPS: usize = 5_000;
const WARM_UP: usize = 200;

/// Nearest-rank percentile, `per_mille` in thousandths.
fn percentile(sorted: &[Duration], per_mille: usize) -> Duration {
    sorted[(sorted.len() - 1) * per_mille / 1000]
}

fn micros(d: Duration) -> f64 {
    d.as_secs_f64() * 1e6
}

async fn round_trips(authenticated: bool) -> Vec<Duration> {
    let f = Fixture::start(WebSettings::new(ORIGIN.into()), 1000).await;
    let (value, digest) = cookie();
    f.stub.insert(digest, "alice", |_| {});
    let mut connection = f.connect_from("127.0.0.1".parse().expect("address")).await;
    let mut samples = Vec::with_capacity(ROUND_TRIPS);
    for i in 0..WARM_UP + ROUND_TRIPS {
        let req = if authenticated {
            request("GET", "/api/v1/session", Some(&value), "")
        } else {
            bare("GET", "/api/v1/health", None)
        };
        let start = Instant::now();
        let reply = connection.send(req).await;
        let elapsed = start.elapsed();
        let expected = if authenticated {
            StatusCode::OK
        } else {
            StatusCode::NO_CONTENT
        };
        assert_eq!(reply.status, expected);
        if i >= WARM_UP {
            samples.push(elapsed);
        }
    }
    samples
}

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let mut session = rt.block_on(round_trips(true));
    let mut health = rt.block_on(round_trips(false));
    session.sort_unstable();
    health.sort_unstable();
    for (name, p) in [("p50", 500), ("p99", 990)] {
        let s = percentile(&session, p);
        let h = percentile(&health, p);
        println!(
            "round trip {name}: authenticated {:.0} µs, public {:.0} µs, authentication {:.0} µs",
            micros(s),
            micros(h),
            micros(s.saturating_sub(h))
        );
    }
}
