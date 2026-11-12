//! A test core in its own process, for `cargo xtask footprint`: writes an
//! enrolled agent identity and the root into the directory given as
//! argument, prints `core <address>`, and serves until its standard input is
//! closed. Built only with the `testing` feature, never part of `ostena`.

#![allow(
    clippy::expect_used,
    clippy::print_stdout,
    reason = "test helper binary: prints its address, fixed inputs"
)]

use std::io::Read;
use std::path::PathBuf;

use ostena_crypto::pki::pem_certificate;
use ostena_tunnel::testing::{Behaviour, TestCore, valid};
use ostena_tunnel::{Limits, Uuid};

fn main() {
    let dir = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("usage: test_core <dir> <group>"),
    );
    let group = Uuid::parse(
        &std::env::args()
            .nth(2)
            .expect("usage: test_core <dir> <group>"),
    )
    .expect("group");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let core = TestCore::start(Limits::default(), Behaviour::default()).expect("test core");
        let (cert, key) = core.agent_files(group, valid()).expect("agent files");
        std::fs::write(dir.join("agent.crt"), cert).expect("write");
        // SECRET-EXPOSURE: test helper, the key file `agent enroll` would write.
        #[expect(clippy::disallowed_methods)]
        std::fs::write(dir.join("agent.key"), key.expose_secret()).expect("write");
        std::fs::write(
            dir.join("root.pem"),
            pem_certificate(core.trust_anchor().certificate()),
        )
        .expect("write");
        println!("core {}", core.addr());
        // Serve until the caller closes our standard input.
        let _ = tokio::task::spawn_blocking(|| std::io::stdin().read(&mut [0u8; 1])).await;
        drop(core);
    });
}
