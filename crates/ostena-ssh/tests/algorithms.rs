//! The algorithms really offered on the wire (ADR-0010), as an audit tool
//! would list them: the KEXINIT of the agent listener (the bastion SSH
//! access) and of the driver to the targets are read off a socket and every
//! name must be in the frozen ANSSI list. No outside tool: the offer is
//! parsed by the pre-check parser, offline, in the `ssh-interop` job and
//! with the other tests.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside #[test] functions"
)]

mod common;

use std::time::Duration;

use ostena_ssh::algorithms::{
    CIPHER, HOST_KEY, HOST_KEY_CERTIFICATE, KEX, STRICT_KEX_CLIENT, STRICT_KEX_SERVER,
};
use ostena_ssh::precheck::{KexInit, Role, identification, parse_kexinit};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Extension markers allowed besides the algorithms: strict KEX (mandatory)
/// and the extension negotiation (RFC 8308), which select no algorithm.
const MARKERS: [&str; 4] = [
    STRICT_KEX_CLIENT,
    STRICT_KEX_SERVER,
    "ext-info-c",
    "ext-info-s",
];

/// Reads the identification line and the first binary packet sent by the
/// peer on `tcp`; returns the KEXINIT payload.
async fn read_kexinit(tcp: &mut TcpStream, role: Role) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Ok(Some(start)) = identification(&buf, role) {
            let rest = &buf[start..];
            if rest.len() >= 4 {
                let len = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
                if rest.len() >= 4 + len {
                    let padding = usize::from(rest[4]);
                    return rest[5..4 + len - padding].to_vec();
                }
            }
        }
        let n = tokio::time::timeout(Duration::from_secs(10), tcp.read(&mut chunk))
            .await
            .expect("no KEXINIT in 10 s")
            .unwrap();
        assert_ne!(n, 0, "closed before the KEXINIT");
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Every name of `offer` is in the frozen list; MACs empty (AEAD only).
fn assert_frozen(offer: &KexInit<'_>, strict: &str) {
    assert!(offer.kex.contains(&KEX), "{:?}", offer.kex);
    assert!(offer.kex.contains(&strict), "{:?}", offer.kex);
    for name in &offer.kex {
        assert!(
            *name == KEX || MARKERS.contains(name),
            "échange de clés hors liste : {name}"
        );
    }
    for name in &offer.host_key {
        assert!(
            [HOST_KEY, HOST_KEY_CERTIFICATE].contains(name),
            "clé hôte hors liste : {name}"
        );
    }
    assert_eq!(offer.cipher_c2s, [CIPHER]);
    assert_eq!(offer.cipher_s2c, [CIPHER]);
    assert_eq!(offer.mac_c2s, Vec::<&str>::new());
    assert_eq!(offer.mac_s2c, Vec::<&str>::new());
    assert_eq!(offer.compression_c2s, ["none"]);
    assert_eq!(offer.compression_s2c, ["none"]);
    assert!(!offer.first_kex_follows);
}

#[test]
fn the_agent_listener_offers_only_the_frozen_algorithms() {
    let runtime = common::runtime();
    runtime.block_on(async {
        let host = ostena_ssh::keys::generate("host").unwrap();
        let agent_key = ostena_ssh::keys::generate("agent").unwrap();
        // The agent server as in production: host certificate, user
        // authority, behind the pre-check.
        let agent = common::agent(
            ostena_ssh::keys::load(&host.private).unwrap(),
            ostena_ssh::keys::load(&agent_key.private).unwrap(),
            ostena_ssh::server::ServerSettings::default(),
        )
        .await;
        let mut tcp = TcpStream::connect(agent.addr).await.unwrap();
        // A valid client offer, so that the pre-check lets the exchange go.
        tcp.write_all(&common::raw_offer(&format!("{KEX},{STRICT_KEX_CLIENT}")))
            .await
            .unwrap();
        let payload = read_kexinit(&mut tcp, Role::Server).await;
        let offer = parse_kexinit(&payload).unwrap();
        assert_frozen(&offer, STRICT_KEX_SERVER);
        // The host certificate is offered, the bare key too.
        assert!(offer.host_key.contains(&HOST_KEY_CERTIFICATE));
    });
}

#[test]
fn the_driver_offers_only_the_frozen_algorithms() {
    let runtime = common::runtime();
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let target = common::loopback(port).await;
        let host = ostena_crypto::p256::SigningKey::generate().unwrap().0;
        let agent_key = ostena_ssh::keys::generate("agent").unwrap();
        let dial = tokio::spawn(async move {
            ostena_ssh::driver::connect(
                &target,
                &host.verifying_key(),
                "root",
                std::sync::Arc::new(ostena_ssh::keys::load(&agent_key.private).unwrap()),
                Duration::from_secs(5),
                "kexinit",
            )
            .await
        });
        let (mut tcp, _) = listener.accept().await.unwrap();
        // A valid server offer, so that the pre-check lets the exchange go.
        tcp.write_all(&common::raw_offer(&format!("{KEX},{STRICT_KEX_SERVER}")))
            .await
            .unwrap();
        let payload = read_kexinit(&mut tcp, Role::Client).await;
        let offer = parse_kexinit(&payload).unwrap();
        assert_frozen(&offer, STRICT_KEX_CLIENT);
        drop(tcp);
        assert!(dial.await.unwrap().is_err());
    });
}
