//! A minimal SSH server with the frozen list and the pre-check, for the
//! footprint measures of `tests/ssh/footprint.sh`: it accepts one client key,
//! answers `ok` to the command `ok` and keeps any other session open. It
//! prints `listening <address>` then serves until killed. Not part of
//! `ostena`.
//!
//! `footprint_server <host key> <authorized public key line file>`

#![allow(
    clippy::expect_used,
    clippy::print_stdout,
    clippy::unused_async_trait_impl,
    reason = "measurement helper: prints its address, fixed inputs; the SSH handler methods are async by trait"
)]

use std::sync::Arc;

use ostena_ssh::config;
use ostena_ssh::precheck::Role;
use ostena_ssh::precheck::stream::{DEFAULT_TIMEOUT, Prechecked};
use russh::keys::PublicKey;
use russh::server::{Auth, ChannelOpenHandle, Msg, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId};

#[derive(Clone)]
struct Server {
    allowed: Arc<PublicKey>,
}

impl russh::server::Handler for Server {
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
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        if data == b"ok" {
            session.data(channel, b"ok\n".to_vec())?;
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            session.close(channel)?;
        }
        Ok(())
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let host_key = args
        .next()
        .expect("usage: footprint_server <host key> <public key file>");
    let allowed = args
        .next()
        .expect("usage: footprint_server <host key> <public key file>");
    let host_key = russh::keys::load_secret_key(host_key, None).expect("host key");
    let line = std::fs::read_to_string(allowed).expect("public key file");
    let allowed = Arc::new(PublicKey::from_openssh(line.trim()).expect("public key"));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        println!("listening {}", listener.local_addr().expect("address"));
        let config = config::server(vec![host_key]);
        let server = Server { allowed };
        while let Ok((tcp, peer)) = listener.accept().await {
            let stream = Prechecked::new(tcp, Role::Server, peer.to_string(), DEFAULT_TIMEOUT);
            let config = config.clone();
            let server = server.clone();
            tokio::spawn(async move {
                if let Ok(session) = russh::server::run_stream(config, stream, server).await {
                    let _ = session.await;
                }
            });
        }
    });
}
