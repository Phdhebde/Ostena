//! The TCP multiplexer over an in-memory pipe: streams, flow control,
//! limits, stop and reset, close reasons, liveness, refusal of a peer that
//! breaks the rules (ADR-0008).

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::time::Duration;

use ostena_tunnel::mux::frame::{self, Frame};
use ostena_tunnel::mux::{Connection, Side, StreamError};
use ostena_tunnel::{Limits, TunnelError};
use proptest::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

fn lost(e: &std::io::Error) -> TunnelError {
    TunnelError::ConnectionLost(e.to_string())
}

fn small() -> Limits {
    Limits {
        max_sessions: 1,
        stream_window: 16 * 1024,
        connection_window: 64 * 1024,
        ..Limits::default()
    }
}

async fn pair(limits: Limits) -> (Connection, Connection) {
    let (a, b) = tokio::io::duplex(256 * 1024);
    let (agent, core) = tokio::join!(
        Connection::establish(a, Side::Agent, limits, lost),
        Connection::establish(b, Side::Core, limits, lost),
    );
    (agent.unwrap(), core.unwrap())
}

#[tokio::test]
async fn data_flows_both_ways_and_the_end_is_acknowledged() {
    let (agent, core) = pair(Limits::default()).await;
    let (mut send, mut recv) = agent.open().await.unwrap();
    send.write_all(b"hello").await.unwrap();
    let (mut csend, mut crecv) = core.accept().await.unwrap();
    let mut buf = [0u8; 5];
    crecv.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");
    csend.write_all(b"world").await.unwrap();
    recv.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"world");

    let stopped = send.stopped();
    send.finish().unwrap();
    assert_eq!(crecv.read(&mut buf).await.unwrap(), None);
    assert_eq!(stopped.await.unwrap(), None, "end acknowledged");
    assert_eq!(send.finish(), Err(StreamError::Closed));
}

#[tokio::test]
async fn a_reader_that_does_not_read_stops_its_writer() {
    let (agent, core) = pair(small()).await;
    let (mut send, _recv) = agent.open().await.unwrap();
    send.write_all(b"x").await.unwrap();
    let (_csend, mut crecv) = core.accept().await.unwrap();
    let mut one = [0u8; 1];
    crecv.read_exact(&mut one).await.unwrap();
    // The stream window is 16 KiB: more than that waits for the reader.
    let big = vec![7u8; 40 * 1024];
    let writer = tokio::spawn(async move {
        send.write_all(&big).await.unwrap();
        send
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!writer.is_finished(), "the writer waits for credit");
    let mut got = vec![0u8; 40 * 1024];
    crecv.read_exact(&mut got).await.unwrap();
    assert!(got.iter().all(|b| *b == 7));
    writer.await.unwrap();
}

#[tokio::test]
async fn the_stream_limit_waits_for_a_slot() {
    let (agent, core) = pair(small()).await;
    // One session: four streams and the control stream.
    let mut open = Vec::new();
    for _ in 0..5 {
        open.push(agent.open().await.unwrap());
    }
    let sixth = {
        let agent = agent.clone();
        tokio::spawn(async move { agent.open().await.map(|_| ()) })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!sixth.is_finished());
    // Close one stream on both sides: the core gives a slot back.
    let (mut send, recv) = open.remove(0);
    send.finish().unwrap();
    let (mut csend, mut crecv) = core.accept().await.unwrap();
    assert_eq!(crecv.read(&mut [0u8; 1]).await.unwrap(), None);
    csend.finish().unwrap();
    drop((csend, crecv));
    let mut recv = recv;
    assert_eq!(recv.read(&mut [0u8; 1]).await.unwrap(), None);
    drop((send, recv));
    tokio::time::timeout(Duration::from_secs(2), sixth)
        .await
        .expect("a slot is given back")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn stop_and_reset_carry_their_code() {
    let (agent, core) = pair(Limits::default()).await;
    let (mut send, mut recv) = agent.open().await.unwrap();
    send.write_all(b"a").await.unwrap();
    let (mut csend, mut crecv) = core.accept().await.unwrap();
    let stopped = send.stopped();
    crecv.stop(7).unwrap();
    assert_eq!(stopped.await.unwrap(), Some(7));
    assert_eq!(send.write_all(b"b").await, Err(StreamError::Stopped(7)));
    csend.reset(3).unwrap();
    assert_eq!(recv.read(&mut [0u8; 4]).await, Err(StreamError::Reset(3)));
}

#[tokio::test]
async fn the_close_reason_reaches_the_peer() {
    let (agent, core) = pair(Limits::default()).await;
    core.close(TunnelError::Revoked, 1);
    assert_eq!(agent.closed().await, TunnelError::Revoked);
    assert!(matches!(
        agent.open().await,
        Err(StreamError::ConnectionLost(_))
    ));
}

/// A raw peer that sends its settings, then `then`, and returns its end.
async fn raw_peer(limits: Limits, then: &[Frame<'_>]) -> (Connection, DuplexStream) {
    let (a, mut b) = tokio::io::duplex(64 * 1024);
    let mut out = Vec::new();
    frame::encode(
        &Frame::Settings {
            version: frame::VERSION,
            max_streams: 5,
            stream_window: 16 * 1024,
            connection_window: 64 * 1024,
        },
        &mut out,
    );
    for f in then {
        frame::encode(f, &mut out);
    }
    b.write_all(&out).await.unwrap();
    let core = Connection::establish(a, Side::Core, limits, lost)
        .await
        .unwrap();
    (core, b)
}

#[tokio::test]
async fn a_peer_breaking_the_rules_is_closed_with_tun_e010() {
    let (core, mut raw) = raw_peer(
        small(),
        &[Frame::Data {
            stream: 1,
            payload: b"never opened",
        }],
    )
    .await;
    let reason = core.closed().await;
    assert_eq!(reason.code(), "TUN-E010", "{reason}");
    // The peer receives the reason in a close frame, after our settings.
    let mut got = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), raw.read_to_end(&mut got)).await;
    let (_, used) = frame::decode(&got).unwrap().unwrap();
    match frame::decode(&got[used..]).unwrap().unwrap().0 {
        Frame::Close { code, reason } => {
            assert_eq!(code, 1);
            assert!(String::from_utf8_lossy(reason).starts_with("[TUN-E010]"));
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn garbage_instead_of_settings_is_refused() {
    let (a, mut b) = tokio::io::duplex(1024);
    b.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let e = Connection::establish(a, Side::Core, small(), lost)
        .await
        .unwrap_err();
    assert_eq!(e.code(), "TUN-E010", "{e}");
}

#[tokio::test(start_paused = true)]
async fn a_silent_peer_is_declared_lost() {
    let (core, _raw) = raw_peer(small(), &[]).await;
    let reason = tokio::time::timeout(Duration::from_secs(60), core.closed())
        .await
        .expect("idle timeout");
    assert_eq!(reason.code(), "TUN-E013", "{reason}");
}

#[tokio::test(start_paused = true)]
async fn pings_keep_an_idle_connection_alive() {
    let (agent, core) = pair(small()).await;
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert!(!agent.is_closed() && !core.is_closed());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// Whatever the interleaving and sizes of the writes on several streams,
    /// each stream arrives whole and in order (windows smaller than the
    /// data, so flow control is exercised).
    #[test]
    fn prop_streams_arrive_whole_and_in_order(
        writes in proptest::collection::vec((0usize..3, 1usize..40_000), 1..12)
    ) {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async move {
            let (agent, core) = pair(small()).await;
            let mut expected = vec![Vec::new(); 3];
            let mut sends = Vec::new();
            for _ in 0..3 {
                sends.push(agent.open().await.unwrap());
            }
            let reader = tokio::spawn(async move {
                let mut got = Vec::new();
                for _ in 0..3 {
                    let (_s, mut r) = core.accept().await.unwrap();
                    got.push(tokio::spawn(async move {
                        let mut all = Vec::new();
                        let mut buf = vec![0u8; 3000];
                        while let Some(n) = r.read(&mut buf).await.unwrap() {
                            all.extend_from_slice(&buf[..n]);
                        }
                        all
                    }));
                }
                let mut out = Vec::new();
                for g in got {
                    out.push(g.await.unwrap());
                }
                out
            });
            for (i, (stream, len)) in writes.iter().enumerate() {
                let byte = u8::try_from(i % 251).unwrap();
                let data = vec![byte; *len];
                sends[*stream].0.write_all(&data).await.unwrap();
                expected[*stream].extend_from_slice(&data);
            }
            for (send, _) in &mut sends {
                send.finish().unwrap();
            }
            let got = reader.await.unwrap();
            // Streams are accepted in the order they were opened.
            assert_eq!(got, expected);
        });
    }
}
