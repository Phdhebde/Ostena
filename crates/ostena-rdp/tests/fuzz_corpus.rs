//! Replays the cargo-fuzz corpora (`fuzz/corpus/rdp_*`) on the stable
//! toolchain, so that every input the fuzzer kept is a regression test.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    reason = "test helpers outside #[test] functions; scenario list"
)]

mod support;

use std::path::PathBuf;

fn replay(target: &str, run: fn(&[u8])) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/corpus")
        .join(target);
    let mut count = 0;
    for entry in std::fs::read_dir(&dir).expect("corpus directory must exist") {
        let data = std::fs::read(entry.expect("entry").path()).expect("corpus file");
        run(&data);
        count += 1;
    }
    assert!(count > 0, "empty corpus {}", dir.display());
}

#[test]
fn replay_rdp_x224_corpus() {
    replay("rdp_x224", ostena_rdp::fuzz::x224);
}

#[test]
fn replay_rdp_mcs_gcc_corpus() {
    replay("rdp_mcs_gcc", ostena_rdp::fuzz::mcs_gcc);
}

#[test]
fn replay_rdp_tsrequest_corpus() {
    replay("rdp_tsrequest", ostena_rdp::fuzz::ts_request);
}

#[test]
fn replay_rdp_license_corpus() {
    replay("rdp_license", ostena_rdp::fuzz::license);
}

#[test]
fn replay_rdp_session_corpus() {
    replay("rdp_session", ostena_rdp::fuzz::session);
}

/// The session seeds go through the frame handling, not only the framing:
/// the logoff of the target ends the session as the loop would.
#[test]
fn session_seed_reaches_the_demultiplexer() {
    use ostena_rdp::session::{Demux, SessionEnd};

    let seed = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fuzz/corpus/rdp_session/seed-logoff-stream"),
    )
    .expect("seed");
    let mut demux = Demux::new(1003, Some(1003 + u16::from(seed[0])), 1002);
    let end = demux.feed(&seed[2..]).expect("no protocol error");
    assert_eq!(end, Some(SessionEnd::Closed));
    assert!(demux.counters().frames > 1);
}

/// Regenerates the seed inputs (identical files are then removed by hand) from what the test target sends, in clear,
/// over a few scenarios:
/// `cargo test -p ostena-rdp --test fuzz_corpus -- --ignored`.
#[tokio::test]
#[ignore = "writes files; run on demand"]
async fn write_seed_corpus() {
    use std::time::Duration;

    use ironrdp_connector::DesktopSize;
    use ironrdp_core::decode;
    use ironrdp_pdu::mcs::McsMessage;
    use ironrdp_pdu::x224::X224;
    use ostena_common::secret::SecretString;
    use ostena_crypto::tls::target::TargetTrust;
    use ostena_rdp::connect::{ConnectParams, establish};
    use ostena_rdp::credssp::{Authentication, Mechanism};
    use ostena_rdp::session::SessionLoop;
    use support::{Misbehave, Options, PASSWORD, Script, Target, USER};
    use tokio::sync::{mpsc, watch};

    let scenarios = [
        ("logoff", Options::default()),
        (
            "autodetect",
            Options {
                script: Script::AutoDetect,
                ..Options::default()
            },
        ),
        (
            "error-info",
            Options {
                script: Script::ServerError,
                ..Options::default()
            },
        ),
        (
            "licence-error",
            Options {
                misbehave: Misbehave::LicenseError,
                ..Options::default()
            },
        ),
        (
            "access-denied",
            Options {
                misbehave: Misbehave::AccessDenied,
                ..Options::default()
            },
        ),
        (
            "restricted-admin",
            Options {
                restricted_admin: true,
                ..Options::default()
            },
        ),
    ];
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus");
    let write = |target: &str, name: String, data: &[u8]| {
        std::fs::write(dir.join(target).join(format!("seed-{name}")), data).expect("write");
    };
    for (scenario, options) in scenarios {
        let restricted_admin = options.restricted_admin;
        let target = Target::start(options);
        let params = ConnectParams {
            server_name: "target.example.test".into(),
            trust: TargetTrust::Pinned(target.fingerprint()),
            auth: Authentication {
                username: USER.into(),
                password: SecretString::from(PASSWORD.to_owned()),
                spn: "TERMSRV/target.example.test".into(),
                mechanism: Mechanism::Ntlm,
                restricted_admin,
                workstation: "OST-AGENT".into(),
            },
            desktop: DesktopSize {
                width: 1280,
                height: 720,
            },
            client_name: "OST-0123456789".into(),
            hardware_id: [1, 2, 3, 4],
            profile: None,
            license: None,
            label: "seed".into(),
        };
        let established =
            tokio::time::timeout(Duration::from_secs(20), establish(target.addr, params))
                .await
                .expect("sequence within 20 s");
        if let Ok(established) = established {
            let (_inputs, rx) = mpsc::channel(4);
            let (_stop, stop_rx) = watch::channel(false);
            let looped =
                SessionLoop::new(established.transport, established.result).run(rx, stop_rx, None);
            drop(tokio::time::timeout(Duration::from_secs(20), looped).await);
        }
        let seen = target.join();
        let sent = seen.sent;
        let session_start = seen.session_start.unwrap_or(usize::MAX);
        let mut stream = Vec::new();
        let mut head = 1u8;
        for (i, pdu) in sent.iter().enumerate() {
            let name = format!("{scenario}-{i:02}");
            if i == 0 {
                write("rdp_x224", name, pdu);
            } else if pdu.first() != Some(&0x03) {
                // TSRequest (DER) or Early User Authorization Result.
                write("rdp_tsrequest", name, pdu);
            } else if let Ok(indication) = ironrdp_pdu::mcs::decode_send_data_indication(pdu) {
                let licence =
                    decode::<ironrdp_pdu::rdp::server_license::LicensePdu>(indication.user_data)
                        .is_ok();
                if licence {
                    write("rdp_license", name, pdu);
                } else if i >= session_start {
                    if indication.channel_id != 1003 {
                        head =
                            u8::try_from(indication.channel_id.saturating_sub(1003)).unwrap_or(1);
                    }
                    stream.extend_from_slice(pdu);
                } else {
                    // Activation (Demand Active, finalisation): one seed
                    // each, a reactivation for the loop.
                    let mut input = vec![1, 0];
                    input.extend_from_slice(pdu);
                    write("rdp_session", name, &input);
                }
            } else if decode::<X224<McsMessage<'_>>>(pdu).is_ok() {
                // Join confirms, ultimatum (also in the session corpus).
                write("rdp_mcs_gcc", name, pdu);
                if i >= session_start {
                    stream.extend_from_slice(pdu);
                }
            } else {
                // Connect Response with the server GCC blocks.
                write("rdp_mcs_gcc", name, pdu);
            }
        }
        if !stream.is_empty() {
            let mut input = vec![head, 0];
            input.extend_from_slice(&stream);
            write("rdp_session", format!("{scenario}-stream"), &input);
        }
    }
}
