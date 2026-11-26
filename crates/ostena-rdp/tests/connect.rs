//! End-to-end tests of the connection sequence and the session loop
//! against the test target (`support`), and the named non-regression tests
//! of ADR-0019 that it covers.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers outside #[test] functions"
)]

mod support;

use std::time::Duration;

use ironrdp_connector::DesktopSize;
use ironrdp_pdu::rdp::autodetect::{AutoDetectResponse, BW_RESULTS_CONTINUOUS};
use ostena_common::secret::SecretString;
use ostena_crypto::tls::target::TargetTrust;
use ostena_crypto::tls::target::testing::{KeyKind, TargetCa, Usage};
use ostena_rdp::RdpError;
use ostena_rdp::connect::{ConnectParams, Established, establish};
use ostena_rdp::credssp::{Authentication, Kdcs, Mechanism};
use ostena_rdp::guard::allowed_early_capabilities;
use ostena_rdp::profile::{TargetProfile, to_hex};
use ostena_rdp::session::{SessionEnd, SessionLoop};
use support::{Misbehave, Options, PASSWORD, Script, Target, USER};
use tokio::sync::{mpsc, watch};

fn params(trust: TargetTrust, mechanism: Mechanism, restricted_admin: bool) -> ConnectParams {
    ConnectParams {
        server_name: "target.example.test".into(),
        trust,
        auth: Authentication {
            username: USER.into(),
            password: SecretString::from(PASSWORD.to_owned()),
            spn: "TERMSRV/target.example.test".into(),
            mechanism,
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
        label: "admin@target".into(),
    }
}

fn pinned(target: &Target) -> TargetTrust {
    TargetTrust::Pinned(target.fingerprint())
}

async fn connect(target: &Target, params: ConnectParams) -> Result<Established, RdpError> {
    tokio::time::timeout(Duration::from_secs(20), establish(target.addr, params))
        .await
        .expect("sequence within 20 s")
}

async fn run_session(established: Established) -> (SessionEnd, ostena_rdp::session::Counters) {
    let (_inputs, rx) = mpsc::channel(4);
    let (_stop, stop_rx) = watch::channel(false);
    let looped = SessionLoop::new(established.transport, established.result).run(rx, stop_rx, None);
    tokio::time::timeout(Duration::from_secs(20), looped)
        .await
        .expect("session ends within 20 s")
}

#[tokio::test]
async fn full_sequence_then_logoff() {
    let target = Target::start(Options::default());
    let established = match connect(&target, params(pinned(&target), Mechanism::Ntlm, false)).await
    {
        Ok(e) => e,
        Err(e) => panic!("{e} / target: {:?}", target.join().error),
    };
    let report = established.report.clone();
    assert!(report.ntlm_used);
    assert_eq!(report.profile.certificate, to_hex(&target.fingerprint()));
    assert!(report.profile.message_channel);
    assert_ne!(report.profile.rdp_version, 0);
    let phases: Vec<_> = report.phases.iter().map(|p| p.phase).collect();
    assert_eq!(
        phases,
        [
            "tcp",
            "x224",
            "tls",
            "credssp",
            "mcs",
            "licensing",
            "activation"
        ]
    );
    let (end, _) = run_session(established).await;
    assert_eq!(end, SessionEnd::Closed);
    let seen = target.join();
    assert!(seen.accepted, "{:?}", seen.error);
    assert_eq!(seen.client_name, "OST-0123456789");
}

/// REG-RDP-03: only the flags of the table are announced, whatever the
/// connector builds; NLA only, no cookie (the account never in clear).
#[tokio::test]
async fn reg_rdp_03_only_table_flags_and_nla_without_cookie() {
    let target = Target::start(Options::default());
    let established = connect(&target, params(pinned(&target), Mechanism::Ntlm, false))
        .await
        .unwrap();
    // The connector asked for 32 bpp: removed by the guard.
    assert_ne!(established.report.early_capabilities_removed, 0);
    drop(run_session(established).await);
    let seen = target.join();
    let flags = seen.early_capabilities.expect("Connect Initial seen");
    assert!(allowed_early_capabilities().contains(flags), "{flags:?}");
    assert_eq!(
        seen.requested_protocols, 0x0000_000a,
        "HYBRID | HYBRID_EX only"
    );
    assert!(
        !seen
            .connection_request
            .windows(USER.len())
            .any(|w| w == USER.as_bytes()),
        "no mstshash cookie"
    );
}

/// REG-SEC-01: a certificate other than the pinned one, or outside the
/// PKI, is refused before any credential.
#[tokio::test]
async fn reg_sec_01_certificate_refused_before_any_credential() {
    let target = Target::start(Options::default());
    let wrong = TargetTrust::Pinned([0x42; 32]);
    let error = connect(&target, params(wrong, Mechanism::Ntlm, false))
        .await
        .unwrap_err();
    assert!(matches!(error, RdpError::Certificate(_)), "{error}");
    let seen = target.join();
    assert!(!seen.credssp_done);
    assert_eq!(seen.credssp_bytes, 0, "nothing sent after TLS");

    let other_ca = TargetCa::new("Other CA").unwrap();
    let target = Target::start(Options::default());
    let pki = TargetTrust::Pki(vec![other_ca.anchor()]);
    let error = connect(&target, params(pki, Mechanism::Ntlm, false))
        .await
        .unwrap_err();
    assert!(matches!(error, RdpError::Certificate(_)), "{error}");
    assert_eq!(target.join().credssp_bytes, 0);
}

#[tokio::test]
async fn pki_target_is_accepted() {
    let ca = TargetCa::new("Customer CA").unwrap();
    let identity = ca
        .issue(
            KeyKind::Rsa2048,
            &["target.example.test"],
            Some(Usage::ServerAuth),
        )
        .unwrap();
    let target = Target::start_with(Options::default(), std::sync::Arc::new(identity));
    let pki = TargetTrust::Pki(vec![ca.anchor()]);
    let established = connect(&target, params(pki, Mechanism::Ntlm, false))
        .await
        .unwrap();
    drop(run_session(established).await);
    assert!(target.join().accepted);
}

/// REG-SEC-02: with Kerberos only (a delegated password), a target that
/// cannot do Kerberos is refused without any NTLM fallback.
#[tokio::test]
async fn reg_sec_02_kerberos_only_never_falls_back_to_ntlm() {
    let target = Target::start(Options::default());
    let kdcs = Kdcs {
        realm: "EXAMPLE.TEST".into(),
        servers: Vec::new(),
    };
    let error = connect(
        &target,
        params(pinned(&target), Mechanism::Kerberos(kdcs), false),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(error, RdpError::Kerberos(_) | RdpError::NtlmRefused(_)),
        "{error}"
    );
    let seen = target.join();
    assert!(!seen.credssp_done);
}

#[tokio::test]
async fn target_without_nla_is_refused() {
    let target = Target::start(Options {
        misbehave: Misbehave::NoNla,
        ..Options::default()
    });
    let error = connect(&target, params(pinned(&target), Mechanism::Ntlm, false))
        .await
        .unwrap_err();
    assert_eq!(error, RdpError::NoNla);
    drop(target.join());
}

#[tokio::test]
async fn restricted_admin_requires_the_announce() {
    let target = Target::start(Options::default());
    let error = connect(&target, params(pinned(&target), Mechanism::Ntlm, true))
        .await
        .unwrap_err();
    assert_eq!(error, RdpError::RestrictedAdminUnsupported);
    assert_eq!(target.join().credssp_bytes, 0, "cut before CredSSP");
}

#[tokio::test]
async fn restricted_admin_connects_without_delegating() {
    let target = Target::start(Options {
        restricted_admin: true,
        ..Options::default()
    });
    let established = connect(&target, params(pinned(&target), Mechanism::Ntlm, true))
        .await
        .unwrap();
    drop(run_session(established).await);
    let seen = target.join();
    assert!(seen.accepted, "{:?}", seen.error);
    // RESTRICTED_ADMIN_MODE_REQUIRED in the request.
    let request = seen.connection_request;
    assert_eq!(request[request.len() - 7] & 0x01, 0x01);
}

#[tokio::test]
async fn credssp_older_than_6_is_refused() {
    let target = Target::start(Options {
        misbehave: Misbehave::CredSspVersion(5),
        ..Options::default()
    });
    let error = connect(&target, params(pinned(&target), Mechanism::Ntlm, false))
        .await
        .unwrap_err();
    assert_eq!(error, RdpError::CredSspVersion(5));
    drop(target.join());
}

#[tokio::test]
async fn early_user_authorization_refusal() {
    let target = Target::start(Options {
        misbehave: Misbehave::AccessDenied,
        ..Options::default()
    });
    let error = connect(&target, params(pinned(&target), Mechanism::Ntlm, false))
        .await
        .unwrap_err();
    assert_eq!(error, RdpError::AccessDenied);
    drop(target.join());
}

/// REG-RDP-06 (errors): a licence error is translated, without retry.
#[tokio::test]
async fn reg_rdp_06_licence_error_is_translated() {
    let target = Target::start(Options {
        misbehave: Misbehave::LicenseError,
        ..Options::default()
    });
    let error = connect(&target, params(pinned(&target), Mechanism::Ntlm, false))
        .await
        .unwrap_err();
    assert!(matches!(error, RdpError::License(_)), "{error}");
    assert_eq!(error.code(), "RDP-E010");
    drop(target.join());
}

/// REG-RDP-04 (Auto-Detect): continuous requests served without
/// blocking; unknown ones ignored and counted, never fatal.
#[tokio::test]
async fn reg_rdp_04_continuous_autodetect_is_served() {
    let target = Target::start(Options {
        script: Script::AutoDetect,
        ..Options::default()
    });
    let established = connect(&target, params(pinned(&target), Mechanism::Ntlm, false))
        .await
        .unwrap();
    let (end, counters) = run_session(established).await;
    assert_eq!(end, SessionEnd::Closed);
    assert!(counters.autodetect_ignored >= 2, "{counters:?}");
    let seen = target.join();
    assert!(matches!(
        seen.autodetect_responses[0],
        AutoDetectResponse::RttResponse { sequence_number: 1 }
    ));
    assert!(matches!(
        seen.autodetect_responses[1],
        AutoDetectResponse::BandwidthMeasureResults {
            sequence_number: 3,
            response_type: BW_RESULTS_CONTINUOUS,
            ..
        }
    ));
    assert!(matches!(
        seen.autodetect_responses[2],
        AutoDetectResponse::RttResponse { sequence_number: 5 }
    ));
}

#[tokio::test]
async fn server_error_info_ends_the_session_with_its_code() {
    let target = Target::start(Options {
        script: Script::ServerError,
        ..Options::default()
    });
    let established = connect(&target, params(pinned(&target), Mechanism::Ntlm, false))
        .await
        .unwrap();
    let (end, _) = run_session(established).await;
    assert!(
        matches!(end, SessionEnd::Failed(RdpError::ServerError(_))),
        "{end:?}"
    );
    drop(target.join());
}

/// The error information that comes with the TLS close notification, in
/// the same read and without disconnection PDU, is still the reason of the
/// end (never a silent normal close).
#[tokio::test]
async fn server_error_info_with_close_notify_keeps_its_code() {
    let target = Target::start(Options {
        script: Script::ServerErrorThenClose,
        ..Options::default()
    });
    let established = connect(&target, params(pinned(&target), Mechanism::Ntlm, false))
        .await
        .unwrap();
    let (end, counters) = run_session(established).await;
    assert_eq!(
        end,
        SessionEnd::Failed(RdpError::ServerError(0x0006)),
        "{counters:?}"
    );
    assert_eq!(counters.error_info, Some(0x0006));
    drop(target.join());
}

#[tokio::test]
async fn stop_disconnects_cleanly() {
    let target = Target::start(Options {
        script: Script::WaitClient,
        ..Options::default()
    });
    let established = connect(&target, params(pinned(&target), Mechanism::Ntlm, false))
        .await
        .unwrap();
    let (_inputs, rx) = mpsc::channel(4);
    let (stop, stop_rx) = watch::channel(false);
    let looped = tokio::spawn(
        SessionLoop::new(established.transport, established.result).run(rx, stop_rx, None),
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    stop.send(true).unwrap();
    let (end, _) = tokio::time::timeout(Duration::from_secs(5), looped)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(end, SessionEnd::Stopped);
    assert!(target.join().accepted);
}

/// REG-PERF-01: the profile observed at the first connection is the one
/// the second observes; a difference is detected, never an error.
#[tokio::test]
async fn reg_perf_01_profile_is_remembered_and_changes_detected() {
    let target = Target::start(Options::default());
    let first = connect(&target, params(pinned(&target), Mechanism::Ntlm, false))
        .await
        .unwrap();
    let profile: TargetProfile = first.report.profile.clone();
    assert_eq!(first.report.profile_changed, Vec::<&str>::new());
    drop(run_session(first).await);
    drop(target.join());

    // Same certificate, same server: no change.
    let identity = std::sync::Arc::new(
        ostena_crypto::tls::target::testing::self_signed(KeyKind::Rsa2048, "target.example.test")
            .unwrap(),
    );
    let target = Target::start_with(Options::default(), identity.clone());
    let mut p = params(pinned(&target), Mechanism::Ntlm, false);
    let mut remembered = profile.clone();
    remembered.certificate = to_hex(&identity.fingerprint());
    p.profile = Some(remembered.clone());
    let second = connect(&target, p).await.unwrap();
    assert!(
        second.report.profile_changed.is_empty(),
        "{:?}",
        second.report.profile_changed
    );
    drop(run_session(second).await);
    drop(target.join());

    // An updated target (other version): logged and replaced, no failure.
    let target = Target::start_with(Options::default(), identity);
    let mut p = params(pinned(&target), Mechanism::Ntlm, false);
    remembered.rdp_version = 0x0008_0001;
    p.profile = Some(remembered);
    let third = connect(&target, p).await.unwrap();
    assert_eq!(third.report.profile_changed, ["rdp_version"]);
    drop(run_session(third).await);
    drop(target.join());
}
