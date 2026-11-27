//! The driver against a real Windows target: RDP enabled on the loopback
//! of the Windows CI runner by `tests/rdp/windows-target.ps1` (NLA, Restricted
//! Admin allowed, SMB signing required, one local administrator with a
//! random password, used by every mode: the agent logs its sessions off,
//! ADR-0026).
//!
//! The target is known by a DNS name the script maps to 127.0.0.1 (hosts
//! file): it is pinned by that name through the scope control, and the
//! management channel of the sessions goes through the same check as in
//! production. The runner belongs to no domain: Kerberos is impossible
//! there, so the production mode is refused on the channel (`RDP-E022`)
//! and the sessions are opened in development mode, NTLM admitted.
//!
//! Skipped without the `OSTENA_RDP_TARGET_*` variables; mandatory with
//! `OSTENA_REQUIRE_RDP_TARGET`. The measured phases are printed, and
//! appended as a table to the file named by `OSTENA_RDP_TARGET_SUMMARY`
//! (the summary of the CI job).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "test helpers outside #[test] functions; the measures are printed"
)]

mod support;

use std::fmt::Write as _;
use std::io::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ostena_common::config::DisconnectedSessions;
use ostena_common::secret::SecretString;
use ostena_crypto::hmac::HmacKey;
use ostena_rdp::RdpError;
use ostena_rdp::connect::ConnectReport;
use ostena_rdp::driver::{
    RdpDriver, RdpMode, RdpPolicy, RdpSessionParams, SecretSource, TargetParams, Validation,
};
use ostena_rdp::target_sessions::{self, SessionState, TargetSession, ViewRequest, belongs_to};
use ostena_session::{Driver, DriverConnection};
use support::scope;

/// Session set up in less than 5 s (CLAUDE.md).
const SETUP_BUDGET: Duration = Duration::from_secs(5);

#[derive(Clone)]
struct Lab {
    port: u16,
    name: String,
    /// The one account of every test, whatever the mode.
    user: String,
    password: String,
    sha256: String,
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn lab() -> Option<Lab> {
    let found = (|| {
        Some(Lab {
            port: var("OSTENA_RDP_TARGET_PORT").map_or(Some(3389), |p| p.parse().ok())?,
            name: var("OSTENA_RDP_TARGET_NAME")?,
            user: var("OSTENA_RDP_TARGET_USER")?,
            password: var("OSTENA_RDP_TARGET_PASSWORD")?,
            sha256: var("OSTENA_RDP_TARGET_SHA256")?.to_ascii_lowercase(),
        })
    })();
    if found.is_some() {
        // The events of the driver (logoffs, end of the connection), as
        // JSON lines among the output of the job; once per process.
        let _ = ostena_common::logging::init(&ostena_common::config::LoggingConfig {
            level: ostena_common::config::LogLevel::Debug,
            ..Default::default()
        });
    }
    if found.is_none() {
        assert!(
            var("OSTENA_REQUIRE_RDP_TARGET").is_none(),
            "OSTENA_REQUIRE_RDP_TARGET: variables OSTENA_RDP_TARGET_* absentes"
        );
        eprintln!("cible Windows absente : test sauté");
    }
    found
}

struct Secrets(Lab);

impl SecretSource for Secrets {
    fn password(&self, account: &str) -> Result<SecretString, RdpError> {
        if account == self.0.user {
            Ok(SecretString::from(self.0.password.clone()))
        } else {
            Err(RdpError::Secret("compte inconnu".into()))
        }
    }
}

fn driver_with(
    lab: &Lab,
    production: bool,
    password_delegation: bool,
    sessions: DisconnectedSessions,
) -> RdpDriver {
    RdpDriver::new(
        Arc::new(RdpPolicy {
            production,
            validation: Validation::Pinned,
            password_delegation,
            ntlm_fallback: true,
            realms: Vec::new(),
            identity_key: HmacKey::new(&HmacKey::generate().unwrap()).unwrap(),
            workstation: "OST-AGENT".into(),
            disconnected_sessions: sessions,
        }),
        Arc::new(Secrets(lab.clone())),
        Arc::new(scope(&[lab.port])),
    )
}

/// The target pinned by its name, through the scope control.
async fn pinned(lab: &Lab) -> ostena_scope::PinnedTarget {
    scope(&[lab.port])
        .pin(&lab.name, lab.port)
        .await
        .unwrap_or_else(|e| panic!("{} : {e}", e.code()))
}

fn driver(lab: &Lab, production: bool, password_delegation: bool) -> RdpDriver {
    driver_with(
        lab,
        production,
        password_delegation,
        DisconnectedSessions::Logoff,
    )
}

fn params(lab: &Lab, mode: RdpMode, sha256: &str) -> TargetParams {
    TargetParams {
        session: RdpSessionParams {
            account: lab.user.clone(),
            target_name: Some(lab.name.clone()),
            certificate_sha256: Some(sha256.to_owned()),
            mode,
            width: 1280,
            height: 720,
            profile: None,
            license: None,
        },
        label: format!("{}@windows", lab.user),
    }
}

/// The sessions of the account on the target, seen by the WTS API as the
/// agent sees them (name of the target, credentials of the account).
async fn account_sessions(lab: &Lab) -> Vec<TargetSession> {
    let request = ViewRequest {
        address: std::net::IpAddr::from([127, 0, 0, 1]),
        server: lab.name.clone(),
        kerberos_required: false,
        account: lab.user.clone(),
        password: SecretString::from(lab.password.clone()),
    };
    target_sessions::run(
        target_sessions::platform_control(),
        request,
        |view, account| {
            Ok(view
                .sessions()
                .map_err(RdpError::SessionCleanup)?
                .into_iter()
                .filter(|s| belongs_to(s, account))
                .collect())
        },
    )
    .await
    .map_or_else(|e| panic!("{} : {e}", e.code()), |(sessions, _)| sessions)
}

/// Waits until the sessions of the account satisfy `done`, for 10 s at most.
async fn wait_sessions(
    lab: &Lab,
    what: &str,
    done: impl Fn(&[TargetSession]) -> bool,
) -> Vec<TargetSession> {
    let mut sessions = Vec::new();
    for _ in 0..50 {
        sessions = account_sessions(lab).await;
        if done(&sessions) {
            return sessions;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("{what} : sessions du compte {sessions:?}");
}

/// Prints the phases and appends them to the summary of the job.
fn summary(title: &str, report: &ConnectReport, total: Duration) {
    let mut text = format!("### {title}\n\n| phase | ms | allers-retours |\n|---|---:|---:|\n");
    for p in &report.phases {
        let _ = writeln!(text, "| {} | {} | {} |", p.phase, p.millis, p.round_trips);
    }
    let _ = write!(
        text,
        "| **total (connect du driver)** | **{}** | |\n\nNTLM : {}, échanges KDC : {}, \
         licence : {:?}, capacités retirées : {:#x}\n\n",
        total.as_millis(),
        report.ntlm_used,
        report.kdc_exchanges,
        report.license,
        report.early_capabilities_removed,
    );
    println!("{text}");
    if let Some(path) = var("OSTENA_RDP_TARGET_SUMMARY")
        && let Ok(mut file) = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
    {
        let _ = file.write_all(text.as_bytes());
    }
}

/// Connects, checks the budget and that the session holds 3 s; returns
/// the connection, still open, and the sessions of the account meanwhile.
async fn connect_and_hold_with(
    lab: &Lab,
    driver: RdpDriver,
    mode: RdpMode,
    title: &str,
) -> (ostena_rdp::driver::RdpConnection, Vec<TargetSession>) {
    let pinned = pinned(lab).await;
    let started = Instant::now();
    let connection = driver
        .connect(
            &pinned,
            params(lab, mode, &lab.sha256),
            Duration::from_secs(30),
        )
        .await
        .unwrap_or_else(|e| panic!("{} : {e}", e.code()));
    let total = started.elapsed();
    summary(title, connection.report(), total);
    assert!(connection.report().ntlm_used);
    // The logoff of sessions left on the target is not the agent's
    // establishment: it is measured apart (phase `sessions`).
    let cleanup = connection
        .report()
        .phases
        .iter()
        .find(|p| p.phase == "sessions")
        .map_or(Duration::ZERO, |p| Duration::from_millis(p.millis));
    assert!(
        total.saturating_sub(cleanup) < SETUP_BUDGET,
        "session établie en {total:?}"
    );
    // The session stays up (no early end from the target).
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(!connection.is_closed(), "{:?}", connection.ended().await);
    let during = wait_sessions(lab, "session ouverte", |s| {
        s.iter().any(|t| t.state.is_live())
    })
    .await;
    (connection, during)
}

/// Connects, holds, closes: the session of the account is logged off, not
/// left disconnected (ADR-0026).
async fn connect_and_hold(lab: &Lab, production: bool, mode: RdpMode, title: &str) {
    let (connection, during) = connect_and_hold_with(
        lab,
        driver(lab, production, mode == RdpMode::Delegation),
        mode,
        title,
    )
    .await;
    assert_eq!(during.len(), 1, "{during:?}");
    connection.close().await;
    assert!(connection.is_closed());
    wait_sessions(lab, "session fermée à la fin", <[TargetSession]>::is_empty).await;
}

/// Development: Restricted Admin with NTLM, no password delegated.
#[tokio::test]
async fn development_restricted_admin_with_ntlm() {
    let Some(lab) = lab() else { return };
    connect_and_hold(
        &lab,
        false,
        RdpMode::RestrictedAdmin,
        "Développement : Restricted Admin + NTLM",
    )
    .await;
}

/// ADR-0026 against the real target: the runner belongs to no domain, no
/// Kerberos ticket can be had for `cifs/<name>`, and production refuses
/// NTLM on the management channel, before any RDP connection.
#[tokio::test]
async fn production_refuses_ntlm_on_the_session_channel() {
    let Some(lab) = lab() else { return };
    let pinned = pinned(&lab).await;
    let error = driver(&lab, true, false)
        .connect(
            &pinned,
            params(&lab, RdpMode::RestrictedAdmin, &lab.sha256),
            Duration::from_secs(30),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), "RDP-E022", "{error}");
    assert!(error.to_string().contains("AGT-E014"), "{error}");
    assert_eq!(account_sessions(&lab).await, Vec::new());
}

/// ADR-0026 against the real target: the name of the channel must resolve,
/// through the scope control, to the pinned address. A name mapped to
/// another address, and a name that does not resolve, are refused.
#[tokio::test]
async fn the_session_channel_needs_the_name_of_the_pinned_address() {
    let Some(lab) = lab() else { return };
    let pinned = pinned(&lab).await;
    for name in ["other.ostena.test", "absent.ostena.test"] {
        let mut p = params(&lab, RdpMode::RestrictedAdmin, &lab.sha256);
        p.session.target_name = Some(name.into());
        let error = driver(&lab, false, false)
            .connect(&pinned, p, Duration::from_secs(30))
            .await
            .unwrap_err();
        assert_eq!(error.code(), "RDP-E021", "{name} : {error}");
    }
    assert_eq!(account_sessions(&lab).await, Vec::new());
}

/// ADR-0026 against the real target: the SMB signing probe reads that the
/// target requires it (set by the script).
#[tokio::test]
async fn the_target_requires_smb_signing() {
    let Some(_lab) = lab() else { return };
    let required = target_sessions::smb_signing(
        target_sessions::platform_control(),
        std::net::IpAddr::from([127, 0, 0, 1]),
    )
    .await
    .unwrap_or_else(|e| panic!("{} : {e}", e.code()));
    assert!(required);
}

/// Development: the password delegated with NTLM (refused in production).
#[tokio::test]
async fn development_password_delegation() {
    let Some(lab) = lab() else { return };
    connect_and_hold(
        &lab,
        false,
        RdpMode::Delegation,
        "Développement : délégation du mot de passe (NTLM)",
    )
    .await;
}

/// REG-SEC-02 against the real target: a delegated password never goes
/// with NTLM in production, refused before any connection.
#[tokio::test]
async fn production_refuses_delegation_with_ntlm() {
    let Some(lab) = lab() else { return };
    let pinned = pinned(&lab).await;
    let error = driver(&lab, true, true)
        .connect(
            &pinned,
            params(&lab, RdpMode::Delegation, &lab.sha256),
            Duration::from_secs(30),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, RdpError::NtlmRefused(_)), "{error}");
}

/// REG-SEC-01 against the real target: another fingerprint ends the
/// connection at TLS, before CredSSP.
#[tokio::test]
async fn wrong_fingerprint_is_refused_at_tls() {
    let Some(lab) = lab() else { return };
    let pinned = pinned(&lab).await;
    let wrong = "00".repeat(32);
    let error = driver(&lab, false, false)
        .connect(
            &pinned,
            params(&lab, RdpMode::RestrictedAdmin, &wrong),
            Duration::from_secs(30),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, RdpError::Certificate(_)),
        "{} : {error}",
        error.code()
    );
}

/// ADR-0026, the reported defect: a session with the delegated password,
/// then a Restricted Admin session on the SAME account. The first one is
/// logged off at its end, the second one is a new session: it never sees
/// the delegated password nor the windows of the first.
#[tokio::test]
async fn same_account_delegation_then_restricted_admin_gets_a_new_session() {
    let Some(lab) = lab() else { return };
    let (first, during) = connect_and_hold_with(
        &lab,
        driver(&lab, false, true),
        RdpMode::Delegation,
        "Même compte (1/2) : délégation",
    )
    .await;
    assert_eq!(during.len(), 1, "{during:?}");
    let delegated = during[0].id;
    first.close().await;
    wait_sessions(&lab, "session déléguée fermée", <[TargetSession]>::is_empty).await;

    let (second, during) = connect_and_hold_with(
        &lab,
        driver(&lab, false, false),
        RdpMode::RestrictedAdmin,
        "Même compte (2/2) : Restricted Admin",
    )
    .await;
    // Nothing was left to close, and the only session of the account is a
    // live one: the delegated session no longer exists, so this one is new.
    assert_eq!(second.report().sessions_logged_off, Vec::<u32>::new());
    assert_eq!(during.len(), 1, "{during:?}");
    assert!(during[0].state.is_live());
    println!(
        "session déléguée {delegated} fermée ; session Restricted Admin {}",
        during[0].id
    );
    second.close().await;
    wait_sessions(
        &lab,
        "session Restricted Admin fermée",
        <[TargetSession]>::is_empty,
    )
    .await;
}

/// ADR-0026, before a session: a disconnected session of the account (left
/// by a development driver that keeps them, as the agent did before) is
/// logged off before the next connection, which gets a new session instead
/// of reattaching it.
#[tokio::test]
async fn disconnected_session_is_logged_off_before_the_next_connection() {
    let Some(lab) = lab() else { return };
    let (kept, _) = connect_and_hold_with(
        &lab,
        driver_with(&lab, false, true, DisconnectedSessions::Keep),
        RdpMode::Delegation,
        "Session laissée déconnectée (développement, keep)",
    )
    .await;
    kept.close().await;
    let left = wait_sessions(&lab, "session laissée déconnectée", |s| {
        s.len() == 1 && s[0].state == SessionState::Disconnected
    })
    .await;
    let disconnected = left[0].id;

    let (next, during) = connect_and_hold_with(
        &lab,
        driver(&lab, false, false),
        RdpMode::RestrictedAdmin,
        "Connexion suivante : session déconnectée fermée avant",
    )
    .await;
    assert_eq!(next.report().sessions_logged_off, vec![disconnected]);
    assert_eq!(during.len(), 1, "{during:?}");
    assert!(during[0].state.is_live());
    next.close().await;
    wait_sessions(&lab, "session fermée à la fin", <[TargetSession]>::is_empty).await;
}
