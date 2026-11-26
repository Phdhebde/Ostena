//! The driver against a real Windows target: RDP enabled on the loopback
//! of the Windows CI runner by `tests/rdp/windows-target.ps1` (NLA, Restricted
//! Admin allowed, one local administrator per mode with a random password:
//! the target reconnects a connection to the disconnected session of the
//! same account, so each test opens its own session).
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

use ostena_common::secret::SecretString;
use ostena_crypto::hmac::HmacKey;
use ostena_rdp::RdpError;
use ostena_rdp::connect::ConnectReport;
use ostena_rdp::driver::{
    RdpDriver, RdpMode, RdpPolicy, RdpSessionParams, SecretSource, TargetParams, Validation,
};
use ostena_session::{Driver, DriverConnection};
use support::loopback;

/// Session set up in less than 5 s (CLAUDE.md).
const SETUP_BUDGET: Duration = Duration::from_secs(5);

#[derive(Clone)]
struct Account {
    user: String,
    password: String,
}

#[derive(Clone)]
struct Lab {
    port: u16,
    name: String,
    /// The account of the delegation tests.
    delegation: Account,
    /// The account of the Restricted Admin tests.
    restricted_admin: Account,
    sha256: String,
}

impl Lab {
    fn account(&self, mode: RdpMode) -> &Account {
        if mode == RdpMode::Delegation {
            &self.delegation
        } else {
            &self.restricted_admin
        }
    }
}

fn account(prefix: &str) -> Option<Account> {
    Some(Account {
        user: var(&format!("{prefix}_USER"))?,
        password: var(&format!("{prefix}_PASSWORD"))?,
    })
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn lab() -> Option<Lab> {
    let found = (|| {
        Some(Lab {
            port: var("OSTENA_RDP_TARGET_PORT").map_or(Some(3389), |p| p.parse().ok())?,
            name: var("OSTENA_RDP_TARGET_NAME")?,
            delegation: account("OSTENA_RDP_TARGET_DELEGATION")?,
            restricted_admin: account("OSTENA_RDP_TARGET_RA")?,
            sha256: var("OSTENA_RDP_TARGET_SHA256")?.to_ascii_lowercase(),
        })
    })();
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
        [&self.0.delegation, &self.0.restricted_admin]
            .into_iter()
            .find(|a| a.user == account)
            .map(|a| SecretString::from(a.password.clone()))
            .ok_or_else(|| RdpError::Secret("compte inconnu".into()))
    }
}

fn driver(lab: &Lab, production: bool, password_delegation: bool) -> RdpDriver {
    RdpDriver::new(
        Arc::new(RdpPolicy {
            production,
            validation: Validation::Pinned,
            password_delegation,
            ntlm_fallback: true,
            realms: Vec::new(),
            identity_key: HmacKey::new(&HmacKey::generate().unwrap()).unwrap(),
            workstation: "OST-AGENT".into(),
        }),
        Arc::new(Secrets(lab.clone())),
    )
}

fn params(lab: &Lab, mode: RdpMode, sha256: &str) -> TargetParams {
    TargetParams {
        session: RdpSessionParams {
            account: lab.account(mode).user.clone(),
            target_name: Some(lab.name.clone()),
            certificate_sha256: Some(sha256.to_owned()),
            mode,
            width: 1280,
            height: 720,
            profile: None,
            license: None,
        },
        label: format!("{}@windows", lab.account(mode).user),
    }
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

async fn connect_and_hold(lab: &Lab, production: bool, mode: RdpMode, title: &str) {
    let pinned = loopback(lab.port).await;
    let started = Instant::now();
    let connection = driver(lab, production, mode == RdpMode::Delegation)
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
    assert!(total < SETUP_BUDGET, "session établie en {total:?}");
    // The session stays up (no early end from the target).
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(!connection.is_closed(), "{:?}", connection.ended().await);
    connection.close().await;
    assert!(connection.is_closed());
}

/// Production: Restricted Admin with NTLM, no password delegated.
#[tokio::test]
async fn production_restricted_admin_with_ntlm() {
    let Some(lab) = lab() else { return };
    connect_and_hold(
        &lab,
        true,
        RdpMode::RestrictedAdmin,
        "Production : Restricted Admin + NTLM",
    )
    .await;
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
    let pinned = loopback(lab.port).await;
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
    let pinned = loopback(lab.port).await;
    let wrong = "00".repeat(32);
    let error = driver(&lab, true, false)
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
