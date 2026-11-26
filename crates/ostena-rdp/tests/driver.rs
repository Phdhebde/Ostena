//! The RDP driver through the `Driver` trait of the session manager,
//! against the test target.

#![allow(clippy::unwrap_used, reason = "test helpers outside #[test] functions")]

mod support;

use std::sync::Arc;
use std::time::Duration;

use ostena_common::secret::SecretString;
use ostena_crypto::hmac::HmacKey;
use ostena_rdp::RdpError;
use ostena_rdp::driver::{
    RdpDriver, RdpMode, RdpPolicy, RdpSessionParams, SecretSource, TargetParams, Validation,
};
use ostena_rdp::profile::to_hex;
use ostena_session::{Driver, DriverConnection};
use support::{Options, PASSWORD, Script, Target, USER};

struct Secrets;

impl SecretSource for Secrets {
    fn password(&self, account: &str) -> Result<SecretString, RdpError> {
        if account == USER {
            Ok(SecretString::from(PASSWORD.to_owned()))
        } else {
            Err(RdpError::Secret("compte inconnu".into()))
        }
    }
}

async fn loopback(port: u16) -> ostena_scope::PinnedTarget {
    use ostena_common::config::Mode;
    use ostena_common::config::scope::{AllowRuleSpec, FloorExceptionSpec, PolicySpec};
    let spec = PolicySpec {
        gateway_group: "rdp-tests".into(),
        allow: vec![AllowRuleSpec {
            label: None,
            networks: vec!["127.0.0.0/8".into()],
            ports: vec![port.to_string()],
        }],
        floor_exceptions: vec![FloorExceptionSpec {
            network: "127.0.0.0/8".into(),
            reason: "tests: cible sur la boucle locale".into(),
        }],
        ..PolicySpec::default()
    };
    let policy = ostena_scope::CompiledPolicy::compile(&spec, Mode::Development).unwrap();
    let scope = ostena_scope::Scope::new(
        Arc::new(policy),
        ostena_scope::SharedLocalAddresses::new(ostena_scope::LocalAddresses::from_addrs([])),
        ostena_scope::SystemResolver::new(Duration::from_secs(5), 4),
    );
    scope.pin("127.0.0.1", port).await.unwrap()
}

fn driver(production: bool, ntlm_fallback: bool) -> RdpDriver {
    RdpDriver::new(
        Arc::new(RdpPolicy {
            production,
            validation: Validation::Pinned,
            password_delegation: false,
            ntlm_fallback,
            realms: Vec::new(),
            identity_key: HmacKey::new(&HmacKey::generate().unwrap()).unwrap(),
            workstation: "OST-AGENT".into(),
        }),
        Arc::new(Secrets),
    )
}

fn params(target: &Target, account: &str) -> TargetParams {
    TargetParams {
        session: RdpSessionParams {
            account: account.into(),
            target_name: Some("target.example.test".into()),
            certificate_sha256: Some(to_hex(&target.fingerprint())),
            mode: RdpMode::RestrictedAdmin,
            width: 1280,
            height: 720,
            profile: None,
            license: None,
        },
        label: format!("{account}@target"),
    }
}

/// Production: Restricted Admin with NTLM and a pinned certificate, what
/// the Windows CI job plays against a real target.
#[tokio::test]
async fn production_restricted_admin_with_ntlm_fallback() {
    let target = Target::start(Options {
        restricted_admin: true,
        script: Script::WaitClient,
        ..Options::default()
    });
    let pinned = loopback(target.addr.port()).await;
    let connection = driver(true, true)
        .connect(&pinned, params(&target, USER), Duration::from_secs(20))
        .await
        .unwrap();
    assert!(connection.report().ntlm_used);
    assert!(!connection.is_closed());
    connection.close().await;
    assert!(connection.is_closed());
    assert!(target.join().accepted);
}

#[tokio::test]
async fn refusals_are_typed_and_sent_nothing() {
    let target = Target::start(Options::default());
    let pinned = loopback(target.addr.port()).await;
    // No NTLM fallback and no KDC for the account: refused before TCP.
    let error = driver(true, false)
        .connect(&pinned, params(&target, USER), Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(matches!(error, RdpError::NtlmRefused(_)), "{error}");
    // Secret missing on the agent.
    let error = driver(true, true)
        .connect(&pinned, params(&target, "other"), Duration::from_secs(5))
        .await
        .unwrap_err();
    assert_eq!(error.code(), "RDP-E016");
    drop(target);
}
