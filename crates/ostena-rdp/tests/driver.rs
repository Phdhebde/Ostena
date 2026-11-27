//! The RDP driver through the `Driver` trait of the session manager,
//! against the test target.

#![allow(clippy::unwrap_used, reason = "test helpers outside #[test] functions")]

mod support;

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ostena_common::config::DisconnectedSessions;
use ostena_common::secret::SecretString;
use ostena_crypto::hmac::HmacKey;
use ostena_rdp::RdpError;
use ostena_rdp::driver::{
    RdpDriver, RdpMode, RdpPolicy, RdpSessionParams, SecretSource, TargetParams, Validation,
};
use ostena_rdp::profile::to_hex;
use ostena_rdp::target_sessions::{
    OpenError, Opened, SessionControl, SessionState, SessionView, TargetNames, TargetSession,
    Unsupported, ViewRequest,
};
use ostena_session::{Driver, DriverConnection};
use support::{LOGON_SESSION, Options, PASSWORD, Script, Target, USER, loopback};

/// The DNS name of the test target.
const NAME: &str = "target.example.test";

/// The sessions of a fake target, shared by the views.
struct Sessions {
    list: Vec<TargetSession>,
    logged_off: Vec<u32>,
    /// Server name, Kerberos required, password of each view.
    opened_with: Vec<(String, bool, String)>,
    /// Addresses asked for SMB signing.
    probed: Vec<SocketAddr>,
    /// A Kerberos ticket can be had for the target.
    kerberos: bool,
    /// The target requires SMB signing.
    signing: bool,
}

impl Default for Sessions {
    fn default() -> Self {
        Self {
            list: Vec::new(),
            logged_off: Vec::new(),
            opened_with: Vec::new(),
            probed: Vec::new(),
            kerberos: true,
            signing: true,
        }
    }
}

#[derive(Clone, Default)]
struct FakeControl(Arc<Mutex<Sessions>>);

impl FakeControl {
    fn with(list: Vec<TargetSession>) -> Self {
        Self(Arc::new(Mutex::new(Sessions {
            list,
            ..Sessions::default()
        })))
    }

    fn channel(kerberos: bool, signing: bool) -> Self {
        Self(Arc::new(Mutex::new(Sessions {
            kerberos,
            signing,
            ..Sessions::default()
        })))
    }

    fn logged_off(&self) -> Vec<u32> {
        self.0.lock().unwrap().logged_off.clone()
    }
}

struct FakeView(Arc<Mutex<Sessions>>);

impl SessionView for FakeView {
    fn sessions(&mut self) -> Result<Vec<TargetSession>, String> {
        Ok(self.0.lock().unwrap().list.clone())
    }

    fn logoff(&mut self, id: u32) -> Result<(), String> {
        let mut s = self.0.lock().unwrap();
        s.logged_off.push(id);
        s.list.retain(|t| t.id != id);
        Ok(())
    }
}

impl SessionControl for FakeControl {
    fn open(&self, request: &ViewRequest) -> Result<Opened, OpenError> {
        // SECRET-EXPOSURE: test checks the password given to the view.
        #[expect(clippy::disallowed_methods)]
        let password = request.password.expose_secret().to_owned();
        let mut state = self.0.lock().unwrap();
        state
            .opened_with
            .push((request.server.clone(), request.kerberos_required, password));
        if !state.kerberos && request.kerberos_required {
            return Err(OpenError::Kerberos(format!(
                "pas de KDC pour cifs/{}",
                request.server
            )));
        }
        Ok(Opened {
            view: Box::new(FakeView(self.0.clone())),
            kerberos: state.kerberos,
        })
    }

    fn smb_signing(&self, addr: SocketAddr) -> Result<bool, String> {
        let mut state = self.0.lock().unwrap();
        state.probed.push(addr);
        Ok(state.signing)
    }
}

/// The scope control of the tests: each name resolves to its addresses.
struct Names(Vec<(&'static str, Vec<IpAddr>)>);

impl Names {
    fn standard() -> Self {
        Self(vec![
            (NAME, vec![IpAddr::from([127, 0, 0, 1])]),
            ("elsewhere.example.test", vec![IpAddr::from([192, 0, 2, 7])]),
        ])
    }
}

impl TargetNames for Names {
    fn resolve<'a>(
        &'a self,
        name: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, String>> + Send + 'a>> {
        Box::pin(async move {
            assert_eq!(port, 445);
            self.0
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, a)| a.clone())
                .ok_or_else(|| "[SCOPE-E00x] résolution impossible".to_owned())
        })
    }
}

fn session(id: u32, state: SessionState, user: &str) -> TargetSession {
    TargetSession {
        id,
        state,
        user: user.into(),
        domain: "TARGET".into(),
    }
}

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

fn driver(production: bool, ntlm_fallback: bool) -> RdpDriver {
    driver_with(production, ntlm_fallback, DisconnectedSessions::Logoff)
        .with_session_control(Arc::new(FakeControl::default()))
}

fn driver_with(production: bool, ntlm_fallback: bool, sessions: DisconnectedSessions) -> RdpDriver {
    RdpDriver::new(
        Arc::new(RdpPolicy {
            production,
            validation: Validation::Pinned,
            password_delegation: false,
            ntlm_fallback,
            realms: Vec::new(),
            identity_key: HmacKey::new(&HmacKey::generate().unwrap()).unwrap(),
            workstation: "OST-AGENT".into(),
            disconnected_sessions: sessions,
        }),
        Arc::new(Secrets),
        Arc::new(Names::standard()),
    )
}

fn params(target: &Target, account: &str) -> TargetParams {
    TargetParams {
        session: RdpSessionParams {
            account: account.into(),
            target_name: Some(NAME.into()),
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

/// ADR-0026: the disconnected session of the account is logged off before
/// the connection, and the session the target named is logged off at the
/// end, never left disconnected.
#[tokio::test]
async fn sessions_of_the_account_are_logged_off_before_and_after() {
    let target = Target::start(Options {
        restricted_admin: true,
        script: Script::LogonThenWait,
        ..Options::default()
    });
    let pinned = loopback(target.addr.port()).await;
    let control = FakeControl::with(vec![
        session(0, SessionState::Other, ""),
        session(2, SessionState::Disconnected, USER),
        session(3, SessionState::Disconnected, "someone-else"),
    ]);
    let connection = driver_with(true, true, DisconnectedSessions::Logoff)
        .with_session_control(Arc::new(control.clone()))
        .connect(&pinned, params(&target, USER), Duration::from_secs(20))
        .await
        .unwrap();
    assert_eq!(connection.report().sessions_logged_off, vec![2]);
    assert_eq!(connection.report().phases[0].phase, "sessions");
    assert_eq!(control.logged_off(), vec![2]);
    {
        let state = control.0.lock().unwrap();
        // The view goes by the verified name, Kerberos only in
        // production, with the secret of the account; signing was asked
        // on the pinned address.
        assert_eq!(
            state.opened_with[0],
            (NAME.to_owned(), true, PASSWORD.to_owned())
        );
        assert_eq!(state.probed, vec![SocketAddr::from(([127, 0, 0, 1], 445))]);
    }
    // The target opened session LOGON_SESSION; the agent disconnects, the
    // target sees it disconnected, the agent logs it off.
    control
        .0
        .lock()
        .unwrap()
        .list
        .push(session(LOGON_SESSION, SessionState::Disconnected, USER));
    // The logon notification has reached the agent.
    tokio::time::sleep(Duration::from_millis(300)).await;
    connection.close().await;
    assert!(connection.is_closed());
    assert_eq!(control.logged_off(), vec![2, LOGON_SESSION]);
    assert!(target.join().accepted);
}

/// ADR-0026: a live session of the account (another connection) refuses
/// the new one, before any connection to the target, and is left alone.
#[tokio::test]
async fn a_live_session_of_the_account_refuses_the_connection() {
    let target = Target::start(Options {
        restricted_admin: true,
        script: Script::WaitClient,
        ..Options::default()
    });
    let pinned = loopback(target.addr.port()).await;
    let control = FakeControl::with(vec![
        session(2, SessionState::Disconnected, USER),
        session(4, SessionState::Active, USER),
    ]);
    let error = driver_with(true, true, DisconnectedSessions::Logoff)
        .with_session_control(Arc::new(control.clone()))
        .connect(&pinned, params(&target, USER), Duration::from_secs(5))
        .await
        .unwrap_err();
    assert_eq!(error, RdpError::SessionInUse(4));
    assert_eq!(error.event(), "rdp.session_in_use");
    assert_eq!(control.logged_off(), Vec::<u32>::new());
    drop(target);
}

/// ADR-0026: without a mechanism to close the sessions (an agent off
/// Windows), the connection is refused; keeping them is refused in
/// production and admitted, logged, in development.
#[tokio::test]
async fn no_mechanism_refuses_and_keep_is_development_only() {
    let target = Target::start(Options {
        restricted_admin: true,
        script: Script::WaitClient,
        ..Options::default()
    });
    let pinned = loopback(target.addr.port()).await;
    let error = driver_with(true, true, DisconnectedSessions::Logoff)
        .with_session_control(Arc::new(Unsupported))
        .connect(&pinned, params(&target, USER), Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(matches!(error, RdpError::SessionCleanup(_)), "{error}");
    let error = driver_with(true, true, DisconnectedSessions::Keep)
        .with_session_control(Arc::new(FakeControl::default()))
        .connect(&pinned, params(&target, USER), Duration::from_secs(5))
        .await
        .unwrap_err();
    assert_eq!(error.code(), "RDP-E019");
    assert!(error.to_string().contains("CFG-P022"), "{error}");
    // Development: kept, the control is never asked.
    let connection = driver_with(false, true, DisconnectedSessions::Keep)
        .with_session_control(Arc::new(Unsupported))
        .connect(&pinned, params(&target, USER), Duration::from_secs(20))
        .await
        .unwrap();
    assert_eq!(connection.report().sessions_logged_off, Vec::<u32>::new());
    assert!(
        connection
            .report()
            .phases
            .iter()
            .all(|p| p.phase != "sessions")
    );
    connection.close().await;
    assert!(target.join().accepted);
}

fn params_named(target: &Target, name: Option<&str>) -> TargetParams {
    let mut p = params(target, USER);
    p.session.target_name = name.map(Into::into);
    p
}

/// ADR-0026: the management channel goes by the DNS name of the target
/// only once the scope control resolves it to the pinned address; no name,
/// a name elsewhere or a name the scope refuses refuses the session before
/// any connection.
#[tokio::test]
async fn the_channel_needs_a_name_resolving_to_the_pinned_address() {
    let target = Target::start(Options {
        restricted_admin: true,
        script: Script::WaitClient,
        ..Options::default()
    });
    let pinned = loopback(target.addr.port()).await;
    for name in [
        None,
        Some("elsewhere.example.test"),
        Some("unknown.example.test"),
    ] {
        let control = FakeControl::default();
        let error = driver_with(true, true, DisconnectedSessions::Logoff)
            .with_session_control(Arc::new(control.clone()))
            .connect(&pinned, params_named(&target, name), Duration::from_secs(5))
            .await
            .unwrap_err();
        assert_eq!(error.code(), "RDP-E021", "{name:?}: {error}");
        assert_eq!(error.event(), "rdp.session_channel_refused");
        let state = control.0.lock().unwrap();
        assert_eq!(state.probed, Vec::new());
        assert_eq!(state.opened_with, Vec::new());
    }
    drop(target);
}

/// ADR-0026: without a Kerberos ticket for the target, NTLM is refused on
/// the channel in production (even with `ntlm_fallback`, which admits it
/// for RDP itself); development with `ntlm_fallback` admits it (logged).
/// Without `ntlm_fallback`, the RDP connection itself needs Kerberos and
/// the plan refuses first (`RDP-E011`).
#[tokio::test]
async fn ntlm_on_the_channel_is_development_only() {
    let target = Target::start(Options {
        restricted_admin: true,
        script: Script::LogonThenWait,
        ..Options::default()
    });
    let pinned = loopback(target.addr.port()).await;
    {
        let control = FakeControl::channel(false, true);
        let error = driver_with(true, true, DisconnectedSessions::Logoff)
            .with_session_control(Arc::new(control.clone()))
            .connect(&pinned, params(&target, USER), Duration::from_secs(5))
            .await
            .unwrap_err();
        assert_eq!(error.code(), "RDP-E022", "{error}");
        assert_eq!(error.event(), "rdp.session_channel_ntlm_refused");
        assert!(control.0.lock().unwrap().opened_with[0].1);
    }
    let control = FakeControl::channel(false, true);
    let connection = driver_with(false, true, DisconnectedSessions::Logoff)
        .with_session_control(Arc::new(control.clone()))
        .connect(&pinned, params(&target, USER), Duration::from_secs(20))
        .await
        .unwrap();
    assert!(!control.0.lock().unwrap().opened_with[0].1);
    connection.close().await;
    assert!(target.join().accepted);
}

/// ADR-0026: a target that does not require SMB signing is refused in
/// production, admitted (logged) in development.
#[tokio::test]
async fn smb_signing_is_required_in_production() {
    let target = Target::start(Options {
        restricted_admin: true,
        script: Script::LogonThenWait,
        ..Options::default()
    });
    let pinned = loopback(target.addr.port()).await;
    let control = FakeControl::channel(true, false);
    let error = driver_with(true, true, DisconnectedSessions::Logoff)
        .with_session_control(Arc::new(control.clone()))
        .connect(&pinned, params(&target, USER), Duration::from_secs(5))
        .await
        .unwrap_err();
    assert_eq!(error, RdpError::SmbSigning);
    assert_eq!(error.code(), "RDP-E023");
    assert_eq!(control.0.lock().unwrap().opened_with, Vec::new());
    let connection = driver_with(false, true, DisconnectedSessions::Logoff)
        .with_session_control(Arc::new(FakeControl::channel(true, false)))
        .connect(&pinned, params(&target, USER), Duration::from_secs(20))
        .await
        .unwrap();
    connection.close().await;
    assert!(target.join().accepted);
}
