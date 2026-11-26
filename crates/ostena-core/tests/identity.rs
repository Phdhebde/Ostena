//! Identity sources (ADR-0021) against the test LDAP server of
//! `ostena-ldap`, served over TLS 1.3 by a test PKI: two directories at
//! once, the same identifier in both, nested groups, routing, failover,
//! plain LDAP and foreign certificates refused, then on a real PostgreSQL
//! server: provisioning, login of a directory user, disabling in the
//! directory cut within the check interval, deletion, password change.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test helpers and scenarios"
)]

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{TestDb, block_on};
use ostena_common::api::login::LoginRequest;
use ostena_common::config::{CoreLoginConfig, LdapSourceConfig};
use ostena_common::secret::{SecretBytes, SecretString};
use ostena_core::api::{ApiCode, Authenticator};
use ostena_core::audit::{self, Recorder};
use ostena_core::authn::PgAuthenticator;
use ostena_core::credential::{self, TotpKey};
use ostena_core::identity::{Directories, DirectorySource, Identity, Route};
use ostena_core::inventory;
use ostena_core::ssh_ca::SshAuthorities;
use ostena_crypto::p256::SigningKey;
use ostena_crypto::pki::pem_certificate;
use ostena_crypto::tls::ServerConfig;
use ostena_crypto::tls::target::testing::{KeyKind, TargetCa, Usage, Versions, server_config};
use ostena_crypto::totp::{TotpAlgorithm, step_at};
use ostena_ldap::testing::{Directory, serve};
use sqlx::PgPool;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const SVC_AD: &str = "CN=svc,OU=Service,DC=corp,DC=test";
const SVC_LAB: &str = "cn=svc,dc=lab,dc=test";
const SVC_PASSWORD: &str = "service account password";
const ADMINS: &str = "CN=Admins,OU=Groups,DC=corp,DC=test";
const TIER0: &str = "CN=Tier0,OU=Groups,DC=corp,DC=test";
const JDUPONT_AD: &str = "CN=Jean Dupont,OU=Users,DC=corp,DC=test";
const MMARTIN_AD: &str = "CN=Marie Martin,OU=Users,DC=corp,DC=test";
const JDUPONT_LAB: &str = "uid=jdupont,ou=people,dc=lab,dc=test";

fn now() -> u64 {
    ostena_grant::unix_now()
}

fn secret(text: &str) -> SecretString {
    SecretString::from(text.to_owned())
}

/// A CA and the TLS 1.3 server configuration of a directory at 127.0.0.1.
struct Pki {
    ca_pem: Vec<u8>,
    server: Arc<ServerConfig>,
}

fn pki(name: &str) -> Pki {
    let ca = TargetCa::new(name).unwrap();
    let dc = ca
        .issue(KeyKind::EcdsaP256, &["127.0.0.1"], Some(Usage::ServerAuth))
        .unwrap();
    Pki {
        ca_pem: pem_certificate(&ca.certificate).into_bytes(),
        server: server_config(&dc, Versions::Tls13).unwrap(),
    }
}

/// Serves `directory` on 127.0.0.1, over TLS with `tls`, in clear without.
async fn listen(directory: Arc<Mutex<Directory>>, tls: Option<Arc<ServerConfig>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (directory, tls) = (directory.clone(), tls.clone());
            tokio::spawn(async move {
                match tls {
                    Some(tls) => {
                        if let Ok(stream) = TlsAcceptor::from(tls).accept(tcp).await {
                            let _ = serve(directory, stream).await;
                        }
                    }
                    None => {
                        let _ = serve(directory, tcp).await;
                    }
                }
            });
        }
    });
    addr
}

/// A port where nothing listens.
async fn dead_port() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

fn servers(addrs: &[SocketAddr]) -> String {
    addrs
        .iter()
        .map(|a| format!("\"ldaps://{a}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

fn ad_config(addrs: &[SocketAddr]) -> LdapSourceConfig {
    toml::from_str(&format!(
        r#"name = "corp"
kind = "active-directory"
servers = [{}]
ca_bundle = "/unused"
bind_dn = "{SVC_AD}"
bind_password = {{ credential = "corp.password" }}
user_base = "OU=Users,DC=corp,DC=test"
suffixes = ["corp.test"]
connect_timeout_secs = 2
groups = [{{ directory = "{ADMINS}", group = "admins" }}]
"#,
        servers(addrs)
    ))
    .unwrap()
}

fn lab_config(addrs: &[SocketAddr]) -> LdapSourceConfig {
    toml::from_str(&format!(
        r#"name = "lab"
kind = "openldap"
servers = [{}]
ca_bundle = "/unused"
bind_dn = "{SVC_LAB}"
bind_password = {{ credential = "lab.password" }}
user_base = "ou=people,dc=lab,dc=test"
group_base = "ou=groups,dc=lab,dc=test"
suffixes = ["lab.test"]
groups = [{{ directory = "cn=ops,ou=groups,dc=lab,dc=test", group = "ops" }}]
"#,
        servers(addrs)
    ))
    .unwrap()
}

fn ad_user(d: &mut Directory, dn: &str, login: &str, guid: u8, groups: &[&str]) {
    let cn = dn.split(',').next().unwrap().trim_start_matches("CN=");
    let mut attributes: Vec<(&str, &[&str])> = vec![
        ("objectClass", &["top", "person", "user"][..]),
        ("objectCategory", &["person"][..]),
        ("sAMAccountName", std::slice::from_ref(&login)),
        ("displayName", std::slice::from_ref(&cn)),
        ("userAccountControl", &["512"][..]),
    ];
    if !groups.is_empty() {
        attributes.push(("memberOf", groups));
    }
    d.add(dn, &attributes);
    d.set(dn, "objectGUID", &[&[guid; 16]]);
    d.set_password(dn, &format!("{login} password"));
}

/// The directory of `corp`: jdupont in Admins through Tier0 (nested),
/// mmartin in Admins, outsider in no ruled group.
fn ad_directory() -> Arc<Mutex<Directory>> {
    let mut d = Directory::new();
    d.add(SVC_AD, &[("objectClass", &["user"])]);
    d.set_password(SVC_AD, SVC_PASSWORD);
    d.add(ADMINS, &[("objectClass", &["group"])]);
    d.add(
        TIER0,
        &[("objectClass", &["group"]), ("memberOf", &[ADMINS])],
    );
    ad_user(&mut d, JDUPONT_AD, "jdupont", 1, &[TIER0]);
    ad_user(&mut d, MMARTIN_AD, "mmartin", 2, &[ADMINS]);
    ad_user(
        &mut d,
        "CN=Out Sider,OU=Users,DC=corp,DC=test",
        "outsider",
        3,
        &[],
    );
    Arc::new(Mutex::new(d))
}

/// The directory of `lab`: another jdupont, in ops through oncall.
fn lab_directory() -> Arc<Mutex<Directory>> {
    let mut d = Directory::new();
    d.add(SVC_LAB, &[("objectClass", &["person"])]);
    d.set_password(SVC_LAB, SVC_PASSWORD);
    d.add(
        JDUPONT_LAB,
        &[
            ("objectClass", &["inetOrgPerson"]),
            ("uid", &["jdupont"]),
            ("cn", &["Jeanne Dupont"]),
            ("entryUUID", &["6a1f2c9e-lab-0001"]),
        ],
    );
    d.set_password(JDUPONT_LAB, "jeanne password");
    d.add(
        "cn=oncall,ou=groups,dc=lab,dc=test",
        &[("member", &[JDUPONT_LAB])],
    );
    d.add(
        "cn=ops,ou=groups,dc=lab,dc=test",
        &[("member", &["cn=oncall,ou=groups,dc=lab,dc=test"])],
    );
    Arc::new(Mutex::new(d))
}

fn source(config: &LdapSourceConfig, pki: &Pki) -> Arc<DirectorySource> {
    Arc::new(DirectorySource::new(config, &pki.ca_pem, secret(SVC_PASSWORD)).unwrap())
}

#[test]
fn two_directories_route_and_read_nested_groups() {
    block_on(async {
        let (corp_pki, lab_pki) = (pki("corp ca"), pki("lab ca"));
        let corp_addr = listen(ad_directory(), Some(corp_pki.server.clone())).await;
        let lab_addr = listen(lab_directory(), Some(lab_pki.server.clone())).await;
        let corp = source(&ad_config(&[corp_addr]), &corp_pki);
        let lab = source(&lab_config(&[lab_addr]), &lab_pki);
        let directories = Directories::from_sources(
            vec![corp.clone(), lab.clone()],
            Some("corp".into()),
            Duration::from_secs(20),
            Duration::from_mins(15),
        );

        // Routing: default source, suffix, explicit source, local accounts.
        let name = |n: &str| directories.route(n).user_name();
        assert_eq!(name("jdupont").as_deref(), Some("corp/jdupont"));
        assert_eq!(name("JDupont@lab.test").as_deref(), Some("lab/jdupont"));
        assert_eq!(name("lab/jdupont").as_deref(), Some("lab/jdupont"));
        assert_eq!(name("local/alice").as_deref(), Some("alice"));
        assert!(matches!(directories.route("x@other.test"), Route::Unknown));
        assert!(matches!(directories.route("nope/x"), Route::Unknown));
        let local = Directories::local_only();
        assert!(matches!(local.route("alice"), Route::Local(n) if n == "alice"));
        assert!(matches!(local.route("corp/jdupont"), Route::Unknown));

        // Both directories at once; nested groups of each kind.
        let listing = corp.list(now()).await.unwrap();
        let mut users: Vec<_> = listing
            .users
            .iter()
            .map(|u| (u.login.as_str(), u.groups.clone()))
            .collect();
        users.sort();
        assert_eq!(
            users,
            [
                ("jdupont", vec!["admins".to_owned()]),
                ("mmartin", vec!["admins".to_owned()]),
                ("outsider", vec![]),
            ]
        );
        let jeanne = &lab.list(now()).await.unwrap().users[0];
        assert_eq!(
            (jeanne.login.as_str(), jeanne.groups.as_slice()),
            ("jdupont", &["ops".to_owned()][..])
        );
        assert_eq!(jeanne.display_name, "Jeanne Dupont");
        assert_eq!(jeanne.external_id, "6a1f2c9e-lab-0001");

        // The password is checked by a bind as the user.
        let (user, ok) = corp
            .authenticate("jdupont", Some(&secret("jdupont password")), now())
            .await
            .unwrap()
            .unwrap();
        assert!(ok);
        assert_eq!(user.external_id, "01".repeat(16));
        let (_, ok) = corp
            .authenticate("jdupont", Some(&secret("jeanne password")), now())
            .await
            .unwrap()
            .unwrap();
        assert!(!ok);
        assert!(
            corp.authenticate("nobody", Some(&secret("x")), now())
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn failover_plain_ldap_and_foreign_certificates() {
    block_on(async {
        let corp_pki = pki("corp ca");
        let directory = ad_directory();
        let good = listen(directory.clone(), Some(corp_pki.server.clone())).await;

        // The first server is down: the second answers, and is kept.
        let corp = source(&ad_config(&[dead_port().await, good]), &corp_pki);
        assert_eq!(corp.list(now()).await.unwrap().users.len(), 3);
        assert_eq!(corp.list(now()).await.unwrap().users.len(), 3);

        // Plain LDAP on the LDAPS port: refused, the password never sent.
        let binds = directory.lock().unwrap().binds();
        let plain = listen(directory.clone(), None).await;
        let corp = source(&ad_config(&[plain]), &corp_pki);
        let err = corp.list(now()).await.unwrap_err();
        assert!(["IDN-E001", "IDN-E002"].contains(&err.code()), "{err}");
        assert_eq!(directory.lock().unwrap().binds(), binds);

        // A certificate of another CA, or of another name: refused.
        let rogue = pki("rogue ca");
        let foreign = listen(directory.clone(), Some(rogue.server.clone())).await;
        let corp = source(&ad_config(&[foreign]), &corp_pki);
        let err = corp.list(now()).await.unwrap_err();
        assert_eq!(err.code(), "IDN-E001");
        assert!(err.to_string().contains("TLS"), "{err}");
        let ca = TargetCa::new("corp ca").unwrap();
        let ca_pem = pem_certificate(&ca.certificate).into_bytes();
        let with = |addr| {
            DirectorySource::new(&ad_config(&[addr]), &ca_pem, secret(SVC_PASSWORD)).unwrap()
        };
        let other = ca
            .issue(
                KeyKind::EcdsaP256,
                &["dc02.corp.test"],
                Some(Usage::ServerAuth),
            )
            .unwrap();
        let named = listen(
            directory.clone(),
            Some(server_config(&other, Versions::Tls13).unwrap()),
        )
        .await;
        assert!(with(named).list(now()).await.is_err());
        // TLS 1.2 only, with a certificate that would be accepted: refused.
        let dc = ca
            .issue(KeyKind::EcdsaP256, &["127.0.0.1"], Some(Usage::ServerAuth))
            .unwrap();
        let tls12 = listen(
            directory.clone(),
            Some(server_config(&dc, Versions::Tls12).unwrap()),
        )
        .await;
        let err = with(tls12).list(now()).await.unwrap_err();
        assert!(err.to_string().contains("TLS 1.3"), "{err}");
        assert_eq!(directory.lock().unwrap().binds(), binds);
        // The same server offering TLS 1.3 too: accepted.
        let both = listen(
            directory.clone(),
            Some(server_config(&dc, Versions::Both).unwrap()),
        )
        .await;
        assert_eq!(with(both).list(now()).await.unwrap().users.len(), 3);

        // A refused service account stops at once (IDN-E003).
        let mut config = ad_config(&[good]);
        config.bind_dn = "CN=nobody,DC=corp,DC=test".into();
        let corp = DirectorySource::new(&config, &corp_pki.ca_pem, secret("wrong")).unwrap();
        assert_eq!(corp.list(now()).await.unwrap_err().code(), "IDN-E003");

        // Plain LDAP in the configuration: refused before any connection.
        let mut config = ad_config(&[good]);
        config.servers = vec![format!("ldap://{good}")];
        assert!(DirectorySource::new(&config, &corp_pki.ca_pem, secret(SVC_PASSWORD)).is_err());
    });
}

fn totp_key() -> TotpKey {
    let bytes: [u8; 32] = ostena_crypto::rand::array().unwrap();
    TotpKey::from_bytes(&SecretBytes::from(bytes.to_vec()), &[]).unwrap()
}

fn login_settings() -> CoreLoginConfig {
    toml::from_str(
        "listen = \"127.0.0.1:0\"\ntotp_key = { credential = \"totp.key\" }\n\
         ssh_hosts = [\"bastion.lab\"]\n",
    )
    .unwrap()
}

async fn audit_count(pool: &PgPool, event: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_record WHERE event = $1")
        .bind(event)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn user_state(pool: &PgPool, name: &str) -> Option<(String, String, bool)> {
    sqlx::query_as("SELECT id::text, state, directory_disabled FROM app_user WHERE name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await
        .unwrap()
}

async fn open_sessions(pool: &PgPool, user: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM login_session WHERE user_id = $1::text::uuid AND revoked_at IS NULL",
    )
    .bind(user)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Opens a login session of `user` directly, as a login would.
async fn open_session(pool: &PgPool, user: &str) {
    let mut tx = pool.begin().await.unwrap();
    ostena_core::login::open_session(
        &mut tx,
        ostena_core::login::new_session_id().unwrap(),
        ostena_tunnel::Uuid::parse(user).unwrap(),
        ostena_crypto::rand::array().unwrap(),
        now() + 3600,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

struct Fixture {
    db: TestDb,
    pool: PgPool,
    recorder: Arc<Recorder>,
    identity: Arc<Identity>,
    corp: Arc<DirectorySource>,
    directory: Arc<Mutex<Directory>>,
}

/// A migrated database and the source `corp`, checked every second.
async fn fixture(test: &str) -> Option<Fixture> {
    let db = TestDb::create(test).await?;
    db.migrate().await;
    let pool = db.pool().await;
    audit::ensure_genesis(&pool).await.unwrap();
    let recorder = Arc::new(Recorder::new());
    tokio::spawn(audit::run_writer(pool.clone(), recorder.clone()));
    let corp_pki = pki("corp ca");
    let directory = ad_directory();
    let addr = listen(directory.clone(), Some(corp_pki.server.clone())).await;
    let corp = source(&ad_config(&[addr]), &corp_pki);
    let directories = Directories::from_sources(
        vec![corp.clone()],
        Some("corp".into()),
        Duration::from_secs(1),
        Duration::from_secs(3600),
    );
    let identity = Arc::new(Identity::new(
        Arc::new(directories),
        pool.clone(),
        recorder.clone(),
    ));
    Some(Fixture {
        db,
        pool,
        recorder,
        identity,
        corp,
        directory,
    })
}

impl Fixture {
    async fn close(self) {
        assert!(self.recorder.flush(Duration::from_secs(5)).await);
        drop(self.identity);
        self.pool.close().await;
        self.db.drop_database().await;
    }
}

#[test]
fn same_identifier_in_two_sources_gives_two_users() {
    block_on(async {
        let Some(f) = fixture("same_identifier_in_two_sources_gives_two_users").await else {
            return;
        };
        let lab_pki = pki("lab ca");
        let lab_addr = listen(lab_directory(), Some(lab_pki.server.clone())).await;
        let lab = source(&lab_config(&[lab_addr]), &lab_pki);
        let identity = Identity::new(
            Arc::new(Directories::from_sources(
                vec![f.corp.clone(), lab.clone()],
                None,
                Duration::from_secs(20),
                Duration::from_mins(15),
            )),
            f.pool.clone(),
            f.recorder.clone(),
        );
        // A local account of the same name stays apart too.
        inventory::add_user(&f.pool, "jdupont", "Local")
            .await
            .unwrap();
        let corp = identity.sync(&f.corp).await.unwrap();
        assert_eq!((corp.seen, corp.created), (3, 2));
        let lab_report = identity.sync(&lab).await.unwrap();
        assert_eq!((lab_report.seen, lab_report.created), (1, 1));
        // A second pass changes nothing.
        let again = identity.sync(&f.corp).await.unwrap();
        assert_eq!((again.created, again.updated, again.disabled), (0, 0, 0));

        let rows: Vec<(String, String, Option<String>)> = sqlx::query_as(
            "SELECT name, source, external_id FROM app_user WHERE name LIKE '%jdupont' ORDER BY name",
        )
        .fetch_all(&f.pool)
        .await
        .unwrap();
        assert_eq!(
            rows,
            [
                ("corp/jdupont".into(), "corp".into(), Some("01".repeat(16))),
                ("jdupont".into(), "local".into(), None),
                (
                    "lab/jdupont".into(),
                    "lab".into(),
                    Some("6a1f2c9e-lab-0001".into())
                ),
            ]
        );
        assert!(user_state(&f.pool, "corp/outsider").await.is_none());
        let groups: Vec<(String, String)> = sqlx::query_as(
            "SELECT u.name, g.name FROM user_group_member m
             JOIN app_user u ON u.id = m.user_id JOIN user_group g ON g.id = m.group_id
             ORDER BY u.name",
        )
        .fetch_all(&f.pool)
        .await
        .unwrap();
        assert_eq!(
            groups,
            [
                ("corp/jdupont".into(), "admins".into()),
                ("corp/mmartin".into(), "admins".into()),
                ("lab/jdupont".into(), "ops".into()),
            ]
        );
        assert!(f.recorder.flush(Duration::from_secs(5)).await);
        assert_eq!(audit_count(&f.pool, "identity.user_provisioned").await, 3);
        assert_eq!(audit_count(&f.pool, "user_group.member_added").await, 3);
        assert_eq!(audit_count(&f.pool, "identity.sync_completed").await, 3);
        f.close().await;
    });
}

#[test]
fn directory_user_logs_in_and_is_cut_when_disabled() {
    block_on(async {
        let Some(f) = fixture("directory_user_logs_in_and_is_cut_when_disabled").await else {
            return;
        };
        f.identity.sync(&f.corp).await.unwrap();
        let key = Arc::new(totp_key());
        let totp = credential::enroll_totp(&f.pool, &key, "corp/jdupont", TotpAlgorithm::Sha1)
            .await
            .unwrap();
        credential::confirm_totp(&f.pool, &key, "corp/jdupont", &totp.code(step_at(now())))
            .await
            .unwrap();
        // The password of a directory user is the directory's.
        assert!(
            credential::set_password(&f.pool, "corp/jdupont", secret("another password!"))
                .await
                .is_err()
        );
        let ssh = Arc::new(
            SshAuthorities::new(
                SigningKey::generate().unwrap().0,
                SigningKey::generate().unwrap().0,
                30,
            )
            .unwrap(),
        );
        let authenticator = PgAuthenticator::new(
            f.pool.clone(),
            f.recorder.clone(),
            ssh,
            key,
            &login_settings(),
        )
        .with_refusal_floor(Duration::from_millis(1))
        .with_identity(f.identity.clone());
        let device = SigningKey::generate().unwrap().0;
        let login = |user: &str, password: &str, code: SecretString| {
            authenticator.login(
                LoginRequest {
                    protocol: 1,
                    username: user.into(),
                    password: secret(password),
                    totp: code,
                    p256_public: URL_SAFE_NO_PAD.encode(device.verifying_key().to_bytes()),
                    ttl_secs: None,
                },
                "192.0.2.7:50123".parse().unwrap(),
            )
        };
        let code = || totp.code(step_at(now()) + 1);
        let (id, _, _) = user_state(&f.pool, "corp/jdupont").await.unwrap();

        // Wrong password (another source's), unknown suffix: refused.
        let refused = login("jdupont", "jeanne password", code())
            .await
            .unwrap_err();
        assert_eq!(refused.code, ApiCode::InvalidCredentials);
        let refused = login("jdupont@other.test", "jdupont password", code())
            .await
            .unwrap_err();
        assert_eq!(refused.code, ApiCode::InvalidCredentials);
        // An admitted user without a TOTP secret: not enrolled.
        let refused = login("mmartin", "mmartin password", code())
            .await
            .unwrap_err();
        assert_eq!(refused.code, ApiCode::InvalidCredentials);
        // The right password and code, by suffix.
        let response = login("jdupont@corp.test", "jdupont password", code())
            .await
            .unwrap();
        assert_eq!(response.user, id);
        open_session(&f.pool, &id).await;
        assert_eq!(open_sessions(&f.pool, &id).await, 2);

        // A password changed in the directory after the sessions opened.
        let later = (now() + 5 + 11_644_473_600) * 10_000_000;
        f.directory
            .lock()
            .unwrap()
            .set(JDUPONT_AD, "pwdLastSet", &[later.to_string().as_bytes()]);
        let report = f.identity.check(&f.corp).await.unwrap();
        assert_eq!(report.revoked_sessions, 2);
        assert_eq!(open_sessions(&f.pool, &id).await, 0);
        f.directory
            .lock()
            .unwrap()
            .set(JDUPONT_AD, "pwdLastSet", &[b"0"]);
        open_session(&f.pool, &id).await;

        // Disabled in the directory: detected by the periodic check, the
        // sessions revoked well within 60 s.
        let tasks = f.identity.spawn();
        tokio::time::sleep(Duration::from_millis(300)).await;
        f.directory
            .lock()
            .unwrap()
            .set(JDUPONT_AD, "userAccountControl", &[b"514"]);
        let disabled_at = Instant::now();
        while open_sessions(&f.pool, &id).await > 0 {
            assert!(disabled_at.elapsed() < Duration::from_secs(60));
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let elapsed = disabled_at.elapsed();
        println!("disabled in the directory -> sessions revoked: {elapsed:?}");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
        for task in tasks {
            task.abort();
        }
        let (_, state, by_source) = user_state(&f.pool, "corp/jdupont").await.unwrap();
        assert_eq!((state.as_str(), by_source), ("disabled", true));
        let refused = login("jdupont", "jdupont password", code())
            .await
            .unwrap_err();
        assert_eq!(refused.code, ApiCode::InvalidCredentials);

        // Enabled again in the directory: lifted at the next full pass.
        f.directory
            .lock()
            .unwrap()
            .set(JDUPONT_AD, "userAccountControl", &[b"512"]);
        f.identity.sync(&f.corp).await.unwrap();
        let (_, state, _) = user_state(&f.pool, "corp/jdupont").await.unwrap();
        assert_eq!(state, "active");
        assert!(f.recorder.flush(Duration::from_secs(5)).await);
        assert_eq!(audit_count(&f.pool, "user.disabled").await, 1);
        assert_eq!(audit_count(&f.pool, "identity.user_reenabled").await, 1);
        assert_eq!(audit_count(&f.pool, "login_session.revoked").await, 3);
        assert_eq!(audit_count(&f.pool, "login.succeeded").await, 1);
        drop(authenticator);
        f.close().await;
    });
}

#[test]
fn deleted_or_ungrouped_users_are_disabled() {
    block_on(async {
        let Some(f) = fixture("deleted_or_ungrouped_users_are_disabled").await else {
            return;
        };
        f.identity.sync(&f.corp).await.unwrap();
        let (jdupont, _, _) = user_state(&f.pool, "corp/jdupont").await.unwrap();
        open_session(&f.pool, &jdupont).await;
        {
            let mut d = f.directory.lock().unwrap();
            d.remove(JDUPONT_AD);
            d.set(MMARTIN_AD, "memberOf", &[]);
        }
        // The check sees the deletion of a user with a session.
        let report = f.identity.check(&f.corp).await.unwrap();
        assert_eq!((report.disabled, report.revoked_sessions), (1, 1));
        // The full pass sees the rest.
        let report = f.identity.sync(&f.corp).await.unwrap();
        assert_eq!(report.disabled, 1);
        for name in ["corp/jdupont", "corp/mmartin"] {
            let (_, state, by_source) = user_state(&f.pool, name).await.unwrap();
            assert_eq!((state.as_str(), by_source), ("disabled", true), "{name}");
        }
        // Back in the group: enabled again; a disabling by an
        // administrator is never lifted by the source.
        f.directory
            .lock()
            .unwrap()
            .set(MMARTIN_AD, "memberOf", &[ADMINS.as_bytes()]);
        f.identity.sync(&f.corp).await.unwrap();
        assert_eq!(
            user_state(&f.pool, "corp/mmartin").await.unwrap().1,
            "active"
        );
        inventory::disable_user(&f.pool, "corp/mmartin")
            .await
            .unwrap();
        f.identity.sync(&f.corp).await.unwrap();
        let (_, state, by_source) = user_state(&f.pool, "corp/mmartin").await.unwrap();
        assert_eq!((state.as_str(), by_source), ("disabled", false));
        let member: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM user_group_member m JOIN app_user u ON u.id = m.user_id
             WHERE u.name = 'corp/mmartin'",
        )
        .fetch_one(&f.pool)
        .await
        .unwrap();
        assert_eq!(member, 1);
        assert!(f.recorder.flush(Duration::from_secs(5)).await);
        assert_eq!(audit_count(&f.pool, "user_group.member_removed").await, 1);
        f.close().await;
    });
}
