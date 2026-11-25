//! `ostena login` on a real PostgreSQL server (ADR-0010): credentials
//! administered as by `ostena core user …`, then the PostgreSQL
//! authenticator decides logins and logouts: certificate and session,
//! anti-replay of the codes, lockout, uniform refusals, audit records.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test helpers and scenarios"
)]

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use common::{TestDb, block_on};
use ostena_common::api::login::{LoginRequest, LoginResponse, LogoutRequest, logout_message};
use ostena_common::config::CoreLoginConfig;
use ostena_common::secret::{SecretBytes, SecretString};
use ostena_core::api::{ApiCode, Authenticator};
use ostena_core::audit::{self, Recorder};
use ostena_core::authn::PgAuthenticator;
use ostena_core::credential::{self, TotpKey};
use ostena_core::ssh_ca::SshAuthorities;
use ostena_core::{inventory, schema};
use ostena_crypto::p256::SigningKey;
use ostena_crypto::totp::{TotpAlgorithm, TotpSecret, step_at};
use ostena_ssh::cert;
use sqlx::PgPool;

const PEER: &str = "192.0.2.7:50123";
const PASSWORD: &str = "correct horse battery";

fn now() -> u64 {
    ostena_grant::unix_now()
}

fn secret(text: &str) -> SecretString {
    SecretString::from(text.to_owned())
}

fn peer() -> SocketAddr {
    PEER.parse().unwrap()
}

fn totp_key() -> TotpKey {
    let bytes: [u8; 32] = ostena_crypto::rand::array().unwrap();
    TotpKey::from_bytes(&SecretBytes::from(bytes.to_vec()), &[]).unwrap()
}

fn settings() -> CoreLoginConfig {
    toml::from_str(
        "listen = \"127.0.0.1:0\"\ntotp_key = { credential = \"totp.key\" }\n\
         ssh_hosts = [\"bastion.lab\"]\nmax_failures = 3\nlockout_minutes = 15\n\
         session_max_hours = 2\n",
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

/// Waits until the best-effort queue is written.
async fn flushed(recorder: &Recorder) {
    assert!(recorder.flush(Duration::from_secs(5)).await);
}

struct Fixture {
    db: TestDb,
    pool: PgPool,
    recorder: Arc<Recorder>,
    ssh: Arc<SshAuthorities>,
    key: Arc<TotpKey>,
    authenticator: PgAuthenticator,
    totp: TotpSecret,
}

/// A migrated database with alice, her password and a confirmed TOTP
/// secret (the confirmation consumed the current step).
async fn fixture(test: &str) -> Option<Fixture> {
    let db = TestDb::create(test).await?;
    let pool = db.pool().await;
    schema::migrate(&pool).await.unwrap();
    audit::ensure_genesis(&pool).await.unwrap();
    inventory::add_user(&pool, "alice", "Alice Martin")
        .await
        .unwrap();
    credential::set_password(&pool, "alice", secret(PASSWORD))
        .await
        .unwrap();
    let key = Arc::new(totp_key());
    let totp = credential::enroll_totp(&pool, &key, "alice", TotpAlgorithm::Sha1)
        .await
        .unwrap();
    credential::confirm_totp(&pool, &key, "alice", &totp.code(step_at(now())))
        .await
        .unwrap();
    let recorder = Arc::new(Recorder::new());
    tokio::spawn(audit::run_writer(pool.clone(), recorder.clone()));
    let ssh = Arc::new(
        SshAuthorities::new(
            SigningKey::generate().unwrap().0,
            SigningKey::generate().unwrap().0,
            30,
        )
        .unwrap(),
    );
    let authenticator = PgAuthenticator::new(
        pool.clone(),
        recorder.clone(),
        ssh.clone(),
        key.clone(),
        &settings(),
    );
    Some(Fixture {
        db,
        pool,
        recorder,
        ssh,
        key,
        authenticator,
        totp,
    })
}

impl Fixture {
    /// The code of the next step: accepted once (one step of tolerance).
    fn next_code(&self) -> SecretString {
        self.totp.code(step_at(now()) + 1)
    }

    async fn login(
        &self,
        user: &str,
        password: &str,
        code: SecretString,
        key: &SigningKey,
    ) -> Result<LoginResponse, ApiCode> {
        self.authenticator
            .login(
                LoginRequest {
                    protocol: 1,
                    username: user.into(),
                    password: secret(password),
                    totp: code,
                    p256_public: URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
                    ttl_secs: None,
                },
                peer(),
            )
            .await
            .map_err(|e| {
                if e.code == ApiCode::InvalidCredentials {
                    // One message whatever the cause.
                    assert_eq!(e.message, ostena_core::api::INVALID_CREDENTIALS);
                }
                e.code
            })
    }

    async fn failures(&self) -> (i32, Option<i64>) {
        sqlx::query_as(
            "SELECT failed_attempts, locked_until FROM user_credential c
             JOIN app_user u ON u.id = c.user_id WHERE u.name = 'alice'",
        )
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }
}

fn logout_request(response: &LoginResponse, key: &SigningKey, issued_at: u64) -> LogoutRequest {
    LogoutRequest {
        protocol: 1,
        login_session: response.login_session.clone(),
        certificate: response.certificate.clone(),
        issued_at,
        signature: URL_SAFE_NO_PAD.encode(
            key.sign(&logout_message(&response.login_session, issued_at))
                .unwrap()
                .to_bytes(),
        ),
    }
}

#[test]
fn login_issues_a_certificate_and_opens_a_session() {
    block_on(async {
        let Some(f) = fixture("login_issues_a_certificate_and_opens_a_session").await else {
            return;
        };
        let key = SigningKey::generate().unwrap().0;
        let response = f
            .login("alice", PASSWORD, f.next_code(), &key)
            .await
            .unwrap();

        // The certificate: the key sent, signed by the user authority, the
        // user and the session of the answer, two hours (the setting).
        let blob = STANDARD
            .decode(response.certificate.split(' ').nth(1).unwrap())
            .unwrap();
        let parsed = cert::parse(&blob).unwrap();
        parsed.verify(&[f.ssh.user_ca_public()]).unwrap();
        assert_eq!(parsed.public, key.verifying_key());
        let identity = cert::check_user(&parsed, now()).unwrap();
        assert!(identity.allow_pty);
        assert_eq!(cert::format_uuid(&identity.subject), response.user);
        assert_eq!(
            cert::format_uuid(&identity.login_session),
            response.login_session
        );
        assert!((7198..=7200).contains(&(response.valid_before - now())));
        assert_eq!(response.valid_before - response.valid_after, 7260);
        assert_eq!(response.ssh_hosts, ["bastion.lab"]);
        assert_eq!(response.ssh_port, 2222);
        assert_eq!(
            response.host_ca,
            ostena_ssh::keys::public_line(&f.ssh.host_ca_public(), "ostena-host-ca")
        );

        // The session, keyed by the SHA-256 of the certificate.
        let (user, sha256, expires): (String, Vec<u8>, i64) = sqlx::query_as(
            "SELECT user_id::text, certificate_sha256, expires_at FROM login_session
             WHERE id = $1::text::uuid AND revoked_at IS NULL",
        )
        .bind(&response.login_session)
        .fetch_one(&f.pool)
        .await
        .unwrap();
        assert_eq!(user, response.user);
        assert_eq!(sha256, identity.certificate_sha256);
        assert_eq!(expires, i64::try_from(response.valid_before).unwrap());
        assert_eq!(audit_count(&f.pool, "login.succeeded").await, 1);

        // The same code again: replayed, refused like anything else.
        assert_eq!(
            f.login("alice", PASSWORD, f.next_code(), &key)
                .await
                .unwrap_err(),
            ApiCode::InvalidCredentials
        );
        flushed(&f.recorder).await;
        assert_eq!(audit_count(&f.pool, "login.refused").await, 1);

        // A public key that is not a point.
        let refused = f
            .authenticator
            .login(
                LoginRequest {
                    protocol: 1,
                    username: "alice".into(),
                    password: secret(PASSWORD),
                    totp: f.totp.code(step_at(now())),
                    p256_public: URL_SAFE_NO_PAD.encode([4u8; 65]),
                    ttl_secs: Some(600),
                },
                peer(),
            )
            .await
            .unwrap_err();
        assert_eq!(refused.code, ApiCode::PublicKey);

        drop(f.authenticator);
        f.pool.close().await;
        f.db.drop_database().await;
    });
}

#[test]
fn failures_lock_the_account_and_refusals_are_uniform() {
    block_on(async {
        let Some(f) = fixture("failures_lock_the_account_and_refusals_are_uniform").await else {
            return;
        };
        let key = SigningKey::generate().unwrap().0;
        // Unknown user and wrong password: the same refusal, nothing to
        // count for an unknown name.
        assert_eq!(
            f.login("bob", PASSWORD, f.next_code(), &key)
                .await
                .unwrap_err(),
            ApiCode::InvalidCredentials
        );
        for n in 1..=2 {
            assert_eq!(
                f.login("alice", "wrong password!", f.next_code(), &key)
                    .await
                    .unwrap_err(),
                ApiCode::InvalidCredentials
            );
            assert_eq!(f.failures().await, (n, None));
        }
        // A wrong code counts too; the third failure locks.
        assert_eq!(
            f.login("alice", PASSWORD, secret("000000"), &key)
                .await
                .unwrap_err(),
            ApiCode::InvalidCredentials
        );
        let (count, locked) = f.failures().await;
        assert_eq!(count, 0);
        let until = u64::try_from(locked.unwrap()).unwrap();
        assert!(until > now() + 14 * 60 && until <= now() + 15 * 60);
        assert_eq!(audit_count(&f.pool, "login.locked").await, 1);
        // Locked: even the right password and code are refused.
        assert_eq!(
            f.login("alice", PASSWORD, f.next_code(), &key)
                .await
                .unwrap_err(),
            ApiCode::InvalidCredentials
        );
        let state = credential::state(&f.pool, alice(&f.pool).await)
            .await
            .unwrap();
        assert_eq!(state.locked_until, Some(until));
        // The administrator unlocks; the next step's code is still unused.
        credential::unlock(&f.pool, "alice").await.unwrap();
        assert_eq!(audit_count(&f.pool, "user.unlocked").await, 1);
        f.login("alice", PASSWORD, f.next_code(), &key)
            .await
            .unwrap();

        // A disabled user is refused.
        inventory::disable_user(&f.pool, "alice").await.unwrap();
        assert_eq!(
            f.login("alice", PASSWORD, f.totp.code(step_at(now()) + 1), &key)
                .await
                .unwrap_err(),
            ApiCode::InvalidCredentials
        );
        flushed(&f.recorder).await;
        // bob, two passwords, one code, locked, disabled.
        assert_eq!(audit_count(&f.pool, "login.refused").await, 6);

        drop(f.authenticator);
        f.pool.close().await;
        f.db.drop_database().await;
    });
}

/// A disabling that runs during a login: the login waits on the user row,
/// then sees the user disabled and opens no session (ADR-0014 lock order).
#[test]
fn a_disabled_user_cannot_open_a_login_session() {
    block_on(async {
        let Some(f) = fixture("a_disabled_user_cannot_open_a_login_session").await else {
            return;
        };
        let f = Arc::new(f);
        // An uncommitted disabling holds the user row.
        let mut disabling = f.pool.begin().await.unwrap();
        sqlx::query(
            "UPDATE app_user SET state = 'disabled', disabled_at = now() WHERE name = 'alice'",
        )
        .execute(&mut *disabling)
        .await
        .unwrap();
        let attempt = tokio::spawn({
            let f = f.clone();
            async move {
                let key = SigningKey::generate().unwrap().0;
                f.login("alice", PASSWORD, f.next_code(), &key).await
            }
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!attempt.is_finished(), "the login waits on the user row");
        disabling.commit().await.unwrap();
        assert_eq!(
            attempt.await.unwrap().unwrap_err(),
            ApiCode::InvalidCredentials
        );
        let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM login_session")
            .fetch_one(&f.pool)
            .await
            .unwrap();
        assert_eq!(sessions, 0);
        // The refusal did not count as a failure.
        assert_eq!(f.failures().await, (0, None));

        let f = Arc::into_inner(f).unwrap();
        drop(f.authenticator);
        f.pool.close().await;
        f.db.drop_database().await;
    });
}

/// Failures count only within the lockout of the last one: an old count
/// starts again instead of locking at the next mistake.
#[test]
fn failures_decay_after_the_lockout_window() {
    block_on(async {
        let Some(f) = fixture("failures_decay_after_the_lockout_window").await else {
            return;
        };
        let key = SigningKey::generate().unwrap().0;
        for n in 1..=2 {
            assert!(
                f.login("alice", "wrong password!", f.next_code(), &key)
                    .await
                    .is_err()
            );
            assert_eq!(f.failures().await, (n, None));
        }
        let last: Option<i64> = sqlx::query_scalar(
            "SELECT last_failure_at FROM user_credential c
             JOIN app_user u ON u.id = c.user_id WHERE u.name = 'alice'",
        )
        .fetch_one(&f.pool)
        .await
        .unwrap();
        assert!(last.unwrap().abs_diff(i64::try_from(now()).unwrap()) <= 1);
        // The last failure is just over 15 minutes old: the third one does
        // not lock, it starts a new count.
        let old = i64::try_from(now() - 15 * 60 - 1).unwrap();
        sqlx::query("UPDATE user_credential SET last_failure_at = $1")
            .bind(old)
            .execute(&f.pool)
            .await
            .unwrap();
        assert!(
            f.login("alice", "wrong password!", f.next_code(), &key)
                .await
                .is_err()
        );
        assert_eq!(f.failures().await, (1, None));
        // Within the window, they add up again and lock at three.
        for _ in 0..2 {
            assert!(
                f.login("alice", "wrong password!", f.next_code(), &key)
                    .await
                    .is_err()
            );
        }
        let (count, locked) = f.failures().await;
        assert_eq!(count, 0);
        assert!(locked.is_some());
        // A success clears the time of the last failure.
        credential::unlock(&f.pool, "alice").await.unwrap();
        f.login("alice", PASSWORD, f.next_code(), &key)
            .await
            .unwrap();
        let last: Option<i64> = sqlx::query_scalar("SELECT last_failure_at FROM user_credential")
            .fetch_one(&f.pool)
            .await
            .unwrap();
        assert_eq!(last, None);

        drop(f.authenticator);
        f.pool.close().await;
        f.db.drop_database().await;
    });
}

async fn alice(pool: &PgPool) -> ostena_tunnel::Uuid {
    let id: String = sqlx::query_scalar("SELECT id::text FROM app_user WHERE name = 'alice'")
        .fetch_one(pool)
        .await
        .unwrap();
    ostena_tunnel::Uuid::parse(&id).unwrap()
}

#[test]
fn enrolment_states_and_administration() {
    block_on(async {
        let Some(f) = fixture("enrolment_states_and_administration").await else {
            return;
        };
        let key = SigningKey::generate().unwrap().0;
        let user = alice(&f.pool).await;
        let state = credential::state(&f.pool, user).await.unwrap();
        assert!(state.password && state.totp && !state.totp_pending);

        // A new secret is pending: the login is refused until confirmed.
        let pending = credential::enroll_totp(&f.pool, &f.key, "alice", TotpAlgorithm::Sha256)
            .await
            .unwrap();
        let state = credential::state(&f.pool, user).await.unwrap();
        assert!(state.totp_pending && !state.totp);
        assert_eq!(
            f.login("alice", PASSWORD, pending.code(step_at(now())), &key)
                .await
                .unwrap_err(),
            ApiCode::InvalidCredentials
        );
        // A wrong confirmation code; then the right one.
        assert!(
            credential::confirm_totp(&f.pool, &f.key, "alice", &secret("123"))
                .await
                .is_err()
        );
        credential::confirm_totp(&f.pool, &f.key, "alice", &pending.code(step_at(now())))
            .await
            .unwrap();
        f.login("alice", PASSWORD, pending.code(step_at(now()) + 1), &key)
            .await
            .unwrap();
        // The old secret no longer works.
        assert_eq!(
            f.login("alice", PASSWORD, f.totp.code(step_at(now())), &key)
                .await
                .unwrap_err(),
            ApiCode::InvalidCredentials
        );

        // Another key cannot open a stored secret.
        let again = credential::enroll_totp(&f.pool, &f.key, "alice", TotpAlgorithm::Sha1)
            .await
            .unwrap();
        assert!(matches!(
            credential::confirm_totp(&f.pool, &totp_key(), "alice", &again.code(step_at(now())))
                .await,
            Err(ostena_core::CoreError::Keys(_))
        ));

        // Reset: nothing left, login refused, confirmation impossible.
        credential::reset_totp(&f.pool, "alice").await.unwrap();
        let state = credential::state(&f.pool, user).await.unwrap();
        assert!(!state.totp && !state.totp_pending && state.password);
        assert!(
            credential::confirm_totp(&f.pool, &f.key, "alice", &secret("123456"))
                .await
                .is_err()
        );

        // Password rules; an unknown user.
        assert!(
            credential::set_password(&f.pool, "alice", secret("short"))
                .await
                .is_err()
        );
        assert!(matches!(
            credential::set_password(&f.pool, "nobody", secret(PASSWORD)).await,
            Err(ostena_core::CoreError::NotFound(_))
        ));
        assert_eq!(audit_count(&f.pool, "user.password_set").await, 1);
        assert_eq!(audit_count(&f.pool, "user.totp_enrolled").await, 2);
        // Three new secrets and one reset.
        assert_eq!(audit_count(&f.pool, "user.totp_reset").await, 4);

        // Nothing is left of the secret.
        let stored: Option<Vec<u8>> = sqlx::query_scalar("SELECT totp_secret FROM user_credential")
            .fetch_one(&f.pool)
            .await
            .unwrap();
        assert!(stored.is_none());

        drop(f.authenticator);
        f.pool.close().await;
        f.db.drop_database().await;
    });
}

#[test]
fn logout_is_signed_by_the_session_key() {
    block_on(async {
        let Some(f) = fixture("logout_is_signed_by_the_session_key").await else {
            return;
        };
        let key = SigningKey::generate().unwrap().0;
        let response = f
            .login("alice", PASSWORD, f.next_code(), &key)
            .await
            .unwrap();
        // Signed by another key, or too old: refused.
        let other = SigningKey::generate().unwrap().0;
        for request in [
            logout_request(&response, &other, now()),
            logout_request(&response, &key, now() - 3600),
        ] {
            assert_eq!(
                f.authenticator
                    .logout(request, peer())
                    .await
                    .unwrap_err()
                    .code,
                ApiCode::InvalidCredentials
            );
        }
        // A certificate of another authority, for the same session.
        let rogue = SshAuthorities::new(
            SigningKey::generate().unwrap().0,
            SigningKey::generate().unwrap().0,
            30,
        )
        .unwrap();
        let session = ostena_tunnel::Uuid::parse(&response.login_session).unwrap();
        let user = ostena_tunnel::Uuid::parse(&response.user).unwrap();
        let forged = rogue
            .issue_user(
                &key.verifying_key(),
                user.to_bytes(),
                session.to_bytes(),
                now() - 60,
                now() + 600,
                true,
            )
            .unwrap();
        let mut request = logout_request(&response, &key, now());
        request.certificate = format!(
            "ecdsa-sha2-nistp256-cert-v01@openssh.com {}",
            STANDARD.encode(&forged.blob)
        );
        assert!(f.authenticator.logout(request, peer()).await.is_err());

        // The session key: revoked, once; a second logout changes nothing.
        f.authenticator
            .logout(logout_request(&response, &key, now()), peer())
            .await
            .unwrap();
        f.authenticator
            .logout(logout_request(&response, &key, now()), peer())
            .await
            .unwrap();
        let (by, reason): (String, String) = sqlx::query_as(
            "SELECT revoked_by, revocation_reason FROM login_session WHERE id = $1::text::uuid",
        )
        .bind(&response.login_session)
        .fetch_one(&f.pool)
        .await
        .unwrap();
        assert_eq!(by, format!("user:{}", response.user));
        assert_eq!(reason, "ostena logout");
        assert_eq!(audit_count(&f.pool, "login_session.revoked").await, 1);

        drop(f.authenticator);
        f.pool.close().await;
        f.db.drop_database().await;
    });
}

#[test]
fn the_totp_key_is_a_key_of_its_own() {
    let bytes = |b: &[u8]| SecretBytes::from(b.to_vec());
    let random: [u8; 32] = ostena_crypto::rand::array().unwrap();
    assert!(TotpKey::from_bytes(&bytes(&random), &[]).is_ok());
    assert!(TotpKey::from_bytes(&bytes(&random[..31]), &[]).is_err());
    assert!(TotpKey::from_bytes(&bytes(&[7; 32]), &[]).is_err());
    let audit = SigningKey::generate().unwrap().0.scalar().unwrap();
    // SECRET-EXPOSURE: test only, a key reused as the TOTP key.
    #[expect(clippy::disallowed_methods)]
    let reused = bytes(audit.expose_secret());
    let error = TotpKey::from_bytes(&reused, &[("core.audit.signing_key", audit)]).unwrap_err();
    assert!(
        error.to_string().contains("core.audit.signing_key"),
        "{error}"
    );
}
