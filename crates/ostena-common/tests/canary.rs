//! Canary test: a secret with a recognisable value goes through every logging
//! path we protect, and the value must never appear in the JSON output.
//!
//! The last test pins down the known limit documented in ADR-0003.

#![allow(clippy::unwrap_used, reason = "test helpers outside #[test] functions")]

use std::fmt;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use ostena_common::config::Config;
use ostena_common::logging::JsonLayer;
use ostena_common::secret::SecretString;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::Registry;

const CANARY: &str = "CANARY-7f3a9c1e-do-not-log";

#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Write for Buffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Runs `f` under the JSON layer and returns everything written.
fn capture(f: impl FnOnce()) -> String {
    let buffer = Buffer::default();
    let subscriber = Registry::default()
        .with(LevelFilter::TRACE)
        .with(JsonLayer::new(vec![Box::new(buffer.clone())]));
    tracing::subscriber::with_default(subscriber, f);
    let bytes = buffer.0.lock().unwrap().clone();
    String::from_utf8(bytes).unwrap()
}

fn canary() -> SecretString {
    SecretString::from(CANARY.to_owned())
}

/// A type holding a secret: it cannot derive `Debug` (see tests/ui) and must
/// redact the secret in its hand-written implementation.
struct Credential {
    user: String,
    password: SecretString,
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("user", &self.user)
            .field("password", &self.password.redacted())
            .finish()
    }
}

#[test]
fn exposed_secret_under_sensitive_field_name_is_redacted() {
    let secret = canary();
    let out = capture(|| {
        // SECRET-EXPOSURE: canary test, the value must be redacted by field name.
        #[expect(clippy::disallowed_methods)]
        let exposed = secret.expose_secret();
        tracing::info!(password = exposed, "event field");
        let span = tracing::info_span!("login", token = exposed);
        let _guard = span.enter();
        tracing::info!("inside span");
    });
    assert!(!out.contains(CANARY), "canary leaked: {out}");
    assert!(out.contains("[REDACTED]"));
}

#[test]
fn secret_inside_struct_under_harmless_field_name_is_redacted() {
    let credential = Credential {
        user: "alice".to_owned(),
        password: canary(),
    };
    let out = capture(|| {
        tracing::info!(account = ?credential, "debug of a struct holding a secret");
    });
    assert!(out.contains("alice"));
    assert!(!out.contains(CANARY), "canary leaked: {out}");
}

#[test]
fn config_debug_never_contains_the_secret() {
    // The configuration holds no secret by design: secrets are referenced by
    // path. A Secret field could not be added without breaking `derive(Debug)`.
    let config = Config::from_toml_str(
        "[rdp]\ncertificate_validation = \"pki\"\npki_ca_bundle = \"/etc/ostena/ca.pem\"",
    )
    .unwrap();
    let secret = canary();
    let out = capture(|| {
        tracing::info!(config = ?config, "configuration loaded");
        drop(secret);
    });
    assert!(out.contains("ca.pem"));
    assert!(!out.contains(CANARY), "canary leaked: {out}");
}

/// Known limit (ADR-0003): once taken out with `expose_secret()`, a value
/// logged under a harmless name is written in clear. The only safeguards are
/// the reviewed `SECRET-EXPOSURE` justification and `cargo xtask check-secrets`.
/// If this test starts failing, the protection improved: update the ADR.
#[test]
fn known_limit_exposed_value_under_harmless_name_is_not_redacted() {
    let secret = canary();
    let out = capture(|| {
        // SECRET-EXPOSURE: demonstrates the documented limit of redaction.
        #[expect(clippy::disallowed_methods)]
        let exposed = secret.expose_secret();
        tracing::info!(note = exposed);
    });
    assert!(out.contains(CANARY));
}
