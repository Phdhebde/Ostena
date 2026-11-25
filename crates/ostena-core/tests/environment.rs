//! The `PG*` variables of the environment never change where or as whom the
//! core connects: the test runs itself again in a child process with them
//! set (setting variables in this process would be unsafe).

#![allow(clippy::print_stdout, clippy::unwrap_used, reason = "test helpers")]

use std::path::PathBuf;
use std::process::Command;

use ostena_common::config::DatabaseConfig;
use ostena_core::db;

const PROBE: &str = "OSTENA_ENV_PROBE";

fn config() -> DatabaseConfig {
    DatabaseConfig {
        socket_dir: PathBuf::from("/run/postgresql"),
        port: 5433,
        name: "ostena".into(),
        user: "ostena".into(),
        ..DatabaseConfig::default()
    }
}

/// In the child: prints what the options say.
#[test]
fn probe() {
    if std::env::var_os(PROBE).is_none() {
        return;
    }
    let o = db::options(&config()).unwrap();
    println!(
        "socket={:?} port={} user={} database={:?} application={:?} ssl={:?} options={:?}",
        o.get_socket(),
        o.get_port(),
        o.get_username(),
        o.get_database(),
        o.get_application_name(),
        o.get_ssl_mode(),
        o.get_options(),
    );
    let refused = db::check_environment(|name| std::env::var(name).ok());
    println!("environment={refused:?}");
}

fn run_probe(vars: &[(&str, &str)]) -> String {
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "probe", "--nocapture", "--test-threads=1"])
        .env(PROBE, "1")
        .env_remove("PGPASSWORD")
        .env_remove("PGOPTIONS")
        .envs(vars.iter().copied())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn connection_variables_have_no_effect() {
    let out = run_probe(&[
        ("PGHOST", "evil.example"),
        ("PGHOSTADDR", "192.0.2.1"),
        ("PGPORT", "1"),
        ("PGUSER", "mallory"),
        ("PGDATABASE", "other"),
        ("PGAPPNAME", "spoofed"),
        ("PGSSLMODE", "require"),
        ("PGSSLROOTCERT", "/tmp/ca.pem"),
    ]);
    let expected = format!(
        "socket={:?} port=5433 user=ostena database=Some(\"ostena\") application=Some(\"ostena-core\") ssl=Disable options=None",
        Some(PathBuf::from("/run/postgresql"))
    );
    assert!(out.contains(&expected), "{out}");
    assert!(out.contains("environment=Ok(())"), "{out}");
}

#[test]
fn password_and_server_options_from_the_environment_are_refused() {
    let out = run_probe(&[("PGPASSWORD", "x"), ("PGOPTIONS", "-c search_path=evil")]);
    assert!(
        out.contains("environment=Err(Environment(\"PGPASSWORD, PGOPTIONS\"))"),
        "{out}"
    );
}
