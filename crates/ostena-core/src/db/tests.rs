use std::path::PathBuf;

use ostena_common::config::{DatabaseConfig, DatabaseTcp, Mode};

use super::*;

#[test]
fn socket_options_come_from_the_configuration() {
    let config = DatabaseConfig {
        socket_dir: PathBuf::from("/run/postgresql"),
        port: 5433,
        name: "ostena_db".into(),
        user: "ostena_svc".into(),
        ..DatabaseConfig::default()
    };
    let o = options(&config).unwrap();
    assert_eq!(o.get_socket(), Some(&PathBuf::from("/run/postgresql")));
    assert_eq!(o.get_port(), 5433);
    assert_eq!(o.get_username(), "ostena_svc");
    assert_eq!(o.get_database(), Some("ostena_db"));
    assert_eq!(o.get_application_name(), Some(APPLICATION_NAME));
    assert!(matches!(o.get_ssl_mode(), PgSslMode::Disable));
}

#[test]
fn tcp_options_use_the_host_and_no_socket() {
    let config = DatabaseConfig {
        tcp: Some(DatabaseTcp {
            host: "127.0.0.1".into(),
            password_file: None,
        }),
        ..DatabaseConfig::default()
    };
    let o = options(&config).unwrap();
    assert_eq!(o.get_socket(), None);
    assert_eq!(o.get_host(), "127.0.0.1");
}

#[test]
fn unclearable_variables_are_refused() {
    assert_eq!(check_environment(|_| None), Ok(()));
    let e = check_environment(|name| (name == "PGOPTIONS").then(|| "-c x=y".into())).unwrap_err();
    assert_eq!(e, CoreError::Environment("PGOPTIONS".into()));
    let e = check_environment(|_| Some(String::new())).unwrap_err();
    assert_eq!(e.code(), "CORE-E008");
    assert!(e.to_string().contains("PGPASSWORD, PGOPTIONS"));
}

#[test]
fn server_checks() {
    let prod = Mode::Production;
    assert_eq!(check_server(160_011, Some("peer:ostena"), prod), Ok(()));
    assert_eq!(
        check_server(150_000, Some("peer:ostena"), prod),
        Err(CoreError::ServerVersion(150_000))
    );
    assert_eq!(
        check_server(160_011, Some("scram-sha-256:ostena"), prod),
        Err(CoreError::NotPeer("scram-sha-256".into()))
    );
    assert_eq!(
        check_server(160_011, Some("md5:ostena"), prod),
        Err(CoreError::NotPeer("md5".into()))
    );
    assert_eq!(
        check_server(160_011, None, prod),
        Err(CoreError::NotPeer("trust".into()))
    );
    assert_eq!(check_server(160_011, None, Mode::Development), Ok(()));
    assert_eq!(
        check_server(170_000, Some("scram-sha-256:x"), Mode::Development),
        Ok(())
    );
}
