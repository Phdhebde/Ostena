use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use proptest::prelude::*;
use proptest::sample::select;

use super::validation::{Host, is_local_address, parse_host_port};
use super::*;

fn parse(text: &str) -> Config {
    Config::from_toml_str(text).unwrap()
}

fn production_codes(config: &Config) -> Vec<Code> {
    config
        .validate_for_production()
        .err()
        .map(|v| v.codes())
        .unwrap_or_default()
}

fn has(config: &Config, code: Code) -> bool {
    production_codes(config).contains(&code)
}

// ---------------------------------------------------------------- parsing

#[test]
fn empty_file_gives_safe_defaults() {
    let config = parse("");
    assert_eq!(config, Config::default());
    assert_eq!(config.mode, Mode::Production);
    assert_eq!(
        config.ssh.host_key_verification,
        HostKeyVerification::Strict
    );
    assert_eq!(
        config.rdp.certificate_validation,
        CertificateValidation::Pinned
    );
    assert!(!config.rdp.ntlm_fallback);
    assert_eq!(config.grant.signature_algorithm, "ecdsa-p256-sha256");
    assert_eq!(config.logging.outputs, vec![Output::Stdout {}]);
    assert!(config.validate_for_production().is_ok());
}

#[test]
fn full_example_parses() {
    let config = parse(
        r#"
        mode = "development"
        [ssh]
        host_key_verification = "accept-new"
        [rdp]
        certificate_validation = "pki"
        pki_ca_bundle = "/etc/ostena/rdp-ca.pem"
        password_delegation = true
        ntlm_fallback = false
        [grant]
        signature_algorithm = "ecdsa-p256-sha256"
        [logging]
        level = "debug"
        [[logging.outputs]]
        kind = "file"
        path = "/var/log/ostena/ostena.json"
        [[audit.outputs]]
        kind = "syslog"
        address = "siem.example:6514"
        [[audit.outputs]]
        kind = "syslog-unix"
        path = "/dev/log"
        "#,
    );
    assert_eq!(config.mode, Mode::Development);
    assert_eq!(config.logging.level, LogLevel::Debug);
    assert_eq!(
        config.audit.outputs[0],
        Output::Syslog {
            address: "siem.example:6514".to_owned(),
            transport: Transport::Tls,
        }
    );
    assert!(config.validate().is_ok());
}

#[test]
fn unknown_fields_are_rejected_everywhere() {
    for text in [
        "unknown = 1",
        "[ssh]\nunknown = 1",
        "[rdp]\nunknown = 1",
        "[grant]\nunknown = 1",
        "[logging]\nunknown = 1",
        "[audit]\nunknown = 1",
        "[unknown]",
        "[[logging.outputs]]\nkind = \"stdout\"\nunknown = 1",
        "[[audit.outputs]]\nkind = \"syslog\"\naddress = \"a:1\"\nunknown = 1",
    ] {
        let err = Config::from_toml_str(text).unwrap_err();
        assert_eq!(err.codes(), vec![Code::Parse], "accepted: {text}");
    }
}

#[test]
fn host_key_verification_cannot_be_disabled() {
    let err = Config::from_toml_str("[ssh]\nhost_key_verification = \"off\"").unwrap_err();
    assert_eq!(err.codes(), vec![Code::Parse]);
}

#[test]
fn parse_error_message_is_french_and_coded() {
    let err = Config::from_toml_str("mode = 3").unwrap_err();
    assert!(
        err.to_string()
            .starts_with("[CFG-E002] fichier de configuration invalide")
    );
}

// ---------------------------------------------------------------- codes

#[test]
fn codes_are_stable_and_unique() {
    let expected = [
        "CFG-E001", "CFG-E002", "CFG-V001", "CFG-V002", "CFG-V003", "CFG-V004", "CFG-V005",
        "CFG-P001", "CFG-P002", "CFG-P003", "CFG-P004", "CFG-P005", "CFG-P006", "CFG-V006",
        "CFG-V007", "CFG-V008", "CFG-V009", "CFG-V010", "CFG-P007", "CFG-P008", "CFG-P009",
        "CFG-P010", "CFG-V011",
    ];
    let actual: Vec<_> = Code::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(actual, expected);
    for code in Code::ALL {
        assert_eq!(code.is_weakening(), code.as_str().starts_with("CFG-P"));
    }
}

// ---------------------------------------------------------------- consistency rules

#[test]
fn v001_pki_without_bundle() {
    let config = parse("[rdp]\ncertificate_validation = \"pki\"");
    assert_eq!(
        config.validate().unwrap_err().codes(),
        vec![Code::PkiWithoutCaBundle]
    );
}

#[test]
fn v002_bundle_without_pki() {
    let config = parse("[rdp]\npki_ca_bundle = \"/ca.pem\"");
    assert_eq!(
        config.validate().unwrap_err().codes(),
        vec![Code::CaBundleUnused]
    );
}

#[test]
fn v003_empty_paths() {
    let config = parse(
        "[rdp]\ncertificate_validation = \"pki\"\npki_ca_bundle = \"\"\n\
         [[logging.outputs]]\nkind = \"file\"\npath = \"\"\n\
         [[audit.outputs]]\nkind = \"syslog-unix\"\npath = \"\"",
    );
    assert_eq!(
        config.validate().unwrap_err().codes(),
        vec![Code::EmptyPath, Code::EmptyPath, Code::EmptyPath]
    );
}

#[test]
fn v004_unknown_algorithm() {
    let config = parse("[grant]\nsignature_algorithm = \"md5\"");
    assert_eq!(
        config.validate().unwrap_err().codes(),
        vec![Code::UnknownSignatureAlgorithm]
    );
    // Not reported twice as P004.
    assert!(!has(&config, Code::GrantAlgorithmNotEcdsaP256));
}

#[test]
fn v005_invalid_syslog_address() {
    for address in [
        "",
        "siem",
        "siem:",
        "siem:0",
        "siem:70000",
        ":514",
        "-a:514",
        "a b:514",
    ] {
        let config = Config {
            audit: AuditConfig {
                outputs: vec![Output::Syslog {
                    address: address.to_owned(),
                    transport: Transport::Tls,
                }],
            },
            ..Config::default()
        };
        assert_eq!(
            config.validate().unwrap_err().codes(),
            vec![Code::InvalidSyslogAddress],
            "accepted: {address:?}"
        );
    }
}

// ---------------------------------------------------------------- production rules

#[test]
fn p001_accept_new_host_key() {
    let config = parse("[ssh]\nhost_key_verification = \"accept-new\"");
    assert!(config.validate().is_ok());
    assert_eq!(production_codes(&config), vec![Code::SshHostKeyNotStrict]);
}

#[test]
fn p002_rdp_certificate_not_validated() {
    let config = parse("[rdp]\ncertificate_validation = \"none\"");
    assert!(config.validate().is_ok());
    assert_eq!(
        production_codes(&config),
        vec![Code::RdpCertificateNotValidated]
    );
    let pki = parse("[rdp]\ncertificate_validation = \"pki\"\npki_ca_bundle = \"/ca.pem\"");
    assert!(pki.validate_for_production().is_ok());
}

#[test]
fn p003_ntlm_with_password_delegation() {
    let config = parse("[rdp]\npassword_delegation = true\nntlm_fallback = true");
    assert_eq!(
        production_codes(&config),
        vec![Code::NtlmWithPasswordDelegation]
    );
    let ntlm_only = parse("[rdp]\nntlm_fallback = true");
    assert!(ntlm_only.validate_for_production().is_ok());
}

#[test]
fn p004_grant_not_ecdsa_p256() {
    for algorithm in KNOWN_SIGNATURE_ALGORITHMS
        .iter()
        .filter(|a| **a != GRANT_SIGNATURE_ALGORITHM)
    {
        let config = parse(&format!("[grant]\nsignature_algorithm = \"{algorithm}\""));
        assert!(config.validate().is_ok());
        assert_eq!(
            production_codes(&config),
            vec![Code::GrantAlgorithmNotEcdsaP256]
        );
    }
}

#[test]
fn p005_unencrypted_remote_outputs() {
    let config = parse(
        "[[logging.outputs]]\nkind = \"syslog\"\naddress = \"10.0.0.5:514\"\ntransport = \"udp\"\n\
         [[audit.outputs]]\nkind = \"syslog\"\naddress = \"localhost:514\"\ntransport = \"tcp\"\n\
         [[audit.outputs]]\nkind = \"syslog\"\naddress = \"127.0.0.1:514\"\ntransport = \"udp\"\n\
         [[audit.outputs]]\nkind = \"syslog\"\naddress = \"[::1]:514\"\ntransport = \"tcp\"\n\
         [[audit.outputs]]\nkind = \"syslog\"\naddress = \"10.0.0.5:6514\"\ntransport = \"tls\"",
    );
    let violations = config.validate_for_production().unwrap_err();
    assert_eq!(
        violations.codes(),
        vec![Code::UnencryptedRemoteOutput, Code::UnencryptedRemoteOutput]
    );
    assert!(
        violations.as_slice()[0]
            .message
            .starts_with("logging.outputs[0]")
    );
    // localhost is not resolved, hence treated as remote.
    assert!(
        violations.as_slice()[1]
            .message
            .starts_with("audit.outputs[0]")
    );
}

#[test]
fn all_violations_are_reported_at_once() {
    let config = parse(
        "[ssh]\nhost_key_verification = \"accept-new\"\n\
         [rdp]\ncertificate_validation = \"none\"\npki_ca_bundle = \"/ca.pem\"\n\
         password_delegation = true\nntlm_fallback = true\n\
         [grant]\nsignature_algorithm = \"hmac-sha256\"\n\
         [[audit.outputs]]\nkind = \"syslog\"\naddress = \"siem:514\"\ntransport = \"tcp\"",
    );
    let violations = config.validate_for_production().unwrap_err();
    assert_eq!(
        violations.codes(),
        vec![
            Code::CaBundleUnused,
            Code::SshHostKeyNotStrict,
            Code::RdpCertificateNotValidated,
            Code::NtlmWithPasswordDelegation,
            Code::GrantAlgorithmNotEcdsaP256,
            Code::UnencryptedRemoteOutput,
        ]
    );
    let text = violations.to_string();
    assert!(text.starts_with("configuration refusée (6 problème(s)) :"));
    assert!(text.contains("\n  - [CFG-P001] ssh.host_key_verification"));
}

// ---------------------------------------------------------------- addresses

#[test]
fn host_port_parsing() {
    assert_eq!(
        parse_host_port("siem.example:6514"),
        Some((Host::Name("siem.example".to_owned()), 6514))
    );
    assert_eq!(
        parse_host_port("[::1]:514"),
        Some((Host::Ip("::1".parse().unwrap()), 514))
    );
    assert!(is_local_address("127.10.0.1:514"));
    assert!(is_local_address("[::ffff:127.0.0.1]:514"));
    assert!(!is_local_address("localhost:514"));
    assert!(!is_local_address("[::]:514"));
    assert!(!is_local_address("0.0.0.0:514"));
}

// ---------------------------------------------------------------- CFG-P006

#[test]
fn p006_evaluate() {
    let path = PathBuf::from("/etc/ostena/ostena.toml");
    assert_eq!(
        permissions::evaluate("le fichier", &path, 0, 0o100_640, 999),
        None
    );
    assert_eq!(
        permissions::evaluate("le fichier", &path, 999, 0o100_600, 999),
        None
    );
    let other_owner = permissions::evaluate("le fichier", &path, 1000, 0o100_600, 999).unwrap();
    assert!(other_owner.contains("uid 1000"));
    let group_write = permissions::evaluate("le dossier", &path, 0, 0o040_775, 999).unwrap();
    assert!(group_write.contains("mode 775"));
    assert!(permissions::evaluate("le dossier", &path, 0, 0o041_777, 999).is_some());
}

/// A private directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("ostena-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(dir)
    }

    fn write(&self, content: &str) -> PathBuf {
        let path = self.0.join("ostena.toml");
        std::fs::write(&path, content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn load_missing_file() {
    let err = load(Path::new("/nonexistent/ostena.toml")).unwrap_err();
    assert_eq!(err.codes(), vec![Code::Read]);
    assert!(err.to_string().starts_with("[CFG-E001] impossible de lire"));
}

#[test]
fn load_development_keeps_weakenings() {
    let dir = TempDir::new("load-dev");
    let path = dir.write("mode = \"development\"\n[ssh]\nhost_key_verification = \"accept-new\"");
    let loaded = load(&path).unwrap();
    let mut codes: Vec<_> = loaded.weakenings.iter().map(|w| w.code).collect();
    codes.retain(|c| *c != Code::ConfigFileWritableByOthers); // always present on Windows
    assert_eq!(codes, vec![Code::SshHostKeyNotStrict]);
}

#[test]
fn load_development_still_refuses_inconsistencies() {
    let dir = TempDir::new("load-dev-invalid");
    let path = dir.write("mode = \"development\"\n[rdp]\ncertificate_validation = \"pki\"");
    assert_eq!(
        load(&path).unwrap_err().codes(),
        vec![Code::PkiWithoutCaBundle]
    );
}

#[cfg(unix)]
#[test]
fn load_production_accepts_protected_file() {
    let dir = TempDir::new("load-prod-ok");
    let path = dir.write("");
    let loaded = load(&path).unwrap();
    assert_eq!(loaded.weakenings, Vec::new());
}

#[cfg(unix)]
#[test]
fn load_production_refuses_writable_file_and_directory() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("load-prod-p006");
    let path = dir.write("");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert_eq!(
        load(&path).unwrap_err().codes(),
        vec![Code::ConfigFileWritableByOthers]
    );

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o777)).unwrap();
    let err = load(&path).unwrap_err();
    assert_eq!(err.codes(), vec![Code::ConfigFileWritableByOthers]);
    assert!(err.to_string().contains("le dossier"));
}

#[cfg(not(unix))]
#[test]
fn load_production_fails_closed_on_windows() {
    let dir = TempDir::new("load-prod-windows");
    let path = dir.write("");
    let err = load(&path).unwrap_err();
    assert_eq!(err.codes(), vec![Code::ConfigFileWritableByOthers]);
    assert!(err.to_string().contains("ostena-platform"));
}

#[test]
fn production_reports_p006_with_other_violations() {
    let dir = TempDir::new("load-prod-all");
    let path = dir.write(
        "[ssh]\nhost_key_verification = \"accept-new\"\n[rdp]\ncertificate_validation = \"pki\"",
    );
    let codes = load(&path).unwrap_err().codes();
    assert!(codes.starts_with(&[Code::PkiWithoutCaBundle, Code::SshHostKeyNotStrict]));
}

// ---------------------------------------------------------------- properties

fn host_key() -> impl Strategy<Value = HostKeyVerification> {
    prop_oneof![
        Just(HostKeyVerification::Strict),
        Just(HostKeyVerification::AcceptNew)
    ]
}

fn certificate_validation() -> impl Strategy<Value = CertificateValidation> {
    prop_oneof![
        Just(CertificateValidation::Pinned),
        Just(CertificateValidation::Pki),
        Just(CertificateValidation::Disabled),
    ]
}

fn path() -> impl Strategy<Value = PathBuf> {
    prop_oneof![Just(String::new()), "/[a-z]{1,8}(/[a-z]{1,8}){0,2}"].prop_map(PathBuf::from)
}

fn algorithm() -> impl Strategy<Value = String> {
    prop_oneof![
        select(KNOWN_SIGNATURE_ALGORITHMS).prop_map(str::to_owned),
        "[a-z0-9-]{0,16}",
    ]
}

fn transport() -> impl Strategy<Value = Transport> {
    prop_oneof![
        Just(Transport::Tls),
        Just(Transport::Tcp),
        Just(Transport::Udp)
    ]
}

fn address() -> impl Strategy<Value = String> {
    prop_oneof![
        (any::<IpAddr>(), any::<u16>())
            .prop_map(|(ip, port)| SocketAddr::new(ip, port).to_string()),
        ("[a-z][a-z0-9-]{0,10}(\\.[a-z]{1,6}){0,2}", 1..=u16::MAX)
            .prop_map(|(host, port)| format!("{host}:{port}")),
        ".{0,20}",
    ]
}

fn output() -> impl Strategy<Value = Output> {
    prop_oneof![
        Just(Output::Stdout {}),
        path().prop_map(|path| Output::File { path }),
        (address(), transport())
            .prop_map(|(address, transport)| Output::Syslog { address, transport }),
        path().prop_map(|path| Output::SyslogUnix { path }),
    ]
}

fn config() -> impl Strategy<Value = Config> {
    (
        prop_oneof![Just(Mode::Production), Just(Mode::Development)],
        host_key(),
        certificate_validation(),
        proptest::option::of(path()),
        any::<bool>(),
        any::<bool>(),
        algorithm(),
        proptest::collection::vec(output(), 0..4),
        proptest::collection::vec(output(), 0..4),
    )
        .prop_map(
            |(mode, hk, cv, bundle, delegation, ntlm, algorithm, logging, audit)| Config {
                mode,
                ssh: SshConfig {
                    host_key_verification: hk,
                },
                rdp: RdpConfig {
                    certificate_validation: cv,
                    pki_ca_bundle: bundle,
                    password_delegation: delegation,
                    ntlm_fallback: ntlm,
                },
                grant: GrantConfig {
                    signature_algorithm: algorithm,
                },
                logging: LoggingConfig {
                    level: LogLevel::Info,
                    outputs: logging,
                },
                audit: AuditConfig { outputs: audit },
                agent: None,
            },
        )
}

fn all_outputs(c: &Config) -> impl Iterator<Item = &Output> {
    c.logging.outputs.iter().chain(&c.audit.outputs)
}

proptest! {
    #[test]
    fn prop_p001_iff_accept_new(c in config()) {
        prop_assert_eq!(
            has(&c, Code::SshHostKeyNotStrict),
            c.ssh.host_key_verification == HostKeyVerification::AcceptNew
        );
    }

    #[test]
    fn prop_p002_iff_validation_disabled(c in config()) {
        prop_assert_eq!(
            has(&c, Code::RdpCertificateNotValidated),
            c.rdp.certificate_validation == CertificateValidation::Disabled
        );
    }

    #[test]
    fn prop_p003_iff_ntlm_and_delegation(c in config()) {
        prop_assert_eq!(
            has(&c, Code::NtlmWithPasswordDelegation),
            c.rdp.password_delegation && c.rdp.ntlm_fallback
        );
    }

    #[test]
    fn prop_p004_iff_known_non_ecdsa_p256(c in config()) {
        let a = c.grant.signature_algorithm.as_str();
        prop_assert_eq!(
            has(&c, Code::GrantAlgorithmNotEcdsaP256),
            a != GRANT_SIGNATURE_ALGORITHM && KNOWN_SIGNATURE_ALGORITHMS.contains(&a)
        );
    }

    #[test]
    fn prop_p005_iff_clear_text_remote_syslog(c in config()) {
        let expected = all_outputs(&c).any(|o| matches!(
            o,
            Output::Syslog { address, transport }
                if *transport != Transport::Tls && !is_local_address(address)
        ));
        prop_assert_eq!(has(&c, Code::UnencryptedRemoteOutput), expected);
    }

    #[test]
    fn prop_v001_iff_pki_without_bundle(c in config()) {
        let codes = c.validate().err().map(|v| v.codes()).unwrap_or_default();
        prop_assert_eq!(
            codes.contains(&Code::PkiWithoutCaBundle),
            c.rdp.certificate_validation == CertificateValidation::Pki && c.rdp.pki_ca_bundle.is_none()
        );
        prop_assert_eq!(
            codes.contains(&Code::CaBundleUnused),
            c.rdp.certificate_validation != CertificateValidation::Pki && c.rdp.pki_ca_bundle.is_some()
        );
    }

    #[test]
    fn prop_v004_iff_unknown_algorithm(c in config()) {
        let codes = c.validate().err().map(|v| v.codes()).unwrap_or_default();
        prop_assert_eq!(
            codes.contains(&Code::UnknownSignatureAlgorithm),
            !KNOWN_SIGNATURE_ALGORITHMS.contains(&c.grant.signature_algorithm.as_str())
        );
    }

    #[test]
    fn prop_levels_do_not_mix(c in config()) {
        let consistency = c.validate().err().map(|v| v.codes()).unwrap_or_default();
        prop_assert!(consistency.iter().all(|code| !code.is_weakening()));
        prop_assert!(c.weakenings().iter().all(|w| w.code.is_weakening()));
        let mut expected = consistency;
        expected.extend(c.weakenings().iter().map(|w| w.code));
        prop_assert_eq!(production_codes(&c), expected);
    }

    #[test]
    fn prop_validation_ignores_mode(c in config()) {
        let other = Config {
            mode: match c.mode {
                Mode::Production => Mode::Development,
                Mode::Development => Mode::Production,
            },
            ..c.clone()
        };
        prop_assert_eq!(c.validate(), other.validate());
        prop_assert_eq!(c.weakenings(), other.weakenings());
    }

    #[test]
    fn prop_only_literal_loopback_is_local(ip in any::<IpAddr>(), port in 1..=u16::MAX) {
        let address = SocketAddr::new(ip, port).to_string();
        prop_assert_eq!(is_local_address(&address), ip.to_canonical().is_loopback());
    }

    #[test]
    fn prop_names_are_never_local(host in "[a-z][a-z0-9-]{0,10}(\\.[a-z]{1,6}){0,2}", port in 1..=u16::MAX) {
        let address = format!("{host}:{port}");
        prop_assert!(!is_local_address(&address));
    }

    #[test]
    fn prop_parsing_never_panics(text in ".{0,200}") {
        let _ = Config::from_toml_str(&text);
    }

    #[test]
    fn prop_p006_iff_foreign_owner_or_shared_write(
        owner in prop_oneof![Just(0u32), Just(999u32), any::<u32>()],
        mode in 0u32..0o10_000,
        service in prop_oneof![Just(0u32), Just(999u32)],
    ) {
        let refused = permissions::evaluate("le fichier", Path::new("/x"), owner, mode, service).is_some();
        let expected = (owner != 0 && owner != service) || mode & 0o022 != 0;
        prop_assert_eq!(refused, expected);
    }
}

// ---------------------------------------------------------------- agent

const AGENT: &str = r#"
[agent]
gateway_group = "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6"
core_address = "core.corp.example:8443"
tls_certificate = "/etc/ostena/agent.crt"
tls_private_key = "/etc/ostena/agent.key"
tls_core_ca = "/etc/ostena/core-ca.pem"
replay_journal = "/var/lib/ostena/replay.journal"

[[agent.scope.allow]]
networks = ["10.0.0.0/8"]
ports = ["22", "3389"]

[[agent.infrastructure]]
role = "core"
addresses = ["core.corp.example", "10.0.0.5"]

[[agent.infrastructure]]
role = "postgresql"
addresses = ["10.0.0.0/30"]
"#;

fn agent_with(replace: &str, by: &str) -> Config {
    parse(&AGENT.replace(replace, by))
}

fn agent_codes(c: &Config) -> Vec<Code> {
    c.validate().err().map(|v| v.codes()).unwrap_or_default()
}

#[test]
fn agent_section_parses() {
    let c = parse(AGENT);
    assert!(c.validate_for_production().is_ok());
    let a = c.agent.as_ref().unwrap();
    assert_eq!(a.shutdown_grace_secs, 30);
    assert_eq!(a.infrastructure.len(), 2);
    assert_eq!(a.scope.allow[0].ports, ["22", "3389"]);
    let policy = a.scope_policy();
    assert_eq!(policy.gateway_group, a.gateway_group);
    let workers = a.worker_threads();
    assert!((1..=4).contains(&workers));
}

#[test]
fn agent_unknown_fields_are_rejected() {
    for (anchor, extra) in [
        ("[agent]\n", "[agent]\nunknown = 1\n"),
        (
            "[[agent.scope.allow]]\n",
            "[[agent.scope.allow]]\nunknown = 1\n",
        ),
        (
            "role = \"postgresql\"\n",
            "role = \"postgresql\"\nunknown = 1\n",
        ),
        ("role = \"postgresql\"", "role = \"mysql\""),
    ] {
        let text = AGENT.replacen(anchor, extra, 1);
        assert_eq!(
            Config::from_toml_str(&text).unwrap_err().codes(),
            vec![Code::Parse],
            "{extra}"
        );
    }
}

#[test]
fn v006_gateway_group() {
    let c = agent_with("2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6", "dc-paris");
    assert_eq!(agent_codes(&c), vec![Code::AgentGatewayGroup]);
}

#[test]
fn v007_core_address() {
    for bad in [
        "core.corp.example",
        "core.corp.example:0",
        "https://core:443",
    ] {
        let c = agent_with("core.corp.example:8443", bad);
        assert_eq!(agent_codes(&c), vec![Code::AgentCoreAddress], "{bad}");
    }
}

#[test]
fn v003_v008_paths() {
    let c = agent_with("/etc/ostena/agent.key", "agent.key");
    assert_eq!(agent_codes(&c), vec![Code::RelativePath]);
    let c = agent_with("/var/lib/ostena/replay.journal", "");
    assert_eq!(agent_codes(&c), vec![Code::EmptyPath]);
}

#[test]
fn v009_bounds() {
    let c = agent_with(
        "[agent]\n",
        "[agent]\nshutdown_grace_secs = 0\nworker_threads = 65\n",
    );
    assert_eq!(agent_codes(&c), vec![Code::AgentBounds, Code::AgentBounds]);
}

#[test]
fn v010_infrastructure() {
    let c = agent_with("addresses = [\"10.0.0.0/30\"]", "addresses = []");
    assert_eq!(agent_codes(&c), vec![Code::AgentInfrastructure]);
    let c = agent_with("\"10.0.0.0/30\"", "\"http://db\"");
    assert_eq!(agent_codes(&c), vec![Code::AgentInfrastructure]);
    let c = agent_with(
        "[[agent.scope.allow]]\n",
        "[[agent.scope.infrastructure]]\nrole = \"core\"\nnetworks = [\"10.0.0.5\"]\n\n[[agent.scope.allow]]\n",
    );
    assert_eq!(agent_codes(&c), vec![Code::AgentInfrastructure]);
    let c = agent_with(
        "[[agent.scope.allow]]\n",
        "[agent.scope]\ngateway_group = \"other\"\n\n[[agent.scope.allow]]\n",
    );
    assert_eq!(agent_codes(&c), vec![Code::AgentInfrastructure]);
}

#[test]
fn p007_core_ca_required_in_production() {
    let c = agent_with("tls_core_ca = \"/etc/ostena/core-ca.pem\"\n", "");
    assert!(c.validate().is_ok());
    assert_eq!(production_codes(&c), vec![Code::CoreCaMissing]);
}

/// Refuses the paths it is told to refuse.
struct FakeChecker {
    writable: Vec<PathBuf>,
    exposed: Vec<PathBuf>,
}

impl PermissionChecker for FakeChecker {
    fn not_writable_by_others(&self, path: &Path) -> Result<(), String> {
        if self.writable.iter().any(|p| p == path) {
            Err("modifiable".into())
        } else {
            Ok(())
        }
    }

    fn private(&self, path: &Path) -> Result<(), String> {
        if self.exposed.iter().any(|p| p == path) {
            Err("lisible".into())
        } else {
            Ok(())
        }
    }
}

#[test]
fn p006_p008_p009_through_the_injected_checker() {
    let dir = TempDir::new("agent-perms");
    let path = dir.write(AGENT);
    let ok = FakeChecker {
        writable: vec![],
        exposed: vec![],
    };
    assert_eq!(load_with(&path, &ok).unwrap().weakenings, Vec::new());

    let bad = FakeChecker {
        writable: vec![path.clone(), PathBuf::from("/var/lib/ostena")],
        exposed: vec![PathBuf::from("/etc/ostena/agent.key")],
    };
    let codes = load_with(&path, &bad).unwrap_err().codes();
    assert_eq!(
        codes,
        vec![
            Code::ConfigFileWritableByOthers,
            Code::PrivateKeyExposed,
            Code::ReplayJournalExposed
        ]
    );
}

#[test]
fn private_key_is_read_into_a_secret() {
    let dir = TempDir::new("agent-key");
    let key = dir.0.join("agent.key");
    std::fs::write(&key, b"-----BEGIN PRIVATE KEY-----").unwrap();
    let mut c = parse(AGENT);
    let agent = c.agent.as_mut().unwrap();
    agent.tls_private_key = key;
    let secret = agent.read_private_key().unwrap();
    // SECRET-EXPOSURE: test checks the loaded bytes.
    #[expect(clippy::disallowed_methods)]
    let bytes = secret.expose_secret();
    assert_eq!(bytes, b"-----BEGIN PRIVATE KEY-----");
}

#[test]
fn private_rule_on_unix_modes() {
    let p = PathBuf::from("/etc/ostena/agent.key");
    assert_eq!(
        permissions::evaluate_private("le fichier", &p, 0, 0o100_600, 999),
        None
    );
    assert_eq!(
        permissions::evaluate_private("le fichier", &p, 999, 0o100_400, 999),
        None
    );
    assert!(
        permissions::evaluate_private("le fichier", &p, 0, 0o100_640, 999)
            .unwrap()
            .contains("chmod 600")
    );
    assert!(permissions::evaluate_private("le fichier", &p, 1000, 0o100_600, 999).is_some());
}

proptest! {
    #[test]
    fn prop_v009_iff_out_of_bounds(grace in 0u64..1_000, workers in proptest::option::of(0usize..100)) {
        let mut c = parse(AGENT);
        let a = c.agent.as_mut().unwrap();
        a.shutdown_grace_secs = grace;
        a.worker_threads = workers;
        let n = agent_codes(&c).iter().filter(|x| **x == Code::AgentBounds).count();
        let expected = usize::from(!(1..=300).contains(&grace)) + usize::from(workers.is_some_and(|w| !(1..=64).contains(&w)));
        prop_assert_eq!(n, expected);
    }
}

#[test]
fn v011_control_endpoint() {
    for ok in [
        r"\\.\pipe\ostena-dev",
        "/run/ostena/agent.sock",
        "/tmp/ostena-dev/agent.sock",
    ] {
        let c = agent_with(
            "[agent]\n",
            &format!("[agent]\ncontrol_endpoint = '{ok}'\n"),
        );
        assert_eq!(agent_codes(&c), vec![], "{ok}");
    }
    for bad in [
        "agent.sock",
        r"\\.\pipe\",
        r"\\server\pipe\x",
        r"\\.\pipe\a\b",
        r"C:\agent.sock",
    ] {
        let c = agent_with(
            "[agent]\n",
            &format!("[agent]\ncontrol_endpoint = '{bad}'\n"),
        );
        assert_eq!(agent_codes(&c), vec![Code::ControlEndpoint], "{bad}");
    }
}
