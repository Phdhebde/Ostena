#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::path::{Path, PathBuf};

use ostena_crypto::pki::{RootAuthority, Validity};

use super::*;

const GROUP: &str = "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6";

fn root_pem(name: &str) -> (String, String) {
    let root = RootAuthority::generate(
        name,
        Validity {
            not_before: 1_700_000_000,
            not_after: 4_000_000_000,
        },
    )
    .unwrap();
    let fingerprint = hex(&tls::fingerprint(root.trust_anchor().certificate()));
    (root.certificate_pem(), fingerprint)
}

struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("ostena-setup-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn layout(&self) -> Layout {
        Layout {
            root: self.0.join("etc/root.pem"),
            state: self.0.join("state"),
            log_file: Some(self.0.join("state/agent.log")),
        }
    }

    fn config(&self) -> PathBuf {
        self.0.join("etc/ostena.toml")
    }

    fn file(&self, name: &str, text: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, text).unwrap();
        path
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn args(dir: &Dir, root: Option<PathBuf>, fingerprint: Option<&str>) -> SetupArgs {
    SetupArgs {
        config: dir.config(),
        core_address: Some("core.example.test:8443".into()),
        gateway_group: Some(GROUP.into()),
        root_ca: root,
        root_fingerprint: fingerprint.map(str::to_owned),
        timeout: 1,
        ..SetupArgs::default()
    }
}

fn run(args: &SetupArgs, layout: &Layout) -> (Result<(), String>, Vec<String>) {
    let mut said = Vec::new();
    let result = prepare(args, layout, &mut |m| said.push(m.to_owned()));
    (result, said)
}

#[test]
fn fingerprints_as_written_in_a_record() {
    let hex64 = "ab".repeat(32);
    let expected = [0xab; 32];
    assert_eq!(parse_fingerprint(&hex64).unwrap(), expected);
    assert_eq!(parse_fingerprint(&hex64.to_uppercase()).unwrap(), expected);
    assert_eq!(
        parse_fingerprint(&format!("SHA256:{hex64}")).unwrap(),
        expected
    );
    let colons = vec!["AB"; 32].join(":");
    assert_eq!(parse_fingerprint(&colons).unwrap(), expected);
    let spaced = vec!["ab"; 32].join(" ");
    assert_eq!(
        parse_fingerprint(&format!("  {spaced} ")).unwrap(),
        expected
    );
    for bad in [
        "",
        "ab",
        &"ab".repeat(33),
        &"zz".repeat(32),
        &"é".repeat(32),
    ] {
        assert!(parse_fingerprint(bad).is_err(), "{bad}");
    }
}

#[test]
fn toml_strings_are_escaped() {
    assert_eq!(
        toml_string(r"C:\ProgramData\Ostena"),
        r#""C:\\ProgramData\\Ostena""#
    );
    assert_eq!(toml_string("a\"b\n"), r#""a\"b\u000A""#);
    // A value cannot add a key.
    let text = render_config(
        "core:8443\"\nmode = \"development",
        GROUP,
        None,
        &Layout {
            root: PathBuf::from("/etc/ostena/root.pem"),
            state: PathBuf::from("/var/lib/ostena"),
            log_file: None,
        },
    );
    assert!(text.is_err(), "an invalid core address must be refused");
}

#[test]
fn new_configuration_is_production_and_valid() {
    let layout = Layout {
        root: PathBuf::from("/etc/ostena/root.pem"),
        state: PathBuf::from("/var/lib/ostena"),
        log_file: None,
    };
    let text = render_config(
        "core.example.test:8443",
        GROUP,
        Some("core.example.test:9444"),
        &layout,
    )
    .unwrap();
    let config = ostena_common::config::Config::from_toml_str(&text).unwrap();
    assert_eq!(config.mode, ostena_common::config::Mode::Production);
    let agent = config.agent.unwrap();
    assert_eq!(agent.gateway_group, GROUP);
    assert_eq!(
        agent.tls_private_key,
        Path::new("/var/lib/ostena/agent.key")
    );
    assert_eq!(
        agent.tls_core_ca.as_deref(),
        Some(Path::new("/etc/ostena/root.pem"))
    );
    assert_eq!(
        agent.enrollment_address.as_deref(),
        Some("core.example.test:9444")
    );
    // Dial-back only: no listening SSH server.
    assert!(agent.ssh.is_none());
    assert!(render_config("core.example.test:8443", "not-a-uuid", None, &layout).is_err());
}

#[test]
fn installs_root_and_configuration_then_is_idempotent() {
    let dir = Dir::new("fresh");
    let layout = dir.layout();
    let (pem, fingerprint) = root_pem("Root A");
    let root = dir.file("given.pem", &pem);
    let args = args(&dir, Some(root), Some(&fingerprint));

    let (result, said) = run(&args, &layout);
    result.unwrap();
    assert_eq!(fs::read_to_string(&layout.root).unwrap(), pem);
    // The service account reads the root: public, unlike the configuration.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&layout.root), 0o644);
        assert_eq!(mode(&dir.config()), 0o640);
    }
    let config = agent::read(&dir.config()).unwrap();
    let agent = config.agent.unwrap();
    assert_eq!(agent.core_address, "core.example.test:8443");
    assert_eq!(agent.tls_core_ca.as_deref(), Some(layout.root.as_path()));
    assert!(said.iter().any(|m| m.contains("non enrôlé")), "{said:?}");

    // Again (repair, upgrade): nothing is rewritten.
    let before = fs::read(dir.config()).unwrap();
    let (result, said) = run(&args, &layout);
    result.unwrap();
    assert_eq!(fs::read(dir.config()).unwrap(), before);
    assert!(said.iter().any(|m| m.contains("conservée")), "{said:?}");
}

#[test]
fn refuses_a_root_with_another_fingerprint() {
    let dir = Dir::new("mismatch");
    let layout = dir.layout();
    let (pem, _) = root_pem("Root A");
    let (_, other) = root_pem("Root B");
    let root = dir.file("given.pem", &pem);
    let (result, _) = run(&args(&dir, Some(root.clone()), Some(&other)), &layout);
    let error = result.unwrap_err();
    assert!(error.contains("empreinte"), "{error}");
    assert!(
        !dir.config().exists() && !layout.root.exists(),
        "nothing written"
    );

    // A root without a fingerprint is refused too.
    let (result, _) = run(&args(&dir, Some(root), None), &layout);
    assert!(result.unwrap_err().contains("--root-fingerprint"));
}

#[test]
fn never_replaces_a_different_root() {
    let dir = Dir::new("replace");
    let layout = dir.layout();
    let (pem_a, fp_a) = root_pem("Root A");
    let (pem_b, fp_b) = root_pem("Root B");
    run(
        &args(&dir, Some(dir.file("a.pem", &pem_a)), Some(&fp_a)),
        &layout,
    )
    .0
    .unwrap();
    let (result, _) = run(
        &args(&dir, Some(dir.file("b.pem", &pem_b)), Some(&fp_b)),
        &layout,
    );
    assert!(result.unwrap_err().contains("autre racine"));
    assert_eq!(fs::read_to_string(&layout.root).unwrap(), pem_a);
    // The root in place is checked against a fingerprint given alone.
    let (result, _) = run(&args(&dir, None, Some(&fp_b)), &layout);
    assert!(result.unwrap_err().contains("empreinte"));
    run(&args(&dir, None, Some(&fp_a)), &layout).0.unwrap();
}

#[test]
fn existing_configuration_must_agree() {
    let dir = Dir::new("agree");
    let layout = dir.layout();
    let (pem, fp) = root_pem("Root A");
    run(
        &args(&dir, Some(dir.file("a.pem", &pem)), Some(&fp)),
        &layout,
    )
    .0
    .unwrap();
    let mut other = args(&dir, None, None);
    other.core_address = Some("elsewhere.example.test:8443".into());
    let error = run(&other, &layout).0.unwrap_err();
    assert!(error.contains("core_address"), "{error}");
    // Parameters left out: the configuration in place is used as is.
    let mut bare = args(&dir, None, None);
    bare.core_address = None;
    bare.gateway_group = None;
    run(&bare, &layout).0.unwrap();
}

#[test]
fn new_configuration_needs_its_parameters_and_a_root() {
    let dir = Dir::new("missing");
    let layout = dir.layout();
    let mut no_core = args(&dir, None, None);
    no_core.core_address = None;
    assert!(
        run(&no_core, &layout)
            .0
            .unwrap_err()
            .contains("--core-address")
    );
    let error = run(&args(&dir, None, None), &layout).0.unwrap_err();
    assert!(error.contains("racine"), "{error}");
    assert!(!dir.config().exists());
}

#[test]
fn empty_values_count_as_absent() {
    let args = SetupArgs {
        core_address: Some(String::new()),
        gateway_group: Some("  ".into()),
        root_ca: Some(PathBuf::new()),
        token_file: Some(PathBuf::new()),
        root_fingerprint: Some(String::new()),
        log: Some(PathBuf::new()),
        ..SetupArgs::default()
    }
    .normalized();
    assert!(args.core_address.is_none() && args.gateway_group.is_none());
    assert!(args.root_ca.is_none() && args.token_file.is_none());
    assert!(args.root_fingerprint.is_none() && args.log.is_none());
}
