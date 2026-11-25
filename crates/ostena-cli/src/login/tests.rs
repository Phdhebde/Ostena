use super::*;

/// A fresh directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "ostena-login-{}-{name}-{}",
            std::process::id(),
            unix_now()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn response() -> LoginResponse {
    LoginResponse {
        protocol: 1,
        login_session: "0b8f4c1e-7a52-4d0e-9f3b-2c6d1a9e8f70".into(),
        user: "5a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d".into(),
        certificate: "ecdsa-sha2-nistp256-cert-v01@openssh.com AAAA x".into(),
        valid_after: 1_800_000_000,
        valid_before: 1_800_028_800,
        host_ca: "ecdsa-sha2-nistp256 AAAAE2Vj ostena-host-ca".into(),
        ssh_hosts: vec!["bastion.example".into(), "*.bastion.example".into()],
        ssh_port: 2222,
    }
}

#[test]
fn addresses() {
    assert_eq!(
        split_address("core.example").unwrap(),
        ("core.example".into(), DEFAULT_PORT)
    );
    assert_eq!(
        split_address("core.example:9000").unwrap(),
        ("core.example".into(), 9000)
    );
    assert_eq!(
        split_address("[2001:db8::1]:9000").unwrap(),
        ("2001:db8::1".into(), 9000)
    );
    assert_eq!(
        split_address("[2001:db8::1]").unwrap(),
        ("2001:db8::1".into(), DEFAULT_PORT)
    );
    for bad in [
        "",
        ":9000",
        "core:0",
        "core:x",
        "core:70000",
        "2001:db8::1",
        "[2001:db8::1",
        "[::1]x",
        "co re:1",
        "core\n:1",
    ] {
        assert!(split_address(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn settings_round_trip_through_toml() {
    let settings = Settings {
        core: "core.example:8445".into(),
        user: "jdupont".into(),
    };
    let back: Settings = toml::from_str(&settings.to_toml()).unwrap();
    assert_eq!(back, settings);
    // Quotes and backslashes survive.
    let odd = Settings {
        core: "a\"b\\c".into(),
        user: "x".into(),
    };
    assert_eq!(toml::from_str::<Settings>(&odd.to_toml()).unwrap(), odd);
    assert!(toml::from_str::<Settings>("core = \"a\"\nuser = \"b\"\nother = 1\n").is_err());
}

#[test]
fn ssh_fragment_and_known_hosts() {
    let dir = Path::new("/home/jdupont/.ostena");
    let text = ssh_config(dir, &response()).unwrap();
    assert!(text.contains("Host bastion.example *.bastion.example\n"));
    assert!(text.contains("    Port 2222\n"));
    // The paths as the platform joins them (OpenSSH for Windows reads
    // both separators), each quoted, one per line.
    for (option, name) in [("IdentityFile", KEY), ("UserKnownHostsFile", KNOWN_HOSTS)] {
        let path = dir.join(name);
        let line = format!("    {option} \"{}\"\n", path.display());
        assert!(text.contains(&line), "{line:?} absent : {text}");
    }
    #[cfg(unix)]
    {
        assert!(text.contains("    IdentityFile \"/home/jdupont/.ostena/id_ecdsa\"\n"));
        assert!(text.contains("    UserKnownHostsFile \"/home/jdupont/.ostena/known_hosts\"\n"));
    }
    assert!(text.contains("    StrictHostKeyChecking yes\n"));
    assert!(text.contains("    ForwardAgent no\n"));
    // The certificate is found next to the key (`id_ecdsa-cert.pub`).
    assert!(!text.contains("CertificateFile"), "{text}");
    assert_eq!(CERTIFICATE, format!("{KEY}-cert.pub"));
    assert!(text.contains("2027-01-15 16:00:00 UTC"), "{text}");
    assert_eq!(
        known_hosts(&response()),
        "@cert-authority [bastion.example]:2222,[*.bastion.example]:2222 \
         ecdsa-sha2-nistp256 AAAAE2Vj ostena-host-ca\n"
    );
    let mut on_22 = response();
    on_22.ssh_port = 22;
    assert!(known_hosts(&on_22).starts_with("@cert-authority bastion.example,*.bastion.example "));
}

#[test]
fn include_is_added_once_at_the_top() {
    let scratch = Scratch::new("include");
    let ssh = scratch.0.join("ssh");
    let dir = scratch.0.join("ostena");
    install_include_in(&ssh, &dir).unwrap();
    let line = include_line(&dir).unwrap();
    assert_eq!(
        fs::read_to_string(ssh.join("config")).unwrap(),
        format!("{line}\n")
    );

    fs::write(ssh.join("config"), "Host other\n    User me\n").unwrap();
    install_include_in(&ssh, &dir).unwrap();
    install_include_in(&ssh, &dir).unwrap();
    assert_eq!(
        fs::read_to_string(ssh.join("config")).unwrap(),
        format!("{line}\nHost other\n    User me\n")
    );
}

#[cfg(unix)]
#[test]
fn include_refuses_a_linked_config() {
    let scratch = Scratch::new("include-link");
    let ssh = scratch.0.join("ssh");
    let dir = scratch.0.join("ostena");
    fs::create_dir_all(&ssh).unwrap();
    let real = scratch.0.join("dotfiles-config");
    fs::write(&real, "Host other\n").unwrap();
    std::os::unix::fs::symlink(&real, ssh.join("config")).unwrap();
    let refused = install_include_in(&ssh, &dir).unwrap_err().to_string();
    assert!(refused.contains("lien symbolique"), "{refused}");
    assert!(refused.contains("Include "), "{refused}");
    // Neither the link nor its target changed.
    assert!(
        fs::symlink_metadata(ssh.join("config"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_to_string(&real).unwrap(), "Host other\n");
}

#[test]
fn quoting_refuses_what_ssh_config_would_misread() {
    assert_eq!(
        quoted(Path::new("/home/jdupont/.ostena/id_ecdsa")).unwrap(),
        "\"/home/jdupont/.ostena/id_ecdsa\""
    );
    // A Windows path keeps its single backslashes.
    assert_eq!(
        quoted(Path::new(r"C:\Users\jdupont\.ostena\id_ecdsa")).unwrap(),
        r#""C:\Users\jdupont\.ostena\id_ecdsa""#
    );
    for bad in [
        "/home/a\"b/id",
        "/home/a\nb/id",
        "/home/a\tb/id",
        "/home/a\u{7f}b/id",
        r"\\server\share\id",
        r"C:\Users\it's\'id",
        r"C:\Users\dir\",
    ] {
        assert!(quoted(Path::new(bad)).is_err(), "{bad:?}");
    }
}

#[test]
fn refusals_carry_the_core_code() {
    let body = br#"{"protocol":1,"code":"AUTH-E001","message":"identifiants invalides"}"#;
    assert_eq!(
        refusal(StatusCode::UNAUTHORIZED, body),
        LoginError::Refused {
            code: "AUTH-E001".into(),
            message: "identifiants invalides".into(),
        }
    );
    assert!(matches!(
        refusal(StatusCode::BAD_GATEWAY, b"<html>"),
        LoginError::Response(_)
    ));
}

#[test]
fn first_login_needs_core_user_and_root() {
    let scratch = Scratch::new("usage");
    let options = Options {
        dir: Some(scratch.0.clone()),
        ..Options::default()
    };
    assert!(matches!(
        resolve(&options, &scratch.0),
        Err(LoginError::Usage(_))
    ));
    let options = Options {
        core: Some("core.example".into()),
        user: Some("jdupont".into()),
        ..options
    };
    // No root given, none pinned.
    assert!(matches!(
        resolve(&options, &scratch.0),
        Err(LoginError::Usage(_))
    ));
    let options = Options {
        user: Some("J Dupont".into()),
        ..options
    };
    assert!(matches!(
        resolve(&options, &scratch.0),
        Err(LoginError::Usage(_))
    ));
}

/// Against the login listener of the core, with a stub that issues real
/// certificates. The core runs on Linux only (ADR-0011).
#[cfg(target_os = "linux")]
mod against_the_listener {
    #![allow(clippy::unused_async_trait_impl, reason = "the stub does not await")]

    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use ostena_core::api::{ApiError, Authenticator, Limits, LoginListener};
    use ostena_crypto::p256::{Signature, SigningKey, VerifyingKey};
    use ostena_crypto::pki::{pem_certificate, testing::TestPki};
    use ostena_crypto::tls::ClientAuth;
    use ostena_ssh::cert::{Kind, PERMIT_PTY, Template};

    use super::*;

    const SESSION: &str = "0b8f4c1e-7a52-4d0e-9f3b-2c6d1a9e8f70";
    const USER: &str = "5a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d";

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mode {
        Good,
        OtherKey,
        OtherDates,
    }

    struct Stub {
        user_ca: SigningKey,
        host_ca: String,
        mode: Mutex<Mode>,
        logged_out: Mutex<Vec<String>>,
        public: Mutex<Option<VerifyingKey>>,
    }

    impl Authenticator for Stub {
        async fn login(
            &self,
            request: LoginRequest,
            _peer: SocketAddr,
        ) -> Result<LoginResponse, ApiError> {
            // SECRET-EXPOSURE: test stub compares the password and the code.
            #[expect(clippy::disallowed_methods)]
            let good = request.password.expose_secret() == "good"
                && request.totp.expose_secret() == "123456";
            if request.username != "jdupont" || !good {
                return Err(ApiError::invalid_credentials());
            }
            let bytes: [u8; 65] = URL_SAFE_NO_PAD
                .decode(&request.p256_public)
                .unwrap()
                .try_into()
                .unwrap();
            let mode = *self.mode.lock().unwrap();
            let public = if mode == Mode::OtherKey {
                SigningKey::generate().unwrap().0.verifying_key()
            } else {
                VerifyingKey::from_bytes(&bytes).unwrap()
            };
            *self.public.lock().unwrap() = Some(public);
            let valid_after = unix_now() - 60;
            let ttl = request.ttl_secs.unwrap_or(login::MAX_SESSION_SECS);
            let valid_before = valid_after + ttl;
            let blob = cert::issue(
                &Template {
                    kind: Kind::User,
                    public,
                    serial: 1,
                    key_id: SESSION.into(),
                    principals: vec![USER.into()],
                    valid_after,
                    valid_before,
                    critical_options: vec![],
                    extensions: vec![(PERMIT_PTY.into(), vec![])],
                },
                &self.user_ca,
            )
            .unwrap();
            Ok(LoginResponse {
                protocol: 1,
                login_session: SESSION.into(),
                user: USER.into(),
                certificate: format!(
                    "ecdsa-sha2-nistp256-cert-v01@openssh.com {} {SESSION}",
                    STANDARD.encode(blob)
                ),
                valid_after,
                // The answer and the certificate disagree.
                valid_before: if mode == Mode::OtherDates {
                    valid_before - 60
                } else {
                    valid_before
                },
                host_ca: self.host_ca.clone(),
                ssh_hosts: vec!["bastion.test".into()],
                ssh_port: 2222,
            })
        }

        async fn logout(&self, request: LogoutRequest, _peer: SocketAddr) -> Result<(), ApiError> {
            let public = self.public.lock().unwrap().unwrap();
            let signature: [u8; 64] = URL_SAFE_NO_PAD
                .decode(&request.signature)
                .unwrap()
                .try_into()
                .unwrap();
            public
                .verify(
                    &login::logout_message(&request.login_session, request.issued_at),
                    &Signature::from_bytes(&signature),
                )
                .map_err(|_| ApiError::invalid_credentials())?;
            self.logged_out.lock().unwrap().push(request.login_session);
            Ok(())
        }
    }

    struct Fixture {
        scratch: Scratch,
        pki: TestPki,
        listener: LoginListener,
        stub: Arc<Stub>,
    }

    impl Fixture {
        async fn start(name: &str) -> Self {
            let scratch = Scratch::new(name);
            let pki = TestPki::new("login").unwrap();
            let server = pki.server(&["127.0.0.1"]).unwrap();
            let config = tls::server_config(&server, ClientAuth::None, &[b"http/1.1"]).unwrap();
            let host_ca = ostena_ssh::keys::generate("ostena-host-ca").unwrap().public;
            let stub = Arc::new(Stub {
                user_ca: SigningKey::generate().unwrap().0,
                host_ca,
                mode: Mutex::new(Mode::Good),
                logged_out: Mutex::new(Vec::new()),
                public: Mutex::new(None),
            });
            let listener = LoginListener::bind(
                "127.0.0.1:0".parse().unwrap(),
                config,
                Limits::default(),
                stub.clone(),
            )
            .await
            .unwrap();
            fs::write(
                scratch.0.join("given-root.pem"),
                pem_certificate(pki.root_anchor().certificate()),
            )
            .unwrap();
            Self {
                scratch,
                pki,
                listener,
                stub,
            }
        }

        fn dir(&self) -> PathBuf {
            self.scratch.0.join("ostena")
        }

        fn options(&self) -> Options {
            Options {
                core: Some(self.listener.local_addr().to_string()),
                root: Some(self.scratch.0.join("given-root.pem")),
                user: Some("jdupont".into()),
                hours: None,
                dir: Some(self.dir()),
                replace_root: false,
                install_include: false,
                stdin: false,
            }
        }
    }

    fn secret(text: &str) -> SecretString {
        SecretString::from(text.to_owned())
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn login_writes_private_files_then_logout_deletes_the_key() {
        runtime().block_on(async {
            let f = Fixture::start("full").await;
            let summary = login_with(&f.options(), secret("good"), secret("123456"))
                .await
                .unwrap();
            assert_eq!(summary.login_session, SESSION);
            assert_eq!(summary.ssh_hosts, ["bastion.test"]);
            let dir = f.dir();
            assert_eq!(mode_of(&dir), 0o700);
            for name in [
                CONFIG,
                ROOT,
                KEY,
                PUBLIC,
                CERTIFICATE,
                KNOWN_HOSTS,
                SSH_CONFIG,
            ] {
                assert_eq!(mode_of(&dir.join(name)), 0o600, "{name}");
            }
            // No temporary file left behind.
            assert_eq!(fs::read_dir(&dir).unwrap().count(), 7);

            // The key on disk is the certified one.
            let (key, _) =
                ostena_ssh::keys::decode(&SecretBytes::from(fs::read(dir.join(KEY)).unwrap()))
                    .unwrap();
            let line = fs::read_to_string(dir.join(CERTIFICATE)).unwrap();
            let blob = STANDARD.decode(line.split(' ').nth(1).unwrap()).unwrap();
            assert_eq!(cert::parse(&blob).unwrap().public, key.verifying_key());
            assert!(
                fs::read_to_string(dir.join(KNOWN_HOSTS))
                    .unwrap()
                    .starts_with("@cert-authority [bastion.test]:2222 ecdsa-sha2-nistp256 ")
            );
            let settings = read_settings(&dir).unwrap().unwrap();
            assert_eq!(settings.user, "jdupont");

            // A second login reuses the settings and the pinned root.
            let again = Options {
                core: None,
                root: None,
                user: None,
                ..f.options()
            };
            login_with(&again, secret("good"), secret("123456"))
                .await
                .unwrap();

            assert_eq!(logout_in(&dir).await.unwrap(), SESSION);
            assert_eq!(*f.stub.logged_out.lock().unwrap(), [SESSION]);
            for name in [KEY, PUBLIC, CERTIFICATE] {
                assert!(!dir.join(name).exists(), "{name}");
            }
            assert!(dir.join(ROOT).exists() && dir.join(CONFIG).exists());
            // Nothing left to close.
            assert!(matches!(logout_in(&dir).await, Err(LoginError::Files(_))));
            f.listener.close();
        });
    }

    /// An OpenSSH tool on the path; with `OSTENA_REQUIRE_OPENSSH=1` (CI) its
    /// absence fails the test.
    fn openssh(tool: &str) -> Option<std::process::Command> {
        let found = std::process::Command::new(tool).arg("-V").output().is_ok();
        if !found {
            assert!(
                std::env::var("OSTENA_REQUIRE_OPENSSH").as_deref() != Ok("1"),
                "{tool} introuvable alors que OSTENA_REQUIRE_OPENSSH=1"
            );
            eprintln!("{tool} introuvable : test sauté");
        }
        found.then(|| std::process::Command::new(tool))
    }

    fn stdout(command: &mut std::process::Command) -> String {
        let out = command.output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    /// OpenSSH reads the key, the certificate and the fragment as written.
    #[test]
    fn openssh_reads_the_files() {
        let (Some(mut keygen), Some(mut ssh)) = (openssh("ssh-keygen"), openssh("ssh")) else {
            return;
        };
        runtime().block_on(async {
            let f = Fixture::start("openssh").await;
            login_with(&f.options(), secret("good"), secret("123456"))
                .await
                .unwrap();
            let dir = f.dir();

            let shown = stdout(keygen.arg("-L").arg("-f").arg(dir.join(CERTIFICATE)));
            assert!(shown.contains("user certificate"), "{shown}");
            assert!(shown.contains(&format!("Key ID: \"{SESSION}\"")), "{shown}");
            assert!(shown.contains(USER), "{shown}");
            assert!(shown.contains("permit-pty"), "{shown}");
            assert!(!shown.contains("permit-agent-forwarding"), "{shown}");

            let public = stdout(
                std::process::Command::new("ssh-keygen")
                    .arg("-y")
                    .arg("-f")
                    .arg(dir.join(KEY)),
            );
            let written = fs::read_to_string(dir.join(PUBLIC)).unwrap();
            assert_eq!(
                public.split(' ').take(2).collect::<Vec<_>>(),
                written.split(' ').take(2).collect::<Vec<_>>()
            );

            let config = stdout(
                ssh.arg("-G")
                    .arg("-F")
                    .arg(dir.join(SSH_CONFIG))
                    .arg("compte@srv@bastion.test"),
            );
            for line in [
                "port 2222",
                "identitiesonly yes",
                "stricthostkeychecking true",
                "forwardagent no",
                "clearallforwardings yes",
                "ciphers aes256-gcm@openssh.com",
                "kexalgorithms ecdh-sha2-nistp256",
            ] {
                assert!(config.lines().any(|l| l == line), "{line}\n{config}");
            }
            // No explicit certificate: OpenSSH pairs `id_ecdsa-cert.pub`
            // with `id_ecdsa` (see `ssh_config`).
            assert!(
                !config.lines().any(|l| l.starts_with("certificatefile ")),
                "{config}"
            );
            let key = dir.join(KEY);
            assert!(
                config
                    .lines()
                    .any(|l| l == format!("identityfile {}", key.display())),
                "{config}"
            );
            f.listener.close();
        });
    }

    #[test]
    fn refusal_writes_nothing() {
        runtime().block_on(async {
            let f = Fixture::start("refused").await;
            let error = login_with(&f.options(), secret("bad"), secret("123456"))
                .await
                .unwrap_err();
            assert!(
                matches!(&error, LoginError::Refused { code, .. } if code == "AUTH-E001"),
                "{error}"
            );
            assert!(!f.dir().exists());
            let error = login_with(
                &Options {
                    hours: Some(9),
                    ..f.options()
                },
                secret("good"),
                secret("123456"),
            )
            .await
            .unwrap_err();
            assert!(matches!(error, LoginError::Usage(_)));
            f.listener.close();
        });
    }

    #[test]
    fn a_certificate_that_does_not_match_is_refused() {
        runtime().block_on(async {
            let f = Fixture::start("mismatch").await;
            for mode in [Mode::OtherKey, Mode::OtherDates] {
                *f.stub.mode.lock().unwrap() = mode;
                let error = login_with(&f.options(), secret("good"), secret("123456"))
                    .await
                    .unwrap_err();
                assert!(matches!(error, LoginError::Certificate(_)), "{error}");
                assert!(!f.dir().join(KEY).exists());
            }
            f.listener.close();
        });
    }

    #[test]
    fn the_pinned_root_is_kept() {
        runtime().block_on(async {
            let f = Fixture::start("root").await;
            login_with(&f.options(), secret("good"), secret("123456"))
                .await
                .unwrap();
            let pinned = fs::read(f.dir().join(ROOT)).unwrap();

            // Another root given: refused without --replace-root.
            let other = TestPki::new("other").unwrap();
            let other_path = f.scratch.0.join("other-root.pem");
            fs::write(
                &other_path,
                pem_certificate(other.root_anchor().certificate()),
            )
            .unwrap();
            let options = Options {
                root: Some(other_path),
                ..f.options()
            };
            let error = login_with(&options, secret("good"), secret("123456"))
                .await
                .unwrap_err();
            assert!(matches!(error, LoginError::RootChanged(_)), "{error}");
            assert_eq!(fs::read(f.dir().join(ROOT)).unwrap(), pinned);

            // With --replace-root, the core certificate no longer matches.
            let error = login_with(
                &Options {
                    replace_root: true,
                    ..options
                },
                secret("good"),
                secret("123456"),
            )
            .await
            .unwrap_err();
            assert!(matches!(error, LoginError::Unreachable(_)), "{error}");
            assert_eq!(fs::read(f.dir().join(ROOT)).unwrap(), pinned);
            drop(f.pki);
            f.listener.close();
        });
    }
}
