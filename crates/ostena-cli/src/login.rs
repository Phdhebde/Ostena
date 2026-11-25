//! `ostena login` and `ostena logout` (ADR-0010, step 1; ADR-0015), on the
//! administrator's workstation.
//!
//! `ostena login` asks for the password (without echo) and the TOTP code,
//! generates a new ECDSA P-256 key with `ostena-crypto` (its private half
//! never leaves the workstation), and sends its public half to the core in
//! HTTPS, the core certificate checked against the pinned root. The core
//! returns an OpenSSH user certificate for the session. Written in
//! `~/.ostena/`, with private rights, each file replaced atomically:
//!
//! - `config.toml`: the core address and the user name;
//! - `root.pem`: the pinned root (a different one is refused without
//!   `--replace-root`);
//! - `id_ecdsa`, `id_ecdsa.pub`, `id_ecdsa-cert.pub`: the key and the
//!   certificate of the session;
//! - `known_hosts`: the `@cert-authority` line of the bastion hosts;
//! - `ssh_config`: a fragment to include from `~/.ssh/config`.
//!
//! `ostena logout` closes the session on the core with a request signed by
//! the session key, then deletes the key and the certificate.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use ostena_common::api::login::{
    self, ErrorResponse, LOGIN_PATH, LOGOUT_PATH, LoginRequest, LoginResponse, LogoutRequest,
};
use ostena_common::logging::utc_text;
use ostena_common::secret::{SecretBytes, SecretString};
use ostena_crypto::tls::{self, HandshakeFailure, ServerName, TrustAnchor};
use ostena_platform::private_file::{self, Reader};
use ostena_ssh::cert;
use serde::Deserialize;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Default port of the login API.
pub(crate) const DEFAULT_PORT: u16 = 8445;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

const CONFIG: &str = "config.toml";
const ROOT: &str = "root.pem";
const KEY: &str = "id_ecdsa";
const PUBLIC: &str = "id_ecdsa.pub";
const CERTIFICATE: &str = "id_ecdsa-cert.pub";
const KNOWN_HOSTS: &str = "known_hosts";
const SSH_CONFIG: &str = "ssh_config";

/// Why `ostena login` or `ostena logout` fails. Codes are stable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum LoginError {
    /// The core cannot be reached, or the TLS handshake fails.
    #[error("[LOGIN-E001] core injoignable : {0}")]
    Unreachable(String),
    /// The core answered something else than the protocol.
    #[error("[LOGIN-E002] réponse du core invalide : {0}")]
    Response(String),
    /// The certificate received does not match the request.
    #[error("[LOGIN-E003] certificat reçu invalide : {0}")]
    Certificate(String),
    /// A file of `~/.ostena` cannot be read or written.
    #[error("[LOGIN-E004] {0}")]
    Files(String),
    /// Another root than the pinned one.
    #[error(
        "[LOGIN-E005] la racine donnée diffère de celle épinglée dans {0} ; vérifiez-la avec \
         l'administrateur, puis relancez avec --replace-root"
    )]
    RootChanged(String),
    /// Missing setting or interrupted input.
    #[error("[LOGIN-E006] {0}")]
    Usage(String),
    /// The core refused, with its own code (`AUTH-E…`).
    #[error("[{code}] {message}")]
    Refused {
        /// The code of the core.
        code: String,
        /// Its message.
        message: String,
    },
}

/// What `ostena login` is given on its command line.
#[derive(Debug, Clone, Default)]
pub(crate) struct Options {
    /// The core, `host:port` (port 8445 if left out).
    pub(crate) core: Option<String>,
    /// The root to pin (`root.pem`).
    pub(crate) root: Option<PathBuf>,
    /// The user name.
    pub(crate) user: Option<String>,
    /// Session length in hours, at most 8 (the core may give less).
    pub(crate) hours: Option<u64>,
    /// The directory, `~/.ostena` by default.
    pub(crate) dir: Option<PathBuf>,
    /// Accept another root than the pinned one.
    pub(crate) replace_root: bool,
    /// Add `Include` of the fragment at the top of `~/.ssh/config`.
    pub(crate) install_include: bool,
    /// Read the password and the code from standard input, one line each.
    pub(crate) stdin: bool,
}

/// `config.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    core: String,
    user: String,
}

impl Settings {
    /// The TOML text. A JSON string is a valid TOML basic string, which
    /// spares the serializer of the `toml` crate.
    fn to_toml(&self) -> String {
        let quote = |s: &str| serde_json::Value::from(s).to_string();
        format!(
            "# Écrit par ostena login.\ncore = {}\nuser = {}\n",
            quote(&self.core),
            quote(&self.user)
        )
    }
}

fn home() -> Option<PathBuf> {
    #[cfg(windows)]
    let var = "USERPROFILE";
    #[cfg(not(windows))]
    let var = "HOME";
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// `~/.ostena`, or the directory given.
pub(crate) fn directory(dir: Option<&Path>) -> Result<PathBuf, LoginError> {
    match dir {
        Some(dir) => Ok(dir.to_path_buf()),
        None => home()
            .map(|h| h.join(".ostena"))
            .ok_or_else(|| LoginError::Usage("dossier personnel inconnu : précisez --dir".into())),
    }
}

fn files(path: &Path, e: &io::Error) -> LoginError {
    LoginError::Files(format!("{} : {e}", path.display()))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Creates the directory, private (0700 on Unix).
fn ensure_dir(dir: &Path) -> Result<(), LoginError> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir).map_err(|e| files(dir, &e))
}

/// Replaces `dir/name` atomically by a new private file holding `bytes`.
fn write_private(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), LoginError> {
    let target = dir.join(name);
    let temporary = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&temporary);
    let result = private_file::create(&temporary, bytes, Reader::CurrentProcess)
        .and_then(|()| fs::rename(&temporary, &target));
    if let Err(e) = result {
        let _ = fs::remove_file(&temporary);
        return Err(files(&target, &e));
    }
    Ok(())
}

/// `host:port` → (host, port); IPv6 in brackets.
pub(crate) fn split_address(text: &str) -> Result<(String, u16), LoginError> {
    let bad = || LoginError::Usage(format!("adresse du core invalide : « {text} »"));
    let (host, port) = if let Some(rest) = text.strip_prefix('[') {
        let (host, rest) = rest.split_once(']').ok_or_else(bad)?;
        let port = match rest {
            "" => DEFAULT_PORT,
            p => p
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .ok_or_else(bad)?,
        };
        (host.to_owned(), port)
    } else {
        match text.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => {
                (host.to_owned(), port.parse().map_err(|_| bad())?)
            }
            None => (text.to_owned(), DEFAULT_PORT),
            Some(_) => return Err(bad()),
        }
    };
    if host.is_empty() || port == 0 || host.chars().any(|c| c.is_control() || c == ' ') {
        return Err(bad());
    }
    Ok((host, port))
}

/// A request body wiped when its last reference is dropped: hyper holds
/// the only copy, through [`Bytes::from_owner`].
struct Wiped(Vec<u8>);

impl AsRef<[u8]> for Wiped {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Wiped {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

/// The body of a request, its bytes wiped once sent and dropped.
fn wiped_body(body: Vec<u8>) -> Bytes {
    Bytes::from_owner(Wiped(body))
}

/// One HTTPS request to the core: (status, body). hyper writes the body
/// from `body` itself (vectored writes, no flattening copy).
async fn post(
    core: &str,
    root: &TrustAnchor,
    path: &str,
    body: Bytes,
) -> Result<(StatusCode, Vec<u8>), LoginError> {
    let (host, port) = split_address(core)?;
    let unreachable = |what: String| LoginError::Unreachable(format!("{core} : {what}"));
    let name = ServerName::try_from(host.clone())
        .map_err(|_| LoginError::Usage(format!("nom du core invalide : « {host} »")))?;
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), port)))
        .await
        .map_err(|_| unreachable("délai de connexion dépassé".into()))?
        .map_err(|e| unreachable(e.to_string()))?;
    let _ = tcp.set_nodelay(true);
    let config = tls::client_config(root, None, &[b"http/1.1"])
        .map_err(|e| LoginError::Usage(e.to_string()))?;
    let stream = TlsConnector::from(config)
        .connect(name, tcp)
        .await
        .map_err(|e| {
            unreachable(match tls::classify_io(&e) {
                Some(
                    HandshakeFailure::UnknownIssuer
                    | HandshakeFailure::NotRootIssued
                    | HandshakeFailure::NameMismatch,
                ) => format!(
                    "certificat du core refusé ({e}) : il n'est pas signé par la racine épinglée \
                     pour ce nom"
                ),
                Some(_) => format!("poignée de main TLS refusée : {e}"),
                None => e.to_string(),
            })
        })?;
    let exchange = async {
        let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
            .writev(true)
            .handshake(TokioIo::new(stream))
            .await
            .map_err(|e| unreachable(e.to_string()))?;
        let driver = tokio::spawn(connection);
        let host_header = if port == DEFAULT_PORT {
            host.clone()
        } else if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let request = Request::post(path)
            .header("host", host_header)
            .header("content-type", "application/json")
            .body(Full::new(body))
            .map_err(|e| LoginError::Usage(e.to_string()))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|e| unreachable(e.to_string()))?;
        let status = response.status();
        let mut out = Vec::new();
        let mut incoming = response.into_body();
        while let Some(frame) = incoming.frame().await {
            let frame = frame.map_err(|e| unreachable(e.to_string()))?;
            if let Ok(data) = frame.into_data() {
                if out.len() + data.len() > login::MAX_BODY {
                    return Err(LoginError::Response("réponse de plus de 16 Kio".into()));
                }
                out.extend_from_slice(&data);
            }
        }
        driver.abort();
        Ok((status, out))
    };
    tokio::time::timeout(EXCHANGE_TIMEOUT, exchange)
        .await
        .map_err(|_| unreachable("délai d'échange dépassé".into()))?
}

/// The refusal carried by a non-success answer.
fn refusal(status: StatusCode, body: &[u8]) -> LoginError {
    match ErrorResponse::parse(body) {
        Ok(e) => LoginError::Refused {
            code: e.code,
            message: e.message,
        },
        Err(_) => LoginError::Response(format!("statut HTTP {status} sans erreur lisible")),
    }
}

fn read_root(path: &Path) -> Result<(TrustAnchor, Vec<u8>), LoginError> {
    let pem = fs::read(path).map_err(|e| files(path, &e))?;
    let anchor = TrustAnchor::from_pem(&pem)
        .map_err(|e| LoginError::Usage(format!("{} : {e}", path.display())))?;
    Ok((anchor, pem))
}

fn read_settings(dir: &Path) -> Result<Option<Settings>, LoginError> {
    let path = dir.join(CONFIG);
    match fs::read_to_string(&path) {
        Ok(text) => toml::from_str(&text)
            .map(Some)
            .map_err(|e| LoginError::Files(format!("{} : {e}", path.display()))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(files(&path, &e)),
    }
}

/// The settings to use and the root to pin, from the options and what is
/// already in `dir`.
fn resolve(
    options: &Options,
    dir: &Path,
) -> Result<(Settings, TrustAnchor, Option<Vec<u8>>), LoginError> {
    let saved = read_settings(dir)?;
    let core = options
        .core
        .clone()
        .or_else(|| saved.as_ref().map(|s| s.core.clone()))
        .ok_or_else(|| {
            LoginError::Usage("première connexion : précisez --core hôte:port et --root".into())
        })?;
    split_address(&core)?;
    let user = options
        .user
        .clone()
        .or_else(|| saved.as_ref().map(|s| s.user.clone()))
        .ok_or_else(|| LoginError::Usage("précisez --user".into()))?;
    if !login::is_username(&user) {
        return Err(LoginError::Usage(format!(
            "nom d'utilisateur invalide : « {user} »"
        )));
    }
    let pinned_path = dir.join(ROOT);
    let pinned = match fs::read(&pinned_path) {
        Ok(pem) => Some(pem),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(files(&pinned_path, &e)),
    };
    let (anchor, new_pin) = match (&options.root, pinned) {
        (Some(path), pinned) => {
            let (anchor, pem) = read_root(path)?;
            if let Some(old) = pinned {
                let old = TrustAnchor::from_pem(&old)
                    .map_err(|e| LoginError::Files(format!("{} : {e}", pinned_path.display())))?;
                if old.certificate() != anchor.certificate() && !options.replace_root {
                    return Err(LoginError::RootChanged(pinned_path.display().to_string()));
                }
            }
            (anchor, Some(pem))
        }
        (None, Some(pem)) => {
            let anchor = TrustAnchor::from_pem(&pem)
                .map_err(|e| LoginError::Files(format!("{} : {e}", pinned_path.display())))?;
            (anchor, None)
        }
        (None, None) => {
            return Err(LoginError::Usage(
                "aucune racine épinglée : précisez --root (root.pem remis par l'administrateur)"
                    .into(),
            ));
        }
    };
    Ok((Settings { core, user }, anchor, new_pin))
}

/// What a successful login wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Summary {
    /// The session.
    pub(crate) login_session: String,
    /// End of validity, Unix seconds.
    pub(crate) valid_before: u64,
    /// The host patterns.
    pub(crate) ssh_hosts: Vec<String>,
    /// The directory.
    pub(crate) dir: PathBuf,
}

/// Checks the certificate against the request and the response, and
/// returns its blob.
fn check_certificate(
    response: &LoginResponse,
    public: &[u8; 65],
    now: u64,
) -> Result<Vec<u8>, LoginError> {
    let invalid = |what: &str| LoginError::Certificate(what.to_owned());
    let blob = response
        .certificate
        .split(' ')
        .nth(1)
        .and_then(|b| STANDARD.decode(b).ok())
        .ok_or_else(|| invalid("ligne OpenSSH illisible"))?;
    let parsed = cert::parse(&blob).map_err(|e| LoginError::Certificate(e.to_string()))?;
    if parsed.public.to_bytes() != *public {
        return Err(invalid("il ne certifie pas la clé envoyée"));
    }
    parsed
        .verify(&[parsed.authority])
        .map_err(|e| LoginError::Certificate(e.to_string()))?;
    let identity =
        cert::check_user(&parsed, now).map_err(|e| LoginError::Certificate(e.to_string()))?;
    if cert::format_uuid(&identity.subject) != response.user
        || cert::format_uuid(&identity.login_session) != response.login_session
    {
        return Err(invalid("utilisateur ou session différents de la réponse"));
    }
    if parsed.valid_after != response.valid_after || parsed.valid_before != response.valid_before {
        return Err(invalid("dates différentes de la réponse"));
    }
    Ok(blob)
}

/// Quotes a path for `ssh_config` and `known_hosts` readers.
fn quoted(path: &Path) -> String {
    format!("\"{}\"", path.display())
}

/// The `ssh_config` fragment.
pub(crate) fn ssh_config(dir: &Path, response: &LoginResponse) -> String {
    format!(
        "# Écrit par ostena login, réécrit à chaque connexion.\n\
         # Session {session}, valable jusqu'au {until}.\n\
         Host {hosts}\n\
         \x20   Port {port}\n\
         \x20   IdentityFile {key}\n\
         \x20   CertificateFile {cert}\n\
         \x20   IdentitiesOnly yes\n\
         \x20   IdentityAgent none\n\
         \x20   UserKnownHostsFile {known}\n\
         \x20   StrictHostKeyChecking yes\n\
         \x20   UpdateHostKeys no\n\
         \x20   HostKeyAlgorithms ecdsa-sha2-nistp256-cert-v01@openssh.com\n\
         \x20   PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256-cert-v01@openssh.com\n\
         \x20   KexAlgorithms ecdh-sha2-nistp256\n\
         \x20   Ciphers aes256-gcm@openssh.com\n\
         \x20   ForwardAgent no\n\
         \x20   ForwardX11 no\n\
         \x20   ClearAllForwardings yes\n",
        session = response.login_session,
        until = utc_text(response.valid_before),
        hosts = response.ssh_hosts.join(" "),
        port = response.ssh_port,
        key = quoted(&dir.join(KEY)),
        cert = quoted(&dir.join(CERTIFICATE)),
        known = quoted(&dir.join(KNOWN_HOSTS)),
    )
}

/// The `known_hosts` line that trusts the host CA for the bastion hosts.
pub(crate) fn known_hosts(response: &LoginResponse) -> String {
    let patterns: Vec<String> = response
        .ssh_hosts
        .iter()
        .map(|h| {
            if response.ssh_port == 22 {
                h.clone()
            } else {
                format!("[{h}]:{}", response.ssh_port)
            }
        })
        .collect();
    let key: Vec<&str> = response.host_ca.split(' ').take(2).collect();
    format!(
        "@cert-authority {} {} ostena-host-ca\n",
        patterns.join(","),
        key.join(" ")
    )
}

/// Logs in with `password` and `totp`, and writes the files.
///
/// # Errors
///
/// [`LoginError`].
pub(crate) async fn login_with(
    options: &Options,
    password: SecretString,
    totp: SecretString,
) -> Result<Summary, LoginError> {
    let dir = directory(options.dir.as_deref())?;
    let (settings, root, new_pin) = resolve(options, &dir)?;
    let ttl_secs = match options.hours {
        None => None,
        Some(h @ 1..=8) => Some(h * 3600),
        Some(_) => return Err(LoginError::Usage("--hours : de 1 à 8".into())),
    };
    // A new key per login; read back for signing through ostena-crypto.
    let generated = ostena_ssh::keys::generate(&format!("ostena-{}", settings.user))
        .map_err(|e| LoginError::Usage(e.to_string()))?;
    let (key, _) = ostena_ssh::keys::decode(&generated.private)
        .map_err(|e| LoginError::Usage(e.to_string()))?;
    let public = key.verifying_key().to_bytes();
    let request = LoginRequest {
        protocol: login::PROTOCOL,
        username: settings.user.clone(),
        password,
        totp,
        p256_public: URL_SAFE_NO_PAD.encode(public),
        ttl_secs,
    };
    // The secrets are serialised once, into a buffer of the right size
    // (no reallocation), whose only copy hyper sends and drops.
    let mut body = Vec::with_capacity(login::MAX_BODY);
    let written = serde_json::to_writer(&mut body, &request);
    drop(request);
    if let Err(e) = written {
        zeroize::Zeroize::zeroize(&mut body);
        return Err(LoginError::Usage(e.to_string()));
    }
    let (status, answer) = post(&settings.core, &root, LOGIN_PATH, wiped_body(body)).await?;
    if status != StatusCode::OK {
        return Err(refusal(status, &answer));
    }
    let response =
        LoginResponse::parse(&answer).map_err(|e| LoginError::Response(e.to_string()))?;
    check_certificate(&response, &public, unix_now())?;

    ensure_dir(&dir)?;
    if let Some(pem) = new_pin {
        write_private(&dir, ROOT, &pem)?;
    }
    write_private(&dir, CONFIG, settings.to_toml().as_bytes())?;
    // SECRET-EXPOSURE: the private key is written once, to a private file.
    #[expect(clippy::disallowed_methods)]
    write_private(&dir, KEY, generated.private.expose_secret())?;
    write_private(&dir, PUBLIC, format!("{}\n", generated.public).as_bytes())?;
    write_private(
        &dir,
        CERTIFICATE,
        format!("{}\n", response.certificate).as_bytes(),
    )?;
    write_private(&dir, KNOWN_HOSTS, known_hosts(&response).as_bytes())?;
    write_private(&dir, SSH_CONFIG, ssh_config(&dir, &response).as_bytes())?;
    if options.install_include {
        install_include(&dir)?;
    }
    Ok(Summary {
        login_session: response.login_session,
        valid_before: response.valid_before,
        ssh_hosts: response.ssh_hosts,
        dir,
    })
}

/// The `Include` line of the fragment.
fn include_line(dir: &Path) -> String {
    format!("Include {}", quoted(&dir.join(SSH_CONFIG)))
}

/// Adds the `Include` line at the top of `~/.ssh/config`, once.
fn install_include(dir: &Path) -> Result<(), LoginError> {
    let ssh = home()
        .map(|h| h.join(".ssh"))
        .ok_or_else(|| LoginError::Usage("dossier personnel inconnu".into()))?;
    install_include_in(&ssh, dir)
}

fn install_include_in(ssh: &Path, dir: &Path) -> Result<(), LoginError> {
    ensure_dir(ssh)?;
    let path = ssh.join("config");
    let current = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(files(&path, &e)),
    };
    let line = include_line(dir);
    if current.lines().any(|l| l.trim() == line) {
        return Ok(());
    }
    write_private(ssh, "config", format!("{line}\n{current}").as_bytes())
}

fn say(text: &str) {
    let _ = writeln!(io::stdout(), "{text}");
}

fn fail(error: &LoginError) -> ExitCode {
    let _ = writeln!(io::stderr(), "{error}");
    ExitCode::FAILURE
}

fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}

fn input(e: &io::Error) -> LoginError {
    LoginError::Usage(format!("saisie : {e}"))
}

/// `ostena login`.
pub(crate) fn login(options: &Options) -> ExitCode {
    let run = || -> Result<Summary, LoginError> {
        let (password, totp) = if options.stdin {
            (
                ostena_platform::tty::read_stdin_line().map_err(|e| input(&e))?,
                ostena_platform::tty::read_stdin_line().map_err(|e| input(&e))?,
            )
        } else {
            (
                ostena_platform::tty::read_hidden("Mot de passe : ").map_err(|e| input(&e))?,
                ostena_platform::tty::read_visible("Code TOTP : ").map_err(|e| input(&e))?,
            )
        };
        runtime()
            .map_err(|e| LoginError::Usage(e.to_string()))?
            .block_on(login_with(options, password, totp))
    };
    match run() {
        Ok(summary) => {
            say(&format!(
                "Connecté : session {}, valable jusqu'au {}.",
                summary.login_session,
                utc_text(summary.valid_before)
            ));
            if !options.install_include {
                say(&format!(
                    "Ajoutez une fois cette ligne en tête de ~/.ssh/config (ou relancez avec \
                     --install-include) :\n  {}",
                    include_line(&summary.dir)
                ));
            }
            if let Some(host) = summary.ssh_hosts.first() {
                say(&format!(
                    "Puis : ssh compte@ressource@{}",
                    host.replace(['*', '?'], "x")
                ));
            }
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}

/// Closes the session of `dir` on the core, then deletes its key and
/// certificate.
///
/// # Errors
///
/// [`LoginError`].
pub(crate) async fn logout_in(dir: &Path) -> Result<String, LoginError> {
    let settings = read_settings(dir)?
        .ok_or_else(|| LoginError::Usage("aucune session : config.toml absent".into()))?;
    let (root, _) = read_root(&dir.join(ROOT))?;
    let certificate_path = dir.join(CERTIFICATE);
    let line = fs::read_to_string(&certificate_path).map_err(|e| files(&certificate_path, &e))?;
    let line = line.trim().to_owned();
    let blob = line
        .split(' ')
        .nth(1)
        .and_then(|b| STANDARD.decode(b).ok())
        .ok_or_else(|| LoginError::Certificate("ligne OpenSSH illisible".into()))?;
    let parsed = cert::parse(&blob).map_err(|e| LoginError::Certificate(e.to_string()))?;
    let session = parsed.key_id.to_owned();
    let key_path = dir.join(KEY);
    let key_file = SecretBytes::from(fs::read(&key_path).map_err(|e| files(&key_path, &e))?);
    let (key, _) = ostena_ssh::keys::decode(&key_file)
        .map_err(|e| LoginError::Files(format!("{} : {e}", key_path.display())))?;
    if key.verifying_key() != parsed.public {
        return Err(LoginError::Certificate(
            "le certificat ne correspond pas à la clé".into(),
        ));
    }
    let issued_at = unix_now();
    let signature = key
        .sign(&login::logout_message(&session, issued_at))
        .map_err(|e| LoginError::Usage(e.to_string()))?;
    let request = LogoutRequest {
        protocol: login::PROTOCOL,
        login_session: session.clone(),
        certificate: line,
        issued_at,
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    };
    let body = serde_json::to_vec(&request).map_err(|e| LoginError::Usage(e.to_string()))?;
    // No secret in a logout: signed, bound to its session and its time.
    let (status, answer) = post(&settings.core, &root, LOGOUT_PATH, Bytes::from(body)).await?;
    if status != StatusCode::NO_CONTENT {
        return Err(refusal(status, &answer));
    }
    for name in [KEY, PUBLIC, CERTIFICATE] {
        let path = dir.join(name);
        if let Err(e) = fs::remove_file(&path)
            && e.kind() != io::ErrorKind::NotFound
        {
            return Err(files(&path, &e));
        }
    }
    Ok(session)
}

/// `ostena logout`.
pub(crate) fn logout(dir: Option<&Path>) -> ExitCode {
    let run = || -> Result<String, LoginError> {
        let dir = directory(dir)?;
        runtime()
            .map_err(|e| LoginError::Usage(e.to_string()))?
            .block_on(logout_in(&dir))
    };
    match run() {
        Ok(session) => {
            say(&format!(
                "Session {session} fermée ; clé et certificat supprimés."
            ));
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}

#[cfg(test)]
mod tests;
