//! `ostena agent setup` (ADR-0024): what an installation package runs, once
//! its files are in place, to make a working agent out of a few parameters.
//!
//! 1. the root certificate given by the deployer is checked against the
//!    fingerprint of the ceremony record, then copied next to the
//!    configuration (never replacing a different root);
//! 2. a minimal production configuration is written if none exists (an
//!    existing one is kept, and must agree with the parameters given);
//! 3. the agent is enrolled if it has no certificate yet and a token file is
//!    given (`ostena agent enroll`);
//! 4. the service is installed and started (`ostena agent install`).
//!
//! Each step is skipped when already done, so the command can run again (a
//! package repair or upgrade). The MSI and the `.deb` call it rather than
//! repeating any of this logic.

use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ostena_crypto::tls::{self, TrustAnchor};

use crate::{agent, enroll};

/// Parameters of `ostena agent setup`. An empty value counts as absent: the
/// MSI passes every property, set or not.
#[derive(Debug, Default)]
pub(crate) struct SetupArgs {
    /// Configuration file.
    pub config: PathBuf,
    /// Executable to register (default: this one).
    pub executable: Option<PathBuf>,
    /// `agent.core_address`, for a new configuration.
    pub core_address: Option<String>,
    /// `agent.gateway_group`, for a new configuration.
    pub gateway_group: Option<String>,
    /// `agent.enrollment_address`, for a new configuration.
    pub enrollment_address: Option<String>,
    /// Root certificate (PEM) to install.
    pub root_ca: Option<PathBuf>,
    /// Expected SHA-256 of the root certificate (ceremony record).
    pub root_fingerprint: Option<String>,
    /// Enrolment token file.
    pub token_file: Option<PathBuf>,
    /// Deadline of the enrolment exchange, in seconds.
    pub timeout: u64,
    /// Do not start the service.
    pub no_start: bool,
    /// No output on success.
    pub quiet: bool,
    /// Also append every message to this file (the MSI has no console).
    pub log: Option<PathBuf>,
}

impl SetupArgs {
    /// Empty strings and paths become `None`.
    pub(crate) fn normalized(mut self) -> Self {
        fn text(v: Option<String>) -> Option<String> {
            v.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
        }
        fn path(v: Option<PathBuf>) -> Option<PathBuf> {
            v.filter(|p| !p.as_os_str().is_empty())
        }
        self.executable = path(self.executable);
        self.core_address = text(self.core_address);
        self.gateway_group = text(self.gateway_group);
        self.enrollment_address = text(self.enrollment_address);
        self.root_ca = path(self.root_ca);
        self.root_fingerprint = text(self.root_fingerprint);
        self.token_file = path(self.token_file);
        self.log = path(self.log);
        self
    }
}

/// Where a new configuration puts the agent files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Layout {
    /// Root certificate, next to the configuration.
    pub root: PathBuf,
    /// State directory: the only one the service may write to.
    pub state: PathBuf,
    /// Log file (Windows: the service has no console); `None`: standard
    /// output, that is journald under systemd.
    pub log_file: Option<PathBuf>,
}

impl Layout {
    /// The layout of this platform for `config` (ADR-0007): Windows keeps
    /// everything under the configuration directory (`…\Ostena\state`);
    /// Linux uses the systemd `StateDirectory`, `/var/lib/ostena`, the only
    /// writable path under `ProtectSystem=strict`.
    pub(crate) fn for_config(config: &Path) -> Self {
        let dir = config.parent().unwrap_or(Path::new("."));
        if cfg!(windows) {
            let state = dir.join("state");
            Self {
                root: dir.join("root.pem"),
                log_file: Some(state.join("agent.log")),
                state,
            }
        } else {
            Self {
                root: dir.join("root.pem"),
                state: PathBuf::from("/var/lib/ostena"),
                log_file: None,
            }
        }
    }
}

/// Collects the messages, to the console and to the log file if any.
struct Report {
    quiet: bool,
    log: Option<fs::File>,
}

impl Report {
    fn open(quiet: bool, log: Option<&Path>) -> Self {
        let log = log.and_then(|path| {
            if let Some(dir) = path.parent() {
                let _ = fs::create_dir_all(dir);
            }
            OpenOptions::new().create(true).append(true).open(path).ok()
        });
        Self { quiet, log }
    }

    fn line(&mut self, text: &str) {
        if let Some(file) = &mut self.log {
            let _ = writeln!(file, "{text}");
        }
    }

    fn info(&mut self, text: &str) {
        self.line(text);
        if !self.quiet {
            let _ = writeln!(io::stdout(), "{text}");
        }
    }

    fn error(&mut self, text: &str) {
        self.line(&format!("ÉCHEC : {text}"));
        let _ = writeln!(io::stderr(), "{text}");
    }
}

/// `ostena agent setup`.
pub(crate) fn setup(args: SetupArgs) -> ExitCode {
    let args = args.normalized();
    let mut report = Report::open(args.quiet, args.log.as_deref());
    report.line(&format!(
        "ostena {} agent setup, configuration {}",
        env!("CARGO_PKG_VERSION"),
        args.config.display()
    ));
    let layout = Layout::for_config(&args.config);
    let result = prepare(&args, &layout, &mut |m| report.info(m)).and_then(|()| {
        agent::install_service(&args.config, args.executable.clone(), !args.no_start)
    });
    match result {
        Ok(()) => {
            report.info(if args.no_start {
                "Agent installé."
            } else {
                "Agent installé et démarré."
            });
            ExitCode::SUCCESS
        }
        Err(e) => {
            report.error(&e);
            ExitCode::FAILURE
        }
    }
}

/// Steps 1 to 3: root, configuration, enrolment. Nothing here needs
/// administrator rights by itself; the files are protected by `install`.
pub(crate) fn prepare(
    args: &SetupArgs,
    layout: &Layout,
    say: &mut dyn FnMut(&str),
) -> Result<(), String> {
    let expected = args
        .root_fingerprint
        .as_deref()
        .map(parse_fingerprint)
        .transpose()?;
    // The root given by the deployer is checked before anything is written.
    let given_root = match &args.root_ca {
        Some(path) => {
            let expected = expected.ok_or(
                "[AGT-E011] --root-fingerprint est obligatoire avec --root-ca : comparez l'empreinte du \
                 procès-verbal de la cérémonie",
            )?;
            let pem = fs::read(path).map_err(|e| format!("{} : {e}", path.display()))?;
            check_root(&pem, &expected, path)?;
            Some(pem)
        }
        None => None,
    };

    // The configuration: kept if present, written otherwise.
    let root_path = if args.config.exists() {
        let config = agent::read(&args.config)?;
        let existing = config
            .agent
            .ok_or_else(|| format!("{} : section [agent] absente", args.config.display()))?;
        agrees(
            "gateway_group",
            args.gateway_group.as_deref(),
            &existing.gateway_group,
        )?;
        agrees(
            "core_address",
            args.core_address.as_deref(),
            &existing.core_address,
        )?;
        say(&format!(
            "Configuration existante conservée : {}",
            args.config.display()
        ));
        existing.tls_core_ca.unwrap_or_else(|| layout.root.clone())
    } else {
        let (Some(core), Some(group)) = (&args.core_address, &args.gateway_group) else {
            return Err(format!(
                "[AGT-E012] {} absent : --core-address et --gateway-group sont nécessaires pour l'écrire",
                args.config.display()
            ));
        };
        if given_root.is_none() && !layout.root.exists() {
            return Err(
                "[AGT-E011] certificat de la racine absent : donnez --root-ca et --root-fingerprint".into(),
            );
        }
        let text = render_config(core, group, args.enrollment_address.as_deref(), layout)?;
        write_new(&args.config, text.as_bytes(), 0o640)?;
        say(&format!("Configuration écrite : {}", args.config.display()));
        layout.root.clone()
    };

    // The root next to the configuration: copied once, never replaced by a
    // different one; an existing one is checked when a fingerprint is given.
    match (&given_root, root_path.exists()) {
        (Some(pem), false) => {
            write_new(&root_path, pem, 0o644)?;
            say(&format!(
                "Certificat de la racine installé : {}",
                root_path.display()
            ));
        }
        (Some(pem), true) => {
            let current =
                fs::read(&root_path).map_err(|e| format!("{} : {e}", root_path.display()))?;
            if fingerprint_of(&current, &root_path)? != fingerprint_of(pem, &root_path)? {
                return Err(format!(
                    "[AGT-E011] {} contient une autre racine : rien n'est remplacé. Retirez-la à la main si \
                     le changement de racine est voulu.",
                    root_path.display()
                ));
            }
        }
        (None, true) => {
            if let Some(expected) = &expected {
                let current =
                    fs::read(&root_path).map_err(|e| format!("{} : {e}", root_path.display()))?;
                check_root(&current, expected, &root_path)?;
            }
        }
        (None, false) => {}
    }

    // Enrolment, once.
    let config = agent::read(&args.config)?;
    let agent_config = config
        .agent
        .ok_or_else(|| format!("{} : section [agent] absente", args.config.display()))?;
    if agent_config.tls_certificate.exists() {
        say("Agent déjà enrôlé : certificat présent.");
    } else if let Some(token) = &args.token_file {
        let text = enroll::enroll_with_config(&args.config, token, args.timeout)?;
        say(&text);
    } else {
        say(
            "AVERTISSEMENT : agent non enrôlé (aucun jeton donné). Il démarre sans lien avec le \
             core ; enrôlez-le avec `ostena agent enroll` puis redémarrez le service.",
        );
    }
    Ok(())
}

/// A parameter given again must agree with the configuration in place.
fn agrees(name: &str, given: Option<&str>, current: &str) -> Result<(), String> {
    match given {
        Some(given) if given != current => Err(format!(
            "[AGT-E012] la configuration en place a agent.{name} = \"{current}\", et non \"{given}\" : rien \
             n'est modifié. Corrigez la configuration à la main ou le paramètre."
        )),
        _ => Ok(()),
    }
}

/// SHA-256 of the first certificate of `pem`.
fn fingerprint_of(pem: &[u8], path: &Path) -> Result<[u8; 32], String> {
    let anchor = TrustAnchor::from_pem(pem).map_err(|e| format!("{} : {e}", path.display()))?;
    Ok(tls::fingerprint(anchor.certificate()))
}

fn check_root(pem: &[u8], expected: &[u8; 32], path: &Path) -> Result<(), String> {
    let actual = fingerprint_of(pem, path)?;
    if &actual == expected {
        Ok(())
    } else {
        Err(format!(
            "[AGT-E011] {} : l'empreinte SHA-256 du certificat de la racine est {}, et non {} (procès-verbal) : \
             rien n'est installé",
            path.display(),
            hex(&actual),
            hex(expected)
        ))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// A SHA-256 fingerprint as written in a record: 64 hexadecimal digits, in
/// either case, optionally prefixed by `sha256:` and separated by colons or
/// spaces.
pub(crate) fn parse_fingerprint(text: &str) -> Result<[u8; 32], String> {
    let trimmed = text.trim();
    let body = trimmed
        .get(..7)
        .filter(|p| p.eq_ignore_ascii_case("sha256:"))
        .map_or(trimmed, |_| &trimmed[7..]);
    let digits: Vec<u8> = body.bytes().filter(|b| !matches!(b, b':' | b' ')).collect();
    let invalid = || {
        format!(
            "[AGT-E011] empreinte SHA-256 invalide : « {text} » (64 chiffres hexadécimaux attendus)"
        )
    };
    if digits.len() != 64 {
        return Err(invalid());
    }
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(digits.as_chunks::<2>().0) {
        let pair = std::str::from_utf8(pair.as_slice()).map_err(|_| invalid())?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| invalid())?;
    }
    Ok(out)
}

/// A TOML basic string.
fn toml_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04X}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn path_string(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(toml_string)
        .ok_or_else(|| format!("{} : chemin non UTF-8", path.display()))
}

/// The minimal production configuration of a new agent: no SSH server (no
/// listening port: the agent only dials out), safe defaults for the rest.
/// Checked like `install` checks it before it is written.
pub(crate) fn render_config(
    core_address: &str,
    gateway_group: &str,
    enrollment_address: Option<&str>,
    layout: &Layout,
) -> Result<String, String> {
    let mut text = String::from(
        "# Written by `ostena agent setup` (ADR-0024). Settings: ADR-0003, ADR-0007,\n\
         # docs/exploitation/agent-installation.md.\n\
         mode = \"production\"\n",
    );
    if let Some(log) = &layout.log_file {
        let _ = write!(
            text,
            "\n[[logging.outputs]]\nkind = \"file\"\npath = {}\n",
            path_string(log)?
        );
    }
    let _ = write!(
        text,
        "\n[agent]\ngateway_group = {}\ncore_address = {}\n",
        toml_string(gateway_group),
        toml_string(core_address)
    );
    if let Some(enrollment) = enrollment_address {
        let _ = writeln!(text, "enrollment_address = {}", toml_string(enrollment));
    }
    let _ = write!(
        text,
        "tls_certificate = {}\ntls_private_key = {}\ntls_core_ca = {}\nreplay_journal = {}\n",
        path_string(&layout.state.join("agent.crt"))?,
        path_string(&layout.state.join("agent.key"))?,
        path_string(&layout.root)?,
        path_string(&layout.state.join("replay.journal"))?,
    );
    let config = ostena_common::config::Config::from_toml_str(&text).map_err(|e| e.to_string())?;
    config.validate().map_err(|v| v.to_string())?;
    Ok(text)
}

/// Creates a new file (never overwrites), with its parent directory; `mode`
/// on Unix: 0640 for the configuration (`install` gives it to the service
/// group), 0644 for the root certificate, which is public and read by the
/// service.
fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let failed = |e: io::Error| format!("{} : {e}", path.display());
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir).map_err(failed)?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, mode);
    let mut file = options.open(path).map_err(failed)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(failed)
}

#[cfg(test)]
mod tests;
