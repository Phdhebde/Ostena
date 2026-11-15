//! Entry point of the single `ostena` binary.
//!
//! Roles are enabled at installation time; subcommands are added as lots
//! deliver them.

#![forbid(unsafe_code)]

mod agent;
mod audit;
mod ca;
mod control;
#[cfg(target_os = "linux")]
mod core;
mod core_link;
mod enroll;
mod keyset_state;
mod sessions;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};
use ostena_common::config::LoggingConfig;

/// Ostena administration bastion.
#[derive(Debug, Parser)]
#[command(name = "ostena", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Gateway agent operations.
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    /// Audit chain: offline verification of an export (any workstation).
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Root ceremony and certification of the core keys (offline workstation).
    Ca {
        #[command(subcommand)]
        command: CaCommand,
    },
    /// The core (Linux): run it, migrate its database, administer the agents.
    #[cfg(target_os = "linux")]
    Core {
        #[command(subcommand)]
        command: CoreCommand,
    },
}

#[cfg(target_os = "linux")]
const CORE_CONFIG: &str = "/etc/ostena/ostena.toml";

#[cfg(target_os = "linux")]
#[derive(Debug, Subcommand)]
enum CoreCommand {
    /// Run the core (in the foreground, or as started by systemd): apply
    /// the embedded migrations, then serve the tunnel and enrolment
    /// listeners.
    Run {
        /// Configuration file.
        #[arg(long, default_value = CORE_CONFIG)]
        config: PathBuf,
    },
    /// Apply the embedded migrations, or only check them (exit code 1 if
    /// some are pending).
    Migrate {
        /// Configuration file.
        #[arg(long, default_value = CORE_CONFIG)]
        config: PathBuf,
        /// Check only, change nothing.
        #[arg(long)]
        check: bool,
    },
    /// Administer the agents (the running core applies changes at once).
    Agent {
        #[command(subcommand)]
        command: CoreAgentCommand,
    },
    /// The audit chain: export, last head, online verification, break
    /// acknowledgement.
    Audit {
        #[command(subcommand)]
        command: CoreAuditCommand,
    },
}

#[cfg(target_os = "linux")]
#[derive(Debug, Subcommand)]
enum CoreAgentCommand {
    /// Issue a single-use enrolment token for a gateway group; it opens the
    /// enrolment listener of the running core.
    Token {
        /// Configuration file.
        #[arg(long, default_value = CORE_CONFIG)]
        config: PathBuf,
        /// Gateway group (UUID).
        #[arg(long)]
        group: String,
        /// Lifetime in minutes (1 to 60).
        #[arg(long, default_value_t = 15)]
        ttl_mins: u64,
        /// File to create (mode 0600, never overwritten), or `-` for
        /// standard output.
        #[arg(long)]
        out: PathBuf,
    },
    /// List the agents and their certificates.
    List {
        /// Configuration file.
        #[arg(long, default_value = CORE_CONFIG)]
        config: PathBuf,
    },
    /// Revoke an agent and all its certificates; its tunnels are closed.
    Revoke {
        /// Configuration file.
        #[arg(long, default_value = CORE_CONFIG)]
        config: PathBuf,
        /// Agent identifier (UUID).
        agent: String,
    },
}

#[cfg(target_os = "linux")]
#[derive(Debug, Subcommand)]
enum CoreAuditCommand {
    /// Export the audit chain (records and signed heads) to a file, for
    /// `ostena audit verify` on another workstation.
    Export {
        /// Configuration file.
        #[arg(long, default_value = CORE_CONFIG)]
        config: PathBuf,
        /// File to create (mode 0600, never overwritten).
        #[arg(long)]
        out: PathBuf,
        /// Export only what follows this head (partial export anchored on it).
        #[arg(long)]
        from_head: Option<u64>,
    },
    /// Print the last signed head, in text form, to keep outside the bastion.
    Head {
        /// Configuration file.
        #[arg(long, default_value = CORE_CONFIG)]
        config: PathBuf,
    },
    /// Verify the chain in the database with the public keys of the head
    /// signer. Exit codes of `ostena audit verify`.
    Verify {
        /// Configuration file.
        #[arg(long, default_value = CORE_CONFIG)]
        config: PathBuf,
        /// Public key file of the head signer, once per trusted key.
        #[arg(long = "key", required = true)]
        keys: Vec<PathBuf>,
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Record that an administrator acknowledged a break of the chain from
    /// record `--seq`, so that the core signs heads again.
    AcknowledgeBreak {
        /// Configuration file.
        #[arg(long, default_value = CORE_CONFIG)]
        config: PathBuf,
        /// First record of the break.
        #[arg(long)]
        seq: u64,
    },
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Verify an audit export with the public keys of the head signer.
    /// Exit code 0 intact and covered by a signed head, 1 error, 2 warnings
    /// only, 3 usage or input/output error.
    Verify {
        /// Export file.
        export: PathBuf,
        /// Public key file of the head signer (`ostena-p256-public-key-v1`),
        /// once per trusted key.
        #[arg(long = "key", required = true)]
        keys: Vec<PathBuf>,
        /// Head kept outside the core, in text form
        /// (`ostena-audit-head-v1:…`) or the file holding it; the export
        /// must contain the record it covers.
        #[arg(long = "head")]
        heads: Vec<String>,
        /// Print the report as JSON.
        #[arg(long)]
        json: bool,
        /// Accepted backward step of the clock between records, in ms.
        #[arg(long, default_value_t = 5_000)]
        clock_tolerance_ms: u64,
        /// Accepted delay of a head beyond its heartbeat, in seconds.
        #[arg(long, default_value_t = 60)]
        head_gap_tolerance_secs: u64,
    },
}

#[derive(Debug, Subcommand)]
enum CaCommand {
    /// The offline root.
    Root {
        #[command(subcommand)]
        command: RootCommand,
    },
    /// A P-256 key, generated where it is used (on the core).
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    /// The online issuing CA (agent certificates only).
    Issuing {
        #[command(subcommand)]
        command: SignCommand,
    },
    /// The core server certificate.
    Server {
        #[command(subcommand)]
        command: ServerCommand,
    },
}

#[derive(Debug, Subcommand)]
enum RootCommand {
    /// Generate the root and the secret that seals it (three shares, two
    /// rebuild it); write one copy per `--out`.
    Init {
        /// Common name of the root.
        #[arg(long)]
        name: String,
        /// Validity in days.
        #[arg(long, default_value_t = 3650)]
        days: u32,
        /// Output directory, one per removable medium (at least two).
        #[arg(long = "out", required = true)]
        outs: Vec<PathBuf>,
    },
    /// Reopen the root with two shares and seal it under a new secret, in
    /// three new shares, onto new media (lost envelope, custodian change).
    Reseal {
        /// Directory holding the current root copy.
        #[arg(long)]
        root: PathBuf,
        /// New output directory, one per removable medium (at least two).
        #[arg(long = "out", required = true)]
        outs: Vec<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum KeyCommand {
    /// Generate a key (PEM, mode 0600) and its public key file.
    New {
        /// Private key file to create.
        #[arg(long)]
        key_out: PathBuf,
        /// Public key file to carry to the ceremony.
        #[arg(long)]
        public_out: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum SignCommand {
    /// Certify the issuing CA key with the root (passphrase on standard input).
    Sign {
        /// Directory holding the root copy.
        #[arg(long)]
        root: PathBuf,
        /// Public key file from `ostena ca key new`.
        #[arg(long)]
        public_key: PathBuf,
        /// Common name of the issuing CA.
        #[arg(long)]
        name: String,
        /// Validity in days.
        #[arg(long, default_value_t = 365)]
        days: u32,
        /// Certificate to create (PEM).
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ServerCommand {
    /// Certify the core server key with the root (passphrase on standard input).
    Sign {
        /// Directory holding the root copy.
        #[arg(long)]
        root: PathBuf,
        /// Public key file from `ostena ca key new`.
        #[arg(long)]
        public_key: PathBuf,
        /// Name the agents use to reach the core (DNS name or IP address).
        #[arg(long = "name", required = true)]
        names: Vec<String>,
        /// Validity in days.
        #[arg(long, default_value_t = 365)]
        days: u32,
        /// Certificate to create (PEM).
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum AgentCommand {
    /// Register the agent as a service (systemd or Windows SCM) and start it.
    /// Non-interactive; can be run again.
    Install {
        /// Configuration file.
        #[arg(long, default_value_os_t = agent::default_config())]
        config: PathBuf,
        /// Executable to register (default: this one).
        #[arg(long)]
        executable: Option<PathBuf>,
        /// Do not start the service.
        #[arg(long)]
        no_start: bool,
        /// No output on success.
        #[arg(long)]
        quiet: bool,
    },
    /// Stop and unregister the service (configuration, data and account kept).
    Uninstall {
        /// No output on success.
        #[arg(long)]
        quiet: bool,
    },
    /// Run the agent (in the foreground, or as started by the service manager).
    Run {
        /// Configuration file.
        #[arg(long, default_value_os_t = agent::default_config())]
        config: PathBuf,
        /// Started by the Windows SCM.
        #[arg(long, hide = true)]
        service: bool,
    },
    /// Service state and what the agent reports (exit code 0 running, 3
    /// stopped, 4 not installed).
    Status {
        /// Configuration file (for the control endpoint).
        #[arg(long, default_value_os_t = agent::default_config())]
        config: PathBuf,
        /// Query a foreground agent with this process id (development).
        #[arg(long)]
        pid: Option<u32>,
    },
    /// Enrol the agent with the core: generate its key, prove a single-use
    /// token, write the certificate. Run once, before `install`.
    Enroll {
        /// Configuration file.
        #[arg(long, default_value_os_t = agent::default_config())]
        config: PathBuf,
        /// File holding the enrolment token, or `-` for standard input.
        #[arg(long)]
        token_file: PathBuf,
        /// Deadline for the exchange with the core, in seconds.
        #[arg(long, default_value_t = 15)]
        timeout: u64,
    },
    /// Anti-replay journal of the gateway.
    ReplayStore {
        #[command(subcommand)]
        command: ReplayStoreCommand,
    },
    /// State file of the grant key set version.
    KeysetState {
        #[command(subcommand)]
        command: KeysetStateCommand,
    },
}

#[derive(Debug, Subcommand)]
enum KeysetStateCommand {
    /// Reset an unreadable state file, after confirmation. The original is
    /// kept as `<file>.corrupt-<time>`; the agent then accepts the version the
    /// core pushes at the next connection. The agent must be stopped.
    Repair {
        /// Configuration file.
        #[arg(long, default_value_os_t = agent::default_config())]
        config: PathBuf,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ReplayStoreCommand {
    /// Rebuild a damaged journal. The original is kept as
    /// `<path>.corrupt-<time>`, and grants issued before the repair are refused.
    /// The agent must be stopped.
    Repair {
        /// Journal path.
        #[arg(long)]
        path: PathBuf,
        /// Longest grant lifetime accepted by the agent, in seconds.
        #[arg(long, default_value_t = 300)]
        max_ttl_secs: u64,
        /// Clock tolerance of the agent, in seconds.
        #[arg(long, default_value_t = 5)]
        clock_skew_secs: u64,
    },
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            // Help and version also arrive here, with exit code 0.
            let _ = e.print();
            let args: Vec<String> = std::env::args_os()
                .skip(1)
                .take(2)
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            return ExitCode::from(usage_exit_code(&e, &args));
        }
    };
    match cli.command {
        None => {
            let _ = Cli::command().print_help();
            ExitCode::SUCCESS
        }
        Some(Command::Agent {
            command:
                AgentCommand::Install {
                    config,
                    executable,
                    no_start,
                    quiet,
                },
        }) => agent::install(&config, executable, !no_start, quiet),
        Some(Command::Agent {
            command: AgentCommand::Uninstall { quiet },
        }) => agent::uninstall(quiet),
        Some(Command::Agent {
            command: AgentCommand::Run { config, service },
        }) => agent::run(&config, service),
        Some(Command::Agent {
            command: AgentCommand::Status { config, pid },
        }) => agent::status(&config, pid),
        Some(Command::Agent {
            command:
                AgentCommand::Enroll {
                    config,
                    token_file,
                    timeout,
                },
        }) => enroll::enroll_agent(&config, &token_file, timeout),
        Some(Command::Agent {
            command:
                AgentCommand::ReplayStore {
                    command:
                        ReplayStoreCommand::Repair {
                            path,
                            max_ttl_secs,
                            clock_skew_secs,
                        },
                },
        }) => repair_replay_store(&path, max_ttl_secs, clock_skew_secs),
        Some(Command::Agent {
            command:
                AgentCommand::KeysetState {
                    command: KeysetStateCommand::Repair { config, yes },
                },
        }) => keyset_state::repair(&config, yes),
        Some(Command::Audit { command }) => run_audit(command),
        #[cfg(target_os = "linux")]
        Some(Command::Core { command }) => run_core(command),
        Some(Command::Ca { command }) => match command {
            CaCommand::Root {
                command: RootCommand::Init { name, days, outs },
            } => ca::root_init(&name, days, &outs),
            CaCommand::Root {
                command: RootCommand::Reseal { root, outs },
            } => ca::root_reseal(&root, &outs),
            CaCommand::Key {
                command:
                    KeyCommand::New {
                        key_out,
                        public_out,
                    },
            } => ca::key_new(&key_out, &public_out),
            CaCommand::Issuing {
                command:
                    SignCommand::Sign {
                        root,
                        public_key,
                        name,
                        days,
                        out,
                    },
            } => ca::issuing_sign(&root, &public_key, &name, days, &out),
            CaCommand::Server {
                command:
                    ServerCommand::Sign {
                        root,
                        public_key,
                        names,
                        days,
                        out,
                    },
            } => ca::server_sign(&root, &public_key, &names, days, &out),
        },
    }
}

/// Exit code of a command line that does not parse: clap's (2 for a usage
/// error, 0 for help and version), except under `ostena audit` and `ostena
/// core audit`, where 2 means "warnings only" and a usage error is 3.
/// `args` are the first two arguments.
fn usage_exit_code(error: &clap::Error, args: &[&str]) -> u8 {
    let code = u8::try_from(error.exit_code()).unwrap_or(2);
    let audit = matches!(args, ["audit", ..] | ["core", "audit", ..]);
    if code != 0 && audit {
        audit::USAGE_ERROR
    } else {
        code
    }
}

fn run_audit(command: AuditCommand) -> ExitCode {
    match command {
        AuditCommand::Verify {
            export,
            keys,
            heads,
            json,
            clock_tolerance_ms,
            head_gap_tolerance_secs,
        } => audit::verify(&audit::VerifyArgs {
            export: &export,
            keys: &keys,
            heads: &heads,
            json,
            clock_tolerance_ms,
            head_gap_tolerance_secs,
        }),
    }
}

#[cfg(target_os = "linux")]
fn run_core(command: CoreCommand) -> ExitCode {
    match command {
        CoreCommand::Run { config } => core::run(&config),
        CoreCommand::Migrate { config, check } => core::migrate(&config, check),
        CoreCommand::Agent { command } => match command {
            CoreAgentCommand::Token {
                config,
                group,
                ttl_mins,
                out,
            } => core::agent_token(&config, &group, ttl_mins, &out),
            CoreAgentCommand::List { config } => core::agent_list(&config),
            CoreAgentCommand::Revoke { config, agent } => core::agent_revoke(&config, &agent),
        },
        CoreCommand::Audit { command } => match command {
            CoreAuditCommand::Export {
                config,
                out,
                from_head,
            } => core::audit_export(&config, &out, from_head),
            CoreAuditCommand::Head { config } => core::audit_head(&config),
            CoreAuditCommand::Verify { config, keys, json } => {
                core::audit_verify(&config, &keys, json)
            }
            CoreAuditCommand::AcknowledgeBreak { config, seq } => {
                core::audit_acknowledge_break(&config, seq)
            }
        },
    }
}

/// `ostena agent replay-store repair`: logs `replay_store.repaired` or
/// `replay_store.repair_failed` as JSON on standard output.
fn repair_replay_store(
    path: &std::path::Path,
    max_ttl_secs: u64,
    clock_skew_secs: u64,
) -> ExitCode {
    if ostena_common::logging::init(&LoggingConfig::default()).is_err() {
        return ExitCode::FAILURE;
    }
    let now = ostena_grant::unix_now();
    let fence = now
        .saturating_add(max_ttl_secs)
        .saturating_add(clock_skew_secs);
    match ostena_grant::replay::repair(path, now, fence) {
        Ok(report) => {
            tracing::info!(
                event = "replay_store.repaired",
                path = %path.display(),
                backup = %report.backup.display(),
                kept = report.kept,
                dropped = report.dropped,
                truncated_bytes = report.truncated_bytes,
                fence = report.fence,
                "journal anti-rejeu reconstruit ; l'original est conservé"
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            tracing::error!(
                event = "replay_store.repair_failed",
                path = %path.display(),
                "{e}"
            );
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::{Cli, usage_exit_code};

    #[test]
    fn command_line_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn audit_usage_errors_exit_with_3() {
        let error = Cli::command().error(clap::error::ErrorKind::UnknownArgument, "x");
        assert_eq!(usage_exit_code(&error, &["audit", "verify"]), 3);
        assert_eq!(usage_exit_code(&error, &["core", "audit"]), 3);
        assert_eq!(usage_exit_code(&error, &["core", "agent"]), 2);
        assert_eq!(usage_exit_code(&error, &[]), 2);
        let help = Cli::command().error(clap::error::ErrorKind::DisplayHelp, "x");
        assert_eq!(usage_exit_code(&help, &["core", "audit"]), 0);
    }
}
