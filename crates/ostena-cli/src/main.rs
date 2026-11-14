//! Entry point of the single `ostena` binary.
//!
//! Roles are enabled at installation time; subcommands are added as lots
//! deliver them.

#![forbid(unsafe_code)]

mod agent;
mod ca;
mod control;
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
    /// Root ceremony and certification of the core keys (offline workstation).
    Ca {
        #[command(subcommand)]
        command: CaCommand,
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
            return ExitCode::from(u8::try_from(e.exit_code()).unwrap_or(2));
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

    use super::Cli;

    #[test]
    fn command_line_definition_is_consistent() {
        Cli::command().debug_assert();
    }
}
