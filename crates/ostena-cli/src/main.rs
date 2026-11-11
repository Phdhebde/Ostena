//! Entry point of the single `ostena` binary.
//!
//! Roles are enabled at installation time; subcommands are added as lots
//! deliver them.

#![forbid(unsafe_code)]

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
}

#[derive(Debug, Subcommand)]
enum AgentCommand {
    /// Anti-replay journal of the gateway.
    ReplayStore {
        #[command(subcommand)]
        command: ReplayStoreCommand,
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
                AgentCommand::ReplayStore {
                    command:
                        ReplayStoreCommand::Repair {
                            path,
                            max_ttl_secs,
                            clock_skew_secs,
                        },
                },
        }) => repair_replay_store(&path, max_ttl_secs, clock_skew_secs),
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
