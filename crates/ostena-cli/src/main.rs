//! Entry point of the single `ostena` binary.
//!
//! Roles are enabled at installation time. During L0 the binary only answers
//! `--version` and `--help`; argument parsing moves to `clap` with the first
//! real subcommand.

#![forbid(unsafe_code)]

use std::io::{self, Write};
use std::process::ExitCode;

const USAGE: &str = "\
Usage: ostena [OPTIONS]

Options:
  -h, --help       Print help
  -V, --version    Print version
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (code, out, err) = run(&args);
    // Nothing sensible can be done if the standard streams are closed.
    let _ = io::stdout().lock().write_all(out.as_bytes());
    let _ = io::stderr().lock().write_all(err.as_bytes());
    code
}

/// Runs the command line and returns the exit code with stdout and stderr contents.
fn run(args: &[String]) -> (ExitCode, String, String) {
    match args.first().map(String::as_str) {
        None | Some("-h" | "--help") => (ExitCode::SUCCESS, USAGE.to_owned(), String::new()),
        Some("-V" | "--version") => (
            ExitCode::SUCCESS,
            format!("ostena {}\n", ostena_common::VERSION),
            String::new(),
        ),
        Some(other) => (
            ExitCode::from(2),
            String::new(),
            format!("error: unexpected argument '{other}'\n\n{USAGE}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::run;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn version_flag_prints_version() {
        let (_, out, err) = run(&args(&["--version"]));
        assert_eq!(out, format!("ostena {}\n", ostena_common::VERSION));
        assert_eq!(err, "");
    }

    #[test]
    fn unknown_argument_is_rejected() {
        let (code, out, err) = run(&args(&["--nope"]));
        assert_eq!(code, std::process::ExitCode::from(2));
        assert_eq!(out, "");
        assert!(err.contains("'--nope'"));
    }
}
