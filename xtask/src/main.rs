//! Repository automation, invoked with `cargo xtask <task>`.
//!
//! Standard library only, so that it builds offline before any vendoring.

#![forbid(unsafe_code)]
// A developer tool: reporting progress on the console is its job.
#![allow(clippy::print_stdout, clippy::print_stderr)]

mod secrets;

use std::error::Error;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const USAGE: &str = "\
Usage: cargo xtask <TASK>

Tasks:
  ci             Run fmt, clippy, tests, cargo-deny and check-secrets like the CI
  check-secrets  Check that every secret exposure is justified
  vendor         Vendor all dependencies into vendor/ for offline builds
  sbom           Generate CycloneDX SBOMs into target/sbom/ (needs cargo-cyclonedx)
  fuzz [SECS]    Run the grant decoder fuzzer (default 60 s; needs cargo-fuzz, Linux)
  help           Print this message
";

/// Directory receiving vendored crates.
const VENDOR_DIR: &str = "vendor";
/// Cargo configuration snippet that redirects crates.io to `VENDOR_DIR`.
const VENDOR_CONFIG: &str = ".cargo/vendor.toml";

fn main() -> ExitCode {
    let task = std::env::args().nth(1);
    let result = match task.as_deref() {
        Some("ci") => ci(),
        Some("check-secrets") => check_secrets(),
        Some("vendor") => vendor(),
        Some("sbom") => sbom(),
        Some("fuzz") => fuzz(std::env::args().nth(2).as_deref()),
        None | Some("help" | "-h" | "--help") => {
            print!("{USAGE}");
            Ok(())
        }
        Some(other) => Err(format!("unknown task '{other}'\n\n{USAGE}").into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Root of the workspace (parent of the `xtask` directory).
fn workspace_root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "xtask must live inside the workspace".into())
}

fn cargo() -> Command {
    Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
}

/// Runs a command in the workspace root and fails if it does not succeed.
fn run(mut cmd: Command) -> Result<()> {
    cmd.current_dir(workspace_root()?);
    let shown = format!(
        "{} {}",
        cmd.get_program().to_string_lossy(),
        cmd.get_args()
            .map(OsStr::to_string_lossy)
            .collect::<Vec<_>>()
            .join(" ")
    );
    eprintln!("$ {shown}");
    let status = cmd
        .status()
        .map_err(|e| format!("cannot run `{shown}`: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("`{shown}` failed with {status}").into())
    }
}

fn ci() -> Result<()> {
    let steps: [&[&str]; 4] = [
        &["fmt", "--all", "--check"],
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
        &["test", "--workspace", "--locked"],
        &["deny", "--locked", "check"],
    ];
    for args in steps {
        let mut cmd = cargo();
        cmd.args(args);
        run(cmd)?;
    }
    check_secrets()
}

fn check_secrets() -> Result<()> {
    let crates = workspace_root()?.join("crates");
    eprintln!("$ check-secrets {}", crates.display());
    let report = secrets::check_tree(&crates)?;
    if report.is_empty() {
        eprintln!("every secret exposure is justified");
        Ok(())
    } else {
        for line in &report {
            eprintln!("{line}");
        }
        Err(format!("{} unjustified secret exposure(s)", report.len()).into())
    }
}

fn vendor() -> Result<()> {
    let root = workspace_root()?;
    let mut cmd = cargo();
    cmd.args(["vendor", "--locked", "--versioned-dirs", VENDOR_DIR])
        .current_dir(&root);
    eprintln!("$ cargo vendor --locked --versioned-dirs {VENDOR_DIR}");
    let output = cmd.output()?;
    if !output.status.success() {
        return Err(format!(
            "cargo vendor failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    // `cargo vendor` prints the source replacement to stdout.
    fs::write(root.join(VENDOR_CONFIG), &output.stdout)?;
    eprintln!(
        "Vendored into {VENDOR_DIR}/. Offline build:\n  \
         cargo build --offline --locked --config {VENDOR_CONFIG}"
    );
    Ok(())
}

fn sbom() -> Result<()> {
    let root = workspace_root()?;
    let mut cmd = cargo();
    cmd.args([
        "cyclonedx",
        "--format",
        "json",
        "--spec-version",
        "1.5",
        "--all-features",
    ]);
    run(cmd)?;

    // cargo-cyclonedx writes one `<crate>.cdx.json` next to each manifest:
    // gather them in one place so they are not left in the source tree.
    let out_dir = root.join("target").join("sbom");
    fs::create_dir_all(&out_dir)?;
    let mut count = 0usize;
    for dir in ["crates", "xtask"] {
        count += collect_sboms(&root.join(dir), &out_dir)?;
    }
    if count == 0 {
        return Err("cargo cyclonedx produced no SBOM".into());
    }
    eprintln!("{count} SBOM(s) written to {}", out_dir.display());
    Ok(())
}

/// Moves every `*.cdx.json` found under `dir` into `out_dir`.
fn collect_sboms(dir: &Path, out_dir: &Path) -> Result<usize> {
    let mut count = 0;
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            count += collect_sboms(&path, out_dir)?;
        } else if path
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|n| n.ends_with(".cdx.json"))
        {
            let name = path.file_name().ok_or("SBOM path without file name")?;
            let dest = out_dir.join(name);
            // `rename` fails across filesystems; copy then remove instead.
            fs::copy(&path, &dest)?;
            fs::remove_file(&path)?;
            count += 1;
        }
    }
    Ok(count)
}

/// Fuzz target run by `cargo xtask fuzz`.
const FUZZ_TARGET: &str = "grant_decode";

/// Runs the fuzzer with the nightly pinned in `fuzz/rust-toolchain.toml`.
/// libFuzzer is only reliable on Linux (the CI runs it there).
fn fuzz(seconds: Option<&str>) -> Result<()> {
    let seconds: u32 = seconds
        .map_or(Ok(60), str::parse)
        .map_err(|_| "fuzz duration must be a number of seconds")?;
    let root = workspace_root()?;
    let channel = fuzz_toolchain(&fs::read_to_string(root.join("fuzz/rust-toolchain.toml"))?)
        .ok_or("no channel in fuzz/rust-toolchain.toml")?;
    // cargo-fuzz defaults to the target it was itself built for (musl for the
    // prebuilt CI binary), and AddressSanitizer refuses a static libc: always
    // build for the host.
    let host = host_triple(&channel)?;
    // The rustup proxy, not $CARGO: `+toolchain` selects the pinned nightly.
    let mut cmd = Command::new("cargo");
    cmd.env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("RUSTC")
        .arg(format!("+{channel}"))
        .args(["fuzz", "run", "--target", &host, FUZZ_TARGET, "--"])
        .arg(format!("-max_total_time={seconds}"));
    run(cmd)
}

/// Host triple of a toolchain, from `rustc -vV`.
fn host_triple(channel: &str) -> Result<String> {
    let output = Command::new("rustc")
        .env_remove("RUSTUP_TOOLCHAIN")
        .arg(format!("+{channel}"))
        .arg("-vV")
        .output()?;
    parse_host(&String::from_utf8_lossy(&output.stdout))
        .ok_or_else(|| format!("no host triple in `rustc +{channel} -vV`").into())
}

/// Reads the `host: <triple>` line of `rustc -vV`.
fn parse_host(version: &str) -> Option<String> {
    version
        .lines()
        .find_map(|l| l.strip_prefix("host:"))
        .map(|h| h.trim().to_owned())
        .filter(|h| !h.is_empty())
}

/// Reads `channel = "..."` from a rust-toolchain.toml.
fn fuzz_toolchain(toml: &str) -> Option<String> {
    toml.lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("channel"))
        .and_then(|rest| rest.trim_start().strip_prefix('='))
        .map(|v| v.trim().trim_matches('"').to_owned())
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_host_triple() {
        let out = "rustc 1.101.0-nightly (f9ceb4a4d 2026-10-31)
binary: rustc
host: x86_64-unknown-linux-gnu
release: 1.101.0-nightly
";
        assert_eq!(parse_host(out).as_deref(), Some("x86_64-unknown-linux-gnu"));
        assert_eq!(
            parse_host(
                "rustc 1.0
"
            ),
            None
        );
    }

    #[test]
    fn reads_fuzz_toolchain() {
        let toml = "# comment
[toolchain]
channel = \"nightly-2026-11-01\"
profile = \"minimal\"
";
        assert_eq!(fuzz_toolchain(toml).as_deref(), Some("nightly-2026-11-01"));
        assert_eq!(
            fuzz_toolchain(
                "[toolchain]
"
            ),
            None
        );
        let real =
            fs::read_to_string(workspace_root().unwrap().join("fuzz/rust-toolchain.toml")).unwrap();
        assert!(fuzz_toolchain(&real).is_some_and(|c| c.starts_with("nightly-")));
    }

    #[test]
    fn workspace_root_contains_manifest() {
        let root = workspace_root().unwrap();
        assert!(root.join("Cargo.toml").is_file());
        assert!(root.join("xtask").is_dir());
    }

    #[test]
    fn collect_sboms_moves_only_cdx_files() {
        let base = std::env::temp_dir().join(format!("xtask-sbom-{}", std::process::id()));
        let src = base.join("src").join("nested");
        let out = base.join("out");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&out).unwrap();
        fs::write(src.join("a.cdx.json"), "{}").unwrap();
        fs::write(src.join("Cargo.toml"), "").unwrap();

        let moved = collect_sboms(&base.join("src"), &out).unwrap();

        assert_eq!(moved, 1);
        assert!(out.join("a.cdx.json").is_file());
        assert!(!src.join("a.cdx.json").exists());
        assert!(src.join("Cargo.toml").exists());
        fs::remove_dir_all(&base).unwrap();
    }
}
