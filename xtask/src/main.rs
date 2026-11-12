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
  footprint      Measure the idle memory of the agent (release build)
  fuzz [SECS] [TARGET...]
                 Run fuzz targets, each for SECS (default 60, all targets)
  check-release [BINARY]
                 Fail if a test-only feature is in the release build of ostena-cli,
                 or if BINARY contains the test core
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
        Some("footprint") => footprint(),
        Some("fuzz") => fuzz(&std::env::args().skip(2).collect::<Vec<_>>()),
        Some("check-release") => check_release(std::env::args().nth(2).as_deref()),
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
    check_secrets()?;
    check_release(None)
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

/// Indicative idle footprint target (ADR-0007): displayed, not enforced.
const FOOTPRINT_TARGET_MIB: f64 = 20.0;

/// The gateway group of the measured agent.
const FOOTPRINT_GROUP: &str = "2f6c9a4e-1b2c-4d5e-8f90-a1b2c3d4e5f6";

/// Measures the idle footprint of a release agent in three states: without
/// a link to the core, with a link that cannot connect, and connected to a
/// test core (the `test_core` example, in its own process). Each agent runs
/// in the foreground with a development configuration; its
/// `agent.idle_footprint` event (5 s after start) gives the resident memory.
fn footprint() -> Result<()> {
    use std::io::BufRead;
    use std::process::Stdio;

    let root = workspace_root()?;
    let mut build = cargo();
    build.args(["build", "--release", "--locked", "--package", "ostena-cli"]);
    run(build)?;
    let mut build = cargo();
    build.args([
        "build",
        "--release",
        "--locked",
        "--package",
        "ostena-tunnel",
        "--features",
        "testing",
        "--example",
        "test_core",
    ]);
    run(build)?;
    let release = root.join("target/release");
    let exe = release.join(format!("ostena{}", std::env::consts::EXE_SUFFIX));
    let test_core = release
        .join("examples")
        .join(format!("test_core{}", std::env::consts::EXE_SUFFIX));

    let dir = std::env::temp_dir().join(format!("ostena-footprint-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("state"))?;

    // The test core writes the agent identity and the root, then serves.
    let mut core = Command::new(&test_core)
        .arg(&dir)
        .arg(FOOTPRINT_GROUP)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let core_line = std::io::BufReader::new(core.stdout.take().ok_or("no test core output")?)
        .lines()
        .map_while(std::result::Result::ok)
        .find(|l| l.starts_with("core "));
    let measures = core_line
        .and_then(|l| l.strip_prefix("core ").map(str::to_owned))
        .ok_or_else(|| "the test core did not start".into())
        .and_then(|address| {
            [
                ("without link", None),
                ("not connected", Some("127.0.0.1:9")),
                ("connected", Some(address.as_str())),
            ]
            .into_iter()
            .map(|(state, core)| Ok((state, measure(&exe, &dir, core)?)))
            .collect::<Result<Vec<_>>>()
        });
    drop(core.stdin.take());
    let _ = core.wait();
    let _ = fs::remove_dir_all(&dir);

    for (state, (bytes, detail)) in measures? {
        #[expect(clippy::cast_precision_loss, reason = "display only")]
        let mib = bytes as f64 / 1_048_576.0;
        let verdict = if mib <= FOOTPRINT_TARGET_MIB {
            "within"
        } else {
            "ABOVE"
        };
        println!(
            "idle footprint ({state}): {mib:.1} MiB resident ({verdict} the indicative {FOOTPRINT_TARGET_MIB} MiB target){detail}"
        );
    }
    Ok(())
}

/// Runs one agent until its `agent.idle_footprint` event; `core` is the
/// core address, `None` for an agent without link (no `tls_core_ca`).
fn measure(exe: &Path, dir: &Path, core: Option<&str>) -> Result<(u64, String)> {
    use std::io::BufRead;
    use std::process::Stdio;

    let path = |p: &str| dir.join(p).display().to_string().replace('\\', "\\\\");
    let endpoint = if cfg!(windows) {
        format!(r"\\\\.\\pipe\\ostena-footprint-{}", std::process::id())
    } else {
        path("run/agent.sock")
    };
    let ca = core.map_or_else(String::new, |_| {
        format!("tls_core_ca = \"{}\"\n", path("root.pem"))
    });
    let config = format!(
        "mode = \"development\"\n\n[agent]\ngateway_group = \"{FOOTPRINT_GROUP}\"\n\
         core_address = \"{}\"\ntls_certificate = \"{}\"\ntls_private_key = \"{}\"\n{ca}\
         replay_journal = \"{}\"\ncontrol_endpoint = \"{endpoint}\"\n",
        core.unwrap_or("core.invalid:8443"),
        path("agent.crt"),
        path("agent.key"),
        path("state/replay.journal"),
    );
    let file = dir.join("ostena.toml");
    fs::write(&file, config)?;

    eprintln!("$ {} agent run --config {}", exe.display(), file.display());
    let mut child = Command::new(exe)
        .args(["agent", "run", "--config"])
        .arg(&file)
        .stdout(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("no agent output")?;
    let mut connected = false;
    let mut footprint = None;
    for line in std::io::BufReader::new(stdout)
        .lines()
        .map_while(std::result::Result::ok)
    {
        connected |= line.contains("agent.core_connected");
        if line.contains("agent.idle_footprint") {
            footprint = Some(line);
            break;
        }
    }
    let detail = breakdown(child.id());
    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_file(dir.join("state/replay.journal"));
    let line = footprint.ok_or("the agent stopped before reporting its footprint")?;
    if core.is_some_and(|c| c != "127.0.0.1:9") && !connected {
        return Err("the agent did not connect to the test core".into());
    }
    let bytes = resident_bytes_of(&line).ok_or_else(|| format!("no resident_bytes in: {line}"))?;
    Ok((bytes, detail))
}

/// Linux: anonymous (heap, stacks) and file-backed (code of the binary and
/// of the libraries) resident memory, and the thread count, to explain a
/// difference. Empty elsewhere.
fn breakdown(pid: u32) -> String {
    let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else {
        return String::new();
    };
    let field = |name: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .map_or("?", str::trim)
            .to_owned()
    };
    format!(
        " [anonymous {}, file-backed {}, threads {}]",
        field("RssAnon:"),
        field("RssFile:"),
        field("Threads:")
    )
}

/// `"resident_bytes":12345` in a JSON log line.
fn resident_bytes_of(line: &str) -> Option<u64> {
    let rest = line.split("\"resident_bytes\":").nth(1)?;
    rest.chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .ok()
}

/// Text the test core of ostena-tunnel puts in any binary that links it
/// (`ostena_tunnel::testing::MARKER`).
const TESTING_MARKER: &[u8] = b"ostena-testing-core";

/// Fails if a test-only feature (`testing`) of an Ostena crate is enabled in
/// the release build of ostena-cli, or if `binary` contains the test core.
fn check_release(binary: Option<&str>) -> Result<()> {
    let root = workspace_root()?;
    let args = [
        "tree",
        "--locked",
        "-p",
        "ostena-cli",
        "-e",
        "normal,features",
        "--prefix",
        "none",
        "--target",
        "all",
    ];
    eprintln!("$ cargo {}", args.join(" "));
    let out = cargo().args(args).current_dir(&root).output()?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).into_owned().into());
    }
    let found = testing_features(&String::from_utf8_lossy(&out.stdout));
    if !found.is_empty() {
        return Err(format!(
            "test-only features in the release build: {}",
            found.join(", ")
        )
        .into());
    }
    eprintln!("no test-only feature in the release build of ostena-cli");
    if let Some(path) = binary {
        let bytes = fs::read(path)?;
        if contains(&bytes, TESTING_MARKER) {
            return Err(format!("{path} contains the test core").into());
        }
        eprintln!("{path}: no test core");
    }
    Ok(())
}

/// The `testing` features of Ostena crates in a `cargo tree -e features`
/// output.
fn testing_features(tree: &str) -> Vec<String> {
    let mut found: Vec<String> = tree
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("ostena-") && l.contains("feature \"testing\""))
        .map(|l| l.split(" (").next().unwrap_or(l).to_owned())
        .collect();
    found.sort();
    found.dedup();
    found
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Fuzz target run by `cargo xtask fuzz`.
const FUZZ_TARGETS: [&str; 6] = [
    "grant_decode",
    "scope_target",
    "scope_policy",
    "frame_decode",
    "frame_reassembly",
    "tunnel_control_decode",
];

/// Runs each fuzz target (all by default) for `SECS` seconds with the nightly
/// pinned in `fuzz/rust-toolchain.toml`. libFuzzer is only reliable on Linux
/// (the CI runs it there).
fn fuzz(args: &[String]) -> Result<()> {
    let seconds: u32 = args
        .first()
        .map_or(Ok(60), |s| s.parse())
        .map_err(|_| "fuzz duration must be a number of seconds")?;
    let targets: Vec<&str> = if args.len() > 1 {
        args[1..].iter().map(String::as_str).collect()
    } else {
        FUZZ_TARGETS.to_vec()
    };
    if let Some(unknown) = targets.iter().find(|t| !FUZZ_TARGETS.contains(t)) {
        return Err(format!(
            "unknown fuzz target {unknown} (known: {})",
            FUZZ_TARGETS.join(", ")
        )
        .into());
    }
    let root = workspace_root()?;
    let channel = fuzz_toolchain(&fs::read_to_string(root.join("fuzz/rust-toolchain.toml"))?)
        .ok_or("no channel in fuzz/rust-toolchain.toml")?;
    // cargo-fuzz defaults to the target it was itself built for (musl for the
    // prebuilt CI binary), and AddressSanitizer refuses a static libc: always
    // build for the host.
    let host = host_triple(&channel)?;
    for target in targets {
        // The rustup proxy, not $CARGO: `+toolchain` selects the pinned nightly.
        let mut cmd = Command::new("cargo");
        cmd.env_remove("RUSTUP_TOOLCHAIN")
            .env_remove("RUSTC")
            .arg(format!("+{channel}"))
            .args(["fuzz", "run", "--target", &host, target, "--"])
            .arg(format!("-max_total_time={seconds}"));
        run(cmd)?;
    }
    Ok(())
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
    fn parses_resident_bytes() {
        let line = r#"{"fields":{"event":"agent.idle_footprint","resident_bytes":9437184},"level":"INFO"}"#;
        assert_eq!(resident_bytes_of(line), Some(9_437_184));
        assert_eq!(resident_bytes_of(r#"{"resident_bytes":null}"#), None);
    }

    #[test]
    fn ci_matrices_list_every_fuzz_target() {
        let root = workspace_root().unwrap();
        for workflow in ["ci.yml", "fuzz-nightly.yml"] {
            let text = fs::read_to_string(root.join(".github/workflows").join(workflow)).unwrap();
            let line = text
                .lines()
                .map(str::trim)
                .find_map(|l| l.strip_prefix("target: ["))
                .unwrap_or_else(|| panic!("no fuzz matrix in {workflow}"));
            let mut listed: Vec<&str> = line
                .trim_end_matches(']')
                .split(',')
                .map(str::trim)
                .collect();
            let mut expected = FUZZ_TARGETS.to_vec();
            listed.sort_unstable();
            expected.sort_unstable();
            assert_eq!(
                listed, expected,
                "{workflow} is out of sync with FUZZ_TARGETS"
            );
        }
    }

    #[test]
    fn finds_testing_features_in_a_cargo_tree() {
        let clean = "ostena-cli v0.0.0 (C:\\x)\nostena-tunnel feature \"default\"\nquinn feature \"testing\"\n";
        assert_eq!(testing_features(clean), Vec::<String>::new());
        let leaked = "ostena-tunnel feature \"testing\"\nostena-crypto feature \"testing\" (*)\nostena-tunnel feature \"testing\"\n";
        assert_eq!(
            testing_features(leaked),
            vec![
                "ostena-crypto feature \"testing\"",
                "ostena-tunnel feature \"testing\""
            ]
        );
    }

    #[test]
    fn finds_the_test_core_marker_in_a_binary() {
        let mut binary = vec![0u8; 1000];
        assert!(!contains(&binary, TESTING_MARKER));
        binary[500..500 + TESTING_MARKER.len()].copy_from_slice(TESTING_MARKER);
        assert!(contains(&binary, TESTING_MARKER));
    }

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
