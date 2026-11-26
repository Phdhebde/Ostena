//! Repository automation, invoked with `cargo xtask <task>`.
//!
//! Standard library only, so that it builds offline before any vendoring.

#![forbid(unsafe_code)]
// A developer tool: reporting progress on the console is its job.
#![allow(clippy::print_stdout, clippy::print_stderr)]

mod bench;
mod pe;
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
  footprint [--target TRIPLE]
                 Measure the idle memory of the agent, with and without SSH (release
                 build, for TRIPLE if given, such as x86_64-unknown-linux-musl); fail
                 on a blocking regression (ADR-0009)
  bench-ssh      Run the SSH latency benches (agent relay, tunnel), write
                 target/bench/ssh-latency.jsonl and .md, and append the summary
                 to $GITHUB_STEP_SUMMARY if set; displayed only, not a gate
  fuzz [SECS] [TARGET...]
                 Run fuzz targets, each for SECS (default 60, all targets)
  check-release [BINARY]
                 Fail if a test-only feature is in the release build of ostena-cli,
                 if the SSH server is not linked, or if BINARY contains the test
                 core, lacks the SSH server or imports a GUI or COM DLL statically
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
        Some("footprint") => footprint(&std::env::args().skip(2).collect::<Vec<_>>()),
        Some("bench-ssh") => bench_ssh(),
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

/// The SSH latency benches, gathered into one summary (ADR-0005: not a
/// gate).
fn bench_ssh() -> Result<()> {
    let out_dir = workspace_root()?.join("target").join("bench");
    fs::create_dir_all(&out_dir)?;
    let lines = out_dir.join("ssh-latency.jsonl");
    if lines.exists() {
        fs::remove_file(&lines)?;
    }
    for args in [
        ["bench", "--locked", "-p", "ostena-ssh", "--bench", "relay"],
        [
            "bench",
            "--locked",
            "-p",
            "ostena-tunnel",
            "--bench",
            "latency",
        ],
    ] {
        let mut cmd = cargo();
        cmd.args(args).env("OSTENA_BENCH_OUT", &lines);
        run(cmd)?;
    }
    let text = fs::read_to_string(&lines)?;
    let results = text
        .lines()
        .map(|l| bench::parse_line(l).ok_or_else(|| format!("unreadable bench line: {l}")))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    // relay (round trip, session setup), tunnel over QUIC and over TCP.
    if results.len() != 4 {
        return Err(format!("expected 4 bench results, got {}", results.len()).into());
    }
    let commit = std::env::var("GITHUB_SHA").ok();
    let summary = bench::markdown(&results, commit.as_deref());
    fs::write(out_dir.join("ssh-latency.md"), &summary)?;
    if let Some(path) = std::env::var_os("GITHUB_STEP_SUMMARY") {
        use std::io::Write as _;
        fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)?
            .write_all(summary.as_bytes())?;
    }
    print!("{summary}");
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

/// Accepted cost of the native SSH server in the idle agent: in any state,
/// the agent with SSH may take at most this much more than the agent built
/// without it; over it, the footprint fails. A ceiling accepted by the
/// project lead on 2026-11-25 (ADR-0009, "Décision du 2026-11-25") in
/// place of the general rule (+10 % and +1 MiB, CLAUDE.md), which the SSH
/// cost exceeds; that rule stays for every other regression. Linux: the
/// highest measure, +2.31 MiB (static musl binary, after the core grew in
/// the same binary), plus about 0.4 MiB of noise; raised from 2.25 MiB by
/// the project lead on 2026-11-25.
#[cfg(not(windows))]
const SSH_ACCEPTED_BYTES: u64 = 11 * 1024 * 1024 / 4;
/// Windows: see the Linux ceiling; the highest CI measure plus noise.
#[cfg(windows)]
const SSH_ACCEPTED_BYTES: u64 = 1280 * 1024;

/// One idle measure of an agent.
struct Measure {
    /// Resident memory (`agent.idle_footprint`).
    bytes: u64,
    /// Linux breakdown, empty elsewhere.
    detail: String,
    /// Shared libraries (Linux) or DLLs (Windows) loaded, lower case.
    modules: Vec<String>,
}

/// Builds the release agent, the reference without SSH (kept next to it as
/// `ostena-without-ssh`) and the test core; returns their paths.
/// `target`: a target triple, such as `x86_64-unknown-linux-musl` for the
/// static Linux release; the host target if `None`. The test core is built
/// for the host.
fn footprint_binaries(target: Option<&str>) -> Result<(PathBuf, PathBuf, PathBuf)> {
    let root = workspace_root()?;
    let host_release = root.join("target/release");
    let release = target.map_or_else(
        || host_release.clone(),
        |t| root.join("target").join(t).join("release"),
    );
    let target_args: Vec<&str> = target.map(|t| vec!["--target", t]).unwrap_or_default();
    let exe = release.join(format!("ostena{}", std::env::consts::EXE_SUFFIX));
    let reference = release.join(format!(
        "ostena-without-ssh{}",
        std::env::consts::EXE_SUFFIX
    ));
    // The reference first: the release binary stays in target/release.
    let mut build = cargo();
    build.args([
        "build",
        "--release",
        "--locked",
        "--package",
        "ostena-cli",
        "--no-default-features",
    ]);
    build.args(&target_args);
    run(build)?;
    fs::copy(&exe, &reference)?;
    let mut build = cargo();
    build.args(["build", "--release", "--locked", "--package", "ostena-cli"]);
    build.args(&target_args);
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
    let test_core = host_release
        .join("examples")
        .join(format!("test_core{}", std::env::consts::EXE_SUFFIX));
    Ok((exe, reference, test_core))
}

/// Measures the idle footprint of a release agent in three states: without
/// a link to the core, with a link that cannot connect, and connected to a
/// test core (the `test_core` example, in its own process). Each state is
/// measured twice: an agent built without SSH (feature `ssh` off: the
/// reference), and the release agent with `[agent.ssh]` listening. Each
/// agent runs in the foreground with a development configuration; its
/// `agent.idle_footprint` event (5 s after start) gives the resident
/// memory.
///
/// Fails (ADR-0009) when, in any state, the agent with SSH:
/// - takes more than the accepted SSH cost over the reference
///   ([`SSH_ACCEPTED_BYTES`]);
/// - loads a library or DLL the reference loads in no state;
/// - loads a GUI or COM DLL (`user32`, `gdi32`, `win32u`, `combase`,
///   `ole32`, `oleaut32`).
fn footprint(args: &[String]) -> Result<()> {
    use std::io::BufRead;
    use std::process::Stdio;

    let target = match args {
        [] => None,
        [flag, triple] if flag == "--target" => Some(triple.as_str()),
        _ => return Err(format!("footprint takes [--target TRIPLE]\n\n{USAGE}").into()),
    };
    let (exe, reference, test_core) = footprint_binaries(target)?;

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
            .map(|(state, core)| {
                let without = measure(&reference, &dir, core, None)?;
                let with = measure(&exe, &dir, core, Some(free_port()?))?;
                Ok((state, without, with))
            })
            .collect::<Result<Vec<_>>>()
        });
    drop(core.stdin.take());
    let _ = core.wait();
    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_file(&reference);

    let measures = measures?;
    // A library the reference loads in some state is not one the SSH server
    // adds: listening on a socket loads the Winsock provider (mswsock.dll)
    // before the reference opens its first socket.
    let reference_modules: Vec<String> = measures
        .iter()
        .flat_map(|(_, without, _)| without.modules.iter().cloned())
        .collect();
    let mut failures = Vec::new();
    for (state, without, with) in measures {
        for (name, m) in [("without SSH", &without), ("with SSH", &with)] {
            let mib = mib(m.bytes);
            let verdict = if mib <= FOOTPRINT_TARGET_MIB {
                "within"
            } else {
                "ABOVE"
            };
            println!(
                "idle footprint ({state}, {name}): {mib:.2} MiB resident ({verdict} the \
                 indicative {FOOTPRINT_TARGET_MIB} MiB target){}",
                m.detail
            );
        }
        let delta = with.bytes.saturating_sub(without.bytes);
        #[expect(clippy::cast_precision_loss, reason = "display only")]
        let percent = delta as f64 * 100.0 / without.bytes.max(1) as f64;
        println!(
            "  SSH cost ({state}): {:+.2} MiB ({percent:+.1} %), modules: {} without, {} with",
            mib(delta),
            without.modules.len(),
            with.modules.len()
        );
        failures.extend(compare(state, &without, &with, &reference_modules));
    }
    if failures.is_empty() {
        println!(
            "footprint: SSH cost within the accepted {:.2} MiB (ADR-0009), no module \
             loaded in addition, no GUI or COM DLL",
            mib(SSH_ACCEPTED_BYTES)
        );
        Ok(())
    } else {
        Err(format!("footprint (ADR-0009):\n  {}", failures.join("\n  ")).into())
    }
}

#[expect(clippy::cast_precision_loss, reason = "display only")]
fn mib(bytes: u64) -> f64 {
    bytes as f64 / 1_048_576.0
}

/// The blocking differences between the reference and the agent with SSH.
fn compare(
    state: &str,
    without: &Measure,
    with: &Measure,
    reference_modules: &[String],
) -> Vec<String> {
    let mut failures = Vec::new();
    let delta = with.bytes.saturating_sub(without.bytes);
    if delta > SSH_ACCEPTED_BYTES {
        failures.push(format!(
            "{state}: the agent with SSH takes {delta} bytes more than without, over the \
             accepted {SSH_ACCEPTED_BYTES} (ADR-0009)",
        ));
    }
    let extra: Vec<&str> = with
        .modules
        .iter()
        .filter(|m| !without.modules.contains(m) && !reference_modules.contains(m))
        .map(String::as_str)
        .collect();
    if !extra.is_empty() {
        failures.push(format!(
            "{state}: loaded with SSH only: {}",
            extra.join(", ")
        ));
    }
    let forbidden: Vec<&str> = with
        .modules
        .iter()
        .map(String::as_str)
        .filter(|m| pe::is_forbidden(m))
        .collect();
    if !forbidden.is_empty() {
        failures.push(format!(
            "{state}: GUI or COM DLLs loaded at rest: {}",
            forbidden.join(", ")
        ));
    }
    failures
}

/// A TCP port free on the loopback now.
fn free_port() -> Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}

/// Runs one agent until its `agent.idle_footprint` event; `core` is the
/// core address, `None` for an agent without link (no `tls_core_ca`);
/// `ssh` the port of `[agent.ssh]`, `None` for none.
fn measure(exe: &Path, dir: &Path, core: Option<&str>, ssh: Option<u16>) -> Result<Measure> {
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
    let ssh_section = ssh.map_or_else(String::new, |port| {
        format!("\n[agent.ssh]\nlisten = [\"127.0.0.1:{port}\"]\n")
    });
    let config = format!(
        "mode = \"development\"\n\n[agent]\ngateway_group = \"{FOOTPRINT_GROUP}\"\n\
         core_address = \"{}\"\ntls_certificate = \"{}\"\ntls_private_key = \"{}\"\n{ca}\
         replay_journal = \"{}\"\ncontrol_endpoint = \"{endpoint}\"\n{ssh_section}",
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
    let mut ssh_started = false;
    let mut footprint = None;
    for line in std::io::BufReader::new(stdout)
        .lines()
        .map_while(std::result::Result::ok)
    {
        connected |= line.contains("agent.core_connected");
        ssh_started |= line.contains("agent.ssh_started");
        if line.contains("agent.idle_footprint") {
            footprint = Some(line);
            break;
        }
    }
    let detail = breakdown(child.id());
    let modules = modules(child.id(), exe);
    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_file(dir.join("state/replay.journal"));
    let line = footprint.ok_or("the agent stopped before reporting its footprint")?;
    let modules = modules?;
    if core.is_some_and(|c| c != "127.0.0.1:9") && !connected {
        return Err("the agent did not connect to the test core".into());
    }
    if ssh.is_some() && !ssh_started {
        return Err("the SSH server of the agent did not start".into());
    }
    let bytes = resident_bytes_of(&line).ok_or_else(|| format!("no resident_bytes in: {line}"))?;
    Ok(Measure {
        bytes,
        detail,
        modules,
    })
}

/// The shared libraries (Linux, `/proc/<pid>/maps`) or DLLs (Windows, through
/// PowerShell) loaded by `pid`, running `exe`, lower case, sorted.
///
/// # Errors
///
/// The list cannot be read, or it cannot be the one of the agent (see
/// [`windows_modules`] and [`linux_modules`]): an empty list must not pass
/// the module checks unnoticed.
fn modules(pid: u32, exe: &Path) -> Result<Vec<String>> {
    let mut found = if cfg!(windows) {
        let script =
            format!("(Get-Process -Id {pid}).Modules | ForEach-Object {{ $_.ModuleName }}");
        let out = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()
            .map_err(|e| format!("modules of the agent: PowerShell: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "modules of the agent: PowerShell failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            )
            .into());
        }
        windows_modules(&String::from_utf8_lossy(&out.stdout))?
    } else if cfg!(target_os = "linux") {
        let maps = fs::read_to_string(format!("/proc/{pid}/maps"))
            .map_err(|e| format!("modules of the agent: /proc/{pid}/maps: {e}"))?;
        let name = exe
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or("modules of the agent: executable without a name")?;
        linux_modules(&maps, name)?
    } else {
        return Err("modules of the agent: not listed on this system".into());
    };
    found.sort();
    found.dedup();
    Ok(found)
}

/// The DLLs of a PowerShell module list. Every process maps `ntdll.dll`
/// and `kernel32.dll`: a list without them was not read from the agent.
fn windows_modules(text: &str) -> Result<Vec<String>> {
    let found = parse_module_names(text);
    let missing: Vec<&str> = ["ntdll.dll", "kernel32.dll"]
        .into_iter()
        .filter(|m| !found.iter().any(|f| f == m))
        .collect();
    if missing.is_empty() {
        Ok(found)
    } else {
        Err(format!(
            "modules of the agent: {} missing from the list ({} modules): not the list of a \
             running process",
            missing.join(", "),
            found.len()
        )
        .into())
    }
}

/// The shared libraries of a `/proc/<pid>/maps` that maps the executable
/// `exe` (file name). A static musl binary maps no shared library: an
/// empty list is then expected, but the executable is always mapped.
fn linux_modules(maps: &str, exe: &str) -> Result<Vec<String>> {
    let mapped = maps
        .lines()
        .filter_map(|l| l.split_whitespace().nth(5))
        .any(|p| p.rsplit('/').next() == Some(exe));
    if !mapped {
        return Err(format!(
            "modules of the agent: {exe} is not mapped in the process: not the agent"
        )
        .into());
    }
    Ok(parse_maps(maps))
}

/// One module name per line (PowerShell), the executable excluded.
fn parse_module_names(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.trim().to_ascii_lowercase())
        .filter(|l| {
            Path::new(l)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("dll"))
        })
        .collect()
}

/// The shared libraries of a `/proc/<pid>/maps`.
fn parse_maps(maps: &str) -> Vec<String> {
    maps.lines()
        .filter_map(|l| l.split_whitespace().nth(5))
        .filter_map(|p| p.rsplit('/').next())
        .filter(|name| name.contains(".so"))
        .map(str::to_ascii_lowercase)
        .collect()
}

/// Linux: anonymous (heap, stacks) and file-backed (code of the binary and
/// of the libraries) resident memory, the proportional (PSS) and private
/// resident memory (pages shared with no other process), and the thread
/// count, to explain a difference. Empty elsewhere.
fn breakdown(pid: u32) -> String {
    let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else {
        return String::new();
    };
    let rollup = fs::read_to_string(format!("/proc/{pid}/smaps_rollup")).unwrap_or_default();
    let field = |text: &str, name: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(name))
            .map_or("?", str::trim)
            .to_owned()
    };
    format!(
        " [anonymous {}, file-backed {}, PSS {}, private {}, threads {}]",
        field(&status, "RssAnon:"),
        field(&status, "RssFile:"),
        field(&rollup, "Pss:"),
        private_kib(&rollup).map_or_else(|| "?".to_owned(), |k| format!("{k} kB")),
        field(&status, "Threads:")
    )
}

/// `Private_Clean` plus `Private_Dirty` of a `smaps_rollup`, in KiB.
fn private_kib(rollup: &str) -> Option<u64> {
    let kib = |name: &str| {
        rollup
            .lines()
            .find_map(|l| l.strip_prefix(name))?
            .trim()
            .trim_end_matches("kB")
            .trim()
            .parse::<u64>()
            .ok()
    };
    Some(kib("Private_Clean:")? + kib("Private_Dirty:")?)
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

/// The SSH identification every Ostena SSH end sends
/// (`ostena_ssh::config::IDENTIFICATION`): present in a binary that links
/// the SSH server.
const SSH_MARKER: &[u8] = b"SSH-2.0-Ostena";

/// Fails if a test-only feature (`testing`) of an Ostena crate is enabled in
/// the release build of ostena-cli, if the SSH server is not linked into
/// it, or, for `binary`: if it contains the test core, lacks the SSH server,
/// or (Windows) imports a GUI or COM DLL statically (ADR-0009).
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
    match ssh_without_library(&String::from_utf8_lossy(&out.stdout)) {
        SshLink::WithLibrary => eprintln!("ostena-ssh linked with its SSH library (feature russh)"),
        SshLink::Absent => {
            return Err(
                "ostena-ssh is not in the release build of ostena-cli (feature `ssh` off?): the \
                 agent would have no SSH server (ADR-0010)"
                    .into(),
            );
        }
        SshLink::WithoutLibrary => {
            return Err(
                "ostena-ssh is linked without its feature `russh`: the release binary would \
                 have no SSH server (ADR-0009)"
                    .into(),
            );
        }
    }
    if let Some(path) = binary {
        let bytes = fs::read(path)?;
        if contains(&bytes, TESTING_MARKER) {
            return Err(format!("{path} contains the test core").into());
        }
        eprintln!("{path}: no test core");
        if !contains(&bytes, SSH_MARKER) {
            return Err(
                format!("{path} has no SSH server (built without the feature `ssh`?)").into(),
            );
        }
        eprintln!("{path}: SSH server linked");
        if pe::is_pe(&bytes) {
            check_windows_imports(path, &bytes)?;
        }
    }
    Ok(())
}

/// ADR-0009: no GUI or COM DLL in the static imports of the Windows binary;
/// `oleaut32.dll`, imported by the SSH library, must be delay-loaded.
fn check_windows_imports(path: &str, bytes: &[u8]) -> Result<()> {
    let imports = pe::imports(bytes).map_err(|e| format!("{path}: {e}"))?;
    eprintln!("{path}: static imports: {}", imports.static_dlls.join(", "));
    eprintln!("{path}: delay-loaded: {}", imports.delayed.join(", "));
    let forbidden = imports.forbidden();
    if !forbidden.is_empty() {
        return Err(format!(
            "{path} imports GUI or COM DLLs statically: {} (ADR-0009: delay-load them, see \
             crates/ostena-cli/build.rs)",
            forbidden.join(", ")
        )
        .into());
    }
    eprintln!(
        "{path}: no GUI or COM DLL imported statically ({}), nor an API set resolving to \
         one ({}*)",
        pe::FORBIDDEN.join(", "),
        pe::FORBIDDEN_API_SETS.join("*, ")
    );
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

/// How `ostena-ssh` is linked into the release build.
#[derive(Debug, PartialEq, Eq)]
enum SshLink {
    /// Not a dependency: refused, the agent would have no SSH server.
    Absent,
    /// With the `russh` feature, as the agent needs it.
    WithLibrary,
    /// Without it: only the pre-check, no SSH server. Refused.
    WithoutLibrary,
}

/// Reads a `cargo tree -e normal,features --prefix none` output. The
/// feature `russh` shows as an edge only when a dependency declaration
/// enables it; enabled by a feature of ostena-cli itself (`ssh`, while
/// `ostena login` links ostena-ssh without it), only the library shows.
fn ssh_without_library(tree: &str) -> SshLink {
    let lines: Vec<&str> = tree.lines().map(str::trim).collect();
    if !lines.iter().any(|l| l.starts_with("ostena-ssh v")) {
        SshLink::Absent
    } else if lines
        .iter()
        .any(|l| l.starts_with("ostena-ssh feature \"russh\"") || l.starts_with("russh v"))
    {
        SshLink::WithLibrary
    } else {
        SshLink::WithoutLibrary
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Fuzz target run by `cargo xtask fuzz`.
const FUZZ_TARGETS: [&str; 23] = [
    "grant_decode",
    "scope_target",
    "scope_policy",
    "frame_decode",
    "frame_reassembly",
    "tunnel_control_decode",
    "tunnel_mux_decode",
    "ssh_precheck",
    "ssh_certificate",
    "ssh_login",
    "ssh_sftp",
    "audit_decode",
    "audit_verify",
    "login_messages",
    "web_messages",
    "release_manifest",
    "recorder_decode",
    "recorder_cast",
    "rdp_x224",
    "rdp_mcs_gcc",
    "rdp_tsrequest",
    "rdp_license",
    "rdp_session",
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
    fn ci_runs_every_fuzz_target() {
        let workflows = workspace_root().unwrap().join(".github/workflows");
        let text = fs::read_to_string(workflows.join("fuzz-nightly.yml")).unwrap();
        let line = text
            .lines()
            .map(str::trim)
            .find_map(|l| l.strip_prefix("target: ["))
            .expect("no fuzz matrix in fuzz-nightly.yml");
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
            "fuzz-nightly.yml is out of sync with FUZZ_TARGETS"
        );
        // The smoke run names no target, so it runs all of them.
        let ci = fs::read_to_string(workflows.join("ci.yml")).unwrap();
        assert!(
            ci.lines().any(|l| l.trim() == "- run: cargo xtask fuzz 30"),
            "ci.yml must run `cargo xtask fuzz 30` without a target list"
        );
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

    fn measure_of(bytes: u64, modules: &[&str]) -> Measure {
        Measure {
            bytes,
            detail: String::new(),
            modules: modules.iter().map(|m| (*m).to_owned()).collect(),
        }
    }

    #[test]
    fn footprint_ssh_cost_blocks_over_the_accepted_ceiling_only() {
        const MIB: u64 = 1024 * 1024;
        let base = measure_of(7 * MIB, &["kernel32.dll"]);
        let none: Vec<String> = Vec::new();
        // Up to the ceiling: accepted.
        let at = measure_of(7 * MIB + SSH_ACCEPTED_BYTES, &["kernel32.dll"]);
        assert_eq!(compare("s", &base, &at, &[]), none);
        // One page over it: blocking, whatever the base.
        let over = measure_of(7 * MIB + SSH_ACCEPTED_BYTES + 4096, &["kernel32.dll"]);
        let failures = compare("s", &base, &over, &[]);
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(failures[0].contains("ADR-0009"));
        let big = measure_of(300 * MIB, &[]);
        let failures = compare(
            "s",
            &big,
            &measure_of(300 * MIB + SSH_ACCEPTED_BYTES + 4096, &[]),
            &[],
        );
        assert_eq!(failures.len(), 1, "{failures:?}");
        // Smaller with SSH: fine.
        let smaller = measure_of(6 * MIB, &["kernel32.dll"]);
        assert_eq!(compare("s", &base, &smaller, &[]), none);
    }

    #[test]
    fn footprint_refuses_extra_and_com_modules() {
        let base = measure_of(100, &["kernel32.dll", "ws2_32.dll"]);
        let with = measure_of(
            100,
            &["combase.dll", "kernel32.dll", "oleaut32.dll", "ws2_32.dll"],
        );
        let failures = compare("connected", &base, &with, &[]);
        assert_eq!(failures.len(), 2, "{failures:?}");
        assert!(failures[0].contains("combase.dll, oleaut32.dll"));
        assert!(failures[1].contains("GUI or COM"));
    }

    #[test]
    fn footprint_accepts_a_module_the_reference_loads_in_another_state() {
        // Without a link, only the agent with SSH has a socket: Winsock loads
        // its provider, which the reference loads once it connects.
        let base = measure_of(100, &["kernel32.dll"]);
        let with = measure_of(100, &["kernel32.dll", "mswsock.dll"]);
        let none: Vec<String> = Vec::new();
        assert_eq!(
            compare("without link", &base, &with, &["mswsock.dll".to_owned()]),
            none
        );
        // A library the reference never loads still blocks.
        let failures = compare("without link", &base, &with, &["kernel32.dll".to_owned()]);
        assert_eq!(failures.len(), 1, "{failures:?}");
        // A forbidden DLL blocks even if the reference loads it somewhere.
        let com = measure_of(100, &["kernel32.dll", "ole32.dll"]);
        let failures = compare("connected", &base, &com, &["ole32.dll".to_owned()]);
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(failures[0].contains("GUI or COM"));
    }

    #[test]
    fn reads_loaded_modules() {
        let maps = "\
55d0c0a00000-55d0c0a20000 r--p 00000000 08:01 1234 /usr/local/bin/ostena
7f00a0000000-7f00a0020000 r-xp 00000000 08:01 42 /usr/lib/x86_64-linux-gnu/libc.so.6
7f00a0100000-7f00a0120000 r--p 00000000 08:01 43 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f00a0200000-7f00a0220000 rw-p 00000000 00:00 0
7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0 [stack]
";
        assert_eq!(parse_maps(maps), ["libc.so.6", "ld-linux-x86-64.so.2"]);
        assert_eq!(
            parse_module_names("ostena.exe\r\nntdll.dll\r\nKERNEL32.DLL\r\n\r\n"),
            ["ntdll.dll", "kernel32.dll"]
        );
    }

    #[test]
    fn module_lists_that_cannot_be_the_agent_fail() {
        // Windows: nothing, or no ntdll.dll and kernel32.dll.
        assert!(windows_modules("").is_err());
        assert!(windows_modules("ostena.exe\r\nws2_32.dll\r\n").is_err());
        assert!(windows_modules("ntdll.dll\r\n").is_err());
        assert_eq!(
            windows_modules("ostena.exe\r\nNTDLL.DLL\r\nkernel32.dll\r\n").unwrap(),
            ["ntdll.dll", "kernel32.dll"]
        );
        // Linux, static musl: the executable alone, no shared library.
        let musl = "\
55d0c0a00000-55d0c0a20000 r--p 00000000 08:01 1234 /tmp/x/ostena
55d0c0a20000-55d0c0b20000 r-xp 00020000 08:01 1234 /tmp/x/ostena
7f00a0200000-7f00a0220000 rw-p 00000000 00:00 0
7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0 [stack]
7ffd00100000-7ffd00102000 r-xp 00000000 00:00 0 [vdso]
";
        assert_eq!(linux_modules(musl, "ostena").unwrap(), Vec::<String>::new());
        // Nothing, or another executable: not the agent.
        assert!(linux_modules("", "ostena").is_err());
        assert!(linux_modules(musl, "ostena-reference").is_err());
    }

    #[test]
    fn reads_private_memory() {
        let rollup = "Rss:  9000 kB\nPss:  6000 kB\nPrivate_Clean:  300 kB\n\
                      Private_Dirty:  900 kB\n";
        assert_eq!(private_kib(rollup), Some(1200));
        assert_eq!(private_kib("Rss: 1 kB\n"), None);
    }

    #[test]
    fn release_build_needs_the_ssh_library() {
        assert_eq!(
            ssh_without_library("ostena-cli v0.0.0 (C:\\x)\n"),
            SshLink::Absent
        );
        let with = "ostena-ssh v0.0.0 (C:\\x)\nostena-ssh feature \"default\"\nostena-ssh feature \"russh\"\n";
        assert_eq!(ssh_without_library(with), SshLink::WithLibrary);
        let by_root_feature =
            "ostena-ssh v0.0.0 (C:\\x)\nrussh v0.65.1\nrussh feature \"aws-lc-rs\"\n";
        assert_eq!(ssh_without_library(by_root_feature), SshLink::WithLibrary);
        let without = "ostena-ssh v0.0.0 (C:\\x)\nrussh feature \"aws-lc-rs\"\n";
        assert_eq!(ssh_without_library(without), SshLink::WithoutLibrary);
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
