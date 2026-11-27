//! `cargo xtask portal` (ADR-0020, § 1): checks the pinned Node and the npm
//! lockfile, installs the packages without running any of their code
//! (offline from `vendor/npm/` when it exists), type-checks, builds and
//! packs the portal, then enforces its budget.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::json::{self, Value};
use crate::{Result, VENDOR_CONFIG, cargo, run_in, workspace_root};

/// The npm cache produced by `cargo xtask vendor`, next to `vendor/`.
pub(crate) const NPM_VENDOR_DIR: &str = "vendor/npm";

/// The package of the end-to-end tests, under `portal/`.
const E2E_DIR: &str = "e2e";

/// Licences allowed for npm packages: the list of CLAUDE.md, plus 0BSD (BSD
/// family).
const ALLOWED_LICENSES: &[&str] = &[
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Zlib",
    "MPL-2.0",
    "0BSD",
];

/// The fonts embedded in the portal, the only packages allowed under
/// OFL-1.1 (ADR-0009, amendment of 2026-11-26); shipped, never a tool.
const FONT_PACKAGES: &[&str] = &["@fontsource-variable/inter"];

/// Packages declaring an install script. Scripts never run
/// (`ignore-scripts`); this closed list makes any new one visible in review.
/// fsevents: macOS only, never installed on the build platforms.
const INSTALL_SCRIPTS: &[&str] = &["fsevents"];

/// Registry of every package.
const REGISTRY: &str = "https://registry.npmjs.org/";

/// Sum of the files of the portal sent compressed (brotli, fonts included,
/// WebAssembly excluded), in bytes.
pub(crate) const BUDGET_TOTAL: u64 = 400_000;
/// What the login page loads, compressed, in bytes.
pub(crate) const BUDGET_LOGIN: u64 = 150_000;

fn npm() -> Command {
    Command::new(if cfg!(windows) { "npm.cmd" } else { "npm" })
}

/// `cargo xtask portal [--offline]`.
pub(crate) fn portal(args: &[String]) -> Result<()> {
    let offline = match args {
        [] => false,
        [flag] if flag == "--offline" => true,
        _ => return Err("portal takes [--offline]".into()),
    };
    let root = workspace_root()?;
    let dir = root.join("portal");
    check_node(&dir)?;
    check_manifest(&dir)?;
    check_lockfile(&dir)?;
    // The end-to-end tests: their own package, never installed by the
    // offline build, checked by the same rules (ADR-0020, § 6).
    let e2e = dir.join(E2E_DIR);
    check_manifest(&e2e)?;
    check_lockfile(&e2e)?;
    eprintln!(
        "package.json and package-lock.json (portal and {E2E_DIR}/): exact versions, registry, \
         integrity, licences"
    );

    let cache = root.join(NPM_VENDOR_DIR);
    let mut install = npm();
    install.args(["ci", "--ignore-scripts", "--no-audit", "--no-fund"]);
    if cache.is_dir() {
        install.arg("--offline").arg("--cache").arg(&cache);
    } else if offline {
        return Err(format!(
            "{NPM_VENDOR_DIR}/ absent: run `cargo xtask vendor` while connected first"
        )
        .into());
    } else {
        eprintln!("{NPM_VENDOR_DIR}/ absent: installing from the registry (not an offline build)");
    }
    run_in(install, &dir)?;
    web_client(&root, offline)?;
    let mut check = npm();
    check.args(["run", "check"]);
    run_in(check, &dir)?;
    let mut build = npm();
    build.args(["run", "build"]);
    run_in(build, &dir)?;

    let manifest = json::parse(&fs::read_to_string(dir.join("dist/manifest.json"))?)?;
    let report = budget(&manifest)?;
    if let Some(path) = std::env::var_os("GITHUB_STEP_SUMMARY") {
        use std::io::Write as _;
        fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)?
            .write_all(report.markdown.as_bytes())?;
    }
    print!("{}", report.text);
    if report.failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "portal budget (ADR-0020):\n  {}",
            report.failures.join("\n  ")
        )
        .into())
    }
}

/// The glue tool of `ostena-web-client`, its own workspace (ADR-0020).
pub(crate) const BINDGEN_MANIFEST: &str = "tools/wasm-bindgen/Cargo.toml";
/// Where the WebAssembly client and its glue are written for Vite.
const WASM_OUT: &str = "portal/src/wasm";

/// The arguments that make cargo build without network: `--offline`, and
/// the vendored sources when `cargo xtask vendor` wrote them.
fn cargo_offline(root: &Path, offline: bool) -> Vec<String> {
    let mut args = Vec::new();
    if offline {
        args.push("--offline".to_owned());
        if root.join(VENDOR_CONFIG).is_file() {
            args.extend(["--config".to_owned(), VENDOR_CONFIG.to_owned()]);
        }
    }
    args
}

/// Builds `ostena-web-client` for `wasm32-unknown-unknown` and writes its
/// JavaScript glue into `portal/src/wasm/`, by the tool of
/// `tools/wasm-bindgen` built from its own lockfile.
///
/// The paths of the build machine are remapped (`/ostena`, `/cargo`), so
/// that the module is the same whatever the directory of the sources; the
/// module keeps its custom sections for the glue tool (`strip` off), which
/// removes the names and producers sections itself.
fn web_client(root: &Path, offline: bool) -> Result<()> {
    let target_dir = root.join("target").join("portal");
    let cargo_home = std::env::var_os("CARGO_HOME").map_or_else(
        || {
            std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(|h| Path::new(&h).join(".cargo"))
                .unwrap_or_default()
        },
        std::path::PathBuf::from,
    );
    let flags = format!(
        "--remap-path-prefix={}=/ostena\x1f--remap-path-prefix={}=/cargo",
        root.display(),
        cargo_home.display()
    );
    let mut build = cargo();
    build
        .args([
            "build",
            "--release",
            "--locked",
            "--package",
            "ostena-web-client",
            "--target",
            "wasm32-unknown-unknown",
        ])
        .arg("--target-dir")
        .arg(&target_dir)
        .args(cargo_offline(root, offline))
        .env("CARGO_ENCODED_RUSTFLAGS", flags)
        .env("CARGO_PROFILE_RELEASE_STRIP", "false");
    run_in(build, root)?;

    let tools_dir = root.join("target").join("tools");
    let mut tool = cargo();
    tool.args([
        "build",
        "--release",
        "--locked",
        "--manifest-path",
        BINDGEN_MANIFEST,
    ])
    .arg("--target-dir")
    .arg(&tools_dir)
    .args(cargo_offline(root, offline));
    run_in(tool, root)?;

    let out = root.join(WASM_OUT);
    if out.exists() {
        fs::remove_dir_all(&out)?;
    }
    let mut glue = Command::new(tools_dir.join("release").join(format!(
        "ostena-wasm-bindgen{}",
        std::env::consts::EXE_SUFFIX
    )));
    glue.arg(
        target_dir
            .join("wasm32-unknown-unknown")
            .join("release")
            .join("ostena_web_client.wasm"),
    )
    .arg(&out);
    run_in(glue, root)
}

/// `.node-version` holds the exact version of Node, which must be the one
/// running.
fn check_node(dir: &Path) -> Result<()> {
    let pinned = fs::read_to_string(dir.join(".node-version"))?;
    let pinned = pinned.trim();
    if !is_exact_version(pinned) {
        return Err(format!("portal/.node-version: not an exact version: {pinned}").into());
    }
    let out = Command::new("node")
        .arg("--version")
        .output()
        .map_err(|e| {
            format!("node not found ({e}): install Node {pinned} (portal/.node-version)")
        })?;
    let running = String::from_utf8_lossy(&out.stdout);
    let running = running.trim().trim_start_matches('v');
    if running != pinned {
        return Err(format!(
            "Node {running} runs, portal/.node-version pins {pinned}: the build would not be \
             reproducible"
        )
        .into());
    }
    eprintln!("Node {running}, as pinned by portal/.node-version");
    Ok(())
}

/// `x.y.z`, digits only.
fn is_exact_version(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// `package.json`: exact versions only, and `.npmrc` turns scripts off.
fn check_manifest(dir: &Path) -> Result<()> {
    let manifest = json::parse(&fs::read_to_string(dir.join("package.json"))?)?;
    for section in ["dependencies", "devDependencies"] {
        for (name, version) in manifest
            .get(section)
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            let version = version.as_str().unwrap_or_default();
            if !is_exact_version(version) {
                return Err(format!(
                    "package.json: {section}.{name} = {version:?}: exact versions only (ADR-0020)"
                )
                .into());
            }
        }
    }
    for forbidden in [
        "optionalDependencies",
        "peerDependencies",
        "bundleDependencies",
    ] {
        if manifest.get(forbidden).is_some() {
            return Err(format!("package.json: no {forbidden} (ADR-0020)").into());
        }
    }
    let npmrc = fs::read_to_string(dir.join(".npmrc"))?;
    if !npmrc.lines().any(|l| l.trim() == "ignore-scripts=true") {
        return Err("portal/.npmrc must set ignore-scripts=true (ADR-0020)".into());
    }
    Ok(())
}

fn check_lockfile(dir: &Path) -> Result<()> {
    let lock = json::parse(&fs::read_to_string(dir.join("package-lock.json"))?)?;
    let failures = lockfile_failures(&lock);
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("package-lock.json (ADR-0020):\n  {}", failures.join("\n  ")).into())
    }
}

/// Every breach of the lockfile rules: format 3, each package from the
/// registry with a SHA-512 integrity, an exact version, an allowed licence,
/// no install script outside [`INSTALL_SCRIPTS`].
pub(crate) fn lockfile_failures(lock: &Value) -> Vec<String> {
    let mut failures = Vec::new();
    if lock.get("lockfileVersion").and_then(Value::as_u64) != Some(3) {
        failures.push("lockfileVersion must be 3".to_owned());
    }
    let Some(packages) = lock.get("packages").and_then(Value::as_object) else {
        failures.push("no packages".to_owned());
        return failures;
    };
    for (key, entry) in packages {
        if key.is_empty() {
            continue;
        }
        let name = package_name(key);
        if !key.starts_with("node_modules/") || entry.get("link").is_some() {
            failures.push(format!("{key}: a linked or local package"));
            continue;
        }
        let version = entry.get("version").and_then(Value::as_str).unwrap_or("");
        if !is_exact_version(version.split('-').next().unwrap_or("")) {
            failures.push(format!("{key}: version {version:?}"));
        }
        let resolved = entry.get("resolved").and_then(Value::as_str).unwrap_or("");
        if !resolved.starts_with(REGISTRY) || !resolved.to_ascii_lowercase().ends_with(".tgz") {
            failures.push(format!("{key}: not from {REGISTRY}: {resolved:?}"));
        }
        let integrity = entry.get("integrity").and_then(Value::as_str).unwrap_or("");
        if !integrity.starts_with("sha512-") || integrity.contains(' ') {
            failures.push(format!("{key}: integrity is not a single SHA-512"));
        }
        let license = entry.get("license").and_then(Value::as_str).unwrap_or("");
        let dev = entry.get("dev").and_then(Value::as_bool) == Some(true);
        let font = FONT_PACKAGES.contains(&name) && !dev;
        if !license_allowed(license, font) {
            failures.push(format!("{key}: licence {license:?} not allowed"));
        }
        if entry.get("hasInstallScript").and_then(Value::as_bool) == Some(true)
            && !INSTALL_SCRIPTS.contains(&name)
        {
            failures.push(format!(
                "{key}: declares an install script (never run; add it to the reviewed list)"
            ));
        }
    }
    failures
}

/// `node_modules/a/node_modules/@s/b` → `@s/b`.
fn package_name(key: &str) -> &str {
    key.rsplit_once("node_modules/").map_or(key, |(_, n)| n)
}

/// An SPDX expression of `OR` and `AND` (parentheses flattened): allowed
/// when one alternative has only allowed licences.
fn license_allowed(expression: &str, font: bool) -> bool {
    let cleaned = expression.replace(['(', ')'], " ");
    cleaned.split(" OR ").any(|alternative| {
        let terms: Vec<&str> = alternative.split(" AND ").map(str::trim).collect();
        !terms.is_empty()
            && terms
                .iter()
                .all(|t| ALLOWED_LICENSES.contains(t) || (font && *t == "OFL-1.1"))
    })
}

/// The budget lines and their failures.
struct Report {
    text: String,
    markdown: String,
    failures: Vec<String>,
}

fn budget(manifest: &Value) -> Result<Report> {
    let get = |key: &str| {
        manifest
            .get("budget")
            .and_then(|b| b.get(key))
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("portal/dist/manifest.json: no budget.{key}"))
    };
    let (total, login, wasm) = (get("total")?, get("login")?, get("wasm")?);
    let digest = manifest
        .get("digest")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut failures = Vec::new();
    if total > BUDGET_TOTAL {
        failures.push(format!("total {total} B over {BUDGET_TOTAL} B"));
    }
    if login > BUDGET_LOGIN {
        failures.push(format!("login page {login} B over {BUDGET_LOGIN} B"));
    }
    #[expect(clippy::cast_precision_loss, reason = "display only")]
    let kb = |n: u64| format!("{:.1} Ko", n as f64 / 1000.0);
    let text = format!(
        "portal: digest of SHA256SUMS {digest}\n\
         portal: total {} of {} (brotli, fonts included, without WebAssembly)\n\
         portal: login page {} of {}\n\
         portal: WebAssembly client {} (followed, no threshold at M2)\n",
        kb(total),
        kb(BUDGET_TOTAL),
        kb(login),
        kb(BUDGET_LOGIN),
        kb(wasm),
    );
    let markdown = format!(
        "## Portail (ADR-0020)\n\n\
         | Mesure (brotli) | Taille | Budget |\n|---|---|---|\n\
         | Total, polices comprises, hors WebAssembly | {} | {} |\n\
         | Page de connexion | {} | {} |\n\
         | Client WebAssembly | {} | suivi, sans seuil |\n\n\
         Empreinte du manifeste (`SHA256SUMS`) : `{digest}`\n\n",
        kb(total),
        kb(BUDGET_TOTAL),
        kb(login),
        kb(BUDGET_LOGIN),
        kb(wasm),
    );
    Ok(Report {
        text,
        markdown,
        failures,
    })
}

/// `cargo xtask vendor`, npm part: fills `vendor/npm/` (an npm cache, each
/// archive addressed by its integrity) from the lockfile, for the build
/// platform. `npm ci --offline --cache vendor/npm` then installs without
/// network.
pub(crate) fn vendor_npm(root: &Path) -> Result<()> {
    let dir = root.join("portal");
    check_lockfile(&dir)?;
    let cache = root.join(NPM_VENDOR_DIR);
    if cache.exists() {
        fs::remove_dir_all(&cache)?;
    }
    let mut install = npm();
    install
        .args([
            "ci",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
            "--prefer-online",
        ])
        .arg("--cache")
        .arg(&cache);
    run_in(install, &dir)?;
    eprintln!(
        "npm packages cached into {NPM_VENDOR_DIR}/. Offline build:\n  cargo xtask portal --offline"
    );
    Ok(())
}

/// The SBOM of the portal (CycloneDX 1.5): the npm packages it ships
/// (`dependencies`, not the build tools), from the lockfile, joined to those
/// of the crates (ADR-0020). Written here rather than by `npm sbom`, whose
/// `--omit dev` drops packages that a tool also depends on (svelte).
pub(crate) fn sbom(root: &Path, out_dir: &Path) -> Result<usize> {
    let lock = json::parse(&fs::read_to_string(root.join("portal/package-lock.json"))?)?;
    let text = sbom_json(&lock)?;
    fs::write(out_dir.join("ostena-portal.cdx.json"), text)?;
    Ok(1)
}

fn sbom_json(lock: &Value) -> Result<String> {
    let mut components = Vec::new();
    for (key, entry) in lock
        .get("packages")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        if key.is_empty() || entry.get("dev").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let name = package_name(key);
        let field = |f: &str| entry.get(f).and_then(Value::as_str).unwrap_or_default();
        let version = field("version");
        let purl_name = name
            .strip_prefix('@')
            .map_or_else(|| name.to_owned(), |scoped| format!("%40{scoped}"));
        let digest = base64_to_hex(field("integrity").trim_start_matches("sha512-"))
            .ok_or_else(|| format!("{key}: unreadable integrity"))?;
        components.push(format!(
            "    {{\"type\": \"library\", \"bom-ref\": \"pkg:npm/{purl_name}@{version}\", \
             \"name\": {}, \"version\": {}, \"purl\": \"pkg:npm/{purl_name}@{version}\", \
             \"licenses\": [{{\"expression\": {}}}], \
             \"hashes\": [{{\"alg\": \"SHA-512\", \"content\": \"{digest}\"}}], \
             \"externalReferences\": [{{\"type\": \"distribution\", \"url\": {}}}]}}",
            quote(name),
            quote(version),
            quote(field("license")),
            quote(field("resolved")),
        ));
    }
    Ok(format!(
        "{{\n  \"bomFormat\": \"CycloneDX\",\n  \"specVersion\": \"1.5\",\n  \"version\": 1,\n  \
         \"metadata\": {{\"component\": {{\"type\": \"application\", \"bom-ref\": \"ostena-portal\", \
         \"name\": \"ostena-portal\", \"licenses\": [{{\"expression\": \"AGPL-3.0-or-later\"}}]}}}},\n  \
         \"components\": [\n{}\n  ]\n}}\n",
        components.join(",\n")
    ))
}

/// A JSON string literal.
fn quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Standard base64 (with padding) to lower-case hex.
fn base64_to_hex(text: &str) -> Option<String> {
    let mut bits = 0u32;
    let mut count = 0;
    let mut out = String::new();
    for b in text.bytes().filter(|&b| b != b'=') {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(v);
        count += 6;
        if count >= 8 {
            count -= 8;
            let _ = write!(out, "{:02x}", (bits >> count) & 0xff);
        }
    }
    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock(entries: &str) -> Value {
        json::parse(&format!(
            r#"{{"lockfileVersion": 3, "packages": {{"": {{"name": "p"}}, {entries}}}}}"#
        ))
        .unwrap()
    }

    const OK: &str = r#""node_modules/a": {"version": "1.2.3", "resolved": "https://registry.npmjs.org/a/-/a-1.2.3.tgz", "integrity": "sha512-AAAA", "license": "MIT"}"#;

    #[test]
    fn the_portal_lockfile_passes() {
        let root = workspace_root().unwrap();
        let text = fs::read_to_string(root.join("portal/package-lock.json")).unwrap();
        assert_eq!(
            lockfile_failures(&json::parse(&text).unwrap()),
            Vec::<String>::new()
        );
        check_manifest(&root.join("portal")).unwrap();
        let e2e = root.join("portal").join(E2E_DIR);
        check_lockfile(&e2e).unwrap();
        check_manifest(&e2e).unwrap();
    }

    #[test]
    fn a_clean_entry_passes() {
        assert_eq!(lockfile_failures(&lock(OK)), Vec::<String>::new());
    }

    #[test]
    fn each_breach_is_refused() {
        for (entry, why) in [
            (
                OK.replace("https://registry.npmjs.org/", "https://evil.example/"),
                "registry",
            ),
            (OK.replace("sha512-AAAA", "sha1-AAAA"), "sha1"),
            (OK.replace(r#""MIT""#, r#""GPL-3.0-only""#), "gpl"),
            (OK.replace(r#""MIT""#, r#""OFL-1.1""#), "ofl outside fonts"),
            (OK.replace(r#""1.2.3""#, r#""^1.2.3""#), "range"),
            (
                OK.replace(
                    r#""license": "MIT""#,
                    r#""license": "MIT", "hasInstallScript": true"#,
                ),
                "script",
            ),
            (
                r#""node_modules/a": {"resolved": "git+https://github.com/a/a.git", "link": true}"#
                    .to_owned(),
                "git",
            ),
        ] {
            assert!(!lockfile_failures(&lock(&entry)).is_empty(), "{why}");
        }
        let v2 = json::parse(r#"{"lockfileVersion": 2, "packages": {}}"#).unwrap();
        assert_eq!(lockfile_failures(&v2).len(), 1);
    }

    #[test]
    fn licences() {
        assert!(license_allowed("MIT", false));
        assert!(license_allowed("(MIT OR GPL-3.0-only)", false));
        assert!(license_allowed("0BSD", false));
        assert!(!license_allowed("MIT AND GPL-3.0-only", false));
        assert!(!license_allowed("", false));
        assert!(!license_allowed("OFL-1.1", false));
        assert!(license_allowed("OFL-1.1", true));
        assert!(!license_allowed("CC-BY-4.0", true));
    }

    #[test]
    fn the_sbom_lists_the_shipped_packages_only() {
        let root = workspace_root().unwrap();
        let text = fs::read_to_string(root.join("portal/package-lock.json")).unwrap();
        let sbom = json::parse(&sbom_json(&json::parse(&text).unwrap()).unwrap()).unwrap();
        let names: Vec<&str> = sbom
            .get("components")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .map(|c| c.get("name").and_then(Value::as_str).unwrap())
            .collect();
        assert!(names.contains(&"svelte") && names.contains(&"@fontsource-variable/inter"));
        assert!(!names.contains(&"vite") && !names.contains(&"typescript"));
        assert_eq!(base64_to_hex("AAEC/w==").as_deref(), Some("000102ff"));
        assert_eq!(quote("a\"b\\c"), r#""a\"b\\c""#);
    }

    #[test]
    fn names_and_versions() {
        assert_eq!(package_name("node_modules/a/node_modules/@s/b"), "@s/b");
        assert!(is_exact_version("22.23.5"));
        assert!(
            !is_exact_version("^1.2.3") && !is_exact_version("1.2") && !is_exact_version("1.2.x")
        );
    }
}
