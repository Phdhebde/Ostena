//! Embeds the portal built by `cargo xtask portal` (ADR-0020, § 1).
//!
//! Reads `portal/dist/SHA256SUMS` (or `$OSTENA_PORTAL_DIST/SHA256SUMS`) and
//! generates `$OUT_DIR/portal.rs`: one entry per served file, with its type,
//! its bytes and those of its brotli variant (`include_bytes!`), and their
//! `ETag`s taken from the digests. No cryptography and no dependency here: the
//! digests are checked at run time by `ostena core portal-manifest`, and by
//! a test. Without `portal/dist/`, the table is empty: the API works, and
//! the portal answers `503` `WEB-E008`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::{env, fs};

/// Served types, by extension: the list of `portal/scripts/pack.mjs`.
const TYPES: &[(&str, &str)] = &[
    ("html", "text/html; charset=utf-8"),
    ("js", "text/javascript; charset=utf-8"),
    ("css", "text/css; charset=utf-8"),
    ("svg", "image/svg+xml"),
    ("json", "application/json"),
    ("txt", "text/plain; charset=utf-8"),
    ("wasm", "application/wasm"),
    ("woff2", "font/woff2"),
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=OSTENA_PORTAL_DIST");
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default());
    let dist = env::var_os("OSTENA_PORTAL_DIST")
        .map_or_else(|| manifest_dir.join("../../portal/dist"), PathBuf::from);
    let sums = dist.join("SHA256SUMS");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap_or_default()).join("portal.rs");
    let code = if sums.is_file() {
        println!("cargo:rerun-if-changed={}", sums.display());
        match generate(&dist, &sums) {
            Ok(code) => code,
            Err(e) => {
                println!("cargo:error=portal/dist invalide : {e}");
                std::process::exit(1);
            }
        }
    } else {
        // A missing path would rerun this script at every build: watch the
        // portal sources instead, where `cargo xtask portal` writes dist/.
        let portal = manifest_dir.join("../../portal");
        if portal.is_dir() {
            println!("cargo:rerun-if-changed={}", portal.display());
        }
        println!(
            "cargo:warning=portail absent ({} introuvable) : ce binaire répondra 503 WEB-E008 \
             à la racine du portail ; cargo xtask portal le construit",
            sums.display()
        );
        "/// No portal in this build.\npub(super) static SUMS: Option<&str> = None;\n\
         /// No portal in this build.\npub(super) static FILES: &[Asset] = &[];\n"
            .to_owned()
    };
    if let Err(e) = fs::write(&out, code) {
        println!("cargo:error={}: {e}", out.display());
        std::process::exit(1);
    }
}

/// A served path: relative, `[A-Za-z0-9._-]` segments separated by `/`,
/// none empty or made of dots only.
fn is_safe_path(path: &str) -> bool {
    !path.is_empty()
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && !segment.bytes().all(|b| b == b'.')
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        })
}

fn generate(dist: &Path, sums: &Path) -> Result<String, String> {
    let text = fs::read_to_string(sums).map_err(|e| format!("{}: {e}", sums.display()))?;
    let mut digests = BTreeMap::new();
    for line in text.lines() {
        let (digest, path) = line
            .split_once("  ")
            .ok_or_else(|| format!("ligne de SHA256SUMS illisible : {line:?}"))?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(format!("empreinte invalide pour {path}"));
        }
        if !is_safe_path(path) {
            return Err(format!("chemin refusé : {path:?}"));
        }
        if digests.insert(path.to_owned(), digest.to_owned()).is_some() {
            return Err(format!("chemin en double : {path}"));
        }
    }
    if !digests.contains_key("index.html") {
        return Err("index.html absent de SHA256SUMS".into());
    }
    let mut code = String::new();
    let _ = writeln!(
        code,
        "/// `SHA256SUMS` of the embedded portal.\npub(super) static SUMS: Option<&str> = \
         Some(include_str!({:?}));",
        path_string(sums)?
    );
    code.push_str(
        "/// The embedded files of the portal.\npub(super) static FILES: &[Asset] = &[\n",
    );
    for (path, digest) in &digests {
        if let Some(raw) = path.strip_suffix(".br") {
            if !digests.contains_key(raw) {
                return Err(format!("{path} sans {raw}"));
            }
            continue;
        }
        let extension = path.rsplit_once('.').map_or("", |(_, e)| e);
        let content_type = TYPES
            .iter()
            .find(|(e, _)| *e == extension)
            .map(|(_, t)| *t)
            .ok_or_else(|| format!("{path} : extension non servie"))?;
        let file = path_string(&dist.join(path))?;
        let brotli = match digests.get(&format!("{path}.br")) {
            Some(br_digest) => format!(
                "Some(super::Variant {{ bytes: include_bytes!({:?}), etag: \"\\\"br-{br_digest}\\\"\" }})",
                path_string(&dist.join(format!("{path}.br")))?
            ),
            None => "None".to_owned(),
        };
        let _ = writeln!(
            code,
            "    Asset {{ path: {path:?}, content_type: {content_type:?}, sha256: {digest:?}, \
             raw: super::Variant {{ bytes: include_bytes!({file:?}), etag: \"\\\"{digest}\\\"\" }}, \
             brotli: {brotli} }},"
        );
    }
    code.push_str("];\n");
    Ok(code)
}

/// The absolute path of a file, as a string for `include_bytes!`.
fn path_string(path: &Path) -> Result<String, String> {
    let absolute = fs::canonicalize(path).map_err(|e| format!("{}: {e}", path.display()))?;
    absolute
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("{} : chemin hors UTF-8", absolute.display()))
}
