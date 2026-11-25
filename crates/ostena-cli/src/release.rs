//! `ostena release`: signed manifests of the deliverables (ADR-0017).
//!
//! - `sign` hashes the given files, writes the manifest and its signature
//!   (`<manifest>.sig`), never overwriting;
//! - `verify` checks the signature with the trusted public keys, then the
//!   SHA-256 of every listed file, offline and without any secret.
//!
//! Exit codes of `verify`: 0 every file verified, 1 at least one error
//! (`REL-E…`), 3 usage or input/output error (manifest, signature or key
//! unreadable).

use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, Read, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ostena_common::secret::SecretBytes;
use ostena_crypto::p256::VerifyingKey;
use ostena_crypto::pki;
use ostena_crypto::release::{
    self, Entry, MAX_MANIFEST_LEN, MAX_SIGNATURE_LEN, MAX_TRUSTED_KEYS, Manifest, ReleaseError,
};

/// Exit code of a usage or input/output error.
pub(crate) const USAGE_ERROR: u8 = 3;

/// The signature file of `manifest`: its name followed by `.sig`.
fn signature_path(manifest: &Path) -> PathBuf {
    let mut name = manifest.as_os_str().to_owned();
    name.push(".sig");
    PathBuf::from(name)
}

fn fail(error: &str) -> ExitCode {
    let _ = writeln!(io::stderr(), "ostena release : {error}");
    ExitCode::FAILURE
}

/// `ostena release sign`.
pub(crate) fn sign(key: &Path, out: &Path, files: &[PathBuf]) -> ExitCode {
    match try_sign(key, out, files) {
        Ok((manifest, kid)) => {
            let _ = writeln!(
                io::stdout(),
                "{} fichier(s) signés par la clé {kid}\nManifeste : {}\nSignature : {}",
                manifest.entries().len(),
                out.display(),
                signature_path(out).display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}

fn try_sign(key: &Path, out: &Path, files: &[PathBuf]) -> Result<(Manifest, String), String> {
    let pem = fs::read(key)
        .map(SecretBytes::from)
        .map_err(|e| format!("[REL-E007] clé de signature {} : {e}", key.display()))?;
    let key = pki::signing_key_from_pem(&pem).map_err(|_| {
        format!(
            "[REL-E007] clé de signature {} : clé P-256 PKCS#8 en PEM attendue",
            key.display()
        )
    })?;
    let mut entries = Vec::with_capacity(files.len());
    for path in files {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| format!("{} : nom de fichier illisible", path.display()))?;
        let digest = File::open(path)
            .and_then(release::digest_reader)
            .map_err(|e| format!("[REL-E005] {} : {e}", path.display()))?;
        entries.push(Entry::new(name, digest).map_err(|e| format!("{name} : {e}"))?);
    }
    let manifest = Manifest::new(entries).map_err(|e| e.to_string())?;
    let signature = release::sign(&manifest, &key).map_err(|e| e.to_string())?;
    let signature_file = signature_path(out);
    if signature_file.exists() {
        return Err(format!(
            "[REL-E008] {} existe déjà : jamais écrasé",
            signature_file.display()
        ));
    }
    crate::ca::create(out, manifest.encode().as_bytes(), false)
        .map_err(|e| format!("[REL-E008] {e}"))?;
    if let Err(e) = crate::ca::create(&signature_file, signature.to_text().as_bytes(), false) {
        // No manifest without its signature.
        let _ = fs::remove_file(out);
        return Err(format!("[REL-E008] {e}"));
    }
    Ok((manifest, release::hex(&signature.kid())))
}

/// What `ostena release verify` was given.
pub(crate) struct VerifyArgs<'a> {
    pub(crate) manifest: &'a Path,
    pub(crate) keys: &'a [PathBuf],
    pub(crate) signature: Option<&'a Path>,
    pub(crate) dir: Option<&'a Path>,
}

/// `ostena release verify`.
pub(crate) fn verify(args: &VerifyArgs<'_>) -> ExitCode {
    match run_verify(args) {
        Ok(report) => {
            let _ = io::stdout().write_all(report.text.as_bytes());
            if report.errors == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            let _ = writeln!(io::stderr(), "ostena release : {e}");
            ExitCode::from(USAGE_ERROR)
        }
    }
}

struct Report {
    text: String,
    errors: usize,
}

/// Reads at most `max` bytes of `path`; a longer file is refused.
fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|e| format!("{} : {e}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{} : {e}", path.display()))?;
    if bytes.len() > max {
        return Err(format!("{} : plus de {max} octets", path.display()));
    }
    Ok(bytes)
}

fn read_keys(paths: &[PathBuf]) -> Result<Vec<VerifyingKey>, String> {
    if paths.len() > MAX_TRUSTED_KEYS {
        return Err(ReleaseError::TrustedKeys.to_string());
    }
    paths
        .iter()
        .map(|path| {
            let text = fs::read_to_string(path).map_err(|e| format!("{} : {e}", path.display()))?;
            pki::decode_public_key(&text).map_err(|e| format!("{} : {e}", path.display()))
        })
        .collect()
}

fn run_verify(args: &VerifyArgs<'_>) -> Result<Report, String> {
    let keys = read_keys(args.keys)?;
    let manifest_bytes = read_bounded(args.manifest, MAX_MANIFEST_LEN)?;
    let signature_file = args
        .signature
        .map_or_else(|| signature_path(args.manifest), Path::to_path_buf);
    let signature = String::from_utf8(read_bounded(&signature_file, MAX_SIGNATURE_LEN)?)
        .map_err(|_| format!("{} : UTF-8 invalide", signature_file.display()))?;
    let dir = match args.dir {
        Some(dir) => dir.to_path_buf(),
        None => args
            .manifest
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf),
    };

    let mut text = format!("Manifeste : {}\n", args.manifest.display());
    let manifest = match release::verify(&manifest_bytes, &signature, &keys) {
        Ok(manifest) => manifest,
        Err(e) => {
            let _ = writeln!(text, "{e}\nAucun fichier vérifié.");
            return Ok(Report { text, errors: 1 });
        }
    };
    if let Ok(parsed) = release::ReleaseSignature::from_text(&signature) {
        let _ = writeln!(text, "Signé par la clé {}", release::hex(&parsed.kid()));
    }
    let mut errors = 0;
    for entry in manifest.entries() {
        let path = dir.join(entry.name());
        match File::open(&path).and_then(release::digest_reader) {
            Ok(digest) if digest == *entry.digest() => {
                let _ = writeln!(text, "ok          {}", entry.name());
            }
            Ok(digest) => {
                errors += 1;
                let _ = writeln!(
                    text,
                    "[REL-E006] {} : empreinte différente (attendue {}, trouvée {})",
                    entry.name(),
                    release::hex(entry.digest()),
                    release::hex(&digest)
                );
            }
            Err(e) => {
                errors += 1;
                let _ = writeln!(
                    text,
                    "[REL-E005] {} : absent ou illisible ({e})",
                    path.display()
                );
            }
        }
    }
    let _ = writeln!(
        text,
        "{} fichier(s), {errors} erreur(s)",
        manifest.entries().len()
    );
    Ok(Report { text, errors })
}
