//! `ostena ca`: the offline root ceremony and the keys it certifies
//! (ADR-0008, docs/exploitation/ceremonie-racine.md).
//!
//! On the isolated ceremony workstation:
//!
//! - `root init` draws the root key and the secret that seals it, shows the
//!   three shares of that secret (two rebuild it), and
//!   writes `root.pem`, `root.name` and `root.key.sealed` to every `--out`
//!   directory (one per removable medium);
//! - `issuing sign` and `server sign` certify a public key generated on the
//!   core (`key new`) with the root, after reading two shares on
//!   standard input.
//!
//! Nothing is overwritten. Private key files are created with mode 0600.

use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ostena_common::secret::SecretBytes;
use ostena_crypto::p256;
use ostena_crypto::pki::{self, RootAuthority, Validity};
use ostena_crypto::sealed::{self, RootSecret, Share};
use ostena_crypto::tls::{self, CertificateDer, TrustAnchor};

const DAY: u64 = 86_400;
/// Tolerated clock difference at the start of validity.
const SKEW: u64 = 300;

const ROOT_CERT: &str = "root.pem";
const ROOT_NAME: &str = "root.name";
const ROOT_KEY: &str = "root.key.sealed";

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn validity(days: u32) -> Validity {
    let now = now();
    Validity {
        not_before: now.saturating_sub(SKEW),
        not_after: now + u64::from(days) * DAY,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Creates `path` with `bytes`, refusing to overwrite; `secret` files get
/// mode 0600 on Unix.
pub(crate) fn create(path: &Path, bytes: &[u8], secret: bool) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = secret;
    let mut file = options
        .open(path)
        .map_err(|e| format!("{} : {e}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("{} : {e}", path.display()))
}

fn fail(error: &str) -> ExitCode {
    let _ = writeln!(io::stderr(), "ostena ca : {error}");
    ExitCode::FAILURE
}

/// `ostena ca root init`.
pub(crate) fn root_init(name: &str, days: u32, outs: &[PathBuf]) -> ExitCode {
    match try_root_init(name, days, outs) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(&e),
    }
}

/// At least two output media, none already holding a root.
fn check_outs(outs: &[PathBuf]) -> Result<(), String> {
    if outs.len() < 2 {
        return Err("au moins deux --out (deux supports, conservés séparément)".into());
    }
    for out in outs {
        if [ROOT_CERT, ROOT_NAME, ROOT_KEY]
            .iter()
            .any(|f| out.join(f).exists())
        {
            return Err(format!(
                "{} contient déjà une racine : rien n'est écrasé",
                out.display()
            ));
        }
    }
    Ok(())
}

/// Seals `root` under a fresh secret, writes it to every medium of `outs`
/// and shows the fingerprint and the three new shares.
fn seal_and_write(root: &RootAuthority, name: &str, outs: &[PathBuf]) -> Result<(), String> {
    let (secret, shares) = RootSecret::generate().map_err(|e| e.to_string())?;
    let sealed = sealed::seal(&root.key_pkcs8(), &secret).map_err(|e| e.to_string())?;
    let cert_pem = root.certificate_pem();
    for out in outs {
        fs::create_dir_all(out).map_err(|e| format!("{} : {e}", out.display()))?;
        create(&out.join(ROOT_CERT), cert_pem.as_bytes(), false)?;
        create(&out.join(ROOT_NAME), name.as_bytes(), false)?;
        create(&out.join(ROOT_KEY), &sealed, true)?;
    }
    let fingerprint = hex(&tls::fingerprint(root.trust_anchor().certificate()));
    let _ = writeln!(io::stdout(), "Racine : {name}");
    let _ = writeln!(
        io::stdout(),
        "Empreinte SHA-256 du certificat racine : {fingerprint}"
    );
    let _ = writeln!(io::stdout(), "Copies écrites : {}", outs.len());
    let _ = writeln!(io::stdout());
    let _ = writeln!(
        io::stdout(),
        "Parts du secret de la racine, affichées une seule fois ; deux parts quelconques \
         suffisent à rouvrir la racine. Chaque dépositaire recopie la sienne seulement :"
    );
    for share in &shares {
        let _ = writeln!(
            io::stdout(),
            "  Dépositaire {} : {}",
            share.id(),
            share.to_text()
        );
    }
    Ok(())
}

fn try_root_init(name: &str, days: u32, outs: &[PathBuf]) -> Result<(), String> {
    if name.trim().is_empty() || name.len() > 64 || name.chars().any(char::is_control) {
        return Err("--name : de 1 à 64 caractères imprimables".into());
    }
    check_outs(outs)?;
    let root = RootAuthority::generate(name, validity(days)).map_err(|e| e.to_string())?;
    seal_and_write(&root, name, outs)
}

/// `ostena ca root reseal`: reopens the root with two shares and seals it
/// under a new secret, in three new shares, onto new media (after a lost
/// envelope or a custodian change). The old media are then destroyed.
pub(crate) fn root_reseal(root: &Path, outs: &[PathBuf]) -> ExitCode {
    let result = (|| {
        check_outs(outs)?;
        let name = fs::read_to_string(root.join(ROOT_NAME))
            .map_err(|e| format!("{} : {e}", root.join(ROOT_NAME).display()))?;
        let authority = open_root(root)?;
        seal_and_write(&authority, name.trim(), outs)?;
        let _ = writeln!(
            io::stdout(),
            "\nLes anciens supports et les anciennes enveloppes doivent maintenant être détruits."
        );
        Ok::<(), String>(())
    })();
    result.map_or_else(|e| fail(&e), |()| ExitCode::SUCCESS)
}

/// `ostena ca key new`: a P-256 key generated where it will be used.
pub(crate) fn key_new(key_out: &Path, public_out: &Path) -> ExitCode {
    let result = (|| {
        let (key, pkcs8) = p256::SigningKey::generate().map_err(|e| e.to_string())?;
        let pem = pki::pem_private_key(&pkcs8);
        // SECRET-EXPOSURE: written once to a new 0600 file.
        #[expect(clippy::disallowed_methods)]
        create(key_out, pem.expose_secret(), true)?;
        create(
            public_out,
            pki::encode_public_key(&key.verifying_key()).as_bytes(),
            false,
        )
    })();
    match result {
        Ok(()) => {
            let _ = writeln!(
                io::stdout(),
                "Clé privée : {} (ne quitte pas cette machine)",
                key_out.display()
            );
            let _ = writeln!(
                io::stdout(),
                "Clé publique à porter à la cérémonie : {}",
                public_out.display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}

fn open_root(dir: &Path) -> Result<RootAuthority, String> {
    let read =
        |f: &str| fs::read(dir.join(f)).map_err(|e| format!("{} : {e}", dir.join(f).display()));
    let certificate = TrustAnchor::from_pem(&read(ROOT_CERT)?)
        .map_err(|e| e.to_string())?
        .certificate()
        .clone();
    let name = String::from_utf8(read(ROOT_NAME)?).map_err(|_| "root.name illisible".to_owned())?;
    let sealed = read(ROOT_KEY)?;
    let _ = writeln!(
        io::stderr(),
        "Parts du secret de la racine : deux au moins, une par ligne, puis une ligne vide :"
    );
    let mut shares = Vec::new();
    for line in io::stdin().lock().lines() {
        let typed = SecretBytes::from(line.map_err(|e| e.to_string())?.into_bytes());
        // SECRET-EXPOSURE: only to detect the empty line that ends the input.
        #[expect(clippy::disallowed_methods)]
        let empty = typed.expose_secret().iter().all(u8::is_ascii_whitespace);
        if empty {
            break;
        }
        shares.push(Share::parse(&typed).map_err(|e| e.to_string())?);
    }
    let secret = RootSecret::combine(&shares).map_err(|e| e.to_string())?;
    let pkcs8 = sealed::open(&sealed, &secret).map_err(|e| e.to_string())?;
    RootAuthority::from_parts(name.trim(), &pkcs8, certificate).map_err(|e| e.to_string())
}

fn read_public_key(path: &Path) -> Result<p256::VerifyingKey, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{} : {e}", path.display()))?;
    pki::decode_public_key(&text).map_err(|e| e.to_string())
}

fn write_certificate(out: &Path, cert: &CertificateDer<'_>) -> Result<(), String> {
    create(out, pki::pem_certificate(cert).as_bytes(), false)?;
    let _ = writeln!(io::stdout(), "Certificat : {}", out.display());
    let _ = writeln!(
        io::stdout(),
        "Empreinte SHA-256 : {}",
        hex(&tls::fingerprint(cert))
    );
    Ok(())
}

/// `ostena ca issuing sign`: the online issuing CA (agent certificates only).
pub(crate) fn issuing_sign(
    root: &Path,
    public_key: &Path,
    name: &str,
    days: u32,
    out: &Path,
) -> ExitCode {
    let result = (|| {
        let key = read_public_key(public_key)?;
        let root = open_root(root)?;
        let cert = root
            .sign_issuing(&key, name, validity(days))
            .map_err(|e| e.to_string())?;
        write_certificate(out, &cert)
    })();
    result.map_or_else(|e| fail(&e), |()| ExitCode::SUCCESS)
}

/// `ostena ca server sign`: the core server certificate.
pub(crate) fn server_sign(
    root: &Path,
    public_key: &Path,
    names: &[String],
    days: u32,
    out: &Path,
) -> ExitCode {
    let result = (|| {
        let key = read_public_key(public_key)?;
        let root = open_root(root)?;
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        let cert = root
            .sign_server(&key, &names, validity(days))
            .map_err(|e| e.to_string())?;
        write_certificate(out, &cert)
    })();
    result.map_or_else(|e| fail(&e), |()| ExitCode::SUCCESS)
}
