//! Offline check of the session transcripts against their seals
//! (ADR-0016): `ostena audit verify --transcripts <directory>`.
//!
//! Each `transcript.sealed` record of a verified export names a file,
//! `<session>.cast`, with its size and SHA-256. The file must be in the
//! directory and match (`AUD-E017`, `AUD-E018`). A transcript sealed as
//! incomplete is reported (`AUD-W006`), as is a `.cast` file the export does
//! not seal (`AUD-W005`). Nothing else in the directory is read, and no
//! secret is needed.

use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use ostena_crypto::sha256::Hasher;

use crate::AuditError;
use crate::verify::{Finding, Report};

/// Size and SHA-256 of `path`, read in chunks.
fn measure(path: &Path) -> std::io::Result<(u64, [u8; 32])> {
    let mut file = File::open(path)?;
    let mut hasher = Hasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok((hasher.len(), hasher.finish()))
}

/// Checks the transcripts of `dir` against the seals of `report`, and adds
/// the findings to it. The last seal of a session counts (a session is
/// sealed once; a second seal would be an anomaly of the core, and its file
/// must match the last one).
///
/// # Errors
///
/// [`AuditError::Io`] if the directory cannot be listed.
pub fn check(report: &mut Report, dir: &Path) -> Result<(), AuditError> {
    let io = |e: std::io::Error| AuditError::Io(format!("{} : {e}", dir.display()));
    let seals = std::mem::take(&mut report.transcripts);
    let mut sealed = HashSet::with_capacity(seals.len());
    for seal in seals.iter().rev() {
        let file = seal.file_name();
        if !sealed.insert(file.clone()) {
            continue;
        }
        match measure(&dir.join(&file)) {
            Ok((size, sha256)) if size == seal.size && sha256 == seal.sha256 => {
                if !seal.complete {
                    report.add(Finding::TranscriptIncomplete {
                        file,
                        seq: seal.seq,
                        code: seal.code.clone().unwrap_or_default(),
                    });
                }
            }
            Ok(_) => report.add(Finding::TranscriptAltered {
                file,
                seq: seal.seq,
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                report.add(Finding::TranscriptMissing {
                    file,
                    seq: seal.seq,
                });
            }
            Err(e) => return Err(io(e)),
        }
    }
    let mut unsealed: Vec<String> = std::fs::read_dir(dir)
        .map_err(io)?
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|name| {
            name.len() == 41
                && Path::new(name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("cast"))
                && !sealed.contains(name)
        })
        .collect();
    unsealed.sort();
    for file in unsealed {
        report.add(Finding::TranscriptUnsealed { file });
    }
    report.transcripts = seals;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::TranscriptSeal;

    fn report(seals: Vec<TranscriptSeal>) -> Report {
        Report {
            records: 0,
            heads: 0,
            first_seq: None,
            last_seq: None,
            covered_seq: None,
            findings: Vec::new(),
            errors: 0,
            warnings: 0,
            transcripts: seals,
        }
    }

    fn seal(session: u8, content: &[u8], complete: bool) -> TranscriptSeal {
        TranscriptSeal {
            seq: u64::from(session),
            session: [session; 16],
            sha256: ostena_crypto::sha256::digest(content),
            size: content.len() as u64,
            complete,
            code: (!complete).then(|| "REC-E005".to_owned()),
        }
    }

    #[test]
    fn files_are_checked_against_their_seals() {
        let dir =
            std::env::temp_dir().join(format!("ostena-audit-transcripts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ok = seal(1, b"{\"version\":2}\n", true);
        let cut = seal(2, b"{\"version\":2}\n[0.1,\"o\",\"x\"]\n", false);
        let altered = seal(3, b"original", true);
        let missing = seal(4, b"gone", true);
        std::fs::write(dir.join(ok.file_name()), b"{\"version\":2}\n").unwrap();
        std::fs::write(
            dir.join(cut.file_name()),
            b"{\"version\":2}\n[0.1,\"o\",\"x\"]\n",
        )
        .unwrap();
        std::fs::write(dir.join(altered.file_name()), b"0riginal").unwrap();
        let stray = seal(5, b"", true).file_name();
        std::fs::write(dir.join(&stray), b"").unwrap();
        std::fs::write(dir.join("notes.txt"), b"ignored").unwrap();
        assert_eq!(ok.file_name(), "01010101-0101-0101-0101-010101010101.cast");

        let mut r = report(vec![ok, cut, altered, missing]);
        check(&mut r, &dir).unwrap();
        let codes: Vec<&str> = r.findings.iter().map(Finding::code).collect();
        assert_eq!(codes, ["AUD-E017", "AUD-E018", "AUD-W006", "AUD-W005"]);
        assert_eq!((r.errors, r.warnings), (2, 2));
        assert_eq!(r.exit_code(), 1);
        assert_eq!(r.transcripts.len(), 4);
        for finding in &r.findings {
            assert!(
                finding
                    .to_string()
                    .starts_with(&format!("[{}]", finding.code()))
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
