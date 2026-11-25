//! Offline check of the session transcripts against their seals
//! (ADR-0016): `ostena audit verify --transcripts <directory>`.
//!
//! Each `transcript.sealed` record of a verified export names a file,
//! `<session>.cast`, with its size and SHA-256. The file must be in the
//! directory and match (`AUD-E017`, `AUD-E018`). A transcript sealed as
//! incomplete is reported (`AUD-W006`), as is a `.cast` file the export does
//! not seal (`AUD-W005`). Every SSH session opened in the export
//! (`access.session_opened`) must have its transcript sealed in it
//! (`AUD-E019`), unless it may still have been running at export time
//! (`AUD-W007`). Nothing else in the directory is read, and no secret is
//! needed.

use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use ostena_crypto::sha256::Hasher;

use crate::AuditError;
use crate::verify::{Finding, Report};

/// Time after the maximum length of a session within which its transcript
/// may still be unsealed: the cut of the session, the end of the stream,
/// the seal.
const END_MARGIN_MS: u64 = 5 * 60 * 1000;

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
        let on_disk = match measure(&dir.join(&file)) {
            Ok(on_disk) => Some(on_disk),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(io(e)),
        };
        match (seal.digest, on_disk) {
            // As sealed: with its digest, or absent when the core wrote
            // no file.
            (Some(sealed), Some(on_disk)) if sealed == on_disk => {}
            (None, None) => {}
            (Some(_), None) => {
                report.add(Finding::TranscriptMissing {
                    file,
                    seq: seal.seq,
                });
                continue;
            }
            // Altered, or a file where the core sealed none.
            (_, Some(_)) => {
                report.add(Finding::TranscriptAltered {
                    file,
                    seq: seal.seq,
                });
                continue;
            }
        }
        if !seal.complete {
            report.add(Finding::TranscriptIncomplete {
                file,
                seq: seal.seq,
                code: seal.code.clone().unwrap_or_default(),
            });
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
    // Every SSH session opened in the export has its transcript sealed in
    // it, unless it may still have been running at export time.
    let export_ms = report.export_time_ms.unwrap_or(u64::MAX);
    let sessions = std::mem::take(&mut report.ssh_sessions);
    for opened in &sessions {
        let file = opened.file_name();
        if sealed.contains(&file) {
            continue;
        }
        if opened.ended_by_ms(END_MARGIN_MS) > export_ms {
            report.add(Finding::TranscriptPending {
                file,
                seq: opened.seq,
            });
        } else {
            report.add(Finding::TranscriptNeverSealed {
                file,
                seq: opened.seq,
            });
        }
    }
    report.ssh_sessions = sessions;
    report.transcripts = seals;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::{SshSession, TranscriptSeal};

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
            ssh_sessions: Vec::new(),
            export_time_ms: Some(10_000_000),
        }
    }

    fn seal(session: u8, content: &[u8], complete: bool) -> TranscriptSeal {
        TranscriptSeal {
            seq: u64::from(session),
            session: [session; 16],
            digest: Some((content.len() as u64, ostena_crypto::sha256::digest(content))),
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

        // Sealed without a file: none must be there.
        let mut none = seal(6, b"", false);
        none.digest = None;
        let mut appeared = seal(7, b"", false);
        appeared.digest = None;
        std::fs::write(dir.join(appeared.file_name()), b"added").unwrap();

        let mut r = report(vec![ok, cut, altered, missing, none, appeared]);
        check(&mut r, &dir).unwrap();
        let codes: Vec<&str> = r.findings.iter().map(Finding::code).collect();
        assert_eq!(
            codes,
            [
                "AUD-E018", "AUD-W006", "AUD-E017", "AUD-E018", "AUD-W006", "AUD-W005"
            ]
        );
        assert_eq!((r.errors, r.warnings), (3, 3));
        assert_eq!(r.exit_code(), 1);
        assert_eq!(r.transcripts.len(), 6);
        for finding in &r.findings {
            assert!(
                finding
                    .to_string()
                    .starts_with(&format!("[{}]", finding.code()))
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An SSH session opened in the export without a seal: an error once
    /// it must have ended, a warning while it may still run.
    #[test]
    fn every_ssh_session_has_its_transcript_sealed() {
        let dir = std::env::temp_dir().join(format!(
            "ostena-audit-transcripts-sessions-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sealed = seal(1, b"x", true);
        std::fs::write(dir.join(sealed.file_name()), b"x").unwrap();
        let opened = |session: u8, opened_ms: u64| SshSession {
            seq: u64::from(session) + 100,
            session: [session; 16],
            opened_ms,
            max_session_secs: 60,
        };
        let mut r = report(vec![sealed]);
        // Sealed; ended long ago; may still run (export at 10 000 s).
        r.ssh_sessions = vec![opened(1, 0), opened(2, 0), opened(3, 9_900_000)];
        check(&mut r, &dir).unwrap();
        let codes: Vec<&str> = r.findings.iter().map(Finding::code).collect();
        assert_eq!(codes, ["AUD-E019", "AUD-W007"]);
        assert!(r.findings[0].to_string().contains("02020202-"));
        assert_eq!(r.exit_code(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
