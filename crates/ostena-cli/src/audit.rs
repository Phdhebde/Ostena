//! `ostena audit verify`: offline verification of an audit export
//! (ADR-0012), on any workstation, without any secret.
//!
//! Exit codes: 0 intact and covered by a signed head, 1 at least one error,
//! 2 warnings only, 3 usage or input/output error.

use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ostena_audit::head::TEXT_PREFIX;
use ostena_audit::{Head, Options, Report, Severity, TrustedKeys, transcripts, verify_export};
use ostena_crypto::pki;
use ostena_crypto::tsp::TsaTrust;

/// Exit code of a usage or input/output error.
pub(crate) const USAGE_ERROR: u8 = 3;

/// What `ostena audit verify` was given.
pub(crate) struct VerifyArgs<'a> {
    pub(crate) export: &'a Path,
    pub(crate) keys: &'a [PathBuf],
    pub(crate) heads: &'a [String],
    pub(crate) transcripts: Option<&'a Path>,
    pub(crate) tsa_ca: &'a [PathBuf],
    pub(crate) json: bool,
    pub(crate) clock_tolerance_ms: u64,
    pub(crate) head_gap_tolerance_secs: u64,
}

/// `ostena audit verify`.
pub(crate) fn verify(args: &VerifyArgs<'_>) -> ExitCode {
    match run(args) {
        Ok(report) => {
            let text = if args.json {
                json(args.export, &report)
            } else {
                summary(args.export, &report)
            };
            let _ = io::stdout().write_all(text.as_bytes());
            ExitCode::from(report.exit_code())
        }
        Err(e) => {
            let _ = writeln!(io::stderr(), "ostena audit : {e}");
            ExitCode::from(USAGE_ERROR)
        }
    }
}

/// The trusted keys, from public key files (`ostena-p256-public-key-v1`).
pub(crate) fn read_keys(paths: &[PathBuf]) -> Result<TrustedKeys, String> {
    let mut keys = TrustedKeys::new();
    for path in paths {
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("{} : {e}", path.display()))?;
        let key = pki::decode_public_key(&text).map_err(|e| format!("{} : {e}", path.display()))?;
        keys.insert(key).map_err(|e| e.to_string())?;
    }
    Ok(keys)
}

/// The trusted certificates of the time-stamping authorities, from PEM
/// files; `None` without any.
pub(crate) fn read_tsa(paths: &[PathBuf]) -> Result<Option<TsaTrust>, String> {
    let mut trust: Option<TsaTrust> = None;
    for path in paths {
        let pem = std::fs::read(path).map_err(|e| format!("{} : {e}", path.display()))?;
        let more = TsaTrust::from_pem(&pem).map_err(|e| format!("{} : {e}", path.display()))?;
        match &mut trust {
            Some(trust) => trust.extend(more).map_err(|e| e.to_string())?,
            None => trust = Some(more),
        }
    }
    Ok(trust)
}

fn run(args: &VerifyArgs<'_>) -> Result<Report, String> {
    let keys = read_keys(args.keys)?;
    let mut external_heads = Vec::with_capacity(args.heads.len());
    for head in args.heads {
        external_heads.push(read_head(head)?);
    }
    let file = File::open(args.export).map_err(|e| format!("{} : {e}", args.export.display()))?;
    let options = Options {
        tsa: read_tsa(args.tsa_ca)?,
        external_heads,
        clock_tolerance_ms: args.clock_tolerance_ms,
        head_gap_tolerance_secs: args.head_gap_tolerance_secs,
    };
    let mut report = verify_export(BufReader::new(file), keys, options)
        .map_err(|e| format!("{} : {e}", args.export.display()))?;
    if let Some(dir) = args.transcripts {
        transcripts::check(&mut report, dir).map_err(|e| e.to_string())?;
    }
    Ok(report)
}

/// A head given in its text form, or the file that holds it.
fn read_head(arg: &str) -> Result<Head, String> {
    let text = if arg.starts_with(TEXT_PREFIX) {
        arg.to_owned()
    } else {
        std::fs::read_to_string(arg).map_err(|e| format!("--head {arg} : {e}"))?
    };
    Head::from_text(text.trim()).map_err(|e| format!("--head : {e}"))
}

/// `YYYY-MM-DD HH:MM:SS.mmm UTC` of Unix milliseconds.
fn utc(ms: u64) -> String {
    let secs = ms / 1000;
    let days = secs / 86_400;
    let rem = secs % 86_400;
    // Civil date from days since 1970-01-01 (proleptic Gregorian).
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}.{:03} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        ms % 1000
    )
}

fn seq(value: Option<u64>) -> String {
    value.map_or_else(|| "aucun".to_owned(), |v| format!("n° {v}"))
}

/// The French summary.
pub(crate) fn summary(export: &Path, report: &Report) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Export : {}", export.display());
    let _ = writeln!(
        out,
        "Enregistrements : {} (premier : {}, dernier : {})",
        report.records,
        seq(report.first_seq),
        seq(report.last_seq)
    );
    let _ = writeln!(
        out,
        "Têtes signées : {} ; dernier enregistrement couvert : {}",
        report.heads,
        seq(report.covered_seq)
    );
    if !report.transcripts.is_empty() {
        let _ = writeln!(out, "Transcripts scellés : {}", report.transcripts.len());
    }
    if report.timestamps > 0 {
        let _ = writeln!(
            out,
            "Horodatages RFC 3161 : {} ({} vérifié(s){})",
            report.timestamps,
            report.timestamps_verified,
            if report.timestamps_verified == 0 {
                " ; --tsa-ca pour les vérifier"
            } else {
                ""
            }
        );
    }
    if let Some((head_no, ms)) = report.last_timestamp {
        let _ = writeln!(
            out,
            "Dernière tête horodatée : n° {head_no}, existante au plus tard à {} (heure de l'autorité)",
            utc(ms)
        );
    }
    let _ = writeln!(
        out,
        "Constats : {} erreur(s), {} avertissement(s)",
        report.errors, report.warnings
    );
    for finding in &report.findings {
        let _ = writeln!(out, "  {finding}");
    }
    if report.dropped() > 0 {
        let _ = writeln!(out, "  … et {} constat(s) non affiché(s)", report.dropped());
    }
    let verdict = match report.exit_code() {
        0 => "chaîne intacte et couverte par une tête signée",
        2 => "chaîne intacte, avec des avertissements à examiner",
        _ => "CHAÎNE NON INTÈGRE OU NON VÉRIFIABLE",
    };
    let _ = writeln!(out, "Résultat : {verdict} (code {})", report.exit_code());
    out
}

/// The report as one JSON object.
pub(crate) fn json(export: &Path, report: &Report) -> String {
    let findings: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "code": f.code(),
                "severity": match f.severity() {
                    Severity::Error => "error",
                    Severity::Warning => "warning",
                },
                "message": f.to_string(),
            })
        })
        .collect();
    let value = serde_json::json!({
        "export": export.display().to_string(),
        "records": report.records,
        "heads": report.heads,
        "first_seq": report.first_seq,
        "last_seq": report.last_seq,
        "covered_seq": report.covered_seq,
        "transcripts": report.transcripts.len(),
        "timestamps": report.timestamps,
        "timestamps_verified": report.timestamps_verified,
        "last_timestamp": report.last_timestamp.map(|(head_no, ms)| serde_json::json!({
            "head_no": head_no,
            "gen_time_ms": ms,
        })),
        "errors": report.errors,
        "warnings": report.warnings,
        "dropped": report.dropped(),
        "exit_code": report.exit_code(),
        "findings": findings,
    });
    format!("{value}\n")
}
