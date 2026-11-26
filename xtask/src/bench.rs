//! `cargo xtask bench-ssh`: runs the SSH latency benches (agent relay and
//! tunnel), gathers their JSON Lines results and writes a Markdown summary
//! against the objectives of CLAUDE.md. Displayed only, never a gate
//! (ADR-0005): shared runners are noisy.

use std::fmt::Write as _;

/// One result line written by a bench (`OSTENA_BENCH_OUT`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BenchResult {
    pub(crate) bench: String,
    pub(crate) case: String,
    pub(crate) samples: u64,
    pub(crate) direct_p50_us: u64,
    pub(crate) direct_p99_us: u64,
    pub(crate) through_p50_us: u64,
    pub(crate) through_p99_us: u64,
}

/// The value of `"key":` in a flat JSON line written by the benches: a
/// string without escapes, or an unsigned integer.
fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = &line[line.find(&format!("\"{key}\":"))? + key.len() + 3..];
    if let Some(string) = rest.strip_prefix('"') {
        string.split('"').next()
    } else {
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        Some(&rest[..end])
    }
}

/// Reads one result line; `None` if a field is missing or not a number.
pub(crate) fn parse_line(line: &str) -> Option<BenchResult> {
    let number = |key: &str| field(line, key)?.parse().ok();
    Some(BenchResult {
        bench: field(line, "bench")?.to_owned(),
        case: field(line, "case")?.to_owned(),
        samples: number("samples")?,
        direct_p50_us: number("direct_p50_us")?,
        direct_p99_us: number("direct_p99_us")?,
        through_p50_us: number("through_p50_us")?,
        through_p99_us: number("through_p99_us")?,
    })
}

/// What a result is compared to: a label, and the bound in microseconds on
/// the added p99 (`added`) or on the p99 through Ostena.
fn objective(result: &BenchResult) -> Option<(&'static str, u64, bool)> {
    match (result.bench.as_str(), result.case.as_str()) {
        ("ssh-relay", "round_trip_64") => Some(("ajout p99 ≤ 3 ms", 3_000, true)),
        ("ssh-relay", "session_setup") => Some(("établissement p99 < 5 s", 5_000_000, false)),
        ("tunnel", "round_trip_64" | "round_trip_64_tcp") => {
            Some(("ajout p99 < 1 ms (indicatif)", 1_000, true))
        }
        _ => None,
    }
}

fn label(result: &BenchResult) -> String {
    match (result.bench.as_str(), result.case.as_str()) {
        ("ssh-relay", "round_trip_64") => "SSH via l'agent, aller-retour 64 octets".to_owned(),
        ("ssh-relay", "session_setup") => "SSH via l'agent, établissement de session".to_owned(),
        ("tunnel", "round_trip_64") => "Tunnel agent-core, aller-retour 64 octets".to_owned(),
        ("tunnel", "round_trip_64_tcp") => {
            "Tunnel agent-core en repli TCP, aller-retour 64 octets".to_owned()
        }
        (bench, case) => format!("{bench} {case}"),
    }
}

fn ms(us: u64) -> String {
    format!("{}.{:03}", us / 1_000, us % 1_000)
}

/// The Markdown summary of the results.
pub(crate) fn markdown(results: &[BenchResult], commit: Option<&str>) -> String {
    let mut out = String::from("## Latence SSH (banc, non bloquant)\n\n");
    if let Some(commit) = commit {
        let _ = writeln!(out, "Commit `{commit}`.\n");
    }
    out.push_str(
        "| Mesure | Échantillons | Direct p50 / p99 (ms) | Via Ostena p50 / p99 (ms) | \
         Ajout p50 / p99 (ms) | Objectif | État |\n|---|---|---|---|---|---|---|\n",
    );
    for r in results {
        let added_p50 = r.through_p50_us.saturating_sub(r.direct_p50_us);
        let added_p99 = r.through_p99_us.saturating_sub(r.direct_p99_us);
        let (goal, state) = match objective(r) {
            Some((goal, bound, on_added)) => {
                let value = if on_added {
                    added_p99
                } else {
                    r.through_p99_us
                };
                (
                    goal,
                    if value <= bound {
                        "atteint"
                    } else {
                        "dépassé"
                    },
                )
            }
            None => ("—", "—"),
        };
        let _ = writeln!(
            out,
            "| {} | {} | {} / {} | {} / {} | {} / {} | {goal} | {state} |",
            label(r),
            r.samples,
            ms(r.direct_p50_us),
            ms(r.direct_p99_us),
            ms(r.through_p50_us),
            ms(r.through_p99_us),
            ms(added_p50),
            ms(added_p99),
        );
    }
    out.push_str(
        "\nBoucle locale, runner partagé : mesure indicative, sans seuil de régression \
         (ADR-0005). Résultats bruts : artefact `bench-ssh-latency`.\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINE: &str = r#"{"bench":"ssh-relay","case":"round_trip_64","samples":3000,"direct_p50_us":40,"direct_p99_us":95,"through_p50_us":160,"through_p99_us":1350}"#;

    #[test]
    fn parses_a_bench_line() {
        let r = parse_line(LINE).unwrap();
        assert_eq!(r.bench, "ssh-relay");
        assert_eq!(r.case, "round_trip_64");
        assert_eq!(r.samples, 3000);
        assert_eq!((r.direct_p99_us, r.through_p99_us), (95, 1350));
        assert_eq!(parse_line(r#"{"bench":"x"}"#), None);
        assert_eq!(parse_line(&LINE.replace("3000", "-1")), None);
    }

    #[test]
    fn summary_compares_to_the_objectives() {
        let ok = parse_line(LINE).unwrap();
        let slow = BenchResult {
            through_p99_us: 4_000,
            ..ok.clone()
        };
        let setup = BenchResult {
            case: "session_setup".into(),
            through_p99_us: 6_000_000,
            ..ok.clone()
        };
        let text = markdown(&[ok, slow, setup], Some("abc123"));
        assert!(text.contains("Commit `abc123`"));
        assert!(
            text.contains(
                "| 0.040 / 0.095 | 0.160 / 1.350 | 0.120 / 1.255 | ajout p99 ≤ 3 ms | atteint |"
            ),
            "{text}"
        );
        assert!(
            text.contains("| 0.120 / 3.905 | ajout p99 ≤ 3 ms | dépassé |"),
            "{text}"
        );
        assert!(
            text.contains("établissement p99 < 5 s | dépassé |"),
            "{text}"
        );
    }

    #[test]
    fn summary_shows_the_tcp_fallback() {
        let tcp = BenchResult {
            bench: "tunnel".into(),
            case: "round_trip_64_tcp".into(),
            through_p99_us: 176,
            ..parse_line(LINE).unwrap()
        };
        let text = markdown(&[tcp], None);
        assert!(
            text.contains("| Tunnel agent-core en repli TCP, aller-retour 64 octets | 3000 |"),
            "{text}"
        );
        assert!(
            text.contains("| 0.120 / 0.081 | ajout p99 < 1 ms (indicatif) | atteint |"),
            "{text}"
        );
    }
}
