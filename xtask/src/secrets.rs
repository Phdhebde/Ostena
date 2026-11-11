//! `cargo xtask check-secrets`: every exemption from the clippy ban on
//! `expose_secret` must be a local `#[expect(clippy::disallowed_methods)]`
//! placed right below a `// SECRET-EXPOSURE: <reason>` comment.
//!
//! Rules, checked on every `.rs` file under `crates/`:
//! - `allow(clippy::disallowed_methods)` is refused: use `expect`, which fails
//!   when it no longer applies;
//! - an inner attribute (`#![expect(clippy::disallowed_methods)]`) is refused:
//!   its scope is a whole module;
//! - an `#[expect(clippy::disallowed_methods)]` whose item mentions
//!   `expose_secret` needs a `// SECRET-EXPOSURE:` comment with a non-empty
//!   reason in the comments and attributes directly above it.
//!
//! This is a line-based check, not a parser: it is a review aid on top of
//! clippy, which does the actual enforcement.

use std::fs;
use std::path::{Path, PathBuf};

const LINT: &str = "clippy::disallowed_methods";
const TAG: &str = "// SECRET-EXPOSURE:";

/// One finding: 1-based line number and explanation.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Finding {
    pub(crate) line: usize,
    pub(crate) problem: &'static str,
}

/// Scans every `.rs` file under `dir` and returns `path:line: problem` entries.
pub(crate) fn check_tree(dir: &Path) -> std::io::Result<Vec<String>> {
    let mut files = Vec::new();
    collect_rs(dir, &mut files)?;
    files.sort();
    let mut report = Vec::new();
    for file in files {
        let text = fs::read_to_string(&file)?;
        for f in scan(&text) {
            report.push(format!("{}:{}: {}", file.display(), f.line, f.problem));
        }
    }
    Ok(report)
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            collect_rs(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

/// Checks one source file.
pub(crate) fn scan(text: &str) -> Vec<Finding> {
    let lines: Vec<&str> = text.lines().collect();
    let mut findings = Vec::new();
    for (i, raw) in lines.iter().enumerate() {
        let line = raw.trim_start();
        if line.starts_with("//") || !line.contains(LINT) {
            continue;
        }
        if line.contains("allow(") {
            findings.push(Finding {
                line: i + 1,
                problem: "`allow(clippy::disallowed_methods)` is refused: use a local \
                          `#[expect(...)]` under a `// SECRET-EXPOSURE: <reason>` comment",
            });
        } else if line.starts_with("#![") {
            findings.push(Finding {
                line: i + 1,
                problem: "inner `#![expect(clippy::disallowed_methods)]` covers a whole module: \
                          put a local `#[expect(...)]` on each exposing statement",
            });
        } else if line.starts_with("#[expect(")
            && item_text(&lines, i).contains("expose_secret")
            && !justified(&lines, i)
        {
            findings.push(Finding {
                line: i + 1,
                problem: "secret exposure without justification: add \
                          `// SECRET-EXPOSURE: <reason>` right above the attribute",
            });
        }
    }
    findings
}

/// Text of the item an outer attribute at `start` applies to: up to the first
/// `;` at nesting depth 0, or the `}` closing the first block. Comments are
/// ignored; string literals are not parsed (good enough for a review aid).
fn item_text(lines: &[&str], start: usize) -> String {
    let mut text = String::new();
    let mut depth = 0i32;
    let mut opened = false;
    // Skip the attribute itself, which may span several lines.
    let mut attr_depth = 0i32;
    let mut in_attr = true;
    for line in &lines[start..] {
        let code = line.split("//").next().unwrap_or_default();
        for c in code.chars() {
            if in_attr {
                match c {
                    '[' => attr_depth += 1,
                    ']' => {
                        attr_depth -= 1;
                        if attr_depth == 0 {
                            in_attr = false;
                        }
                    }
                    _ => {}
                }
                continue;
            }
            text.push(c);
            match c {
                '(' | '[' | '{' => {
                    depth += 1;
                    opened |= c == '{';
                }
                ')' | ']' | '}' => {
                    depth -= 1;
                    if depth == 0 && c == '}' && opened {
                        return text;
                    }
                }
                ';' if depth == 0 => return text,
                _ => {}
            }
        }
        text.push('\n');
    }
    text
}

/// Whether the comments and attributes directly above line `attr` contain a
/// `// SECRET-EXPOSURE:` tag followed by a reason.
fn justified(lines: &[&str], attr: usize) -> bool {
    lines[..attr]
        .iter()
        .rev()
        .map(|l| l.trim())
        .take_while(|l| l.starts_with("//") || l.starts_with("#["))
        .any(|l| {
            l.strip_prefix(TAG)
                .is_some_and(|reason| !reason.trim().is_empty())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn problems(src: &str) -> Vec<usize> {
        scan(src).into_iter().map(|f| f.line).collect()
    }

    #[test]
    fn justified_statement_passes() {
        let src = "fn f(s: &S) {\n    // SECRET-EXPOSURE: sent to the target.\n    \
                   #[expect(clippy::disallowed_methods)]\n    let v = s.expose_secret();\n}\n";
        assert_eq!(problems(src), Vec::<usize>::new());
    }

    #[test]
    fn justified_block_with_extra_comment_and_attribute_passes() {
        let src = "// SECRET-EXPOSURE: test.\n// more context\n#[rustfmt::skip]\n\
                   #[expect(clippy::disallowed_methods)]\n{\n    a(s.expose_secret());\n}\n";
        assert_eq!(problems(src), Vec::<usize>::new());
    }

    #[test]
    fn missing_comment_is_reported() {
        let src = "fn f() {\n    #[expect(clippy::disallowed_methods)]\n    let v = s.expose_secret();\n}\n";
        assert_eq!(problems(src), vec![2]);
    }

    #[test]
    fn empty_reason_is_reported() {
        let src = "// SECRET-EXPOSURE:   \n#[expect(clippy::disallowed_methods)]\nlet v = s.expose_secret();\n";
        assert_eq!(problems(src), vec![2]);
    }

    #[test]
    fn comment_separated_by_code_does_not_count() {
        let src = "// SECRET-EXPOSURE: old.\nlet x = 1;\n#[expect(clippy::disallowed_methods)]\nlet v = s.expose_secret_mut();\n";
        assert_eq!(problems(src), vec![3]);
    }

    #[test]
    fn exposure_inside_block_is_seen() {
        let src = "#[expect(clippy::disallowed_methods)]\n{\n    let a = 1;\n    b(s.expose_secret());\n}\n";
        assert_eq!(problems(src), vec![1]);
    }

    #[test]
    fn other_disallowed_method_needs_no_tag() {
        let src = "#[expect(clippy::disallowed_methods)]\nlet v = std::env::var(\"X\");\nlet w = s.expose_secret();\n";
        assert_eq!(problems(src), Vec::<usize>::new());
    }

    #[test]
    fn allow_and_inner_attributes_are_refused() {
        let src = "#![expect(clippy::disallowed_methods)]\n// SECRET-EXPOSURE: x\n\
                   #[allow(clippy::disallowed_methods)]\nlet v = s.expose_secret();\n";
        assert_eq!(problems(src), vec![1, 3]);
    }

    #[test]
    fn doc_comments_are_ignored() {
        let src = "//! use `#[expect(clippy::disallowed_methods)]` with expose_secret\n";
        assert_eq!(problems(src), Vec::<usize>::new());
    }
}
