//! Generic CSV importer (`format="csv"`).
//!
//! Expects a header row and maps common column names case-insensitively:
//! title/name, severity, description, cwe, cve, cvss/cvss_score, cvss_vector,
//! host/url/location, remediation/solution, kind. Unknown columns are ignored;
//! a row missing a usable title is skipped with a warning (the file is never
//! aborted on one bad row).

use std::collections::HashMap;

use super::{annotate_cwe_name, normalize_cve, normalize_cwe, severity_from_label, ImportOutcome};
use crate::error::{AppError, AppResult};
use crate::models::{Evidence, FindingDescription, FindingKind, FindingRemediation, NewFinding};

/// Resolve a value for the first header alias that exists in the row.
fn pick<'a>(row: &'a HashMap<String, String>, aliases: &[&str]) -> Option<&'a str> {
    for a in aliases {
        if let Some(v) = row.get(*a) {
            let t = v.trim();
            if !t.is_empty() {
                return Some(t);
            }
        }
    }
    None
}

fn kind_of(raw: &str) -> Option<FindingKind> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "sast" => Some(FindingKind::Sast),
        "dast" => Some(FindingKind::Dast),
        "iac" => Some(FindingKind::Iac),
        "sca" => Some(FindingKind::Sca),
        "secret" => Some(FindingKind::Secret),
        "manual" => Some(FindingKind::Manual),
        _ => None,
    }
}

pub fn parse(content: &str) -> AppResult<ImportOutcome> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(content.as_bytes());

    // Lowercased headers so column matching is case-insensitive.
    let headers: Vec<String> = reader
        .headers()
        .map_err(|e| AppError::Import(format!("invalid CSV header: {e}")))?
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();

    if headers.is_empty() {
        return Err(AppError::Import("CSV has no header row".into()));
    }

    let mut out = ImportOutcome::new();

    for (i, rec) in reader.records().enumerate() {
        let line = i + 2; // +1 for 0-based, +1 for the header row.
        let rec = match rec {
            Ok(r) => r,
            Err(e) => {
                out.warn(format!("csv line {line}: skipped (parse error: {e})"));
                continue;
            }
        };

        // Build a header→value map for this row.
        let mut row: HashMap<String, String> = HashMap::new();
        for (h, v) in headers.iter().zip(rec.iter()) {
            row.insert(h.clone(), v.to_string());
        }

        let title = match pick(&row, &["title", "name", "finding", "issue"]) {
            Some(t) => t.to_string(),
            None => {
                out.warn(format!("csv line {line}: skipped (missing title)"));
                continue;
            }
        };

        let severity =
            severity_from_label(pick(&row, &["severity", "risk", "level"]).unwrap_or(""));

        let summary = pick(&row, &["description", "desc", "summary", "details"])
            .map(|s| s.to_string())
            .unwrap_or_default();

        let cwe = pick(&row, &["cwe", "cwe_id", "cweakness"]).and_then(normalize_cwe);
        let cve = pick(&row, &["cve", "cve_id"]).and_then(normalize_cve);

        let cvss_score = pick(&row, &["cvss", "cvss_score", "score", "cvss_base_score"])
            .and_then(|s| s.parse::<f64>().ok());
        let cvss_vector = pick(&row, &["cvss_vector", "vector"]).map(|s| s.to_string());

        let location = pick(
            &row,
            &["host", "url", "location", "target", "asset", "endpoint"],
        )
        .map(|s| s.to_string());
        let evidence = location.map(|loc| Evidence {
            file: Some(loc),
            start_line: None,
            end_line: None,
            snippet: None,
        });

        let fix = pick(&row, &["remediation", "solution", "fix", "recommendation"])
            .map(|s| s.to_string())
            .unwrap_or_default();

        let kind = pick(&row, &["kind", "type", "category"])
            .and_then(kind_of)
            .unwrap_or(FindingKind::Manual);

        let mut f = NewFinding {
            title,
            severity,
            confidence: None,
            kind: Some(kind),
            cwe,
            cve,
            cvss_vector,
            cvss_score,
            triage_status: None,
            triage_note: None,
            description: Some(FindingDescription {
                summary: if summary.is_empty() {
                    "Imported from CSV.".into()
                } else {
                    summary
                },
                ..Default::default()
            }),
            remediation: if fix.is_empty() {
                None
            } else {
                Some(FindingRemediation {
                    fix,
                    code_patch: None,
                    references: Vec::new(),
                })
            },
            evidence,
            poc: None,
            refs: None,
            tags: Some(vec!["imported".into(), "csv".into()]),
            retest_status: None,
            retest_date: None,
            custom_fields: None,
            mappings: None,
        };
        annotate_cwe_name(&mut f);
        out.push(f);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::parse;
    use crate::models::{FindingKind, Severity};

    #[test]
    fn maps_common_columns_case_insensitively() {
        let csv = "Title,Severity,Description,CWE,CVE,Host,Solution\n\
                   SQL Injection,High,User input in query,89,CVE-2021-1234,https://x/login,Use prepared statements\n";
        let out = parse(csv).expect("csv parse");
        assert_eq!(out.findings.len(), 1);
        let f = &out.findings[0];
        assert_eq!(f.title, "SQL Injection");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.cwe.as_deref(), Some("CWE-89"));
        assert_eq!(f.cve.as_deref(), Some("CVE-2021-1234"));
        assert_eq!(
            f.evidence.as_ref().and_then(|e| e.file.as_deref()),
            Some("https://x/login")
        );
        assert_eq!(f.kind, Some(FindingKind::Manual));
        // CWE name annotation lands in technical_details.
        assert!(f
            .description
            .as_ref()
            .unwrap()
            .technical_details
            .contains("SQL Injection"));
    }

    #[test]
    fn row_missing_title_becomes_a_warning_not_an_abort() {
        let csv = "name,severity\n,high\nReal Finding,low\n";
        let out = parse(csv).expect("csv parse");
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].title, "Real Finding");
        assert_eq!(out.warnings.len(), 1);
        assert!(out.warnings[0].contains("missing title"));
    }

    #[test]
    fn unknown_columns_ignored_and_defaults_applied() {
        let csv = "name,wat,severity\nFoo,bar,nonsense\n";
        let out = parse(csv).expect("csv parse");
        assert_eq!(out.findings.len(), 1);
        // Unknown severity → Medium default.
        assert_eq!(out.findings[0].severity, Severity::Medium);
    }
}
