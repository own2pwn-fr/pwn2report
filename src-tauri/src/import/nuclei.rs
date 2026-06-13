//! Nuclei JSON-Lines importer (`-jsonl` / `-json` output, one finding per line).
//!
//! Maps each line's `info.name` → title, `info.severity` → severity,
//! `info.description` → summary, `matched-at` → evidence/refs, and
//! `info.classification.cve-id` / `cwe-id` → cve/cwe.

use serde_json::Value;

use super::{annotate_cwe_name, normalize_cve, normalize_cwe, severity_from_label, ImportOutcome};
use crate::error::AppResult;
use crate::models::{Evidence, FindingDescription, FindingKind, NewFinding};

/// Pull the first id from a classification field that may be a string, a single
/// value, or an array (nuclei emits arrays like ["CVE-2021-1234"]).
fn first_classification(class: &Value, key: &str) -> Option<String> {
    let v = class.get(key)?;
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Array(a) => a.first().and_then(|x| x.as_str()).map(|s| s.to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Parse one JSONL line. `Ok(None)` = blank line; `Err(msg)` = a malformed line
/// that the caller turns into a per-line warning (NOT a whole-file abort).
fn parse_line(line: &str) -> Result<Option<NewFinding>, String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let v: Value = serde_json::from_str(trimmed).map_err(|e| format!("invalid JSON ({e})"))?;

    let info = v.get("info");

    let title = info
        .and_then(|i| i.get("name"))
        .and_then(|n| n.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| {
            v.get("template-id")
                .and_then(|t| t.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "Nuclei finding".to_string());

    let severity_label = info
        .and_then(|i| i.get("severity"))
        .and_then(|s| s.as_str())
        .unwrap_or("info");
    let severity = severity_from_label(severity_label);

    let description = info
        .and_then(|i| i.get("description"))
        .and_then(|d| d.as_str())
        .unwrap_or("")
        .to_string();

    // matched-at (or host/matched) → evidence + reference.
    let matched = v
        .get("matched-at")
        .or_else(|| v.get("matched"))
        .or_else(|| v.get("host"))
        .and_then(|m| m.as_str())
        .map(|s| s.to_string());

    let mut refs: Vec<String> = Vec::new();
    if let Some(m) = &matched {
        refs.push(m.clone());
    }
    if let Some(arr) = info
        .and_then(|i| i.get("reference"))
        .and_then(|r| r.as_array())
    {
        for r in arr {
            if let Some(s) = r.as_str() {
                refs.push(s.to_string());
            }
        }
    }

    // classification.cve-id / cwe-id
    let class = info.and_then(|i| i.get("classification"));
    let cve = class
        .and_then(|c| first_classification(c, "cve-id"))
        .and_then(|s| normalize_cve(&s));
    let cwe = class
        .and_then(|c| first_classification(c, "cwe-id"))
        .and_then(|s| normalize_cwe(&s));
    let cvss_score = class
        .and_then(|c| c.get("cvss-score"))
        .and_then(|s| s.as_f64());
    let cvss_vector = class
        .and_then(|c| c.get("cvss-metrics"))
        .and_then(|s| s.as_str())
        .map(|s| s.to_string());

    let evidence = matched.as_ref().map(|m| Evidence {
        file: Some(m.clone()),
        start_line: None,
        end_line: None,
        snippet: v
            .get("extracted-results")
            .and_then(|e| e.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .filter(|s| !s.is_empty()),
    });

    let mut f = NewFinding {
        title,
        severity,
        confidence: None,
        // Nuclei is a dynamic (DAST) template scanner.
        kind: Some(FindingKind::Dast),
        cwe,
        cve,
        cvss_vector,
        cvss_score,
        triage_status: None,
        triage_note: None,
        description: Some(FindingDescription {
            summary: if description.is_empty() {
                "Imported from Nuclei scan.".into()
            } else {
                description
            },
            ..Default::default()
        }),
        remediation: None,
        evidence,
        poc: None,
        refs: Some(refs),
        tags: Some(vec!["imported".into(), "nuclei".into()]),
        retest_status: None,
        retest_date: None,
        custom_fields: None,
        mappings: None,
    };
    annotate_cwe_name(&mut f);
    Ok(Some(f))
}

pub fn parse(content: &str) -> AppResult<ImportOutcome> {
    let mut out = ImportOutcome::new();
    for (i, line) in content.lines().enumerate() {
        match parse_line(line) {
            Ok(Some(f)) => out.push(f),
            Ok(None) => {}
            Err(msg) => out.warn(format!("nuclei line {}: skipped ({msg})", i + 1)),
        }
    }
    Ok(out)
}
