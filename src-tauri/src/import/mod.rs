//! Scanner-output importers.
//!
//! Each submodule maps one tool's report format to `Vec<NewFinding>` (with an
//! appropriate [`FindingKind`]). The [`parse`] dispatcher selects a parser by
//! format string; the `import_findings` command then bulk-inserts the result
//! into a report.
//!
//! Parsers are deliberately defensive: unknown or missing fields fall back to
//! sensible defaults and never panic. A malformed top-level document surfaces
//! as [`AppError::Import`].

pub mod burp;
pub mod nessus;
pub mod nuclei;
pub mod sarif;
pub mod secai;
pub mod zap;

use crate::error::{AppError, AppResult};
use crate::models::{NewFinding, Severity};

/// Parse `content` according to `format` into a list of findings.
///
/// Supported formats: `sarif`, `nuclei`, `zap`, `burp`, `nessus`, `secai`.
pub fn parse(format: &str, content: &str) -> AppResult<Vec<NewFinding>> {
    match format.to_ascii_lowercase().as_str() {
        "sarif" => sarif::parse(content),
        "nuclei" => nuclei::parse(content),
        "zap" => zap::parse(content),
        "burp" => burp::parse(content),
        "nessus" => nessus::parse(content),
        "secai" => secai::parse(content),
        other => Err(AppError::Import(format!("unknown import format: {other}"))),
    }
}

// --- shared severity mapping ------------------------------------------------

/// Map a free-form textual severity label (case-insensitive) to [`Severity`].
/// Unknown/empty labels fall back to `Medium` — a conservative default that
/// keeps imported findings visible without over-stating risk.
pub(crate) fn severity_from_label(label: &str) -> Severity {
    match label.trim().to_ascii_lowercase().as_str() {
        "critical" | "crit" => Severity::Critical,
        "high" => Severity::High,
        "medium" | "moderate" | "warning" => Severity::Medium,
        "low" => Severity::Low,
        // Informational synonyms across tools.
        "info" | "informational" | "information" | "note" | "none" | "unknown" => Severity::Info,
        _ => Severity::Medium,
    }
}

/// Normalize a CWE reference to the canonical `CWE-<n>` form, or `None` if no
/// numeric id can be extracted. Accepts inputs like `89`, `CWE-89`, `cwe:79`.
pub(crate) fn normalize_cwe(raw: &str) -> Option<String> {
    let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        Some(format!("CWE-{digits}"))
    }
}

/// Normalize a CVE reference to `CVE-YYYY-NNNN...`, or `None` if it doesn't look
/// like a CVE id. Case-insensitive; trims surrounding whitespace.
pub(crate) fn normalize_cve(raw: &str) -> Option<String> {
    let up = raw.trim().to_ascii_uppercase();
    let stripped = up.strip_prefix("CVE-").unwrap_or(&up);
    let parts: Vec<&str> = stripped.split('-').collect();
    if parts.len() == 2
        && parts[0].len() == 4
        && parts[0].chars().all(|c| c.is_ascii_digit())
        && parts[1].len() >= 4
        && parts[1].chars().all(|c| c.is_ascii_digit())
    {
        Some(format!("CVE-{}-{}", parts[0], parts[1]))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::parse;
    use crate::models::Severity;

    #[test]
    fn sarif_maps_level_and_title() {
        let s = r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t"}},
            "results":[{"ruleId":"R","level":"error","message":{"text":"SQLi found"},
            "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},"region":{"startLine":3}}}]}]}]}"#;
        let f = parse("sarif", s).expect("sarif parse");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High); // error -> high
        // No rule definition for ruleId "R", so the title falls back to the
        // ruleId and the message text lands in the summary.
        assert_eq!(f[0].title, "R");
        assert!(f[0].description.as_ref().unwrap().summary.contains("SQLi"));
    }

    #[test]
    fn nuclei_jsonl_maps_severity() {
        let s = r#"{"info":{"name":"Open Redirect","severity":"medium","description":"d"},"matched-at":"http://x"}"#;
        let f = parse("nuclei", s).expect("nuclei parse");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
    }

    #[test]
    fn nessus_xml_numeric_severity() {
        let s = r#"<NessusClientData_v2><Report name="r"><ReportHost name="h">
            <ReportItem severity="4" pluginName="Critical Issue">
            <description>d</description><solution>s</solution></ReportItem>
            </ReportHost></Report></NessusClientData_v2>"#;
        let f = parse("nessus", s).expect("nessus parse");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Critical); // 4 -> critical
    }

    #[test]
    fn unknown_format_errors() {
        assert!(parse("definitely-not-a-format", "{}").is_err());
    }

    #[test]
    fn bundled_kb_catalog_is_valid() {
        let cat: serde_json::Value =
            serde_json::from_str(include_str!("../../resources/kb/catalog.json"))
                .expect("catalog.json must be valid JSON");
        let arr = cat.as_array().expect("catalog must be an array");
        assert!(arr.len() >= 12, "expected >=12 KB entries, got {}", arr.len());
        for e in arr {
            let sev = e["severity"].as_str().expect("severity str");
            assert!(
                ["info", "low", "medium", "high", "critical"].contains(&sev),
                "invalid severity: {sev}"
            );
            assert!(!e["title"].as_str().unwrap_or("").is_empty(), "empty title");
        }
    }
}
