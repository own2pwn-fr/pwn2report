//! Scanner-output importers.
//!
//! Each submodule maps one tool's report format to an [`ImportOutcome`] (a list
//! of [`NewFinding`]s plus per-record warnings) with an appropriate
//! [`FindingKind`]. Formats register through the [`Importer`] trait + a small
//! [`registry`]; the `import_findings` command then dedups and bulk-inserts the
//! result into a report.
//!
//! Parsers are deliberately defensive: a single malformed record is SKIPPED
//! with a warning rather than aborting the whole file; unknown or missing
//! fields fall back to sensible defaults and never panic. Only a malformed
//! top-level document (unparseable JSON/XML) surfaces as [`AppError::Import`].

pub mod burp;
pub mod csv;
pub mod nessus;
pub mod nuclei;
pub mod sarif;
pub mod secai;
pub mod zap;

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::error::{AppError, AppResult};
use crate::models::{NewFinding, Severity};

/// Result of parsing one scanner file: the successfully-mapped findings plus a
/// list of human-readable warnings for records that were skipped or partially
/// salvaged. Parsing a file therefore never fails on a single bad record — it
/// only fails (returns `Err`) when the whole document is unparseable.
#[derive(Debug, Default)]
pub struct ImportOutcome {
    pub findings: Vec<NewFinding>,
    pub warnings: Vec<String>,
}

impl ImportOutcome {
    /// An empty outcome (no findings, no warnings).
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a successfully-mapped finding.
    pub fn push(&mut self, f: NewFinding) {
        self.findings.push(f);
    }

    /// Record a skip/partial-salvage warning.
    pub fn warn(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
    }
}

/// A scanner-format importer. Adding a new format is one [`registry`] entry plus
/// an `impl Importer`.
pub trait Importer: Send + Sync {
    /// The lowercase format id this importer handles (e.g. `"sarif"`).
    fn id(&self) -> &'static str;
    /// Parse the whole file. Returns `Err` only for an unparseable top-level
    /// document; per-record problems become [`ImportOutcome::warnings`].
    fn parse(&self, content: &str) -> AppResult<ImportOutcome>;
}

/// Thin adapter that wraps a free `fn(&str) -> AppResult<ImportOutcome>` into an
/// [`Importer`] so each submodule can keep exposing a plain `parse` fn.
struct FnImporter {
    id: &'static str,
    parse: fn(&str) -> AppResult<ImportOutcome>,
}

impl Importer for FnImporter {
    fn id(&self) -> &'static str {
        self.id
    }
    fn parse(&self, content: &str) -> AppResult<ImportOutcome> {
        (self.parse)(content)
    }
}

/// The static importer registry. One entry per supported format. Built once.
pub fn registry() -> &'static [&'static dyn Importer] {
    static REG: OnceLock<Vec<Box<dyn Importer>>> = OnceLock::new();
    static SLICE: OnceLock<Vec<&'static dyn Importer>> = OnceLock::new();
    let boxes = REG.get_or_init(|| {
        let v: Vec<Box<dyn Importer>> = vec![
            Box::new(FnImporter {
                id: "sarif",
                parse: sarif::parse,
            }),
            Box::new(FnImporter {
                id: "nuclei",
                parse: nuclei::parse,
            }),
            Box::new(FnImporter {
                id: "zap",
                parse: zap::parse,
            }),
            Box::new(FnImporter {
                id: "burp",
                parse: burp::parse,
            }),
            Box::new(FnImporter {
                id: "nessus",
                parse: nessus::parse,
            }),
            Box::new(FnImporter {
                id: "secai",
                parse: secai::parse,
            }),
            Box::new(FnImporter {
                id: "csv",
                parse: csv::parse,
            }),
        ];
        v
    });
    SLICE.get_or_init(|| boxes.iter().map(|b| b.as_ref()).collect())
}

/// Parse `content` according to `format` into an [`ImportOutcome`].
///
/// Supported formats: `sarif`, `nuclei`, `zap`, `burp`, `nessus`, `secai`, `csv`.
pub fn parse(format: &str, content: &str) -> AppResult<ImportOutcome> {
    let fmt = format.to_ascii_lowercase();
    registry()
        .iter()
        .find(|imp| imp.id() == fmt)
        .ok_or_else(|| AppError::Import(format!("unknown import format: {format}")))
        .and_then(|imp| imp.parse(content))
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

/// Map a numeric `security-severity` (0.0–10.0, the SARIF/CodeQL convention,
/// aligned to CVSS bands) to [`Severity`]. Out-of-range/NaN → `Medium`.
pub(crate) fn severity_from_score(score: f64) -> Severity {
    if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else if score > 0.0 {
        Severity::Low
    } else {
        Severity::Info
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

// --- CWE name table ---------------------------------------------------------

/// Bundled, offline CWE id → name table (~130 common weaknesses). Parsed once.
fn cwe_names() -> &'static HashMap<String, String> {
    static TABLE: OnceLock<HashMap<String, String>> = OnceLock::new();
    TABLE.get_or_init(|| {
        serde_json::from_str(include_str!("../../resources/cwe/cwe-names.json"))
            .expect("bundled cwe-names.json must be valid JSON")
    })
}

/// Look up the human-readable name for a normalized `CWE-<n>` id, if bundled.
pub(crate) fn cwe_name(cwe: &str) -> Option<&'static str> {
    cwe_names().get(cwe).map(String::as_str)
}

/// Enrich a finding's description with a "CWE-89: SQL Injection" context line
/// when the bundled table knows the id and the finding carries a CWE. Appends to
/// `technical_details` (kept idempotent: skips if already present). No-op when
/// the cwe is absent/unknown.
pub(crate) fn annotate_cwe_name(f: &mut NewFinding) {
    let Some(cwe) = f.cwe.clone() else { return };
    let Some(name) = cwe_name(&cwe) else { return };
    let line = format!("{cwe}: {name}");
    let desc = f
        .description
        .get_or_insert_with(crate::models::FindingDescription::default);
    if desc.technical_details.contains(&line) {
        return;
    }
    if desc.technical_details.is_empty() {
        desc.technical_details = line;
    } else {
        desc.technical_details = format!("{}\n\n{line}", desc.technical_details);
    }
}

// --- dedup fingerprint ------------------------------------------------------

/// A stable content fingerprint for a finding, used to dedup on import (both
/// within a batch and against findings already in the target report).
///
/// Hash of `title | cwe | cve | primary-evidence-file | severity` — the fields
/// that identify "the same issue at the same place". Two scanner runs of the
/// same target therefore collapse to one finding. Lowercased/trimmed so trivial
/// formatting differences don't defeat it.
pub(crate) fn fingerprint(
    title: &str,
    cwe: Option<&str>,
    cve: Option<&str>,
    evidence_file: Option<&str>,
    severity: Severity,
) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut h = DefaultHasher::new();
    title.trim().to_ascii_lowercase().hash(&mut h);
    cwe.unwrap_or("").trim().to_ascii_uppercase().hash(&mut h);
    cve.unwrap_or("").trim().to_ascii_uppercase().hash(&mut h);
    evidence_file
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
        .hash(&mut h);
    severity.as_str().hash(&mut h);
    h.finish()
}

/// Fingerprint of an in-flight [`NewFinding`] (uses its primary evidence file).
pub(crate) fn finding_fingerprint(f: &NewFinding) -> u64 {
    fingerprint(
        &f.title,
        f.cwe.as_deref(),
        f.cve.as_deref(),
        f.evidence.as_ref().and_then(|e| e.file.as_deref()),
        f.severity,
    )
}

#[cfg(test)]
mod tests {
    use super::{parse, severity_from_score};
    use crate::models::Severity;

    #[test]
    fn sarif_maps_level_and_title() {
        let s = r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t"}},
            "results":[{"ruleId":"R","level":"error","message":{"text":"SQLi found"},
            "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},"region":{"startLine":3}}}]}]}]}"#;
        let out = parse("sarif", s).expect("sarif parse");
        let f = out.findings;
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
        let out = parse("nuclei", s).expect("nuclei parse");
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].severity, Severity::Medium);
    }

    #[test]
    fn nessus_xml_numeric_severity() {
        let s = r#"<NessusClientData_v2><Report name="r"><ReportHost name="h">
            <ReportItem severity="4" pluginName="Critical Issue">
            <description>d</description><solution>s</solution></ReportItem>
            </ReportHost></Report></NessusClientData_v2>"#;
        let out = parse("nessus", s).expect("nessus parse");
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].severity, Severity::Critical); // 4 -> critical
    }

    #[test]
    fn unknown_format_errors() {
        assert!(parse("definitely-not-a-format", "{}").is_err());
    }

    #[test]
    fn security_severity_score_buckets() {
        assert_eq!(severity_from_score(9.8), Severity::Critical);
        assert_eq!(severity_from_score(7.5), Severity::High);
        assert_eq!(severity_from_score(5.0), Severity::Medium);
        assert_eq!(severity_from_score(2.0), Severity::Low);
        assert_eq!(severity_from_score(0.0), Severity::Info);
    }

    #[test]
    fn cwe_table_is_well_formed() {
        let t = super::cwe_names();
        assert!(t.len() >= 100, "expected >=100 CWE names, got {}", t.len());
        assert_eq!(super::cwe_name("CWE-89"), Some("Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"));
        assert_eq!(super::cwe_name("CWE-0"), None);
        for (k, v) in t {
            assert!(k.starts_with("CWE-"), "bad key {k}");
            assert!(!v.is_empty(), "empty name for {k}");
        }
    }

    #[test]
    fn registry_ids_are_unique_and_cover_formats() {
        let ids: Vec<&str> = super::registry().iter().map(|i| i.id()).collect();
        for want in ["sarif", "nuclei", "zap", "burp", "nessus", "secai", "csv"] {
            assert!(ids.contains(&want), "registry missing {want}");
        }
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "duplicate importer id");
    }

    #[test]
    fn nuclei_partial_failure_warns_not_aborts() {
        // First line is valid, second is malformed JSON, third valid.
        let s = "{\"info\":{\"name\":\"A\",\"severity\":\"high\"},\"matched-at\":\"http://x\"}\n\
                 {not json}\n\
                 {\"info\":{\"name\":\"B\",\"severity\":\"low\"},\"matched-at\":\"http://y\"}";
        let out = parse("nuclei", s).expect("nuclei parse");
        assert_eq!(out.findings.len(), 2, "valid lines kept");
        assert_eq!(out.warnings.len(), 1, "one bad line warned");
        assert!(out.warnings[0].contains("line 2"));
    }

    #[test]
    fn secai_tolerates_bad_records_and_uppercase_severity() {
        // First: uppercase severity + bad kind (should still import, mapped
        // leniently). Second: missing title → skipped with a warning.
        let s = r#"[
            {"title":"Weak TLS","severity":"HIGH","kind":"WEIRD","cwe":"326"},
            {"severity":"low","description":{"summary":"no title here"}}
        ]"#;
        let out = parse("secai", s).expect("secai parse");
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].severity, Severity::High);
        assert_eq!(out.findings[0].cwe.as_deref(), Some("CWE-326"));
        assert_eq!(out.warnings.len(), 1);
        assert!(out.warnings[0].contains("missing title"));
    }

    #[test]
    fn sarif_security_severity_overrides_level() {
        // level says "note" (low) but security-severity 9.5 → critical.
        let s = r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t","rules":[]}},
            "results":[{"ruleId":"R","level":"note",
              "properties":{"security-severity":"9.5"},
              "message":{"text":"boom"},
              "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a"},"region":{"startLine":1}}}]}]}]}"#;
        let out = parse("sarif", s).expect("sarif parse");
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].severity, Severity::Critical);
    }

    #[test]
    fn sarif_resolves_rule_by_index_when_ruleid_absent() {
        // No ruleId; ruleIndex 1 points at the second driver rule.
        let s = r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t","rules":[
              {"id":"first","name":"First"},
              {"id":"py/sql","name":"SQL Injection","properties":{"tags":["CWE-89"]}}
            ]}},
            "results":[{"ruleIndex":1,"level":"error","message":{"text":"x"},
              "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a"}}}]}]}]}"#;
        let out = parse("sarif", s).expect("sarif parse");
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].title, "SQL Injection");
        assert_eq!(out.findings[0].cwe.as_deref(), Some("CWE-89"));
    }

    #[test]
    fn zap_captures_all_instance_urls() {
        let s = r#"{"site":[{"alerts":[{"name":"XSS","riskcode":"3",
            "cweid":"79","desc":"d","solution":"s",
            "instances":[{"uri":"http://a/1"},{"uri":"http://a/2"},{"uri":"http://a/3"}]}]}]}"#;
        let out = parse("zap", s).expect("zap parse");
        assert_eq!(out.findings.len(), 1);
        let f = &out.findings[0];
        let snip = f
            .evidence
            .as_ref()
            .unwrap()
            .snippet
            .as_deref()
            .unwrap_or("");
        assert!(snip.contains("http://a/2") && snip.contains("http://a/3"));
        // All URLs surfaced in refs too.
        let refs = f.refs.as_ref().unwrap();
        assert!(refs.iter().any(|r| r == "http://a/3"));
    }

    #[test]
    fn burp_extracts_cwe_and_confidence() {
        let s = r#"<issues><issue><name>SQLi</name><type>1</type>
            <severity>High</severity><confidence>Certain</confidence>
            <host>http://x</host><path>/a</path>
            <vulnerabilityClassifications>See CWE-89: SQL Injection</vulnerabilityClassifications>
            </issue></issues>"#;
        let out = parse("burp", s).expect("burp parse");
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].cwe.as_deref(), Some("CWE-89"));
        assert_eq!(
            out.findings[0].confidence,
            Some(crate::models::Confidence::High)
        );
    }

    #[test]
    fn nessus_merges_hosts_into_one_finding() {
        let s = r#"<NessusClientData_v2><Report name="r">
            <ReportHost name="h1"><ReportItem severity="3" pluginID="42" pluginName="TLS issue" port="443">
              <description>d</description></ReportItem></ReportHost>
            <ReportHost name="h2"><ReportItem severity="3" pluginID="42" pluginName="TLS issue" port="443">
              <description>d</description></ReportItem></ReportHost>
            </Report></NessusClientData_v2>"#;
        let out = parse("nessus", s).expect("nessus parse");
        assert_eq!(out.findings.len(), 1, "same plugin across hosts merged");
        let snip = out.findings[0]
            .evidence
            .as_ref()
            .unwrap()
            .snippet
            .as_deref()
            .unwrap_or("");
        assert!(snip.contains("h1") && snip.contains("h2"));
    }

    #[test]
    fn bundled_kb_catalog_is_valid() {
        let cat: serde_json::Value =
            serde_json::from_str(include_str!("../../resources/kb/catalog.json"))
                .expect("catalog.json must be valid JSON");
        let arr = cat.as_array().expect("catalog must be an array");
        assert!(
            arr.len() >= 12,
            "expected >=12 KB entries, got {}",
            arr.len()
        );
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
