//! Render IR — the data shape passed into the Typst template via
//! `#import sys: inputs`.
//!
//! Deliberately SEPARATE from the DB models: this is a flattened,
//! template-friendly projection (all-strings where convenient, pre-computed
//! severity counts) so the `.typ` files stay simple and robust to missing
//! optional fields. Each type derives `IntoValue`/`IntoDict` from
//! `derive_typst_intoval` and `Vec<_>` of nested types is supported directly.

use derive_typst_intoval::{IntoDict, IntoValue};
// The trait (same name as the derive macro, different namespace) must be in
// scope: the derived `into_dict`/`into_value` call `field.into_value()`.
use typst::foundations::{Dict, IntoValue as _};

use crate::models::{Finding, Report, ReportType, Severity};

/// Top-level template input.
#[derive(Debug, Clone, IntoValue, IntoDict)]
pub struct ReportDocument {
    pub title: String,
    pub client: String,
    /// Human-readable report-type label ("Web Penetration Test", …).
    pub report_type: String,
    /// snake_case report-type slug ("web_pentest", …) — used by renderers to
    /// pick a per-type layout and by the Typst path to resolve the template.
    pub report_type_slug: String,
    pub status: String,
    /// Localized/ISO date string for the title page.
    pub date: String,
    pub exec_summary: String,
    pub scope: String,
    pub methodology: String,
    /// Per-severity counts for the summary table.
    pub summary: SeveritySummary,
    /// Findings, already sorted (severity desc, then sort_order).
    pub findings: Vec<FindingInput>,
}

/// Required by `compile_with_input` (input must be `impl Into<Dict>`).
impl From<ReportDocument> for Dict {
    fn from(v: ReportDocument) -> Self {
        v.into_dict()
    }
}

/// Counts of findings per severity bucket (i64 so Typst sees integers).
#[derive(Debug, Clone, Default, IntoValue, IntoDict)]
pub struct SeveritySummary {
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub info: i64,
    pub total: i64,
}

/// A finding, flattened for the template. Optional fields become empty strings
/// (or empty vecs) so the `.typ` never has to test for `none` on a missing key.
#[derive(Debug, Clone, IntoValue, IntoDict)]
pub struct FindingInput {
    pub title: String,
    /// snake_case severity string ("critical", …) — the template maps it to a
    /// color + label.
    pub severity: String,
    pub confidence: String,
    pub kind: String,
    pub cwe: String,
    pub cve: String,
    pub cvss_vector: String,
    /// Pre-formatted score string ("" when absent).
    pub cvss_score: String,
    pub triage_status: String,
    // description facets
    pub summary: String,
    pub root_cause: String,
    pub attack_vector: String,
    pub business_impact: String,
    pub technical_details: String,
    // remediation
    pub fix: String,
    pub code_patch: String,
    pub remediation_refs: Vec<String>,
    // evidence
    pub has_evidence: bool,
    pub evidence_file: String,
    pub evidence_lines: String,
    pub evidence_snippet: String,
    // poc
    pub has_poc: bool,
    pub poc_scenario: String,
    pub poc_steps: Vec<String>,
    pub poc_payload: String,
    // misc
    pub refs: Vec<String>,
    pub tags: Vec<String>,
}

fn report_type_label(t: ReportType) -> &'static str {
    match t {
        ReportType::WebPentest => "Web Penetration Test",
        ReportType::CodeAudit => "Code Audit",
        ReportType::RedTeam => "Red Team Engagement",
    }
}

impl FindingInput {
    /// Project a DB `Finding` into the template-friendly shape.
    fn from_finding(f: &Finding) -> Self {
        let evidence = f.evidence.as_ref();
        let evidence_lines = evidence
            .map(|e| match (e.start_line, e.end_line) {
                (Some(s), Some(end)) if end != s => format!("{s}-{end}"),
                (Some(s), _) => s.to_string(),
                _ => String::new(),
            })
            .unwrap_or_default();

        let poc = f.poc.as_ref();

        FindingInput {
            title: f.title.clone(),
            severity: f.severity.as_str().to_string(),
            confidence: format!("{:?}", f.confidence).to_lowercase(),
            kind: format!("{:?}", f.kind).to_lowercase(),
            cwe: f.cwe.clone().unwrap_or_default(),
            cve: f.cve.clone().unwrap_or_default(),
            cvss_vector: f.cvss_vector.clone().unwrap_or_default(),
            cvss_score: f
                .cvss_score
                .map(|s| format!("{s:.1}"))
                .unwrap_or_default(),
            triage_status: format!("{:?}", f.triage_status).to_lowercase(),
            summary: f.description.summary.clone(),
            root_cause: f.description.root_cause.clone(),
            attack_vector: f.description.attack_vector.clone(),
            business_impact: f.description.business_impact.clone(),
            technical_details: f.description.technical_details.clone(),
            fix: f.remediation.fix.clone(),
            code_patch: f.remediation.code_patch.clone().unwrap_or_default(),
            remediation_refs: f.remediation.references.clone(),
            has_evidence: evidence.is_some(),
            evidence_file: evidence
                .and_then(|e| e.file.clone())
                .unwrap_or_default(),
            evidence_lines,
            evidence_snippet: evidence
                .and_then(|e| e.snippet.clone())
                .unwrap_or_default(),
            has_poc: poc.is_some(),
            poc_scenario: poc.map(|p| p.scenario.clone()).unwrap_or_default(),
            poc_steps: poc.map(|p| p.exploitation_steps.clone()).unwrap_or_default(),
            poc_payload: poc
                .and_then(|p| p.payload.clone())
                .unwrap_or_default(),
            refs: f.refs.clone(),
            tags: f.tags.clone(),
        }
    }
}

/// Build the full `ReportDocument` IR from a report + its findings.
///
/// Findings are sorted by severity (critical first) then `sort_order` so the
/// PDF leads with the most important issues. `date` is the report's
/// `updated_at` truncated to the date portion (falls back to the full string).
pub fn build_document(report: &Report, mut findings: Vec<Finding>) -> ReportDocument {
    findings.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then(a.sort_order.cmp(&b.sort_order))
    });

    let mut summary = SeveritySummary::default();
    for f in &findings {
        match f.severity {
            Severity::Critical => summary.critical += 1,
            Severity::High => summary.high += 1,
            Severity::Medium => summary.medium += 1,
            Severity::Low => summary.low += 1,
            Severity::Info => summary.info += 1,
        }
        summary.total += 1;
    }

    let date = report
        .updated_at
        .split('T')
        .next()
        .unwrap_or(&report.updated_at)
        .to_string();

    ReportDocument {
        title: report.title.clone(),
        client: report.client.clone(),
        report_type: report_type_label(report.report_type).to_string(),
        report_type_slug: report.report_type.slug().to_string(),
        status: report.status.clone(),
        date,
        exec_summary: report.exec_summary.clone(),
        scope: report.scope.clone(),
        methodology: report.methodology.clone(),
        summary,
        findings: findings.iter().map(FindingInput::from_finding).collect(),
    }
}
