//! Render IR — the data shape passed into the Typst template via
//! `#import sys: inputs`.
//!
//! Deliberately SEPARATE from the DB models: this is a flattened,
//! template-friendly projection (all-strings where convenient, pre-computed
//! severity counts) so the `.typ` files stay simple and robust to missing
//! optional fields. Each type derives `IntoValue`/`IntoDict` from
//! `derive_typst_intoval` and `Vec<_>` of nested types is supported directly.

use std::collections::HashMap;

use derive_typst_intoval::{IntoDict, IntoValue};
// The trait (same name as the derive macro, different namespace) must be in
// scope: the derived `into_dict`/`into_value` call `field.into_value()`.
use typst::foundations::{Bytes, Dict, IntoValue as _};

use crate::models::{Finding, Report, ReportType, Severity};
use crate::render::markup::md_to_typst;

/// One image source for a finding, as passed into [`build_document`]:
/// `(caption, mime, raw bytes)`. Kept as a plain tuple-friendly type so the
/// command/export layer can build the map without depending on Typst types.
pub type ImageSource = (String, String, Vec<u8>);

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
    // evidence images (screenshots / diagrams)
    pub images: Vec<FindingImage>,
    // misc
    pub refs: Vec<String>,
    pub tags: Vec<String>,
}

/// A single evidence image, flattened for the renderers.
///
/// `data` is `typst::foundations::Bytes` so the Typst path can feed it straight
/// to `image(..)` (its `IntoValue` impl makes the derive macro inject it into
/// the template dict as raw bytes). The HTML / Markdown renderers read the same
/// bytes via `data.as_slice()` and base64-encode them into data-URIs.
#[derive(Debug, Clone, IntoValue, IntoDict)]
pub struct FindingImage {
    pub caption: String,
    pub mime: String,
    pub data: Bytes,
}

// ---------------------------------------------------------------------------
// Typst-specific projection.
//
// `ReportDocument` is the RAW IR: the Markdown / HTML / DOCX renderers read its
// prose fields as authored Markdown. The Typst path is different — it `eval`s
// the prose as Typst markup — so it needs the prose pre-converted from Markdown
// to compile-safe Typst markup (see `render/markup.rs`). To avoid leaking that
// conversion into the other renderers, the PDF renderer builds these
// `Typst*Input` mirrors (SAME field names the themes reference) from a
// `&ReportDocument`, converting only the prose fields. Everything else is copied
// verbatim. This keeps the "raw IR" and "Typst dict" concerns cleanly split.
// ---------------------------------------------------------------------------

/// Top-level Typst template input. Field names MUST match `ReportDocument` so
/// the bundled themes (which read `doc.exec_summary`, `doc.findings`, …) work
/// unchanged. Prose fields hold Typst markup; the rest is copied verbatim.
#[derive(Debug, Clone, IntoValue, IntoDict)]
pub struct TypstReportInput {
    pub title: String,
    pub client: String,
    pub report_type: String,
    pub report_type_slug: String,
    pub status: String,
    pub date: String,
    /// Prose → Typst markup.
    pub exec_summary: String,
    /// Prose → Typst markup.
    pub scope: String,
    /// Prose → Typst markup.
    pub methodology: String,
    pub summary: SeveritySummary,
    pub findings: Vec<TypstFindingInput>,
}

/// Required by `compile_with_input` (input must be `impl Into<Dict>`).
impl From<TypstReportInput> for Dict {
    fn from(v: TypstReportInput) -> Self {
        v.into_dict()
    }
}

/// A finding projected for Typst. Field names mirror [`FindingInput`]; only the
/// prose facets + remediation fix are converted to Typst markup, everything else
/// (metadata, code blocks, evidence, images, refs, tags) is copied verbatim.
#[derive(Debug, Clone, IntoValue, IntoDict)]
pub struct TypstFindingInput {
    pub title: String,
    pub severity: String,
    pub confidence: String,
    pub kind: String,
    pub cwe: String,
    pub cve: String,
    pub cvss_vector: String,
    pub cvss_score: String,
    pub triage_status: String,
    // description facets — converted Markdown → Typst markup
    pub summary: String,
    pub root_cause: String,
    pub attack_vector: String,
    pub business_impact: String,
    pub technical_details: String,
    // remediation — `fix` converted; code_patch stays raw (it's a code block)
    pub fix: String,
    pub code_patch: String,
    pub remediation_refs: Vec<String>,
    // evidence (verbatim — snippet is a code block)
    pub has_evidence: bool,
    pub evidence_file: String,
    pub evidence_lines: String,
    pub evidence_snippet: String,
    // poc — scenario is prose (and the red_team theme routes it through `facet`,
    // which `eval`s its body, so it MUST be converted to compile-safe markup);
    // steps + payload stay raw (list / code block)
    pub has_poc: bool,
    pub poc_scenario: String,
    pub poc_steps: Vec<String>,
    pub poc_payload: String,
    // evidence images
    pub images: Vec<FindingImage>,
    // misc
    pub refs: Vec<String>,
    pub tags: Vec<String>,
}

impl TypstReportInput {
    /// Project a raw [`ReportDocument`] into the Typst input, converting prose
    /// fields from Markdown to Typst markup. Non-prose fields are cloned as-is.
    pub fn from_document(doc: &ReportDocument) -> Self {
        TypstReportInput {
            title: doc.title.clone(),
            client: doc.client.clone(),
            report_type: doc.report_type.clone(),
            report_type_slug: doc.report_type_slug.clone(),
            status: doc.status.clone(),
            date: doc.date.clone(),
            exec_summary: md_to_typst(&doc.exec_summary),
            scope: md_to_typst(&doc.scope),
            methodology: md_to_typst(&doc.methodology),
            summary: doc.summary.clone(),
            findings: doc
                .findings
                .iter()
                .map(TypstFindingInput::from_finding)
                .collect(),
        }
    }
}

impl TypstFindingInput {
    /// Project a raw [`FindingInput`] into the Typst input, converting the prose
    /// description facets + remediation fix to Typst markup. Code blocks,
    /// evidence, PoC, images, refs and tags are copied verbatim.
    fn from_finding(f: &FindingInput) -> Self {
        TypstFindingInput {
            title: f.title.clone(),
            severity: f.severity.clone(),
            confidence: f.confidence.clone(),
            kind: f.kind.clone(),
            cwe: f.cwe.clone(),
            cve: f.cve.clone(),
            cvss_vector: f.cvss_vector.clone(),
            cvss_score: f.cvss_score.clone(),
            triage_status: f.triage_status.clone(),
            summary: md_to_typst(&f.summary),
            root_cause: md_to_typst(&f.root_cause),
            attack_vector: md_to_typst(&f.attack_vector),
            business_impact: md_to_typst(&f.business_impact),
            technical_details: md_to_typst(&f.technical_details),
            fix: md_to_typst(&f.fix),
            code_patch: f.code_patch.clone(),
            remediation_refs: f.remediation_refs.clone(),
            has_evidence: f.has_evidence,
            evidence_file: f.evidence_file.clone(),
            evidence_lines: f.evidence_lines.clone(),
            evidence_snippet: f.evidence_snippet.clone(),
            has_poc: f.has_poc,
            poc_scenario: md_to_typst(&f.poc_scenario),
            poc_steps: f.poc_steps.clone(),
            poc_payload: f.poc_payload.clone(),
            images: f.images.clone(),
            refs: f.refs.clone(),
            tags: f.tags.clone(),
        }
    }
}

fn report_type_label(t: ReportType) -> &'static str {
    match t {
        ReportType::WebPentest => "Web Penetration Test",
        ReportType::CodeAudit => "Code Audit",
        ReportType::RedTeam => "Red Team Engagement",
    }
}

impl FindingInput {
    /// Project a DB `Finding` (plus its evidence images) into the
    /// template-friendly shape. `images` is the `(caption, mime, bytes)` list
    /// for this finding, already ordered; an empty slice yields no images.
    fn from_finding(f: &Finding, images: &[ImageSource]) -> Self {
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
            cvss_score: f.cvss_score.map(|s| format!("{s:.1}")).unwrap_or_default(),
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
            evidence_file: evidence.and_then(|e| e.file.clone()).unwrap_or_default(),
            evidence_lines,
            evidence_snippet: evidence.and_then(|e| e.snippet.clone()).unwrap_or_default(),
            has_poc: poc.is_some(),
            poc_scenario: poc.map(|p| p.scenario.clone()).unwrap_or_default(),
            poc_steps: poc
                .map(|p| p.exploitation_steps.clone())
                .unwrap_or_default(),
            poc_payload: poc.and_then(|p| p.payload.clone()).unwrap_or_default(),
            images: images
                .iter()
                .map(|(caption, mime, data)| FindingImage {
                    caption: caption.clone(),
                    mime: mime.clone(),
                    data: Bytes::new(data.clone()),
                })
                .collect(),
            refs: f.refs.clone(),
            tags: f.tags.clone(),
        }
    }
}

/// Build the full `ReportDocument` IR from a report + its findings + their
/// evidence images.
///
/// Findings are sorted by severity (critical first) then `sort_order` so the
/// PDF leads with the most important issues. `date` is the report's
/// `updated_at` truncated to the date portion (falls back to the full string).
///
/// `images` maps a finding id to its ordered `(caption, mime, bytes)` list;
/// findings absent from the map render with no images. This function stays pure
/// (no DB) — the command/export layer fetches the bytes and builds the map.
pub fn build_document(
    report: &Report,
    mut findings: Vec<Finding>,
    images: &HashMap<String, Vec<ImageSource>>,
) -> ReportDocument {
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
        findings: findings
            .iter()
            .map(|f| {
                let imgs = images.get(&f.id).map(Vec::as_slice).unwrap_or(&[]);
                FindingInput::from_finding(f, imgs)
            })
            .collect(),
    }
}
