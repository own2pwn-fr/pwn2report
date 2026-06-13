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

use crate::models::{
    Asset, AssetKind, Finding, Report, ReportType, RetestStatus, ScopeItem, Severity,
};
use crate::render::cvss;
use crate::render::labels::Labels;
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
    /// BCP-47-ish language code of the report ("en", "fr", …). Drives the
    /// localized [`labels`](Self::labels) and (in the Typst path) `text(lang:)`.
    pub lang: String,
    /// Localized label dictionary (section titles, severity names, facet labels,
    /// …). Renderers/themes read these instead of hardcoding English literals.
    pub labels: Labels,
    /// Human-readable report-type label ("Web Penetration Test", …), already
    /// localized via [`labels`](Self::labels).
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
    // --- engagement metadata (title page) -----------------------------------
    /// Authors / assessors (may be empty).
    pub authors: Vec<String>,
    pub reviewer: String,
    pub engagement_start: String,
    pub engagement_end: String,
    pub engagement_ref: String,
    pub confidentiality: String,
    // --- branding logo ------------------------------------------------------
    /// `true` when a logo is present; renderers gate the logo block on this.
    pub has_logo: bool,
    /// Logo MIME type ("" when absent).
    pub logo_mime: String,
    /// Logo bytes (empty when absent). `Bytes` so the Typst path can feed it to
    /// `image(..)`; other renderers read `.as_slice()` for data-URI embedding.
    pub logo: Bytes,
    // --- structured scope ---------------------------------------------------
    /// Structured scope rows (in- and out-of-scope), in author order.
    pub scope_items: Vec<ScopeRowInput>,
    /// Per-severity counts for the summary table.
    pub summary: SeveritySummary,
    /// Report-level user-defined custom fields (key order). May be empty.
    pub custom_fields: Vec<CustomFieldInput>,
    /// Findings, already sorted (severity desc, then sort_order).
    pub findings: Vec<FindingInput>,
}

/// A single structured scope row, flattened for the renderers. `in_scope` drives
/// which table (in/out) the renderer places it in.
#[derive(Debug, Clone, IntoValue, IntoDict)]
pub struct ScopeRowInput {
    pub kind: String,
    pub value: String,
    pub in_scope: bool,
    pub note: String,
}

/// A single affected asset, flattened for the renderers. `kind_label` is the
/// localized asset-kind name; `kind` is the raw slug.
#[derive(Debug, Clone, IntoValue, IntoDict)]
pub struct AssetInput {
    pub kind: String,
    pub kind_label: String,
    pub identifier: String,
    pub description: String,
}

/// A single user-defined custom field, flattened for the renderers as a
/// `(field, value)` pair. Used for both report-level and per-finding custom
/// fields; emitted in a small two-column table.
#[derive(Debug, Clone, IntoValue, IntoDict)]
pub struct CustomFieldInput {
    pub field: String,
    pub value: String,
}

/// A single compliance / framework mapping, flattened for the renderers.
/// `name` is "" when the source mapping had no human-readable label.
#[derive(Debug, Clone, IntoValue, IntoDict)]
pub struct MappingInput {
    pub framework: String,
    pub id: String,
    pub name: String,
}

/// Project a model `BTreeMap` of custom fields into the renderer-friendly list,
/// in key order (the map is already sorted).
fn custom_fields_to_inputs(
    fields: &std::collections::BTreeMap<String, String>,
) -> Vec<CustomFieldInput> {
    fields
        .iter()
        .map(|(field, value)| CustomFieldInput {
            field: field.clone(),
            value: value.clone(),
        })
        .collect()
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
    /// Decoded CVSS base metrics (localized label/value pairs). Empty when the
    /// vector is absent or unparseable — renderers then fall back to the raw
    /// vector string.
    pub cvss_metrics: Vec<CvssMetricInput>,
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
    // affected assets (the finding↔asset link set, resolved to live assets)
    pub affected_assets: Vec<AssetInput>,
    // retest workflow (schema v7)
    /// `true` when a retest status is recorded; renderers gate the badge on this.
    pub has_retest: bool,
    /// snake_case retest status ("fixed", …) — the renderer maps it to a label.
    pub retest_status: String,
    /// Localized retest-status label ("Fixed", …); "" when no retest.
    pub retest_status_label: String,
    /// Retest date ("" when unset).
    pub retest_date: String,
    // compliance mappings (schema v7)
    pub mappings: Vec<MappingInput>,
    // per-finding user-defined custom fields (key order)
    pub custom_fields: Vec<CustomFieldInput>,
    // misc
    pub refs: Vec<String>,
    pub tags: Vec<String>,
}

/// A single decoded CVSS base metric, as a localized `(label, value)` pair.
/// Carried as a struct (not a tuple) so the `IntoDict`/`IntoValue` derive can
/// inject it into the Typst template dict the themes index (`m.label`/`m.value`).
#[derive(Debug, Clone, IntoValue, IntoDict)]
pub struct CvssMetricInput {
    pub label: String,
    pub value: String,
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
    /// Language code (drives `#set text(lang: doc.lang)` in the themes).
    pub lang: String,
    /// Localized label dict the themes index (`doc.labels.executive_summary`, …).
    pub labels: Labels,
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
    // engagement metadata + branding — copied verbatim from the raw IR.
    pub authors: Vec<String>,
    pub reviewer: String,
    pub engagement_start: String,
    pub engagement_end: String,
    pub engagement_ref: String,
    pub confidentiality: String,
    pub has_logo: bool,
    pub logo_mime: String,
    pub logo: Bytes,
    pub scope_items: Vec<ScopeRowInput>,
    pub summary: SeveritySummary,
    /// Report-level custom fields — copied verbatim from the raw IR.
    pub custom_fields: Vec<CustomFieldInput>,
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
    /// Decoded CVSS base metrics (localized) — copied verbatim from the raw IR.
    pub cvss_metrics: Vec<CvssMetricInput>,
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
    // affected assets — copied verbatim from the raw IR.
    pub affected_assets: Vec<AssetInput>,
    // retest workflow + mappings + custom fields — copied verbatim.
    pub has_retest: bool,
    pub retest_status: String,
    pub retest_status_label: String,
    pub retest_date: String,
    pub mappings: Vec<MappingInput>,
    pub custom_fields: Vec<CustomFieldInput>,
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
            lang: doc.lang.clone(),
            labels: doc.labels,
            report_type: doc.report_type.clone(),
            report_type_slug: doc.report_type_slug.clone(),
            status: doc.status.clone(),
            date: doc.date.clone(),
            exec_summary: md_to_typst(&doc.exec_summary),
            scope: md_to_typst(&doc.scope),
            methodology: md_to_typst(&doc.methodology),
            authors: doc.authors.clone(),
            reviewer: doc.reviewer.clone(),
            engagement_start: doc.engagement_start.clone(),
            engagement_end: doc.engagement_end.clone(),
            engagement_ref: doc.engagement_ref.clone(),
            confidentiality: doc.confidentiality.clone(),
            has_logo: doc.has_logo,
            logo_mime: doc.logo_mime.clone(),
            logo: doc.logo.clone(),
            scope_items: doc.scope_items.clone(),
            summary: doc.summary.clone(),
            custom_fields: doc.custom_fields.clone(),
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
            cvss_metrics: f.cvss_metrics.clone(),
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
            affected_assets: f.affected_assets.clone(),
            has_retest: f.has_retest,
            retest_status: f.retest_status.clone(),
            retest_status_label: f.retest_status_label.clone(),
            retest_date: f.retest_date.clone(),
            mappings: f.mappings.clone(),
            custom_fields: f.custom_fields.clone(),
            refs: f.refs.clone(),
            tags: f.tags.clone(),
        }
    }
}

/// The localized human-readable report-type label for the given language's
/// [`Labels`] table.
fn report_type_label(t: ReportType, labels: &Labels) -> &'static str {
    match t {
        ReportType::WebPentest => labels.report_type_web_pentest,
        ReportType::CodeAudit => labels.report_type_code_audit,
        ReportType::RedTeam => labels.report_type_red_team,
    }
}

/// The localized human-readable asset-kind label.
fn asset_kind_label(kind: AssetKind, labels: &Labels) -> &'static str {
    match kind {
        AssetKind::Host => labels.asset_host,
        AssetKind::Ip => labels.asset_ip,
        AssetKind::Url => labels.asset_url,
        AssetKind::Domain => labels.asset_domain,
        AssetKind::Credential => labels.asset_credential,
        AssetKind::Other => labels.asset_other,
    }
}

/// The localized human-readable retest-status label.
fn retest_status_label(status: RetestStatus, labels: &Labels) -> &'static str {
    match status {
        RetestStatus::NotRetested => labels.retest_not_retested,
        RetestStatus::Fixed => labels.retest_fixed,
        RetestStatus::PartiallyFixed => labels.retest_partially_fixed,
        RetestStatus::NotFixed => labels.retest_not_fixed,
        RetestStatus::RiskAccepted => labels.retest_risk_accepted,
    }
}

/// Project a DB `Asset` into the renderer-friendly [`AssetInput`].
fn asset_to_input(a: &Asset, labels: &Labels) -> AssetInput {
    AssetInput {
        kind: a.kind.as_str().to_string(),
        kind_label: asset_kind_label(a.kind, labels).to_string(),
        identifier: a.identifier.clone(),
        description: a.description.clone(),
    }
}

impl FindingInput {
    /// Project a DB `Finding` (plus its evidence images) into the
    /// template-friendly shape. `images` is the `(caption, mime, bytes)` list
    /// for this finding, already ordered, taken BY VALUE so the image bytes are
    /// MOVED into the IR rather than copied — they then exist exactly once for
    /// the duration of an export. An empty vec yields no images.
    fn from_finding(
        f: &Finding,
        images: Vec<ImageSource>,
        assets: &[Asset],
        labels: &Labels,
    ) -> Self {
        let evidence = f.evidence.as_ref();
        let evidence_lines = evidence
            .map(|e| match (e.start_line, e.end_line) {
                (Some(s), Some(end)) if end != s => format!("{s}-{end}"),
                (Some(s), _) => s.to_string(),
                _ => String::new(),
            })
            .unwrap_or_default();

        let poc = f.poc.as_ref();

        let cvss_vector = f.cvss_vector.clone().unwrap_or_default();
        let cvss_metrics = cvss::decode(&cvss_vector, labels)
            .into_iter()
            .map(|(label, value)| CvssMetricInput {
                label: label.to_string(),
                value: value.to_string(),
            })
            .collect();

        FindingInput {
            title: f.title.clone(),
            severity: f.severity.as_str().to_string(),
            confidence: format!("{:?}", f.confidence).to_lowercase(),
            kind: format!("{:?}", f.kind).to_lowercase(),
            cwe: f.cwe.clone().unwrap_or_default(),
            cve: f.cve.clone().unwrap_or_default(),
            cvss_vector,
            cvss_score: f.cvss_score.map(|s| format!("{s:.1}")).unwrap_or_default(),
            cvss_metrics,
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
                .into_iter()
                .map(|(caption, mime, data)| FindingImage {
                    caption,
                    mime,
                    data: Bytes::new(data),
                })
                .collect(),
            affected_assets: assets.iter().map(|a| asset_to_input(a, labels)).collect(),
            has_retest: f.retest_status.is_some(),
            retest_status: f
                .retest_status
                .map(|r| r.as_str().to_string())
                .unwrap_or_default(),
            retest_status_label: f
                .retest_status
                .map(|r| retest_status_label(r, labels).to_string())
                .unwrap_or_default(),
            retest_date: f.retest_date.clone().unwrap_or_default(),
            mappings: f
                .mappings
                .iter()
                .map(|m| MappingInput {
                    framework: m.framework.clone(),
                    id: m.id.clone(),
                    name: m.name.clone().unwrap_or_default(),
                })
                .collect(),
            custom_fields: custom_fields_to_inputs(&f.custom_fields),
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
/// `images` maps a finding id to its ordered `(caption, mime, bytes)` list and
/// is CONSUMED: each finding's bytes are moved out of the map and into the IR so
/// the (potentially large) image bytes are never copied during export — they
/// exist exactly once. Findings absent from the map render with no images.
/// `scope_items` are the report's structured scope rows (in author order);
/// `finding_assets` maps a finding id to its ordered affected assets; `logo` is
/// the report's branding logo as `(mime, bytes)` when present. This function
/// stays pure (no DB) — the command/export layer fetches the bytes and builds
/// the maps.
pub fn build_document(
    report: &Report,
    mut findings: Vec<Finding>,
    mut images: HashMap<String, Vec<ImageSource>>,
    scope_items: &[ScopeItem],
    finding_assets: &HashMap<String, Vec<Asset>>,
    logo: Option<&(String, Vec<u8>)>,
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

    let labels = Labels::for_lang(&report.language);

    let engagement_start = report.engagement_start.clone().unwrap_or_default();
    let engagement_end = report.engagement_end.clone().unwrap_or_default();

    let (logo_mime, logo_bytes) = match logo {
        Some((mime, data)) if !data.is_empty() => (mime.clone(), Bytes::new(data.clone())),
        _ => (String::new(), Bytes::new(Vec::new())),
    };
    let has_logo = !logo_mime.is_empty();

    let scope_rows: Vec<ScopeRowInput> = scope_items
        .iter()
        .map(|s| ScopeRowInput {
            kind: s.kind.clone(),
            value: s.value.clone(),
            in_scope: s.in_scope,
            note: s.note.clone(),
        })
        .collect();

    ReportDocument {
        title: report.title.clone(),
        client: report.client.clone(),
        lang: report.language.clone(),
        labels,
        report_type: report_type_label(report.report_type, &labels).to_string(),
        report_type_slug: report.report_type.slug().to_string(),
        status: report.status.clone(),
        date,
        exec_summary: report.exec_summary.clone(),
        scope: report.scope.clone(),
        methodology: report.methodology.clone(),
        authors: report.authors.clone(),
        reviewer: report.reviewer.clone().unwrap_or_default(),
        engagement_start,
        engagement_end,
        engagement_ref: report.engagement_ref.clone().unwrap_or_default(),
        confidentiality: report.confidentiality.clone().unwrap_or_default(),
        has_logo,
        logo_mime,
        logo: logo_bytes,
        scope_items: scope_rows,
        summary,
        custom_fields: custom_fields_to_inputs(&report.custom_fields),
        findings: findings
            .iter()
            .map(|f| {
                // Move the bytes out of the map (consumed) so they are not copied.
                let imgs = images.remove(&f.id).unwrap_or_default();
                let assets = finding_assets.get(&f.id).map(Vec::as_slice).unwrap_or(&[]);
                FindingInput::from_finding(f, imgs, assets, &labels)
            })
            .collect(),
    }
}
