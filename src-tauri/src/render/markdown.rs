//! GitHub-flavored Markdown renderer.
//!
//! Pure projection of the [`ReportDocument`] IR to a GFM string (no I/O), so it
//! stays unit-testable and can be reused as the source for the DOCX path
//! (`render/docx.rs` pipes this through pandoc). Robust to missing optional
//! fields: every block is emitted only when its source text/array is non-empty.
//!
//! Layout per report type is intentionally uniform here (one Markdown shape for
//! all types); the per-type emphasis lives in the Typst themes. The renderer
//! still leans on the IR's `report_type` label for the document header.

use base64::Engine as _;

use super::content_model::{FindingInput, ReportDocument};
use super::labels::Labels;

/// How a finding's evidence images are emitted into the Markdown.
///
/// The default `to_markdown` inlines them as self-contained base64 data-URIs.
/// The DOCX path needs real file references instead (pandoc does not embed
/// data-URI images reliably), so it supplies its own strategy via
/// [`to_markdown_with`].
pub enum ImageMode<'a> {
    /// Inline every image as a `data:<mime>;base64,...` URI.
    DataUri,
    /// Use a caller-provided `(finding_index, image_index) -> relative path`
    /// resolver (e.g. files written to a temp dir for pandoc's resource path).
    Paths(&'a dyn Fn(usize, usize) -> String),
}

/// Render the full report to a GitHub-flavored Markdown string with images
/// inlined as base64 data-URIs (self-contained `.md`).
pub fn to_markdown(doc: &ReportDocument) -> String {
    to_markdown_with(doc, &ImageMode::DataUri)
}

/// Render the full report to GFM, choosing how evidence images are referenced.
/// See [`ImageMode`]. The DOCX renderer uses [`ImageMode::Paths`].
pub fn to_markdown_with(doc: &ReportDocument, image_mode: &ImageMode) -> String {
    let mut out = String::new();

    let l = &doc.labels;

    // Confidentiality banner (above the title).
    if !doc.confidentiality.is_empty() {
        out.push_str(&format!("> **{}**\n\n", doc.confidentiality.to_uppercase()));
    }

    // Branding logo (self-contained base64 data-URI) at the top.
    if doc.has_logo && !doc.logo.as_slice().is_empty() {
        out.push_str(&format!(
            "![]({})\n\n",
            data_uri(&doc.logo_mime, doc.logo.as_slice())
        ));
    }

    // Title + metadata.
    out.push_str(&format!("# {}\n\n", doc.title));

    let mut meta: Vec<String> = Vec::new();
    if !doc.client.is_empty() {
        meta.push(format!("**{}:** {}", l.client, doc.client));
    }
    if !doc.report_type.is_empty() {
        meta.push(format!("**{}:** {}", l.report_type, doc.report_type));
    }
    if !doc.status.is_empty() {
        meta.push(format!("**{}:** {}", l.status, doc.status));
    }
    if !doc.date.is_empty() {
        meta.push(format!("**{}:** {}", l.date, doc.date));
    }
    // Engagement metadata.
    if !doc.authors.is_empty() {
        meta.push(format!("**{}:** {}", l.authors, doc.authors.join(", ")));
    }
    if !doc.reviewer.is_empty() {
        meta.push(format!("**{}:** {}", l.reviewer, doc.reviewer));
    }
    let period = engagement_period(&doc.engagement_start, &doc.engagement_end);
    if !period.is_empty() {
        meta.push(format!("**{}:** {}", l.engagement_period, period));
    }
    if !doc.engagement_ref.is_empty() {
        meta.push(format!("**{}:** {}", l.reference, doc.engagement_ref));
    }
    if !meta.is_empty() {
        out.push_str(&meta.join("  \n"));
        out.push_str("\n\n");
    }

    if !doc.exec_summary.is_empty() {
        out.push_str(&format!("## {}\n\n", l.executive_summary));
        out.push_str(&doc.exec_summary);
        out.push_str("\n\n");
    }

    // Severity summary table.
    out.push_str(&format!("## {}\n\n", l.findings_overview));
    out.push_str(&format!(
        "| {} | {} |\n| --- | --- |\n",
        l.severity, l.count
    ));
    out.push_str(&format!("| {} | {} |\n", l.critical, doc.summary.critical));
    out.push_str(&format!("| {} | {} |\n", l.high, doc.summary.high));
    out.push_str(&format!("| {} | {} |\n", l.medium, doc.summary.medium));
    out.push_str(&format!("| {} | {} |\n", l.low, doc.summary.low));
    out.push_str(&format!("| {} | {} |\n", l.info, doc.summary.info));
    out.push_str(&format!(
        "| **{}** | **{}** |\n\n",
        l.total, doc.summary.total
    ));

    if !doc.scope.is_empty() || !doc.scope_items.is_empty() {
        out.push_str(&format!("## {}\n\n", l.scope));
        if !doc.scope.is_empty() {
            out.push_str(&doc.scope);
            out.push_str("\n\n");
        }
        push_scope_table(&mut out, doc, l);
    }
    if !doc.methodology.is_empty() {
        out.push_str(&format!("## {}\n\n", l.methodology));
        out.push_str(&doc.methodology);
        out.push_str("\n\n");
    }

    if !doc.findings.is_empty() {
        out.push_str(&format!("## {}\n\n", l.detailed_findings));
        for (i, f) in doc.findings.iter().enumerate() {
            push_finding(&mut out, i, f, l, image_mode);
        }
    } else {
        out.push_str(&format!("_{}_\n", l.no_findings));
    }

    out
}

/// Append a single finding section. `idx` is the 0-based finding index (used
/// both for the displayed number and to resolve image paths in DOCX mode).
fn push_finding(
    out: &mut String,
    idx: usize,
    f: &FindingInput,
    l: &Labels,
    image_mode: &ImageMode,
) {
    out.push_str(&format!(
        "### {}. {} `{}`\n\n",
        idx + 1,
        f.title,
        f.severity.to_uppercase()
    ));

    // Meta line.
    let mut meta: Vec<String> = Vec::new();
    if !f.cwe.is_empty() {
        meta.push(f.cwe.clone());
    }
    if !f.cve.is_empty() {
        meta.push(f.cve.clone());
    }
    if !f.cvss_score.is_empty() {
        meta.push(format!("{} {}", l.cvss, f.cvss_score));
    }
    if !f.confidence.is_empty() {
        meta.push(format!("{}: {}", l.confidence.to_lowercase(), f.confidence));
    }
    if !f.kind.is_empty() {
        meta.push(f.kind.clone());
    }
    if !meta.is_empty() {
        out.push_str(&format!("_{}_\n\n", meta.join(" · ")));
    }
    // CVSS: prefer the decoded metric grid; fall back to the raw vector.
    if !f.cvss_metrics.is_empty() {
        for m in &f.cvss_metrics {
            out.push_str(&format!("- **{}:** {}\n", m.label, m.value));
        }
        out.push('\n');
    } else if !f.cvss_vector.is_empty() {
        out.push_str(&format!("`{}`\n\n", f.cvss_vector));
    }

    facet(out, l.summary, &f.summary);
    facet(out, l.root_cause, &f.root_cause);
    facet(out, l.attack_vector, &f.attack_vector);
    facet(out, l.business_impact, &f.business_impact);
    facet(out, l.technical_details, &f.technical_details);

    // Affected assets (the finding↔asset link set).
    if !f.affected_assets.is_empty() {
        out.push_str(&format!("**{}**\n\n", l.affected_assets));
        for a in &f.affected_assets {
            let desc = if a.description.is_empty() {
                String::new()
            } else {
                format!(" — {}", a.description)
            };
            out.push_str(&format!(
                "- _{}_ `{}`{}\n",
                a.kind_label, a.identifier, desc
            ));
        }
        out.push('\n');
    }

    // Evidence.
    if f.has_evidence {
        out.push_str(&format!("**{}**\n\n", l.evidence));
        let loc = if !f.evidence_file.is_empty() {
            if !f.evidence_lines.is_empty() {
                format!("{}:{}", f.evidence_file, f.evidence_lines)
            } else {
                f.evidence_file.clone()
            }
        } else {
            String::new()
        };
        if !loc.is_empty() {
            out.push_str(&format!("`{loc}`\n\n"));
        }
        code_block(out, &f.evidence_snippet);
    }

    // Proof of Concept.
    if f.has_poc {
        out.push_str(&format!("**{}**\n\n", l.proof_of_concept));
        if !f.poc_scenario.is_empty() {
            out.push_str(&f.poc_scenario);
            out.push_str("\n\n");
        }
        if !f.poc_steps.is_empty() {
            for (i, step) in f.poc_steps.iter().enumerate() {
                out.push_str(&format!("{}. {}\n", i + 1, step));
            }
            out.push('\n');
        }
        code_block(out, &f.poc_payload);
    }

    // Evidence images. In `DataUri` mode the `.md` is self-contained; in
    // `Paths` mode each image is referenced by a relative file path (pandoc's
    // `--resource-path` resolves it for DOCX embedding).
    if !f.images.is_empty() {
        out.push_str(&format!("**{}**\n\n", l.screenshots));
        for (j, img) in f.images.iter().enumerate() {
            let src = match image_mode {
                ImageMode::DataUri => format!(
                    "data:{};base64,{}",
                    img.mime,
                    base64::engine::general_purpose::STANDARD.encode(img.data.as_slice())
                ),
                ImageMode::Paths(resolve) => resolve(idx, j),
            };
            // Alt text doubles as the visible caption line below the image.
            out.push_str(&format!("![{}]({})\n\n", md_alt(&img.caption), src));
            if !img.caption.is_empty() {
                out.push_str(&format!("_{}_\n\n", img.caption));
            }
        }
    }

    // Remediation.
    if !f.fix.is_empty() || !f.code_patch.is_empty() || !f.remediation_refs.is_empty() {
        facet(out, l.remediation, &f.fix);
        code_block(out, &f.code_patch);
        if !f.remediation_refs.is_empty() {
            out.push_str(&format!("**{}**\n\n", l.references));
            for r in &f.remediation_refs {
                out.push_str(&format!("- {r}\n"));
            }
            out.push('\n');
        }
    }

    if !f.tags.is_empty() {
        out.push_str(&format!("{}: {}\n\n", l.tags, f.tags.join(", ")));
    }

    out.push_str("---\n\n");
}

/// Sanitize a caption for use as Markdown image alt text (strip the bracket
/// that would terminate the alt span and collapse newlines).
fn md_alt(caption: &str) -> String {
    caption.replace(['[', ']'], "").replace('\n', " ")
}

/// Format a `data:<mime>;base64,...` URI for the given bytes.
fn data_uri(mime: &str, data: &[u8]) -> String {
    format!(
        "data:{};base64,{}",
        mime,
        base64::engine::general_purpose::STANDARD.encode(data)
    )
}

/// Combine engagement start/end into a single display string ("" when both
/// empty, a single date when only one is set, else "start – end").
fn engagement_period(start: &str, end: &str) -> String {
    match (start.is_empty(), end.is_empty()) {
        (true, true) => String::new(),
        (false, false) => format!("{start} – {end}"),
        (false, true) => start.to_string(),
        (true, false) => end.to_string(),
    }
}

/// Emit the structured-scope tables (in-scope / out-of-scope) when present.
fn push_scope_table(out: &mut String, doc: &ReportDocument, l: &Labels) {
    if doc.scope_items.is_empty() {
        return;
    }
    let mut emit = |heading: &str, in_scope: bool| {
        let rows: Vec<_> = doc
            .scope_items
            .iter()
            .filter(|s| s.in_scope == in_scope)
            .collect();
        if rows.is_empty() {
            return;
        }
        out.push_str(&format!("**{heading}**\n\n"));
        out.push_str("| Kind | Value | Note |\n| --- | --- | --- |\n");
        for s in rows {
            let kind = if s.kind.is_empty() { "—" } else { &s.kind };
            out.push_str(&format!("| {} | `{}` | {} |\n", kind, s.value, s.note));
        }
        out.push('\n');
    };
    emit(l.in_scope, true);
    emit(l.out_of_scope, false);
}

/// Emit a bold-labelled paragraph only when the body is non-empty.
fn facet(out: &mut String, label: &str, body: &str) {
    if !body.is_empty() {
        out.push_str(&format!("**{label}**\n\n{body}\n\n"));
    }
}

/// Emit a fenced code block only when the body is non-empty.
fn code_block(out: &mut String, body: &str) {
    if !body.is_empty() {
        out.push_str("```\n");
        out.push_str(body);
        if !body.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("```\n\n");
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::render::content_model::build_document;
    use crate::test_fixtures::{sample_finding, sample_report};

    #[test]
    fn markdown_includes_title_summary_table_and_findings() {
        let doc = build_document(
            &sample_report(),
            vec![sample_finding()],
            &HashMap::new(),
            &[],
            &HashMap::new(),
            None,
        );
        let md = to_markdown(&doc);
        assert!(md.starts_with("# Test Report"));
        assert!(md.contains("| Severity | Count |"));
        assert!(md.contains("| High | 1 |"));
        assert!(md.contains("### 1. SQL Injection `HIGH`"));
        // code blocks for snippet and patch are fenced.
        assert!(md.contains("```\nSELECT * FROM users"));
        assert!(md.contains("CWE-89"));
    }

    #[test]
    fn markdown_decodes_cvss_vector_into_metric_list() {
        let doc = build_document(
            &sample_report(),
            vec![sample_finding()],
            &HashMap::new(),
            &[],
            &HashMap::new(),
            None,
        );
        let md = to_markdown(&doc);
        assert!(md.contains("- **Attack vector:** Network"));
        // Raw vector string is replaced by the decoded list.
        assert!(!md.contains("`CVSS:3.1/AV:N"));
    }

    #[test]
    fn markdown_renders_engagement_meta_scope_and_assets() {
        use crate::models::{Asset, AssetKind, ScopeItem};
        let mut report = sample_report();
        report.authors = vec!["Alice".into(), "Bob".into()];
        report.reviewer = Some("Carol".into());
        report.engagement_ref = Some("PO-42".into());
        report.confidentiality = Some("Confidential".into());

        let scope = vec![
            ScopeItem {
                id: "s1".into(),
                report_id: "r1".into(),
                kind: "url".into(),
                value: "https://app.example.com".into(),
                in_scope: true,
                note: "prod".into(),
                sort_order: 0,
                created_at: "x".into(),
                updated_at: "x".into(),
                deleted_at: None,
            },
            ScopeItem {
                id: "s2".into(),
                report_id: "r1".into(),
                kind: "host".into(),
                value: "legacy.example.com".into(),
                in_scope: false,
                note: String::new(),
                sort_order: 1,
                created_at: "x".into(),
                updated_at: "x".into(),
                deleted_at: None,
            },
        ];
        let mut fa = HashMap::new();
        fa.insert(
            "f1".to_string(),
            vec![Asset {
                id: "a1".into(),
                report_id: "r1".into(),
                kind: AssetKind::Url,
                identifier: "https://app.example.com".into(),
                description: "Main app".into(),
                sort_order: 0,
                created_at: "x".into(),
                updated_at: "x".into(),
                deleted_at: None,
            }],
        );
        let doc = build_document(
            &report,
            vec![sample_finding()],
            &HashMap::new(),
            &scope,
            &fa,
            None,
        );
        let md = to_markdown(&doc);
        assert!(md.contains("**Authors:** Alice, Bob"));
        assert!(md.contains("**Reference:** PO-42"));
        assert!(md.contains("> **CONFIDENTIAL**"));
        // Scope tables for both in- and out-of-scope.
        assert!(md.contains("**In scope**"));
        assert!(md.contains("**Out of scope**"));
        assert!(md.contains("`legacy.example.com`"));
        // Affected assets list under the finding.
        assert!(md.contains("**Affected assets**"));
        assert!(md.contains("_URL_ `https://app.example.com` — Main app"));
    }

    #[test]
    fn markdown_omits_empty_optional_sections() {
        let mut report = sample_report();
        report.scope = String::new();
        report.methodology = String::new();
        let doc = build_document(&report, vec![], &HashMap::new(), &[], &HashMap::new(), None);
        let md = to_markdown(&doc);
        assert!(!md.contains("## Scope"));
        assert!(!md.contains("## Methodology"));
        assert!(md.contains("_No findings recorded"));
    }
}
