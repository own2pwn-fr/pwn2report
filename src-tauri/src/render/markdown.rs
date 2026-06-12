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

use super::content_model::{FindingInput, ReportDocument};

/// Render the full report to a GitHub-flavored Markdown string.
pub fn to_markdown(doc: &ReportDocument) -> String {
    let mut out = String::new();

    // Title + metadata.
    out.push_str(&format!("# {}\n\n", doc.title));

    let mut meta: Vec<String> = Vec::new();
    if !doc.client.is_empty() {
        meta.push(format!("**Client:** {}", doc.client));
    }
    if !doc.report_type.is_empty() {
        meta.push(format!("**Type:** {}", doc.report_type));
    }
    if !doc.status.is_empty() {
        meta.push(format!("**Status:** {}", doc.status));
    }
    if !doc.date.is_empty() {
        meta.push(format!("**Date:** {}", doc.date));
    }
    if !meta.is_empty() {
        out.push_str(&meta.join("  \n"));
        out.push_str("\n\n");
    }

    if !doc.exec_summary.is_empty() {
        out.push_str("## Executive Summary\n\n");
        out.push_str(&doc.exec_summary);
        out.push_str("\n\n");
    }

    // Severity summary table.
    out.push_str("## Findings Overview\n\n");
    out.push_str("| Severity | Count |\n| --- | --- |\n");
    out.push_str(&format!("| Critical | {} |\n", doc.summary.critical));
    out.push_str(&format!("| High | {} |\n", doc.summary.high));
    out.push_str(&format!("| Medium | {} |\n", doc.summary.medium));
    out.push_str(&format!("| Low | {} |\n", doc.summary.low));
    out.push_str(&format!("| Info | {} |\n", doc.summary.info));
    out.push_str(&format!("| **Total** | **{}** |\n\n", doc.summary.total));

    if !doc.scope.is_empty() {
        out.push_str("## Scope\n\n");
        out.push_str(&doc.scope);
        out.push_str("\n\n");
    }
    if !doc.methodology.is_empty() {
        out.push_str("## Methodology\n\n");
        out.push_str(&doc.methodology);
        out.push_str("\n\n");
    }

    if !doc.findings.is_empty() {
        out.push_str("## Detailed Findings\n\n");
        for (i, f) in doc.findings.iter().enumerate() {
            push_finding(&mut out, i + 1, f);
        }
    } else {
        out.push_str("_No findings recorded for this report._\n");
    }

    out
}

/// Append a single finding section.
fn push_finding(out: &mut String, n: usize, f: &FindingInput) {
    out.push_str(&format!(
        "### {}. {} `{}`\n\n",
        n,
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
        meta.push(format!("CVSS {}", f.cvss_score));
    }
    if !f.confidence.is_empty() {
        meta.push(format!("confidence: {}", f.confidence));
    }
    if !f.kind.is_empty() {
        meta.push(f.kind.clone());
    }
    if !meta.is_empty() {
        out.push_str(&format!("_{}_\n\n", meta.join(" · ")));
    }
    if !f.cvss_vector.is_empty() {
        out.push_str(&format!("`{}`\n\n", f.cvss_vector));
    }

    facet(out, "Summary", &f.summary);
    facet(out, "Root cause", &f.root_cause);
    facet(out, "Attack vector", &f.attack_vector);
    facet(out, "Business impact", &f.business_impact);
    facet(out, "Technical details", &f.technical_details);

    // Evidence.
    if f.has_evidence {
        out.push_str("**Evidence**\n\n");
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
        out.push_str("**Proof of Concept**\n\n");
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

    // Remediation.
    if !f.fix.is_empty() || !f.code_patch.is_empty() || !f.remediation_refs.is_empty() {
        facet(out, "Remediation", &f.fix);
        code_block(out, &f.code_patch);
        if !f.remediation_refs.is_empty() {
            out.push_str("**References**\n\n");
            for r in &f.remediation_refs {
                out.push_str(&format!("- {r}\n"));
            }
            out.push('\n');
        }
    }

    if !f.tags.is_empty() {
        out.push_str(&format!("Tags: {}\n\n", f.tags.join(", ")));
    }

    out.push_str("---\n\n");
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
    use super::*;
    use crate::render::content_model::build_document;
    use crate::test_fixtures::{sample_finding, sample_report};

    #[test]
    fn markdown_includes_title_summary_table_and_findings() {
        let doc = build_document(&sample_report(), vec![sample_finding()]);
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
    fn markdown_omits_empty_optional_sections() {
        let mut report = sample_report();
        report.scope = String::new();
        report.methodology = String::new();
        let doc = build_document(&report, vec![]);
        let md = to_markdown(&doc);
        assert!(!md.contains("## Scope"));
        assert!(!md.contains("## Methodology"));
        assert!(md.contains("_No findings recorded"));
    }
}
