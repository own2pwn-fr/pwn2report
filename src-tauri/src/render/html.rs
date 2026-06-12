//! Self-contained HTML renderer.
//!
//! Pure projection of the [`ReportDocument`] IR to a single standalone HTML
//! document (no I/O, no external references — all CSS inlined in a `<style>`
//! tag). own2pwn-styled: dark theme, violet accent, Inter / JetBrains Mono
//! font-family stacks, per-severity color chips. All user-supplied content is
//! HTML-escaped before insertion.

use base64::Engine as _;

use super::content_model::{FindingInput, ReportDocument};

/// Escape the five significant HTML characters in user content.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Hex color for a severity chip (mirrors the Typst `severity-color`).
fn severity_color(sev: &str) -> &'static str {
    match sev {
        "critical" => "#dc2626",
        "high" => "#ea580c",
        "medium" => "#d97706",
        "low" => "#2563eb",
        _ => "#6b7280", // info / unknown
    }
}

const STYLE: &str = r#"
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 2.5rem 1.5rem;
  background: #0d0d0f;
  color: #e5e5ea;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  line-height: 1.6;
}
.container { max-width: 860px; margin: 0 auto; }
h1 { font-size: 2rem; margin: 0 0 0.25rem; color: #f4f4f6; }
h2 { font-size: 1.4rem; margin: 2.5rem 0 1rem; color: #7c5cff; border-bottom: 1px solid #26262c; padding-bottom: 0.35rem; }
h3 { font-size: 1.15rem; margin: 0 0 0.5rem; color: #f4f4f6; }
a { color: #7c5cff; }
.meta { color: #9b9ba3; font-size: 0.95rem; margin-bottom: 0.5rem; }
.meta strong { color: #c7c7cf; }
.facet-label { color: #7c5cff; font-weight: 600; margin: 1rem 0 0.25rem; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
th, td { border: 1px solid #26262c; padding: 0.5rem 0.75rem; text-align: left; }
th { background: #17171b; color: #c7c7cf; }
tr.total td { font-weight: 700; background: #17171b; }
pre {
  background: #17171b;
  border: 1px solid #26262c;
  border-radius: 6px;
  padding: 0.85rem 1rem;
  overflow-x: auto;
  font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.85rem;
  color: #e5e5ea;
}
code {
  font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.85rem;
  color: #c7c7cf;
}
.chip {
  display: inline-block;
  padding: 0.1rem 0.55rem;
  border-radius: 4px;
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.03em;
  color: #fff;
  vertical-align: middle;
}
.tag {
  display: inline-block;
  padding: 0.1rem 0.5rem;
  border-radius: 3px;
  font-size: 0.72rem;
  background: #26262c;
  color: #c7c7cf;
  margin-right: 0.35rem;
}
.finding { padding: 1.25rem 0; border-bottom: 1px solid #26262c; }
.loc { color: #9b9ba3; }
ol, ul { margin: 0.25rem 0 1rem; padding-left: 1.4rem; }
.empty { color: #9b9ba3; font-style: italic; }
figure.evidence-img { margin: 0.75rem 0; }
figure.evidence-img img {
  max-width: 100%;
  height: auto;
  border: 1px solid #26262c;
  border-radius: 6px;
  display: block;
}
figure.evidence-img figcaption {
  color: #9b9ba3;
  font-size: 0.85rem;
  font-style: italic;
  margin-top: 0.35rem;
}
"#;

/// Render the full report to a self-contained HTML document string.
pub fn to_html(doc: &ReportDocument) -> String {
    let mut out = String::new();
    out.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    out.push_str("<meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    out.push_str(&format!("<title>{}</title>\n", esc(&doc.title)));
    out.push_str("<style>");
    out.push_str(STYLE);
    out.push_str("</style>\n</head>\n<body>\n<div class=\"container\">\n");

    out.push_str(&format!("<h1>{}</h1>\n", esc(&doc.title)));

    // Metadata.
    let mut meta: Vec<String> = Vec::new();
    if !doc.client.is_empty() {
        meta.push(format!("<strong>Client:</strong> {}", esc(&doc.client)));
    }
    if !doc.report_type.is_empty() {
        meta.push(format!("<strong>Type:</strong> {}", esc(&doc.report_type)));
    }
    if !doc.status.is_empty() {
        meta.push(format!("<strong>Status:</strong> {}", esc(&doc.status)));
    }
    if !doc.date.is_empty() {
        meta.push(format!("<strong>Date:</strong> {}", esc(&doc.date)));
    }
    if !meta.is_empty() {
        out.push_str(&format!("<div class=\"meta\">{}</div>\n", meta.join(" &middot; ")));
    }

    if !doc.exec_summary.is_empty() {
        out.push_str("<h2>Executive Summary</h2>\n");
        para(&mut out, &doc.exec_summary);
    }

    // Severity summary table.
    out.push_str("<h2>Findings Overview</h2>\n<table>\n");
    out.push_str("<tr><th>Severity</th><th>Count</th></tr>\n");
    for (sev, label, n) in [
        ("critical", "Critical", doc.summary.critical),
        ("high", "High", doc.summary.high),
        ("medium", "Medium", doc.summary.medium),
        ("low", "Low", doc.summary.low),
        ("info", "Info", doc.summary.info),
    ] {
        out.push_str(&format!(
            "<tr><td>{}</td><td>{}</td></tr>\n",
            chip(sev, label),
            n
        ));
    }
    out.push_str(&format!(
        "<tr class=\"total\"><td>Total</td><td>{}</td></tr>\n</table>\n",
        doc.summary.total
    ));

    if !doc.scope.is_empty() {
        out.push_str("<h2>Scope</h2>\n");
        para(&mut out, &doc.scope);
    }
    if !doc.methodology.is_empty() {
        out.push_str("<h2>Methodology</h2>\n");
        para(&mut out, &doc.methodology);
    }

    if !doc.findings.is_empty() {
        out.push_str("<h2>Detailed Findings</h2>\n");
        for (i, f) in doc.findings.iter().enumerate() {
            push_finding(&mut out, i + 1, f);
        }
    } else {
        out.push_str("<p class=\"empty\">No findings recorded for this report.</p>\n");
    }

    out.push_str("</div>\n</body>\n</html>\n");
    out
}

/// A severity color chip.
fn chip(sev: &str, label: &str) -> String {
    format!(
        "<span class=\"chip\" style=\"background:{}\">{}</span>",
        severity_color(sev),
        esc(label)
    )
}

fn push_finding(out: &mut String, n: usize, f: &FindingInput) {
    out.push_str("<div class=\"finding\">\n");
    out.push_str(&format!(
        "<h3>{}. {} {}</h3>\n",
        n,
        esc(&f.title),
        chip(&f.severity, &f.severity.to_uppercase())
    ));

    // Meta line.
    let mut meta: Vec<String> = Vec::new();
    if !f.cwe.is_empty() {
        meta.push(esc(&f.cwe));
    }
    if !f.cve.is_empty() {
        meta.push(esc(&f.cve));
    }
    if !f.cvss_score.is_empty() {
        meta.push(format!("CVSS {}", esc(&f.cvss_score)));
    }
    if !f.confidence.is_empty() {
        meta.push(format!("confidence: {}", esc(&f.confidence)));
    }
    if !f.kind.is_empty() {
        meta.push(esc(&f.kind));
    }
    if !meta.is_empty() {
        out.push_str(&format!("<div class=\"meta\">{}</div>\n", meta.join(" &middot; ")));
    }
    if !f.cvss_vector.is_empty() {
        out.push_str(&format!("<div class=\"meta\"><code>{}</code></div>\n", esc(&f.cvss_vector)));
    }

    facet(out, "Summary", &f.summary);
    facet(out, "Root cause", &f.root_cause);
    facet(out, "Attack vector", &f.attack_vector);
    facet(out, "Business impact", &f.business_impact);
    facet(out, "Technical details", &f.technical_details);

    // Evidence.
    if f.has_evidence {
        out.push_str("<div class=\"facet-label\">Evidence</div>\n");
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
            out.push_str(&format!("<div class=\"meta loc\"><code>{}</code></div>\n", esc(&loc)));
        }
        code_block(out, &f.evidence_snippet);
    }

    // Proof of Concept.
    if f.has_poc {
        out.push_str("<div class=\"facet-label\">Proof of Concept</div>\n");
        if !f.poc_scenario.is_empty() {
            para(out, &f.poc_scenario);
        }
        if !f.poc_steps.is_empty() {
            out.push_str("<ol>\n");
            for step in &f.poc_steps {
                out.push_str(&format!("<li>{}</li>\n", esc(step)));
            }
            out.push_str("</ol>\n");
        }
        code_block(out, &f.poc_payload);
    }

    // Evidence images (inlined as base64 data-URIs so the doc is self-contained).
    if !f.images.is_empty() {
        out.push_str("<div class=\"facet-label\">Screenshots</div>\n");
        for img in &f.images {
            let b64 = base64::engine::general_purpose::STANDARD.encode(img.data.as_slice());
            out.push_str("<figure class=\"evidence-img\">\n");
            out.push_str(&format!(
                "<img src=\"data:{};base64,{}\" alt=\"{}\">\n",
                esc(&img.mime),
                b64,
                esc(&img.caption)
            ));
            if !img.caption.is_empty() {
                out.push_str(&format!("<figcaption>{}</figcaption>\n", esc(&img.caption)));
            }
            out.push_str("</figure>\n");
        }
    }

    // Remediation.
    if !f.fix.is_empty() || !f.code_patch.is_empty() || !f.remediation_refs.is_empty() {
        if !f.fix.is_empty() {
            out.push_str("<div class=\"facet-label\">Remediation</div>\n");
            para(out, &f.fix);
        }
        code_block(out, &f.code_patch);
        if !f.remediation_refs.is_empty() {
            out.push_str("<div class=\"facet-label\">References</div>\n<ul>\n");
            for r in &f.remediation_refs {
                out.push_str(&format!("<li><a href=\"{0}\">{0}</a></li>\n", esc(r)));
            }
            out.push_str("</ul>\n");
        }
    }

    if !f.tags.is_empty() {
        out.push_str("<div class=\"meta\">");
        for t in &f.tags {
            out.push_str(&format!("<span class=\"tag\">{}</span>", esc(t)));
        }
        out.push_str("</div>\n");
    }

    out.push_str("</div>\n");
}

/// Emit a labelled facet (label + paragraph) only when non-empty.
fn facet(out: &mut String, label: &str, body: &str) {
    if !body.is_empty() {
        out.push_str(&format!("<div class=\"facet-label\">{}</div>\n", esc(label)));
        para(out, body);
    }
}

/// Emit an escaped paragraph (preserving line breaks).
fn para(out: &mut String, body: &str) {
    out.push_str(&format!("<p>{}</p>\n", esc(body).replace('\n', "<br>")));
}

/// Emit an escaped fenced code block only when non-empty.
fn code_block(out: &mut String, body: &str) {
    if !body.is_empty() {
        out.push_str(&format!("<pre>{}</pre>\n", esc(body)));
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::render::content_model::build_document;
    use crate::test_fixtures::{sample_finding, sample_report};

    #[test]
    fn html_is_self_contained_and_escapes_user_content() {
        let mut finding = sample_finding();
        finding.title = "XSS <script>alert(1)</script>".to_string();
        let doc = build_document(&sample_report(), vec![finding], &HashMap::new());
        let html = to_html(&doc);

        assert!(html.starts_with("<!DOCTYPE html>"));
        // CSS is inline, no external refs.
        assert!(html.contains("<style>"));
        assert!(!html.contains("<link"));
        assert!(!html.contains("src=\"http"));
        // User content is escaped (no raw <script>).
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<script>alert(1)"));
        // Severity chip carries the high color.
        assert!(html.contains("#ea580c"));
    }

    #[test]
    fn esc_handles_all_significant_chars() {
        assert_eq!(esc("a&b<c>d\"e'f"), "a&amp;b&lt;c&gt;d&quot;e&#39;f");
    }

    /// A 1x1 transparent PNG (decoded from base64) used to exercise embedding.
    fn one_px_png() -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
            )
            .unwrap()
    }

    #[test]
    fn html_embeds_evidence_images_as_data_uri() {
        let png = one_px_png();
        let mut images = HashMap::new();
        images.insert(
            "f1".to_string(),
            vec![("Login bypass".to_string(), "image/png".to_string(), png)],
        );
        let doc = build_document(&sample_report(), vec![sample_finding()], &images);
        let html = to_html(&doc);

        assert!(html.contains("<img src=\"data:image/png;base64,iVBOR"));
        // Caption surfaces as both alt and figcaption.
        assert!(html.contains("<figcaption>Login bypass</figcaption>"));
        // Still self-contained (no external image refs).
        assert!(!html.contains("src=\"http"));
    }
}
