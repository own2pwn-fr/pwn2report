//! Self-contained HTML renderer.
//!
//! Pure projection of the [`ReportDocument`] IR to a single standalone HTML
//! document (no I/O, no external references — all CSS inlined in a `<style>`
//! tag). own2pwn-styled: dark theme, violet accent, Inter / JetBrains Mono
//! font-family stacks, per-severity color chips. All user-supplied content is
//! HTML-escaped before insertion.

use base64::Engine as _;
use pulldown_cmark::{html as cmark_html, Event, Options, Parser};

use super::content_model::{FindingInput, ReportDocument};
use super::labels::Labels;

/// Render authored Markdown prose to a safe HTML fragment.
///
/// The IR's prose fields are authored Markdown (the same raw text the Markdown
/// renderer emits verbatim). For HTML we parse them with pulldown-cmark so bold,
/// lists, links, inline code, etc. become real HTML elements — but we **drop**
/// any raw `Html` / `InlineHtml` events first, so attacker-influenceable prose
/// can never inject raw markup (e.g. a `<script>` typed into a finding). The
/// parser still HTML-escapes text content of the Markdown it does emit.
fn md_to_html(md: &str) -> String {
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_TABLES);
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    // Filter out raw HTML so inline/blocks of HTML in prose are not passed
    // through (defense in depth — the source is attacker-influenceable).
    let events =
        Parser::new_ext(md, opts).filter(|ev| !matches!(ev, Event::Html(_) | Event::InlineHtml(_)));
    let mut html = String::new();
    cmark_html::push_html(&mut html, events);
    html
}

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
dl.cvss {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 0.15rem 0.75rem;
  margin: 0.5rem 0 0.75rem;
  font-size: 0.85rem;
}
dl.cvss dt { color: #9b9ba3; }
dl.cvss dd { margin: 0; color: #e5e5ea; font-weight: 600; }
@media print {
  :root { color-scheme: light; }
  body { background: #fff; color: #000; }
  h1, h3 { color: #000; }
  h2 { color: #000; border-bottom-color: #000; }
  a { color: #000; }
  .meta, .meta strong, .loc, dl.cvss dt, dl.cvss dd,
  figure.evidence-img figcaption, code { color: #000; }
  .facet-label { color: #000; }
  th { background: #eee; color: #000; }
  tr.total td { background: #eee; }
  pre { background: #f5f5f5; color: #000; border-color: #999; }
  .tag { background: #eee; color: #000; }
  table, th, td, .finding, figure.evidence-img img { border-color: #999; }
}
"#;

/// Render the full report to a self-contained HTML document string.
pub fn to_html(doc: &ReportDocument) -> String {
    let l = &doc.labels;
    let lang = if doc.lang.is_empty() { "en" } else { &doc.lang };
    let mut out = String::new();
    out.push_str(&format!(
        "<!DOCTYPE html>\n<html lang=\"{}\">\n<head>\n",
        esc(lang)
    ));
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
        meta.push(format!(
            "<strong>{}:</strong> {}",
            esc(l.client),
            esc(&doc.client)
        ));
    }
    if !doc.report_type.is_empty() {
        meta.push(format!(
            "<strong>{}:</strong> {}",
            esc(l.report_type),
            esc(&doc.report_type)
        ));
    }
    if !doc.status.is_empty() {
        meta.push(format!(
            "<strong>{}:</strong> {}",
            esc(l.status),
            esc(&doc.status)
        ));
    }
    if !doc.date.is_empty() {
        meta.push(format!(
            "<strong>{}:</strong> {}",
            esc(l.date),
            esc(&doc.date)
        ));
    }
    if !meta.is_empty() {
        out.push_str(&format!(
            "<div class=\"meta\">{}</div>\n",
            meta.join(" &middot; ")
        ));
    }

    if !doc.exec_summary.is_empty() {
        out.push_str(&format!("<h2>{}</h2>\n", esc(l.executive_summary)));
        para(&mut out, &doc.exec_summary);
    }

    // Severity summary table.
    out.push_str(&format!("<h2>{}</h2>\n<table>\n", esc(l.findings_overview)));
    out.push_str(&format!(
        "<tr><th>{}</th><th>{}</th></tr>\n",
        esc(l.severity),
        esc(l.count)
    ));
    for (sev, label, n) in [
        ("critical", l.critical, doc.summary.critical),
        ("high", l.high, doc.summary.high),
        ("medium", l.medium, doc.summary.medium),
        ("low", l.low, doc.summary.low),
        ("info", l.info, doc.summary.info),
    ] {
        out.push_str(&format!(
            "<tr><td>{}</td><td>{}</td></tr>\n",
            chip(sev, label),
            n
        ));
    }
    out.push_str(&format!(
        "<tr class=\"total\"><td>{}</td><td>{}</td></tr>\n</table>\n",
        esc(l.total),
        doc.summary.total
    ));

    if !doc.scope.is_empty() {
        out.push_str(&format!("<h2>{}</h2>\n", esc(l.scope)));
        para(&mut out, &doc.scope);
    }
    if !doc.methodology.is_empty() {
        out.push_str(&format!("<h2>{}</h2>\n", esc(l.methodology)));
        para(&mut out, &doc.methodology);
    }

    if !doc.findings.is_empty() {
        out.push_str(&format!("<h2>{}</h2>\n", esc(l.detailed_findings)));
        for (i, f) in doc.findings.iter().enumerate() {
            push_finding(&mut out, i + 1, f, l);
        }
    } else {
        out.push_str(&format!("<p class=\"empty\">{}</p>\n", esc(l.no_findings)));
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

fn push_finding(out: &mut String, n: usize, f: &FindingInput, l: &Labels) {
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
        meta.push(format!("{} {}", esc(l.cvss), esc(&f.cvss_score)));
    }
    if !f.confidence.is_empty() {
        meta.push(format!(
            "{}: {}",
            esc(&l.confidence.to_lowercase()),
            esc(&f.confidence)
        ));
    }
    if !f.kind.is_empty() {
        meta.push(esc(&f.kind));
    }
    if !meta.is_empty() {
        out.push_str(&format!(
            "<div class=\"meta\">{}</div>\n",
            meta.join(" &middot; ")
        ));
    }
    // CVSS: prefer the decoded metric grid; fall back to the raw vector string.
    if !f.cvss_metrics.is_empty() {
        out.push_str("<dl class=\"cvss\">\n");
        for m in &f.cvss_metrics {
            out.push_str(&format!(
                "<dt>{}</dt><dd>{}</dd>\n",
                esc(&m.label),
                esc(&m.value)
            ));
        }
        out.push_str("</dl>\n");
    } else if !f.cvss_vector.is_empty() {
        out.push_str(&format!(
            "<div class=\"meta\"><code>{}</code></div>\n",
            esc(&f.cvss_vector)
        ));
    }

    facet(out, l.summary, &f.summary);
    facet(out, l.root_cause, &f.root_cause);
    facet(out, l.attack_vector, &f.attack_vector);
    facet(out, l.business_impact, &f.business_impact);
    facet(out, l.technical_details, &f.technical_details);

    // Evidence.
    if f.has_evidence {
        out.push_str(&format!(
            "<div class=\"facet-label\">{}</div>\n",
            esc(l.evidence)
        ));
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
            out.push_str(&format!(
                "<div class=\"meta loc\"><code>{}</code></div>\n",
                esc(&loc)
            ));
        }
        code_block(out, &f.evidence_snippet);
    }

    // Proof of Concept.
    if f.has_poc {
        out.push_str(&format!(
            "<div class=\"facet-label\">{}</div>\n",
            esc(l.proof_of_concept)
        ));
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
        out.push_str(&format!(
            "<div class=\"facet-label\">{}</div>\n",
            esc(l.screenshots)
        ));
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
            out.push_str(&format!(
                "<div class=\"facet-label\">{}</div>\n",
                esc(l.remediation)
            ));
            para(out, &f.fix);
        }
        code_block(out, &f.code_patch);
        if !f.remediation_refs.is_empty() {
            out.push_str(&format!(
                "<div class=\"facet-label\">{}</div>\n<ul>\n",
                esc(l.references)
            ));
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
        out.push_str(&format!(
            "<div class=\"facet-label\">{}</div>\n",
            esc(label)
        ));
        para(out, body);
    }
}

/// Emit a prose block, rendering its Markdown to sanitized HTML.
fn para(out: &mut String, body: &str) {
    out.push_str(&md_to_html(body));
    out.push('\n');
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
    fn prose_markdown_renders_and_raw_html_is_dropped() {
        let mut finding = sample_finding();
        // Markdown + an embedded raw <script> that must NOT survive.
        finding.description.summary = "Be **careful** here.<script>alert(1)</script>".to_string();
        let doc = build_document(&sample_report(), vec![finding], &HashMap::new());
        let html = to_html(&doc);
        assert!(
            html.contains("<strong>careful</strong>"),
            "bold should render"
        );
        // Raw inline HTML from prose is dropped (not passed through, not escaped
        // into a literal tag either — the element simply does not appear).
        assert!(
            !html.contains("<script>alert(1)"),
            "raw html must be dropped"
        );
    }

    #[test]
    fn print_media_block_present() {
        let doc = build_document(&sample_report(), vec![sample_finding()], &HashMap::new());
        let html = to_html(&doc);
        assert!(html.contains("@media print"), "print stylesheet missing");
    }

    #[test]
    fn cvss_vector_decoded_into_grid() {
        let doc = build_document(&sample_report(), vec![sample_finding()], &HashMap::new());
        let html = to_html(&doc);
        // The sample finding's v3.1 vector decodes to a labelled grid.
        assert!(html.contains("<dl class=\"cvss\">"), "cvss grid missing");
        assert!(html.contains("<dt>Attack vector</dt><dd>Network</dd>"));
        // The raw vector string should no longer be shown when decoded.
        assert!(
            !html.contains("CVSS:3.1/AV:N"),
            "raw vector should be replaced"
        );
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
