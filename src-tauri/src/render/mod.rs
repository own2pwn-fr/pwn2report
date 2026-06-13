//! Rendering subsystem.
//!
//! A `Renderer` trait abstracts output formats so MD / HTML / DOCX can be
//! added later; only the Typst-backed PDF renderer exists today.

pub mod content_model;
pub mod cvss;
pub mod docx;
pub mod html;
pub mod labels;
pub mod markdown;
pub mod markup;
pub mod typst_pdf;

use crate::error::AppResult;
use content_model::ReportDocument;

/// A report renderer producing bytes for a single output format.
pub trait Renderer {
    /// Render the document IR into a byte buffer (e.g. PDF bytes).
    fn render(&self, doc: ReportDocument) -> AppResult<Vec<u8>>;
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::Renderer;
    use crate::render::content_model::build_document;
    use crate::render::typst_pdf::PdfRenderer;
    use crate::render::{html::to_html, markdown::to_markdown};
    use crate::test_fixtures::{sample_finding, sample_report};

    /// Every shipped Typst theme must compile a representative report to PDF.
    #[test]
    fn all_bundled_themes_compile_to_pdf() {
        for slug in ["web_pentest", "code_audit", "red_team"] {
            let doc = build_document(
                &sample_report(),
                vec![sample_finding()],
                &HashMap::new(),
                &[],
                &HashMap::new(),
                None,
            );
            let pdf = PdfRenderer::bundled(slug)
                .render(doc)
                .unwrap_or_else(|e| panic!("theme {slug} failed to compile: {e:?}"));
            assert!(pdf.starts_with(b"%PDF"), "{slug}: output is not a PDF");
            assert!(
                pdf.len() > 1000,
                "{slug}: PDF suspiciously small ({} bytes)",
                pdf.len()
            );
        }
    }

    #[test]
    fn markdown_and_html_render_finding_content() {
        let doc = build_document(
            &sample_report(),
            vec![sample_finding()],
            &HashMap::new(),
            &[],
            &HashMap::new(),
            None,
        );
        let md = to_markdown(&doc);
        assert!(md.contains("Test Report") && md.contains("SQL Injection"));
        let html = to_html(&doc);
        assert!(html.contains("<!DOCTYPE") || html.contains("<html"));
        assert!(html.contains("SQL Injection"));
    }

    /// Exercises the real pandoc pipeline (embedded reference.docx + stdin md).
    /// Skips gracefully where pandoc isn't installed (e.g. minimal CI).
    #[test]
    fn docx_renders_when_pandoc_available() {
        use crate::render::docx::to_docx;
        if std::process::Command::new("pandoc")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("pandoc not found on PATH; skipping docx render test");
            return;
        }
        let doc = build_document(
            &sample_report(),
            vec![sample_finding()],
            &HashMap::new(),
            &[],
            &HashMap::new(),
            None,
        );
        let bytes = to_docx(&doc).expect("docx render failed");
        assert!(bytes.starts_with(b"PK"), "docx must be a zip (PK header)");
        assert!(
            bytes.len() > 1000,
            "docx suspiciously small ({} bytes)",
            bytes.len()
        );
    }

    /// 1x1 PNG; exercises the Typst `image(bytes)` path + HTML data-URI embedding.
    fn tiny_png() -> Vec<u8> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC")
            .unwrap()
    }

    #[test]
    fn themes_compile_with_an_embedded_image() {
        let mut images = HashMap::new();
        images.insert(
            "f1".to_string(),
            vec![(
                "screenshot".to_string(),
                "image/png".to_string(),
                tiny_png(),
            )],
        );
        for slug in ["web_pentest", "code_audit", "red_team"] {
            let doc = build_document(
                &sample_report(),
                vec![sample_finding()],
                &images,
                &[],
                &HashMap::new(),
                None,
            );
            let pdf = PdfRenderer::bundled(slug)
                .render(doc)
                .unwrap_or_else(|e| panic!("theme {slug} with image failed: {e:?}"));
            assert!(pdf.starts_with(b"%PDF"), "{slug}: output is not a PDF");
        }
    }

    /// Markdown-rich prose in the PDF path must compile through ALL themes.
    ///
    /// The Rust converter (`render/markup.rs`) turns the authored Markdown into
    /// Typst markup and the themes `eval` it; this proves that round-trip never
    /// breaks Typst compilation — including adversarial special characters that
    /// would otherwise be misread as Typst syntax.
    #[test]
    fn themes_compile_with_markdown_prose() {
        let mut finding = sample_finding();
        // Description summary: bold, inline code, a link, a list.
        finding.description.summary =
            "A **critical** flaw in `auth()` — see [OWASP](https://owasp.org).\n\n\
             - reachable pre-auth\n- no rate limiting"
                .to_string();
        // Remediation fix: heading + ordered list + code fence + special chars.
        finding.remediation.fix = "# Fix\n\n1. Use `prepared statements`\n2. Validate input\n\n\
             ```python\nq = \"SELECT 1\"  # $cost #1\n```\n\n\
             Cost estimate: $5 for a=b & c<d > e @ ~tilde \\backslash"
            .to_string();
        // PoC scenario routed through `facet`/prose in red_team — adversarial.
        finding.poc = finding.poc.map(|mut p| {
            p.scenario = "Attacker sends `' OR 1=1 --` to /login $$ #boom".to_string();
            p
        });

        // Report-level prose with Markdown too.
        let mut report = sample_report();
        report.exec_summary =
            "Overall posture is **weak**. Key risks:\n\n- SQLi\n- broken auth".to_string();
        report.scope = "In scope: `*.example.com` (see [policy](https://x/y)).".to_string();
        report.methodology = "## Approach\n\nManual + `automated` testing.".to_string();

        for slug in ["web_pentest", "code_audit", "red_team"] {
            let doc = build_document(
                &report,
                vec![finding.clone()],
                &HashMap::new(),
                &[],
                &HashMap::new(),
                None,
            );
            let pdf = PdfRenderer::bundled(slug)
                .render(doc)
                .unwrap_or_else(|e| panic!("theme {slug} failed on markdown prose: {e:?}"));
            assert!(pdf.starts_with(b"%PDF"), "{slug}: output is not a PDF");
            assert!(
                pdf.len() > 1000,
                "{slug}: PDF suspiciously small ({} bytes)",
                pdf.len()
            );
        }
    }

    /// The Markdown renderer keeps prose as RAW markdown (the Typst conversion
    /// must not leak into the shared `ReportDocument` IR); the HTML renderer now
    /// renders prose Markdown to real HTML elements (still never Typst markup).
    #[test]
    fn other_renderers_keep_raw_markdown() {
        let mut finding = sample_finding();
        finding.description.summary = "A **bold** point with `code`.\n\n- one\n- two".to_string();
        finding.remediation.fix = "Use [docs](https://x).".to_string();
        let doc = build_document(
            &sample_report(),
            vec![finding],
            &HashMap::new(),
            &[],
            &HashMap::new(),
            None,
        );

        // Markdown renderer: prose passes through verbatim (still markdown).
        let md = to_markdown(&doc);
        assert!(
            md.contains("A **bold** point with `code`."),
            "md lost raw markdown"
        );
        assert!(
            md.contains("Use [docs](https://x)."),
            "md fix lost raw markdown"
        );
        assert!(!md.contains("#link("), "md must NOT contain typst markup");

        // HTML renderer: prose Markdown becomes real HTML, never raw markdown
        // characters or Typst markup.
        let html = to_html(&doc);
        assert!(
            html.contains("<strong>bold</strong>"),
            "html should render bold as <strong>"
        );
        assert!(
            html.contains("<ul>") && html.contains("<li>"),
            "html should render lists"
        );
        assert!(
            html.contains("<a href=\"https://x\">docs</a>"),
            "html should render links as <a>"
        );
        assert!(
            !html.contains("**bold**"),
            "html must not keep raw markdown"
        );
        assert!(
            !html.contains("#link("),
            "html must NOT contain typst markup"
        );
    }

    #[test]
    fn html_embeds_image_as_data_uri() {
        let mut images = HashMap::new();
        images.insert(
            "f1".to_string(),
            vec![(
                "screenshot".to_string(),
                "image/png".to_string(),
                tiny_png(),
            )],
        );
        let doc = build_document(
            &sample_report(),
            vec![sample_finding()],
            &images,
            &[],
            &HashMap::new(),
            None,
        );
        let html = to_html(&doc);
        assert!(
            html.contains("data:image/png;base64,"),
            "html must inline the image"
        );
    }
}
