//! Rendering subsystem.
//!
//! A `Renderer` trait abstracts output formats so MD / HTML / DOCX can be
//! added later; only the Typst-backed PDF renderer exists today.

pub mod content_model;
pub mod docx;
pub mod html;
pub mod markdown;
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
            let doc = build_document(&sample_report(), vec![sample_finding()], &HashMap::new());
            let pdf = PdfRenderer::bundled(slug)
                .render(doc)
                .unwrap_or_else(|e| panic!("theme {slug} failed to compile: {e:?}"));
            assert!(pdf.starts_with(b"%PDF"), "{slug}: output is not a PDF");
            assert!(pdf.len() > 1000, "{slug}: PDF suspiciously small ({} bytes)", pdf.len());
        }
    }

    #[test]
    fn markdown_and_html_render_finding_content() {
        let doc = build_document(&sample_report(), vec![sample_finding()], &HashMap::new());
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
        if std::process::Command::new("pandoc").arg("--version").output().is_err() {
            eprintln!("pandoc not found on PATH; skipping docx render test");
            return;
        }
        let doc = build_document(&sample_report(), vec![sample_finding()], &HashMap::new());
        let bytes = to_docx(&doc).expect("docx render failed");
        assert!(bytes.starts_with(b"PK"), "docx must be a zip (PK header)");
        assert!(bytes.len() > 1000, "docx suspiciously small ({} bytes)", bytes.len());
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
            vec![("screenshot".to_string(), "image/png".to_string(), tiny_png())],
        );
        for slug in ["web_pentest", "code_audit", "red_team"] {
            let doc = build_document(&sample_report(), vec![sample_finding()], &images);
            let pdf = PdfRenderer::bundled(slug)
                .render(doc)
                .unwrap_or_else(|e| panic!("theme {slug} with image failed: {e:?}"));
            assert!(pdf.starts_with(b"%PDF"), "{slug}: output is not a PDF");
        }
    }

    #[test]
    fn html_embeds_image_as_data_uri() {
        let mut images = HashMap::new();
        images.insert(
            "f1".to_string(),
            vec![("screenshot".to_string(), "image/png".to_string(), tiny_png())],
        );
        let doc = build_document(&sample_report(), vec![sample_finding()], &images);
        let html = to_html(&doc);
        assert!(html.contains("data:image/png;base64,"), "html must inline the image");
    }
}
