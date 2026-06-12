//! Rendering subsystem.
//!
//! A `Renderer` trait abstracts output formats so MD / HTML / DOCX can be
//! added later; only the Typst-backed PDF renderer exists today.

pub mod content_model;
pub mod typst_pdf;

use crate::error::AppResult;
use content_model::ReportDocument;

/// A report renderer producing bytes for a single output format.
pub trait Renderer {
    /// Render the document IR into a byte buffer (e.g. PDF bytes).
    fn render(&self, doc: ReportDocument) -> AppResult<Vec<u8>>;
}
