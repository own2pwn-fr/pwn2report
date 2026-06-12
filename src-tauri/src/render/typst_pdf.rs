//! Typst-backed PDF renderer.
//!
//! Fonts and the `.typ` template sources are embedded at compile time via
//! `include_bytes!` / `include_str!`. The template (`web_pentest.typ`) imports
//! a shared `lib/common.typ`; both are registered with the engine's static
//! source resolver so the `#import` resolves in-memory (no filesystem at
//! runtime). `web_pentest.typ` is the main file and reads its data from
//! `#import sys: inputs`.

use typst_as_lib::TypstEngine;

use super::content_model::ReportDocument;
use super::Renderer;
use crate::error::{AppError, AppResult};

// Embedded fonts (paths relative to this source file).
static FONT_INTER: &[u8] = include_bytes!("../../resources/fonts/Inter-Regular.ttf");
static FONT_INTER_BOLD: &[u8] = include_bytes!("../../resources/fonts/Inter-Bold.ttf");
static FONT_INTER_SEMIBOLD: &[u8] = include_bytes!("../../resources/fonts/Inter-SemiBold.ttf");
static FONT_JBM: &[u8] = include_bytes!("../../resources/fonts/JetBrainsMono-Regular.ttf");
static FONT_JBM_BOLD: &[u8] = include_bytes!("../../resources/fonts/JetBrainsMono-Bold.ttf");

// Embedded template sources.
static THEME: &str = include_str!("../../resources/typst/themes/web_pentest.typ");
static COMMON: &str = include_str!("../../resources/typst/lib/common.typ");

/// PDF renderer using the embedded Typst template + fonts.
pub struct PdfRenderer;

impl Renderer for PdfRenderer {
    fn render(&self, doc: ReportDocument) -> AppResult<Vec<u8>> {
        // The theme imports "lib/common.typ" relative to itself; register it
        // under that virtual path so the resolver finds it in-memory.
        let engine = TypstEngine::builder()
            .main_file(THEME)
            .with_static_source_file_resolver([("lib/common.typ", COMMON)])
            .fonts([
                FONT_INTER,
                FONT_INTER_BOLD,
                FONT_INTER_SEMIBOLD,
                FONT_JBM,
                FONT_JBM_BOLD,
            ])
            .build();

        let document = engine
            .compile_with_input(doc)
            .output
            .map_err(|e| AppError::Render(format!("typst compile failed: {e:?}")))?;

        let pdf = typst_pdf::pdf(&document, &Default::default())
            .map_err(|e| AppError::Render(format!("pdf generation failed: {e:?}")))?;

        Ok(pdf)
    }
}
