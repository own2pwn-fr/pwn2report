//! Typst-backed PDF renderer.
//!
//! Fonts and the bundled `.typ` template sources are embedded at compile time
//! via `include_bytes!` / `include_str!`. The bundled themes import a shared
//! `lib/common.typ`; it (and the chosen main file) are registered with the
//! engine's static source resolver so the `#import` resolves in-memory (no
//! filesystem at runtime). The main file reads its data from `#import sys:
//! inputs`.
//!
//! The main file is either the bundled theme for the report type (default) or a
//! user-supplied **custom** template string (resolved from the app config dir
//! by the command layer). Both forms `#import "lib/common.typ"` — that import
//! path stays stable for custom templates because `common.typ` is always
//! registered under the same virtual path.

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

// Embedded template sources (defaults).
static THEME_WEB_PENTEST: &str = include_str!("../../resources/typst/themes/web_pentest.typ");
static THEME_CODE_AUDIT: &str = include_str!("../../resources/typst/themes/code_audit.typ");
static THEME_RED_TEAM: &str = include_str!("../../resources/typst/themes/red_team.typ");
static COMMON: &str = include_str!("../../resources/typst/lib/common.typ");

/// The shared-library virtual path that ALL main files (bundled or custom)
/// `#import`. Documented at the top of each bundled theme so custom templates
/// use the exact same string.
pub const COMMON_IMPORT_PATH: &str = "lib/common.typ";

/// Return the bundled default theme source for a report-type slug.
pub fn bundled_theme(report_type_slug: &str) -> &'static str {
    match report_type_slug {
        "code_audit" => THEME_CODE_AUDIT,
        "red_team" => THEME_RED_TEAM,
        _ => THEME_WEB_PENTEST,
    }
}

/// PDF renderer using a Typst main file + the embedded fonts and shared lib.
///
/// `main_source` is the template to compile as the main file: either a bundled
/// theme (see [`bundled_theme`]) or a custom template loaded from the config
/// dir. Use [`PdfRenderer::new`] from the command layer after resolving which
/// source to use.
pub struct PdfRenderer {
    main_source: String,
}

impl PdfRenderer {
    /// Build a renderer over the given Typst main-file source.
    pub fn new(main_source: String) -> Self {
        Self { main_source }
    }

    /// Convenience: a renderer over the bundled theme for a report-type slug.
    /// Used by tests and as public API; the command path resolves custom-or-
    /// bundled source via `resolve_template_source` + [`PdfRenderer::new`].
    #[allow(dead_code)]
    pub fn bundled(report_type_slug: &str) -> Self {
        Self::new(bundled_theme(report_type_slug).to_string())
    }
}

impl Renderer for PdfRenderer {
    fn render(&self, doc: ReportDocument) -> AppResult<Vec<u8>> {
        // Register the shared lib under its stable virtual path so the main
        // file's `#import "lib/common.typ"` resolves in-memory.
        let engine = TypstEngine::builder()
            .main_file(self.main_source.as_str())
            .with_static_source_file_resolver([(COMMON_IMPORT_PATH, COMMON)])
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
