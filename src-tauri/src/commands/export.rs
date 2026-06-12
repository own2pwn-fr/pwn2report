//! Export commands: PDF (Typst), Markdown, HTML, DOCX (pandoc).
//!
//! All renderers consume the same `ReportDocument` IR built from the report +
//! its findings (sorted severity-desc then sort_order by `build_document`).

use tauri::{AppHandle, State};

use super::templates::resolve_template_source;
use crate::db;
use crate::error::AppResult;
use crate::render::{content_model, docx, html, markdown, typst_pdf::PdfRenderer, Renderer};
use crate::state::AppState;

/// Build the `ReportDocument` IR for a report id (fetch + project).
fn build_doc(state: &AppState, report_id: &str) -> AppResult<content_model::ReportDocument> {
    let (report, findings) = state.with_conn(|conn| {
        let report = db::reports::get(conn, report_id)?;
        let findings = db::findings::list(conn, report_id)?;
        Ok((report, findings))
    })?;
    Ok(content_model::build_document(&report, findings))
}

/// Render a report (with its findings) to PDF bytes. Uses the custom Typst
/// template for the report's type if one exists in the config dir, else the
/// bundled theme. The frontend saves the bytes to disk via the dialog/fs
/// plugins.
#[tauri::command]
pub fn export_pdf(
    app: AppHandle,
    state: State<'_, AppState>,
    report_id: String,
) -> AppResult<Vec<u8>> {
    let doc = build_doc(&state, &report_id)?;
    let source = resolve_template_source(&app, &doc.report_type_slug)?;
    PdfRenderer::new(source).render(doc)
}

/// Render a report to a GitHub-flavored Markdown string.
#[tauri::command]
pub fn export_markdown(state: State<'_, AppState>, report_id: String) -> AppResult<String> {
    let doc = build_doc(&state, &report_id)?;
    Ok(markdown::to_markdown(&doc))
}

/// Render a report to a self-contained HTML document string.
#[tauri::command]
pub fn export_html(state: State<'_, AppState>, report_id: String) -> AppResult<String> {
    let doc = build_doc(&state, &report_id)?;
    Ok(html::to_html(&doc))
}

/// Render a report to DOCX bytes (markdown piped through pandoc).
#[tauri::command]
pub fn export_docx(state: State<'_, AppState>, report_id: String) -> AppResult<Vec<u8>> {
    let doc = build_doc(&state, &report_id)?;
    docx::to_docx(&doc)
}
