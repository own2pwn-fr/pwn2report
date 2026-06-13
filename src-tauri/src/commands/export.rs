//! Export commands: PDF (Typst), Markdown, HTML, DOCX (pandoc).
//!
//! All renderers consume the same `ReportDocument` IR built from the report +
//! its findings (sorted severity-desc then sort_order by `build_document`).

use std::collections::HashMap;

use tauri::{AppHandle, State};

use super::templates::resolve_template_source;
use crate::db;
use crate::error::AppResult;
use crate::render::content_model::ImageSource;
use crate::render::{
    content_model, csv, docx, html, markdown, sarif, typst_pdf::PdfRenderer, Renderer,
};
use crate::state::AppState;

/// Build the `ReportDocument` IR for a report id (fetch report + findings +
/// each finding's evidence images, then project). Image bytes are read from the
/// encrypted vault here so the renderers stay pure.
fn build_doc(state: &AppState, report_id: &str) -> AppResult<content_model::ReportDocument> {
    use crate::models::Asset;

    let (report, findings, images, scope_items, finding_assets, logo) =
        state.with_conn(|conn| {
            let report = db::reports::get(conn, report_id)?;
            let findings = db::findings::list(conn, report_id)?;

            // For each finding, fetch its ordered images and their raw bytes, plus
            // its affected assets (the resolved finding↔asset link set).
            let mut images: HashMap<String, Vec<ImageSource>> = HashMap::new();
            let mut finding_assets: HashMap<String, Vec<Asset>> = HashMap::new();
            for f in &findings {
                let metas = db::evidence::list(conn, &f.id)?;
                if !metas.is_empty() {
                    let mut sources = Vec::with_capacity(metas.len());
                    for m in metas {
                        let (mime, data) = db::evidence::get_data(conn, &m.id)?;
                        sources.push((m.caption, mime, data));
                    }
                    images.insert(f.id.clone(), sources);
                }
                let assets = db::findings::list_finding_assets(conn, &f.id)?;
                if !assets.is_empty() {
                    finding_assets.insert(f.id.clone(), assets);
                }
            }

            let scope_items = db::scope::list(conn, report_id)?;
            let logo = db::reports::get_logo(conn, report_id)?;

            Ok((report, findings, images, scope_items, finding_assets, logo))
        })?;
    Ok(content_model::build_document(
        &report,
        findings,
        &images,
        &scope_items,
        &finding_assets,
        logo.as_ref(),
    ))
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

/// Export a report's findings as a CSV string (one row per finding).
#[tauri::command]
pub fn export_csv(state: State<'_, AppState>, report_id: String) -> AppResult<String> {
    let doc = build_doc(&state, &report_id)?;
    Ok(csv::to_csv(&doc))
}

/// Export a report's findings as a minimal SARIF 2.1.0 document string.
#[tauri::command]
pub fn export_sarif(state: State<'_, AppState>, report_id: String) -> AppResult<String> {
    let doc = build_doc(&state, &report_id)?;
    Ok(sarif::to_sarif(&doc))
}
