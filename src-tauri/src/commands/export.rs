//! Export commands. Currently PDF only (via Typst).

use tauri::State;

use crate::db;
use crate::error::AppResult;
use crate::render::{content_model, typst_pdf::PdfRenderer, Renderer};
use crate::state::AppState;

/// Render a report (with its findings) to PDF bytes. The frontend saves them to
/// disk via the dialog + fs plugins.
#[tauri::command]
pub fn export_pdf(state: State<'_, AppState>, report_id: String) -> AppResult<Vec<u8>> {
    let (report, findings) = state.with_conn(|conn| {
        let report = db::reports::get(conn, &report_id)?;
        let findings = db::findings::list(conn, &report_id)?;
        Ok((report, findings))
    })?;

    let doc = content_model::build_document(&report, findings);
    PdfRenderer.render(doc)
}
