//! Report CRUD commands.

use tauri::State;

use crate::db;
use crate::error::AppResult;
use crate::models::{NewReport, Report, ReportPatch, ReportSummary};
use crate::state::AppState;

#[tauri::command]
pub fn list_reports(state: State<'_, AppState>) -> AppResult<Vec<ReportSummary>> {
    state.with_conn(db::reports::list)
}

#[tauri::command]
pub fn create_report(state: State<'_, AppState>, input: NewReport) -> AppResult<Report> {
    state.with_conn(|conn| db::reports::create(conn, input))
}

#[tauri::command]
pub fn get_report(state: State<'_, AppState>, id: String) -> AppResult<Report> {
    state.with_conn(|conn| db::reports::get(conn, &id))
}

#[tauri::command]
pub fn update_report(
    state: State<'_, AppState>,
    id: String,
    patch: ReportPatch,
) -> AppResult<Report> {
    state.with_conn(|conn| db::reports::update(conn, &id, patch))
}

#[tauri::command]
pub fn delete_report(state: State<'_, AppState>, id: String) -> AppResult<()> {
    state.with_conn(|conn| db::reports::delete(conn, &id))
}

/// Set (or replace) a report's branding logo. `data` is the raw image bytes,
/// `mime` its content type ("image/png", …).
#[tauri::command]
pub fn set_report_logo(
    state: State<'_, AppState>,
    report_id: String,
    mime: String,
    data: Vec<u8>,
) -> AppResult<()> {
    state.with_conn(|conn| db::reports::set_logo(conn, &report_id, &mime, &data))
}

/// Return a report's logo bytes, or an empty vec when no logo is set. (The MIME
/// is exposed via the report's `has_logo` flag + a separate fetch if needed; the
/// frontend builds an object URL from these bytes.)
#[tauri::command]
pub fn get_report_logo(state: State<'_, AppState>, report_id: String) -> AppResult<Vec<u8>> {
    state.with_conn(|conn| {
        Ok(db::reports::get_logo(conn, &report_id)?
            .map(|(_mime, data)| data)
            .unwrap_or_default())
    })
}

/// Clear a report's branding logo.
#[tauri::command]
pub fn clear_report_logo(state: State<'_, AppState>, report_id: String) -> AppResult<()> {
    state.with_conn(|conn| db::reports::clear_logo(conn, &report_id))
}
