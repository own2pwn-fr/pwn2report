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
