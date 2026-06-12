//! Finding CRUD + reorder commands.

use tauri::State;

use crate::db;
use crate::error::AppResult;
use crate::models::{Finding, FindingPatch, NewFinding};
use crate::state::AppState;

#[tauri::command]
pub fn list_findings(state: State<'_, AppState>, report_id: String) -> AppResult<Vec<Finding>> {
    state.with_conn(|conn| db::findings::list(conn, &report_id))
}

#[tauri::command]
pub fn create_finding(
    state: State<'_, AppState>,
    report_id: String,
    input: NewFinding,
) -> AppResult<Finding> {
    state.with_conn(|conn| db::findings::create(conn, &report_id, input))
}

#[tauri::command]
pub fn update_finding(
    state: State<'_, AppState>,
    id: String,
    patch: FindingPatch,
) -> AppResult<Finding> {
    state.with_conn(|conn| db::findings::update(conn, &id, patch))
}

#[tauri::command]
pub fn delete_finding(state: State<'_, AppState>, id: String) -> AppResult<()> {
    state.with_conn(|conn| db::findings::delete(conn, &id))
}

#[tauri::command]
pub fn reorder_findings(
    state: State<'_, AppState>,
    report_id: String,
    ordered_ids: Vec<String>,
) -> AppResult<()> {
    state.with_conn_mut(|conn| db::findings::reorder(conn, &report_id, &ordered_ids))
}
