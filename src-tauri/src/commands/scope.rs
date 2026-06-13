//! Structured scope-item commands: list / create / update / delete / reorder
//! per report.

use tauri::State;

use crate::db;
use crate::error::AppResult;
use crate::models::{NewScopeItem, ScopeItem, ScopeItemPatch};
use crate::state::AppState;

#[tauri::command]
pub fn list_scope_items(
    state: State<'_, AppState>,
    report_id: String,
) -> AppResult<Vec<ScopeItem>> {
    state.with_conn(|conn| db::scope::list(conn, &report_id))
}

#[tauri::command]
pub fn create_scope_item(
    state: State<'_, AppState>,
    report_id: String,
    input: NewScopeItem,
) -> AppResult<ScopeItem> {
    state.with_conn(|conn| db::scope::create(conn, &report_id, input))
}

#[tauri::command]
pub fn update_scope_item(
    state: State<'_, AppState>,
    id: String,
    patch: ScopeItemPatch,
) -> AppResult<ScopeItem> {
    state.with_conn(|conn| db::scope::update(conn, &id, patch))
}

#[tauri::command]
pub fn delete_scope_item(state: State<'_, AppState>, id: String) -> AppResult<()> {
    state.with_conn(|conn| db::scope::delete(conn, &id))
}

#[tauri::command]
pub fn reorder_scope_items(
    state: State<'_, AppState>,
    report_id: String,
    ordered_ids: Vec<String>,
) -> AppResult<()> {
    state.with_conn_mut(|conn| db::scope::reorder(conn, &report_id, &ordered_ids))
}
