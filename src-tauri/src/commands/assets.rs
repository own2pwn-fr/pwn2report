//! Affected-asset commands: list / create / update / delete / reorder per
//! report, plus the finding↔asset link commands (set the link set for a
//! finding, list a finding's linked assets).

use tauri::State;

use crate::db;
use crate::error::AppResult;
use crate::models::{Asset, AssetPatch, NewAsset};
use crate::state::AppState;

#[tauri::command]
pub fn list_assets(state: State<'_, AppState>, report_id: String) -> AppResult<Vec<Asset>> {
    state.with_conn(|conn| db::assets::list(conn, &report_id))
}

#[tauri::command]
pub fn create_asset(
    state: State<'_, AppState>,
    report_id: String,
    input: NewAsset,
) -> AppResult<Asset> {
    state.with_conn(|conn| db::assets::create(conn, &report_id, input))
}

#[tauri::command]
pub fn update_asset(state: State<'_, AppState>, id: String, patch: AssetPatch) -> AppResult<Asset> {
    state.with_conn(|conn| db::assets::update(conn, &id, patch))
}

#[tauri::command]
pub fn delete_asset(state: State<'_, AppState>, id: String) -> AppResult<()> {
    state.with_conn(|conn| db::assets::delete(conn, &id))
}

#[tauri::command]
pub fn reorder_assets(
    state: State<'_, AppState>,
    report_id: String,
    ordered_ids: Vec<String>,
) -> AppResult<()> {
    state.with_conn_mut(|conn| db::assets::reorder(conn, &report_id, &ordered_ids))
}

/// Replace a finding's affected-asset link set with exactly `asset_ids`. Only
/// ids referencing live assets in the finding's report are linked.
#[tauri::command]
pub fn set_finding_assets(
    state: State<'_, AppState>,
    finding_id: String,
    asset_ids: Vec<String>,
) -> AppResult<()> {
    state.with_conn_mut(|conn| {
        db::findings::set_finding_assets(conn, &finding_id, &asset_ids).map(|_| ())
    })
}

/// List the live assets affected by a finding.
#[tauri::command]
pub fn list_finding_assets(
    state: State<'_, AppState>,
    finding_id: String,
) -> AppResult<Vec<Asset>> {
    state.with_conn(|conn| db::findings::list_finding_assets(conn, &finding_id))
}
