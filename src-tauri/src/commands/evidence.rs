//! Evidence-image commands: attach / list / fetch-bytes / caption / delete /
//! reorder per-finding images. Image bytes are stored in the encrypted vault;
//! only metadata crosses the IPC boundary except for `get_evidence_image`,
//! which returns the raw bytes (the frontend builds an object URL from them).

use tauri::State;

use crate::db;
use crate::error::AppResult;
use crate::models::EvidenceImage;
use crate::state::AppState;

#[tauri::command]
pub fn add_evidence_image(
    state: State<'_, AppState>,
    finding_id: String,
    caption: String,
    mime: String,
    data: Vec<u8>,
) -> AppResult<EvidenceImage> {
    state.with_conn(|conn| db::evidence::add(conn, &finding_id, &caption, &mime, &data))
}

#[tauri::command]
pub fn list_evidence_images(
    state: State<'_, AppState>,
    finding_id: String,
) -> AppResult<Vec<EvidenceImage>> {
    state.with_conn(|conn| db::evidence::list(conn, &finding_id))
}

/// Return the raw image bytes for an id (the MIME is already known to the
/// frontend from `list_evidence_images`).
#[tauri::command]
pub fn get_evidence_image(state: State<'_, AppState>, id: String) -> AppResult<Vec<u8>> {
    state.with_conn(|conn| db::evidence::get_data(conn, &id).map(|(_mime, data)| data))
}

#[tauri::command]
pub fn update_evidence_caption(
    state: State<'_, AppState>,
    id: String,
    caption: String,
) -> AppResult<EvidenceImage> {
    state.with_conn(|conn| db::evidence::update_caption(conn, &id, &caption))
}

#[tauri::command]
pub fn delete_evidence_image(state: State<'_, AppState>, id: String) -> AppResult<()> {
    state.with_conn(|conn| db::evidence::delete(conn, &id))
}

#[tauri::command]
pub fn reorder_evidence_images(
    state: State<'_, AppState>,
    finding_id: String,
    ordered_ids: Vec<String>,
) -> AppResult<()> {
    state.with_conn_mut(|conn| db::evidence::reorder(conn, &finding_id, &ordered_ids))
}
