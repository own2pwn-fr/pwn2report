//! Knowledge-base commands: CRUD over reusable finding templates, bundled
//! catalog import, and materialising an entry into a report finding.

use tauri::State;

use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{Finding, KbEntry, KbEntryPatch, NewKbEntry};
use crate::state::AppState;

/// The bundled catalog of common web/app vulnerability templates, embedded at
/// compile time. Imported on demand via [`kb_import_bundled`].
static BUNDLED_CATALOG: &str = include_str!("../../resources/kb/catalog.json");

#[tauri::command]
pub fn kb_list(state: State<'_, AppState>) -> AppResult<Vec<KbEntry>> {
    state.with_conn(db::kb::list)
}

#[tauri::command]
pub fn kb_get(state: State<'_, AppState>, id: String) -> AppResult<KbEntry> {
    state.with_conn(|conn| db::kb::get(conn, &id))
}

#[tauri::command]
pub fn kb_create(state: State<'_, AppState>, input: NewKbEntry) -> AppResult<KbEntry> {
    state.with_conn(|conn| db::kb::create(conn, input))
}

#[tauri::command]
pub fn kb_update(
    state: State<'_, AppState>,
    id: String,
    patch: KbEntryPatch,
) -> AppResult<KbEntry> {
    state.with_conn(|conn| db::kb::update(conn, &id, patch))
}

#[tauri::command]
pub fn kb_delete(state: State<'_, AppState>, id: String) -> AppResult<()> {
    state.with_conn(|conn| db::kb::delete(conn, &id))
}

/// Insert bundled-catalog entries whose title isn't already present in the KB.
/// Returns the number of entries inserted (0 if all already present).
#[tauri::command]
pub fn kb_import_bundled(state: State<'_, AppState>) -> AppResult<usize> {
    let entries: Vec<NewKbEntry> = serde_json::from_str(BUNDLED_CATALOG)
        .map_err(|e| AppError::Serialization(format!("bundled KB catalog is invalid: {e}")))?;

    state.with_conn(|conn| {
        let mut inserted = 0;
        for entry in entries {
            if !db::kb::title_exists(conn, &entry.title)? {
                db::kb::create(conn, entry)?;
                inserted += 1;
            }
        }
        Ok(inserted)
    })
}

/// Materialise a KB entry into a new finding under `report_id`. Copies the
/// template fields (title/severity/confidence/kind/cwe/cve/cvss/description/
/// remediation/tags); evidence and poc start empty and triage defaults to open.
#[tauri::command]
pub fn create_finding_from_kb(
    state: State<'_, AppState>,
    report_id: String,
    kb_id: String,
) -> AppResult<Finding> {
    state.with_conn(|conn| {
        let entry = db::kb::get(conn, &kb_id)?;
        let new_finding = db::kb::to_new_finding(&entry);
        db::findings::create(conn, &report_id, new_finding)
    })
}
