//! Scanner-import command: parse a tool's report text and bulk-insert the
//! resulting findings into a report.

use tauri::State;

use crate::db;
use crate::error::AppResult;
use crate::import;
use crate::state::AppState;

/// Parse `content` as `format` (`sarif` | `nuclei` | `zap` | `burp` | `nessus`
/// | `secai`) and append the resulting findings to `report_id`. Returns the
/// number of findings inserted. The frontend reads the file and passes its text.
#[tauri::command]
pub fn import_findings(
    state: State<'_, AppState>,
    report_id: String,
    format: String,
    content: String,
) -> AppResult<usize> {
    let findings = import::parse(&format, &content)?;
    state.with_conn_mut(|conn| db::findings::create_bulk(conn, &report_id, findings))
}
