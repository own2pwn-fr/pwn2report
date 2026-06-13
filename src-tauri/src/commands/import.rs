//! Scanner-import command: parse a tool's report text and bulk-insert the
//! resulting findings into a report.

use tauri::State;

use crate::db;
use crate::error::{AppError, AppResult};
use crate::import;
use crate::state::AppState;

/// Upper bound on the imported report text (bytes). Scanner exports are usually
/// well under this; a larger payload is rejected up front to bound memory/CPU
/// (DoS guard) before any (potentially expensive) XML/JSON parsing happens.
const MAX_IMPORT_BYTES: usize = 64 * 1024 * 1024;

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
    if content.len() > MAX_IMPORT_BYTES {
        return Err(AppError::Import(format!(
            "import is too large ({} bytes); the maximum is {} bytes ({} MB)",
            content.len(),
            MAX_IMPORT_BYTES,
            MAX_IMPORT_BYTES / (1024 * 1024)
        )));
    }
    let findings = import::parse(&format, &content)?;
    state.with_conn_mut(|conn| db::findings::create_bulk(conn, &report_id, findings))
}
