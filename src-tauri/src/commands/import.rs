//! Scanner-import command: parse a tool's report text and bulk-insert the
//! resulting findings into a report.

use serde::Serialize;
use tauri::State;

use crate::db;
use crate::error::{AppError, AppResult};
use crate::import;
use crate::state::AppState;

/// Upper bound on the imported report text (bytes). Scanner exports are usually
/// well under this; a larger payload is rejected up front to bound memory/CPU
/// (DoS guard) before any (potentially expensive) XML/JSON parsing happens.
const MAX_IMPORT_BYTES: usize = 64 * 1024 * 1024;

/// Outcome of an import, surfaced to the frontend.
///
/// - `imported`: findings actually inserted into the report.
/// - `skipped`: malformed/incomplete records the parser dropped (one per
///   [`warnings`](Self::warnings) entry).
/// - `deduped`: findings dropped because an identical finding (same
///   fingerprint) already existed in the report or earlier in this batch.
/// - `warnings`: human-readable per-record notes (e.g. "line 42: skipped …").
#[derive(Debug, Serialize)]
pub struct ImportReport {
    pub imported: usize,
    pub skipped: usize,
    pub deduped: usize,
    pub warnings: Vec<String>,
}

/// Parse `content` as `format` (`sarif` | `nuclei` | `zap` | `burp` | `nessus`
/// | `secai` | `csv`) and append the resulting findings to `report_id`.
///
/// Parsing is per-record fault-tolerant: a single bad record is skipped (and
/// reported in `warnings`/`skipped`) rather than failing the whole file. Exact
/// duplicates (by content fingerprint) — both within the file and against
/// findings already in the report — are dropped and counted in `deduped`. The
/// frontend reads the file and passes its text.
#[tauri::command]
pub fn import_findings(
    state: State<'_, AppState>,
    report_id: String,
    format: String,
    content: String,
) -> AppResult<ImportReport> {
    if content.len() > MAX_IMPORT_BYTES {
        return Err(AppError::Import(format!(
            "import is too large ({} bytes); the maximum is {} bytes ({} MB)",
            content.len(),
            MAX_IMPORT_BYTES,
            MAX_IMPORT_BYTES / (1024 * 1024)
        )));
    }
    let outcome = import::parse(&format, &content)?;
    let skipped = outcome.warnings.len();
    let warnings = outcome.warnings;
    let (imported, deduped) = state.with_conn_mut(|conn| {
        db::findings::create_bulk_dedup(conn, &report_id, outcome.findings)
    })?;
    Ok(ImportReport {
        imported,
        skipped,
        deduped,
        warnings,
    })
}
