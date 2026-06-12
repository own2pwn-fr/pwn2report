//! Sync-bundle commands: export (snapshot + encrypt + write) and import
//! (read + decrypt + parse + merge). Both require an unlocked vault.

use tauri::State;

use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::sync::{self, SyncBundle, SyncSummary};

/// Snapshot the unlocked vault, encrypt it under `passphrase`, and write the age
/// bundle to `dest_path`. Rejects an empty passphrase.
#[tauri::command]
pub fn export_sync_bundle(
    state: State<'_, AppState>,
    passphrase: String,
    dest_path: String,
) -> AppResult<()> {
    if passphrase.is_empty() {
        return Err(AppError::Sync("passphrase must not be empty".into()));
    }

    let json = state.with_conn(|conn| SyncBundle::snapshot(conn)?.to_json())?;
    let ciphertext = sync::crypto::encrypt(&passphrase, &json)?;
    std::fs::write(&dest_path, &ciphertext)
        .map_err(|e| AppError::Io(format!("cannot write sync bundle: {e}")))?;
    Ok(())
}

/// Read + decrypt + parse the bundle at `src_path` and merge it into the
/// unlocked vault (per-row LWW). Returns the merge summary. A wrong passphrase
/// or a malformed bundle surfaces as [`AppError::Sync`].
#[tauri::command]
pub fn import_sync_bundle(
    state: State<'_, AppState>,
    passphrase: String,
    src_path: String,
) -> AppResult<SyncSummary> {
    if passphrase.is_empty() {
        return Err(AppError::Sync("passphrase must not be empty".into()));
    }

    let ciphertext = std::fs::read(&src_path)
        .map_err(|e| AppError::Io(format!("cannot read sync bundle: {e}")))?;
    let json = sync::crypto::decrypt(&passphrase, &ciphertext)?;
    let bundle = SyncBundle::from_json(&json)?;

    state.with_conn_mut(|conn| sync::merge(conn, bundle))
}
