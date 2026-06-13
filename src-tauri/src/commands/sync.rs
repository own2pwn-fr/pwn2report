//! Sync-bundle commands: export (snapshot + encrypt + write) and import
//! (read + decrypt + parse + merge). Both require an unlocked vault.

use tauri::State;

use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::sync::{self, SyncBundle, SyncSummary};

/// Snapshot the unlocked vault, encrypt it under `passphrase`, and write the age
/// bundle to `dest_path`. Rejects an empty passphrase.
///
/// The ciphertext is streamed: age wraps a `BufWriter<File>` and the JSON bytes
/// are encrypted straight into the destination file, so we never hold a separate
/// full-size ciphertext `Vec` in memory alongside the plaintext (which matters
/// when the bundle carries many/large evidence images). Peak memory is bounded
/// by ~one copy of the JSON payload rather than several multiples of it.
#[tauri::command]
pub fn export_sync_bundle(
    state: State<'_, AppState>,
    passphrase: String,
    dest_path: String,
) -> AppResult<()> {
    use std::io::{BufWriter, Write};

    if passphrase.is_empty() {
        return Err(AppError::Sync("passphrase must not be empty".into()));
    }

    let json = state.with_conn(|conn| SyncBundle::snapshot(conn)?.to_json())?;

    let file = std::fs::File::create(&dest_path)
        .map_err(|e| AppError::Io(format!("cannot write sync bundle: {e}")))?;
    let mut writer = BufWriter::new(file);
    sync::crypto::encrypt_to_writer(&passphrase, &json, &mut writer)?;
    // Flush the BufWriter explicitly so any deferred write error surfaces here
    // rather than being swallowed on drop.
    writer
        .flush()
        .map_err(|e| AppError::Io(format!("cannot flush sync bundle: {e}")))?;
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
