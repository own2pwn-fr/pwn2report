//! Vault lifecycle commands: status, create, unlock, lock, keychain.

use serde::Serialize;
use tauri::{AppHandle, State};

use super::vault_path;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::vault::{connection, keychain};

/// Snapshot of vault state for the frontend's gate logic.
#[derive(Debug, Serialize)]
pub struct VaultStatus {
    /// Whether the on-disk vault file exists.
    pub exists: bool,
    /// Whether a vault is currently unlocked in memory.
    pub unlocked: bool,
    /// Whether the OS keychain is usable for remember-me.
    pub keychain_available: bool,
}

#[tauri::command]
pub fn vault_status(app: AppHandle, state: State<'_, AppState>) -> AppResult<VaultStatus> {
    let path = vault_path(&app)?;
    Ok(VaultStatus {
        exists: path.exists(),
        unlocked: state.is_unlocked(),
        keychain_available: keychain::available(),
    })
}

/// Create a new encrypted vault. Fails if one already exists.
#[tauri::command]
pub fn create_vault(
    app: AppHandle,
    state: State<'_, AppState>,
    passphrase: String,
    remember: bool,
) -> AppResult<()> {
    let path = vault_path(&app)?;
    if path.exists() {
        return Err(AppError::Db("vault already exists".into()));
    }
    let conn = connection::create_encrypted(&path, &passphrase)?;
    state.set_vault(conn);

    if remember {
        // Best-effort: never fail vault creation because the keychain is down.
        let _ = keychain::store(&passphrase);
    }
    Ok(())
}

/// Unlock an existing vault with the given passphrase.
#[tauri::command]
pub fn unlock_vault(
    app: AppHandle,
    state: State<'_, AppState>,
    passphrase: String,
    remember: bool,
) -> AppResult<()> {
    let path = vault_path(&app)?;
    if !path.exists() {
        return Err(AppError::NotFound);
    }
    let conn = connection::open_encrypted(&path, &passphrase)?;
    state.set_vault(conn);

    if remember {
        let _ = keychain::store(&passphrase);
    }
    Ok(())
}

/// Try to unlock using a passphrase stored in the OS keychain.
/// Returns `false` (never errors) when no usable stored credential unlocks it.
#[tauri::command]
pub fn unlock_with_keychain(app: AppHandle, state: State<'_, AppState>) -> AppResult<bool> {
    let path = vault_path(&app)?;
    if !path.exists() {
        return Ok(false);
    }
    let stored = match keychain::get() {
        Ok(Some(p)) => p,
        _ => return Ok(false),
    };
    match connection::open_encrypted(&path, &stored) {
        Ok(conn) => {
            state.set_vault(conn);
            Ok(true)
        }
        // Stale/wrong stored passphrase: forget it and report failure.
        Err(_) => {
            let _ = keychain::delete();
            Ok(false)
        }
    }
}

/// Lock the vault (drop the in-memory connection).
#[tauri::command]
pub fn lock_vault(state: State<'_, AppState>) -> AppResult<()> {
    state.clear();
    Ok(())
}

/// Forget any keychain-stored passphrase (best-effort).
#[tauri::command]
pub fn forget_keychain() -> AppResult<()> {
    let _ = keychain::delete();
    Ok(())
}
