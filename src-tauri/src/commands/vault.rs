//! Vault lifecycle commands: status, create, unlock, lock, keychain.

use serde::Serialize;
use tauri::{AppHandle, State};
use zeroize::Zeroizing;

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
    // Move the secret into a Zeroizing buffer so the plaintext copy is wiped on
    // drop (Tauri requires the command param itself to be a plain `String`).
    let passphrase = Zeroizing::new(passphrase);
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
    let passphrase = Zeroizing::new(passphrase);
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
        Ok(Some(p)) => Zeroizing::new(p),
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

/// Change the vault passphrase via SQLCipher `PRAGMA rekey`.
///
/// Requires the vault to be unlocked. The `old` passphrase is re-verified
/// (canary check against a fresh connection) before rekeying so a typo cannot
/// silently rekey to an unintended new passphrase. The live in-memory
/// connection is rekeyed in place, so it stays valid afterwards. If the
/// passphrase was remembered in the keychain, the stored value is refreshed
/// (best-effort).
#[tauri::command]
pub fn change_passphrase(
    app: AppHandle,
    state: State<'_, AppState>,
    old_passphrase: String,
    new_passphrase: String,
) -> AppResult<()> {
    if !state.is_unlocked() {
        return Err(AppError::VaultLocked);
    }
    // Move both secrets into Zeroizing buffers so the plaintext copies are wiped.
    let old_passphrase = Zeroizing::new(old_passphrase);
    let new_passphrase = Zeroizing::new(new_passphrase);
    let path = vault_path(&app)?;

    // Re-verify the old passphrase against the canary on a throwaway, read-only
    // connection (no schema write — safe alongside the live connection). Maps a
    // wrong key to WrongPassphrase rather than rekeying blindly.
    connection::verify_passphrase(&path, &old_passphrase)?;

    // Rekey the live connection in place (escape ' by doubling, as PRAGMAs
    // cannot be parameter-bound). Both the escaped key and the full PRAGMA
    // string embed the new secret, so wrap them in Zeroizing to be wiped.
    let escaped = Zeroizing::new(new_passphrase.replace('\'', "''"));
    let pragma = Zeroizing::new(format!("PRAGMA rekey = '{}';", escaped.as_str()));
    state.with_conn(|conn| {
        conn.execute_batch(&pragma)?;
        Ok(())
    })?;

    // Refresh the keychain entry if one was stored (best-effort, never fatal).
    if let Ok(Some(_)) = keychain::get() {
        let _ = keychain::store(&new_passphrase);
    }
    Ok(())
}

/// Write an encrypted copy of the vault to `dest_path`.
///
/// Requires the vault to be unlocked. The on-disk `vault.db` is already
/// encrypted at rest, so we checkpoint the WAL (to fold pending writes into the
/// main file) and then copy the file. The copy remains encrypted with the
/// current passphrase.
#[tauri::command]
pub fn backup_vault(
    app: AppHandle,
    state: State<'_, AppState>,
    dest_path: String,
) -> AppResult<()> {
    let src = vault_path(&app)?;
    // Fold the WAL into the main db so the file copy is complete.
    state.with_conn(|conn| {
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    })?;
    std::fs::copy(&src, &dest_path)
        .map_err(|e| AppError::Io(format!("vault backup failed: {e}")))?;
    Ok(())
}
