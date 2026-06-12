//! Tauri command surface. All commands are synchronous and return
//! `Result<T, AppError>`.

pub mod export;
pub mod findings;
pub mod reports;
pub mod vault;

use std::path::PathBuf;

use tauri::{AppHandle, Manager};

use crate::error::{AppError, AppResult};

/// Resolve the vault database path (`<app_data_dir>/vault.db`), creating the
/// data directory if missing.
pub fn vault_path(app: &AppHandle) -> AppResult<PathBuf> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| AppError::Db(format!("cannot resolve app data dir: {e}")))?;
    if !dir.exists() {
        std::fs::create_dir_all(&dir)
            .map_err(|e| AppError::Db(format!("cannot create app data dir: {e}")))?;
    }
    Ok(dir.join("vault.db"))
}
