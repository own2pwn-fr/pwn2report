//! Tauri command surface. All commands are synchronous and return
//! `Result<T, AppError>`.

pub mod evidence;
pub mod export;
pub mod findings;
pub mod import;
pub mod kb;
pub mod reports;
pub mod templates;
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

/// Resolve the writable templates directory (`<app_config_dir>/templates`),
/// creating it (and the config dir) if missing. Custom per-report-type Typst
/// templates live here as `<report_type>.typ`.
pub fn templates_dir(app: &AppHandle) -> AppResult<PathBuf> {
    let dir = app
        .path()
        .app_config_dir()
        .map_err(|e| AppError::Io(format!("cannot resolve app config dir: {e}")))?
        .join("templates");
    if !dir.exists() {
        std::fs::create_dir_all(&dir)
            .map_err(|e| AppError::Io(format!("cannot create templates dir: {e}")))?;
    }
    Ok(dir)
}

/// Path to the custom template file for a report-type slug
/// (`<app_config_dir>/templates/<slug>.typ`). Does not create the file.
pub fn template_path(app: &AppHandle, report_type_slug: &str) -> AppResult<PathBuf> {
    Ok(templates_dir(app)?.join(format!("{report_type_slug}.typ")))
}
