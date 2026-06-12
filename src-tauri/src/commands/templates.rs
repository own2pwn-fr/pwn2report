//! Editable-template commands.
//!
//! Bundled `.typ` themes (embedded via `include_str!`) are the defaults. A user
//! may override the theme for a report type by saving a custom template to
//! `<app_config_dir>/templates/<report_type>.typ`. The Typst render path
//! (`commands::export::export_pdf`) prefers the custom file when present, else
//! falls back to the bundled theme. Custom templates may `#import` the shared
//! lib at the stable path [`crate::render::typst_pdf::COMMON_IMPORT_PATH`].

use serde::Serialize;
use tauri::AppHandle;

use super::{template_path, templates_dir};
use crate::error::AppResult;
use crate::models::ReportType;
use crate::render::typst_pdf::bundled_theme;

/// One entry per report type, indicating whether a custom override exists.
#[derive(Debug, Serialize)]
pub struct TemplateInfo {
    pub report_type: String,
    pub is_custom: bool,
}

/// Resolve the Typst main-file source for a report-type slug: the custom file
/// from the config dir if present, else the bundled default. Used by the PDF
/// export path.
pub fn resolve_template_source(app: &AppHandle, report_type_slug: &str) -> AppResult<String> {
    let path = template_path(app, report_type_slug)?;
    if path.exists() {
        Ok(std::fs::read_to_string(&path)?)
    } else {
        Ok(bundled_theme(report_type_slug).to_string())
    }
}

/// List all report types and whether each has a custom template override.
#[tauri::command]
pub fn list_templates(app: AppHandle) -> AppResult<Vec<TemplateInfo>> {
    // Ensure the dir exists so a later save/exists check is consistent.
    let dir = templates_dir(&app)?;
    let mut out = Vec::new();
    for rt in ReportType::all() {
        let slug = rt.slug();
        let is_custom = dir.join(format!("{slug}.typ")).exists();
        out.push(TemplateInfo {
            report_type: slug.to_string(),
            is_custom,
        });
    }
    Ok(out)
}

/// Get the template source for a report type: the custom source if present,
/// else the bundled default.
#[tauri::command]
pub fn get_template(app: AppHandle, report_type: String) -> AppResult<String> {
    resolve_template_source(&app, &report_type)
}

/// Save a custom template for a report type (writes to the config dir, creating
/// it as needed).
#[tauri::command]
pub fn save_template(app: AppHandle, report_type: String, content: String) -> AppResult<()> {
    let path = template_path(&app, &report_type)?;
    std::fs::write(&path, content)?;
    Ok(())
}

/// Reset a report type to its bundled default by deleting the custom file. No
/// error if it does not exist.
#[tauri::command]
pub fn reset_template(app: AppHandle, report_type: String) -> AppResult<()> {
    let path = template_path(&app, &report_type)?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
