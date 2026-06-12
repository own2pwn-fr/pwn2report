//! pwn2report — Tauri v2 backend.
//!
//! An offline desktop pentest-report writer. All data lives in a single
//! SQLCipher-encrypted vault (`<app_data_dir>/vault.db`) unlocked with a
//! passphrase (optionally remembered in the OS keychain). Reports + findings
//! are authored in the UI and exported to PDF via an embedded Typst template.

mod commands;
mod db;
mod error;
mod import;
mod models;
mod render;
mod state;
#[cfg(test)]
mod test_fixtures;
mod vault;

use state::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        // Plugins.
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        // Shared state: the (optionally) unlocked vault.
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            // vault lifecycle
            commands::vault::vault_status,
            commands::vault::create_vault,
            commands::vault::unlock_vault,
            commands::vault::unlock_with_keychain,
            commands::vault::lock_vault,
            commands::vault::forget_keychain,
            commands::vault::change_passphrase,
            commands::vault::backup_vault,
            // reports
            commands::reports::list_reports,
            commands::reports::create_report,
            commands::reports::get_report,
            commands::reports::update_report,
            commands::reports::delete_report,
            // findings
            commands::findings::list_findings,
            commands::findings::create_finding,
            commands::findings::update_finding,
            commands::findings::delete_finding,
            commands::findings::reorder_findings,
            // evidence images
            commands::evidence::add_evidence_image,
            commands::evidence::list_evidence_images,
            commands::evidence::get_evidence_image,
            commands::evidence::update_evidence_caption,
            commands::evidence::delete_evidence_image,
            commands::evidence::reorder_evidence_images,
            // export
            commands::export::export_pdf,
            commands::export::export_markdown,
            commands::export::export_html,
            commands::export::export_docx,
            // templates
            commands::templates::list_templates,
            commands::templates::get_template,
            commands::templates::save_template,
            commands::templates::reset_template,
            // knowledge base
            commands::kb::kb_list,
            commands::kb::kb_get,
            commands::kb::kb_create,
            commands::kb::kb_update,
            commands::kb::kb_delete,
            commands::kb::kb_import_bundled,
            commands::kb::create_finding_from_kb,
            // scanner importers
            commands::import::import_findings,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
