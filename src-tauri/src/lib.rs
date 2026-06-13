//! pwn2report — Tauri v2 backend.
//!
//! An offline desktop pentest-report writer. All data lives in a single
//! SQLCipher-encrypted vault (`<app_data_dir>/vault.db`) unlocked with a
//! passphrase (optionally remembered in the OS keychain). Reports + findings
//! are authored in the UI and exported to PDF via an embedded Typst template.

mod ai;
mod commands;
mod db;
#[cfg(test)]
mod e2e_tests;
mod error;
mod import;
mod models;
mod render;
mod state;
mod sync;
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
            commands::reports::set_report_logo,
            commands::reports::get_report_logo,
            commands::reports::clear_report_logo,
            // assets + scope (aggregate report layer)
            commands::assets::list_assets,
            commands::assets::create_asset,
            commands::assets::update_asset,
            commands::assets::delete_asset,
            commands::assets::reorder_assets,
            commands::assets::set_finding_assets,
            commands::assets::list_finding_assets,
            commands::scope::list_scope_items,
            commands::scope::create_scope_item,
            commands::scope::update_scope_item,
            commands::scope::delete_scope_item,
            commands::scope::reorder_scope_items,
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
            // AI assistance (v3, opt-in)
            commands::ai::ai_get_config,
            commands::ai::ai_set_config,
            commands::ai::ai_test_connection,
            commands::ai::ai_complete,
            // sync (v4): E2E-encrypted, local-first bundle sync
            commands::sync::export_sync_bundle,
            commands::sync::import_sync_bundle,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
