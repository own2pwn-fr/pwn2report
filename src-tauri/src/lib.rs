//! pwn2report — Tauri v2 backend.
//!
//! An offline desktop pentest-report writer. All data lives in a single
//! SQLCipher-encrypted vault (`<app_data_dir>/vault.db`) unlocked with a
//! passphrase (optionally remembered in the OS keychain). Reports + findings
//! are authored in the UI and exported to PDF via an embedded Typst template.

mod commands;
mod db;
mod error;
mod models;
mod render;
mod state;
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
            // export
            commands::export::export_pdf,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
