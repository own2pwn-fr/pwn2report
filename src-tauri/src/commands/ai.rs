//! AI-assistance commands (v3) — opt-in, OFF by default.
//!
//! Config lives at `<app_config_dir>/ai.json` (via [`crate::ai::config`]); the
//! sensitive cloud API key lives in the OS keychain (via
//! [`crate::ai::keychain`]) and is never returned to the frontend — only its
//! *presence* is exposed as `has_key`.

use serde::Serialize;
use tauri::AppHandle;

use crate::ai::config::{self, AiConfig};
use crate::ai::{self, keychain};
use crate::error::{AppError, AppResult};

/// Frontend-facing view of the AI config. Deliberately omits the API key:
/// `has_key` reflects keychain presence so the UI can show "configured"
/// without ever handling the secret.
#[derive(Debug, Serialize)]
pub struct AiConfigView {
    pub enabled: bool,
    pub provider: config::AiProvider,
    pub base_url: String,
    pub model: String,
    pub max_tokens: u32,
    pub api_version: Option<String>,
    pub has_key: bool,
}

/// Read the persisted AI config plus whether an API key is stored.
#[tauri::command]
pub fn ai_get_config(app: AppHandle) -> AppResult<AiConfigView> {
    let cfg = config::load(&app)?;
    Ok(AiConfigView {
        enabled: cfg.enabled,
        provider: cfg.provider,
        base_url: cfg.base_url,
        model: cfg.model,
        max_tokens: cfg.max_tokens,
        api_version: cfg.api_version,
        has_key: keychain::has_key(),
    })
}

/// Persist the AI config and (optionally) update the stored API key.
///
/// API key semantics:
/// - `Some(non-empty)` → store/replace it in the keychain.
/// - `Some("")`        → delete any stored key.
/// - `None`            → leave the stored key unchanged.
///
/// Key operations are best-effort (the keychain may be unavailable): a failed
/// store does not roll back the config write — `ai_get_config().has_key` will
/// simply report `false`, and cloud calls will then error clearly.
#[tauri::command]
pub fn ai_set_config(app: AppHandle, config: AiConfig, api_key: Option<String>) -> AppResult<()> {
    config::save(&app, &config)?;
    match api_key {
        Some(k) if k.is_empty() => {
            let _ = keychain::delete();
        }
        Some(k) => {
            let _ = keychain::store(&k);
        }
        None => {}
    }
    Ok(())
}

/// Probe the configured provider with a tiny prompt and return its (trimmed)
/// reply. Errors clearly if AI is disabled or (for cloud) no key is stored.
#[tauri::command]
pub fn ai_test_connection(app: AppHandle) -> AppResult<String> {
    let cfg = config::load(&app)?;
    if !cfg.enabled {
        return Err(AppError::Ai(
            "AI is disabled — enable it in AI settings first".to_string(),
        ));
    }
    let key = keychain::get().ok().flatten();
    let out = ai::complete(
        &cfg,
        key.as_deref(),
        Some("You are a connection test. Answer with exactly one word."),
        "Reply with the single word: ok",
    )?;
    Ok(out.trim().to_string())
}

/// Generic completion entry point used by the frontend's improve / generate /
/// translate actions. Errors clearly if AI is disabled or (for cloud) no key
/// is stored.
#[tauri::command]
pub fn ai_complete(app: AppHandle, system: Option<String>, prompt: String) -> AppResult<String> {
    let cfg = config::load(&app)?;
    if !cfg.enabled {
        return Err(AppError::Ai(
            "AI is disabled — enable it in AI settings first".to_string(),
        ));
    }
    let key = keychain::get().ok().flatten();
    ai::complete(&cfg, key.as_deref(), system.as_deref(), &prompt)
}

/// List the model identifiers advertised by the configured provider, using the
/// saved config + stored key. A convenience for the settings UI (the app does
/// not depend on it): errors surface clearly if AI is disabled, the provider is
/// unreachable, or the key is missing for a provider that requires one.
#[tauri::command]
pub fn ai_list_models(app: AppHandle) -> AppResult<Vec<String>> {
    let cfg = config::load(&app)?;
    if !cfg.enabled {
        return Err(AppError::Ai(
            "AI is disabled — enable it in AI settings first".to_string(),
        ));
    }
    let key = keychain::get().ok().flatten();
    ai::list_models(&cfg, key.as_deref())
}
