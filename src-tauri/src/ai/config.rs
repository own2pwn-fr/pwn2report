//! AI-assistance configuration: the `AiConfig` shape and its on-disk I/O.
//!
//! Stored as `<app_config_dir>/ai.json` — this is *app config*, not report
//! data, so it lives next to the templates dir rather than in the encrypted
//! vault. The sensitive API key is deliberately **not** part of this struct;
//! it lives in the OS keychain ([`super::keychain`]). Privacy first: a brand
//! new install has `enabled = false`, so nothing ever leaves the machine until
//! the user opts in.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

use crate::error::{AppError, AppResult};

/// Which AI backend to talk to. Serialized snake_case to match the IPC
/// convention and the frontend's discriminated union.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiProvider {
    /// A local Ollama server (default). Nothing leaves the machine.
    Ollama,
    /// Any OpenAI-compatible `/v1/chat/completions` endpoint.
    Openai,
    /// Anthropic's `/v1/messages` API.
    Anthropic,
}

impl Default for AiProvider {
    fn default() -> Self {
        AiProvider::Ollama
    }
}

/// Persisted AI configuration. The API key is **not** here (keychain only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    /// Master opt-in switch. `false` by default → AI fully inert.
    pub enabled: bool,
    /// Selected provider.
    pub provider: AiProvider,
    /// Base URL of the provider endpoint (user-overridable).
    pub base_url: String,
    /// Model identifier to request.
    pub model: String,
}

impl Default for AiConfig {
    fn default() -> Self {
        AiConfig {
            enabled: false,
            provider: AiProvider::Ollama,
            base_url: "http://localhost:11434".to_string(),
            model: "llama3.1".to_string(),
        }
    }
}

/// Resolve `<app_config_dir>/ai.json`, creating the config dir if missing.
fn config_path(app: &AppHandle) -> AppResult<PathBuf> {
    let dir = app
        .path()
        .app_config_dir()
        .map_err(|e| AppError::Io(format!("cannot resolve app config dir: {e}")))?;
    if !dir.exists() {
        std::fs::create_dir_all(&dir)
            .map_err(|e| AppError::Io(format!("cannot create app config dir: {e}")))?;
    }
    Ok(dir.join("ai.json"))
}

/// Load the AI config, falling back to [`AiConfig::default`] if the file is
/// absent. A malformed file surfaces as a serialization error rather than
/// silently resetting (so the user isn't surprised by a wiped config).
pub fn load(app: &AppHandle) -> AppResult<AiConfig> {
    let path = config_path(app)?;
    if !path.exists() {
        return Ok(AiConfig::default());
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| AppError::Io(format!("cannot read ai.json: {e}")))?;
    let cfg: AiConfig = serde_json::from_str(&raw)?;
    Ok(cfg)
}

/// Persist the AI config to `ai.json` (pretty-printed for hand-edits).
pub fn save(app: &AppHandle, cfg: &AiConfig) -> AppResult<()> {
    let path = config_path(app)?;
    let json = serde_json::to_string_pretty(cfg)?;
    std::fs::write(&path, json)
        .map_err(|e| AppError::Io(format!("cannot write ai.json: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_disabled_and_local() {
        let cfg = AiConfig::default();
        assert!(!cfg.enabled, "AI must be OFF by default (privacy first)");
        assert_eq!(cfg.provider, AiProvider::Ollama);
        assert_eq!(cfg.base_url, "http://localhost:11434");
        assert_eq!(cfg.model, "llama3.1");
    }

    #[test]
    fn config_serde_round_trip() {
        let cfg = AiConfig {
            enabled: true,
            provider: AiProvider::Anthropic,
            base_url: "https://api.anthropic.com".to_string(),
            model: "claude-3-5-sonnet".to_string(),
        };
        let json = serde_json::to_string(&cfg).unwrap();
        // Provider must serialize snake_case for the frontend union.
        assert!(json.contains("\"anthropic\""), "got: {json}");
        let back: AiConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.enabled, cfg.enabled);
        assert_eq!(back.provider, cfg.provider);
        assert_eq!(back.base_url, cfg.base_url);
        assert_eq!(back.model, cfg.model);
    }

    #[test]
    fn provider_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&AiProvider::Openai).unwrap(),
            "\"openai\""
        );
        assert_eq!(
            serde_json::to_string(&AiProvider::Ollama).unwrap(),
            "\"ollama\""
        );
    }
}
