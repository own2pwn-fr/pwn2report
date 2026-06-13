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
#[derive(Default)]
pub enum AiProvider {
    /// A local Ollama server (default). Nothing leaves the machine.
    #[default]
    Ollama,
    /// Any OpenAI-compatible `/v1/chat/completions` endpoint. The API key is
    /// optional so keyless local servers (LM Studio, etc.) work.
    Openai,
    /// Anthropic's `/v1/messages` API.
    Anthropic,
    /// Azure OpenAI: `POST /openai/deployments/{model}/chat/completions`.
    Azure,
    /// Google Gemini: `POST /v1beta/models/{model}:generateContent`.
    Gemini,
}

/// Default Azure OpenAI REST API version (recent stable).
pub const DEFAULT_AZURE_API_VERSION: &str = "2024-06-01";

/// Default max output tokens requested from the provider.
pub const DEFAULT_MAX_TOKENS: u32 = 1024;

/// Serde default for `max_tokens` (keeps older `ai.json` files loadable).
fn default_max_tokens() -> u32 {
    DEFAULT_MAX_TOKENS
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
    /// Max output tokens to request. Used by Anthropic/Azure/Gemini (and as a
    /// sensible cap elsewhere the API supports it). Defaulted for back-compat.
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    /// Azure OpenAI REST API version (`api-version` query param). Only used by
    /// the `azure` provider; `None` falls back to [`DEFAULT_AZURE_API_VERSION`].
    #[serde(default)]
    pub api_version: Option<String>,
}

impl Default for AiConfig {
    fn default() -> Self {
        AiConfig {
            enabled: false,
            provider: AiProvider::Ollama,
            base_url: "http://localhost:11434".to_string(),
            model: "llama3.1".to_string(),
            max_tokens: DEFAULT_MAX_TOKENS,
            api_version: None,
        }
    }
}

impl AiConfig {
    /// Effective Azure API version: the configured value or the default.
    pub fn azure_api_version(&self) -> &str {
        self.api_version
            .as_deref()
            .filter(|v| !v.is_empty())
            .unwrap_or(DEFAULT_AZURE_API_VERSION)
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
    std::fs::write(&path, json).map_err(|e| AppError::Io(format!("cannot write ai.json: {e}")))?;
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
        assert_eq!(cfg.max_tokens, DEFAULT_MAX_TOKENS);
        assert_eq!(cfg.api_version, None);
    }

    #[test]
    fn config_serde_round_trip() {
        let cfg = AiConfig {
            enabled: true,
            provider: AiProvider::Anthropic,
            base_url: "https://api.anthropic.com".to_string(),
            model: "claude-3-5-sonnet".to_string(),
            max_tokens: 4096,
            api_version: Some("2024-10-21".to_string()),
        };
        let json = serde_json::to_string(&cfg).unwrap();
        // Provider must serialize snake_case for the frontend union.
        assert!(json.contains("\"anthropic\""), "got: {json}");
        let back: AiConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.enabled, cfg.enabled);
        assert_eq!(back.provider, cfg.provider);
        assert_eq!(back.base_url, cfg.base_url);
        assert_eq!(back.model, cfg.model);
        assert_eq!(back.max_tokens, cfg.max_tokens);
        assert_eq!(back.api_version, cfg.api_version);
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
        assert_eq!(
            serde_json::to_string(&AiProvider::Azure).unwrap(),
            "\"azure\""
        );
        assert_eq!(
            serde_json::to_string(&AiProvider::Gemini).unwrap(),
            "\"gemini\""
        );
    }

    #[test]
    fn missing_new_fields_default_on_load() {
        // An older `ai.json` that predates max_tokens/api_version must still load.
        let raw = r#"{
            "enabled": true,
            "provider": "ollama",
            "base_url": "http://localhost:11434",
            "model": "llama3.1"
        }"#;
        let cfg: AiConfig = serde_json::from_str(raw).unwrap();
        assert_eq!(cfg.max_tokens, DEFAULT_MAX_TOKENS);
        assert_eq!(cfg.api_version, None);
    }

    #[test]
    fn azure_api_version_falls_back_to_default() {
        let mut cfg = AiConfig {
            provider: AiProvider::Azure,
            api_version: None,
            ..AiConfig::default()
        };
        assert_eq!(cfg.azure_api_version(), DEFAULT_AZURE_API_VERSION);
        cfg.api_version = Some(String::new());
        assert_eq!(cfg.azure_api_version(), DEFAULT_AZURE_API_VERSION);
        cfg.api_version = Some("2024-10-21".to_string());
        assert_eq!(cfg.azure_api_version(), "2024-10-21");
    }
}
