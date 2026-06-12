//! Pluggable AI assistance (v3) — opt-in, OFF by default.
//!
//! Privacy first: nothing leaves the machine unless the user explicitly
//! enables AI and configures a provider. The default provider is a *local*
//! Ollama server. Cloud providers (OpenAI-compatible, Anthropic) require an
//! API key, which is stored in the OS keychain ([`keychain`]) — never in the
//! plaintext `ai.json` config ([`config`]).
//!
//! This module owns the HTTP/provider dispatch; the actual Tauri commands live
//! in [`crate::commands::ai`].

pub mod config;
pub mod keychain;

use serde_json::{json, Value};

use crate::error::{AppError, AppResult};
use config::{AiConfig, AiProvider};

/// HTTP timeout for a (non-streaming) completion. Generous: local models on
/// modest hardware can take a while to produce a first/full response.
const TIMEOUT_SECS: u64 = 120;

/// Run a single non-streaming completion against the configured provider.
///
/// `system` is an optional system prompt; `prompt` is the user message. Returns
/// the model's text output, or [`AppError::Ai`] with a clear, user-facing
/// message (including the provider name and, for HTTP failures, the status).
///
/// Cloud providers (OpenAI/Anthropic) require `api_key`; a missing key yields a
/// clear error rather than a confusing 401 round-trip.
pub fn complete(
    cfg: &AiConfig,
    api_key: Option<&str>,
    system: Option<&str>,
    prompt: &str,
) -> AppResult<String> {
    match cfg.provider {
        AiProvider::Ollama => complete_ollama(cfg, system, prompt),
        AiProvider::Openai => complete_openai(cfg, api_key, system, prompt),
        AiProvider::Anthropic => complete_anthropic(cfg, api_key, system, prompt),
    }
}

/// Build a `ureq` agent with the shared timeout applied to both read & write.
fn agent() -> ureq::Agent {
    let t = std::time::Duration::from_secs(TIMEOUT_SECS);
    ureq::AgentBuilder::new()
        .timeout_read(t)
        .timeout_write(t)
        .build()
}

/// Trim a trailing slash so we can join paths without doubling it.
fn base(cfg: &AiConfig) -> &str {
    cfg.base_url.trim_end_matches('/')
}

/// Map a `ureq` error into a clear, provider-tagged [`AppError::Ai`]. A
/// `Status` error carries the HTTP code (and the response body, which usually
/// contains the provider's own error message); a `Transport` error is a
/// connection-level failure (server down, bad URL, TLS).
fn map_ureq_err(provider: &str, err: ureq::Error) -> AppError {
    match err {
        ureq::Error::Status(code, resp) => {
            let body = resp
                .into_string()
                .unwrap_or_else(|_| "<unreadable body>".to_string());
            let body = body.trim();
            let snippet = if body.len() > 500 { &body[..500] } else { body };
            AppError::Ai(format!(
                "{provider} request failed (HTTP {code}): {snippet}"
            ))
        }
        ureq::Error::Transport(t) => AppError::Ai(format!(
            "{provider} request failed (could not reach the server): {t}"
        )),
    }
}

/// Pull a required string out of a JSON path, erroring clearly if the provider
/// returned an unexpected shape.
fn require_text(provider: &str, v: Option<&Value>) -> AppResult<String> {
    match v.and_then(Value::as_str) {
        Some(s) => Ok(s.to_string()),
        None => Err(AppError::Ai(format!(
            "{provider} returned an unexpected response shape (no text content)"
        ))),
    }
}

/// Require a non-empty API key for cloud providers.
fn require_key<'a>(provider: &str, api_key: Option<&'a str>) -> AppResult<&'a str> {
    match api_key {
        Some(k) if !k.is_empty() => Ok(k),
        _ => Err(AppError::Ai(format!(
            "{provider} requires an API key — set one in AI settings"
        ))),
    }
}

/// Assemble the `messages` array shared by Ollama and OpenAI-compatible APIs.
fn chat_messages(system: Option<&str>, prompt: &str) -> Vec<Value> {
    let mut msgs = Vec::with_capacity(2);
    if let Some(sys) = system {
        if !sys.is_empty() {
            msgs.push(json!({ "role": "system", "content": sys }));
        }
    }
    msgs.push(json!({ "role": "user", "content": prompt }));
    msgs
}

/// Ollama: `POST {base_url}/api/chat`, non-streaming → `.message.content`.
fn complete_ollama(cfg: &AiConfig, system: Option<&str>, prompt: &str) -> AppResult<String> {
    let url = format!("{}/api/chat", base(cfg));
    let body = json!({
        "model": cfg.model,
        "messages": chat_messages(system, prompt),
        "stream": false,
    });
    let resp: Value = agent()
        .post(&url)
        .send_json(body)
        .map_err(|e| map_ureq_err("Ollama", e))?
        .into_json()
        .map_err(|e| AppError::Ai(format!("Ollama returned invalid JSON: {e}")))?;
    require_text("Ollama", resp.pointer("/message/content"))
}

/// OpenAI-compatible: `POST {base_url}/v1/chat/completions` with a bearer key,
/// non-streaming → `.choices[0].message.content`.
fn complete_openai(
    cfg: &AiConfig,
    api_key: Option<&str>,
    system: Option<&str>,
    prompt: &str,
) -> AppResult<String> {
    let key = require_key("OpenAI", api_key)?;
    let url = format!("{}/v1/chat/completions", base(cfg));
    let body = json!({
        "model": cfg.model,
        "messages": chat_messages(system, prompt),
    });
    let resp: Value = agent()
        .post(&url)
        .set("Authorization", &format!("Bearer {key}"))
        .send_json(body)
        .map_err(|e| map_ureq_err("OpenAI", e))?
        .into_json()
        .map_err(|e| AppError::Ai(format!("OpenAI returned invalid JSON: {e}")))?;
    require_text("OpenAI", resp.pointer("/choices/0/message/content"))
}

/// Anthropic: `POST {base_url}/v1/messages` with `x-api-key` and
/// `anthropic-version`, non-streaming → `.content[0].text`.
fn complete_anthropic(
    cfg: &AiConfig,
    api_key: Option<&str>,
    system: Option<&str>,
    prompt: &str,
) -> AppResult<String> {
    let key = require_key("Anthropic", api_key)?;
    let url = format!("{}/v1/messages", base(cfg));
    let mut body = json!({
        "model": cfg.model,
        "max_tokens": 1024,
        "messages": [{ "role": "user", "content": prompt }],
    });
    if let Some(sys) = system {
        if !sys.is_empty() {
            body["system"] = json!(sys);
        }
    }
    let resp: Value = agent()
        .post(&url)
        .set("x-api-key", key)
        .set("anthropic-version", "2023-06-01")
        .send_json(body)
        .map_err(|e| map_ureq_err("Anthropic", e))?
        .into_json()
        .map_err(|e| AppError::Ai(format!("Anthropic returned invalid JSON: {e}")))?;
    require_text("Anthropic", resp.pointer("/content/0/text"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_messages_omits_empty_system() {
        let msgs = chat_messages(None, "hi");
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0]["role"], "user");

        let msgs = chat_messages(Some(""), "hi");
        assert_eq!(msgs.len(), 1, "empty system prompt must be skipped");

        let msgs = chat_messages(Some("be terse"), "hi");
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0]["role"], "system");
        assert_eq!(msgs[0]["content"], "be terse");
    }

    #[test]
    fn cloud_providers_require_a_key() {
        let err = require_key("OpenAI", None).unwrap_err();
        assert!(matches!(err, AppError::Ai(_)));
        let err = require_key("Anthropic", Some("")).unwrap_err();
        assert!(matches!(err, AppError::Ai(_)));
        assert_eq!(require_key("OpenAI", Some("sk-x")).unwrap(), "sk-x");
    }

    #[test]
    fn base_trims_trailing_slash() {
        let cfg = AiConfig {
            base_url: "http://localhost:11434/".to_string(),
            ..AiConfig::default()
        };
        assert_eq!(base(&cfg), "http://localhost:11434");
    }
}
