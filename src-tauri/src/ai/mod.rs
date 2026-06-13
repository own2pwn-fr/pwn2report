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

/// Number of attempts (initial try + retries) for a provider HTTP call. Only
/// HTTP 429 and 5xx (plus transport errors) are retried; other 4xx fail fast.
const MAX_ATTEMPTS: u32 = 3;

/// Base backoff between retries; doubled each attempt (exponential).
const BACKOFF_BASE_MS: u64 = 500;

/// Cap on a single backoff sleep, including a server-supplied `Retry-After`.
const BACKOFF_MAX_MS: u64 = 10_000;

/// Run a single non-streaming completion against the configured provider.
///
/// `system` is an optional system prompt; `prompt` is the user message. Returns
/// the model's text output, or [`AppError::Ai`] with a clear, user-facing
/// message (including the provider name and, for HTTP failures, the status).
///
/// Cloud providers that mandate auth (Anthropic, Azure, Gemini) require
/// `api_key`; a missing key yields a clear error rather than a confusing 401
/// round-trip. The OpenAI provider's key is optional (keyless local servers).
pub fn complete(
    cfg: &AiConfig,
    api_key: Option<&str>,
    system: Option<&str>,
    prompt: &str,
) -> AppResult<String> {
    validate_base_url(cfg)?;
    match cfg.provider {
        AiProvider::Ollama => complete_ollama(cfg, system, prompt),
        AiProvider::Openai => complete_openai(cfg, api_key, system, prompt),
        AiProvider::Anthropic => complete_anthropic(cfg, api_key, system, prompt),
        AiProvider::Azure => complete_azure(cfg, api_key, system, prompt),
        AiProvider::Gemini => complete_gemini(cfg, api_key, system, prompt),
    }
}

/// List the model identifiers advertised by the configured provider.
///
/// This is a convenience for the settings UI — it is *not* required for the app
/// to function. Each provider exposes its own listing endpoint and JSON shape;
/// failures surface as a clear [`AppError::Ai`].
pub fn list_models(cfg: &AiConfig, api_key: Option<&str>) -> AppResult<Vec<String>> {
    validate_base_url(cfg)?;
    match cfg.provider {
        AiProvider::Ollama => list_models_ollama(cfg),
        AiProvider::Openai => list_models_openai(cfg, api_key),
        AiProvider::Anthropic => list_models_anthropic(cfg, api_key),
        AiProvider::Azure => list_models_azure(cfg, api_key),
        AiProvider::Gemini => list_models_gemini(cfg, api_key),
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

/// Whether `host` is a loopback / localhost name, where plain `http` is
/// acceptable even for cloud-style providers (local OpenAI-compatible servers,
/// reverse proxies, dev setups). Strips an optional `:port` and IPv6 brackets.
fn is_loopback_host(host: &str) -> bool {
    // Drop a port suffix. For bracketed IPv6 (`[::1]:443`) split on the `]`.
    let host = if let Some(rest) = host.strip_prefix('[') {
        // `[::1]` or `[::1]:port` -> `::1`
        rest.split(']').next().unwrap_or(rest)
    } else {
        // `host` or `host:port` -> `host`
        host.split(':').next().unwrap_or(host)
    };
    let host = host.to_ascii_lowercase();
    host == "localhost" || host == "127.0.0.1" || host == "::1" || host.starts_with("127.")
}

/// Validate `cfg.base_url` before issuing any request (SSRF / scheme guard).
///
/// Rules:
/// - The URL MUST have a `http://` or `https://` scheme and a non-empty host —
///   any other scheme (`file:`, `ftp:`, `gopher:`, `data:`, …) is rejected.
/// - Cloud providers (OpenAI / Anthropic / Azure / Gemini) MUST use `https`,
///   UNLESS the host is loopback/localhost (so local OpenAI-compatible servers
///   over http work).
/// - Ollama (local by design) may use plain `http` to any host.
fn validate_base_url(cfg: &AiConfig) -> AppResult<()> {
    let raw = cfg.base_url.trim();

    // Split scheme from the rest. We don't pull in the `url` crate (not a direct
    // dependency); a minimal scheme+host parse is enough for this guard.
    let (scheme, rest) = match raw.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase(), r),
        None => {
            return Err(AppError::Ai(format!(
                "AI base URL '{raw}' is not a valid http(s) URL"
            )))
        }
    };

    let is_https = match scheme.as_str() {
        "https" => true,
        "http" => false,
        other => {
            return Err(AppError::Ai(format!(
                "AI base URL scheme '{other}' is not allowed — only http and https are supported"
            )))
        }
    };

    // Authority is everything up to the first `/`, `?` or `#`.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    // Strip any `user:pass@` credentials prefix before the host.
    let host = authority.rsplit('@').next().unwrap_or(authority);
    if host.is_empty() {
        return Err(AppError::Ai(format!("AI base URL '{raw}' has no host")));
    }

    // Cloud providers must use TLS unless talking to a local server.
    if !is_https
        && matches!(
            cfg.provider,
            AiProvider::Openai | AiProvider::Anthropic | AiProvider::Azure | AiProvider::Gemini
        )
        && !is_loopback_host(host)
    {
        return Err(AppError::Ai(format!(
            "cloud AI providers require an https:// base URL (got '{raw}'); \
                 plain http is only allowed for localhost"
        )));
    }

    Ok(())
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

/// Whether a `ureq` error is worth retrying: HTTP 429, any 5xx, or a
/// transport-level failure (connection reset, timeout, …). Other 4xx are
/// permanent (bad request, auth, not found) and must fail fast.
fn is_retryable(err: &ureq::Error) -> bool {
    match err {
        ureq::Error::Status(code, _) => *code == 429 || (500..=599).contains(code),
        ureq::Error::Transport(_) => true,
    }
}

/// Parse a `Retry-After` header value (RFC 7231): an integer number of seconds.
/// We deliberately ignore the HTTP-date form (rare for these APIs) and return
/// `None` for anything we can't read as whole seconds.
fn parse_retry_after_secs(value: &str) -> Option<u64> {
    value.trim().parse::<u64>().ok()
}

/// Run a provider HTTP call with retry + exponential backoff.
///
/// `call` is invoked up to [`MAX_ATTEMPTS`] times. It returns the raw `ureq`
/// `Response` so we can read a `Retry-After` header on a 429 before backing off
/// (a `ureq::Error::Status` still carries the response). On a retryable failure
/// we sleep `min(BACKOFF_BASE_MS * 2^attempt, BACKOFF_MAX_MS)` — or the
/// server's `Retry-After` when larger — then try again. The final error is
/// mapped to a clear [`AppError::Ai`] via [`map_ureq_err`].
fn with_retry<F>(provider: &str, mut call: F) -> AppResult<ureq::Response>
where
    F: FnMut() -> Result<ureq::Response, ureq::Error>,
{
    let mut attempt: u32 = 0;
    loop {
        match call() {
            Ok(resp) => return Ok(resp),
            Err(err) => {
                let last = attempt + 1 >= MAX_ATTEMPTS;
                if last || !is_retryable(&err) {
                    return Err(map_ureq_err(provider, err));
                }
                // Honor Retry-After (seconds) on a 429 if it's larger than our
                // computed exponential backoff.
                let retry_after_ms = match &err {
                    ureq::Error::Status(_, resp) => resp
                        .header("Retry-After")
                        .and_then(parse_retry_after_secs)
                        .map(|s| s.saturating_mul(1000)),
                    ureq::Error::Transport(_) => None,
                };
                let backoff = BACKOFF_BASE_MS.saturating_mul(1u64 << attempt);
                let sleep_ms = retry_after_ms
                    .unwrap_or(backoff)
                    .max(backoff)
                    .min(BACKOFF_MAX_MS);
                std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
                attempt += 1;
            }
        }
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

/// Parse a `ureq::Response` body as JSON, with a clear provider-tagged error.
fn into_json(provider: &str, resp: ureq::Response) -> AppResult<Value> {
    resp.into_json()
        .map_err(|e| AppError::Ai(format!("{provider} returned invalid JSON: {e}")))
}

/// Collect a list of model ids from `resp[array_ptr][].field`, skipping any
/// entries that lack a (non-empty) string at `field`. Errors clearly if the
/// pointed-at value isn't an array.
fn collect_model_names(
    provider: &str,
    resp: &Value,
    array_ptr: &str,
    field: &str,
) -> AppResult<Vec<String>> {
    let arr = resp
        .pointer(array_ptr)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            AppError::Ai(format!(
                "{provider} returned an unexpected response shape (no model list)"
            ))
        })?;
    let names: Vec<String> = arr
        .iter()
        .filter_map(|m| m.get(field).and_then(Value::as_str))
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    Ok(names)
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
        "options": { "num_predict": cfg.max_tokens },
    });
    let resp = with_retry("Ollama", || agent().post(&url).send_json(body.clone()))?;
    let resp = into_json("Ollama", resp)?;
    require_text("Ollama", resp.pointer("/message/content"))
}

/// OpenAI-compatible: `POST {base_url}/v1/chat/completions`, non-streaming →
/// `.choices[0].message.content`. The API key is OPTIONAL (keyless local
/// servers like LM Studio): `Authorization` is only sent when a key is present.
fn complete_openai(
    cfg: &AiConfig,
    api_key: Option<&str>,
    system: Option<&str>,
    prompt: &str,
) -> AppResult<String> {
    let url = format!("{}/v1/chat/completions", base(cfg));
    let key = api_key.filter(|k| !k.is_empty());
    let body = json!({
        "model": cfg.model,
        "messages": chat_messages(system, prompt),
        "max_tokens": cfg.max_tokens,
    });
    let resp = with_retry("OpenAI", || {
        let mut req = agent().post(&url);
        if let Some(k) = key {
            req = req.set("Authorization", &format!("Bearer {k}"));
        }
        req.send_json(body.clone())
    })?;
    let resp = into_json("OpenAI", resp)?;
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
        "max_tokens": cfg.max_tokens,
        "messages": [{ "role": "user", "content": prompt }],
    });
    if let Some(sys) = system {
        if !sys.is_empty() {
            body["system"] = json!(sys);
        }
    }
    let resp = with_retry("Anthropic", || {
        agent()
            .post(&url)
            .set("x-api-key", key)
            .set("anthropic-version", "2023-06-01")
            .send_json(body.clone())
    })?;
    let resp = into_json("Anthropic", resp)?;
    require_text("Anthropic", resp.pointer("/content/0/text"))
}

/// Azure OpenAI: `POST {base_url}/openai/deployments/{model}/chat/completions`
/// `?api-version=...` with an `api-key` header, non-streaming →
/// `.choices[0].message.content`. Requires a key (and https unless loopback).
fn complete_azure(
    cfg: &AiConfig,
    api_key: Option<&str>,
    system: Option<&str>,
    prompt: &str,
) -> AppResult<String> {
    let key = require_key("Azure OpenAI", api_key)?;
    let url = format!(
        "{}/openai/deployments/{}/chat/completions?api-version={}",
        base(cfg),
        cfg.model,
        cfg.azure_api_version()
    );
    let body = json!({
        "messages": chat_messages(system, prompt),
        "max_tokens": cfg.max_tokens,
    });
    let resp = with_retry("Azure OpenAI", || {
        agent()
            .post(&url)
            .set("api-key", key)
            .send_json(body.clone())
    })?;
    let resp = into_json("Azure OpenAI", resp)?;
    require_text("Azure OpenAI", resp.pointer("/choices/0/message/content"))
}

/// Google Gemini: `POST {base_url}/v1beta/models/{model}:generateContent`
/// `?key={key}`, non-streaming → `.candidates[0].content.parts[0].text`. The
/// system prompt (if any) goes in `systemInstruction`. Requires a key + https.
fn complete_gemini(
    cfg: &AiConfig,
    api_key: Option<&str>,
    system: Option<&str>,
    prompt: &str,
) -> AppResult<String> {
    let key = require_key("Gemini", api_key)?;
    let url = format!(
        "{}/v1beta/models/{}:generateContent?key={}",
        base(cfg),
        cfg.model,
        key
    );
    let mut body = json!({
        "contents": [{ "role": "user", "parts": [{ "text": prompt }] }],
        "generationConfig": { "maxOutputTokens": cfg.max_tokens },
    });
    if let Some(sys) = system {
        if !sys.is_empty() {
            body["systemInstruction"] = json!({ "parts": [{ "text": sys }] });
        }
    }
    let resp = with_retry("Gemini", || agent().post(&url).send_json(body.clone()))?;
    let resp = into_json("Gemini", resp)?;
    require_text("Gemini", resp.pointer("/candidates/0/content/parts/0/text"))
}

/// Ollama: `GET {base_url}/api/tags` → `.models[].name`.
fn list_models_ollama(cfg: &AiConfig) -> AppResult<Vec<String>> {
    let url = format!("{}/api/tags", base(cfg));
    let resp = with_retry("Ollama", || agent().get(&url).call())?;
    let resp = into_json("Ollama", resp)?;
    collect_model_names("Ollama", &resp, "/models", "name")
}

/// OpenAI-compatible: `GET {base_url}/v1/models` (Bearer if a key is set) →
/// `.data[].id`.
fn list_models_openai(cfg: &AiConfig, api_key: Option<&str>) -> AppResult<Vec<String>> {
    let url = format!("{}/v1/models", base(cfg));
    let key = api_key.filter(|k| !k.is_empty());
    let resp = with_retry("OpenAI", || {
        let mut req = agent().get(&url);
        if let Some(k) = key {
            req = req.set("Authorization", &format!("Bearer {k}"));
        }
        req.call()
    })?;
    let resp = into_json("OpenAI", resp)?;
    collect_model_names("OpenAI", &resp, "/data", "id")
}

/// Anthropic: `GET {base_url}/v1/models` (x-api-key + anthropic-version) →
/// `.data[].id`.
fn list_models_anthropic(cfg: &AiConfig, api_key: Option<&str>) -> AppResult<Vec<String>> {
    let key = require_key("Anthropic", api_key)?;
    let url = format!("{}/v1/models", base(cfg));
    let resp = with_retry("Anthropic", || {
        agent()
            .get(&url)
            .set("x-api-key", key)
            .set("anthropic-version", "2023-06-01")
            .call()
    })?;
    let resp = into_json("Anthropic", resp)?;
    collect_model_names("Anthropic", &resp, "/data", "id")
}

/// Azure OpenAI: `GET {base_url}/openai/models?api-version=...` (api-key header)
/// → `.data[].id`.
fn list_models_azure(cfg: &AiConfig, api_key: Option<&str>) -> AppResult<Vec<String>> {
    let key = require_key("Azure OpenAI", api_key)?;
    let url = format!(
        "{}/openai/models?api-version={}",
        base(cfg),
        cfg.azure_api_version()
    );
    let resp = with_retry("Azure OpenAI", || {
        agent().get(&url).set("api-key", key).call()
    })?;
    let resp = into_json("Azure OpenAI", resp)?;
    collect_model_names("Azure OpenAI", &resp, "/data", "id")
}

/// Gemini: `GET {base_url}/v1beta/models?key=...` → `.models[].name`.
fn list_models_gemini(cfg: &AiConfig, api_key: Option<&str>) -> AppResult<Vec<String>> {
    let key = require_key("Gemini", api_key)?;
    let url = format!("{}/v1beta/models?key={}", base(cfg), key);
    let resp = with_retry("Gemini", || agent().get(&url).call())?;
    let resp = into_json("Gemini", resp)?;
    collect_model_names("Gemini", &resp, "/models", "name")
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

    fn cfg_with(provider: AiProvider, base_url: &str) -> AiConfig {
        AiConfig {
            provider,
            base_url: base_url.to_string(),
            ..AiConfig::default()
        }
    }

    #[test]
    fn validate_rejects_non_http_schemes() {
        for url in [
            "file:///etc/passwd",
            "ftp://host/x",
            "gopher://h",
            "data:text/plain,hi",
        ] {
            let err = validate_base_url(&cfg_with(AiProvider::Ollama, url)).unwrap_err();
            assert!(matches!(err, AppError::Ai(_)), "{url} should be rejected");
        }
    }

    #[test]
    fn validate_rejects_garbage_and_missing_host() {
        assert!(validate_base_url(&cfg_with(AiProvider::Ollama, "not-a-url")).is_err());
        assert!(validate_base_url(&cfg_with(AiProvider::Openai, "https://")).is_err());
    }

    #[test]
    fn validate_cloud_requires_https_except_localhost() {
        // Cloud over plain http to a remote host: rejected.
        assert!(validate_base_url(&cfg_with(AiProvider::Openai, "http://api.openai.com")).is_err());
        assert!(
            validate_base_url(&cfg_with(AiProvider::Anthropic, "http://api.anthropic.com"))
                .is_err()
        );
        // Cloud over https: allowed.
        assert!(validate_base_url(&cfg_with(AiProvider::Openai, "https://api.openai.com")).is_ok());
        // Cloud over http to localhost / loopback: allowed (local OpenAI server).
        assert!(validate_base_url(&cfg_with(AiProvider::Openai, "http://localhost:8080")).is_ok());
        assert!(
            validate_base_url(&cfg_with(AiProvider::Openai, "http://127.0.0.1:1234/v1")).is_ok()
        );
        assert!(validate_base_url(&cfg_with(AiProvider::Openai, "http://[::1]:1234")).is_ok());
    }

    #[test]
    fn validate_ollama_allows_http_anywhere() {
        assert!(validate_base_url(&cfg_with(AiProvider::Ollama, "http://localhost:11434")).is_ok());
        assert!(
            validate_base_url(&cfg_with(AiProvider::Ollama, "http://192.168.1.5:11434")).is_ok()
        );
    }

    #[test]
    fn validate_new_cloud_providers_require_https_except_localhost() {
        // Azure / Gemini over plain http to a remote host: rejected.
        assert!(
            validate_base_url(&cfg_with(AiProvider::Azure, "http://my.openai.azure.com")).is_err()
        );
        assert!(validate_base_url(&cfg_with(
            AiProvider::Gemini,
            "http://generativelanguage.googleapis.com"
        ))
        .is_err());
        // Over https: allowed.
        assert!(
            validate_base_url(&cfg_with(AiProvider::Azure, "https://my.openai.azure.com")).is_ok()
        );
        assert!(validate_base_url(&cfg_with(
            AiProvider::Gemini,
            "https://generativelanguage.googleapis.com"
        ))
        .is_ok());
        // Over http to loopback: allowed (proxy / dev).
        assert!(validate_base_url(&cfg_with(AiProvider::Azure, "http://localhost:8080")).is_ok());
        assert!(validate_base_url(&cfg_with(AiProvider::Gemini, "http://127.0.0.1:9000")).is_ok());
    }

    #[test]
    fn openai_key_is_optional() {
        // Unlike Anthropic/Azure/Gemini, the OpenAI provider must NOT hard-require
        // a key (keyless local servers). require_key is only used by the others.
        assert!(require_key("Anthropic", None).is_err());
        assert!(require_key("Azure OpenAI", None).is_err());
        assert!(require_key("Gemini", None).is_err());
    }

    #[test]
    fn retryable_only_for_429_5xx_and_transport() {
        // Build Status errors via the public ureq constructor.
        let resp_429 = ureq::Response::new(429, "Too Many Requests", "slow down").unwrap();
        let resp_500 = ureq::Response::new(500, "Server Error", "boom").unwrap();
        let resp_503 = ureq::Response::new(503, "Unavailable", "later").unwrap();
        let resp_400 = ureq::Response::new(400, "Bad Request", "nope").unwrap();
        let resp_401 = ureq::Response::new(401, "Unauthorized", "key?").unwrap();
        let resp_404 = ureq::Response::new(404, "Not Found", "missing").unwrap();

        assert!(is_retryable(&ureq::Error::Status(429, resp_429)));
        assert!(is_retryable(&ureq::Error::Status(500, resp_500)));
        assert!(is_retryable(&ureq::Error::Status(503, resp_503)));
        assert!(!is_retryable(&ureq::Error::Status(400, resp_400)));
        assert!(!is_retryable(&ureq::Error::Status(401, resp_401)));
        assert!(!is_retryable(&ureq::Error::Status(404, resp_404)));
    }

    #[test]
    fn retry_after_parses_seconds_only() {
        assert_eq!(parse_retry_after_secs("5"), Some(5));
        assert_eq!(parse_retry_after_secs("  12 "), Some(12));
        assert_eq!(parse_retry_after_secs("0"), Some(0));
        // HTTP-date form and garbage are ignored (fall back to exponential).
        assert_eq!(
            parse_retry_after_secs("Wed, 21 Oct 2025 07:28:00 GMT"),
            None
        );
        assert_eq!(parse_retry_after_secs("soon"), None);
        assert_eq!(parse_retry_after_secs(""), None);
    }

    #[test]
    fn collect_model_names_extracts_and_filters() {
        // OpenAI/Anthropic/Azure shape: .data[].id
        let v = json!({
            "data": [
                { "id": "gpt-4o" },
                { "id": "" },
                { "name": "no-id-here" },
                { "id": "gpt-4o-mini" },
            ]
        });
        let names = collect_model_names("OpenAI", &v, "/data", "id").unwrap();
        assert_eq!(names, vec!["gpt-4o", "gpt-4o-mini"]);

        // Ollama/Gemini shape: .models[].name
        let v = json!({ "models": [ { "name": "llama3.1" }, { "name": "qwen2" } ] });
        let names = collect_model_names("Ollama", &v, "/models", "name").unwrap();
        assert_eq!(names, vec!["llama3.1", "qwen2"]);

        // Wrong shape errors clearly.
        let v = json!({ "data": "not-an-array" });
        assert!(collect_model_names("OpenAI", &v, "/data", "id").is_err());
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
