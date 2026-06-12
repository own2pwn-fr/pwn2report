//! Best-effort OS keychain storage for the AI cloud API key.
//!
//! Reuses the same keyring service as the vault (`fr.own2pwn.pwn2report`) under
//! a distinct entry so the (sensitive) API key never lands in the plaintext
//! `ai.json` config. Mirrors the graceful-degradation contract of
//! [`crate::vault::keychain`]: nothing here ever panics or blocks. On a
//! missing / unusable credential store, `store`/`delete` return `Ok(false)`
//! and `get` returns `Ok(None)`.

use keyring::Entry;

use crate::vault::KEYCHAIN_SERVICE;

/// Account/entry name for the AI API key under the shared service.
pub const AI_KEY_ENTRY: &str = "ai-api-key";

/// Build the keyring entry handle, or `None` if the platform has no store.
fn entry() -> Option<Entry> {
    Entry::new(KEYCHAIN_SERVICE, AI_KEY_ENTRY).ok()
}

/// Persist the API key. Returns `Ok(true)` on success, `Ok(false)` if the
/// keychain rejected the write or is unavailable.
pub fn store(api_key: &str) -> Result<bool, ()> {
    match entry() {
        Some(e) => Ok(e.set_password(api_key).is_ok()),
        None => Ok(false),
    }
}

/// Read the stored API key, or `Ok(None)` if absent / store unavailable.
pub fn get() -> Result<Option<String>, ()> {
    match entry() {
        Some(e) => match e.get_password() {
            Ok(k) => Ok(Some(k)),
            Err(_) => Ok(None),
        },
        None => Ok(None),
    }
}

/// Delete the stored API key. Idempotent: a missing entry is success.
pub fn delete() -> Result<bool, ()> {
    match entry() {
        Some(e) => match e.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(true),
            Err(_) => Ok(false),
        },
        None => Ok(false),
    }
}

/// Whether an API key is currently present in the keychain.
pub fn has_key() -> bool {
    matches!(get(), Ok(Some(ref k)) if !k.is_empty())
}
