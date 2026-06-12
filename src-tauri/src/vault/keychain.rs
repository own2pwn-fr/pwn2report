//! Best-effort OS keychain integration (keyring 3.x).
//!
//! Every operation degrades gracefully: if no secret service / keychain is
//! available (headless Linux, locked login keyring, CI) we never panic and
//! never block the unlock flow. `store`/`delete` return `Ok(false)` on
//! failure, `get` returns `Ok(None)`, and `available()` reflects whether the
//! platform exposes a usable credential store.

use keyring::Entry;

use super::{KEYCHAIN_ENTRY, KEYCHAIN_SERVICE};

/// Build the keyring entry handle, or `None` if the platform has no store.
fn entry() -> Option<Entry> {
    Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ENTRY).ok()
}

/// Whether an OS credential store appears usable. We probe by attempting a
/// read: `Err(NoEntry)` still means the service is reachable (just empty),
/// whereas a platform/no-backend error means unavailable.
pub fn available() -> bool {
    match entry() {
        Some(e) => !matches!(
            e.get_password(),
            Err(keyring::Error::PlatformFailure(_)) | Err(keyring::Error::NoStorageAccess(_))
        ),
        None => false,
    }
}

/// Persist the passphrase. Returns `Ok(true)` on success, `Ok(false)` if the
/// keychain rejected the write (treated as "remember unavailable").
pub fn store(passphrase: &str) -> Result<bool, ()> {
    match entry() {
        Some(e) => Ok(e.set_password(passphrase).is_ok()),
        None => Ok(false),
    }
}

/// Read the stored passphrase, or `Ok(None)` if absent / store unavailable.
pub fn get() -> Result<Option<String>, ()> {
    match entry() {
        Some(e) => match e.get_password() {
            Ok(p) => Ok(Some(p)),
            Err(_) => Ok(None),
        },
        None => Ok(None),
    }
}

/// Delete the stored passphrase. Idempotent: a missing entry is success.
pub fn delete() -> Result<bool, ()> {
    match entry() {
        Some(e) => match e.delete_credential() {
            Ok(()) => Ok(true),
            // No entry to delete is fine.
            Err(keyring::Error::NoEntry) => Ok(true),
            Err(_) => Ok(false),
        },
        None => Ok(false),
    }
}
