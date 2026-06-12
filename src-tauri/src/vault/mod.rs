//! Encrypted-vault subsystem: the SQLCipher connection, schema bootstrap,
//! canary-based passphrase validation, and (best-effort) OS keychain storage.

pub mod connection;
pub mod keychain;
pub mod schema;

/// Service identifier used for the OS keychain entry.
pub const KEYCHAIN_SERVICE: &str = "fr.own2pwn.pwn2report";
/// Account/entry name under the service.
pub const KEYCHAIN_ENTRY: &str = "vault-passphrase";

/// Canary row stored in `meta` to validate the passphrase on unlock.
pub const CANARY_KEY: &str = "canary";
pub const CANARY_VALUE: &str = "pwn2report-v1";
