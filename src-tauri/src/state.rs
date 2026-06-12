//! Shared application state: the (optionally) unlocked vault behind a Mutex.
//!
//! Commands are **synchronous** so the `MutexGuard` is never held across an
//! `await` — rusqlite's `Connection` is not `Sync`, and synchronous commands
//! sidestep that entirely.

use std::sync::Mutex;

use rusqlite::Connection;

use crate::error::{AppError, AppResult};

/// The live, decrypted vault. Exists only while unlocked.
pub struct Vault {
    pub conn: Connection,
}

/// Tauri-managed state. `vault` is `None` until `create_vault`/`unlock_vault`.
#[derive(Default)]
pub struct AppState {
    pub vault: Mutex<Option<Vault>>,
}

impl AppState {
    /// Run `f` with a reference to the unlocked connection, or fail with
    /// [`AppError::VaultLocked`] if nothing is unlocked. The lock is held only
    /// for the duration of `f` (synchronous — no await across the guard).
    pub fn with_conn<T>(&self, f: impl FnOnce(&Connection) -> AppResult<T>) -> AppResult<T> {
        let guard = self.vault.lock().expect("vault mutex poisoned");
        match guard.as_ref() {
            Some(v) => f(&v.conn),
            None => Err(AppError::VaultLocked),
        }
    }

    /// Like [`with_conn`](Self::with_conn) but yields a mutable connection,
    /// required for transactions (e.g. reorder).
    pub fn with_conn_mut<T>(
        &self,
        f: impl FnOnce(&mut Connection) -> AppResult<T>,
    ) -> AppResult<T> {
        let mut guard = self.vault.lock().expect("vault mutex poisoned");
        match guard.as_mut() {
            Some(v) => f(&mut v.conn),
            None => Err(AppError::VaultLocked),
        }
    }

    /// Whether a vault is currently unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.vault
            .lock()
            .expect("vault mutex poisoned")
            .is_some()
    }

    /// Install a freshly opened connection as the active vault.
    pub fn set_vault(&self, conn: Connection) {
        *self.vault.lock().expect("vault mutex poisoned") = Some(Vault { conn });
    }

    /// Drop the active vault (lock).
    pub fn clear(&self) {
        *self.vault.lock().expect("vault mutex poisoned") = None;
    }
}
