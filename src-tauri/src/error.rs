//! Application-wide error type.
//!
//! Every `#[tauri::command]` returns `Result<T, AppError>`. The error is
//! serialized to a stable `{ "kind": "...", "message": "..." }` shape so the
//! frontend can `switch` on `kind` without parsing English prose.

use serde::ser::{Serialize, SerializeStruct, Serializer};
use thiserror::Error;

/// All failure modes the backend can surface to the UI.
#[derive(Debug, Error)]
pub enum AppError {
    /// No vault is currently unlocked (no in-memory connection).
    #[error("vault is locked")]
    VaultLocked,

    /// The supplied passphrase did not decrypt the vault (canary mismatch).
    #[error("wrong passphrase")]
    WrongPassphrase,

    /// A requested entity (report / finding) does not exist.
    #[error("not found")]
    NotFound,

    /// A database / SQLite error. The string is the underlying message.
    #[error("database error: {0}")]
    Db(String),

    /// A rendering (Typst / PDF) error.
    #[error("render error: {0}")]
    Render(String),

    /// A pandoc (DOCX conversion) error: pandoc not found on PATH or it failed.
    #[error("pandoc error: {0}")]
    Pandoc(String),

    /// A filesystem I/O error (template files, vault backup, temp files).
    #[error("io error: {0}")]
    Io(String),

    /// An OS keychain error (kept rare — keychain ops degrade gracefully, so
    /// this is part of the error surface for future use rather than hot today).
    #[allow(dead_code)]
    #[error("keychain error: {0}")]
    Keychain(String),

    /// A (de)serialization error for JSON sub-objects.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// A scanner-import parse failure (unknown format, malformed input).
    #[error("import error: {0}")]
    Import(String),

    /// An AI-assistance failure: disabled/unconfigured, transport error, or an
    /// unexpected provider response. The string is a clear, user-facing message
    /// (usually including the provider name and HTTP status).
    #[error("AI error: {0}")]
    Ai(String),

    /// A sync-bundle failure: encryption/decryption error (e.g. a wrong
    /// passphrase), a malformed bundle, or an unsupported bundle version. The
    /// string is a clear, user-facing message.
    #[error("sync error: {0}")]
    Sync(String),
}

impl AppError {
    /// Machine-readable discriminant the frontend switches on.
    fn kind(&self) -> &'static str {
        match self {
            AppError::VaultLocked => "vault_locked",
            AppError::WrongPassphrase => "wrong_passphrase",
            AppError::NotFound => "not_found",
            AppError::Db(_) => "db",
            AppError::Render(_) => "render",
            AppError::Pandoc(_) => "pandoc",
            AppError::Io(_) => "io",
            AppError::Keychain(_) => "keychain",
            AppError::Serialization(_) => "serialization",
            AppError::Import(_) => "import",
            AppError::Ai(_) => "ai",
            AppError::Sync(_) => "sync",
        }
    }
}

/// Emit `{ "kind": "...", "message": "..." }`.
impl Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("AppError", 2)?;
        s.serialize_field("kind", self.kind())?;
        s.serialize_field("message", &self.to_string())?;
        s.end()
    }
}

/// Map rusqlite errors into `AppError`. A wrong SQLCipher key surfaces as a
/// generic SQLite error on the first real query; the canary check upgrades
/// that to `WrongPassphrase` explicitly, so here we keep it as `Db`.
impl From<rusqlite::Error> for AppError {
    fn from(e: rusqlite::Error) -> Self {
        AppError::Db(e.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError::Serialization(e.to_string())
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::Io(e.to_string())
    }
}

/// Convenience alias used throughout the backend.
pub type AppResult<T> = Result<T, AppError>;
