//! Open / create the SQLCipher-encrypted vault database.
//!
//! SQLCipher requires `PRAGMA key` to be the very first statement on a fresh
//! connection — before any schema or query touches the encrypted pages. A
//! wrong key does not error on the PRAGMA itself; it fails on the first real
//! read. We therefore validate with an explicit canary row.

use std::path::Path;

use rusqlite::Connection;

use super::{schema, CANARY_KEY, CANARY_VALUE};
use crate::error::{AppError, AppResult};

/// Escape a passphrase for inline use inside `PRAGMA key = '...'` by doubling
/// embedded single quotes. (rusqlite cannot bind parameters to PRAGMAs.)
fn escape_passphrase(p: &str) -> String {
    p.replace('\'', "''")
}

/// Apply the SQLCipher key + standard pragmas to a freshly opened connection.
fn key_connection(conn: &Connection, passphrase: &str) -> AppResult<()> {
    let escaped = escape_passphrase(passphrase);
    // MUST be the first statement executed on this connection.
    conn.execute_batch(&format!("PRAGMA key = '{escaped}';"))?;
    // Enforce FK cascades (findings -> reports).
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    Ok(())
}

/// Create a brand-new encrypted vault at `path`, install the schema, and seed
/// the canary row. Caller guarantees the file does not already exist.
pub fn create_encrypted(path: &Path, passphrase: &str) -> AppResult<Connection> {
    let conn = Connection::open(path)?;
    key_connection(&conn, passphrase)?;
    schema::init(&conn)?;
    // Seed the canary so future unlocks can validate the passphrase.
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES (?1, ?2)",
        rusqlite::params![CANARY_KEY, CANARY_VALUE],
    )?;
    Ok(conn)
}

/// Verify a passphrase against an existing vault WITHOUT mutating it.
///
/// Opens a throwaway connection, keys it, and reads the canary. Unlike
/// [`open_encrypted`] this performs no schema write, so it is safe to call
/// while the live connection is open (e.g. to re-verify the old passphrase
/// before a rekey). Returns `WrongPassphrase` on a bad key.
pub fn verify_passphrase(path: &Path, passphrase: &str) -> AppResult<()> {
    let conn = Connection::open(path)?;
    key_connection(&conn, passphrase)?;
    let canary: Result<String, rusqlite::Error> = conn.query_row(
        "SELECT value FROM meta WHERE key = ?1",
        rusqlite::params![CANARY_KEY],
        |row| row.get(0),
    );
    match canary {
        Ok(v) if v == CANARY_VALUE => Ok(()),
        _ => Err(AppError::WrongPassphrase),
    }
}

/// Open an existing encrypted vault and validate the passphrase via the canary.
///
/// On a wrong key, reading `meta` errors ("file is not a database" / HMAC
/// failure) or returns no row; both map to [`AppError::WrongPassphrase`].
pub fn open_encrypted(path: &Path, passphrase: &str) -> AppResult<Connection> {
    let conn = Connection::open(path)?;
    key_connection(&conn, passphrase)?;

    // First real read against an encrypted page — this is where a wrong key
    // surfaces. Treat any error here as a bad passphrase rather than leaking
    // the raw SQLite message.
    let canary: Result<String, rusqlite::Error> = conn.query_row(
        "SELECT value FROM meta WHERE key = ?1",
        rusqlite::params![CANARY_KEY],
        |row| row.get(0),
    );

    match canary {
        Ok(v) if v == CANARY_VALUE => {
            // Make sure the schema is current even on an older vault file.
            schema::init(&conn)?;
            Ok(conn)
        }
        Ok(_) => Err(AppError::WrongPassphrase),
        Err(_) => Err(AppError::WrongPassphrase),
    }
}
