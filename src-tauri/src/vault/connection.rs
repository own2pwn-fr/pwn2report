//! Open / create the SQLCipher-encrypted vault database.
//!
//! SQLCipher requires `PRAGMA key` to be the very first statement on a fresh
//! connection — before any schema or query touches the encrypted pages. A
//! wrong key does not error on the PRAGMA itself; it fails on the first real
//! read. We therefore validate with an explicit canary row.

use std::path::Path;

use rusqlite::Connection;

use super::schema::SCHEMA_VERSION;
use super::{schema, CANARY_KEY, CANARY_VALUE};
use crate::error::{AppError, AppResult};

/// Escape a passphrase for inline use inside `PRAGMA key = '...'` by doubling
/// embedded single quotes. (rusqlite cannot bind parameters to PRAGMAs.)
fn escape_passphrase(p: &str) -> String {
    p.replace('\'', "''")
}

/// Apply the SQLCipher key + standard hardening pragmas to a freshly opened
/// connection. Used by BOTH the create and open paths so every live connection
/// gets the same durability/security posture.
///
/// Ordering is load-bearing: `PRAGMA key` MUST be the very first statement on the
/// connection (SQLCipher requirement); the hardening pragmas only take effect
/// once the connection is keyed.
fn key_connection(conn: &Connection, passphrase: &str) -> AppResult<()> {
    let escaped = escape_passphrase(passphrase);
    // MUST be the first statement executed on this connection.
    conn.execute_batch(&format!("PRAGMA key = '{escaped}';"))?;
    // Hardening, applied after the key. NOTE: we deliberately stay in the default
    // rollback-journal (DELETE) mode — SQLCipher's `PRAGMA rekey` (used by
    // change_passphrase) does NOT work reliably under WAL, so enabling WAL would
    // silently break passphrase changes. The marginal WAL concurrency win isn't
    // worth it for a single-connection desktop app.
    //  - busy_timeout: wait instead of failing fast under a transient lock.
    //  - secure_delete: overwrite freed pages, reducing plaintext-adjacent residue.
    //  - foreign_keys: enforce FK cascades (findings -> reports, etc.).
    conn.execute_batch(
        "PRAGMA busy_timeout = 5000;\
         PRAGMA secure_delete = ON;\
         PRAGMA foreign_keys = ON;",
    )?;
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
            // Forward-compat guard: a vault stamped with a NEWER schema than
            // this build understands must not be opened — applying our (older)
            // migrations / writing our row shapes could silently corrupt data
            // the newer version added. Refuse loudly instead of downgrading.
            let db_version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
            if db_version > SCHEMA_VERSION {
                return Err(AppError::IncompatibleVault(format!(
                    "vault schema version {db_version} is newer than this app supports \
                     ({SCHEMA_VERSION}); upgrade pwn2report to open it"
                )));
            }
            // Otherwise bring an older vault file up to the current schema.
            schema::init(&conn)?;
            Ok(conn)
        }
        Ok(_) => Err(AppError::WrongPassphrase),
        Err(_) => Err(AppError::WrongPassphrase),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "pwn2report-conn-{name}-{}.db",
            uuid::Uuid::new_v4()
        ));
        p
    }

    /// A fresh vault is stamped at the current schema version and applies the
    /// hardening pragmas (secure_delete + foreign_keys; rollback-journal mode is
    /// kept so SQLCipher rekey works).
    #[test]
    fn create_stamps_version_and_hardening_pragmas() {
        let path = tmp("create");
        let conn = create_encrypted(&path, "pw").unwrap();

        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);

        let journal: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_ne!(journal.to_lowercase(), "wal", "WAL breaks SQLCipher rekey");

        let secure_delete: i64 = conn
            .query_row("PRAGMA secure_delete", [], |r| r.get(0))
            .unwrap();
        assert_eq!(secure_delete, 1);

        let fk: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(fk, 1);

        let _ = std::fs::remove_file(&path);
    }

    /// Opening a vault whose on-disk schema is NEWER than this build refuses with
    /// `IncompatibleVault` rather than silently downgrading.
    #[test]
    fn open_rejects_a_newer_schema_vault() {
        let path = tmp("newer");
        {
            let conn = create_encrypted(&path, "pw").unwrap();
            // Simulate a future app bumping the schema past what we understand.
            conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
                .unwrap();
        }
        let err = open_encrypted(&path, "pw").unwrap_err();
        assert!(
            matches!(err, AppError::IncompatibleVault(_)),
            "expected IncompatibleVault, got {err:?}"
        );

        let _ = std::fs::remove_file(&path);
    }
}
