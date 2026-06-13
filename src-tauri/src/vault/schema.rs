//! Versioned schema migration framework, driven by `PRAGMA user_version`.
//!
//! # How migrations work
//!
//! The vault carries its schema version in `PRAGMA user_version` (an integer
//! stored in the SQLite header — cheap to read, survives encryption). On every
//! unlock [`init`] reads that pragma and applies, in order, the migration steps
//! whose target version is greater than the DB's current version, then stamps
//! `user_version` (and a mirrored `meta.schema_version` row) to
//! [`SCHEMA_VERSION`]. A fresh DB starts at `user_version = 0` and runs every
//! step; an already-current DB reads the pragma and no-ops.
//!
//! # How to add a migration
//!
//! 1. Bump [`SCHEMA_VERSION`].
//! 2. Append a `(version, step_fn)` entry to [`MIGRATIONS`] whose `version`
//!    equals the new [`SCHEMA_VERSION`].
//! 3. Make the step **idempotent** (`CREATE TABLE IF NOT EXISTS`, `ADD COLUMN`
//!    guarded by [`column_exists`], etc.) so a partially-applied / re-run
//!    upgrade converges cleanly. Steps run inside a single transaction so a
//!    failure leaves `user_version` untouched and the upgrade retries on the
//!    next unlock.
//!
//! Never edit an already-shipped step in a way that changes the end state for
//! DBs that already ran it — add a new, higher-versioned step instead.

use rusqlite::Connection;

use crate::error::AppResult;

/// Current schema version. Bump when adding a migration step (see module docs).
pub const SCHEMA_VERSION: i64 = 5;

/// A single idempotent migration step.
type MigrationStep = fn(&Connection) -> AppResult<()>;

/// Ordered migration ladder: each entry's step is applied when the DB's
/// `user_version` is below the entry's `version`. Steps must be idempotent.
const MIGRATIONS: &[(i64, MigrationStep)] = &[
    (1, migrate_v1),
    (2, migrate_v2),
    (3, migrate_v3),
    (4, migrate_v4),
    (5, migrate_v5),
];

/// Apply any pending migrations and stamp the schema version.
///
/// Reads `PRAGMA user_version`; if it already equals [`SCHEMA_VERSION`] this is
/// a no-op. Otherwise every step with `version > current` runs in order inside a
/// single transaction, then `user_version` + the `meta` mirror are bumped.
///
/// Fresh installs (user_version 0) run the whole v1..=v5 ladder; existing v1..v4
/// vaults run only the steps they are missing.
pub fn init(conn: &Connection) -> AppResult<()> {
    let current: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;

    if current == SCHEMA_VERSION {
        return Ok(());
    }

    // Apply pending steps atomically so an interrupted upgrade re-runs cleanly.
    conn.execute_batch("BEGIN")?;
    let apply = || -> AppResult<()> {
        for (version, step) in MIGRATIONS {
            if *version > current {
                step(conn)?;
            }
        }
        Ok(())
    };
    if let Err(e) = apply() {
        let _ = conn.execute_batch("ROLLBACK");
        return Err(e);
    }
    conn.execute_batch("COMMIT")?;

    // Stamp the version (pragma can't run inside the txn portably; do it after).
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?1)",
        rusqlite::params![SCHEMA_VERSION.to_string()],
    )?;

    Ok(())
}

/// True if `table` already has a column named `column`. Used to make ADD COLUMN
/// migrations idempotent (SQLite has no `ADD COLUMN IF NOT EXISTS`).
fn column_exists(conn: &Connection, table: &str, column: &str) -> AppResult<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get("name")?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

/// v1 baseline: `meta`, `reports`, `findings`.
fn migrate_v1(conn: &Connection) -> AppResult<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS reports (
            id           TEXT PRIMARY KEY,
            title        TEXT NOT NULL,
            client       TEXT NOT NULL DEFAULT '',
            report_type  TEXT NOT NULL,
            status       TEXT NOT NULL DEFAULT 'draft',
            exec_summary TEXT NOT NULL DEFAULT '',
            scope        TEXT NOT NULL DEFAULT '',
            methodology  TEXT NOT NULL DEFAULT '',
            created_at   TEXT NOT NULL,
            updated_at   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS findings (
            id            TEXT PRIMARY KEY,
            report_id     TEXT NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
            sort_order    INTEGER NOT NULL DEFAULT 0,
            title         TEXT NOT NULL,
            severity      TEXT NOT NULL,
            confidence    TEXT NOT NULL DEFAULT 'medium',
            kind          TEXT NOT NULL DEFAULT 'manual',
            cwe           TEXT,
            cve           TEXT,
            cvss_vector   TEXT,
            cvss_score    REAL,
            triage_status TEXT NOT NULL DEFAULT 'open',
            triage_note   TEXT,
            description   TEXT NOT NULL DEFAULT '{}',
            remediation   TEXT NOT NULL DEFAULT '{}',
            evidence      TEXT,
            poc           TEXT,
            refs          TEXT NOT NULL DEFAULT '[]',
            tags          TEXT NOT NULL DEFAULT '[]',
            created_at    TEXT NOT NULL,
            updated_at    TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_findings_report
            ON findings(report_id, sort_order);
        "#,
    )?;
    Ok(())
}

/// v2: knowledge-base of reusable, client-neutral finding templates. Same
/// JSON-column shapes as `findings` for description/remediation/tags so a KB
/// entry can be materialised into a report finding 1:1.
fn migrate_v2(conn: &Connection) -> AppResult<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS kb_entries (
            id           TEXT PRIMARY KEY,
            title        TEXT NOT NULL,
            severity     TEXT NOT NULL,
            confidence   TEXT NOT NULL DEFAULT 'medium',
            kind         TEXT NOT NULL DEFAULT 'manual',
            cwe          TEXT,
            cve          TEXT,
            cvss_vector  TEXT,
            cvss_score   REAL,
            description  TEXT NOT NULL DEFAULT '{}',
            remediation  TEXT NOT NULL DEFAULT '{}',
            tags         TEXT NOT NULL DEFAULT '[]',
            created_at   TEXT NOT NULL,
            updated_at   TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_kb_entries_title
            ON kb_entries(title);
        "#,
    )?;
    Ok(())
}

/// v3: per-finding evidence images. Bytes are stored inline in the
/// SQLCipher-encrypted DB (encrypted at rest); `ON DELETE CASCADE` keeps them in
/// lockstep with their parent finding.
fn migrate_v3(conn: &Connection) -> AppResult<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS evidence_images (
            id          TEXT PRIMARY KEY,
            finding_id  TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
            caption     TEXT NOT NULL DEFAULT '',
            mime        TEXT NOT NULL,
            data        BLOB NOT NULL,
            sort_order  INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_evidence_images_finding
            ON evidence_images(finding_id, sort_order);
        "#,
    )?;
    Ok(())
}

/// v4: soft-delete + tombstones. Adds a nullable `deleted_at` column to every
/// syncable table so deletions become rows (tombstones) that travel through the
/// sync bundle and win LWW against older live copies, instead of vanishing
/// locally and resurrecting on the next merge from a peer that never saw the
/// delete. `ADD COLUMN` is guarded by [`column_exists`] for idempotency.
fn migrate_v4(conn: &Connection) -> AppResult<()> {
    for table in ["reports", "findings", "kb_entries", "evidence_images"] {
        if !column_exists(conn, table, "deleted_at")? {
            conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN deleted_at TEXT;"))?;
        }
    }
    Ok(())
}

/// v5: per-report export language. Adds a non-null `language` column to
/// `reports` defaulting to `'en'` so existing rows keep rendering in English.
/// Drives the localized export labels + Typst typography. `ADD COLUMN` is
/// guarded by [`column_exists`] for idempotency.
fn migrate_v5(conn: &Connection) -> AppResult<()> {
    if !column_exists(conn, "reports", "language")? {
        conn.execute_batch("ALTER TABLE reports ADD COLUMN language TEXT NOT NULL DEFAULT 'en';")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    /// A fresh in-memory DB starts at user_version 0; `init` runs the whole
    /// ladder, stamps the version, and is idempotent on a second call.
    #[test]
    fn init_migrates_fresh_db_and_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();

        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        // Every syncable table got the v4 deleted_at column.
        for table in ["reports", "findings", "kb_entries", "evidence_images"] {
            assert!(
                column_exists(&conn, table, "deleted_at").unwrap(),
                "{table}"
            );
        }

        // Second call is a no-op (version already current) and does not error.
        init(&conn).unwrap();
        let v2: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v2, SCHEMA_VERSION);
    }

    /// Upgrading a v3 vault (no deleted_at columns) to current adds the column
    /// without dropping existing data.
    #[test]
    fn upgrade_from_v3_adds_deleted_at() {
        let conn = Connection::open_in_memory().unwrap();
        // Build the v1..v3 baseline and stamp it as v3, like an older app would.
        migrate_v1(&conn).unwrap();
        migrate_v2(&conn).unwrap();
        migrate_v3(&conn).unwrap();
        conn.pragma_update(None, "user_version", 3i64).unwrap();
        conn.execute(
            "INSERT INTO reports (id, title, report_type, created_at, updated_at) \
             VALUES ('r1', 't', 'web_pentest', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            [],
        )
        .unwrap();
        assert!(!column_exists(&conn, "reports", "deleted_at").unwrap());

        init(&conn).unwrap();

        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        assert!(column_exists(&conn, "reports", "deleted_at").unwrap());
        // Existing row survived and its new column defaulted to NULL.
        let deleted: Option<String> = conn
            .query_row("SELECT deleted_at FROM reports WHERE id = 'r1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(deleted.is_none());
        // v5 also added `language`, defaulting the pre-existing row to 'en'.
        let lang: String = conn
            .query_row("SELECT language FROM reports WHERE id = 'r1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(lang, "en");
    }

    /// A fresh DB has the v5 `language` column on `reports` defaulting to 'en'.
    #[test]
    fn fresh_db_has_language_column_defaulting_to_en() {
        let conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();
        assert!(column_exists(&conn, "reports", "language").unwrap());
        conn.execute(
            "INSERT INTO reports (id, title, report_type, created_at, updated_at) \
             VALUES ('r2', 't', 'web_pentest', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            [],
        )
        .unwrap();
        let lang: String = conn
            .query_row("SELECT language FROM reports WHERE id = 'r2'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(lang, "en");
    }
}
