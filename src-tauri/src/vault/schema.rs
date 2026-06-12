//! Idempotent schema bootstrap, versioned via `PRAGMA user_version`.

use rusqlite::Connection;

use crate::error::AppResult;

/// Current schema version. Bump when adding migrations.
const SCHEMA_VERSION: i64 = 1;

/// Create all tables/indexes if absent and stamp the schema version. Safe to
/// call on every unlock (uses `IF NOT EXISTS`).
pub fn init(conn: &Connection) -> AppResult<()> {
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

    // Record schema version (informational; meta row + pragma).
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?1)",
        rusqlite::params![SCHEMA_VERSION.to_string()],
    )?;

    Ok(())
}
