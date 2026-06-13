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
pub const SCHEMA_VERSION: i64 = 8;

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
    (6, migrate_v6),
    (7, migrate_v7),
    (8, migrate_v8),
];

/// Apply any pending migrations and stamp the schema version.
///
/// Reads `PRAGMA user_version`; if it already equals [`SCHEMA_VERSION`] this is
/// a no-op. Otherwise every step with `version > current` runs in order inside a
/// single transaction, then `user_version` + the `meta` mirror are bumped.
///
/// Fresh installs (user_version 0) run the whole v1..=v7 ladder; existing v1..v6
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

/// v6: aggregate report layer. Adds:
///   - `assets`: affected-asset inventory per report (host/ip/url/…).
///   - `scope_items`: structured in-/out-of-scope entries per report.
///   - `finding_assets`: link table relating findings to assets (a derived set,
///     so no soft-delete column — it is fully snapshot/UNION-merged by sync).
///   - engagement-metadata columns on `reports` (dates, authors, reviewer,
///     reference, confidentiality) + a per-report branding `logo` BLOB.
///
/// Tables follow the soft-delete/tombstone pattern (`deleted_at`) like the other
/// syncable tables. `CREATE TABLE IF NOT EXISTS` + `column_exists`-guarded
/// `ADD COLUMN` keep the step idempotent.
fn migrate_v6(conn: &Connection) -> AppResult<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS assets (
            id          TEXT PRIMARY KEY,
            report_id   TEXT NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
            kind        TEXT NOT NULL DEFAULT 'other',
            identifier  TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            sort_order  INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT NOT NULL,
            updated_at  TEXT NOT NULL,
            deleted_at  TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_assets_report
            ON assets(report_id, sort_order);

        CREATE TABLE IF NOT EXISTS scope_items (
            id          TEXT PRIMARY KEY,
            report_id   TEXT NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
            kind        TEXT NOT NULL DEFAULT 'other',
            value       TEXT NOT NULL DEFAULT '',
            in_scope    INTEGER NOT NULL DEFAULT 1,
            note        TEXT NOT NULL DEFAULT '',
            sort_order  INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT NOT NULL,
            updated_at  TEXT NOT NULL,
            deleted_at  TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_scope_items_report
            ON scope_items(report_id, sort_order);

        CREATE TABLE IF NOT EXISTS finding_assets (
            finding_id  TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
            asset_id    TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            PRIMARY KEY (finding_id, asset_id)
        );

        CREATE INDEX IF NOT EXISTS idx_finding_assets_asset
            ON finding_assets(asset_id);
        "#,
    )?;

    // Engagement metadata + branding columns on `reports` (idempotent).
    let columns: &[(&str, &str)] = &[
        ("engagement_start", "TEXT"),
        ("engagement_end", "TEXT"),
        ("authors", "TEXT NOT NULL DEFAULT '[]'"),
        ("reviewer", "TEXT"),
        ("engagement_ref", "TEXT"),
        ("confidentiality", "TEXT"),
        ("logo", "BLOB"),
        ("logo_mime", "TEXT"),
    ];
    for (name, ty) in columns {
        if !column_exists(conn, "reports", name)? {
            conn.execute_batch(&format!("ALTER TABLE reports ADD COLUMN {name} {ty};"))?;
        }
    }
    Ok(())
}

/// v7: retest workflow + custom fields + compliance mappings. Adds:
///   - `findings.retest_status` (nullable: not_retested/fixed/partially_fixed/
///     not_fixed/risk_accepted), `findings.retest_date` (nullable).
///   - `findings.custom_fields` (JSON object string→string, default '{}').
///   - `findings.mappings` (JSON array of {framework,id,name?}, default '[]').
///   - `reports.custom_fields` (JSON object, default '{}').
///
/// All are plain columns on existing syncable tables, so they ride the existing
/// LWW snapshot/merge. `column_exists`-guarded `ADD COLUMN` keeps the step
/// idempotent.
fn migrate_v7(conn: &Connection) -> AppResult<()> {
    let finding_columns: &[(&str, &str)] = &[
        ("retest_status", "TEXT"),
        ("retest_date", "TEXT"),
        ("custom_fields", "TEXT NOT NULL DEFAULT '{}'"),
        ("mappings", "TEXT NOT NULL DEFAULT '[]'"),
    ];
    for (name, ty) in finding_columns {
        if !column_exists(conn, "findings", name)? {
            conn.execute_batch(&format!("ALTER TABLE findings ADD COLUMN {name} {ty};"))?;
        }
    }
    if !column_exists(conn, "reports", "custom_fields")? {
        conn.execute_batch(
            "ALTER TABLE reports ADD COLUMN custom_fields TEXT NOT NULL DEFAULT '{}';",
        )?;
    }
    Ok(())
}

/// v8: index hygiene (no schema/data changes, only indexes — performance).
///   - `idx_reports_updated` on `reports(updated_at)`: the main report list sorts
///     `ORDER BY updated_at DESC`, which had no supporting index.
///   - rebuild `idx_kb_entries_title` as case-insensitive (`COLLATE NOCASE`):
///     the KB list sorts `ORDER BY title COLLATE NOCASE`, so the old
///     binary-collation index couldn't serve the sort. Dropped + recreated.
///   - `idx_assets_report` / `idx_scope_report` on `(report_id, sort_order)`:
///     the per-report asset/scope lookups join+sort on these columns.
///
/// All statements are `IF NOT EXISTS`/`DROP IF EXISTS`, so the step is
/// idempotent and converges on a re-run.
///
/// NOTE: JSON-shape CHECK constraints on the existing JSON text columns
/// (description/remediation/custom_fields/…) are intentionally NOT added here:
/// SQLite cannot `ALTER TABLE ... ADD CONSTRAINT`, so retrofitting them onto
/// existing tables would require a full table rebuild (rename → recreate → copy
/// → drop) per table — too invasive for this pass. Validation stays in the
/// serde layer.
fn migrate_v8(conn: &Connection) -> AppResult<()> {
    conn.execute_batch(
        r#"
        CREATE INDEX IF NOT EXISTS idx_reports_updated
            ON reports(updated_at);

        DROP INDEX IF EXISTS idx_kb_entries_title;
        CREATE INDEX IF NOT EXISTS idx_kb_entries_title
            ON kb_entries(title COLLATE NOCASE);

        CREATE INDEX IF NOT EXISTS idx_assets_report
            ON assets(report_id, sort_order);

        CREATE INDEX IF NOT EXISTS idx_scope_report
            ON scope_items(report_id, sort_order);
        "#,
    )?;
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

    /// A fresh DB has the v6 aggregate-layer tables + the new engagement /
    /// branding columns on `reports`.
    #[test]
    fn fresh_db_has_v6_tables_and_columns() {
        let conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();
        for table in ["assets", "scope_items", "finding_assets"] {
            let n: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n, 1, "{table} table missing");
        }
        for col in [
            "engagement_start",
            "engagement_end",
            "authors",
            "reviewer",
            "engagement_ref",
            "confidentiality",
            "logo",
            "logo_mime",
        ] {
            assert!(column_exists(&conn, "reports", col).unwrap(), "{col}");
        }
        // `authors` defaults to an empty JSON array for a fresh row.
        conn.execute(
            "INSERT INTO reports (id, title, report_type, created_at, updated_at) \
             VALUES ('r3', 't', 'web_pentest', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            [],
        )
        .unwrap();
        let authors: String = conn
            .query_row("SELECT authors FROM reports WHERE id = 'r3'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(authors, "[]");
    }

    /// Upgrading a v5 vault to current adds the v6 tables + columns without
    /// dropping existing report data.
    #[test]
    fn upgrade_from_v5_adds_v6_tables() {
        let conn = Connection::open_in_memory().unwrap();
        migrate_v1(&conn).unwrap();
        migrate_v2(&conn).unwrap();
        migrate_v3(&conn).unwrap();
        migrate_v4(&conn).unwrap();
        migrate_v5(&conn).unwrap();
        conn.pragma_update(None, "user_version", 5i64).unwrap();
        conn.execute(
            "INSERT INTO reports (id, title, report_type, created_at, updated_at) \
             VALUES ('r1', 't', 'web_pentest', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            [],
        )
        .unwrap();
        assert!(!column_exists(&conn, "reports", "authors").unwrap());

        init(&conn).unwrap();

        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        assert!(column_exists(&conn, "reports", "authors").unwrap());
        let authors: String = conn
            .query_row("SELECT authors FROM reports WHERE id = 'r1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(authors, "[]");
    }

    /// A fresh DB has the v7 retest / custom-fields / mappings columns with the
    /// documented defaults.
    #[test]
    fn fresh_db_has_v7_columns() {
        let conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();
        for col in ["retest_status", "retest_date", "custom_fields", "mappings"] {
            assert!(column_exists(&conn, "findings", col).unwrap(), "{col}");
        }
        assert!(column_exists(&conn, "reports", "custom_fields").unwrap());

        // Inserting a minimal report + finding picks up the column defaults.
        conn.execute(
            "INSERT INTO reports (id, title, report_type, created_at, updated_at) \
             VALUES ('r1', 't', 'web_pentest', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO findings (id, report_id, title, severity, created_at, updated_at) \
             VALUES ('f1', 'r1', 't', 'high', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            [],
        )
        .unwrap();
        let (cf, maps, retest): (String, String, Option<String>) = conn
            .query_row(
                "SELECT custom_fields, mappings, retest_status FROM findings WHERE id = 'f1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(cf, "{}");
        assert_eq!(maps, "[]");
        assert!(retest.is_none());
        let report_cf: String = conn
            .query_row(
                "SELECT custom_fields FROM reports WHERE id = 'r1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(report_cf, "{}");
    }

    /// True if an index with this name exists in the schema.
    fn index_exists(conn: &Connection, name: &str) -> bool {
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?1",
                [name],
                |r| r.get(0),
            )
            .unwrap();
        n == 1
    }

    /// A fresh DB has the v8 performance indexes, and the rebuilt KB title index
    /// is case-insensitive (`COLLATE NOCASE`).
    #[test]
    fn fresh_db_has_v8_indexes() {
        let conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();
        for idx in [
            "idx_reports_updated",
            "idx_kb_entries_title",
            "idx_assets_report",
            "idx_scope_report",
        ] {
            assert!(index_exists(&conn, idx), "{idx} missing");
        }
        // The rebuilt KB title index carries the NOCASE collation so it serves
        // the `ORDER BY title COLLATE NOCASE` list query.
        let sql: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='index' AND name='idx_kb_entries_title'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            sql.to_uppercase().contains("NOCASE"),
            "kb title index not case-insensitive: {sql}"
        );
    }

    /// Upgrading a v7 vault to current adds the v8 indexes (and rebuilds the KB
    /// title index) without dropping data.
    #[test]
    fn upgrade_from_v7_adds_v8_indexes() {
        let conn = Connection::open_in_memory().unwrap();
        migrate_v1(&conn).unwrap();
        migrate_v2(&conn).unwrap();
        migrate_v3(&conn).unwrap();
        migrate_v4(&conn).unwrap();
        migrate_v5(&conn).unwrap();
        migrate_v6(&conn).unwrap();
        migrate_v7(&conn).unwrap();
        conn.pragma_update(None, "user_version", 7i64).unwrap();
        // The old (binary-collation) KB title index from migrate_v2 is present.
        assert!(index_exists(&conn, "idx_kb_entries_title"));
        conn.execute(
            "INSERT INTO reports (id, title, report_type, created_at, updated_at) \
             VALUES ('r1', 't', 'web_pentest', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            [],
        )
        .unwrap();

        init(&conn).unwrap();

        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        for idx in [
            "idx_reports_updated",
            "idx_kb_entries_title",
            "idx_assets_report",
            "idx_scope_report",
        ] {
            assert!(index_exists(&conn, idx), "{idx} missing after upgrade");
        }
        let sql: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='index' AND name='idx_kb_entries_title'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(sql.to_uppercase().contains("NOCASE"));
        // Pre-existing data survived.
        let title: String = conn
            .query_row("SELECT title FROM reports WHERE id = 'r1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(title, "t");
    }

    /// Upgrading a v6 vault to current adds the v7 columns without dropping data.
    #[test]
    fn upgrade_from_v6_adds_v7_columns() {
        let conn = Connection::open_in_memory().unwrap();
        migrate_v1(&conn).unwrap();
        migrate_v2(&conn).unwrap();
        migrate_v3(&conn).unwrap();
        migrate_v4(&conn).unwrap();
        migrate_v5(&conn).unwrap();
        migrate_v6(&conn).unwrap();
        conn.pragma_update(None, "user_version", 6i64).unwrap();
        conn.execute(
            "INSERT INTO reports (id, title, report_type, created_at, updated_at) \
             VALUES ('r1', 't', 'web_pentest', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            [],
        )
        .unwrap();
        assert!(!column_exists(&conn, "findings", "custom_fields").unwrap());

        init(&conn).unwrap();

        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        assert!(column_exists(&conn, "findings", "mappings").unwrap());
        assert!(column_exists(&conn, "reports", "custom_fields").unwrap());
        // The pre-existing report got the default custom_fields.
        let report_cf: String = conn
            .query_row(
                "SELECT custom_fields FROM reports WHERE id = 'r1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(report_cf, "{}");
    }
}
