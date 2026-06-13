//! Report CRUD.

use rusqlite::types::ToSql;
use rusqlite::{params, Connection, OptionalExtension, Row};
use uuid::Uuid;

use super::now_rfc3339;
use crate::error::{AppError, AppResult};
use crate::models::{NewReport, Report, ReportPatch, ReportSummary, ReportType};

/// Serialize a `ReportType` to its snake_case column value.
fn report_type_str(t: ReportType) -> &'static str {
    t.slug()
}

/// Parse a column value back into a `ReportType` (defaults to web_pentest on an
/// unknown value rather than failing a whole query).
fn report_type_from(s: &str) -> ReportType {
    ReportType::from_slug(s)
}

/// Map a full `reports` row to a `Report`.
fn row_to_report(row: &Row) -> rusqlite::Result<Report> {
    let report_type: String = row.get("report_type")?;
    Ok(Report {
        id: row.get("id")?,
        title: row.get("title")?,
        client: row.get("client")?,
        report_type: report_type_from(&report_type),
        status: row.get("status")?,
        exec_summary: row.get("exec_summary")?,
        scope: row.get("scope")?,
        methodology: row.get("methodology")?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
        deleted_at: row.get("deleted_at")?,
    })
}

/// List all reports as summaries (with finding counts), newest-updated first.
pub fn list(conn: &Connection) -> AppResult<Vec<ReportSummary>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT r.id, r.title, r.client, r.report_type, r.status, r.updated_at,
               COUNT(f.id) AS finding_count
        FROM reports r
        LEFT JOIN findings f
            ON f.report_id = r.id AND f.deleted_at IS NULL
        WHERE r.deleted_at IS NULL
        GROUP BY r.id
        ORDER BY r.updated_at DESC
        "#,
    )?;
    let rows = stmt.query_map([], |row| {
        let report_type: String = row.get("report_type")?;
        Ok(ReportSummary {
            id: row.get("id")?,
            title: row.get("title")?,
            client: row.get("client")?,
            report_type: report_type_from(&report_type),
            status: row.get("status")?,
            finding_count: row.get("finding_count")?,
            updated_at: row.get("updated_at")?,
        })
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// Fetch a single report by id.
pub fn get(conn: &Connection, id: &str) -> AppResult<Report> {
    let report = conn
        .query_row(
            "SELECT * FROM reports WHERE id = ?1 AND deleted_at IS NULL",
            params![id],
            row_to_report,
        )
        .optional()?;
    report.ok_or(AppError::NotFound)
}

/// Fetch all reports as full rows (used by the sync snapshot). Ordered by id
/// for a deterministic snapshot. INCLUDES soft-deleted rows so their tombstones
/// (`deleted_at`) travel in the bundle and suppress resurrection on peers.
pub fn list_all(conn: &Connection) -> AppResult<Vec<Report>> {
    let mut stmt = conn.prepare("SELECT * FROM reports ORDER BY id")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(row_to_report(row)?);
    }
    Ok(out)
}

/// Whether a report with this id exists (INCLUDING soft-deleted tombstones, so
/// the sync merge treats a locally-deleted row as present and applies LWW rather
/// than re-inserting it).
pub fn exists(conn: &Connection, id: &str) -> AppResult<bool> {
    let found: bool = conn
        .query_row("SELECT 1 FROM reports WHERE id = ?1", params![id], |_| {
            Ok(true)
        })
        .optional()?
        .unwrap_or(false);
    Ok(found)
}

/// Fetch a report by id INCLUDING a soft-deleted tombstone (used by the sync
/// merge to read the local `updated_at`/`deleted_at` for LWW). Returns NotFound
/// only if the row is truly absent.
pub fn get_raw(conn: &Connection, id: &str) -> AppResult<Report> {
    let report = conn
        .query_row(
            "SELECT * FROM reports WHERE id = ?1",
            params![id],
            row_to_report,
        )
        .optional()?;
    report.ok_or(AppError::NotFound)
}

/// Insert a report verbatim, preserving its id + timestamps (sync merge — NOT
/// the id-generating [`create`]).
pub fn insert_raw(conn: &Connection, r: &Report) -> AppResult<()> {
    conn.execute(
        r#"
        INSERT INTO reports
            (id, title, client, report_type, status, exec_summary, scope,
             methodology, created_at, updated_at, deleted_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        "#,
        params![
            r.id,
            r.title,
            r.client,
            report_type_str(r.report_type),
            r.status,
            r.exec_summary,
            r.scope,
            r.methodology,
            r.created_at,
            r.updated_at,
            r.deleted_at,
        ],
    )?;
    Ok(())
}

/// Overwrite an existing report verbatim, preserving the incoming timestamps
/// (sync LWW merge — keeps `created_at` and `updated_at` from the bundle).
pub fn update_raw(conn: &Connection, r: &Report) -> AppResult<()> {
    conn.execute(
        r#"
        UPDATE reports SET
            title = ?2, client = ?3, report_type = ?4, status = ?5,
            exec_summary = ?6, scope = ?7, methodology = ?8,
            created_at = ?9, updated_at = ?10, deleted_at = ?11
        WHERE id = ?1
        "#,
        params![
            r.id,
            r.title,
            r.client,
            report_type_str(r.report_type),
            r.status,
            r.exec_summary,
            r.scope,
            r.methodology,
            r.created_at,
            r.updated_at,
            r.deleted_at,
        ],
    )?;
    Ok(())
}

/// Create a new report and return the persisted row.
pub fn create(conn: &Connection, input: NewReport) -> AppResult<Report> {
    let id = Uuid::new_v4().to_string();
    let now = now_rfc3339();
    let client = input.client.unwrap_or_default();
    conn.execute(
        r#"
        INSERT INTO reports
            (id, title, client, report_type, status, exec_summary, scope,
             methodology, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, 'draft', '', '', '', ?5, ?5)
        "#,
        params![
            id,
            input.title,
            client,
            report_type_str(input.report_type),
            now
        ],
    )?;
    get(conn, &id)
}

/// Apply a partial update; returns the updated report. `None` patch fields are
/// left unchanged. Always bumps `updated_at`.
///
/// Built as a SINGLE atomic `UPDATE` from only the present patch fields (plus
/// `updated_at`) so a multi-field edit can never tear into separate writes with
/// a stale `updated_at` (which previously let a concurrent sync silently revert
/// the edit).
pub fn update(conn: &Connection, id: &str, patch: ReportPatch) -> AppResult<Report> {
    // Ensure it exists (so we return NotFound rather than a silent no-op).
    let _ = get(conn, id)?;

    let now = now_rfc3339();
    // All placeholders are anonymous `?` and bound positionally in push order;
    // `updated_at` is always set first, `id` (the WHERE) bound last.
    let mut sets: Vec<&str> = vec!["updated_at = ?"];
    let mut vals: Vec<Box<dyn ToSql>> = vec![Box::new(now)];

    if let Some(title) = patch.title {
        sets.push("title = ?");
        vals.push(Box::new(title));
    }
    if let Some(client) = patch.client {
        sets.push("client = ?");
        vals.push(Box::new(client));
    }
    if let Some(rt) = patch.report_type {
        sets.push("report_type = ?");
        vals.push(Box::new(report_type_str(rt).to_string()));
    }
    if let Some(status) = patch.status {
        sets.push("status = ?");
        vals.push(Box::new(status));
    }
    if let Some(exec_summary) = patch.exec_summary {
        sets.push("exec_summary = ?");
        vals.push(Box::new(exec_summary));
    }
    if let Some(scope) = patch.scope {
        sets.push("scope = ?");
        vals.push(Box::new(scope));
    }
    if let Some(methodology) = patch.methodology {
        sets.push("methodology = ?");
        vals.push(Box::new(methodology));
    }

    // id goes last as the final positional parameter.
    let sql = format!("UPDATE reports SET {} WHERE id = ?", sets.join(", "));
    vals.push(Box::new(id.to_string()));
    let params: Vec<&dyn ToSql> = vals.iter().map(|b| b.as_ref()).collect();
    conn.execute(&sql, params.as_slice())?;

    get(conn, id)
}

/// Soft-delete a report (and, transitively, its findings + their evidence): set
/// `deleted_at = now` and bump `updated_at` so the deletion becomes a tombstone
/// that travels through sync and wins LWW, instead of a hard DELETE that a peer
/// would resurrect. Children are soft-deleted alongside the parent so the FK
/// subtree is consistently "gone" (queries filter `deleted_at IS NULL`).
pub fn delete(conn: &Connection, id: &str) -> AppResult<()> {
    let now = now_rfc3339();
    let n = conn.execute(
        "UPDATE reports SET deleted_at = ?1, updated_at = ?1 \
         WHERE id = ?2 AND deleted_at IS NULL",
        params![now, id],
    )?;
    if n == 0 {
        return Err(AppError::NotFound);
    }
    // Cascade the tombstone to children (only the still-live ones).
    conn.execute(
        "UPDATE findings SET deleted_at = ?1, updated_at = ?1 \
         WHERE report_id = ?2 AND deleted_at IS NULL",
        params![now, id],
    )?;
    conn.execute(
        "UPDATE evidence_images SET deleted_at = ?1 \
         WHERE deleted_at IS NULL AND finding_id IN \
            (SELECT id FROM findings WHERE report_id = ?2)",
        params![now, id],
    )?;
    Ok(())
}
