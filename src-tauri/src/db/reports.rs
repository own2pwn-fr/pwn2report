//! Report CRUD.

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
    })
}

/// List all reports as summaries (with finding counts), newest-updated first.
pub fn list(conn: &Connection) -> AppResult<Vec<ReportSummary>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT r.id, r.title, r.client, r.report_type, r.status, r.updated_at,
               COUNT(f.id) AS finding_count
        FROM reports r
        LEFT JOIN findings f ON f.report_id = r.id
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
            "SELECT * FROM reports WHERE id = ?1",
            params![id],
            row_to_report,
        )
        .optional()?;
    report.ok_or(AppError::NotFound)
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
pub fn update(conn: &Connection, id: &str, patch: ReportPatch) -> AppResult<Report> {
    // Ensure it exists (so we return NotFound rather than a silent no-op).
    let _ = get(conn, id)?;

    let now = now_rfc3339();
    if let Some(title) = patch.title {
        conn.execute(
            "UPDATE reports SET title = ?1 WHERE id = ?2",
            params![title, id],
        )?;
    }
    if let Some(client) = patch.client {
        conn.execute(
            "UPDATE reports SET client = ?1 WHERE id = ?2",
            params![client, id],
        )?;
    }
    if let Some(rt) = patch.report_type {
        conn.execute(
            "UPDATE reports SET report_type = ?1 WHERE id = ?2",
            params![report_type_str(rt), id],
        )?;
    }
    if let Some(status) = patch.status {
        conn.execute(
            "UPDATE reports SET status = ?1 WHERE id = ?2",
            params![status, id],
        )?;
    }
    if let Some(exec_summary) = patch.exec_summary {
        conn.execute(
            "UPDATE reports SET exec_summary = ?1 WHERE id = ?2",
            params![exec_summary, id],
        )?;
    }
    if let Some(scope) = patch.scope {
        conn.execute(
            "UPDATE reports SET scope = ?1 WHERE id = ?2",
            params![scope, id],
        )?;
    }
    if let Some(methodology) = patch.methodology {
        conn.execute(
            "UPDATE reports SET methodology = ?1 WHERE id = ?2",
            params![methodology, id],
        )?;
    }
    conn.execute(
        "UPDATE reports SET updated_at = ?1 WHERE id = ?2",
        params![now, id],
    )?;

    get(conn, id)
}

/// Delete a report (and its findings, via ON DELETE CASCADE).
pub fn delete(conn: &Connection, id: &str) -> AppResult<()> {
    let n = conn.execute("DELETE FROM reports WHERE id = ?1", params![id])?;
    if n == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}
