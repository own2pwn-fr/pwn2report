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

/// Parse the `authors` JSON-array column into a `Vec<String>` (defaulting to
/// empty on NULL / empty / malformed so a bad row never fails a whole query).
fn authors_from(raw: Option<String>) -> Vec<String> {
    match raw {
        Some(s) if !s.is_empty() => serde_json::from_str(&s).unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Map a full `reports` row to a `Report`. Reads the `logo` column only as a
/// presence flag (`has_logo`) — the bytes are fetched via [`get_logo`].
fn row_to_report(row: &Row) -> rusqlite::Result<Report> {
    let report_type: String = row.get("report_type")?;
    let authors: Option<String> = row.get("authors")?;
    // The logo BLOB is potentially large; pull only its byte length to derive
    // presence without copying the bytes into the model.
    let logo_len: Option<i64> = row.get("logo_len")?;
    Ok(Report {
        id: row.get("id")?,
        title: row.get("title")?,
        client: row.get("client")?,
        report_type: report_type_from(&report_type),
        status: row.get("status")?,
        exec_summary: row.get("exec_summary")?,
        scope: row.get("scope")?,
        methodology: row.get("methodology")?,
        language: row.get("language")?,
        engagement_start: row.get("engagement_start")?,
        engagement_end: row.get("engagement_end")?,
        authors: authors_from(authors),
        reviewer: row.get("reviewer")?,
        engagement_ref: row.get("engagement_ref")?,
        confidentiality: row.get("confidentiality")?,
        has_logo: logo_len.map(|n| n > 0).unwrap_or(false),
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
        deleted_at: row.get("deleted_at")?,
    })
}

/// Column list for a full report row, projecting the `logo` BLOB down to a
/// `logo_len` (its byte length) so `row_to_report` can derive `has_logo`
/// without materializing the (potentially large) bytes. Used by every read.
const REPORT_COLUMNS: &str = "id, title, client, report_type, status, exec_summary, scope, \
     methodology, language, engagement_start, engagement_end, authors, reviewer, \
     engagement_ref, confidentiality, LENGTH(logo) AS logo_len, created_at, \
     updated_at, deleted_at";

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
    let sql = format!("SELECT {REPORT_COLUMNS} FROM reports WHERE id = ?1 AND deleted_at IS NULL");
    let report = conn
        .query_row(&sql, params![id], row_to_report)
        .optional()?;
    report.ok_or(AppError::NotFound)
}

/// Fetch all reports as full rows (used by the sync snapshot). Ordered by id
/// for a deterministic snapshot. INCLUDES soft-deleted rows so their tombstones
/// (`deleted_at`) travel in the bundle and suppress resurrection on peers.
pub fn list_all(conn: &Connection) -> AppResult<Vec<Report>> {
    let mut stmt = conn.prepare(&format!("SELECT {REPORT_COLUMNS} FROM reports ORDER BY id"))?;
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
    let sql = format!("SELECT {REPORT_COLUMNS} FROM reports WHERE id = ?1");
    let report = conn
        .query_row(&sql, params![id], row_to_report)
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
             methodology, language, engagement_start, engagement_end, authors,
             reviewer, engagement_ref, confidentiality, created_at, updated_at,
             deleted_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                ?15, ?16, ?17, ?18)
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
            r.language,
            r.engagement_start,
            r.engagement_end,
            serde_json::to_string(&r.authors)?,
            r.reviewer,
            r.engagement_ref,
            r.confidentiality,
            r.created_at,
            r.updated_at,
            r.deleted_at,
        ],
    )?;
    Ok(())
}

/// Overwrite an existing report verbatim, preserving the incoming timestamps
/// (sync LWW merge — keeps `created_at` and `updated_at` from the bundle). The
/// `logo`/`logo_mime` columns are intentionally NOT touched here: the logo is a
/// separate BLOB carried+merged on its own bundle field (see [`set_logo`] and
/// `sync::merge`), so an LWW report overwrite must not clobber it.
pub fn update_raw(conn: &Connection, r: &Report) -> AppResult<()> {
    conn.execute(
        r#"
        UPDATE reports SET
            title = ?2, client = ?3, report_type = ?4, status = ?5,
            exec_summary = ?6, scope = ?7, methodology = ?8, language = ?9,
            engagement_start = ?10, engagement_end = ?11, authors = ?12,
            reviewer = ?13, engagement_ref = ?14, confidentiality = ?15,
            created_at = ?16, updated_at = ?17, deleted_at = ?18
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
            r.language,
            r.engagement_start,
            r.engagement_end,
            serde_json::to_string(&r.authors)?,
            r.reviewer,
            r.engagement_ref,
            r.confidentiality,
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
    let language = input
        .language
        .unwrap_or_else(crate::models::default_language);
    conn.execute(
        r#"
        INSERT INTO reports
            (id, title, client, report_type, status, exec_summary, scope,
             methodology, language, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, 'draft', '', '', '', ?5, ?6, ?6)
        "#,
        params![
            id,
            input.title,
            client,
            report_type_str(input.report_type),
            language,
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
    if let Some(language) = patch.language {
        sets.push("language = ?");
        vals.push(Box::new(language));
    }
    // Engagement metadata. Double-Option fields map Some(None) -> SQL NULL.
    if let Some(v) = patch.engagement_start {
        sets.push("engagement_start = ?");
        vals.push(Box::new(v));
    }
    if let Some(v) = patch.engagement_end {
        sets.push("engagement_end = ?");
        vals.push(Box::new(v));
    }
    if let Some(authors) = patch.authors {
        sets.push("authors = ?");
        vals.push(Box::new(serde_json::to_string(&authors)?));
    }
    if let Some(v) = patch.reviewer {
        sets.push("reviewer = ?");
        vals.push(Box::new(v));
    }
    if let Some(v) = patch.engagement_ref {
        sets.push("engagement_ref = ?");
        vals.push(Box::new(v));
    }
    if let Some(v) = patch.confidentiality {
        sets.push("confidentiality = ?");
        vals.push(Box::new(v));
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
    // Cascade the tombstone to the aggregate-layer children (assets + scope).
    conn.execute(
        "UPDATE assets SET deleted_at = ?1, updated_at = ?1 \
         WHERE report_id = ?2 AND deleted_at IS NULL",
        params![now, id],
    )?;
    conn.execute(
        "UPDATE scope_items SET deleted_at = ?1, updated_at = ?1 \
         WHERE report_id = ?2 AND deleted_at IS NULL",
        params![now, id],
    )?;
    Ok(())
}

// --- per-report branding logo ----------------------------------------------

/// Fetch a report's logo as `(mime, bytes)`, or `None` when no logo is set (or
/// the report row is absent). Tolerant of a soft-deleted row so the sync merge
/// can probe it without erroring. Used by the export layer and the
/// `get_report_logo` command.
pub fn get_logo(conn: &Connection, id: &str) -> AppResult<Option<(String, Vec<u8>)>> {
    let row: Option<(Option<String>, Option<Vec<u8>>)> = conn
        .query_row(
            "SELECT logo_mime, logo FROM reports WHERE id = ?1",
            params![id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match row {
        Some((Some(mime), Some(data))) if !data.is_empty() => Ok(Some((mime, data))),
        _ => Ok(None),
    }
}

/// Set (or replace) a report's branding logo. Bumps `updated_at` so the report
/// edit travels through sync. Returns `NotFound` if the report is absent.
pub fn set_logo(conn: &Connection, id: &str, mime: &str, data: &[u8]) -> AppResult<()> {
    let now = now_rfc3339();
    let n = conn.execute(
        "UPDATE reports SET logo = ?1, logo_mime = ?2, updated_at = ?3 \
         WHERE id = ?4 AND deleted_at IS NULL",
        params![data, mime, now, id],
    )?;
    if n == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// Clear a report's branding logo (logo bytes wiped, mime nulled). Bumps
/// `updated_at`. Returns `NotFound` if the report is absent.
pub fn clear_logo(conn: &Connection, id: &str) -> AppResult<()> {
    let now = now_rfc3339();
    let n = conn.execute(
        "UPDATE reports SET logo = NULL, logo_mime = NULL, updated_at = ?1 \
         WHERE id = ?2 AND deleted_at IS NULL",
        params![now, id],
    )?;
    if n == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// Set a report's logo verbatim from a sync bundle (no `updated_at` bump — the
/// report row's own LWW already governs the merge ordering). `None` data leaves
/// the logo untouched. Used only by `sync::merge`.
pub fn set_logo_raw(
    conn: &Connection,
    id: &str,
    mime: Option<&str>,
    data: Option<&[u8]>,
) -> AppResult<()> {
    if let Some(bytes) = data {
        conn.execute(
            "UPDATE reports SET logo = ?1, logo_mime = ?2 WHERE id = ?3",
            params![bytes, mime, id],
        )?;
    }
    Ok(())
}
