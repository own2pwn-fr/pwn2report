//! Knowledge-base CRUD. Reuses the finding enum/JSON column helpers so the KB
//! stores templates in exactly the same on-disk shape as report findings.

use rusqlite::types::ToSql;
use rusqlite::{params, Connection, OptionalExtension, Row};
use uuid::Uuid;

use super::findings::{
    confidence_from, confidence_str, json_obj, json_vec, kind_from, kind_str, severity_from,
};
use super::now_rfc3339;
use crate::error::{AppError, AppResult};
use crate::models::{
    Confidence, FindingDescription, FindingKind, FindingRemediation, KbEntry, KbEntryPatch,
    NewFinding, NewKbEntry,
};

/// Map a full `kb_entries` row to a `KbEntry`.
fn row_to_kb(row: &Row) -> AppResult<KbEntry> {
    let severity: String = row.get("severity")?;
    let confidence: String = row.get("confidence")?;
    let kind: String = row.get("kind")?;

    Ok(KbEntry {
        id: row.get("id")?,
        title: row.get("title")?,
        severity: severity_from(&severity),
        confidence: confidence_from(&confidence),
        kind: kind_from(&kind),
        cwe: row.get("cwe")?,
        cve: row.get("cve")?,
        cvss_vector: row.get("cvss_vector")?,
        cvss_score: row.get("cvss_score")?,
        description: json_obj::<FindingDescription>(row.get("description")?)?,
        remediation: json_obj::<FindingRemediation>(row.get("remediation")?)?,
        tags: json_vec(row.get("tags")?)?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
        deleted_at: row.get("deleted_at")?,
    })
}

/// List all live KB entries, alphabetical by title.
pub fn list(conn: &Connection) -> AppResult<Vec<KbEntry>> {
    let mut stmt = conn.prepare(
        "SELECT * FROM kb_entries WHERE deleted_at IS NULL ORDER BY title COLLATE NOCASE",
    )?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(row_to_kb(row)?);
    }
    Ok(out)
}

/// Fetch all KB entries as full rows (used by the sync snapshot). Ordered by id
/// for a deterministic snapshot. INCLUDES soft-deleted rows so their tombstones
/// travel in the bundle.
pub fn list_all(conn: &Connection) -> AppResult<Vec<KbEntry>> {
    let mut stmt = conn.prepare("SELECT * FROM kb_entries ORDER BY id")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(row_to_kb(row)?);
    }
    Ok(out)
}

/// Whether a KB entry with this id exists (INCLUDING soft-deleted tombstones,
/// so the sync merge applies LWW rather than re-inserting a deleted row).
pub fn exists(conn: &Connection, id: &str) -> AppResult<bool> {
    let found: bool = conn
        .query_row(
            "SELECT 1 FROM kb_entries WHERE id = ?1",
            params![id],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);
    Ok(found)
}

/// Insert a KB entry verbatim, preserving its id + timestamps (sync merge — NOT
/// the id-generating [`create`]).
pub fn insert_raw(conn: &Connection, e: &KbEntry) -> AppResult<()> {
    conn.execute(
        r#"
        INSERT INTO kb_entries
            (id, title, severity, confidence, kind, cwe, cve, cvss_vector,
             cvss_score, description, remediation, tags, created_at, updated_at,
             deleted_at)
        VALUES
            (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
        "#,
        params![
            e.id,
            e.title,
            e.severity.as_str(),
            confidence_str(e.confidence),
            kind_str(e.kind),
            e.cwe,
            e.cve,
            e.cvss_vector,
            e.cvss_score,
            serde_json::to_string(&e.description)?,
            serde_json::to_string(&e.remediation)?,
            serde_json::to_string(&e.tags)?,
            e.created_at,
            e.updated_at,
            e.deleted_at,
        ],
    )?;
    Ok(())
}

/// Overwrite an existing KB entry verbatim, preserving the incoming timestamps
/// (sync LWW merge).
pub fn update_raw(conn: &Connection, e: &KbEntry) -> AppResult<()> {
    conn.execute(
        r#"
        UPDATE kb_entries SET
            title = ?2, severity = ?3, confidence = ?4, kind = ?5, cwe = ?6,
            cve = ?7, cvss_vector = ?8, cvss_score = ?9, description = ?10,
            remediation = ?11, tags = ?12, created_at = ?13, updated_at = ?14,
            deleted_at = ?15
        WHERE id = ?1
        "#,
        params![
            e.id,
            e.title,
            e.severity.as_str(),
            confidence_str(e.confidence),
            kind_str(e.kind),
            e.cwe,
            e.cve,
            e.cvss_vector,
            e.cvss_score,
            serde_json::to_string(&e.description)?,
            serde_json::to_string(&e.remediation)?,
            serde_json::to_string(&e.tags)?,
            e.created_at,
            e.updated_at,
            e.deleted_at,
        ],
    )?;
    Ok(())
}

/// Fetch a single live KB entry by id (excludes soft-deleted tombstones).
pub fn get(conn: &Connection, id: &str) -> AppResult<KbEntry> {
    let mut stmt = conn.prepare("SELECT * FROM kb_entries WHERE id = ?1 AND deleted_at IS NULL")?;
    let mut rows = stmt.query(params![id])?;
    match rows.next()? {
        Some(row) => row_to_kb(row),
        None => Err(AppError::NotFound),
    }
}

/// Fetch a KB entry by id INCLUDING a soft-deleted tombstone (used by the sync
/// merge to read the local `updated_at`/`deleted_at` for LWW).
pub fn get_raw(conn: &Connection, id: &str) -> AppResult<KbEntry> {
    let mut stmt = conn.prepare("SELECT * FROM kb_entries WHERE id = ?1")?;
    let mut rows = stmt.query(params![id])?;
    match rows.next()? {
        Some(row) => row_to_kb(row),
        None => Err(AppError::NotFound),
    }
}

/// Insert a new KB entry, applying defaults for omitted optional fields.
pub fn create(conn: &Connection, input: NewKbEntry) -> AppResult<KbEntry> {
    let id = Uuid::new_v4().to_string();
    let now = now_rfc3339();

    let confidence = input.confidence.unwrap_or(Confidence::Medium);
    let kind = input.kind.unwrap_or(FindingKind::Manual);
    let description = input.description.unwrap_or_default();
    let remediation = input.remediation.unwrap_or_default();
    let tags = input.tags.unwrap_or_default();

    conn.execute(
        r#"
        INSERT INTO kb_entries
            (id, title, severity, confidence, kind, cwe, cve, cvss_vector,
             cvss_score, description, remediation, tags, created_at, updated_at)
        VALUES
            (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?13)
        "#,
        params![
            id,
            input.title,
            input.severity.as_str(),
            confidence_str(confidence),
            kind_str(kind),
            input.cwe,
            input.cve,
            input.cvss_vector,
            input.cvss_score,
            serde_json::to_string(&description)?,
            serde_json::to_string(&remediation)?,
            serde_json::to_string(&tags)?,
            now,
        ],
    )?;

    get(conn, &id)
}

/// Apply a partial update to a KB entry; returns the updated row.
pub fn update(conn: &Connection, id: &str, patch: KbEntryPatch) -> AppResult<KbEntry> {
    let _ = get(conn, id)?; // NotFound if absent.
    let now = now_rfc3339();

    // Single atomic UPDATE built from the present patch fields + updated_at (see
    // findings::update for the rationale). Double-Option fields map Some(None)
    // -> SQL NULL, Some(Some(v)) -> v.
    let mut sets: Vec<&str> = vec!["updated_at = ?"];
    let mut vals: Vec<Box<dyn ToSql>> = vec![Box::new(now)];

    if let Some(title) = patch.title {
        sets.push("title = ?");
        vals.push(Box::new(title));
    }
    if let Some(sev) = patch.severity {
        sets.push("severity = ?");
        vals.push(Box::new(sev.as_str().to_string()));
    }
    if let Some(c) = patch.confidence {
        sets.push("confidence = ?");
        vals.push(Box::new(confidence_str(c).to_string()));
    }
    if let Some(k) = patch.kind {
        sets.push("kind = ?");
        vals.push(Box::new(kind_str(k).to_string()));
    }
    if let Some(cwe) = patch.cwe {
        sets.push("cwe = ?");
        vals.push(Box::new(cwe));
    }
    if let Some(cve) = patch.cve {
        sets.push("cve = ?");
        vals.push(Box::new(cve));
    }
    if let Some(v) = patch.cvss_vector {
        sets.push("cvss_vector = ?");
        vals.push(Box::new(v));
    }
    if let Some(score) = patch.cvss_score {
        sets.push("cvss_score = ?");
        vals.push(Box::new(score));
    }
    if let Some(desc) = patch.description {
        sets.push("description = ?");
        vals.push(Box::new(serde_json::to_string(&desc)?));
    }
    if let Some(rem) = patch.remediation {
        sets.push("remediation = ?");
        vals.push(Box::new(serde_json::to_string(&rem)?));
    }
    if let Some(tags) = patch.tags {
        sets.push("tags = ?");
        vals.push(Box::new(serde_json::to_string(&tags)?));
    }

    let sql = format!("UPDATE kb_entries SET {} WHERE id = ?", sets.join(", "));
    vals.push(Box::new(id.to_string()));
    let bound: Vec<&dyn ToSql> = vals.iter().map(|b| b.as_ref()).collect();
    conn.execute(&sql, bound.as_slice())?;

    get(conn, id)
}

/// Soft-delete a KB entry by id: set `deleted_at = now` and bump `updated_at` so
/// the deletion becomes a tombstone that travels through sync and wins LWW
/// instead of resurrecting from a peer.
pub fn delete(conn: &Connection, id: &str) -> AppResult<()> {
    let now = now_rfc3339();
    let n = conn.execute(
        "UPDATE kb_entries SET deleted_at = ?1, updated_at = ?1 \
         WHERE id = ?2 AND deleted_at IS NULL",
        params![now, id],
    )?;
    if n == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// True if a LIVE KB entry with this exact title already exists (a soft-deleted
/// entry does not block reusing its title).
pub fn title_exists(conn: &Connection, title: &str) -> AppResult<bool> {
    let found: bool = conn
        .query_row(
            "SELECT 1 FROM kb_entries WHERE title = ?1 AND deleted_at IS NULL LIMIT 1",
            params![title],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);
    Ok(found)
}

/// Build a `NewFinding` template from a KB entry. Copies the reusable facets
/// (title/severity/confidence/kind/cwe/cve/cvss/description/remediation/tags)
/// and leaves per-report context (evidence, poc, triage) at defaults.
pub fn to_new_finding(entry: &KbEntry) -> NewFinding {
    NewFinding {
        title: entry.title.clone(),
        severity: entry.severity,
        confidence: Some(entry.confidence),
        kind: Some(entry.kind),
        cwe: entry.cwe.clone(),
        cve: entry.cve.clone(),
        cvss_vector: entry.cvss_vector.clone(),
        cvss_score: entry.cvss_score,
        triage_status: None, // db layer defaults to `open`
        triage_note: None,
        description: Some(entry.description.clone()),
        remediation: Some(entry.remediation.clone()),
        evidence: None,
        poc: None,
        refs: None,
        tags: Some(entry.tags.clone()),
    }
}
