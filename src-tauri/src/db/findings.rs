//! Finding CRUD. Structured sub-objects live in JSON TEXT columns.

use rusqlite::{params, Connection, OptionalExtension, Row};
use uuid::Uuid;

use super::now_rfc3339;
use crate::error::{AppError, AppResult};
use crate::models::{
    Confidence, Evidence, Finding, FindingDescription, FindingKind, FindingPatch,
    FindingRemediation, NewFinding, Severity, StructuredPoc, TriageStatus,
};

// --- enum <-> column string helpers ----------------------------------------

fn confidence_str(c: Confidence) -> &'static str {
    match c {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
    }
}
fn confidence_from(s: &str) -> Confidence {
    match s {
        "low" => Confidence::Low,
        "high" => Confidence::High,
        _ => Confidence::Medium,
    }
}

fn severity_from(s: &str) -> Severity {
    match s {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => Severity::Medium,
    }
}

fn kind_str(k: FindingKind) -> &'static str {
    match k {
        FindingKind::Manual => "manual",
        FindingKind::Sast => "sast",
        FindingKind::Iac => "iac",
        FindingKind::Sca => "sca",
        FindingKind::Secret => "secret",
    }
}
fn kind_from(s: &str) -> FindingKind {
    match s {
        "sast" => FindingKind::Sast,
        "iac" => FindingKind::Iac,
        "sca" => FindingKind::Sca,
        "secret" => FindingKind::Secret,
        _ => FindingKind::Manual,
    }
}

fn triage_str(t: TriageStatus) -> &'static str {
    match t {
        TriageStatus::Open => "open",
        TriageStatus::Acknowledged => "acknowledged",
        TriageStatus::FalsePositive => "false_positive",
        TriageStatus::Resolved => "resolved",
    }
}
fn triage_from(s: &str) -> TriageStatus {
    match s {
        "acknowledged" => TriageStatus::Acknowledged,
        "false_positive" => TriageStatus::FalsePositive,
        "resolved" => TriageStatus::Resolved,
        _ => TriageStatus::Open,
    }
}

// --- JSON column helpers ----------------------------------------------------

/// Parse a required JSON object column, defaulting on null/empty.
fn json_obj<T: serde::de::DeserializeOwned + Default>(raw: Option<String>) -> AppResult<T> {
    match raw {
        Some(s) if !s.is_empty() => Ok(serde_json::from_str(&s)?),
        _ => Ok(T::default()),
    }
}

/// Parse an optional JSON object column (NULL => None).
fn json_opt<T: serde::de::DeserializeOwned>(raw: Option<String>) -> AppResult<Option<T>> {
    match raw {
        Some(s) if !s.is_empty() => Ok(Some(serde_json::from_str(&s)?)),
        _ => Ok(None),
    }
}

/// Parse a required JSON array column, defaulting to empty.
fn json_vec(raw: Option<String>) -> AppResult<Vec<String>> {
    match raw {
        Some(s) if !s.is_empty() => Ok(serde_json::from_str(&s)?),
        _ => Ok(Vec::new()),
    }
}

/// Map a full `findings` row to a `Finding`.
fn row_to_finding(row: &Row) -> AppResult<Finding> {
    let severity: String = row.get("severity")?;
    let confidence: String = row.get("confidence")?;
    let kind: String = row.get("kind")?;
    let triage_status: String = row.get("triage_status")?;

    Ok(Finding {
        id: row.get("id")?,
        report_id: row.get("report_id")?,
        sort_order: row.get("sort_order")?,
        title: row.get("title")?,
        severity: severity_from(&severity),
        confidence: confidence_from(&confidence),
        kind: kind_from(&kind),
        cwe: row.get("cwe")?,
        cve: row.get("cve")?,
        cvss_vector: row.get("cvss_vector")?,
        cvss_score: row.get("cvss_score")?,
        triage_status: triage_from(&triage_status),
        triage_note: row.get("triage_note")?,
        description: json_obj::<FindingDescription>(row.get("description")?)?,
        remediation: json_obj::<FindingRemediation>(row.get("remediation")?)?,
        evidence: json_opt::<Evidence>(row.get("evidence")?)?,
        poc: json_opt::<StructuredPoc>(row.get("poc")?)?,
        refs: json_vec(row.get("refs")?)?,
        tags: json_vec(row.get("tags")?)?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
    })
}

// --- queries ----------------------------------------------------------------

/// List a report's findings ordered by `sort_order`.
pub fn list(conn: &Connection, report_id: &str) -> AppResult<Vec<Finding>> {
    let mut stmt = conn.prepare(
        "SELECT * FROM findings WHERE report_id = ?1 ORDER BY sort_order, created_at",
    )?;
    // query_map closure must return rusqlite::Result, so collect rows first.
    let mut rows = stmt.query(params![report_id])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(row_to_finding(row)?);
    }
    Ok(out)
}

/// Fetch a single finding by id.
pub fn get(conn: &Connection, id: &str) -> AppResult<Finding> {
    let mut stmt = conn.prepare("SELECT * FROM findings WHERE id = ?1")?;
    let mut rows = stmt.query(params![id])?;
    match rows.next()? {
        Some(row) => row_to_finding(row),
        None => Err(AppError::NotFound),
    }
}

/// The next `sort_order` for a report (max + 1, or 0).
fn next_sort_order(conn: &Connection, report_id: &str) -> AppResult<i64> {
    let max: Option<i64> = conn
        .query_row(
            "SELECT MAX(sort_order) FROM findings WHERE report_id = ?1",
            params![report_id],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    Ok(max.map(|m| m + 1).unwrap_or(0))
}

/// Create a new finding under `report_id`. Applies defaults for omitted
/// optional fields and appends it at the end of the sort order.
pub fn create(conn: &Connection, report_id: &str, input: NewFinding) -> AppResult<Finding> {
    // Guard: parent must exist (FK is enforced, but yield a clean NotFound).
    let exists: bool = conn
        .query_row(
            "SELECT 1 FROM reports WHERE id = ?1",
            params![report_id],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);
    if !exists {
        return Err(AppError::NotFound);
    }

    let id = Uuid::new_v4().to_string();
    let now = now_rfc3339();
    let sort_order = next_sort_order(conn, report_id)?;

    let confidence = input.confidence.unwrap_or(Confidence::Medium);
    let kind = input.kind.unwrap_or(FindingKind::Manual);
    let triage_status = input.triage_status.unwrap_or(TriageStatus::Open);
    let description = input.description.unwrap_or_default();
    let remediation = input.remediation.unwrap_or_default();
    let refs = input.refs.unwrap_or_default();
    let tags = input.tags.unwrap_or_default();

    conn.execute(
        r#"
        INSERT INTO findings
            (id, report_id, sort_order, title, severity, confidence, kind,
             cwe, cve, cvss_vector, cvss_score, triage_status, triage_note,
             description, remediation, evidence, poc, refs, tags,
             created_at, updated_at)
        VALUES
            (?1, ?2, ?3, ?4, ?5, ?6, ?7,
             ?8, ?9, ?10, ?11, ?12, ?13,
             ?14, ?15, ?16, ?17, ?18, ?19,
             ?20, ?20)
        "#,
        params![
            id,
            report_id,
            sort_order,
            input.title,
            input.severity.as_str(),
            confidence_str(confidence),
            kind_str(kind),
            input.cwe,
            input.cve,
            input.cvss_vector,
            input.cvss_score,
            triage_str(triage_status),
            input.triage_note,
            serde_json::to_string(&description)?,
            serde_json::to_string(&remediation)?,
            input
                .evidence
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?,
            input.poc.as_ref().map(serde_json::to_string).transpose()?,
            serde_json::to_string(&refs)?,
            serde_json::to_string(&tags)?,
            now,
        ],
    )?;

    get(conn, &id)
}

/// Apply a partial update to a finding; returns the updated row.
///
/// Double-`Option` fields (cwe, cve, …) distinguish "leave unchanged" (`None`)
/// from "set to NULL" (`Some(None)`).
pub fn update(conn: &Connection, id: &str, patch: FindingPatch) -> AppResult<Finding> {
    let _ = get(conn, id)?; // NotFound if absent.
    let now = now_rfc3339();

    if let Some(title) = patch.title {
        conn.execute(
            "UPDATE findings SET title = ?1 WHERE id = ?2",
            params![title, id],
        )?;
    }
    if let Some(sev) = patch.severity {
        conn.execute(
            "UPDATE findings SET severity = ?1 WHERE id = ?2",
            params![sev.as_str(), id],
        )?;
    }
    if let Some(c) = patch.confidence {
        conn.execute(
            "UPDATE findings SET confidence = ?1 WHERE id = ?2",
            params![confidence_str(c), id],
        )?;
    }
    if let Some(k) = patch.kind {
        conn.execute(
            "UPDATE findings SET kind = ?1 WHERE id = ?2",
            params![kind_str(k), id],
        )?;
    }
    if let Some(cwe) = patch.cwe {
        conn.execute(
            "UPDATE findings SET cwe = ?1 WHERE id = ?2",
            params![cwe, id],
        )?;
    }
    if let Some(cve) = patch.cve {
        conn.execute(
            "UPDATE findings SET cve = ?1 WHERE id = ?2",
            params![cve, id],
        )?;
    }
    if let Some(v) = patch.cvss_vector {
        conn.execute(
            "UPDATE findings SET cvss_vector = ?1 WHERE id = ?2",
            params![v, id],
        )?;
    }
    if let Some(score) = patch.cvss_score {
        conn.execute(
            "UPDATE findings SET cvss_score = ?1 WHERE id = ?2",
            params![score, id],
        )?;
    }
    if let Some(t) = patch.triage_status {
        conn.execute(
            "UPDATE findings SET triage_status = ?1 WHERE id = ?2",
            params![triage_str(t), id],
        )?;
    }
    if let Some(note) = patch.triage_note {
        conn.execute(
            "UPDATE findings SET triage_note = ?1 WHERE id = ?2",
            params![note, id],
        )?;
    }
    if let Some(desc) = patch.description {
        conn.execute(
            "UPDATE findings SET description = ?1 WHERE id = ?2",
            params![serde_json::to_string(&desc)?, id],
        )?;
    }
    if let Some(rem) = patch.remediation {
        conn.execute(
            "UPDATE findings SET remediation = ?1 WHERE id = ?2",
            params![serde_json::to_string(&rem)?, id],
        )?;
    }
    if let Some(ev) = patch.evidence {
        let json = ev.as_ref().map(serde_json::to_string).transpose()?;
        conn.execute(
            "UPDATE findings SET evidence = ?1 WHERE id = ?2",
            params![json, id],
        )?;
    }
    if let Some(poc) = patch.poc {
        let json = poc.as_ref().map(serde_json::to_string).transpose()?;
        conn.execute(
            "UPDATE findings SET poc = ?1 WHERE id = ?2",
            params![json, id],
        )?;
    }
    if let Some(refs) = patch.refs {
        conn.execute(
            "UPDATE findings SET refs = ?1 WHERE id = ?2",
            params![serde_json::to_string(&refs)?, id],
        )?;
    }
    if let Some(tags) = patch.tags {
        conn.execute(
            "UPDATE findings SET tags = ?1 WHERE id = ?2",
            params![serde_json::to_string(&tags)?, id],
        )?;
    }

    conn.execute(
        "UPDATE findings SET updated_at = ?1 WHERE id = ?2",
        params![now, id],
    )?;

    get(conn, id)
}

/// Delete a finding by id.
pub fn delete(conn: &Connection, id: &str) -> AppResult<()> {
    let n = conn.execute("DELETE FROM findings WHERE id = ?1", params![id])?;
    if n == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// Re-assign `sort_order` to match the given id ordering. Ids not belonging to
/// the report are ignored; missing ids are simply left where they are.
pub fn reorder(conn: &mut Connection, report_id: &str, ordered_ids: &[String]) -> AppResult<()> {
    let tx = conn.transaction()?;
    for (idx, fid) in ordered_ids.iter().enumerate() {
        tx.execute(
            "UPDATE findings SET sort_order = ?1 WHERE id = ?2 AND report_id = ?3",
            params![idx as i64, fid, report_id],
        )?;
    }
    tx.commit()?;
    Ok(())
}
