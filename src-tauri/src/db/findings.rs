//! Finding CRUD. Structured sub-objects live in JSON TEXT columns.

use rusqlite::types::ToSql;
use rusqlite::{params, Connection, OptionalExtension, Row};
use uuid::Uuid;

use std::collections::BTreeMap;

use super::now_rfc3339;
use crate::error::{AppError, AppResult};
use crate::models::{
    Asset, AssetKind, Confidence, Evidence, Finding, FindingDescription, FindingKind, FindingPatch,
    FindingRemediation, Mapping, NewFinding, RetestStatus, Severity, StructuredPoc, TriageStatus,
};

// --- enum <-> column string helpers ----------------------------------------

pub(crate) fn confidence_str(c: Confidence) -> &'static str {
    match c {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
    }
}
pub(crate) fn confidence_from(s: &str) -> Confidence {
    match s {
        "low" => Confidence::Low,
        "high" => Confidence::High,
        _ => Confidence::Medium,
    }
}

pub(crate) fn severity_from(s: &str) -> Severity {
    match s {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => Severity::Medium,
    }
}

pub(crate) fn kind_str(k: FindingKind) -> &'static str {
    match k {
        FindingKind::Manual => "manual",
        FindingKind::Sast => "sast",
        FindingKind::Iac => "iac",
        FindingKind::Sca => "sca",
        FindingKind::Secret => "secret",
        FindingKind::Dast => "dast",
    }
}
pub(crate) fn kind_from(s: &str) -> FindingKind {
    match s {
        "sast" => FindingKind::Sast,
        "iac" => FindingKind::Iac,
        "sca" => FindingKind::Sca,
        "secret" => FindingKind::Secret,
        "dast" => FindingKind::Dast,
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
pub(crate) fn json_obj<T: serde::de::DeserializeOwned + Default>(
    raw: Option<String>,
) -> AppResult<T> {
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
pub(crate) fn json_vec(raw: Option<String>) -> AppResult<Vec<String>> {
    match raw {
        Some(s) if !s.is_empty() => Ok(serde_json::from_str(&s)?),
        _ => Ok(Vec::new()),
    }
}

/// Parse the `custom_fields` JSON-object column into a `BTreeMap`, defaulting to
/// empty on NULL / empty.
pub(crate) fn json_map(raw: Option<String>) -> AppResult<BTreeMap<String, String>> {
    match raw {
        Some(s) if !s.is_empty() => Ok(serde_json::from_str(&s)?),
        _ => Ok(BTreeMap::new()),
    }
}

/// Parse the `mappings` JSON-array column into a `Vec<Mapping>`, defaulting to
/// empty on NULL / empty.
pub(crate) fn json_mappings(raw: Option<String>) -> AppResult<Vec<Mapping>> {
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
        retest_status: row
            .get::<_, Option<String>>("retest_status")?
            .as_deref()
            .and_then(RetestStatus::from_db),
        retest_date: row.get("retest_date")?,
        custom_fields: json_map(row.get("custom_fields")?)?,
        mappings: json_mappings(row.get("mappings")?)?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
        deleted_at: row.get("deleted_at")?,
    })
}

/// Serialize a `Finding`'s columns into the positional params shared by the raw
/// insert/update statements (sync merge). Returns the JSON-encoded sub-object
/// strings alongside so they outlive the `params!` borrow.
struct FindingCols {
    description: String,
    remediation: String,
    evidence: Option<String>,
    poc: Option<String>,
    refs: String,
    tags: String,
    custom_fields: String,
    mappings: String,
}

fn finding_cols(f: &Finding) -> AppResult<FindingCols> {
    Ok(FindingCols {
        description: serde_json::to_string(&f.description)?,
        remediation: serde_json::to_string(&f.remediation)?,
        evidence: f.evidence.as_ref().map(serde_json::to_string).transpose()?,
        poc: f.poc.as_ref().map(serde_json::to_string).transpose()?,
        refs: serde_json::to_string(&f.refs)?,
        tags: serde_json::to_string(&f.tags)?,
        custom_fields: serde_json::to_string(&f.custom_fields)?,
        mappings: serde_json::to_string(&f.mappings)?,
    })
}

// --- queries ----------------------------------------------------------------

/// List a report's findings ordered by `sort_order`.
pub fn list(conn: &Connection, report_id: &str) -> AppResult<Vec<Finding>> {
    let mut stmt = conn.prepare(
        "SELECT * FROM findings WHERE report_id = ?1 AND deleted_at IS NULL \
         ORDER BY sort_order, created_at",
    )?;
    // query_map closure must return rusqlite::Result, so collect rows first.
    let mut rows = stmt.query(params![report_id])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(row_to_finding(row)?);
    }
    Ok(out)
}

/// Fetch all findings across every report (used by the sync snapshot). Ordered
/// by id for a deterministic snapshot. INCLUDES soft-deleted rows so their
/// tombstones travel in the bundle.
pub fn list_all(conn: &Connection) -> AppResult<Vec<Finding>> {
    let mut stmt = conn.prepare("SELECT * FROM findings ORDER BY id")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(row_to_finding(row)?);
    }
    Ok(out)
}

/// Whether a finding with this id exists (INCLUDING soft-deleted tombstones, so
/// the sync merge applies LWW rather than re-inserting a locally-deleted row).
pub fn exists(conn: &Connection, id: &str) -> AppResult<bool> {
    let found: bool = conn
        .query_row("SELECT 1 FROM findings WHERE id = ?1", params![id], |_| {
            Ok(true)
        })
        .optional()?
        .unwrap_or(false);
    Ok(found)
}

/// Insert a finding verbatim, preserving its id, sort_order + timestamps (sync
/// merge — NOT the id-generating [`create`]). Caller must ensure the parent
/// report exists.
pub fn insert_raw(conn: &Connection, f: &Finding) -> AppResult<()> {
    let c = finding_cols(f)?;
    conn.execute(
        r#"
        INSERT INTO findings
            (id, report_id, sort_order, title, severity, confidence, kind,
             cwe, cve, cvss_vector, cvss_score, triage_status, triage_note,
             description, remediation, evidence, poc, refs, tags,
             retest_status, retest_date, custom_fields, mappings,
             created_at, updated_at, deleted_at)
        VALUES
            (?1, ?2, ?3, ?4, ?5, ?6, ?7,
             ?8, ?9, ?10, ?11, ?12, ?13,
             ?14, ?15, ?16, ?17, ?18, ?19,
             ?20, ?21, ?22, ?23,
             ?24, ?25, ?26)
        "#,
        params![
            f.id,
            f.report_id,
            f.sort_order,
            f.title,
            f.severity.as_str(),
            confidence_str(f.confidence),
            kind_str(f.kind),
            f.cwe,
            f.cve,
            f.cvss_vector,
            f.cvss_score,
            triage_str(f.triage_status),
            f.triage_note,
            c.description,
            c.remediation,
            c.evidence,
            c.poc,
            c.refs,
            c.tags,
            f.retest_status.map(|r| r.as_str()),
            f.retest_date,
            c.custom_fields,
            c.mappings,
            f.created_at,
            f.updated_at,
            f.deleted_at,
        ],
    )?;
    Ok(())
}

/// Overwrite an existing finding verbatim, preserving the incoming timestamps
/// (sync LWW merge). `report_id` is intentionally NOT updated — a row's parent
/// report is fixed by its primary key.
pub fn update_raw(conn: &Connection, f: &Finding) -> AppResult<()> {
    let c = finding_cols(f)?;
    conn.execute(
        r#"
        UPDATE findings SET
            sort_order = ?2, title = ?3, severity = ?4, confidence = ?5,
            kind = ?6, cwe = ?7, cve = ?8, cvss_vector = ?9, cvss_score = ?10,
            triage_status = ?11, triage_note = ?12, description = ?13,
            remediation = ?14, evidence = ?15, poc = ?16, refs = ?17,
            tags = ?18, retest_status = ?19, retest_date = ?20,
            custom_fields = ?21, mappings = ?22, created_at = ?23,
            updated_at = ?24, deleted_at = ?25
        WHERE id = ?1
        "#,
        params![
            f.id,
            f.sort_order,
            f.title,
            f.severity.as_str(),
            confidence_str(f.confidence),
            kind_str(f.kind),
            f.cwe,
            f.cve,
            f.cvss_vector,
            f.cvss_score,
            triage_str(f.triage_status),
            f.triage_note,
            c.description,
            c.remediation,
            c.evidence,
            c.poc,
            c.refs,
            c.tags,
            f.retest_status.map(|r| r.as_str()),
            f.retest_date,
            c.custom_fields,
            c.mappings,
            f.created_at,
            f.updated_at,
            f.deleted_at,
        ],
    )?;
    Ok(())
}

/// Fetch a single live finding by id (excludes soft-deleted tombstones).
pub fn get(conn: &Connection, id: &str) -> AppResult<Finding> {
    let mut stmt = conn.prepare("SELECT * FROM findings WHERE id = ?1 AND deleted_at IS NULL")?;
    let mut rows = stmt.query(params![id])?;
    match rows.next()? {
        Some(row) => row_to_finding(row),
        None => Err(AppError::NotFound),
    }
}

/// Fetch a finding by id INCLUDING a soft-deleted tombstone (used by the sync
/// merge to read the local `updated_at`/`deleted_at` for LWW).
pub fn get_raw(conn: &Connection, id: &str) -> AppResult<Finding> {
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
    let custom_fields = input.custom_fields.unwrap_or_default();
    let mappings = input.mappings.unwrap_or_default();

    conn.execute(
        r#"
        INSERT INTO findings
            (id, report_id, sort_order, title, severity, confidence, kind,
             cwe, cve, cvss_vector, cvss_score, triage_status, triage_note,
             description, remediation, evidence, poc, refs, tags,
             retest_status, retest_date, custom_fields, mappings,
             created_at, updated_at)
        VALUES
            (?1, ?2, ?3, ?4, ?5, ?6, ?7,
             ?8, ?9, ?10, ?11, ?12, ?13,
             ?14, ?15, ?16, ?17, ?18, ?19,
             ?20, ?21, ?22, ?23,
             ?24, ?24)
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
            input.retest_status.map(|r| r.as_str()),
            input.retest_date,
            serde_json::to_string(&custom_fields)?,
            serde_json::to_string(&mappings)?,
            now,
        ],
    )?;

    get(conn, &id)
}

/// Bulk-insert findings under `report_id`, skipping any whose content
/// fingerprint already exists in the report OR was already inserted earlier in
/// this same batch. Runs in one transaction. Returns `(inserted, deduped)`.
///
/// The fingerprint (see [`crate::import::fingerprint`]) is a hash of
/// `title | cwe | cve | primary-evidence-file | severity`, so re-importing the
/// same scan — or two scanners reporting the same issue — collapses to one
/// finding instead of piling up duplicates.
pub fn create_bulk_dedup(
    conn: &mut Connection,
    report_id: &str,
    inputs: Vec<NewFinding>,
) -> AppResult<(usize, usize)> {
    use std::collections::HashSet;

    // Guard: parent must exist (yield a clean NotFound).
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

    // Seed the seen-set with the fingerprints of the report's existing findings.
    let mut seen: HashSet<u64> = HashSet::new();
    for f in list(conn, report_id)? {
        seen.insert(crate::import::fingerprint(
            &f.title,
            f.cwe.as_deref(),
            f.cve.as_deref(),
            f.evidence.as_ref().and_then(|e| e.file.as_deref()),
            f.severity,
        ));
    }

    let mut sort_order = next_sort_order(conn, report_id)?;
    let now = now_rfc3339();
    let tx = conn.transaction()?;
    let mut inserted = 0usize;
    let mut deduped = 0usize;

    for input in inputs {
        let fp = crate::import::finding_fingerprint(&input);
        if !seen.insert(fp) {
            deduped += 1;
            continue;
        }

        let id = Uuid::new_v4().to_string();
        let confidence = input.confidence.unwrap_or(Confidence::Medium);
        let kind = input.kind.unwrap_or(FindingKind::Manual);
        let triage_status = input.triage_status.unwrap_or(TriageStatus::Open);
        let description = input.description.unwrap_or_default();
        let remediation = input.remediation.unwrap_or_default();
        let refs = input.refs.unwrap_or_default();
        let tags = input.tags.unwrap_or_default();
        let custom_fields = input.custom_fields.unwrap_or_default();
        let mappings = input.mappings.unwrap_or_default();

        tx.execute(
            r#"
            INSERT INTO findings
                (id, report_id, sort_order, title, severity, confidence, kind,
                 cwe, cve, cvss_vector, cvss_score, triage_status, triage_note,
                 description, remediation, evidence, poc, refs, tags,
                 retest_status, retest_date, custom_fields, mappings,
                 created_at, updated_at)
            VALUES
                (?1, ?2, ?3, ?4, ?5, ?6, ?7,
                 ?8, ?9, ?10, ?11, ?12, ?13,
                 ?14, ?15, ?16, ?17, ?18, ?19,
                 ?20, ?21, ?22, ?23,
                 ?24, ?24)
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
                input.retest_status.map(|r| r.as_str()),
                input.retest_date.clone(),
                serde_json::to_string(&custom_fields)?,
                serde_json::to_string(&mappings)?,
                now,
            ],
        )?;
        sort_order += 1;
        inserted += 1;
    }

    tx.commit()?;
    Ok((inserted, deduped))
}

/// Apply a partial update to a finding; returns the updated row.
///
/// Double-`Option` fields (cwe, cve, …) distinguish "leave unchanged" (`None`)
/// from "set to NULL" (`Some(None)`).
pub fn update(conn: &Connection, id: &str, patch: FindingPatch) -> AppResult<Finding> {
    let _ = get(conn, id)?; // NotFound if absent.
    let now = now_rfc3339();

    // Single atomic UPDATE built from the present patch fields + updated_at, so
    // a multi-field edit never tears into separate writes with a stale
    // updated_at (which previously let a concurrent sync revert the edit). The
    // double-Option fields map Some(None) -> SQL NULL, Some(Some(v)) -> v.
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
        vals.push(Box::new(cwe)); // Option<String> -> NULL when None
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
    if let Some(t) = patch.triage_status {
        sets.push("triage_status = ?");
        vals.push(Box::new(triage_str(t).to_string()));
    }
    if let Some(note) = patch.triage_note {
        sets.push("triage_note = ?");
        vals.push(Box::new(note));
    }
    if let Some(desc) = patch.description {
        sets.push("description = ?");
        vals.push(Box::new(serde_json::to_string(&desc)?));
    }
    if let Some(rem) = patch.remediation {
        sets.push("remediation = ?");
        vals.push(Box::new(serde_json::to_string(&rem)?));
    }
    if let Some(ev) = patch.evidence {
        let json = ev.as_ref().map(serde_json::to_string).transpose()?;
        sets.push("evidence = ?");
        vals.push(Box::new(json)); // Option<String> -> NULL when None
    }
    if let Some(poc) = patch.poc {
        let json = poc.as_ref().map(serde_json::to_string).transpose()?;
        sets.push("poc = ?");
        vals.push(Box::new(json));
    }
    if let Some(refs) = patch.refs {
        sets.push("refs = ?");
        vals.push(Box::new(serde_json::to_string(&refs)?));
    }
    if let Some(tags) = patch.tags {
        sets.push("tags = ?");
        vals.push(Box::new(serde_json::to_string(&tags)?));
    }
    if let Some(rs) = patch.retest_status {
        // Some(None) clears (NULL); Some(Some(v)) sets the snake_case string.
        sets.push("retest_status = ?");
        vals.push(Box::new(rs.map(|r| r.as_str().to_string())));
    }
    if let Some(rd) = patch.retest_date {
        sets.push("retest_date = ?");
        vals.push(Box::new(rd)); // Option<String> -> NULL when None
    }
    if let Some(cf) = patch.custom_fields {
        sets.push("custom_fields = ?");
        vals.push(Box::new(serde_json::to_string(&cf)?));
    }
    if let Some(maps) = patch.mappings {
        sets.push("mappings = ?");
        vals.push(Box::new(serde_json::to_string(&maps)?));
    }

    let sql = format!("UPDATE findings SET {} WHERE id = ?", sets.join(", "));
    vals.push(Box::new(id.to_string()));
    let bound: Vec<&dyn ToSql> = vals.iter().map(|b| b.as_ref()).collect();
    conn.execute(&sql, bound.as_slice())?;

    get(conn, id)
}

/// Soft-delete a finding (and its evidence images): set `deleted_at = now` and
/// bump `updated_at` so the deletion becomes a tombstone that travels through
/// sync and wins LWW, instead of resurrecting from a peer. Children (evidence
/// images) are soft-deleted alongside so the subtree is consistently gone.
pub fn delete(conn: &Connection, id: &str) -> AppResult<()> {
    let now = now_rfc3339();
    let n = conn.execute(
        "UPDATE findings SET deleted_at = ?1, updated_at = ?1 \
         WHERE id = ?2 AND deleted_at IS NULL",
        params![now, id],
    )?;
    if n == 0 {
        return Err(AppError::NotFound);
    }
    conn.execute(
        "UPDATE evidence_images SET deleted_at = ?1 \
         WHERE finding_id = ?2 AND deleted_at IS NULL",
        params![now, id],
    )?;
    Ok(())
}

/// Deep-copy a finding within its OWN report: a fresh-UUID finding (title +
/// " (copy)", appended at the next sort order) carrying every authored field
/// EXCEPT the retest disposition, which is reset (a clone is a fresh assessment).
/// Its evidence images (bytes copied) and affected-asset links (same report, so
/// the asset ids are reused) are copied too. Runs in one transaction; returns
/// the new finding.
pub fn clone_finding(conn: &mut Connection, finding_id: &str) -> AppResult<Finding> {
    // Read the source (live only) first to fail fast with NotFound.
    let src = get(conn, finding_id)?;
    let now = now_rfc3339();
    let new_id = Uuid::new_v4().to_string();

    let tx = conn.transaction()?;
    {
        let c: &Connection = &tx;
        let sort_order = next_sort_order(c, &src.report_id)?;

        // Build the clone: reset retest fields, fresh id/sort_order/timestamps.
        let clone = Finding {
            id: new_id.clone(),
            report_id: src.report_id.clone(),
            sort_order,
            title: format!("{} (copy)", src.title),
            retest_status: None,
            retest_date: None,
            created_at: now.clone(),
            updated_at: now.clone(),
            deleted_at: None,
            ..src.clone()
        };
        insert_raw(c, &clone)?;

        // Copy the source's evidence images (bytes + metadata) under the clone.
        copy_evidence_images(c, finding_id, &new_id, &now)?;

        // Re-link the same assets (the clone lives in the same report).
        for aid in live_finding_asset_ids(c, finding_id)? {
            link_finding_asset(c, &new_id, &aid)?;
        }
    }
    tx.commit()?;

    get(conn, &new_id)
}

/// Copy every LIVE evidence image of `src_finding_id` to `dst_finding_id` with
/// fresh image ids, preserving caption/mime/sort_order and the raw bytes. Shared
/// by [`clone_finding`] and `db::reports::clone_report`.
pub(crate) fn copy_evidence_images(
    conn: &Connection,
    src_finding_id: &str,
    dst_finding_id: &str,
    now: &str,
) -> AppResult<()> {
    let mut stmt = conn.prepare(
        "SELECT caption, mime, data, sort_order FROM evidence_images \
         WHERE finding_id = ?1 AND deleted_at IS NULL ORDER BY sort_order, created_at",
    )?;
    let mut rows = stmt.query(params![src_finding_id])?;
    while let Some(row) = rows.next()? {
        let caption: String = row.get("caption")?;
        let mime: String = row.get("mime")?;
        let data: Vec<u8> = row.get("data")?;
        let sort_order: i64 = row.get("sort_order")?;
        let img_id = Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO evidence_images \
                (id, finding_id, caption, mime, data, sort_order, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![img_id, dst_finding_id, caption, mime, data, sort_order, now],
        )?;
    }
    Ok(())
}

/// The live asset ids linked to a finding (filters tombstoned assets), ordered
/// by the asset sort order. Used by the clone paths to re-link assets.
pub(crate) fn live_finding_asset_ids(
    conn: &Connection,
    finding_id: &str,
) -> AppResult<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT a.id FROM finding_assets fa \
         JOIN assets a ON a.id = fa.asset_id \
         WHERE fa.finding_id = ?1 AND a.deleted_at IS NULL \
         ORDER BY a.sort_order, a.created_at",
    )?;
    let mut rows = stmt.query(params![finding_id])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(row.get(0)?);
    }
    Ok(out)
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

// --- finding ↔ asset link set ----------------------------------------------
//
// `finding_assets` is a DERIVED set (which assets a finding affects), not a
// versioned entity, so it has no soft-delete column. It is replaced wholesale by
// [`set_finding_assets`]; sync UNIONs the incoming links (link *removals* do not
// propagate — a documented limitation, see `sync::merge`).

/// Replace a finding's affected-asset link set with exactly `asset_ids`. Only
/// ids that reference assets belonging to the finding's report are linked
/// (cross-report or unknown ids are silently ignored) so the FK always holds.
/// Returns the number of links written. Runs in a transaction.
pub fn set_finding_assets(
    conn: &mut Connection,
    finding_id: &str,
    asset_ids: &[String],
) -> AppResult<usize> {
    // Resolve the finding's report so we can constrain links to same-report
    // assets (and yield a clean NotFound if the finding is absent).
    let report_id: Option<String> = conn
        .query_row(
            "SELECT report_id FROM findings WHERE id = ?1 AND deleted_at IS NULL",
            params![finding_id],
            |r| r.get(0),
        )
        .optional()?;
    let report_id = report_id.ok_or(AppError::NotFound)?;

    let tx = conn.transaction()?;
    tx.execute(
        "DELETE FROM finding_assets WHERE finding_id = ?1",
        params![finding_id],
    )?;
    let mut written = 0usize;
    for aid in asset_ids {
        // INSERT only when the asset exists, is live, and belongs to the same
        // report. OR IGNORE de-dups repeated ids in the input.
        let n = tx.execute(
            "INSERT OR IGNORE INTO finding_assets (finding_id, asset_id) \
             SELECT ?1, a.id FROM assets a \
             WHERE a.id = ?2 AND a.report_id = ?3 AND a.deleted_at IS NULL",
            params![finding_id, aid, report_id],
        )?;
        written += n;
    }
    tx.commit()?;
    Ok(written)
}

/// List the asset ids linked to a finding (raw — includes links to assets that
/// may since have been tombstoned; callers wanting live assets should join).
/// Provided for completeness alongside [`list_finding_assets`]; not yet wired to
/// a command.
#[allow(dead_code)]
pub fn list_finding_asset_ids(conn: &Connection, finding_id: &str) -> AppResult<Vec<String>> {
    let mut stmt = conn
        .prepare("SELECT asset_id FROM finding_assets WHERE finding_id = ?1 ORDER BY asset_id")?;
    let mut rows = stmt.query(params![finding_id])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(row.get(0)?);
    }
    Ok(out)
}

/// List the LIVE assets linked to a finding, ordered by the asset sort order.
/// Tombstoned assets are filtered out (the link row survives but the asset is
/// gone). Used by `list_finding_assets` and the render layer.
pub fn list_finding_assets(conn: &Connection, finding_id: &str) -> AppResult<Vec<Asset>> {
    let mut stmt = conn.prepare(
        "SELECT a.id, a.report_id, a.kind, a.identifier, a.description, \
                a.sort_order, a.created_at, a.updated_at, a.deleted_at \
         FROM finding_assets fa \
         JOIN assets a ON a.id = fa.asset_id \
         WHERE fa.finding_id = ?1 AND a.deleted_at IS NULL \
         ORDER BY a.sort_order, a.created_at",
    )?;
    let mut rows = stmt.query(params![finding_id])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let kind: String = row.get("kind")?;
        out.push(Asset {
            id: row.get("id")?,
            report_id: row.get("report_id")?,
            kind: AssetKind::from_db(&kind),
            identifier: row.get("identifier")?,
            description: row.get("description")?,
            sort_order: row.get("sort_order")?,
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
            deleted_at: row.get("deleted_at")?,
        });
    }
    Ok(out)
}

/// All `(finding_id, asset_id)` link pairs across the vault (sync snapshot).
/// Ordered for a deterministic snapshot.
pub fn list_all_finding_asset_links(conn: &Connection) -> AppResult<Vec<(String, String)>> {
    let mut stmt = conn
        .prepare("SELECT finding_id, asset_id FROM finding_assets ORDER BY finding_id, asset_id")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push((row.get(0)?, row.get(1)?));
    }
    Ok(out)
}

/// Insert a single `(finding_id, asset_id)` link if not already present (sync
/// merge UNION). No-op when either endpoint is absent (FK) — the caller checks
/// existence first; `OR IGNORE` also guards the PK and a racing duplicate.
/// Returns `true` if a new link row was written.
pub fn link_finding_asset(conn: &Connection, finding_id: &str, asset_id: &str) -> AppResult<bool> {
    let n = conn.execute(
        "INSERT OR IGNORE INTO finding_assets (finding_id, asset_id) VALUES (?1, ?2)",
        params![finding_id, asset_id],
    )?;
    Ok(n > 0)
}
