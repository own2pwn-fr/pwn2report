//! secai / EASM native Finding JSON importer (single object or array).
//!
//! The secai-core `Finding` shape and our [`NewFinding`] already align on field
//! names and the structured sub-object shapes (description facets, remediation,
//! evidence, poc), all snake_case. We deserialize leniently into a
//! `serde_json::Value` and map field-by-field, so one bad/uppercase/missing
//! field never aborts the whole batch — that record is skipped with a warning.

use serde_json::Value;

use super::{annotate_cwe_name, normalize_cve, normalize_cwe, severity_from_label, ImportOutcome};
use crate::error::{AppError, AppResult};
use crate::models::{
    Confidence, Evidence, FindingDescription, FindingKind, FindingRemediation, NewFinding,
    StructuredPoc, TriageStatus,
};

fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
}

/// Lenient confidence parse: label-based, defaults to `None` on absence.
fn confidence_of(v: &Value) -> Option<Confidence> {
    match str_field(v, "confidence")?.to_ascii_lowercase().as_str() {
        "low" => Some(Confidence::Low),
        "high" => Some(Confidence::High),
        _ => Some(Confidence::Medium),
    }
}

/// Lenient kind parse (label-based, case-insensitive). Unknown → None (caller
/// applies the default).
fn kind_of(v: &Value) -> Option<FindingKind> {
    match str_field(v, "kind")?.to_ascii_lowercase().as_str() {
        "sast" => Some(FindingKind::Sast),
        "dast" => Some(FindingKind::Dast),
        "iac" => Some(FindingKind::Iac),
        "sca" => Some(FindingKind::Sca),
        "secret" => Some(FindingKind::Secret),
        "manual" => Some(FindingKind::Manual),
        _ => None,
    }
}

fn triage_of(v: &Value) -> Option<TriageStatus> {
    match str_field(v, "triage_status")?.to_ascii_lowercase().as_str() {
        "acknowledged" => Some(TriageStatus::Acknowledged),
        "false_positive" => Some(TriageStatus::FalsePositive),
        "resolved" => Some(TriageStatus::Resolved),
        "open" => Some(TriageStatus::Open),
        _ => None,
    }
}

/// Map one secai Finding `Value` into a [`NewFinding`], leniently. Returns
/// `None` (with no panic) only when the mandatory `title` is missing/empty.
fn map_one(v: &Value) -> Option<NewFinding> {
    let title = str_field(v, "title")?;

    // Severity is label-based and case-insensitive; missing/unknown → Medium.
    let severity = severity_from_label(&str_field(v, "severity").unwrap_or_default());

    let cwe = str_field(v, "cwe").and_then(|s| normalize_cwe(&s));
    let cve = str_field(v, "cve").and_then(|s| normalize_cve(&s));

    // Structured sub-objects: deserialize leniently, defaulting on shape errors.
    let description: Option<FindingDescription> = v
        .get("description")
        .and_then(|d| serde_json::from_value(d.clone()).ok());
    let remediation: Option<FindingRemediation> = v
        .get("remediation")
        .and_then(|r| serde_json::from_value(r.clone()).ok());
    let evidence: Option<Evidence> = v
        .get("evidence")
        .and_then(|e| serde_json::from_value(e.clone()).ok());
    let poc: Option<StructuredPoc> = v
        .get("poc")
        .and_then(|p| serde_json::from_value(p.clone()).ok());

    let refs: Option<Vec<String>> = v.get("refs").and_then(|r| r.as_array()).map(|a| {
        a.iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect()
    });

    // Tag the source while preserving any tags secai already carried.
    let mut tags: Vec<String> = v
        .get("tags")
        .and_then(|t| t.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    if !tags.iter().any(|t| t == "imported") {
        tags.push("imported".into());
    }
    if !tags.iter().any(|t| t == "secai") {
        tags.push("secai".into());
    }

    let mut f = NewFinding {
        title,
        severity,
        confidence: confidence_of(v),
        // secai findings come from scanners; default to sast if unset.
        kind: Some(kind_of(v).unwrap_or(FindingKind::Sast)),
        cwe,
        cve,
        cvss_vector: str_field(v, "cvss_vector"),
        cvss_score: v.get("cvss_score").and_then(|s| s.as_f64()),
        triage_status: triage_of(v),
        triage_note: str_field(v, "triage_note"),
        description,
        remediation,
        evidence,
        poc,
        refs,
        tags: Some(tags),
        retest_status: None,
        retest_date: None,
        custom_fields: None,
        mappings: None,
    };
    annotate_cwe_name(&mut f);
    Some(f)
}

pub fn parse(content: &str) -> AppResult<ImportOutcome> {
    let value: Value = serde_json::from_str(content)
        .map_err(|e| AppError::Import(format!("invalid secai JSON: {e}")))?;

    // Accept either a single finding object or an array of findings.
    let items: Vec<Value> = match value {
        Value::Array(a) => a,
        obj @ Value::Object(_) => vec![obj],
        _ => {
            return Err(AppError::Import(
                "secai import expects a Finding object or array".into(),
            ))
        }
    };

    let mut out = ImportOutcome::new();
    for (i, item) in items.into_iter().enumerate() {
        match map_one(&item) {
            Some(f) => out.push(f),
            None => out.warn(format!("secai record #{}: skipped (missing title)", i + 1)),
        }
    }
    Ok(out)
}
