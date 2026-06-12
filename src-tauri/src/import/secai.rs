//! secai / EASM native Finding JSON importer (single object or array).
//!
//! The secai-core `Finding` shape and our [`NewFinding`] already align on field
//! names and the structured sub-object shapes (description facets, remediation,
//! evidence, poc), all snake_case. We deserialize the reportable subset and
//! ignore secai-only fields (scan_id, fingerprint, lifecycle, taint_chain, …).

use serde::Deserialize;
use serde_json::Value;

use crate::error::{AppError, AppResult};
use crate::models::{
    Confidence, Evidence, FindingDescription, FindingKind, FindingRemediation, NewFinding,
    Severity, StructuredPoc, TriageStatus,
};

/// The reportable subset of a secai `Finding`. Unknown fields are ignored by
/// serde (no `deny_unknown_fields`), so secai-only fields pass through harmlessly.
#[derive(Debug, Deserialize)]
struct SecaiFinding {
    title: String,
    severity: Severity,
    #[serde(default)]
    confidence: Option<Confidence>,
    #[serde(default)]
    kind: Option<FindingKind>,
    #[serde(default)]
    cwe: Option<String>,
    #[serde(default)]
    cve: Option<String>,
    #[serde(default)]
    cvss_vector: Option<String>,
    #[serde(default)]
    cvss_score: Option<f64>,
    #[serde(default)]
    triage_status: Option<TriageStatus>,
    #[serde(default)]
    triage_note: Option<String>,
    #[serde(default)]
    description: Option<FindingDescription>,
    #[serde(default)]
    remediation: Option<FindingRemediation>,
    #[serde(default)]
    evidence: Option<Evidence>,
    #[serde(default)]
    poc: Option<StructuredPoc>,
    #[serde(default)]
    refs: Option<Vec<String>>,
    #[serde(default)]
    tags: Option<Vec<String>>,
}

impl From<SecaiFinding> for NewFinding {
    fn from(s: SecaiFinding) -> Self {
        // Tag the source while preserving any tags secai already carried.
        let mut tags = s.tags.unwrap_or_default();
        if !tags.iter().any(|t| t == "imported") {
            tags.push("imported".into());
        }
        if !tags.iter().any(|t| t == "secai") {
            tags.push("secai".into());
        }
        NewFinding {
            title: s.title,
            severity: s.severity,
            confidence: s.confidence,
            // secai findings come from scanners; default to sast if unset.
            kind: Some(s.kind.unwrap_or(FindingKind::Sast)),
            cwe: s.cwe,
            cve: s.cve,
            cvss_vector: s.cvss_vector,
            cvss_score: s.cvss_score,
            triage_status: s.triage_status,
            triage_note: s.triage_note,
            description: s.description,
            remediation: s.remediation,
            evidence: s.evidence,
            poc: s.poc,
            refs: s.refs,
            tags: Some(tags),
        }
    }
}

pub fn parse(content: &str) -> AppResult<Vec<NewFinding>> {
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

    let mut findings = Vec::with_capacity(items.len());
    for item in items {
        let parsed: SecaiFinding = serde_json::from_value(item)
            .map_err(|e| AppError::Import(format!("invalid secai Finding: {e}")))?;
        findings.push(parsed.into());
    }
    Ok(findings)
}
