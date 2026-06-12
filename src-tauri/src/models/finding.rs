//! Finding model + its structured sub-objects and enums.
//!
//! Mirrors `secai.core.models.finding` for the fields a manually-authored
//! pentest report needs. Sub-objects (`description`, `remediation`,
//! `evidence`, `poc`) are persisted as JSON TEXT columns and (de)serialized
//! with serde_json by the `db` layer.

use serde::{Deserialize, Serialize};

/// Risk severity. Ordering matters for report sorting (critical first); see
/// [`Severity::rank`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Higher = more severe. Used to sort findings descending in the report.
    pub fn rank(self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

    /// snake_case wire string (also what is stored in the DB column).
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// Assessor confidence in the finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// Operator triage disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriageStatus {
    Open,
    Acknowledged,
    FalsePositive,
    Resolved,
}

/// How the finding was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    Manual,
    Sast,
    Iac,
    Sca,
    Secret,
}

/// Five-facet structured description (stored as JSON).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FindingDescription {
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub root_cause: String,
    #[serde(default)]
    pub attack_vector: String,
    #[serde(default)]
    pub business_impact: String,
    #[serde(default)]
    pub technical_details: String,
}

/// Remediation block (stored as JSON).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FindingRemediation {
    #[serde(default)]
    pub fix: String,
    #[serde(default)]
    pub code_patch: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
}

/// Optional code/location evidence (stored as JSON, whole object nullable).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Evidence {
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub start_line: Option<u32>,
    #[serde(default)]
    pub end_line: Option<u32>,
    #[serde(default)]
    pub snippet: Option<String>,
}

/// Optional structured proof-of-concept (stored as JSON, whole object nullable).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StructuredPoc {
    #[serde(default)]
    pub scenario: String,
    #[serde(default)]
    pub exploitation_steps: Vec<String>,
    #[serde(default)]
    pub payload: Option<String>,
}

/// A single report finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub report_id: String,
    pub sort_order: i64,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub kind: FindingKind,
    pub cwe: Option<String>,
    pub cve: Option<String>,
    pub cvss_vector: Option<String>,
    pub cvss_score: Option<f64>,
    pub triage_status: TriageStatus,
    pub triage_note: Option<String>,
    pub description: FindingDescription,
    pub remediation: FindingRemediation,
    pub evidence: Option<Evidence>,
    pub poc: Option<StructuredPoc>,
    pub refs: Vec<String>,
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Payload for `create_finding`. Everything except `title` + `severity` is
/// optional with sensible defaults applied by the `db` layer.
#[derive(Debug, Clone, Deserialize)]
pub struct NewFinding {
    pub title: String,
    pub severity: Severity,
    #[serde(default)]
    pub confidence: Option<Confidence>,
    #[serde(default)]
    pub kind: Option<FindingKind>,
    #[serde(default)]
    pub cwe: Option<String>,
    #[serde(default)]
    pub cve: Option<String>,
    #[serde(default)]
    pub cvss_vector: Option<String>,
    #[serde(default)]
    pub cvss_score: Option<f64>,
    #[serde(default)]
    pub triage_status: Option<TriageStatus>,
    #[serde(default)]
    pub triage_note: Option<String>,
    #[serde(default)]
    pub description: Option<FindingDescription>,
    #[serde(default)]
    pub remediation: Option<FindingRemediation>,
    #[serde(default)]
    pub evidence: Option<Evidence>,
    #[serde(default)]
    pub poc: Option<StructuredPoc>,
    #[serde(default)]
    pub refs: Option<Vec<String>>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

/// Partial update for `update_finding`. A `None` field is left unchanged.
///
/// Note: nullable scalar columns (cwe, cve, …) can be *cleared* by passing
/// the field with a JSON `null`; serde maps that to `Some(None)` thanks to
/// the double-Option. Absent fields deserialize to `None` and are skipped.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FindingPatch {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub severity: Option<Severity>,
    #[serde(default)]
    pub confidence: Option<Confidence>,
    #[serde(default)]
    pub kind: Option<FindingKind>,
    #[serde(default, deserialize_with = "double_option")]
    pub cwe: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub cve: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub cvss_vector: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub cvss_score: Option<Option<f64>>,
    #[serde(default)]
    pub triage_status: Option<TriageStatus>,
    #[serde(default, deserialize_with = "double_option")]
    pub triage_note: Option<Option<String>>,
    #[serde(default)]
    pub description: Option<FindingDescription>,
    #[serde(default)]
    pub remediation: Option<FindingRemediation>,
    #[serde(default, deserialize_with = "double_option")]
    pub evidence: Option<Option<Evidence>>,
    #[serde(default, deserialize_with = "double_option")]
    pub poc: Option<Option<StructuredPoc>>,
    #[serde(default)]
    pub refs: Option<Vec<String>>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

/// Distinguishes "field absent" (`None`) from "field present and null"
/// (`Some(None)`) when deserializing a patch object.
fn double_option<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Deserialize::deserialize(deserializer).map(Some)
}
