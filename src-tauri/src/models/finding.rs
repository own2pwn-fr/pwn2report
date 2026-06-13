//! Finding model + its structured sub-objects and enums.
//!
//! Mirrors `secai.core.models.finding` for the fields a manually-authored
//! pentest report needs. Sub-objects (`description`, `remediation`,
//! `evidence`, `poc`) are persisted as JSON TEXT columns and (de)serialized
//! with serde_json by the `db` layer.

use std::collections::BTreeMap;

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

/// Retest disposition for a finding (the "did the fix land?" verdict of a
/// follow-up assessment). `None` on the model means "no retest column value";
/// the explicit [`RetestStatus::NotRetested`] is the in-band "checked, still to
/// do" state. Serializes snake_case to match the DB column + wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetestStatus {
    NotRetested,
    Fixed,
    PartiallyFixed,
    NotFixed,
    RiskAccepted,
}

impl RetestStatus {
    /// snake_case wire string (also what is stored in the DB column).
    pub fn as_str(self) -> &'static str {
        match self {
            RetestStatus::NotRetested => "not_retested",
            RetestStatus::Fixed => "fixed",
            RetestStatus::PartiallyFixed => "partially_fixed",
            RetestStatus::NotFixed => "not_fixed",
            RetestStatus::RiskAccepted => "risk_accepted",
        }
    }

    /// Parse a column value back into a `RetestStatus`. Returns `None` for NULL /
    /// empty / unknown values so an absent column maps to "no retest".
    pub fn from_db(s: &str) -> Option<RetestStatus> {
        match s {
            "not_retested" => Some(RetestStatus::NotRetested),
            "fixed" => Some(RetestStatus::Fixed),
            "partially_fixed" => Some(RetestStatus::PartiallyFixed),
            "not_fixed" => Some(RetestStatus::NotFixed),
            "risk_accepted" => Some(RetestStatus::RiskAccepted),
            _ => None,
        }
    }
}

/// A compliance / framework mapping for a finding (e.g. OWASP Top 10, PCI-DSS,
/// MITRE ATT&CK). Stored as an element of the finding's `mappings` JSON array.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mapping {
    /// Framework name/slug ("OWASP", "PCI-DSS", "MITRE ATT&CK", …).
    pub framework: String,
    /// Identifier within the framework ("A01:2021", "6.5.1", "T1190", …).
    pub id: String,
    /// Optional human-readable label for the identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
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
    /// Retest disposition (schema v7). `None` = no retest recorded; an explicit
    /// [`RetestStatus`] otherwise. Omitted from the IPC payload when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retest_status: Option<RetestStatus>,
    /// Date the retest was performed (free-form / ISO). `None` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retest_date: Option<String>,
    /// Arbitrary user-defined fields (string → string), stored as a JSON object.
    /// Defaults to an empty map.
    #[serde(default)]
    pub custom_fields: BTreeMap<String, String>,
    /// Compliance / framework mappings (schema v7), stored as a JSON array.
    /// Defaults to empty.
    #[serde(default)]
    pub mappings: Vec<Mapping>,
    pub created_at: String,
    pub updated_at: String,
    /// Soft-delete tombstone marker (RFC3339). `None` = live row. Omitted from
    /// the IPC payload when absent; carried through the sync bundle so deletes
    /// propagate across devices. Not surfaced in the UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
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
    #[serde(default)]
    pub retest_status: Option<RetestStatus>,
    #[serde(default)]
    pub retest_date: Option<String>,
    #[serde(default)]
    pub custom_fields: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub mappings: Option<Vec<Mapping>>,
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
    #[serde(default, deserialize_with = "super::double_option")]
    pub cwe: Option<Option<String>>,
    #[serde(default, deserialize_with = "super::double_option")]
    pub cve: Option<Option<String>>,
    #[serde(default, deserialize_with = "super::double_option")]
    pub cvss_vector: Option<Option<String>>,
    #[serde(default, deserialize_with = "super::double_option")]
    pub cvss_score: Option<Option<f64>>,
    #[serde(default)]
    pub triage_status: Option<TriageStatus>,
    #[serde(default, deserialize_with = "super::double_option")]
    pub triage_note: Option<Option<String>>,
    #[serde(default)]
    pub description: Option<FindingDescription>,
    #[serde(default)]
    pub remediation: Option<FindingRemediation>,
    #[serde(default, deserialize_with = "super::double_option")]
    pub evidence: Option<Option<Evidence>>,
    #[serde(default, deserialize_with = "super::double_option")]
    pub poc: Option<Option<StructuredPoc>>,
    #[serde(default)]
    pub refs: Option<Vec<String>>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    /// Nullable: a JSON `null` clears the retest status; an omitted field leaves
    /// it. `Some(Some(v))` sets it.
    #[serde(default, deserialize_with = "super::double_option")]
    pub retest_status: Option<Option<RetestStatus>>,
    #[serde(default, deserialize_with = "super::double_option")]
    pub retest_date: Option<Option<String>>,
    /// Replace-on-present: the whole map is replaced when the field is present.
    #[serde(default)]
    pub custom_fields: Option<BTreeMap<String, String>>,
    /// Replace-on-present: the whole array is replaced when the field is present.
    #[serde(default)]
    pub mappings: Option<Vec<Mapping>>,
}
