//! Knowledge-base entry model: a client-neutral, reusable finding template.
//!
//! KB entries mirror the reportable subset of a [`Finding`](super::finding)
//! (title/severity/confidence/kind/cwe/cve/cvss + structured description and
//! remediation + tags) but carry no per-report context (no evidence, poc, or
//! triage). Their JSON sub-objects use the exact same shapes as findings so an
//! entry can be materialised into a report finding without translation.

use serde::{Deserialize, Serialize};

use super::finding::{Confidence, FindingDescription, FindingKind, FindingRemediation, Severity};

/// A reusable finding template stored in the vault KB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KbEntry {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub kind: FindingKind,
    pub cwe: Option<String>,
    pub cve: Option<String>,
    pub cvss_vector: Option<String>,
    pub cvss_score: Option<f64>,
    pub description: FindingDescription,
    pub remediation: FindingRemediation,
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    /// Soft-delete tombstone marker (RFC3339). `None` = live row. Omitted from
    /// the IPC payload when absent; carried through the sync bundle so deletes
    /// propagate across devices. Not surfaced in the UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
}

/// Payload for `kb_create` (and the shape of each bundled-catalog entry).
/// Everything except `title` + `severity` is optional with sensible defaults
/// applied by the `db` layer.
#[derive(Debug, Clone, Deserialize)]
pub struct NewKbEntry {
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
    pub description: Option<FindingDescription>,
    #[serde(default)]
    pub remediation: Option<FindingRemediation>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

/// Partial update for `kb_update`. A `None` field is left unchanged; nullable
/// scalar columns can be cleared by passing JSON `null` (double-Option).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct KbEntryPatch {
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
    pub description: Option<FindingDescription>,
    #[serde(default)]
    pub remediation: Option<FindingRemediation>,
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
