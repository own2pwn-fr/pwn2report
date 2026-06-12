//! Report model + list-summary + create/patch payloads.

use serde::{Deserialize, Serialize};

/// The kind of engagement the report documents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportType {
    WebPentest,
    CodeAudit,
    RedTeam,
}

/// A full report (header + narrative sections). Findings are stored separately
/// and joined on demand.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub id: String,
    pub title: String,
    pub client: String,
    pub report_type: ReportType,
    /// Free-form workflow status (e.g. "draft", "review", "final").
    pub status: String,
    pub exec_summary: String,
    pub scope: String,
    pub methodology: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Lightweight row for the report list view (with finding count).
#[derive(Debug, Clone, Serialize)]
pub struct ReportSummary {
    pub id: String,
    pub title: String,
    pub client: String,
    pub report_type: ReportType,
    pub status: String,
    pub finding_count: i64,
    pub updated_at: String,
}

/// Payload for `create_report`.
#[derive(Debug, Clone, Deserialize)]
pub struct NewReport {
    pub title: String,
    #[serde(default)]
    pub client: Option<String>,
    pub report_type: ReportType,
}

/// Partial update for `update_report`; `None` fields are left unchanged.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ReportPatch {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub client: Option<String>,
    #[serde(default)]
    pub report_type: Option<ReportType>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub exec_summary: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub methodology: Option<String>,
}
