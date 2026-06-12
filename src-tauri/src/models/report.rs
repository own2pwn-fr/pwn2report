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

impl ReportType {
    /// snake_case slug used for the DB column, template file names
    /// (`<slug>.typ`) and the render-IR `report_type_slug` field.
    pub fn slug(self) -> &'static str {
        match self {
            ReportType::WebPentest => "web_pentest",
            ReportType::CodeAudit => "code_audit",
            ReportType::RedTeam => "red_team",
        }
    }

    /// Parse a slug back into a `ReportType` (defaults to web_pentest on an
    /// unknown value rather than failing).
    pub fn from_slug(s: &str) -> ReportType {
        match s {
            "code_audit" => ReportType::CodeAudit,
            "red_team" => ReportType::RedTeam,
            _ => ReportType::WebPentest,
        }
    }

    /// All report types, in a stable order (for `list_templates`).
    pub fn all() -> [ReportType; 3] {
        [
            ReportType::WebPentest,
            ReportType::CodeAudit,
            ReportType::RedTeam,
        ]
    }
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
