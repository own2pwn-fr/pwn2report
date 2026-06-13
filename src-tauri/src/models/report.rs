//! Report model + list-summary + create/patch payloads.

use serde::{Deserialize, Serialize};

/// Default report language (used when a row / payload omits `language`).
pub fn default_language() -> String {
    "en".to_string()
}

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
    /// BCP-47-ish language code driving localized export labels + typography
    /// (e.g. `"en"`, `"fr"`). Defaults to `"en"`. Exposed to the frontend.
    #[serde(default = "default_language")]
    pub language: String,
    // --- engagement metadata (aggregate report layer, schema v6) ------------
    /// Engagement start date (free-form / ISO string). `None` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engagement_start: Option<String>,
    /// Engagement end date. `None` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engagement_end: Option<String>,
    /// Report authors (assessors). Stored as a JSON array of strings; defaults
    /// to an empty list.
    #[serde(default)]
    pub authors: Vec<String>,
    /// Quality reviewer / approver name. `None` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewer: Option<String>,
    /// Client/internal engagement reference (PO number, ticket, …). `None` when
    /// unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engagement_ref: Option<String>,
    /// Confidentiality classification banner ("Confidential", "TLP:RED", …).
    /// `None` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidentiality: Option<String>,
    /// Whether a per-report branding logo is stored. The logo BLOB itself is
    /// NEVER carried on this serde payload (fetched via the dedicated
    /// `get_report_logo` command); only this presence flag crosses IPC.
    #[serde(default)]
    pub has_logo: bool,
    pub created_at: String,
    pub updated_at: String,
    /// Soft-delete tombstone marker (RFC3339). `None` = live row. Omitted from
    /// the IPC payload when absent; carried through the sync bundle so deletes
    /// propagate across devices (see `db`/`sync`). Not surfaced in the UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
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
    /// Optional report language ("en" / "fr" / …). Defaults to "en" when absent.
    #[serde(default)]
    pub language: Option<String>,
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
    #[serde(default)]
    pub language: Option<String>,
    // --- engagement metadata (aggregate report layer) -----------------------
    /// Nullable: a JSON `null` clears the value; an omitted field leaves it.
    #[serde(default, deserialize_with = "super::double_option")]
    pub engagement_start: Option<Option<String>>,
    #[serde(default, deserialize_with = "super::double_option")]
    pub engagement_end: Option<Option<String>>,
    /// Authors replace the whole list when present (no per-element patching).
    #[serde(default)]
    pub authors: Option<Vec<String>>,
    #[serde(default, deserialize_with = "super::double_option")]
    pub reviewer: Option<Option<String>>,
    #[serde(default, deserialize_with = "super::double_option")]
    pub engagement_ref: Option<Option<String>>,
    #[serde(default, deserialize_with = "super::double_option")]
    pub confidentiality: Option<Option<String>>,
}
