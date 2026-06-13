//! Structured scope-item model + create/patch payloads.
//!
//! A scope item is a single in-scope or out-of-scope entry for a report (a URL,
//! IP range, host, …) with an optional note. Belongs to a report (FK
//! `report_id`, `ON DELETE CASCADE`) and follows the soft-delete/tombstone
//! pattern so deletes propagate through sync. This is the structured complement
//! to the free-form `reports.scope` prose field, which is kept for narrative.

use serde::{Deserialize, Serialize};

/// A single structured scope entry belonging to a report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeItem {
    pub id: String,
    pub report_id: String,
    /// Free-form category string ("url", "ip", "host", "range", …). Kept as a
    /// plain string (not an enum) so authors can use whatever taxonomy fits.
    pub kind: String,
    pub value: String,
    /// `true` = in scope, `false` = explicitly out of scope.
    pub in_scope: bool,
    pub note: String,
    pub sort_order: i64,
    pub created_at: String,
    pub updated_at: String,
    /// Soft-delete tombstone marker (RFC3339). `None` = live row. Omitted from
    /// the IPC payload when absent; carried through the sync bundle so deletes
    /// propagate across devices. Not surfaced in the UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
}

/// Payload for `create_scope_item`. `value` is required; the rest defaults
/// (`in_scope` defaults to `true`).
#[derive(Debug, Clone, Deserialize)]
pub struct NewScopeItem {
    pub value: String,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub in_scope: Option<bool>,
    #[serde(default)]
    pub note: Option<String>,
}

/// Partial update for `update_scope_item`; `None` fields are left unchanged.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ScopeItemPatch {
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub in_scope: Option<bool>,
    #[serde(default)]
    pub note: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_item_round_trips_through_serde() {
        let s = ScopeItem {
            id: "s-1".into(),
            report_id: "r-1".into(),
            kind: "url".into(),
            value: "https://app.example.com".into(),
            in_scope: true,
            note: "Production".into(),
            sort_order: 0,
            created_at: "2026-06-12T12:00:00Z".into(),
            updated_at: "2026-06-12T12:30:00Z".into(),
            deleted_at: None,
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"in_scope\":true"));
        assert!(!json.contains("deleted_at"));
        let back: ScopeItem = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, s.id);
        assert!(back.in_scope);
        assert_eq!(back.value, s.value);
    }
}
