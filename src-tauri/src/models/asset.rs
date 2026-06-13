//! Affected-asset model + create/patch payloads.
//!
//! An asset is an item in scope that a report (and its findings) concern: a
//! host, IP, URL, domain, credential, or anything else. Assets belong to a
//! report (FK `report_id`, `ON DELETE CASCADE`) and follow the same
//! soft-delete/tombstone pattern as the other syncable tables so deletes
//! propagate through sync.

use serde::{Deserialize, Serialize};

/// The category of an affected asset. Serializes snake_case; an unknown column
/// value parses back to [`AssetKind::Other`] rather than failing a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    Host,
    Ip,
    Url,
    Domain,
    Credential,
    Other,
}

impl AssetKind {
    /// snake_case wire/column string.
    pub fn as_str(self) -> &'static str {
        match self {
            AssetKind::Host => "host",
            AssetKind::Ip => "ip",
            AssetKind::Url => "url",
            AssetKind::Domain => "domain",
            AssetKind::Credential => "credential",
            AssetKind::Other => "other",
        }
    }

    /// Parse a column value back into an `AssetKind` (defaults to `Other`).
    pub fn from_db(s: &str) -> AssetKind {
        match s {
            "host" => AssetKind::Host,
            "ip" => AssetKind::Ip,
            "url" => AssetKind::Url,
            "domain" => AssetKind::Domain,
            "credential" => AssetKind::Credential,
            _ => AssetKind::Other,
        }
    }
}

/// A single affected asset belonging to a report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub id: String,
    pub report_id: String,
    pub kind: AssetKind,
    pub identifier: String,
    pub description: String,
    pub sort_order: i64,
    pub created_at: String,
    pub updated_at: String,
    /// Soft-delete tombstone marker (RFC3339). `None` = live row. Omitted from
    /// the IPC payload when absent; carried through the sync bundle so deletes
    /// propagate across devices. Not surfaced in the UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
}

/// Payload for `create_asset`. `identifier` is required; the rest defaults.
#[derive(Debug, Clone, Deserialize)]
pub struct NewAsset {
    pub identifier: String,
    #[serde(default)]
    pub kind: Option<AssetKind>,
    #[serde(default)]
    pub description: Option<String>,
}

/// Partial update for `update_asset`; `None` fields are left unchanged.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AssetPatch {
    #[serde(default)]
    pub kind: Option<AssetKind>,
    #[serde(default)]
    pub identifier: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_round_trips_through_serde() {
        let a = Asset {
            id: "a-1".into(),
            report_id: "r-1".into(),
            kind: AssetKind::Url,
            identifier: "https://app.example.com".into(),
            description: "Main web app".into(),
            sort_order: 2,
            created_at: "2026-06-12T12:00:00Z".into(),
            updated_at: "2026-06-12T12:30:00Z".into(),
            deleted_at: None,
        };
        let json = serde_json::to_string(&a).unwrap();
        assert!(json.contains("\"kind\":\"url\""));
        // deleted_at is omitted when None.
        assert!(!json.contains("deleted_at"));
        let back: Asset = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, a.id);
        assert_eq!(back.kind, AssetKind::Url);
        assert_eq!(back.identifier, a.identifier);
    }

    #[test]
    fn unknown_kind_parses_to_other() {
        assert_eq!(AssetKind::from_db("nonsense"), AssetKind::Other);
        assert_eq!(AssetKind::from_db("host"), AssetKind::Host);
    }
}
