//! Evidence-image model.
//!
//! Per-finding screenshot/diagram attachments. The image **bytes** live in the
//! SQLCipher-encrypted vault (`evidence_images.data` BLOB → encrypted at rest)
//! and are NEVER part of this serde struct: only the metadata crosses the IPC
//! boundary to the frontend. Bytes are fetched on demand via the dedicated
//! `get_evidence_image` command (the UI turns them into an object URL).

use serde::{Deserialize, Serialize};

/// Metadata for a single evidence image (no bytes — see module docs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceImage {
    pub id: String,
    pub finding_id: String,
    pub caption: String,
    /// MIME type of the stored bytes ("image/png", "image/jpeg", …).
    pub mime: String,
    pub sort_order: i64,
    pub created_at: String,
    /// Soft-delete tombstone marker (RFC3339). `None` = live row. Omitted from
    /// the IPC payload when absent; carried through the sync bundle so deletes
    /// propagate across devices. Not surfaced in the UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_image_round_trips_through_serde() {
        let img = EvidenceImage {
            id: "img-1".into(),
            finding_id: "f-1".into(),
            caption: "Login bypass screenshot".into(),
            mime: "image/png".into(),
            sort_order: 2,
            created_at: "2026-06-12T12:00:00Z".into(),
            deleted_at: None,
        };
        let json = serde_json::to_string(&img).unwrap();
        // camelCase is NOT applied (matches the rest of the models, which rely
        // on Tauri's snake_case↔camelCase mapping at the IPC edge), so the
        // wire field is `finding_id` here.
        assert!(json.contains("\"finding_id\":\"f-1\""));
        let back: EvidenceImage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, img.id);
        assert_eq!(back.finding_id, img.finding_id);
        assert_eq!(back.caption, img.caption);
        assert_eq!(back.mime, img.mime);
        assert_eq!(back.sort_order, img.sort_order);
        assert_eq!(back.created_at, img.created_at);
    }
}
