//! The portable sync bundle: a serde snapshot of every syncable row in the
//! vault, (de)serialized to/from pretty JSON.
//!
//! The bundle is the plaintext payload that [`crate::sync::crypto`] encrypts
//! into a single age passphrase-protected file. It is intentionally a plain
//! data structure (no DB handles, no secrets) so it round-trips cleanly through
//! serde and is trivially testable without a vault.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::db;
use crate::error::{AppError, AppResult};
use crate::models::{EvidenceImage, Finding, KbEntry, Report};

/// Current bundle schema version. Bump when the on-wire shape changes in a way
/// older readers cannot tolerate.
pub const BUNDLE_VERSION: u32 = 1;

/// An evidence image carried inside a bundle: the usual metadata PLUS the image
/// bytes, base64-encoded so they survive JSON. (The live [`EvidenceImage`]
/// model never carries bytes; this is the sync-only "full" variant.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceImageFull {
    pub id: String,
    pub finding_id: String,
    pub caption: String,
    pub mime: String,
    pub sort_order: i64,
    pub created_at: String,
    /// Standard-alphabet base64 of the raw image bytes.
    pub data_base64: String,
}

impl EvidenceImageFull {
    /// Build from a metadata row + its raw bytes (snapshot side).
    pub fn from_parts(meta: EvidenceImage, data: &[u8]) -> Self {
        EvidenceImageFull {
            id: meta.id,
            finding_id: meta.finding_id,
            caption: meta.caption,
            mime: meta.mime,
            sort_order: meta.sort_order,
            created_at: meta.created_at,
            data_base64: B64.encode(data),
        }
    }

    /// Split back into a metadata row + decoded bytes (merge side). A malformed
    /// base64 payload surfaces as [`AppError::Sync`].
    pub fn into_parts(self) -> AppResult<(EvidenceImage, Vec<u8>)> {
        let data = B64
            .decode(self.data_base64.as_bytes())
            .map_err(|e| AppError::Sync(format!("evidence image {}: bad base64: {e}", self.id)))?;
        let meta = EvidenceImage {
            id: self.id,
            finding_id: self.finding_id,
            caption: self.caption,
            mime: self.mime,
            sort_order: self.sort_order,
            created_at: self.created_at,
        };
        Ok((meta, data))
    }
}

/// A full snapshot of all syncable vault data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncBundle {
    pub version: u32,
    /// RFC3339 timestamp of when this bundle was produced.
    pub exported_at: String,
    pub reports: Vec<Report>,
    pub findings: Vec<Finding>,
    pub kb_entries: Vec<KbEntry>,
    pub evidence_images: Vec<EvidenceImageFull>,
}

impl SyncBundle {
    /// Read every syncable row from the unlocked vault into a bundle.
    pub fn snapshot(conn: &Connection) -> AppResult<SyncBundle> {
        let reports = db::reports::list_all(conn)?;
        let findings = db::findings::list_all(conn)?;
        let kb_entries = db::kb::list_all(conn)?;
        let evidence_images = db::evidence::list_all_with_data(conn)?
            .into_iter()
            .map(|(meta, data)| EvidenceImageFull::from_parts(meta, &data))
            .collect();

        Ok(SyncBundle {
            version: BUNDLE_VERSION,
            exported_at: db::now_rfc3339(),
            reports,
            findings,
            kb_entries,
            evidence_images,
        })
    }

    /// Serialize to pretty JSON bytes.
    pub fn to_json(&self) -> AppResult<Vec<u8>> {
        Ok(serde_json::to_vec_pretty(self)?)
    }

    /// Parse from JSON bytes. A malformed payload or an unsupported version
    /// surfaces as [`AppError::Sync`] (not a raw serde error) so the frontend
    /// gets a clear, switchable message.
    pub fn from_json(bytes: &[u8]) -> AppResult<SyncBundle> {
        let bundle: SyncBundle = serde_json::from_slice(bytes)
            .map_err(|e| AppError::Sync(format!("malformed sync bundle: {e}")))?;
        if bundle.version > BUNDLE_VERSION {
            return Err(AppError::Sync(format!(
                "sync bundle version {} is newer than supported ({BUNDLE_VERSION}); upgrade pwn2report",
                bundle.version
            )));
        }
        Ok(bundle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        Confidence, Evidence, FindingDescription, FindingKind, FindingRemediation, ReportType,
        Severity, StructuredPoc, TriageStatus,
    };

    fn sample_report() -> Report {
        Report {
            id: "r-1".into(),
            title: "Test report".into(),
            client: "ACME".into(),
            report_type: ReportType::WebPentest,
            status: "draft".into(),
            exec_summary: "summary".into(),
            scope: "scope".into(),
            methodology: "method".into(),
            created_at: "2026-06-12T10:00:00+00:00".into(),
            updated_at: "2026-06-12T11:00:00+00:00".into(),
        }
    }

    fn sample_finding() -> Finding {
        Finding {
            id: "f-1".into(),
            report_id: "r-1".into(),
            sort_order: 0,
            title: "SQLi".into(),
            severity: Severity::High,
            confidence: Confidence::High,
            kind: FindingKind::Manual,
            cwe: Some("CWE-89".into()),
            cve: None,
            cvss_vector: None,
            cvss_score: Some(8.1),
            triage_status: TriageStatus::Open,
            triage_note: None,
            description: FindingDescription {
                summary: "injection".into(),
                ..Default::default()
            },
            remediation: FindingRemediation {
                fix: "parameterize".into(),
                ..Default::default()
            },
            evidence: Some(Evidence {
                file: Some("app.py".into()),
                start_line: Some(10),
                end_line: Some(12),
                snippet: Some("query".into()),
            }),
            poc: Some(StructuredPoc {
                scenario: "demo".into(),
                exploitation_steps: vec!["step 1".into()],
                payload: Some("' OR 1=1".into()),
            }),
            refs: vec!["https://owasp.org".into()],
            tags: vec!["web".into()],
            created_at: "2026-06-12T10:00:00+00:00".into(),
            updated_at: "2026-06-12T10:30:00+00:00".into(),
        }
    }

    fn sample_image() -> EvidenceImageFull {
        EvidenceImageFull::from_parts(
            EvidenceImage {
                id: "img-1".into(),
                finding_id: "f-1".into(),
                caption: "screenshot".into(),
                mime: "image/png".into(),
                sort_order: 0,
                created_at: "2026-06-12T10:05:00+00:00".into(),
            },
            &[0x89, 0x50, 0x4e, 0x47, 0x00, 0xff],
        )
    }

    #[test]
    fn bundle_json_round_trips() {
        let bundle = SyncBundle {
            version: BUNDLE_VERSION,
            exported_at: "2026-06-12T12:00:00+00:00".into(),
            reports: vec![sample_report()],
            findings: vec![sample_finding()],
            kb_entries: vec![],
            evidence_images: vec![sample_image()],
        };

        let json = bundle.to_json().unwrap();
        let back = SyncBundle::from_json(&json).unwrap();

        assert_eq!(back.version, bundle.version);
        assert_eq!(back.reports.len(), 1);
        assert_eq!(back.reports[0].id, "r-1");
        assert_eq!(back.findings.len(), 1);
        assert_eq!(back.findings[0].cwe.as_deref(), Some("CWE-89"));
        assert_eq!(back.findings[0].poc.as_ref().unwrap().payload.as_deref(), Some("' OR 1=1"));
        assert_eq!(back.evidence_images.len(), 1);
        assert_eq!(back.evidence_images[0].data_base64, bundle.evidence_images[0].data_base64);
    }

    #[test]
    fn evidence_bytes_survive_base64_round_trip() {
        let raw = vec![0x00, 0x01, 0xfe, 0xff, 0x42];
        let full = EvidenceImageFull::from_parts(
            EvidenceImage {
                id: "img-x".into(),
                finding_id: "f-1".into(),
                caption: String::new(),
                mime: "image/jpeg".into(),
                sort_order: 3,
                created_at: "2026-06-12T10:00:00+00:00".into(),
            },
            &raw,
        );
        let (meta, bytes) = full.into_parts().unwrap();
        assert_eq!(meta.sort_order, 3);
        assert_eq!(bytes, raw);
    }

    #[test]
    fn newer_bundle_version_is_rejected() {
        let bundle = SyncBundle {
            version: BUNDLE_VERSION + 1,
            exported_at: "2026-06-12T12:00:00+00:00".into(),
            reports: vec![],
            findings: vec![],
            kb_entries: vec![],
            evidence_images: vec![],
        };
        let json = bundle.to_json().unwrap();
        let err = SyncBundle::from_json(&json).unwrap_err();
        assert!(matches!(err, AppError::Sync(_)));
    }

    #[test]
    fn malformed_json_is_a_sync_error() {
        let err = SyncBundle::from_json(b"not json at all").unwrap_err();
        assert!(matches!(err, AppError::Sync(_)));
    }
}
