//! End-to-end integration tests exercising the real command-layer logic against
//! a genuine on-disk SQLCipher vault: create → CRUD → render (all formats) →
//! import → sync round-trip between two vaults → rekey → backup. These catch
//! wiring bugs that unit tests on isolated functions miss.

use std::collections::HashMap;
use std::path::PathBuf;

use serde_json::json;

use crate::db;
use crate::error::AppError;
use crate::models::{NewFinding, NewKbEntry, NewReport};
use crate::render::content_model::build_document;
use crate::render::typst_pdf::PdfRenderer;
use crate::render::{html::to_html, markdown::to_markdown, Renderer};
use crate::sync::{bundle::SyncBundle, crypto, merge::merge};
use crate::vault::connection;

fn tmp(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "pwn2report-e2e-{}-{}.db",
        name,
        uuid::Uuid::new_v4()
    ));
    p
}

fn png_1x1() -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC")
        .unwrap()
}

fn seed_report_with_finding(conn: &rusqlite::Connection) -> (String, String) {
    let nr: NewReport = serde_json::from_value(json!({
        "title": "Web App Pentest", "client": "ACME", "report_type": "web_pentest"
    }))
    .unwrap();
    let report = db::reports::create(conn, nr).unwrap();

    let nf: NewFinding = serde_json::from_value(json!({
        "title": "SQL Injection", "severity": "high", "cwe": "CWE-89",
        "description": {"summary": "User input reaches SQL unsanitized.",
            "root_cause": "", "attack_vector": "", "business_impact": "", "technical_details": ""},
        "remediation": {"fix": "Use parameterized queries.", "references": []}
    }))
    .unwrap();
    let finding = db::findings::create(conn, &report.id, nf).unwrap();
    (report.id, finding.id)
}

/// Full happy path on a single vault: create → finding → evidence → render all formats.
#[test]
fn e2e_create_render_all_formats() {
    let path = tmp("render");
    let conn = connection::create_encrypted(&path, "master-pass").unwrap();
    let (report_id, finding_id) = seed_report_with_finding(&conn);

    // attach an evidence image
    db::evidence::add(&conn, &finding_id, "screenshot", "image/png", &png_1x1()).unwrap();

    // build the IR with images, exactly like the export command does
    let report = db::reports::get(&conn, &report_id).unwrap();
    let findings = db::findings::list(&conn, &report_id).unwrap();
    let imgs = db::evidence::list(&conn, &finding_id).unwrap();
    assert_eq!(imgs.len(), 1);
    let mut images: HashMap<String, Vec<(String, String, Vec<u8>)>> = HashMap::new();
    images.insert(
        finding_id.clone(),
        vec![("screenshot".into(), "image/png".into(), png_1x1())],
    );

    // PDF for every shipped theme
    for slug in ["web_pentest", "code_audit", "red_team"] {
        let doc = build_document(&report, findings.clone(), &images);
        let pdf = PdfRenderer::bundled(slug).render(doc).unwrap();
        assert!(pdf.starts_with(b"%PDF"), "{slug}");
    }
    // MD + HTML
    let doc = build_document(&report, findings.clone(), &images);
    let md = to_markdown(&doc);
    assert!(md.contains("SQL Injection"));
    let html = to_html(&doc);
    assert!(html.contains("data:image/png;base64,"));

    let _ = std::fs::remove_file(&path);
}

/// Importing a SARIF report adds findings to the report.
#[test]
fn e2e_import_sarif_adds_findings() {
    let path = tmp("import");
    let conn = connection::create_encrypted(&path, "p").unwrap();
    let (report_id, _) = seed_report_with_finding(&conn);
    let before = db::findings::list(&conn, &report_id).unwrap().len();

    let sarif = r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t"}},
        "results":[{"ruleId":"X","level":"error","message":{"text":"XSS"},
        "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.js"},"region":{"startLine":2}}}]}]}]}"#;
    let parsed = crate::import::parse("sarif", sarif).unwrap();
    assert_eq!(parsed.len(), 1);
    for nf in parsed {
        db::findings::create(&conn, &report_id, nf).unwrap();
    }
    let after = db::findings::list(&conn, &report_id).unwrap().len();
    assert_eq!(after, before + 1);

    let _ = std::fs::remove_file(&path);
}

/// The real sync flow: snapshot+encrypt one vault, decrypt+merge into a second
/// (initially empty) vault, and assert the data crossed over.
#[test]
fn e2e_sync_roundtrip_between_two_vaults() {
    // Source vault with a report, a finding, an evidence image and a KB entry.
    let src_path = tmp("sync-src");
    let src = connection::create_encrypted(&src_path, "pp").unwrap();
    let (_rid, fid) = seed_report_with_finding(&src);
    db::evidence::add(&src, &fid, "shot", "image/png", &png_1x1()).unwrap();
    let nk: NewKbEntry = serde_json::from_value(json!({
        "title": "Open Redirect", "severity": "medium",
        "description": {"summary":"s","root_cause":"","attack_vector":"","business_impact":"","technical_details":""},
        "remediation": {"fix":"f","references":[]}, "tags": ["owasp"]
    }))
    .unwrap();
    db::kb::create(&src, nk).unwrap();

    // Export → encrypt → decrypt → parse.
    let bundle_json = SyncBundle::snapshot(&src).unwrap().to_json().unwrap();
    let cipher = crypto::encrypt("sync-secret", &bundle_json).unwrap();
    assert!(
        crypto::decrypt("WRONG", &cipher).is_err(),
        "wrong passphrase must fail"
    );
    let plain = crypto::decrypt("sync-secret", &cipher).unwrap();
    let bundle = SyncBundle::from_json(&plain).unwrap();

    // Fresh destination vault, then merge.
    let dst_path = tmp("sync-dst");
    let mut dst = connection::create_encrypted(&dst_path, "other").unwrap();
    assert_eq!(db::reports::list(&dst).unwrap().len(), 0);
    let summary = merge(&mut dst, bundle).unwrap();
    assert_eq!(summary.reports_added, 1);
    assert_eq!(summary.findings_added, 1);
    assert_eq!(summary.kb_added, 1);
    assert_eq!(summary.images_added, 1);

    // Data is really queryable in the destination.
    let reports = db::reports::list(&dst).unwrap();
    assert_eq!(reports.len(), 1);
    let findings = db::findings::list(&dst, &reports[0].id).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(db::evidence::list(&dst, &findings[0].id).unwrap().len(), 1);

    // Idempotent: merging the same bundle again changes nothing (LWW ties skip).
    let again = SyncBundle::from_json(&plain).unwrap();
    let s2 = merge(&mut dst, again).unwrap();
    assert_eq!(s2.reports_added, 0);
    assert_eq!(s2.findings_added, 0);

    let _ = std::fs::remove_file(&src_path);
    let _ = std::fs::remove_file(&dst_path);
}

/// Rekey (change passphrase) and backup (encrypted file copy) behave correctly.
#[test]
fn e2e_rekey_and_backup() {
    let path = tmp("rekey");
    {
        let conn = connection::create_encrypted(&path, "old-pass").unwrap();
        seed_report_with_finding(&conn);
        // PRAGMA rekey on the live connection (what change_passphrase does).
        conn.execute_batch("PRAGMA rekey = 'new-pass';").unwrap();
    }
    // Old passphrase no longer opens it; the new one does.
    assert!(matches!(
        connection::open_encrypted(&path, "old-pass"),
        Err(AppError::WrongPassphrase)
    ));
    let conn = connection::open_encrypted(&path, "new-pass").unwrap();
    assert_eq!(db::reports::list(&conn).unwrap().len(), 1);

    // Backup = byte copy of the already-encrypted file; opens with the same key.
    let backup = tmp("backup");
    std::fs::copy(&path, &backup).unwrap();
    let restored = connection::open_encrypted(&backup, "new-pass").unwrap();
    assert_eq!(db::reports::list(&restored).unwrap().len(), 1);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&backup);
}
