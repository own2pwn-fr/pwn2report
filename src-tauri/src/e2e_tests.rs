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
        let doc = build_document(
            &report,
            findings.clone(),
            images.clone(),
            &[],
            &HashMap::new(),
            None,
        );
        let pdf = PdfRenderer::bundled(slug).render(doc).unwrap();
        assert!(pdf.starts_with(b"%PDF"), "{slug}");
    }
    // MD + HTML
    let doc = build_document(
        &report,
        findings.clone(),
        images,
        &[],
        &HashMap::new(),
        None,
    );
    let md = to_markdown(&doc);
    assert!(md.contains("SQL Injection"));
    let html = to_html(&doc);
    assert!(html.contains("data:image/png;base64,"));

    let _ = std::fs::remove_file(&path);
}

/// The batched evidence fetch (`get_data_for_finding`, backing the
/// `get_evidence_images_data` command) returns ALL of a finding's live images in
/// one query, in sort order, and skips soft-deleted ones — replacing the per-
/// image N+1 `get_data` round-trip the gallery used to do.
#[test]
fn e2e_batch_evidence_fetch_returns_all_live_images() {
    let path = tmp("batch-evidence");
    let conn = connection::create_encrypted(&path, "p").unwrap();
    let (_rid, fid) = seed_report_with_finding(&conn);

    // Three images appended in order; capture ids so we can delete one.
    let a = db::evidence::add(&conn, &fid, "first", "image/png", &png_1x1()).unwrap();
    let _b = db::evidence::add(&conn, &fid, "second", "image/jpeg", &[0xff, 0xd8, 0xff]).unwrap();
    let c = db::evidence::add(&conn, &fid, "third", "image/png", &png_1x1()).unwrap();

    // All three live: one call returns them in sort order with bytes intact.
    let all = db::evidence::get_data_for_finding(&conn, &fid).unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!(all[0].0, a.id);
    assert_eq!(all[0].1, "image/png");
    assert_eq!(all[1].1, "image/jpeg");
    assert_eq!(all[1].2, vec![0xff, 0xd8, 0xff]);
    assert_eq!(all[2].0, c.id);

    // Soft-deleting one drops it from the batch result (live-only).
    db::evidence::delete(&conn, &c.id).unwrap();
    let live = db::evidence::get_data_for_finding(&conn, &fid).unwrap();
    assert_eq!(live.len(), 2);
    assert!(live.iter().all(|(id, _, _)| *id != c.id));

    // A finding with no images yields an empty vec, not an error.
    let (_r2, fid2) = seed_report_with_finding(&conn);
    assert!(db::evidence::get_data_for_finding(&conn, &fid2)
        .unwrap()
        .is_empty());

    let _ = std::fs::remove_file(&path);
}

/// The streaming export path (`encrypt_to_writer` into a `BufWriter<File>`)
/// produces a file that decrypts + parses + merges into a peer vault — i.e. the
/// memory-bounded encrypt-to-file still round-trips through import.
#[test]
fn e2e_streaming_export_to_file_round_trips_through_import() {
    use std::io::{BufWriter, Write};

    let src_path = tmp("stream-src");
    let src = connection::create_encrypted(&src_path, "pp").unwrap();
    let (_rid, fid) = seed_report_with_finding(&src);
    db::evidence::add(&src, &fid, "shot", "image/png", &png_1x1()).unwrap();

    // Encrypt straight into a file, exactly as `export_sync_bundle` now does.
    let json = SyncBundle::snapshot(&src).unwrap().to_json().unwrap();
    let bundle_path = tmp("stream-bundle");
    {
        let file = std::fs::File::create(&bundle_path).unwrap();
        let mut w = BufWriter::new(file);
        crypto::encrypt_to_writer("stream-secret", &json, &mut w).unwrap();
        w.flush().unwrap();
    }

    // Read the file back, decrypt, parse, and merge into a fresh vault.
    let cipher = std::fs::read(&bundle_path).unwrap();
    assert!(crypto::decrypt("WRONG", &cipher).is_err());
    let plain = crypto::decrypt("stream-secret", &cipher).unwrap();
    let bundle = SyncBundle::from_json(&plain).unwrap();

    let dst_path = tmp("stream-dst");
    let mut dst = connection::create_encrypted(&dst_path, "other").unwrap();
    let summary = merge(&mut dst, bundle).unwrap();
    assert_eq!(summary.reports_added, 1);
    assert_eq!(summary.findings_added, 1);
    assert_eq!(summary.images_added, 1);

    // The streamed-then-imported image bytes match the original.
    let reports = db::reports::list(&dst).unwrap();
    let findings = db::findings::list(&dst, &reports[0].id).unwrap();
    let imgs = db::evidence::get_data_for_finding(&dst, &findings[0].id).unwrap();
    assert_eq!(imgs.len(), 1);
    assert_eq!(imgs[0].2, png_1x1());

    let _ = std::fs::remove_file(&src_path);
    let _ = std::fs::remove_file(&dst_path);
    let _ = std::fs::remove_file(&bundle_path);
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
    assert_eq!(parsed.findings.len(), 1);
    for nf in parsed.findings {
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

/// A soft-delete on one vault propagates as a tombstone through sync and removes
/// the row on the peer — and a later re-merge of the peer's *pre-delete* bundle
/// does NOT resurrect it (LWW: the tombstone is newer).
#[test]
fn e2e_soft_delete_tombstone_propagates_and_blocks_resurrection() {
    // Source vault with a report + finding; snapshot its PRE-delete state.
    let src_path = tmp("tomb-src");
    let src = connection::create_encrypted(&src_path, "pp").unwrap();
    let (rid, fid) = seed_report_with_finding(&src);
    let pre_delete = SyncBundle::snapshot(&src).unwrap();

    // Destination vault that already has the data (simulate a prior sync).
    let dst_path = tmp("tomb-dst");
    let mut dst = connection::create_encrypted(&dst_path, "other").unwrap();
    merge(
        &mut dst,
        SyncBundle::from_json(&pre_delete.to_json().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(db::reports::list(&dst).unwrap().len(), 1);

    // Delete the finding on the source (soft-delete -> tombstone), then snapshot.
    db::findings::delete(&src, &fid).unwrap();
    assert!(db::findings::list(&src, &rid).unwrap().is_empty());
    let post_delete = SyncBundle::snapshot(&src).unwrap();

    // Merge the tombstone into dst: the finding is removed there too.
    let s = merge(
        &mut dst,
        SyncBundle::from_json(&post_delete.to_json().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(s.deleted, 1, "one tombstone should have been applied");
    assert!(db::findings::list(&dst, &rid).unwrap().is_empty());

    // Re-merging the STALE pre-delete bundle must NOT resurrect the finding
    // (its older updated_at loses LWW against the tombstone).
    let s2 = merge(
        &mut dst,
        SyncBundle::from_json(&pre_delete.to_json().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(s2.findings_updated, 0);
    assert!(
        db::findings::list(&dst, &rid).unwrap().is_empty(),
        "stale bundle must not resurrect a deleted finding"
    );

    let _ = std::fs::remove_file(&src_path);
    let _ = std::fs::remove_file(&dst_path);
}

/// An evidence-image soft-delete travels as a tombstone and removes the image on
/// the peer (images are immutable, so the tombstone is the only mutation merged).
#[test]
fn e2e_evidence_tombstone_propagates() {
    let src_path = tmp("img-tomb-src");
    let src = connection::create_encrypted(&src_path, "pp").unwrap();
    let (_rid, fid) = seed_report_with_finding(&src);
    let img = db::evidence::add(&src, &fid, "shot", "image/png", &png_1x1()).unwrap();

    // Peer gets the live image first.
    let dst_path = tmp("img-tomb-dst");
    let mut dst = connection::create_encrypted(&dst_path, "other").unwrap();
    merge(
        &mut dst,
        SyncBundle::from_json(&SyncBundle::snapshot(&src).unwrap().to_json().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(db::evidence::list(&dst, &fid).unwrap().len(), 1);

    // Delete the image on src, then sync the tombstone to dst.
    db::evidence::delete(&src, &img.id).unwrap();
    let s = merge(
        &mut dst,
        SyncBundle::from_json(&SyncBundle::snapshot(&src).unwrap().to_json().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(s.deleted, 1);
    assert!(db::evidence::list(&dst, &fid).unwrap().is_empty());

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

/// Aggregate report layer round-trips through sync: assets, scope items, the
/// finding↔asset link set (UNION), the report logo, and engagement metadata all
/// cross to a fresh peer; LWW + logo monotonicity hold on a re-merge.
#[test]
fn e2e_aggregate_layer_sync_roundtrip() {
    use crate::models::{AssetPatch, NewAsset, NewScopeItem, ReportPatch};

    let src_path = tmp("agg-src");
    let mut src = connection::create_encrypted(&src_path, "pp").unwrap();
    let (rid, fid) = seed_report_with_finding(&src);

    // Engagement metadata + logo on the report.
    let patch: ReportPatch = serde_json::from_value(json!({
        "authors": ["Alice", "Bob"], "reviewer": "Carol",
        "engagement_ref": "PO-42", "confidentiality": "Confidential",
        "engagement_start": "2026-06-01", "engagement_end": "2026-06-10"
    }))
    .unwrap();
    db::reports::update(&src, &rid, patch).unwrap();
    db::reports::set_logo(&src, &rid, "image/png", &png_1x1()).unwrap();

    // Two assets, a scope item, and link one asset to the finding.
    let a1 = db::assets::create(
        &src,
        &rid,
        serde_json::from_value::<NewAsset>(
            json!({"identifier":"https://app.example.com","kind":"url"}),
        )
        .unwrap(),
    )
    .unwrap();
    let _a2 = db::assets::create(
        &src,
        &rid,
        serde_json::from_value::<NewAsset>(json!({"identifier":"10.0.0.5","kind":"ip"})).unwrap(),
    )
    .unwrap();
    db::scope::create(
        &src,
        &rid,
        serde_json::from_value::<NewScopeItem>(
            json!({"value":"*.example.com","kind":"domain","in_scope":true}),
        )
        .unwrap(),
    )
    .unwrap();
    db::findings::set_finding_assets(&mut src, &fid, std::slice::from_ref(&a1.id)).unwrap();
    assert_eq!(
        db::findings::list_finding_assets(&src, &fid).unwrap().len(),
        1
    );

    // Snapshot → fresh peer → merge.
    let bundle = SyncBundle::snapshot(&src).unwrap();
    let dst_path = tmp("agg-dst");
    let mut dst = connection::create_encrypted(&dst_path, "other").unwrap();
    let summary = merge(
        &mut dst,
        SyncBundle::from_json(&bundle.to_json().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(summary.assets_added, 2);
    assert_eq!(summary.scope_added, 1);
    assert_eq!(summary.links_added, 1);
    assert_eq!(summary.logos_added, 1);

    // Verify on the peer.
    let r = db::reports::get(&dst, &rid).unwrap();
    assert_eq!(r.authors, vec!["Alice", "Bob"]);
    assert_eq!(r.engagement_ref.as_deref(), Some("PO-42"));
    assert!(r.has_logo);
    assert!(db::reports::get_logo(&dst, &rid).unwrap().is_some());
    assert_eq!(db::assets::list(&dst, &rid).unwrap().len(), 2);
    assert_eq!(db::scope::list(&dst, &rid).unwrap().len(), 1);
    assert_eq!(
        db::findings::list_finding_assets(&dst, &fid).unwrap().len(),
        1
    );

    // Update an asset on the peer, then re-merge the (stale) source bundle: LWW
    // keeps the newer peer edit; the logo stays (monotonic, not re-applied).
    db::assets::update(
        &dst,
        &a1.id,
        serde_json::from_value::<AssetPatch>(json!({"description":"edited on peer"})).unwrap(),
    )
    .unwrap();
    let s2 = merge(
        &mut dst,
        SyncBundle::from_json(&bundle.to_json().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(s2.assets_updated, 0, "stale asset must lose LWW");
    let a1_dst = db::assets::get(&dst, &a1.id).unwrap();
    assert_eq!(a1_dst.description, "edited on peer");
    assert_eq!(s2.logos_added, 0);

    let _ = std::fs::remove_file(&src_path);
    let _ = std::fs::remove_file(&dst_path);
}

/// Cloning a report deep-copies its children with fresh ids: scope, assets,
/// findings (with evidence images + remapped asset links), and the logo; the
/// clone's findings have their retest disposition reset.
#[test]
fn e2e_clone_report_deep_copies_children() {
    let path = tmp("clone-report");
    let mut conn = connection::create_encrypted(&path, "master-pass").unwrap();
    let (report_id, finding_id) = seed_report_with_finding(&conn);

    // Give the finding a retest status (must be CLEARED on the clone) + an image.
    let patch: crate::models::FindingPatch =
        serde_json::from_value(json!({"retest_status": "fixed", "retest_date": "2026-07-01"}))
            .unwrap();
    db::findings::update(&conn, &finding_id, patch).unwrap();
    db::evidence::add(&conn, &finding_id, "shot", "image/png", &png_1x1()).unwrap();

    // An asset linked to the finding (link must remap to the cloned asset).
    let na: crate::models::NewAsset =
        serde_json::from_value(json!({"identifier": "https://app.example.com", "kind": "url"}))
            .unwrap();
    let asset = db::assets::create(&conn, &report_id, na).unwrap();
    db::findings::set_finding_assets(&mut conn, &finding_id, std::slice::from_ref(&asset.id))
        .unwrap();

    // A scope item + a report logo.
    let ns: crate::models::NewScopeItem =
        serde_json::from_value(json!({"value": "app.example.com", "kind": "domain"})).unwrap();
    db::scope::create(&conn, &report_id, ns).unwrap();
    db::reports::set_logo(&conn, &report_id, "image/png", &png_1x1()).unwrap();

    // Clone.
    let clone = db::reports::clone_report(&mut conn, &report_id).unwrap();
    assert_ne!(clone.id, report_id);
    assert!(clone.title.ends_with(" (copy)"));
    assert!(clone.has_logo);

    // Children: one finding, retest reset, image copied, asset re-linked.
    let cfindings = db::findings::list(&conn, &clone.id).unwrap();
    assert_eq!(cfindings.len(), 1);
    let cf = &cfindings[0];
    assert_ne!(cf.id, finding_id, "finding got a fresh id");
    assert!(cf.retest_status.is_none(), "retest cleared on clone");
    assert!(cf.retest_date.is_none());

    let cimgs = db::evidence::list(&conn, &cf.id).unwrap();
    assert_eq!(cimgs.len(), 1, "evidence image copied");

    let cassets = db::assets::list(&conn, &clone.id).unwrap();
    assert_eq!(cassets.len(), 1);
    assert_ne!(cassets[0].id, asset.id, "asset got a fresh id");
    let linked = db::findings::list_finding_assets(&conn, &cf.id).unwrap();
    assert_eq!(linked.len(), 1);
    assert_eq!(linked[0].id, cassets[0].id, "link remapped to cloned asset");

    let cscope = db::scope::list(&conn, &clone.id).unwrap();
    assert_eq!(cscope.len(), 1);

    // The original is untouched (its finding keeps its retest status).
    let orig = db::findings::get(&conn, &finding_id).unwrap();
    assert_eq!(orig.retest_status, Some(crate::models::RetestStatus::Fixed));

    let _ = std::fs::remove_file(&path);
}

/// Cloning a finding copies it within the same report with a fresh id, appended
/// sort order, copied evidence, and a reset retest status.
#[test]
fn e2e_clone_finding_within_report() {
    let path = tmp("clone-finding");
    let mut conn = connection::create_encrypted(&path, "master-pass").unwrap();
    let (report_id, finding_id) = seed_report_with_finding(&conn);
    let patch: crate::models::FindingPatch =
        serde_json::from_value(json!({"retest_status": "not_fixed"})).unwrap();
    db::findings::update(&conn, &finding_id, patch).unwrap();
    db::evidence::add(&conn, &finding_id, "shot", "image/png", &png_1x1()).unwrap();

    let clone = db::findings::clone_finding(&mut conn, &finding_id).unwrap();
    assert_ne!(clone.id, finding_id);
    assert_eq!(clone.report_id, report_id, "stays in the same report");
    assert!(clone.title.ends_with(" (copy)"));
    assert!(clone.retest_status.is_none(), "retest reset");
    assert!(clone.sort_order > 0, "appended after the source");

    let cimgs = db::evidence::list(&conn, &clone.id).unwrap();
    assert_eq!(cimgs.len(), 1, "evidence image copied");

    // Report now has two findings.
    let all = db::findings::list(&conn, &report_id).unwrap();
    assert_eq!(all.len(), 2);

    let _ = std::fs::remove_file(&path);
}

/// Import dedup: the same SARIF file imported twice yields the findings once;
/// the second pass counts them all as deduped (against the report's existing
/// rows). And within one batch, exact duplicates collapse too.
#[test]
fn e2e_import_dedup_against_report_and_batch() {
    let path = tmp("import-dedup");
    let mut conn = connection::create_encrypted(&path, "master-pass").unwrap();
    let (report_id, _) = seed_report_with_finding(&conn);
    let before = db::findings::list(&conn, &report_id).unwrap().len();

    // Two results, the SECOND a byte-identical duplicate of the first → 1 new.
    let sarif = r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t"}},
        "results":[
          {"ruleId":"X","level":"error","message":{"text":"XSS"},
           "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.js"},"region":{"startLine":2}}}]},
          {"ruleId":"X","level":"error","message":{"text":"XSS"},
           "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.js"},"region":{"startLine":2}}}]}
        ]}]}"#;
    let outcome = crate::import::parse("sarif", sarif).unwrap();
    assert_eq!(outcome.findings.len(), 2, "parser keeps both results");
    let (imported, deduped) =
        db::findings::create_bulk_dedup(&mut conn, &report_id, outcome.findings).unwrap();
    assert_eq!(imported, 1, "in-batch duplicate collapsed");
    assert_eq!(deduped, 1);
    assert_eq!(
        db::findings::list(&conn, &report_id).unwrap().len(),
        before + 1
    );

    // Re-import the same file: everything is now a dup of existing rows.
    let outcome2 = crate::import::parse("sarif", sarif).unwrap();
    let (imported2, deduped2) =
        db::findings::create_bulk_dedup(&mut conn, &report_id, outcome2.findings).unwrap();
    assert_eq!(imported2, 0);
    assert_eq!(deduped2, 2);
    assert_eq!(
        db::findings::list(&conn, &report_id).unwrap().len(),
        before + 1,
        "re-import added nothing"
    );

    let _ = std::fs::remove_file(&path);
}
