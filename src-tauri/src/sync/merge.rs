//! Conflict-free merge of an incoming [`SyncBundle`] into the local vault.
//!
//! Strategy: per-row **Last-Write-Wins**, keyed by the UUID primary key, using
//! `updated_at` as the LWW register. This is conflict-free by construction —
//! two devices that each merge the other's bundle converge on the same state
//! regardless of merge order (the row with the latest `updated_at` always wins).
//!
//! **Tombstones**: a delete is a soft-delete (`deleted_at` set), not a row
//! removal, so it travels in the bundle as a normal row carrying `deleted_at`
//! plus a bumped `updated_at`. LWW therefore treats a delete like any other
//! edit: if the incoming row is newer it wins — soft-deleting locally — and an
//! older live row can never resurrect a row a peer already deleted. Tombstones
//! are applied via the same `update_raw`/`insert_raw` paths (which now persist
//! `deleted_at`), so no special-casing is needed for reports/findings/kb.
//!
//! Evidence images are immutable bytes, so the only mutation a merge applies to
//! an existing image is its tombstone; a brand-new image is inserted (carrying
//! whatever `deleted_at` it already had). Since images have no `updated_at`, the
//! tombstone is monotonic — once set it stays set (a live incoming copy never
//! un-deletes a locally-tombstoned image).
//!
//! Ordering matters for foreign keys: **reports → findings → kb_entries →
//! evidence_images**. The whole merge runs in a single transaction so a failure
//! leaves the vault untouched.

use rusqlite::Connection;
use serde::Serialize;

use super::bundle::SyncBundle;
use crate::db;
use crate::error::AppResult;

/// Outcome of a merge, returned to the frontend.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct SyncSummary {
    pub reports_added: usize,
    pub reports_updated: usize,
    pub findings_added: usize,
    pub findings_updated: usize,
    pub kb_added: usize,
    pub kb_updated: usize,
    pub images_added: usize,
    /// Incoming tombstones that won LWW and soft-deleted a local row (across all
    /// tables). A subset of the "updated" work, surfaced separately so the UI can
    /// report "N items removed by sync".
    pub deleted: usize,
    /// Rows skipped: incoming row not newer (LWW lost), or an evidence image
    /// whose parent finding is absent, or an evidence image already at the
    /// incoming state.
    pub skipped: usize,
}

/// Compare two RFC3339 timestamps; `true` if `incoming` is strictly newer than
/// `local`. Timestamps are zero-padded UTC so a lexical compare is correct, but
/// we parse to be robust to differing offsets/precision; on a parse failure we
/// fall back to the byte comparison.
fn incoming_is_newer(incoming: &str, local: &str) -> bool {
    use chrono::DateTime;
    match (
        DateTime::parse_from_rfc3339(incoming),
        DateTime::parse_from_rfc3339(local),
    ) {
        (Ok(i), Ok(l)) => i > l,
        _ => incoming > local,
    }
}

/// Merge `bundle` into the vault behind `conn`. See module docs for the rules.
pub fn merge(conn: &mut Connection, bundle: SyncBundle) -> AppResult<SyncSummary> {
    let mut summary = SyncSummary::default();
    let tx = conn.transaction()?;
    // `Transaction` derefs to `Connection`; bind an explicit `&Connection` so
    // the db helpers (which take `&Connection`) accept it without relying on
    // coercion at every call site.
    let c: &Connection = &tx;

    // 1. Reports (parents of findings). `get_raw`/`exists` see tombstones too,
    //    so a locally-deleted row is updated via LWW rather than re-inserted.
    for r in &bundle.reports {
        if db::reports::exists(c, &r.id)? {
            let local = db::reports::get_raw(c, &r.id)?;
            if incoming_is_newer(&r.updated_at, &local.updated_at) {
                db::reports::update_raw(c, r)?;
                summary.reports_updated += 1;
                // Count a fresh tombstone (live -> deleted) as a deletion.
                if local.deleted_at.is_none() && r.deleted_at.is_some() {
                    summary.deleted += 1;
                }
            } else {
                summary.skipped += 1;
            }
        } else {
            db::reports::insert_raw(c, r)?;
            summary.reports_added += 1;
        }
    }

    // 2. Findings (parents of evidence images; require their report present).
    for f in &bundle.findings {
        if db::findings::exists(c, &f.id)? {
            let local = db::findings::get_raw(c, &f.id)?;
            if incoming_is_newer(&f.updated_at, &local.updated_at) {
                db::findings::update_raw(c, f)?;
                summary.findings_updated += 1;
                if local.deleted_at.is_none() && f.deleted_at.is_some() {
                    summary.deleted += 1;
                }
            } else {
                summary.skipped += 1;
            }
        } else {
            // Defensive: a finding whose parent report is absent would violate
            // the FK. With reports merged first this only happens for a
            // malformed bundle; skip rather than abort the whole merge.
            if !db::reports::exists(c, &f.report_id)? {
                summary.skipped += 1;
                continue;
            }
            db::findings::insert_raw(c, f)?;
            summary.findings_added += 1;
        }
    }

    // 3. KB entries (no FKs).
    for e in &bundle.kb_entries {
        if db::kb::exists(c, &e.id)? {
            let local = db::kb::get_raw(c, &e.id)?;
            if incoming_is_newer(&e.updated_at, &local.updated_at) {
                db::kb::update_raw(c, e)?;
                summary.kb_updated += 1;
                if local.deleted_at.is_none() && e.deleted_at.is_some() {
                    summary.deleted += 1;
                }
            } else {
                summary.skipped += 1;
            }
        } else {
            db::kb::insert_raw(c, e)?;
            summary.kb_added += 1;
        }
    }

    // 4. Evidence images: immutable bytes. If absent, INSERT (carrying any
    //    tombstone it already had). If present, the only mutation is a tombstone:
    //    a deleted incoming copy soft-deletes the local one (monotonic — a live
    //    incoming copy never un-deletes). Skip an image whose parent finding is
    //    absent after the findings merge.
    for img in bundle.evidence_images {
        let (meta, data) = img.into_parts()?;
        if db::evidence::exists(c, &meta.id)? {
            // Apply an incoming tombstone if the local row is still live.
            if meta.deleted_at.is_some() {
                let local = db::evidence::get_with_tombstone(c, &meta.id)?;
                if local.deleted_at.is_none() {
                    db::evidence::set_deleted(c, &meta.id, meta.deleted_at.as_deref())?;
                    summary.deleted += 1;
                } else {
                    summary.skipped += 1;
                }
            } else {
                summary.skipped += 1;
            }
            continue;
        }
        if !db::findings::exists(c, &meta.finding_id)? {
            summary.skipped += 1;
            continue;
        }
        db::evidence::insert_raw(c, &meta, &data)?;
        summary.images_added += 1;
    }

    tx.commit()?;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lww_prefers_strictly_newer_incoming() {
        assert!(incoming_is_newer(
            "2026-06-12T11:00:00+00:00",
            "2026-06-12T10:00:00+00:00"
        ));
        // Equal timestamps are NOT newer (incoming loses ties → idempotent).
        assert!(!incoming_is_newer(
            "2026-06-12T10:00:00+00:00",
            "2026-06-12T10:00:00+00:00"
        ));
        assert!(!incoming_is_newer(
            "2026-06-12T09:00:00+00:00",
            "2026-06-12T10:00:00+00:00"
        ));
    }

    #[test]
    fn lww_handles_differing_offsets() {
        // 11:00+01:00 == 10:00Z, so it is NOT newer than 10:30Z.
        assert!(!incoming_is_newer(
            "2026-06-12T11:00:00+01:00",
            "2026-06-12T10:30:00+00:00"
        ));
        // 12:00+01:00 == 11:00Z IS newer than 10:30Z.
        assert!(incoming_is_newer(
            "2026-06-12T12:00:00+01:00",
            "2026-06-12T10:30:00+00:00"
        ));
    }

    #[test]
    fn lww_falls_back_to_byte_compare_on_unparseable() {
        assert!(incoming_is_newer("zzz", "aaa"));
        assert!(!incoming_is_newer("aaa", "zzz"));
    }
}
