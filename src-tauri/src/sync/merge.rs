//! Conflict-free merge of an incoming [`SyncBundle`] into the local vault.
//!
//! Strategy: per-row **Last-Write-Wins**, keyed by the UUID primary key, using
//! `updated_at` as the LWW register. This is conflict-free by construction —
//! two devices that each merge the other's bundle converge on the same state
//! regardless of merge order (the row with the latest `updated_at` always wins).
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
    /// Rows skipped: incoming row not newer (LWW lost), or an evidence image
    /// whose parent finding is absent, or an evidence image that already exists.
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

    // 1. Reports (parents of findings).
    for r in &bundle.reports {
        if db::reports::exists(c, &r.id)? {
            let local = db::reports::get(c, &r.id)?;
            if incoming_is_newer(&r.updated_at, &local.updated_at) {
                db::reports::update_raw(c, r)?;
                summary.reports_updated += 1;
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
            let local = db::findings::get(c, &f.id)?;
            if incoming_is_newer(&f.updated_at, &local.updated_at) {
                db::findings::update_raw(c, f)?;
                summary.findings_updated += 1;
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
            let local = db::kb::get(c, &e.id)?;
            if incoming_is_newer(&e.updated_at, &local.updated_at) {
                db::kb::update_raw(c, e)?;
                summary.kb_updated += 1;
            } else {
                summary.skipped += 1;
            }
        } else {
            db::kb::insert_raw(c, e)?;
            summary.kb_added += 1;
        }
    }

    // 4. Evidence images: immutable — INSERT if absent, else skip. Also skip an
    //    image whose parent finding is missing after the findings merge.
    for img in bundle.evidence_images {
        let (meta, data) = img.into_parts()?;
        if db::evidence::exists(c, &meta.id)? {
            summary.skipped += 1;
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
