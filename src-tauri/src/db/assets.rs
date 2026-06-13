//! Affected-asset CRUD (+ sync raw helpers). Mirrors the soft-delete/tombstone
//! pattern of `db::findings` / `db::reports`: live reads filter
//! `deleted_at IS NULL`; the sync path uses `list_all`/`get_raw`/`insert_raw`/
//! `update_raw` (which see tombstones) for LWW merging. Assets carry an
//! `updated_at`, so tombstones travel via `update_raw` like reports/findings —
//! no separate `set_deleted` is needed.

use rusqlite::types::ToSql;
use rusqlite::{params, Connection, OptionalExtension, Row};
use uuid::Uuid;

use super::now_rfc3339;
use crate::error::{AppError, AppResult};
use crate::models::{Asset, AssetKind, AssetPatch, NewAsset};

/// Map an `assets` row to an `Asset`.
fn row_to_asset(row: &Row) -> AppResult<Asset> {
    let kind: String = row.get("kind")?;
    Ok(Asset {
        id: row.get("id")?,
        report_id: row.get("report_id")?,
        kind: AssetKind::from_db(&kind),
        identifier: row.get("identifier")?,
        description: row.get("description")?,
        sort_order: row.get("sort_order")?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
        deleted_at: row.get("deleted_at")?,
    })
}

/// List a report's live assets ordered by `sort_order`.
pub fn list(conn: &Connection, report_id: &str) -> AppResult<Vec<Asset>> {
    let mut stmt = conn.prepare(
        "SELECT * FROM assets WHERE report_id = ?1 AND deleted_at IS NULL \
         ORDER BY sort_order, created_at",
    )?;
    let mut rows = stmt.query(params![report_id])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(row_to_asset(row)?);
    }
    Ok(out)
}

/// Fetch all assets across every report (sync snapshot). Ordered by id for a
/// deterministic snapshot. INCLUDES soft-deleted rows so tombstones travel.
pub fn list_all(conn: &Connection) -> AppResult<Vec<Asset>> {
    let mut stmt = conn.prepare("SELECT * FROM assets ORDER BY id")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(row_to_asset(row)?);
    }
    Ok(out)
}

/// Whether an asset with this id exists (INCLUDING soft-deleted tombstones).
pub fn exists(conn: &Connection, id: &str) -> AppResult<bool> {
    let found: bool = conn
        .query_row("SELECT 1 FROM assets WHERE id = ?1", params![id], |_| {
            Ok(true)
        })
        .optional()?
        .unwrap_or(false);
    Ok(found)
}

/// Fetch a single live asset by id (excludes tombstones).
pub fn get(conn: &Connection, id: &str) -> AppResult<Asset> {
    let mut stmt = conn.prepare("SELECT * FROM assets WHERE id = ?1 AND deleted_at IS NULL")?;
    let mut rows = stmt.query(params![id])?;
    match rows.next()? {
        Some(row) => row_to_asset(row),
        None => Err(AppError::NotFound),
    }
}

/// Fetch an asset by id INCLUDING a soft-deleted tombstone (sync LWW read).
pub fn get_raw(conn: &Connection, id: &str) -> AppResult<Asset> {
    let mut stmt = conn.prepare("SELECT * FROM assets WHERE id = ?1")?;
    let mut rows = stmt.query(params![id])?;
    match rows.next()? {
        Some(row) => row_to_asset(row),
        None => Err(AppError::NotFound),
    }
}

/// The next `sort_order` for a report's assets (max + 1, or 0).
fn next_sort_order(conn: &Connection, report_id: &str) -> AppResult<i64> {
    let max: Option<i64> = conn
        .query_row(
            "SELECT MAX(sort_order) FROM assets WHERE report_id = ?1",
            params![report_id],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    Ok(max.map(|m| m + 1).unwrap_or(0))
}

/// Create a new asset under `report_id`, appended at the end of the sort order.
pub fn create(conn: &Connection, report_id: &str, input: NewAsset) -> AppResult<Asset> {
    // Guard: parent must exist (yield a clean NotFound).
    let exists: bool = conn
        .query_row(
            "SELECT 1 FROM reports WHERE id = ?1 AND deleted_at IS NULL",
            params![report_id],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);
    if !exists {
        return Err(AppError::NotFound);
    }

    let id = Uuid::new_v4().to_string();
    let now = now_rfc3339();
    let sort_order = next_sort_order(conn, report_id)?;
    let kind = input.kind.unwrap_or(AssetKind::Other);
    let description = input.description.unwrap_or_default();

    conn.execute(
        r#"
        INSERT INTO assets
            (id, report_id, kind, identifier, description, sort_order,
             created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
        "#,
        params![
            id,
            report_id,
            kind.as_str(),
            input.identifier,
            description,
            sort_order,
            now,
        ],
    )?;
    get(conn, &id)
}

/// Insert an asset verbatim (sync merge). Caller ensures the report exists.
pub fn insert_raw(conn: &Connection, a: &Asset) -> AppResult<()> {
    conn.execute(
        r#"
        INSERT INTO assets
            (id, report_id, kind, identifier, description, sort_order,
             created_at, updated_at, deleted_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#,
        params![
            a.id,
            a.report_id,
            a.kind.as_str(),
            a.identifier,
            a.description,
            a.sort_order,
            a.created_at,
            a.updated_at,
            a.deleted_at,
        ],
    )?;
    Ok(())
}

/// Overwrite an asset verbatim, preserving incoming timestamps (sync LWW).
/// `report_id` is fixed by the primary key and not updated.
pub fn update_raw(conn: &Connection, a: &Asset) -> AppResult<()> {
    conn.execute(
        r#"
        UPDATE assets SET
            kind = ?2, identifier = ?3, description = ?4, sort_order = ?5,
            created_at = ?6, updated_at = ?7, deleted_at = ?8
        WHERE id = ?1
        "#,
        params![
            a.id,
            a.kind.as_str(),
            a.identifier,
            a.description,
            a.sort_order,
            a.created_at,
            a.updated_at,
            a.deleted_at,
        ],
    )?;
    Ok(())
}

/// Apply a partial update; returns the updated asset. Always bumps `updated_at`.
pub fn update(conn: &Connection, id: &str, patch: AssetPatch) -> AppResult<Asset> {
    let _ = get(conn, id)?; // NotFound if absent.
    let now = now_rfc3339();
    let mut sets: Vec<&str> = vec!["updated_at = ?"];
    let mut vals: Vec<Box<dyn ToSql>> = vec![Box::new(now)];

    if let Some(kind) = patch.kind {
        sets.push("kind = ?");
        vals.push(Box::new(kind.as_str().to_string()));
    }
    if let Some(identifier) = patch.identifier {
        sets.push("identifier = ?");
        vals.push(Box::new(identifier));
    }
    if let Some(description) = patch.description {
        sets.push("description = ?");
        vals.push(Box::new(description));
    }

    let sql = format!("UPDATE assets SET {} WHERE id = ?", sets.join(", "));
    vals.push(Box::new(id.to_string()));
    let bound: Vec<&dyn ToSql> = vals.iter().map(|b| b.as_ref()).collect();
    conn.execute(&sql, bound.as_slice())?;
    get(conn, id)
}

/// Soft-delete an asset: set `deleted_at = now` and bump `updated_at` so the
/// deletion becomes a tombstone that travels through sync and wins LWW. The
/// `finding_assets` links referencing it are NOT removed here (they are a
/// derived set; a tombstoned asset is filtered out of `list_finding_assets`).
pub fn delete(conn: &Connection, id: &str) -> AppResult<()> {
    let now = now_rfc3339();
    let n = conn.execute(
        "UPDATE assets SET deleted_at = ?1, updated_at = ?1 \
         WHERE id = ?2 AND deleted_at IS NULL",
        params![now, id],
    )?;
    if n == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// Re-assign `sort_order` to match the given id ordering. Ids not belonging to
/// the report are ignored; missing ids are left where they are.
pub fn reorder(conn: &mut Connection, report_id: &str, ordered_ids: &[String]) -> AppResult<()> {
    let tx = conn.transaction()?;
    for (idx, aid) in ordered_ids.iter().enumerate() {
        tx.execute(
            "UPDATE assets SET sort_order = ?1 WHERE id = ?2 AND report_id = ?3",
            params![idx as i64, aid, report_id],
        )?;
    }
    tx.commit()?;
    Ok(())
}
