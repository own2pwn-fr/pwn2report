//! Structured scope-item CRUD (+ sync raw helpers). Mirrors the soft-delete /
//! tombstone pattern of `db::assets`.

use rusqlite::types::ToSql;
use rusqlite::{params, Connection, OptionalExtension, Row};
use uuid::Uuid;

use super::now_rfc3339;
use crate::error::{AppError, AppResult};
use crate::models::{NewScopeItem, ScopeItem, ScopeItemPatch};

/// Map a `scope_items` row to a `ScopeItem`.
fn row_to_scope(row: &Row) -> AppResult<ScopeItem> {
    Ok(ScopeItem {
        id: row.get("id")?,
        report_id: row.get("report_id")?,
        kind: row.get("kind")?,
        value: row.get("value")?,
        in_scope: row.get::<_, i64>("in_scope")? != 0,
        note: row.get("note")?,
        sort_order: row.get("sort_order")?,
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
        deleted_at: row.get("deleted_at")?,
    })
}

/// List a report's live scope items ordered by `sort_order`.
pub fn list(conn: &Connection, report_id: &str) -> AppResult<Vec<ScopeItem>> {
    let mut stmt = conn.prepare(
        "SELECT * FROM scope_items WHERE report_id = ?1 AND deleted_at IS NULL \
         ORDER BY sort_order, created_at",
    )?;
    let mut rows = stmt.query(params![report_id])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(row_to_scope(row)?);
    }
    Ok(out)
}

/// Fetch all scope items across every report (sync snapshot). INCLUDES tombstones.
pub fn list_all(conn: &Connection) -> AppResult<Vec<ScopeItem>> {
    let mut stmt = conn.prepare("SELECT * FROM scope_items ORDER BY id")?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(row_to_scope(row)?);
    }
    Ok(out)
}

/// Whether a scope item with this id exists (INCLUDING tombstones).
pub fn exists(conn: &Connection, id: &str) -> AppResult<bool> {
    let found: bool = conn
        .query_row(
            "SELECT 1 FROM scope_items WHERE id = ?1",
            params![id],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);
    Ok(found)
}

/// Fetch a single live scope item by id (excludes tombstones).
pub fn get(conn: &Connection, id: &str) -> AppResult<ScopeItem> {
    let mut stmt =
        conn.prepare("SELECT * FROM scope_items WHERE id = ?1 AND deleted_at IS NULL")?;
    let mut rows = stmt.query(params![id])?;
    match rows.next()? {
        Some(row) => row_to_scope(row),
        None => Err(AppError::NotFound),
    }
}

/// Fetch a scope item by id INCLUDING a soft-deleted tombstone (sync LWW read).
pub fn get_raw(conn: &Connection, id: &str) -> AppResult<ScopeItem> {
    let mut stmt = conn.prepare("SELECT * FROM scope_items WHERE id = ?1")?;
    let mut rows = stmt.query(params![id])?;
    match rows.next()? {
        Some(row) => row_to_scope(row),
        None => Err(AppError::NotFound),
    }
}

/// The next `sort_order` for a report's scope items (max + 1, or 0).
fn next_sort_order(conn: &Connection, report_id: &str) -> AppResult<i64> {
    let max: Option<i64> = conn
        .query_row(
            "SELECT MAX(sort_order) FROM scope_items WHERE report_id = ?1",
            params![report_id],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    Ok(max.map(|m| m + 1).unwrap_or(0))
}

/// Create a new scope item under `report_id`, appended at the end of the sort
/// order. `in_scope` defaults to `true`.
pub fn create(conn: &Connection, report_id: &str, input: NewScopeItem) -> AppResult<ScopeItem> {
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
    let kind = input.kind.unwrap_or_default();
    let in_scope = input.in_scope.unwrap_or(true);
    let note = input.note.unwrap_or_default();

    conn.execute(
        r#"
        INSERT INTO scope_items
            (id, report_id, kind, value, in_scope, note, sort_order,
             created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
        "#,
        params![
            id,
            report_id,
            kind,
            input.value,
            in_scope as i64,
            note,
            sort_order,
            now,
        ],
    )?;
    get(conn, &id)
}

/// Insert a scope item verbatim (sync merge). Caller ensures the report exists.
pub fn insert_raw(conn: &Connection, s: &ScopeItem) -> AppResult<()> {
    conn.execute(
        r#"
        INSERT INTO scope_items
            (id, report_id, kind, value, in_scope, note, sort_order,
             created_at, updated_at, deleted_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        "#,
        params![
            s.id,
            s.report_id,
            s.kind,
            s.value,
            s.in_scope as i64,
            s.note,
            s.sort_order,
            s.created_at,
            s.updated_at,
            s.deleted_at,
        ],
    )?;
    Ok(())
}

/// Overwrite a scope item verbatim, preserving incoming timestamps (sync LWW).
pub fn update_raw(conn: &Connection, s: &ScopeItem) -> AppResult<()> {
    conn.execute(
        r#"
        UPDATE scope_items SET
            kind = ?2, value = ?3, in_scope = ?4, note = ?5, sort_order = ?6,
            created_at = ?7, updated_at = ?8, deleted_at = ?9
        WHERE id = ?1
        "#,
        params![
            s.id,
            s.kind,
            s.value,
            s.in_scope as i64,
            s.note,
            s.sort_order,
            s.created_at,
            s.updated_at,
            s.deleted_at,
        ],
    )?;
    Ok(())
}

/// Apply a partial update; returns the updated item. Always bumps `updated_at`.
pub fn update(conn: &Connection, id: &str, patch: ScopeItemPatch) -> AppResult<ScopeItem> {
    let _ = get(conn, id)?; // NotFound if absent.
    let now = now_rfc3339();
    let mut sets: Vec<&str> = vec!["updated_at = ?"];
    let mut vals: Vec<Box<dyn ToSql>> = vec![Box::new(now)];

    if let Some(kind) = patch.kind {
        sets.push("kind = ?");
        vals.push(Box::new(kind));
    }
    if let Some(value) = patch.value {
        sets.push("value = ?");
        vals.push(Box::new(value));
    }
    if let Some(in_scope) = patch.in_scope {
        sets.push("in_scope = ?");
        vals.push(Box::new(in_scope as i64));
    }
    if let Some(note) = patch.note {
        sets.push("note = ?");
        vals.push(Box::new(note));
    }

    let sql = format!("UPDATE scope_items SET {} WHERE id = ?", sets.join(", "));
    vals.push(Box::new(id.to_string()));
    let bound: Vec<&dyn ToSql> = vals.iter().map(|b| b.as_ref()).collect();
    conn.execute(&sql, bound.as_slice())?;
    get(conn, id)
}

/// Soft-delete a scope item: tombstone + bump `updated_at` for sync LWW.
pub fn delete(conn: &Connection, id: &str) -> AppResult<()> {
    let now = now_rfc3339();
    let n = conn.execute(
        "UPDATE scope_items SET deleted_at = ?1, updated_at = ?1 \
         WHERE id = ?2 AND deleted_at IS NULL",
        params![now, id],
    )?;
    if n == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// Re-assign `sort_order` to match the given id ordering.
pub fn reorder(conn: &mut Connection, report_id: &str, ordered_ids: &[String]) -> AppResult<()> {
    let tx = conn.transaction()?;
    for (idx, sid) in ordered_ids.iter().enumerate() {
        tx.execute(
            "UPDATE scope_items SET sort_order = ?1 WHERE id = ?2 AND report_id = ?3",
            params![idx as i64, sid, report_id],
        )?;
    }
    tx.commit()?;
    Ok(())
}
