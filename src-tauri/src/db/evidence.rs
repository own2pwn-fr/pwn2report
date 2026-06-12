//! Evidence-image CRUD. The image bytes live in the `data` BLOB column of the
//! SQLCipher-encrypted vault (encrypted at rest); only metadata is mapped into
//! the [`EvidenceImage`] model. Raw bytes are fetched separately via
//! [`get_data`] so listing a finding's images never copies the (potentially
//! large) blobs.

use rusqlite::{params, Connection, OptionalExtension, Row};
use uuid::Uuid;

use super::now_rfc3339;
use crate::error::{AppError, AppResult};
use crate::models::EvidenceImage;

/// Map an `evidence_images` row (metadata columns only) to an `EvidenceImage`.
fn row_to_image(row: &Row) -> AppResult<EvidenceImage> {
    Ok(EvidenceImage {
        id: row.get("id")?,
        finding_id: row.get("finding_id")?,
        caption: row.get("caption")?,
        mime: row.get("mime")?,
        sort_order: row.get("sort_order")?,
        created_at: row.get("created_at")?,
    })
}

/// The next `sort_order` for a finding's images (max + 1, or 0).
fn next_sort_order(conn: &Connection, finding_id: &str) -> AppResult<i64> {
    let max: Option<i64> = conn
        .query_row(
            "SELECT MAX(sort_order) FROM evidence_images WHERE finding_id = ?1",
            params![finding_id],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    Ok(max.map(|m| m + 1).unwrap_or(0))
}

/// Attach an image to a finding, appended at the end of its sort order.
/// Returns the freshly-created metadata (not the bytes).
pub fn add(
    conn: &Connection,
    finding_id: &str,
    caption: &str,
    mime: &str,
    data: &[u8],
) -> AppResult<EvidenceImage> {
    // Guard: parent finding must exist (FK is enforced, but yield a clean
    // NotFound rather than a raw constraint error).
    let exists: bool = conn
        .query_row(
            "SELECT 1 FROM findings WHERE id = ?1",
            params![finding_id],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);
    if !exists {
        return Err(AppError::NotFound);
    }

    let id = Uuid::new_v4().to_string();
    let now = now_rfc3339();
    let sort_order = next_sort_order(conn, finding_id)?;

    conn.execute(
        r#"
        INSERT INTO evidence_images
            (id, finding_id, caption, mime, data, sort_order, created_at)
        VALUES
            (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
        params![id, finding_id, caption, mime, data, sort_order, now],
    )?;

    get(conn, &id)
}

/// Fetch a single image's metadata by id.
pub fn get(conn: &Connection, id: &str) -> AppResult<EvidenceImage> {
    let mut stmt = conn.prepare(
        "SELECT id, finding_id, caption, mime, sort_order, created_at \
         FROM evidence_images WHERE id = ?1",
    )?;
    let mut rows = stmt.query(params![id])?;
    match rows.next()? {
        Some(row) => row_to_image(row),
        None => Err(AppError::NotFound),
    }
}

/// List a finding's images ordered by `sort_order` (metadata only).
pub fn list(conn: &Connection, finding_id: &str) -> AppResult<Vec<EvidenceImage>> {
    let mut stmt = conn.prepare(
        "SELECT id, finding_id, caption, mime, sort_order, created_at \
         FROM evidence_images WHERE finding_id = ?1 ORDER BY sort_order, created_at",
    )?;
    let mut rows = stmt.query(params![finding_id])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(row_to_image(row)?);
    }
    Ok(out)
}

/// Fetch an image's `(mime, bytes)` by id. Used by the export layer and the
/// `get_evidence_image` command.
pub fn get_data(conn: &Connection, id: &str) -> AppResult<(String, Vec<u8>)> {
    let mut stmt = conn.prepare("SELECT mime, data FROM evidence_images WHERE id = ?1")?;
    let mut rows = stmt.query(params![id])?;
    match rows.next()? {
        Some(row) => {
            let mime: String = row.get("mime")?;
            let data: Vec<u8> = row.get("data")?;
            Ok((mime, data))
        }
        None => Err(AppError::NotFound),
    }
}

/// Update an image's caption; returns the updated metadata.
pub fn update_caption(conn: &Connection, id: &str, caption: &str) -> AppResult<EvidenceImage> {
    let n = conn.execute(
        "UPDATE evidence_images SET caption = ?1 WHERE id = ?2",
        params![caption, id],
    )?;
    if n == 0 {
        return Err(AppError::NotFound);
    }
    get(conn, id)
}

/// Delete an image by id.
pub fn delete(conn: &Connection, id: &str) -> AppResult<()> {
    let n = conn.execute("DELETE FROM evidence_images WHERE id = ?1", params![id])?;
    if n == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// Re-assign `sort_order` to match the given id ordering. Ids not belonging to
/// the finding are ignored; missing ids are simply left where they are.
pub fn reorder(
    conn: &mut Connection,
    finding_id: &str,
    ordered_ids: &[String],
) -> AppResult<()> {
    let tx = conn.transaction()?;
    for (idx, iid) in ordered_ids.iter().enumerate() {
        tx.execute(
            "UPDATE evidence_images SET sort_order = ?1 WHERE id = ?2 AND finding_id = ?3",
            params![idx as i64, iid, finding_id],
        )?;
    }
    tx.commit()?;
    Ok(())
}
