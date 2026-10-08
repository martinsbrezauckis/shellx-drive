use chrono::Utc;
use rand::RngCore;
use rusqlite::{params, Transaction};
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};

use super::super::{
    bounded_files::ensure_workspace_node_capacity, file_destination::available_copy_name_in_tx,
    refresh_file_search_index_locked,
};

/// The pointer and reverse owner marker must agree. A moved, trashed, or
/// mismatched folder is never a valid public-upload destination.
pub(super) fn inbox_for_drop_in_tx(
    tx: &Transaction<'_>,
    drop_id: &str,
    workspace_id: &str,
) -> ApiResult<String> {
    let pointer: Option<String> = tx.query_row(
        "SELECT inbox_file_id FROM drops WHERE id = ?1 AND workspace_id = ?2",
        params![drop_id, workspace_id],
        |row| row.get(0),
    )?;
    if let Some(id) = pointer {
        let valid: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM files
             WHERE id = ?1 AND workspace_id = ?2 AND parent_id IS NULL
               AND kind = 'folder' AND trashed = 0 AND drop_inbox_owner_id = ?3)",
            params![&id, workspace_id, drop_id],
            |row| row.get::<_, i64>(0),
        )? != 0;
        if valid {
            return Ok(id);
        }
    }

    // A legacy Drop gets its inbox on its first admitted upload. Generate a
    // fresh root node even when an owner has made a similarly named folder.
    ensure_workspace_node_capacity(tx, workspace_id, 1)?;
    let id = Uuid::now_v7().to_string();
    let mut random_bytes = [0_u8; 8];
    rand::thread_rng().fill_bytes(&mut random_bytes);
    let suffix = u64::from_be_bytes(random_bytes);
    let name = available_copy_name_in_tx(
        tx,
        workspace_id,
        None,
        &format!("Drop uploads - {suffix:016x}"),
    )?;
    let revision_id = Uuid::now_v7().to_string();
    let now = Utc::now().to_rfc3339();
    tx.execute(
        "INSERT INTO files (
            id, workspace_id, parent_id, name, kind, revision, trashed,
            starred, content_hash, content_bytes, created_at, updated_at, drop_inbox_owner_id
         ) VALUES (?1, ?2, NULL, ?3, 'folder', 1, 0, 0, NULL, 0, ?4, ?4, ?5)",
        params![&id, workspace_id, &name, &now, drop_id],
    )?;
    tx.execute(
        "INSERT INTO file_revisions (
            id, file_id, revision, content_hash, content_bytes, created_at, conflict_of_revision
         ) VALUES (?1, ?2, 1, NULL, 0, ?3, NULL)",
        params![revision_id, &id, &now],
    )?;
    refresh_file_search_index_locked(tx, &id)?;
    if tx.execute(
        "UPDATE drops SET inbox_file_id = ?1 WHERE id = ?2 AND workspace_id = ?3",
        params![&id, drop_id, workspace_id],
    )? != 1
    {
        return Err(ApiError::Conflict);
    }
    Ok(id)
}
