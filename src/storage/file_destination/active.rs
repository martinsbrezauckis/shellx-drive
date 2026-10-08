use rusqlite::{params, Transaction};

use crate::error::{ApiError, ApiResult};

pub(super) fn live_sibling_exists_in_tx(
    tx: &Transaction<'_>,
    workspace_id: &str,
    parent_id: Option<&str>,
    name: &str,
    excluded_file_id: Option<&str>,
) -> ApiResult<bool> {
    let collision: i64 = match (parent_id, excluded_file_id) {
        (Some(parent_id), Some(file_id)) => tx.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM files
                 WHERE workspace_id = ?1 AND parent_id = ?2 AND name = ?3
                   AND trashed = 0 AND id != ?4
             )",
            params![workspace_id, parent_id, name, file_id],
            |row| row.get(0),
        )?,
        (Some(parent_id), None) => tx.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM files
                 WHERE workspace_id = ?1 AND parent_id = ?2 AND name = ?3
                   AND trashed = 0
             )",
            params![workspace_id, parent_id, name],
            |row| row.get(0),
        )?,
        (None, Some(file_id)) => tx.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM files
                 WHERE workspace_id = ?1 AND parent_id IS NULL AND name = ?2
                   AND trashed = 0 AND id != ?3
             )",
            params![workspace_id, name, file_id],
            |row| row.get(0),
        )?,
        (None, None) => tx.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM files
                 WHERE workspace_id = ?1 AND parent_id IS NULL AND name = ?2
                   AND trashed = 0
             )",
            params![workspace_id, name],
            |row| row.get(0),
        )?,
    };
    Ok(collision != 0)
}

pub(in crate::storage) fn ensure_live_sibling_available_in_tx(
    tx: &Transaction<'_>,
    workspace_id: &str,
    file_id: &str,
    parent_id: Option<&str>,
    name: &str,
) -> ApiResult<()> {
    if live_sibling_exists_in_tx(tx, workspace_id, parent_id, name, Some(file_id))? {
        return Err(ApiError::Conflict);
    }
    Ok(())
}
