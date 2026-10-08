use rusqlite::{params, Transaction};

use crate::{
    error::{ApiError, ApiResult},
    model::DriveFile,
};

use super::super::row_to_file;

pub(super) fn active_sibling_in_tx(
    tx: &Transaction<'_>,
    workspace_id: &str,
    parent_id: Option<&str>,
    name: &str,
    excluded_file_id: Option<&str>,
) -> ApiResult<Option<DriveFile>> {
    let sql = match (parent_id.is_some(), excluded_file_id.is_some()) {
        (true, true) => {
            "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                    content_hash, created_at, updated_at, content_bytes, cover_hash
             FROM files
             WHERE workspace_id = ?1 AND parent_id = ?2 AND name = ?3
               AND trashed = 0 AND id != ?4
             ORDER BY id ASC LIMIT 2"
        }
        (true, false) => {
            "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                    content_hash, created_at, updated_at, content_bytes, cover_hash
             FROM files
             WHERE workspace_id = ?1 AND parent_id = ?2 AND name = ?3 AND trashed = 0
             ORDER BY id ASC LIMIT 2"
        }
        (false, true) => {
            "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                    content_hash, created_at, updated_at, content_bytes, cover_hash
             FROM files
             WHERE workspace_id = ?1 AND parent_id IS NULL AND name = ?2
               AND trashed = 0 AND id != ?3
             ORDER BY id ASC LIMIT 2"
        }
        (false, false) => {
            "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                    content_hash, created_at, updated_at, content_bytes, cover_hash
             FROM files
             WHERE workspace_id = ?1 AND parent_id IS NULL AND name = ?2 AND trashed = 0
             ORDER BY id ASC LIMIT 2"
        }
    };
    let mut statement = tx.prepare(sql)?;
    let files = match (parent_id, excluded_file_id) {
        (Some(parent_id), Some(excluded_file_id)) => statement
            .query_map(
                params![workspace_id, parent_id, name, excluded_file_id],
                row_to_file,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?,
        (Some(parent_id), None) => statement
            .query_map(params![workspace_id, parent_id, name], row_to_file)?
            .collect::<rusqlite::Result<Vec<_>>>()?,
        (None, Some(excluded_file_id)) => statement
            .query_map(params![workspace_id, name, excluded_file_id], row_to_file)?
            .collect::<rusqlite::Result<Vec<_>>>()?,
        (None, None) => statement
            .query_map(params![workspace_id, name], row_to_file)?
            .collect::<rusqlite::Result<Vec<_>>>()?,
    };
    match files.as_slice() {
        [] => Ok(None),
        [file] => Ok(Some(file.clone())),
        _ => Err(ApiError::Conflict),
    }
}
