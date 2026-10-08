use rusqlite::{OptionalExtension, Transaction};

use crate::error::{ApiError, ApiResult};

use super::super::{MAX_FILE_TREE_DEPTH, MAX_FILE_TREE_NODES};

/// Validate the complete restored file forest before it becomes live. Parent
/// shape checks run first; a root-driven recursive CTE can then prove bounded
/// depth and cycle freedom without materializing attacker-sized paths.
pub(super) fn validate_in_tx(tx: &Transaction<'_>) -> ApiResult<()> {
    if let Some(id) = tx
        .query_row(
            "SELECT child.id FROM files child
             LEFT JOIN files parent ON parent.id = child.parent_id
             WHERE child.parent_id IS NOT NULL AND parent.id IS NULL LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?
    {
        return Err(ApiError::Validation(format!(
            "restored file {id} references a missing parent"
        )));
    }
    if let Some(id) = tx
        .query_row(
            "SELECT child.id FROM files child
             JOIN files parent ON parent.id = child.parent_id
             WHERE parent.kind <> 'folder' LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?
    {
        return Err(ApiError::Validation(format!(
            "restored file {id} has a non-folder parent"
        )));
    }
    if let Some(id) = tx
        .query_row(
            "SELECT child.id FROM files child
             JOIN files parent ON parent.id = child.parent_id
             WHERE child.workspace_id <> parent.workspace_id LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?
    {
        return Err(ApiError::Validation(format!(
            "restored file {id} crosses a workspace parent boundary"
        )));
    }
    if let Some(workspace_id) = tx
        .query_row(
            "SELECT workspace_id FROM files GROUP BY workspace_id
             HAVING COUNT(*) > ?1 LIMIT 1",
            [i64::try_from(MAX_FILE_TREE_NODES).unwrap_or(i64::MAX)],
            |row| row.get::<_, String>(0),
        )
        .optional()?
    {
        return Err(ApiError::Validation(format!(
            "restored workspace {workspace_id} exceeds the {MAX_FILE_TREE_NODES}-item file-tree limit"
        )));
    }

    let depth_sentinel = i64::try_from(MAX_FILE_TREE_DEPTH.saturating_add(1)).unwrap_or(i64::MAX);
    let (reachable, deepest): (i64, i64) = tx.query_row(
        "WITH RECURSIVE tree(id, depth) AS (
             SELECT id, 0 FROM files WHERE parent_id IS NULL
             UNION ALL
             SELECT child.id, tree.depth + 1 FROM files child
             JOIN tree ON child.parent_id = tree.id WHERE tree.depth < ?1
         )
         SELECT COUNT(*), COALESCE(MAX(depth), 0) FROM tree",
        [depth_sentinel],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if deepest > MAX_FILE_TREE_DEPTH as i64 {
        return Err(ApiError::Validation(format!(
            "restored file tree exceeds the {MAX_FILE_TREE_DEPTH}-level depth limit"
        )));
    }
    let total: i64 = tx.query_row("SELECT COUNT(*) FROM files", [], |row| row.get(0))?;
    if reachable != total {
        return Err(ApiError::Validation(
            "restored file tree contains a parent cycle".to_string(),
        ));
    }
    Ok(())
}
