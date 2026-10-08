use std::collections::HashSet;

use rusqlite::{params, Transaction};

use crate::{
    error::{ApiError, ApiResult},
    model::{DriveFile, FileKind},
    storage::{validate_parent_chain_in_tx, MAX_FILE_TREE_DEPTH, MAX_FILE_TREE_NODES},
};

/// Keep every stored descendant within the workspace limit before a move.
/// Trashed rows participate because the canonical tree validates their topology.
pub(super) fn validate_move_depth_in_tx(
    tx: &Transaction<'_>,
    source: &DriveFile,
    parent_id: Option<&str>,
) -> ApiResult<()> {
    let destination_depth = parent_id
        .map(|parent| {
            validate_parent_chain_in_tx(tx, &source.workspace_id, parent, Some(&source.id))
        })
        .transpose()?
        .unwrap_or(0);
    if !matches!(source.kind, FileKind::Folder) {
        return Ok(());
    }
    let mut statement = tx.prepare(
        "WITH RECURSIVE tree(id, depth) AS (
             SELECT id, 0 FROM files WHERE id = ?1 AND workspace_id = ?2
             UNION ALL
             SELECT child.id, tree.depth + 1
             FROM files child INDEXED BY idx_files_workspace_parent
             JOIN tree ON child.parent_id = tree.id
             WHERE child.workspace_id = ?2 AND tree.depth < ?3
             LIMIT ?4
         ) SELECT id, depth FROM tree",
    )?;
    let rows = statement
        .query_map(
            params![
                &source.id,
                &source.workspace_id,
                (MAX_FILE_TREE_DEPTH + 1) as i64,
                (MAX_FILE_TREE_NODES + 1) as i64,
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, usize>(1)?)),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if rows.is_empty() {
        return Err(ApiError::NotFound);
    }
    if rows.len() > MAX_FILE_TREE_NODES {
        return Err(ApiError::Validation(format!(
            "file tree exceeds the {MAX_FILE_TREE_NODES}-item limit"
        )));
    }
    let mut visited = HashSet::with_capacity(rows.len());
    for (id, relative_depth) in rows {
        if !visited.insert(id) {
            return Err(ApiError::Validation(
                "file tree contains a parent cycle".to_string(),
            ));
        }
        let depth = destination_depth
            .checked_add(relative_depth)
            .ok_or_else(|| ApiError::Validation("file tree depth overflow".to_string()))?;
        if depth > MAX_FILE_TREE_DEPTH {
            return Err(ApiError::Validation(format!(
                "file tree exceeds the {MAX_FILE_TREE_DEPTH}-level depth limit"
            )));
        }
    }
    Ok(())
}
