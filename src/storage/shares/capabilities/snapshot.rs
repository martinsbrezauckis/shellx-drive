use std::collections::HashSet;

use rusqlite::{params, OptionalExtension};

use crate::{
    error::{ApiError, ApiResult},
    model::DriveFile,
    storage::{
        bounded_files::file_is_effectively_trashed_locked, MAX_FILE_TREE_DEPTH, MAX_FILE_TREE_NODES,
    },
};

/// Compare the response-planning snapshot against the current bounded public
/// subtree while the caller holds an `IMMEDIATE` transaction.  The recursive
/// CTE advances from the exact root only through non-trashed children in the
/// same workspace; it is guarded by the canonical depth/node limits and also
/// rejects cycles.  We then compare every response-bearing raw row, so paths,
/// names, types, revisions, timestamps, and body sizes cannot change between
/// planning and finite-use claim.
pub(super) fn ensure_share_metadata_snapshot_current(
    tx: &rusqlite::Transaction<'_>,
    share_file_id: &str,
    expected_root: &DriveFile,
    expected_descendants: &[DriveFile],
) -> ApiResult<()> {
    if expected_root.id != share_file_id
        || expected_root.trashed
        || file_is_effectively_trashed_locked(tx, share_file_id)?
    {
        return Err(ApiError::NotFound);
    }

    let mut expected = Vec::with_capacity(expected_descendants.len().saturating_add(1));
    expected.push(expected_root);
    expected.extend(expected_descendants);
    let expected_ids = expected
        .iter()
        .map(|file| file.id.as_str())
        .collect::<HashSet<_>>();
    if expected_ids.len() != expected.len() || expected.len() > MAX_FILE_TREE_NODES {
        return Err(ApiError::NotFound);
    }

    if matches!(expected_root.kind, crate::model::FileKind::Folder) {
        let mut statement = tx.prepare(&format!(
            "WITH RECURSIVE live_tree(id, workspace_id, depth) AS (
                 SELECT id, workspace_id, 0
                 FROM files WHERE id = ?1 AND trashed = 0
                 UNION ALL
                 SELECT child.id, live_tree.workspace_id, live_tree.depth + 1
                 FROM files child INDEXED BY idx_files_workspace_parent
                 JOIN live_tree
                   ON child.parent_id = live_tree.id
                  AND child.workspace_id = live_tree.workspace_id
                 WHERE child.trashed = 0
                   AND live_tree.depth < {max_depth}
                 LIMIT {node_sentinel}
             )
             SELECT id, depth FROM live_tree",
            max_depth = MAX_FILE_TREE_DEPTH.saturating_add(1),
            node_sentinel = MAX_FILE_TREE_NODES.saturating_add(1),
        ))?;
        let live = statement
            .query_map(params![share_file_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut observed = HashSet::with_capacity(live.len());
        if live.len() > MAX_FILE_TREE_NODES
            || live
                .iter()
                .any(|(_, depth)| *depth > MAX_FILE_TREE_DEPTH as i64)
            || live.iter().any(|(id, _)| !observed.insert(id.as_str()))
            || observed.len() != expected_ids.len()
            || !observed.iter().all(|id| expected_ids.contains(id))
        {
            return Err(ApiError::NotFound);
        }
    } else if !expected_descendants.is_empty() {
        return Err(ApiError::NotFound);
    }

    for expected_file in expected {
        ensure_metadata_file_current(tx, expected_file)?;
    }
    Ok(())
}

fn ensure_metadata_file_current(
    tx: &rusqlite::Transaction<'_>,
    expected: &DriveFile,
) -> ApiResult<()> {
    let current = tx
        .query_row(
            "SELECT workspace_id, parent_id, name, kind, revision, trashed, starred,
                    content_hash, created_at, updated_at, content_bytes, cover_hash
             FROM files WHERE id = ?1",
            params![&expected.id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)? != 0,
                    row.get::<_, i64>(6)? != 0,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, Option<String>>(11)?.is_some(),
                ))
            },
        )
        .optional()?;
    let matches = current.is_some_and(
        |(
            workspace_id,
            parent_id,
            name,
            kind,
            revision,
            trashed,
            starred,
            content_hash,
            created_at,
            updated_at,
            content_bytes,
            has_cover,
        )| {
            workspace_id == expected.workspace_id
                && parent_id == expected.parent_id
                && name == expected.name
                && kind == expected.kind.as_db_str()
                && revision == expected.revision
                && !trashed
                && !expected.trashed
                && starred == expected.starred
                && content_hash == expected.content_hash
                && created_at == expected.created_at
                && updated_at == expected.updated_at
                && content_bytes == expected.size_bytes.unwrap_or(0)
                && has_cover == expected.has_cover
        },
    );
    matches.then_some(()).ok_or(ApiError::NotFound)
}
