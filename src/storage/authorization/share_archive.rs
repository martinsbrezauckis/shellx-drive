use std::collections::{HashMap, HashSet};

use rusqlite::{params, OptionalExtension};

use crate::{
    download_subjects::CurrentFileSubject,
    error::{ApiError, ApiResult},
    storage::{Storage, MAX_FILE_TREE_DEPTH, MAX_FILE_TREE_NODES},
};

#[derive(Debug)]
struct LiveArchiveNode {
    kind: String,
    revision: i64,
    content_hash: Option<String>,
    content_bytes: Option<i64>,
}

impl Storage {
    /// Revalidate one prepared public archive from a single bounded subtree
    /// snapshot. Cost scales with the shared tree, never with
    /// `ticket entries * ancestor depth`.
    pub(crate) fn ensure_share_archive_ticket_authorized(
        &self,
        share_root_id: &str,
        file_ids: &[String],
        content_subjects: &[CurrentFileSubject],
    ) -> ApiResult<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let (workspace_id, root_trashed): (String, i64) = tx
            .query_row(
                "SELECT workspace_id, trashed FROM files WHERE id = ?1",
                params![share_root_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(ApiError::NotFound)?;
        if root_trashed != 0 {
            return Err(ApiError::NotFound);
        }

        let sentinel =
            i64::try_from(MAX_FILE_TREE_NODES.saturating_add(1)).map_err(|_| ApiError::NotFound)?;
        let mut statement = tx.prepare(
            "WITH RECURSIVE live_subtree(
                 id, workspace_id, kind, revision, content_hash, content_bytes, depth
             ) AS (
                 SELECT id, workspace_id, kind, revision, content_hash, content_bytes, 0
                 FROM files WHERE id = ?1 AND workspace_id = ?2 AND trashed = 0
                 UNION ALL
                 SELECT child.id, child.workspace_id, child.kind, child.revision,
                        child.content_hash, child.content_bytes, live_subtree.depth + 1
                 FROM files child INDEXED BY idx_files_workspace_parent
                 JOIN live_subtree
                   ON child.parent_id = live_subtree.id
                  AND child.workspace_id = live_subtree.workspace_id
                 WHERE child.trashed = 0 AND live_subtree.depth < ?3
             )
             SELECT id, kind, revision, content_hash, content_bytes
             FROM live_subtree LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![
                share_root_id,
                &workspace_id,
                MAX_FILE_TREE_DEPTH as i64,
                sentinel
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    LiveArchiveNode {
                        kind: row.get(1)?,
                        revision: row.get(2)?,
                        content_hash: row.get(3)?,
                        content_bytes: row.get(4)?,
                    },
                ))
            },
        )?;
        let mut live = HashMap::with_capacity(file_ids.len());
        for row in rows {
            let (id, node) = row?;
            if live.insert(id, node).is_some() {
                return Err(ApiError::NotFound);
            }
            if live.len() > MAX_FILE_TREE_NODES {
                return Err(ApiError::NotFound);
            }
        }
        drop(statement);

        let scoped = file_ids.iter().map(String::as_str).collect::<HashSet<_>>();
        if scoped.iter().any(|file_id| !live.contains_key(*file_id)) {
            return Err(ApiError::NotFound);
        }
        for subject in content_subjects {
            if !scoped.contains(subject.file_id.as_str()) {
                return Err(ApiError::NotFound);
            }
            let node = live.get(&subject.file_id).ok_or(ApiError::NotFound)?;
            let size_matches = node
                .content_bytes
                .and_then(|bytes| u64::try_from(bytes).ok())
                == Some(subject.expected_size);
            if node.kind != "file"
                || node.revision != subject.revision
                || node.content_hash.as_deref() != Some(subject.content_hash.as_str())
                || !size_matches
            {
                return Err(ApiError::NotFound);
            }
        }
        tx.commit()?;
        Ok(())
    }
}
