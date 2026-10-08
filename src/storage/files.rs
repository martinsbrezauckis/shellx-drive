use std::collections::{HashMap, HashSet};

use rusqlite::params_from_iter;

use crate::{
    auth::token_hash,
    error::ApiResult,
    model::{DebugBrowseWorkspace, DebugLargeFolder, DriveFile, FileKind},
};

use super::{bounded_files::effectively_live_sql_predicate, Storage};

mod complete_tree;

pub(super) use complete_tree::attach_folder_sizes_complete_tree;

const DEBUG_LARGE_FOLDERS_LIMIT: i64 = 50;
const DEBUG_BROWSE_WORKSPACES_LIMIT: i64 = 1_000;

impl Storage {
    /// Return aggregate-only browse diagnostics. Names, paths, and content
    /// hashes never leave this query; large folders use a stable hashed ref and
    /// the result is capped for predictable Debug API response size.
    pub fn debug_browse_aggregates(
        &self,
    ) -> ApiResult<(Vec<DebugBrowseWorkspace>, Vec<DebugLargeFolder>)> {
        let conn = self.conn.lock().unwrap();
        let mut workspace_stmt = conn.prepare(
            "WITH bounded_workspaces AS (
                 SELECT id, storage_mode
                 FROM workspaces
                 ORDER BY id
                 LIMIT ?1
             ),
             direct_children AS (
                 SELECT files.parent_id, COUNT(*) AS child_count
                 FROM files
                 JOIN bounded_workspaces ON bounded_workspaces.id = files.workspace_id
                 WHERE files.trashed = 0 AND files.parent_id IS NOT NULL
                 GROUP BY parent_id
             )
             SELECT bounded_workspaces.id, bounded_workspaces.storage_mode,
                    COALESCE(SUM(CASE WHEN files.trashed = 0 AND files.kind = 'file' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN files.trashed = 0 AND files.kind = 'folder' THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN files.trashed = 1 THEN 1 ELSE 0 END), 0),
                    COALESCE(SUM(CASE WHEN files.trashed = 0 AND files.kind = 'file' THEN files.content_bytes ELSE 0 END), 0),
                    COALESCE(MAX(CASE WHEN files.trashed = 0 AND files.kind = 'folder' THEN COALESCE(direct_children.child_count, 0) ELSE 0 END), 0)
             FROM bounded_workspaces
             LEFT JOIN files ON files.workspace_id = bounded_workspaces.id
             LEFT JOIN direct_children ON direct_children.parent_id = files.id
             GROUP BY bounded_workspaces.id, bounded_workspaces.storage_mode
             ORDER BY bounded_workspaces.id",
        )?;
        let workspaces = workspace_stmt
            .query_map([DEBUG_BROWSE_WORKSPACES_LIMIT], |row| {
                Ok(DebugBrowseWorkspace {
                    workspace_id: row.get(0)?,
                    storage_mode: row.get(1)?,
                    live_files: row.get(2)?,
                    live_folders: row.get(3)?,
                    trashed_items: row.get(4)?,
                    current_file_bytes: row.get(5)?,
                    max_direct_children: row.get(6)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let effective_file_visibility = effectively_live_sql_predicate("files");
        let effective_folder_visibility = effectively_live_sql_predicate("folders");
        let folder_sql = format!(
            "WITH RECURSIVE bounded_workspaces AS (
                 SELECT id
                 FROM workspaces
                 ORDER BY id
                 LIMIT ?1
             ),
             file_ancestors(file_id, folder_id, content_bytes, workspace_id) AS (
                 SELECT files.id, files.parent_id, files.content_bytes, files.workspace_id
                 FROM files
                 JOIN bounded_workspaces ON bounded_workspaces.id = files.workspace_id
                 WHERE files.kind = 'file' AND files.trashed = 0 AND files.parent_id IS NOT NULL
                   AND {effective_file_visibility}
                 UNION
                 SELECT ancestry.file_id, parent.parent_id, ancestry.content_bytes, ancestry.workspace_id
                 FROM file_ancestors ancestry
                 JOIN files parent
                  ON parent.id = ancestry.folder_id
                 AND parent.workspace_id = ancestry.workspace_id
                 WHERE parent.kind = 'folder' AND parent.trashed = 0 AND parent.parent_id IS NOT NULL
             ),
             folder_sizes AS (
                 SELECT folder_id, SUM(content_bytes) AS folder_size_bytes
                 FROM file_ancestors
                 WHERE folder_id IS NOT NULL
                 GROUP BY folder_id
             ),
             direct_children AS (
                 SELECT files.parent_id, COUNT(*) AS child_count
                 FROM files
                 JOIN bounded_workspaces ON bounded_workspaces.id = files.workspace_id
                 WHERE files.trashed = 0 AND files.parent_id IS NOT NULL
                   AND {effective_file_visibility}
                 GROUP BY parent_id
             )
             SELECT folders.id, folders.workspace_id,
                    COALESCE(direct_children.child_count, 0),
                    COALESCE(folder_sizes.folder_size_bytes, 0)
             FROM files folders
             JOIN bounded_workspaces ON bounded_workspaces.id = folders.workspace_id
             LEFT JOIN direct_children ON direct_children.parent_id = folders.id
             LEFT JOIN folder_sizes ON folder_sizes.folder_id = folders.id
             WHERE folders.kind = 'folder' AND folders.trashed = 0
               AND {effective_folder_visibility}
             ORDER BY COALESCE(direct_children.child_count, 0) DESC,
                      COALESCE(folder_sizes.folder_size_bytes, 0) DESC,
                      folders.id
             LIMIT ?2"
        );
        let mut folder_stmt = conn.prepare(&folder_sql)?;
        let large_folders = folder_stmt
            .query_map(
                [DEBUG_BROWSE_WORKSPACES_LIMIT, DEBUG_LARGE_FOLDERS_LIMIT],
                |row| {
                    let folder_id: String = row.get(0)?;
                    Ok(DebugLargeFolder {
                        folder_ref: format!("folder-{}", &token_hash(&folder_id)[..12]),
                        workspace_id: row.get(1)?,
                        direct_children: row.get(2)?,
                        folder_size_bytes: row.get(3)?,
                    })
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok((workspaces, large_folders))
    }
}

/// Attach recursive logical sizes to every folder in `files` with one
/// set-oriented query across the relevant workspaces. The recursive relation
/// walks upward from each effectively live file, so work is proportional to
/// file depth rather than performing one descendant query per folder. The
/// recursive term stops at a trashed ancestor as a second boundary against
/// malformed legacy state.
/// `UNION` de-duplicates `(file, folder)` pairs and therefore terminates even
/// if a corrupt legacy database contains a parent cycle.
pub(super) fn attach_folder_sizes_locked(
    conn: &rusqlite::Connection,
    files: &mut [DriveFile],
) -> rusqlite::Result<()> {
    let workspace_ids = files
        .iter()
        .filter(|file| matches!(file.kind, FileKind::Folder))
        .map(|file| file.workspace_id.as_str())
        .collect::<HashSet<_>>();
    if workspace_ids.is_empty() {
        return Ok(());
    }
    let mut workspace_ids = workspace_ids.into_iter().collect::<Vec<_>>();
    workspace_ids.sort_unstable();
    let placeholders = std::iter::repeat_n("?", workspace_ids.len())
        .collect::<Vec<_>>()
        .join(", ");
    let effective_visibility = effectively_live_sql_predicate("files");
    let sql = format!(
        "WITH RECURSIVE file_ancestors(file_id, folder_id, content_bytes, workspace_id) AS (
             SELECT id, parent_id, content_bytes, workspace_id
             FROM files
             WHERE kind = 'file'
               AND trashed = 0
               AND parent_id IS NOT NULL
               AND workspace_id IN ({placeholders})
               AND {effective_visibility}
             UNION
             SELECT ancestry.file_id, parent.parent_id, ancestry.content_bytes,
                    ancestry.workspace_id
             FROM file_ancestors ancestry
             JOIN files parent
               ON parent.id = ancestry.folder_id
              AND parent.workspace_id = ancestry.workspace_id
             WHERE parent.kind = 'folder'
               AND parent.trashed = 0
               AND parent.parent_id IS NOT NULL
         )
         SELECT folder_id, SUM(content_bytes)
         FROM file_ancestors
         WHERE folder_id IS NOT NULL
         GROUP BY folder_id"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(workspace_ids), |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    let sizes = rows.collect::<rusqlite::Result<HashMap<_, _>>>()?;
    for file in files {
        file.folder_size_bytes = matches!(file.kind, FileKind::Folder)
            .then(|| sizes.get(&file.id).copied().unwrap_or(0));
    }
    Ok(())
}
