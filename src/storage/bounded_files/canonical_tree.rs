use std::collections::{HashMap, HashSet};

use rusqlite::params;

use crate::{
    error::{ApiError, ApiResult},
    model::{DriveFile, FileTreeNode, FileTreeResponse},
};

use super::{
    attach_folder_sizes_locked, file_is_effectively_trashed_with_cache, row_to_file, Storage,
    MAX_FILE_TREE_NODES,
};

impl Storage {
    /// Build the canonical tree from a complete bounded workspace snapshot.
    /// Topology is validated before effective-Trash projection so malformed
    /// rows cannot be silently hidden from this integrity surface.
    pub fn file_tree(&self, workspace_id: &str) -> ApiResult<FileTreeResponse> {
        self.workspace_storage_mode(workspace_id)?;
        let query_limit = i64::try_from(MAX_FILE_TREE_NODES.saturating_add(1)).unwrap_or(i64::MAX);
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(
            "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                    content_hash, created_at, updated_at, content_bytes, cover_hash
             FROM files
             WHERE workspace_id = ?1
             ORDER BY updated_at DESC, id DESC
             LIMIT ?2",
        )?;
        let rows = statement.query_map(params![workspace_id, query_limit], row_to_file)?;
        let mut files = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        if files.len() > MAX_FILE_TREE_NODES {
            return Err(ApiError::PayloadTooLarge(format!(
                "workspace file tree exceeds the {MAX_FILE_TREE_NODES}-item limit"
            )));
        }
        validate_topology(&files)?;
        filter_effectively_visible_files(&conn, &mut files)?;
        attach_folder_sizes_locked(&conn, &mut files)?;
        let mut paths = crate::path_projection::project_file_paths(
            &files,
            None,
            crate::path_projection::MAX_FILE_TREE_PROJECTED_PATH_BYTES,
            "file tree",
        )?;
        let mut nodes = files
            .into_iter()
            .map(|file| {
                let path = paths.remove(&file.id).ok_or_else(|| {
                    ApiError::Validation("file tree path projection is incomplete".to_string())
                })?;
                Ok(FileTreeNode {
                    id: file.id,
                    workspace_id: file.workspace_id,
                    parent_id: file.parent_id,
                    name: file.name,
                    path,
                    kind: file.kind,
                    revision: file.revision,
                    trashed: file.trashed,
                    starred: file.starred,
                    updated_at: file.updated_at,
                    size_bytes: file.size_bytes,
                    folder_size_bytes: file.folder_size_bytes,
                    has_cover: file.has_cover,
                })
            })
            .collect::<ApiResult<Vec<_>>>()?;
        nodes.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(FileTreeResponse {
            workspace_id: workspace_id.to_string(),
            nodes,
        })
    }
}

fn validate_topology(files: &[DriveFile]) -> ApiResult<()> {
    let by_id = files
        .iter()
        .map(|file| (file.id.as_str(), file))
        .collect::<HashMap<_, _>>();
    for file in files {
        let mut current = file;
        let mut depth = 0usize;
        let mut seen = HashSet::new();
        loop {
            if !seen.insert(current.id.as_str()) {
                return Err(ApiError::Validation(
                    "file tree contains a parent cycle".to_string(),
                ));
            }
            let Some(parent_id) = current.parent_id.as_deref() else {
                break;
            };
            depth = depth.saturating_add(1);
            if depth > super::MAX_FILE_TREE_DEPTH {
                return Err(ApiError::Validation(format!(
                    "file tree exceeds the {}-level depth limit",
                    super::MAX_FILE_TREE_DEPTH
                )));
            }
            current = by_id.get(parent_id).copied().ok_or_else(|| {
                ApiError::Validation(
                    "file tree contains a missing or cross-workspace parent".to_string(),
                )
            })?;
        }
    }
    Ok(())
}

fn filter_effectively_visible_files(
    conn: &rusqlite::Connection,
    files: &mut Vec<DriveFile>,
) -> ApiResult<()> {
    let mut cache = HashMap::new();
    let mut visible = Vec::with_capacity(files.len());
    for file in files.drain(..) {
        if file.trashed || !file_is_effectively_trashed_with_cache(conn, &file.id, &mut cache)? {
            visible.push(file);
        }
    }
    *files = visible;
    Ok(())
}
