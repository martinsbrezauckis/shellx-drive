use std::collections::{HashMap, HashSet};

use rusqlite::{params, params_from_iter, types::Value as SqlValue, OptionalExtension};

use crate::{
    auth::Actor,
    error::{ApiError, ApiResult},
    model::{DriveFile, FileKind},
};

mod canonical_tree;
mod workspace_usage;

pub(super) use workspace_usage::workspace_usage_buckets;

/// Enforce the single workspace-wide metadata ceiling used by tree readers.
/// Count every row, including trash, because trash remains addressable and is
/// deliberately returned by the canonical tree surface.
pub(crate) fn ensure_workspace_node_capacity(
    conn: &rusqlite::Connection,
    workspace_id: &str,
    additional_nodes: usize,
) -> ApiResult<()> {
    let existing: i64 = conn.query_row(
        "SELECT COUNT(*) FROM files WHERE workspace_id = ?1",
        params![workspace_id],
        |row| row.get(0),
    )?;
    let additional = i64::try_from(additional_nodes)
        .map_err(|_| ApiError::PayloadTooLarge("workspace node count overflow".to_string()))?;
    if existing.saturating_add(additional) > MAX_FILE_TREE_NODES as i64 {
        return Err(ApiError::PayloadTooLarge(format!(
            "workspace file tree would exceed the {MAX_FILE_TREE_NODES}-item limit"
        )));
    }
    Ok(())
}

use super::{
    actor_scope::actor_workspace_scope, files::attach_folder_sizes_locked, row_to_file, Storage,
    MAX_FILE_TREE_DEPTH, MAX_FILE_TREE_NODES,
};

/// Resolve destructive subtree membership inside the caller's transaction.
/// The recursive term carries the root workspace and will never cross it. The
/// final `MAX + 1` row is a SQL-side sentinel, so corrupt or oversized trees
/// cannot be fully materialized before the application notices the limit.
pub(super) fn recursive_file_ids_in_tx(
    tx: &rusqlite::Transaction<'_>,
    roots: &[String],
) -> ApiResult<Vec<String>> {
    if roots.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = std::iter::repeat_n("?", roots.len())
        .collect::<Vec<_>>()
        .join(", ");
    let sentinel = MAX_FILE_TREE_NODES.saturating_add(1);
    let sql = format!(
        "WITH RECURSIVE subtree(id, workspace_id) AS (
             SELECT id, workspace_id FROM files WHERE id IN ({placeholders})
             UNION
             SELECT child.id, subtree.workspace_id
             FROM files child INDEXED BY idx_files_workspace_parent
             JOIN subtree
               ON child.parent_id = subtree.id
              AND child.workspace_id = subtree.workspace_id
         )
         SELECT id FROM subtree LIMIT {sentinel}"
    );
    let mut statement = tx.prepare(&sql)?;
    let rows = statement.query_map(params_from_iter(roots.iter()), |row| row.get(0))?;
    let ids = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    if ids.len() > MAX_FILE_TREE_NODES {
        return Err(ApiError::Validation(format!(
            "file tree exceeds the {MAX_FILE_TREE_NODES}-item limit"
        )));
    }
    Ok(ids)
}

impl Storage {
    pub fn list_workspace_files_bounded(
        &self,
        workspace_id: &str,
        max_rows: usize,
        include_trashed: bool,
    ) -> ApiResult<Vec<DriveFile>> {
        let query_limit = i64::try_from(max_rows.saturating_add(1)).unwrap_or(i64::MAX);
        let active_predicate = if include_trashed {
            ""
        } else {
            " AND trashed = 0"
        };
        let effective_visibility = effectively_visible_sql_predicate("files", include_trashed);
        let conn = self.conn.lock().unwrap();
        let sql = format!(
            "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                    content_hash, created_at, updated_at, content_bytes, cover_hash
             FROM files
             WHERE workspace_id = ?1{active_predicate}
               AND {effective_visibility}
             ORDER BY updated_at DESC, id DESC
             LIMIT ?2"
        );
        let mut statement = conn.prepare(&sql)?;
        let rows = statement.query_map(params![workspace_id, query_limit], row_to_file)?;
        let mut files = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        if files.len() > max_rows {
            return Err(ApiError::PayloadTooLarge(format!(
                "workspace file tree exceeds the {max_rows}-item limit"
            )));
        }
        attach_folder_sizes_locked(&conn, &mut files)?;
        Ok(files)
    }

    /// Fetch one row without the recursive folder aggregate used by the normal
    /// metadata endpoint. Capability and traversal code calls this before a
    /// purpose-built bounded subtree query so a single lookup cannot scan the
    /// entire workspace.
    pub(crate) fn get_file_unaggregated(&self, file_id: &str) -> ApiResult<Option<DriveFile>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                    content_hash, created_at, updated_at, content_bytes, cover_hash
             FROM files WHERE id = ?1",
            params![file_id],
            row_to_file,
        )
        .optional()
        .map_err(ApiError::from)
    }

    /// A node inside a trashed folder is not publicly live even when its own
    /// legacy row still has `trashed = 0`. Walk one bounded parent chain and
    /// fail closed on cycles or excessive depth.
    pub(crate) fn file_is_effectively_trashed(&self, file_id: &str) -> ApiResult<bool> {
        let conn = self.conn.lock().unwrap();
        file_is_effectively_trashed_locked(&conn, file_id)
    }

    /// Require that a file is live through its complete parent chain.  Normal
    /// trash mutations mark the whole subtree, but imported or otherwise
    /// legacy rows can still carry an active flag beneath a trashed ancestor.
    pub(crate) fn ensure_file_effectively_live(&self, file_id: &str) -> ApiResult<()> {
        if self.file_is_effectively_trashed(file_id)? {
            return Err(ApiError::NotFound);
        }
        Ok(())
    }

    pub(crate) fn get_active_child_file_by_name(
        &self,
        workspace_id: &str,
        parent_id: Option<&str>,
        name: &str,
    ) -> ApiResult<Option<DriveFile>> {
        let conn = self.conn.lock().unwrap();
        get_active_child_file_by_name_locked(&conn, workspace_id, parent_id, name)
    }
}

/// Callers that publish a child type must authorize the parent in the same
/// transaction before selecting the child row.
pub(crate) fn get_active_child_file_by_name_locked(
    conn: &rusqlite::Connection,
    workspace_id: &str,
    parent_id: Option<&str>,
    name: &str,
) -> ApiResult<Option<DriveFile>> {
    let mut statement = if parent_id.is_some() {
        conn.prepare(
            "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                        content_hash, created_at, updated_at, content_bytes, cover_hash
                 FROM files
                 WHERE workspace_id = ?1 AND parent_id = ?2 AND name = ?3 AND trashed = 0
                 ORDER BY id ASC LIMIT 2",
        )?
    } else {
        conn.prepare(
            "SELECT id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                        content_hash, created_at, updated_at, content_bytes, cover_hash
                 FROM files
                 WHERE workspace_id = ?1 AND parent_id IS NULL AND name = ?2 AND trashed = 0
                 ORDER BY id ASC LIMIT 2",
        )?
    };
    let files = if let Some(parent_id) = parent_id {
        statement
            .query_map(params![workspace_id, parent_id, name], row_to_file)?
            .collect::<rusqlite::Result<Vec<_>>>()?
    } else {
        statement
            .query_map(params![workspace_id, name], row_to_file)?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    match files.as_slice() {
        [] => Ok(None),
        [file] => Ok(Some(file.clone())),
        _ => Err(ApiError::Conflict),
    }
}

impl Storage {
    /// Compatibility list endpoints predate cursor pagination. Preserve their
    /// response shape, but scope visibility in SQL and reject a result that
    /// exceeds a fixed sentinel limit before folder aggregation or JSON.
    pub fn list_files_for_actor_bounded(
        &self,
        actor: &Actor,
        max_rows: usize,
        include_trashed: bool,
    ) -> ApiResult<Vec<DriveFile>> {
        let Some(scope) = actor_workspace_scope(actor) else {
            return Ok(Vec::new());
        };
        let mut parameters = scope.parameters;

        let limit_parameter = scope.next_parameter;
        parameters.push(SqlValue::Integer(
            i64::try_from(max_rows.saturating_add(1)).unwrap_or(i64::MAX),
        ));
        let active_predicate = if include_trashed {
            ""
        } else {
            " AND f.trashed = 0"
        };
        let effective_visibility = effectively_visible_sql_predicate("f", include_trashed);
        let sql = format!(
            "WITH visible_workspaces AS ({})
             SELECT f.id, f.workspace_id, f.parent_id, f.name, f.kind, f.revision,
                    f.trashed, f.starred, f.content_hash, f.created_at, f.updated_at,
                    f.content_bytes, f.cover_hash
             FROM files f
             JOIN visible_workspaces vw ON vw.id = f.workspace_id
             WHERE 1 = 1{active_predicate}
               AND {effective_visibility}
             ORDER BY f.updated_at DESC, f.id DESC
             LIMIT ?{limit_parameter}",
            scope.sql
        );

        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(&sql)?;
        let rows = statement.query_map(params_from_iter(parameters.iter()), row_to_file)?;
        let mut files = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        if files.len() > max_rows {
            return Err(ApiError::PayloadTooLarge(format!(
                "file listing exceeds the {max_rows}-item compatibility limit; use the paginated browser API"
            )));
        }
        attach_folder_sizes_locked(&conn, &mut files)?;
        Ok(files)
    }

    pub(super) fn active_descendants_inclusive_bounded(
        &self,
        file_id: &str,
    ) -> ApiResult<Vec<DriveFile>> {
        self.descendants_inclusive_bounded(file_id, true)
    }

    pub(super) fn descendants_inclusive_bounded(
        &self,
        file_id: &str,
        active_only: bool,
    ) -> ApiResult<Vec<DriveFile>> {
        let active_root = if active_only { " AND trashed = 0" } else { "" };
        let active_child = if active_only {
            " AND child.trashed = 0"
        } else {
            ""
        };
        let max_depth = i64::try_from(MAX_FILE_TREE_DEPTH.saturating_add(1)).unwrap_or(i64::MAX);
        let max_nodes = i64::try_from(MAX_FILE_TREE_NODES.saturating_add(1)).unwrap_or(i64::MAX);
        let sql = format!(
            "WITH RECURSIVE tree(id, workspace_id, depth) AS (
                 SELECT id, workspace_id, 0
                 FROM files WHERE id = ?1{active_root}
                 UNION ALL
                 SELECT child.id, child.workspace_id, tree.depth + 1
                 FROM files child INDEXED BY idx_files_workspace_parent
                 JOIN tree ON child.parent_id = tree.id
                 WHERE child.workspace_id = tree.workspace_id{active_child}
                   AND tree.depth < ?2
                 LIMIT ?3
             )
             SELECT files.id, files.workspace_id, files.parent_id, files.name, files.kind,
                    files.revision, files.trashed, files.starred, files.content_hash,
                    files.created_at, files.updated_at, files.content_bytes, files.cover_hash,
                    tree.depth
             FROM tree JOIN files ON files.id = tree.id"
        );
        let conn = self.conn.lock().unwrap();
        let mut statement = conn.prepare(&sql)?;
        let rows = statement.query_map(params![file_id, max_depth, max_nodes], |row| {
            Ok((row_to_file(row)?, row.get::<_, i64>(13)?))
        })?;
        let rows = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        if rows.is_empty() {
            return Err(ApiError::NotFound);
        }
        let mut visited = HashSet::with_capacity(rows.len());
        if rows.iter().any(|(file, _)| !visited.insert(&file.id)) {
            return Err(ApiError::Validation(
                "file tree contains a parent cycle".to_string(),
            ));
        }
        if rows.len() > MAX_FILE_TREE_NODES {
            return Err(ApiError::Validation(format!(
                "file tree exceeds the {MAX_FILE_TREE_NODES}-item limit"
            )));
        }
        if rows
            .iter()
            .any(|(_, depth)| *depth > MAX_FILE_TREE_DEPTH as i64)
        {
            return Err(ApiError::Validation(format!(
                "file tree exceeds the {MAX_FILE_TREE_DEPTH}-level depth limit"
            )));
        }

        let mut files = rows.into_iter().map(|(file, _)| file).collect::<Vec<_>>();
        attach_subtree_folder_sizes(&mut files)?;
        Ok(files)
    }
}

pub(super) fn file_is_effectively_trashed_locked(
    conn: &rusqlite::Connection,
    file_id: &str,
) -> ApiResult<bool> {
    file_is_effectively_trashed_with_cache(conn, file_id, &mut HashMap::new())
}

/// Return a SQL predicate that admits only a file whose entire parent chain is
/// live.  Every recursive step is bounded, and malformed chains (a cycle, a
/// missing or cross-workspace parent, or a chain deeper than the supported
/// tree depth) are treated as non-live. Applying this predicate before
/// `ORDER BY ... LIMIT` keeps hidden legacy descendants from consuming a list
/// sentinel or browse page while avoiding an unbounded post-query scan.
///
/// `file_alias` is an internal, static query alias supplied by storage code;
/// it is never derived from request data.
pub(super) fn effectively_live_sql_predicate(file_alias: &str) -> String {
    format!(
        r#"NOT EXISTS (
             WITH RECURSIVE effective_ancestors(id, workspace_id, parent_id, trashed, depth) AS (
                 SELECT {file_alias}.id, {file_alias}.workspace_id, {file_alias}.parent_id,
                        {file_alias}.trashed, 0
                 UNION ALL
                 SELECT ancestor.id, effective_ancestors.workspace_id, ancestor.parent_id,
                        ancestor.trashed, effective_ancestors.depth + 1
                 FROM effective_ancestors
                 JOIN files ancestor
                   ON ancestor.id = effective_ancestors.parent_id
                  AND ancestor.workspace_id = effective_ancestors.workspace_id
                 WHERE effective_ancestors.depth < {MAX_FILE_TREE_DEPTH}
             )
             SELECT 1
             FROM effective_ancestors
             WHERE effective_ancestors.trashed != 0
                OR (effective_ancestors.depth = {MAX_FILE_TREE_DEPTH}
                    AND effective_ancestors.parent_id IS NOT NULL)
                OR (effective_ancestors.parent_id IS NOT NULL
                    AND NOT EXISTS (
                        SELECT 1 FROM files missing_parent
                        WHERE missing_parent.id = effective_ancestors.parent_id
                          AND missing_parent.workspace_id = effective_ancestors.workspace_id
                    ))
         )"#
    )
}

/// The canonical tree includes direct trash rows for the Trash UI, but a
/// directly-active row below a trashed ancestor must remain hidden.
pub(super) fn effectively_visible_sql_predicate(file_alias: &str, include_trashed: bool) -> String {
    let live = effectively_live_sql_predicate(file_alias);
    if include_trashed {
        format!("({file_alias}.trashed != 0 OR {live})")
    } else {
        live
    }
}

/// Filter a set of directly-active file ids without loading their full rows.
/// Mobile offline selections use this so a legacy descendant cannot remain a
/// valid content capability after an ancestor was moved to Trash.
pub(super) fn retain_effectively_live_file_ids_locked(
    conn: &rusqlite::Connection,
    file_ids: &mut HashSet<String>,
) -> ApiResult<()> {
    let mut cache = HashMap::new();
    let mut live = HashSet::with_capacity(file_ids.len());
    for file_id in file_ids.drain() {
        if !file_is_effectively_trashed_with_cache(conn, &file_id, &mut cache)? {
            live.insert(file_id);
        }
    }
    *file_ids = live;
    Ok(())
}

pub(super) fn file_is_effectively_trashed_with_cache(
    conn: &rusqlite::Connection,
    file_id: &str,
    cache: &mut HashMap<(String, String), bool>,
) -> ApiResult<bool> {
    let mut current = Some(file_id.to_string());
    let mut root_workspace_id: Option<String> = None;
    let mut seen = HashSet::new();
    let mut traversed = Vec::new();
    for _ in 0..=MAX_FILE_TREE_DEPTH {
        let Some(id) = current.take() else {
            let root_workspace_id = root_workspace_id
                .as_deref()
                .expect("an empty parent chain must start with a file row");
            for traversed_id in traversed {
                cache.insert((root_workspace_id.to_string(), traversed_id), false);
            }
            return Ok(false);
        };
        if !seen.insert(id.clone()) {
            return Err(ApiError::Validation(
                "file tree contains a parent cycle".to_string(),
            ));
        }
        let row = if let Some(root_workspace_id) = root_workspace_id.as_deref() {
            if let Some(trashed) = cache
                .get(&(root_workspace_id.to_string(), id.clone()))
                .copied()
            {
                for traversed_id in traversed {
                    cache.insert((root_workspace_id.to_string(), traversed_id), trashed);
                }
                return Ok(trashed);
            }
            conn.query_row(
                "SELECT workspace_id, parent_id, trashed
                 FROM files WHERE id = ?1 AND workspace_id = ?2",
                params![&id, root_workspace_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?
        } else {
            conn.query_row(
                "SELECT workspace_id, parent_id, trashed FROM files WHERE id = ?1",
                params![&id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?
        };
        let Some(row) = row else {
            if let Some(root_workspace_id) = root_workspace_id.as_deref() {
                for traversed_id in traversed {
                    cache.insert((root_workspace_id.to_string(), traversed_id), true);
                }
                return Ok(true);
            }
            return Err(ApiError::NotFound);
        };
        if root_workspace_id.is_none() {
            root_workspace_id = Some(row.0);
        } else {
            debug_assert_eq!(root_workspace_id.as_deref(), Some(row.0.as_str()));
        }
        traversed.push(id);
        if row.2 != 0 {
            let root_workspace_id = root_workspace_id
                .as_deref()
                .expect("a resolved file row has a workspace");
            for traversed_id in traversed {
                cache.insert((root_workspace_id.to_string(), traversed_id), true);
            }
            return Ok(true);
        }
        current = row.1;
        if current.is_none() {
            let workspace_id = root_workspace_id
                .as_deref()
                .expect("a resolved file row has a workspace");
            for traversed_id in traversed {
                cache.insert((workspace_id.to_string(), traversed_id), false);
            }
            return Ok(false);
        }
    }
    Err(ApiError::Validation(format!(
        "file tree exceeds the {MAX_FILE_TREE_DEPTH}-level depth limit"
    )))
}

fn attach_subtree_folder_sizes(files: &mut [DriveFile]) -> ApiResult<()> {
    let by_id = files
        .iter()
        .enumerate()
        .map(|(index, file)| (file.id.clone(), index))
        .collect::<HashMap<_, _>>();
    let mut sizes = HashMap::<String, i64>::new();
    for file in files.iter().filter(|file| {
        matches!(file.kind, FileKind::File) && !file.trashed && file.size_bytes.is_some()
    }) {
        let bytes = file.size_bytes.unwrap_or(0);
        let mut parent_id = file.parent_id.as_deref();
        let mut visited = HashSet::new();
        while let Some(id) = parent_id {
            if !visited.insert(id) {
                return Err(ApiError::Validation(
                    "file tree contains a parent cycle".to_string(),
                ));
            }
            let Some(parent_index) = by_id.get(id).copied() else {
                break;
            };
            let parent = &files[parent_index];
            let size = sizes.entry(parent.id.clone()).or_default();
            *size = size.checked_add(bytes).ok_or_else(|| {
                ApiError::Validation("folder size exceeds the supported range".to_string())
            })?;
            parent_id = parent.parent_id.as_deref();
        }
    }
    for file in files {
        file.folder_size_bytes = matches!(file.kind, FileKind::Folder)
            .then(|| sizes.get(&file.id).copied().unwrap_or(0));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    mod canonical_tree;

    use super::*;
    use crate::model::CreateFileRequest;

    fn create_node(
        storage: &Storage,
        workspace_id: &str,
        parent_id: Option<String>,
        name: &str,
        kind: FileKind,
    ) -> DriveFile {
        storage
            .create_file(
                CreateFileRequest {
                    workspace_id: workspace_id.to_string(),
                    parent_id,
                    name: name.to_string(),
                    kind,
                    content: None,
                    path: None,
                },
                None,
            )
            .unwrap()
            .0
    }

    #[test]
    fn destructive_recursion_never_crosses_a_workspace_parent_edge() {
        let root = tempfile::tempdir().unwrap();
        let storage = Storage::open(root.path().join("drive.db")).unwrap();
        storage.migrate().unwrap();
        let (first, _, _) = storage
            .create_workspace("First", "owner@example.test")
            .unwrap();
        let (second, _, _) = storage
            .create_workspace("Second", "owner@example.test")
            .unwrap();
        let first_root = create_node(&storage, &first.id, None, "root", FileKind::Folder);
        let foreign_child = create_node(&storage, &second.id, None, "foreign", FileKind::File);
        storage
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE files SET parent_id = ?1 WHERE id = ?2",
                params![&first_root.id, &foreign_child.id],
            )
            .unwrap();

        storage
            .permanently_delete_file(&first_root.id, "system")
            .unwrap();
        let conn = storage.conn.lock().unwrap();
        let foreign_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM files WHERE id = ?1 AND workspace_id = ?2",
                params![&foreign_child.id, &second.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(foreign_count, 1);
    }

    #[test]
    fn file_tree_rejects_excessive_aggregate_projected_paths() {
        let root = tempfile::tempdir().unwrap();
        let storage = Storage::open(root.path().join("drive.db")).unwrap();
        storage.migrate().unwrap();
        let (workspace, _, _) = storage
            .create_workspace("Large paths", "owner@example.test")
            .unwrap();
        let mut parent_id = None;
        let name = "x".repeat(255);
        for _ in 0..MAX_FILE_TREE_DEPTH {
            parent_id =
                Some(create_node(&storage, &workspace.id, parent_id, &name, FileKind::Folder).id);
        }

        let error = storage.file_tree(&workspace.id).unwrap_err();
        assert!(matches!(error, ApiError::PayloadTooLarge(_)));
        assert!(error.to_string().contains("aggregate limit"));
    }
}
