use std::collections::{HashMap, HashSet};

use crate::{
    error::{ApiError, ApiResult},
    model::{DriveFile, FileKind},
};

use super::{Storage, MAX_FILE_TREE_DEPTH};

impl Storage {
    pub fn folder_zip_entries(&self, folder_id: &str) -> ApiResult<Vec<(String, String)>> {
        let folder = self
            .get_file_unaggregated(folder_id)?
            .ok_or(ApiError::NotFound)?;
        if !matches!(folder.kind, FileKind::Folder) {
            return Err(ApiError::Validation("file must be a folder".to_string()));
        }
        let all = self
            .descendants_inclusive(folder_id)?
            .into_iter()
            .filter(|file| !file.trashed)
            .collect::<Vec<_>>();
        let mut paths = crate::path_projection::project_file_paths(
            &all,
            None,
            crate::path_projection::MAX_FILE_TREE_PROJECTED_PATH_BYTES,
            "folder archive",
        )?;
        let mut entries = all
            .into_iter()
            .filter(|file| matches!(file.kind, FileKind::File))
            .filter_map(|file| file.content_hash.clone().map(|hash| (file, hash)))
            .map(|(file, hash)| {
                let path = paths.remove(&file.id).ok_or_else(|| {
                    ApiError::Validation("folder archive path projection is incomplete".to_string())
                })?;
                Ok((path, hash))
            })
            .collect::<ApiResult<Vec<_>>>()?;
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(entries)
    }

    /// Resolve same-level authenticated selections into archive-relative nodes.
    /// Folder selections expand recursively; file selections remain single
    /// entries. Requiring one workspace and parent matches the Drive browser's
    /// visible-row selection model and prevents ambiguous duplicate ZIP roots.
    pub(crate) fn bulk_archive_nodes(
        &self,
        file_ids: &[String],
    ) -> ApiResult<Vec<(String, DriveFile)>> {
        if file_ids.is_empty() {
            return Err(ApiError::Validation(
                "select at least one item to download".to_string(),
            ));
        }
        let mut unique_ids = HashSet::with_capacity(file_ids.len());
        let mut roots = Vec::with_capacity(file_ids.len());
        for file_id in file_ids {
            if !unique_ids.insert(file_id.as_str()) {
                continue;
            }
            roots.push(
                self.get_file_unaggregated(file_id)?
                    .ok_or(ApiError::NotFound)?,
            );
        }
        let selected_ids = roots
            .iter()
            .map(|root| root.id.clone())
            .collect::<HashSet<_>>();
        let mut canonical_roots = Vec::with_capacity(roots.len());
        for root in roots {
            let mut parent_id = root.parent_id.clone();
            let mut depth = 0usize;
            let mut covered_by_selected_folder = false;
            while let Some(current_parent_id) = parent_id {
                if selected_ids.contains(current_parent_id.as_str()) {
                    covered_by_selected_folder = true;
                    break;
                }
                if depth >= MAX_FILE_TREE_DEPTH {
                    return Err(ApiError::Validation(
                        "bulk archive selection exceeds the file-tree depth limit".to_string(),
                    ));
                }
                parent_id = self
                    .get_file_unaggregated(&current_parent_id)?
                    .and_then(|parent| parent.parent_id);
                depth += 1;
            }
            if !covered_by_selected_folder {
                canonical_roots.push(root);
            }
        }
        let first = canonical_roots.first().ok_or_else(|| {
            ApiError::Validation("select at least one item to download".to_string())
        })?;
        if canonical_roots.iter().any(|root| {
            root.workspace_id != first.workspace_id || root.parent_id != first.parent_id
        }) {
            return Err(ApiError::Validation(
                "download selections must come from the same folder".to_string(),
            ));
        }
        if canonical_roots
            .iter()
            .any(|root| root.trashed != first.trashed)
        {
            return Err(ApiError::Validation(
                "download selections must come from the same Drive view".to_string(),
            ));
        }

        let mut expanded = Vec::new();
        for root in canonical_roots {
            let descendants = if matches!(root.kind, FileKind::Folder) {
                self.descendants_inclusive(&root.id)?
                    .into_iter()
                    .filter(|file| file.trashed == root.trashed)
                    .collect()
            } else {
                vec![root.clone()]
            };
            expanded.extend(descendants);
        }
        let mut paths = crate::path_projection::project_file_paths(
            &expanded,
            None,
            crate::path_projection::MAX_FILE_TREE_PROJECTED_PATH_BYTES,
            "bulk archive",
        )?;
        let mut nodes = Vec::with_capacity(expanded.len());
        let mut archive_paths = HashSet::new();
        for file in expanded {
            let path = paths.remove(&file.id).ok_or_else(|| {
                ApiError::Validation("bulk archive path projection is incomplete".to_string())
            })?;
            if !archive_paths.insert(path.clone()) {
                return Err(ApiError::Validation(
                    "download selection contains duplicate archive paths".to_string(),
                ));
            }
            nodes.push((path, file));
        }
        nodes.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(nodes)
    }

    /// Resolve a public folder's selected direct children into archive-relative
    /// nodes. The current folder is supplied as `base_path`; every selection
    /// must be a direct child of it, while selected folders expand recursively.
    /// All lookup is performed against the already capability-scoped subtree.
    pub(crate) fn share_archive_nodes(
        &self,
        folder_id: &str,
        base_path: &str,
        selected_paths: &[String],
    ) -> ApiResult<Vec<(String, DriveFile)>> {
        if selected_paths.is_empty() {
            return Err(ApiError::Validation(
                "select at least one item to download".to_string(),
            ));
        }
        validate_share_archive_path(base_path, true)?;
        let folder = self
            .get_file_unaggregated(folder_id)?
            .ok_or(ApiError::NotFound)?;
        let subtree = self.share_subtree(&folder)?;
        let by_path = subtree
            .iter()
            .map(|(path, file)| (path.as_str(), file))
            .collect::<HashMap<_, _>>();
        if !base_path.is_empty()
            && !matches!(
                by_path.get(base_path).map(|file| &file.kind),
                Some(FileKind::Folder)
            )
        {
            return Err(ApiError::NotFound);
        }

        let mut selections = HashSet::with_capacity(selected_paths.len());
        let mut selected_folders = Vec::new();
        for path in selected_paths {
            validate_share_archive_path(path, false)?;
            if share_path_parent(path) != base_path {
                return Err(ApiError::Validation(
                    "download selections must be visible in the current folder".to_string(),
                ));
            }
            let file = by_path.get(path.as_str()).ok_or(ApiError::NotFound)?;
            if selections.insert(path.as_str()) && matches!(file.kind, FileKind::Folder) {
                selected_folders.push(format!("{path}/"));
            }
        }

        let base_prefix = if base_path.is_empty() {
            String::new()
        } else {
            format!("{base_path}/")
        };
        let mut nodes = subtree
            .into_iter()
            .filter(|(path, _)| {
                selections.contains(path.as_str())
                    || selected_folders
                        .iter()
                        .any(|prefix| path.starts_with(prefix))
            })
            .map(|(path, file)| {
                let archive_path = path
                    .strip_prefix(&base_prefix)
                    .unwrap_or(path.as_str())
                    .to_string();
                (archive_path, file)
            })
            .collect::<Vec<_>>();
        nodes.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(nodes)
    }
}

fn validate_share_archive_path(path: &str, allow_empty: bool) -> ApiResult<()> {
    if allow_empty && path.is_empty() {
        return Ok(());
    }
    if path.is_empty()
        || path != path.trim()
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(ApiError::NotFound);
    }
    Ok(())
}

fn share_path_parent(path: &str) -> &str {
    path.rsplit_once('/')
        .map(|(parent, _)| parent)
        .unwrap_or("")
}
