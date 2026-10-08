use std::collections::{HashMap, HashSet};

use crate::{
    error::{ApiError, ApiResult},
    model::DriveFile,
    storage::MAX_FILE_TREE_DEPTH,
};

/// Keep all response and archive path materialization well below the service's
/// process-memory ceiling. This is shared with restore validation so a backup
/// cannot publish a tree that live readers would reject.
pub(crate) const MAX_FILE_TREE_PROJECTED_PATH_BYTES: usize = 4 * 1024 * 1024;

pub(crate) fn project_file_paths(
    files: &[DriveFile],
    excluded_root_id: Option<&str>,
    max_aggregate_bytes: usize,
    context: &str,
) -> ApiResult<HashMap<String, String>> {
    let by_id = files
        .iter()
        .map(|file| (file.id.as_str(), file))
        .collect::<HashMap<_, _>>();
    let mut paths = HashMap::with_capacity(files.len());
    let mut depths = HashMap::with_capacity(files.len());
    if let Some(root_id) = excluded_root_id {
        paths.insert(root_id.to_string(), String::new());
        depths.insert(root_id.to_string(), 0);
    }
    let mut visiting = HashSet::new();
    let mut aggregate_bytes = 0usize;
    for file in files {
        resolve_path(
            file,
            &by_id,
            excluded_root_id,
            max_aggregate_bytes,
            context,
            &mut aggregate_bytes,
            &mut paths,
            &mut depths,
            &mut visiting,
        )?;
    }
    Ok(paths)
}

#[allow(clippy::too_many_arguments)]
fn resolve_path(
    file: &DriveFile,
    by_id: &HashMap<&str, &DriveFile>,
    excluded_root_id: Option<&str>,
    max_aggregate_bytes: usize,
    context: &str,
    aggregate_bytes: &mut usize,
    paths: &mut HashMap<String, String>,
    depths: &mut HashMap<String, usize>,
    visiting: &mut HashSet<String>,
) -> ApiResult<()> {
    if paths.contains_key(&file.id) {
        return Ok(());
    }
    if !visiting.insert(file.id.clone()) {
        return Err(ApiError::Validation(format!(
            "{context} file tree contains a parent cycle"
        )));
    }
    if visiting.len() > MAX_FILE_TREE_DEPTH.saturating_add(1) {
        return Err(ApiError::Validation(format!(
            "{context} file tree exceeds the {MAX_FILE_TREE_DEPTH}-level depth limit"
        )));
    }
    if let Some(parent) = file
        .parent_id
        .as_deref()
        .filter(|parent_id| Some(*parent_id) != excluded_root_id)
        .and_then(|parent_id| by_id.get(parent_id).copied())
    {
        resolve_path(
            parent,
            by_id,
            excluded_root_id,
            max_aggregate_bytes,
            context,
            aggregate_bytes,
            paths,
            depths,
            visiting,
        )?;
    }
    let depth = file
        .parent_id
        .as_deref()
        .and_then(|parent_id| depths.get(parent_id))
        .copied()
        .map_or(0, |parent_depth| parent_depth.saturating_add(1));
    if depth > MAX_FILE_TREE_DEPTH {
        return Err(ApiError::Validation(format!(
            "{context} file tree exceeds the {MAX_FILE_TREE_DEPTH}-level depth limit"
        )));
    }
    let parent_path = file
        .parent_id
        .as_deref()
        .and_then(|parent_id| paths.get(parent_id));
    let separator_bytes = usize::from(parent_path.is_some_and(|path| !path.is_empty()));
    let path_bytes = parent_path
        .map(String::len)
        .unwrap_or(0)
        .checked_add(separator_bytes)
        .and_then(|bytes| bytes.checked_add(file.name.len()))
        .ok_or_else(|| {
            ApiError::PayloadTooLarge(format!("{context} path metadata size overflow"))
        })?;
    let projected = aggregate_bytes.checked_add(path_bytes).ok_or_else(|| {
        ApiError::PayloadTooLarge(format!("{context} path metadata size overflow"))
    })?;
    if projected > max_aggregate_bytes {
        return Err(ApiError::PayloadTooLarge(format!(
            "{context} path metadata exceeds its {max_aggregate_bytes}-byte aggregate limit"
        )));
    }
    let mut path = String::with_capacity(path_bytes);
    if let Some(parent_path) = parent_path.filter(|path| !path.is_empty()) {
        path.push_str(parent_path);
        path.push('/');
    }
    path.push_str(&file.name);
    paths.insert(file.id.clone(), path);
    depths.insert(file.id.clone(), depth);
    *aggregate_bytes = projected;
    visiting.remove(&file.id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::FileKind;

    fn file(id: &str, parent_id: Option<&str>, name: &str) -> DriveFile {
        DriveFile {
            id: id.to_string(),
            workspace_id: "workspace".to_string(),
            parent_id: parent_id.map(str::to_string),
            name: name.to_string(),
            kind: FileKind::Folder,
            revision: 1,
            trashed: false,
            starred: false,
            content_hash: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            size_bytes: None,
            folder_size_bytes: None,
            has_cover: false,
        }
    }

    #[test]
    fn memoized_projection_enforces_aggregate_path_bytes() {
        let files = vec![
            file("root", None, "root"),
            file("child", Some("root"), "child"),
            file("leaf", Some("child"), "leaf"),
        ];
        let paths = project_file_paths(&files, Some("root"), 20, "share").unwrap();
        assert_eq!(paths["child"], "child");
        assert_eq!(paths["leaf"], "child/leaf");
        assert!(matches!(
            project_file_paths(&files, Some("root"), 10, "share"),
            Err(ApiError::PayloadTooLarge(_))
        ));
    }

    #[test]
    fn memoized_projection_rejects_overdeep_input_before_unbounded_recursion() {
        let mut files = Vec::new();
        let mut parent_id: Option<String> = None;
        for depth in 0..=MAX_FILE_TREE_DEPTH + 1 {
            let id = format!("node-{depth}");
            files.push(file(&id, parent_id.as_deref(), "node"));
            parent_id = Some(id);
        }
        files.reverse();

        let error = project_file_paths(&files, None, MAX_FILE_TREE_PROJECTED_PATH_BYTES, "test")
            .unwrap_err();
        assert!(error.to_string().contains("depth limit"));
    }
}
