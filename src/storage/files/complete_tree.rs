//! Linear folder aggregation for callers that already own the complete live
//! workspace tree.

use std::collections::{HashMap, VecDeque};

use crate::{
    error::{ApiError, ApiResult},
    model::{DriveFile, FileKind},
};

/// Attach recursive folder sizes to a complete, already-bounded workspace
/// tree without issuing a file-by-ancestor recursive query. Sync manifests
/// select the complete effectively-live tree before calling this helper, so a
/// bottom-up pass visits each selected row and parent edge once. This keeps a
/// legal wide/deep workspace from amplifying work while the sole SQLite mutex
/// is held.
///
/// The caller must provide every live parent of every selected row. Treat a
/// missing parent, cross-workspace parent, non-folder parent, cycle, or size
/// overflow as corrupt metadata rather than silently publishing an incorrect
/// aggregate.
pub(in crate::storage) fn attach_folder_sizes_complete_tree(
    files: &mut [DriveFile],
) -> ApiResult<()> {
    if files.is_empty() {
        return Ok(());
    }

    let mut indexes = HashMap::with_capacity(files.len());
    for (index, file) in files.iter().enumerate() {
        if indexes.insert(file.id.as_str(), index).is_some() {
            return Err(ApiError::Validation(
                "sync manifest contains duplicate file identifiers".to_string(),
            ));
        }
    }

    let mut parents = vec![None; files.len()];
    let mut remaining_children = vec![0_usize; files.len()];
    let mut totals = vec![0_i64; files.len()];
    for (index, file) in files.iter().enumerate() {
        totals[index] = if matches!(file.kind, FileKind::File) {
            file.size_bytes.ok_or_else(|| {
                ApiError::Validation("sync manifest file has no stored size".to_string())
            })?
        } else {
            0
        };
        if let Some(parent_id) = file.parent_id.as_deref() {
            let parent = indexes.get(parent_id).copied().ok_or_else(|| {
                ApiError::Validation("sync manifest is missing a live parent".to_string())
            })?;
            let parent_file = &files[parent];
            if parent_file.workspace_id != file.workspace_id
                || !matches!(parent_file.kind, FileKind::Folder)
            {
                return Err(ApiError::Validation(
                    "sync manifest has an invalid parent relation".to_string(),
                ));
            }
            parents[index] = Some(parent);
            remaining_children[parent] =
                remaining_children[parent].checked_add(1).ok_or_else(|| {
                    ApiError::Validation("sync manifest child count overflow".to_string())
                })?;
        }
    }

    let mut ready = remaining_children
        .iter()
        .enumerate()
        .filter_map(|(index, children)| (*children == 0).then_some(index))
        .collect::<VecDeque<_>>();
    let mut visited = 0_usize;
    while let Some(index) = ready.pop_front() {
        visited += 1;
        if matches!(files[index].kind, FileKind::Folder) {
            files[index].folder_size_bytes = Some(totals[index]);
        }
        if let Some(parent) = parents[index] {
            totals[parent] = totals[parent].checked_add(totals[index]).ok_or_else(|| {
                ApiError::Validation("sync manifest folder size overflow".to_string())
            })?;
            remaining_children[parent] = remaining_children[parent]
                .checked_sub(1)
                .expect("child accounting is balanced");
            if remaining_children[parent] == 0 {
                ready.push_back(parent);
            }
        }
    }
    if visited != files.len() {
        return Err(ApiError::Validation(
            "sync manifest contains a parent cycle".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(
        id: usize,
        parent_id: Option<String>,
        kind: FileKind,
        size_bytes: Option<i64>,
    ) -> DriveFile {
        DriveFile {
            id: format!("node-{id}"),
            workspace_id: "workspace".to_string(),
            parent_id,
            name: format!("node-{id}"),
            kind,
            revision: 1,
            trashed: false,
            starred: false,
            content_hash: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            size_bytes,
            folder_size_bytes: None,
            has_cover: false,
        }
    }

    #[test]
    fn aggregation_is_correct_for_a_bounded_wide_and_deep_tree() {
        let mut files = Vec::with_capacity(10_000);
        files.push(node(0, None, FileKind::Folder, None));
        // A 256-level branch exercises the former depth multiplier; the
        // remaining legal nodes make the root fan-out reach the tree limit.
        for index in 1..=255 {
            files.push(node(
                index,
                Some(format!("node-{}", index - 1)),
                FileKind::Folder,
                None,
            ));
        }
        files.push(node(
            256,
            Some("node-255".to_string()),
            FileKind::File,
            Some(7),
        ));
        for index in 257..10_000 {
            files.push(node(
                index,
                Some("node-0".to_string()),
                FileKind::File,
                Some(1),
            ));
        }

        attach_folder_sizes_complete_tree(&mut files).unwrap();

        assert_eq!(files[0].folder_size_bytes, Some(9_750));
        assert_eq!(files[255].folder_size_bytes, Some(7));
        assert_eq!(files[1].folder_size_bytes, Some(7));
    }
}
