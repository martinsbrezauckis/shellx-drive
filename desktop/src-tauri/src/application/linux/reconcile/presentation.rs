//! Review construction and deterministic operation ordering.

use super::*;

pub(super) fn replacement_review(path: &Path, retained_batch: Option<&Path>) -> ReviewItem {
    let summary = retained_batch.map_or_else(
        || "Drive or local state changed before publication. The local destination was left untouched; the downloaded body was discarded and sync can retry after recheck.".to_string(),
        |batch| format!(
            "Drive downloaded and verified a newer body, but publication needs review. Inspect the local destination and the retained private recovery batch at {}.",
            batch.display()
        ),
    );
    ReviewItem {
        id: format!("linux-inbound-replacement:{}", path.display()),
        kind: ReviewKind::ContentConflict,
        relative_path: path.to_path_buf(),
        descendant_count: 0,
        is_directory: false,
        summary,
        actions: vec![ReviewAction::OpenConflictCopies],
    }
}

pub(super) fn move_review(
    path: &Path,
    summary: &str,
    is_directory: bool,
    descendant_count: usize,
) -> ReviewItem {
    ReviewItem {
        id: format!("linux-move-review:{}", path.display()),
        kind: ReviewKind::PathConflict,
        relative_path: path.to_path_buf(),
        descendant_count,
        is_directory,
        summary: summary.to_string(),
        actions: vec![
            ReviewAction::RenameLocalCopy,
            ReviewAction::OpenConflictCopies,
        ],
    }
}

pub(super) fn move_review_shape(
    folder: Option<&shellx_drive_desktop_core::FolderMovePrecondition>,
) -> (bool, usize) {
    folder.map_or((false, 0), |witness| {
        (true, witness.entries.len().saturating_sub(1))
    })
}

pub(crate) fn pair_guard(pair: &SyncPair) -> CoreResult<UnixRootGuard> {
    guard_pair(pair)
}

pub(super) fn remote_folder_ids(
    remote: &[RemoteEntry],
    selected_root: Option<&str>,
) -> CoreResult<HashMap<PathBuf, String>> {
    Ok(map_remote_paths(remote, selected_root)?
        .into_iter()
        .filter_map(|(id, path)| {
            remote
                .iter()
                .find(|entry| {
                    entry.id == id && !entry.trashed && entry.kind == RemoteEntryKind::Folder
                })
                .map(|entry| (path, entry.id.clone()))
        })
        .collect())
}

pub(super) fn remote_parent(
    folders: &HashMap<PathBuf, String>,
    pair: &SyncPair,
    path: &Path,
) -> CoreResult<Option<String>> {
    match path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        None => Ok(pair.remote_root_id.clone()),
        Some(parent) => folders.get(parent).cloned().map(Some).ok_or_else(|| {
            DesktopError::InvalidState(format!(
                "Drive parent folder is unavailable for {}",
                path.display()
            ))
        }),
    }
}

pub(super) fn leaf(path: &Path) -> CoreResult<&str> {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| DesktopError::UnsafePath("Drive path has no Unicode file name".to_string()))
}

pub(super) fn conflict_review(id: &str, path: &Path) -> ReviewItem {
    ReviewItem {
        id: format!("linux-replacement-conflict:{id}"),
        kind: ReviewKind::ContentConflict,
        relative_path: path.into(),
        descendant_count: 0,
        is_directory: false,
        summary: "Drive kept a newer version. The local replacement was left untouched for review."
            .to_string(),
        actions: vec![ReviewAction::OpenConflictCopies],
    }
}
pub(super) fn unsupported_review(id: &str, path: &Path, _: u64) -> ReviewItem {
    ReviewItem { id: format!("linux-replacement-unsupported:{id}"), kind: ReviewKind::UnsupportedTransfer, relative_path: path.into(), descendant_count: 0, is_directory: false, summary: "Drive does not support this safe replacement upload yet. Both copies were left untouched.".to_string(), actions: vec![ReviewAction::RetryWhenServerSupportsResumableReplacement] }
}
