//! Fail-closed inbound and outbound file/folder moves.

use super::super::*;

#[allow(clippy::too_many_arguments)]
pub(super) async fn execute_local(
    client: &DriveHttpClient,
    token: &str,
    pair: &SyncPair,
    guard: &UnixRootGuard,
    root: &SyncRoot,
    remote: &[RemoteEntry],
    remote_id: &str,
    from: &Path,
    to: &Path,
    precondition: &DownloadPrecondition,
    folder: Option<&shellx_drive_desktop_core::FolderMovePrecondition>,
) -> CoreResult<Option<ReviewItem>> {
    let remote_file = remote
        .iter()
        .find(|file| file.id == remote_id && !file.trashed)
        .ok_or_else(|| {
            DesktopError::InvalidState(
                "Drive rename source disappeared before local move".to_string(),
            )
        })?;
    let is_directory = remote_file.kind == RemoteEntryKind::Folder;
    let descendants = descendant_count(folder);
    if is_directory != folder.is_some() {
        return Ok(Some(review(
            to,
            "Drive changed the tracked item's kind before this local rename.",
            is_directory,
            descendants,
        )));
    }
    if !local_move_matches(guard, pair, from, precondition, folder).unwrap_or(false) {
        return Ok(Some(review(
            to,
            "The local source changed after Drive planned this rename.",
            is_directory,
            descendants,
        )));
    }
    if !guard
        .compatible_destination_is_absent(to, Some(from))
        .unwrap_or(false)
    {
        return Ok(Some(review(
            to,
            "The Drive rename destination is occupied locally, including by a case-only alias.",
            is_directory,
            descendants,
        )));
    }
    if !inbound_remote_matches(client, token, pair, root, remote_file, to, folder).await? {
        return Ok(Some(review(
            to,
            "Drive changed the tracked item or folder subtree before the local rename.",
            is_directory,
            descendants,
        )));
    }
    require_pair_marker(guard, pair)?;
    let moved = guard.move_entry_noreplace(from, to, is_directory, || {
        require_pair_marker(guard, pair)?;
        if !local_move_matches(guard, pair, from, precondition, folder)?
            || !guard.compatible_destination_is_absent(to, Some(from))?
        {
            return Err(DesktopError::UnsafePath(
                "local rename inputs changed before the native no-replace move".to_string(),
            ));
        }
        Ok(())
    });
    if moved.is_err() {
        return Ok(Some(review(
            to,
            "Linux could not confirm the native no-replace rename; no later action or baseline update was attempted.",
            is_directory,
            descendants,
        )));
    }
    if !guard
        .compatible_destination_is_absent(to, Some(to))
        .unwrap_or(false)
    {
        return Ok(Some(review(
            to,
            "A case-only local destination collision appeared while the rename completed; the moved bytes were retained for review.",
            is_directory,
            descendants,
        )));
    }
    if !inbound_remote_matches(client, token, pair, root, remote_file, to, folder).await? {
        return Ok(Some(review(
            to,
            "Drive changed while its local rename completed; the moved local bytes were retained for review.",
            is_directory,
            descendants,
        )));
    }
    Ok(None)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn execute_remote(
    client: &DriveHttpClient,
    token: &str,
    pair: &SyncPair,
    guard: &UnixRootGuard,
    root: &SyncRoot,
    remote_id: &str,
    from: &Path,
    to: &Path,
    base_revision: i64,
    folder: Option<&shellx_drive_desktop_core::FolderMovePrecondition>,
) -> CoreResult<Option<ReviewItem>> {
    require_pair_marker(guard, pair)?;
    require_write_grant(root)?;
    let current = fresh_writable_remote_entries(client, token, root).await?;
    let (is_directory, descendants) = move_review_shape(folder);
    let paths = match map_remote_paths(&current, pair.remote_root_id.as_deref()) {
        Ok(paths) => paths,
        Err(_) => {
            return Ok(Some(review(
                to,
                "Drive paths changed or collided before this rename.",
                is_directory,
                descendants,
            )));
        }
    };
    let Some(source) = current
        .iter()
        .find(|file| file.id == remote_id && !file.trashed && file.revision == base_revision)
    else {
        return Ok(Some(review(
            to,
            "Drive changed or removed the tracked item before this rename.",
            is_directory,
            descendants,
        )));
    };
    if (source.kind == RemoteEntryKind::Folder) != is_directory {
        return Ok(Some(review(
            to,
            "Drive changed the tracked item's kind before this rename.",
            is_directory,
            descendants,
        )));
    }
    let execution_folder = match folder {
        Some(folder) => {
            let mut exact = folder.clone();
            exact.remote_witness =
                capture_folder_remote_witness(remote_id, pair.remote_root_id.as_deref(), &current);
            if exact.remote_witness.is_none() {
                return Ok(Some(review(
                    to,
                    "Drive could not capture the complete folder subtree before this rename.",
                    is_directory,
                    descendants,
                )));
            }
            Some(exact)
        }
        None => None,
    };
    if paths
        .get(remote_id)
        .is_none_or(|path| path.as_path() != from)
    {
        return Ok(Some(review(
            to,
            "Drive changed the tracked item's path before this rename.",
            is_directory,
            descendants,
        )));
    }
    if !destination_is_available(&paths, remote_id, to) {
        return Ok(Some(review(
            to,
            "The Drive rename destination is occupied, including by a case-insensitive sibling alias.",
            is_directory,
            descendants,
        )));
    }
    if !outbound_local_move_matches(guard, pair, to, source, execution_folder.as_ref())
        .unwrap_or(false)
    {
        return Ok(Some(review(
            to,
            "The local renamed source changed before Drive could apply it.",
            is_directory,
            descendants,
        )));
    }
    if execution_folder.as_ref().is_some_and(|witness| {
        !folder_remote_witness_matches(witness, pair.remote_root_id.as_deref(), &current)
    }) {
        return Ok(Some(review(
            to,
            "Drive changed this folder subtree before its rename.",
            is_directory,
            descendants,
        )));
    }
    let folders = remote_folder_ids(&current, pair.remote_root_id.as_deref())?;
    let Ok(parent) = remote_parent(&folders, pair, to) else {
        return Ok(Some(review(
            to,
            "The Drive destination folder changed before this rename.",
            is_directory,
            descendants,
        )));
    };
    let Ok(name) = leaf(to) else {
        return Ok(Some(review(
            to,
            "The Drive destination name is invalid.",
            is_directory,
            descendants,
        )));
    };
    require_pair_marker(guard, pair)?;
    let moved = client
        .move_remote_file(token, remote_id, base_revision, parent.as_deref(), name)
        .await?;
    let moved = match moved {
        RemoteMoveTransfer::Moved(moved)
            if remote_move_response_matches(
                &moved,
                remote_id,
                &pair.workspace_id,
                base_revision,
                parent.as_deref(),
                name,
            ) =>
        {
            moved
        }
        RemoteMoveTransfer::Conflict => {
            return Ok(Some(review(
                to,
                "Drive atomically rejected a stale source or occupied rename destination.",
                is_directory,
                descendants,
            )));
        }
        RemoteMoveTransfer::NeedsReview | RemoteMoveTransfer::Moved(_) => {
            return Ok(Some(review(
                to,
                "Drive did not confirm the exact renamed item and destination.",
                is_directory,
                descendants,
            )));
        }
    };
    if !outbound_local_move_matches(guard, pair, to, source, execution_folder.as_ref())
        .unwrap_or(false)
    {
        return Ok(Some(review(
            to,
            "The local item changed while Drive completed its rename.",
            is_directory,
            descendants,
        )));
    }
    if !outbound_remote_matches(
        client,
        token,
        pair,
        root,
        source,
        &moved,
        to,
        execution_folder.as_ref(),
    )
    .await?
    {
        return Ok(Some(review(
            to,
            "Drive changed or collided after the rename response; no baseline was advanced.",
            is_directory,
            descendants,
        )));
    }
    Ok(None)
}

async fn inbound_remote_matches(
    client: &DriveHttpClient,
    token: &str,
    pair: &SyncPair,
    root: &SyncRoot,
    expected: &RemoteEntry,
    destination: &Path,
    folder: Option<&shellx_drive_desktop_core::FolderMovePrecondition>,
) -> CoreResult<bool> {
    match folder {
        Some(folder) => {
            let current = fresh_remote_entries(client, token, root).await?;
            Ok(folder_remote_witness_matches(
                folder,
                pair.remote_root_id.as_deref(),
                &current,
            ))
        }
        None => fresh_remote_file_matches(client, token, pair, root, expected, destination).await,
    }
}

pub(in crate::application::linux::reconcile) fn destination_is_available(
    paths: &BTreeMap<String, PathBuf>,
    source_id: &str,
    destination: &Path,
) -> bool {
    paths
        .iter()
        .all(|(id, path)| id == source_id || !windows_paths_equal_ignore_case(path, destination))
}

#[allow(clippy::too_many_arguments)]
async fn outbound_remote_matches(
    client: &DriveHttpClient,
    token: &str,
    pair: &SyncPair,
    root: &SyncRoot,
    source: &RemoteEntry,
    moved: &shellx_drive_desktop_core::RemoteFile,
    destination: &Path,
    folder: Option<&shellx_drive_desktop_core::FolderMovePrecondition>,
) -> CoreResult<bool> {
    let current = fresh_remote_entries(client, token, root).await?;
    let paths = match map_remote_paths(&current, pair.remote_root_id.as_deref()) {
        Ok(paths) => paths,
        Err(_) => return Ok(false),
    };
    if !destination_is_available(&paths, &source.id, destination) {
        return Ok(false);
    }
    if let Some(folder) = folder {
        let Some(expected) = moved_folder_precondition(folder, moved, destination) else {
            return Ok(false);
        };
        return Ok(folder_remote_witness_matches(
            &expected,
            pair.remote_root_id.as_deref(),
            &current,
        ));
    }
    Ok(current.iter().any(|entry| {
        entry.id == source.id
            && !entry.trashed
            && entry.kind == source.kind
            && entry.revision == moved.revision
            && entry.content_hash == source.content_hash
            && entry.size_bytes == source.size_bytes
            && entry.parent_id == moved.parent_id
            && entry.name == moved.name
            && paths.get(&entry.id).is_some_and(|path| path == destination)
    }))
}

pub(in crate::application::linux::reconcile) fn moved_folder_precondition(
    folder: &shellx_drive_desktop_core::FolderMovePrecondition,
    moved: &shellx_drive_desktop_core::RemoteFile,
    destination: &Path,
) -> Option<shellx_drive_desktop_core::FolderMovePrecondition> {
    let mut expected = folder.clone();
    let witness = expected.remote_witness.as_mut()?;
    let old_root = witness.root_path.clone();
    let root_id = witness.root_id.clone();
    for (id, entry) in &mut witness.entries {
        let tail = entry.relative_path.strip_prefix(&old_root).ok()?;
        entry.relative_path = destination.join(tail);
        if id == &root_id {
            entry.parent_id = moved.parent_id.clone();
            entry.revision = moved.revision;
        }
    }
    witness.root_path = destination.to_path_buf();
    Some(expected)
}

fn descendant_count(folder: Option<&shellx_drive_desktop_core::FolderMovePrecondition>) -> usize {
    folder.map_or(0, |witness| witness.entries.len().saturating_sub(1))
}

fn review(path: &Path, summary: &str, is_directory: bool, descendants: usize) -> ReviewItem {
    move_review(path, summary, is_directory, descendants)
}
