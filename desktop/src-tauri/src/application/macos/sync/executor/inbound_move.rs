//! Fail-closed inbound file and folder moves.

use std::path::Path;

use shellx_drive_desktop_core::{
    folder_remote_witness_matches, DesktopError, DownloadPrecondition, DriveHttpClient,
    FolderMovePrecondition, RemoteEntry, RemoteEntryKind, Result as CoreResult, SyncPair, SyncRoot,
};

use super::operations::ActionOutcome;
use super::{local, presentation, remote};

#[allow(clippy::too_many_arguments)]
pub(super) async fn execute(
    guard: &crate::platform::unix::filesystem::UnixRootGuard,
    client: &DriveHttpClient,
    token: &str,
    pair: &SyncPair,
    root: &SyncRoot,
    remote_file: &RemoteEntry,
    from: &Path,
    to: &Path,
    precondition: &DownloadPrecondition,
    folder: Option<&FolderMovePrecondition>,
) -> CoreResult<ActionOutcome> {
    let is_directory = folder.is_some();
    let descendants = descendant_count(folder);
    if (remote_file.kind == RemoteEntryKind::Folder) != is_directory {
        return Ok(stop(
            to,
            "Drive changed the tracked item's kind before this local rename.",
            is_directory,
            descendants,
        ));
    }
    if !local::inbound_move_matches(guard, pair, from, precondition, folder).unwrap_or(false) {
        return Ok(stop(
            to,
            "The local source changed after Drive planned this rename.",
            is_directory,
            descendants,
        ));
    }
    if !guard.local_entry_is_absent(to).unwrap_or(false) {
        return Ok(stop(
            to,
            "The Drive rename destination is occupied locally, including by a case-only alias; inspect both paths before rechecking.",
            is_directory,
            descendants,
        ));
    }
    if !remote_matches(client, token, pair, root, remote_file, to, folder).await? {
        return Ok(stop(
            to,
            "Drive changed the tracked item or folder subtree before the local rename.",
            is_directory,
            descendants,
        ));
    }
    remote::require_pair_marker(guard, pair)?;
    let moved = guard.move_entry_noreplace(from, to, is_directory, || {
        remote::require_pair_marker(guard, pair)?;
        if !local::inbound_move_matches(guard, pair, from, precondition, folder)?
            || !guard.local_entry_is_absent(to)?
        {
            return Err(DesktopError::UnsafePath(
                "local rename inputs changed before the native no-replace move".to_string(),
            ));
        }
        Ok(())
    });
    if moved.is_err() {
        return Ok(stop(
            to,
            "macOS could not confirm the native no-replace rename; no later action or baseline update was attempted.",
            is_directory,
            descendants,
        ));
    }
    if !remote_matches(client, token, pair, root, remote_file, to, folder).await? {
        return Ok(stop(
            to,
            "Drive changed while its local rename completed; the moved local bytes were retained for review.",
            is_directory,
            descendants,
        ));
    }
    Ok(ActionOutcome::Continue)
}

async fn remote_matches(
    client: &DriveHttpClient,
    token: &str,
    pair: &SyncPair,
    root: &SyncRoot,
    remote_file: &RemoteEntry,
    path: &Path,
    folder: Option<&FolderMovePrecondition>,
) -> CoreResult<bool> {
    if let Some(folder) = folder {
        let current = remote::fresh_entries(client, token, root).await?;
        Ok(folder_remote_witness_matches(
            folder,
            pair.remote_root_id.as_deref(),
            &current,
        ))
    } else {
        remote::fresh_file_matches(client, token, pair, root, remote_file, path).await
    }
}

fn descendant_count(folder: Option<&FolderMovePrecondition>) -> usize {
    folder
        .map(|witness| witness.entries.len().saturating_sub(1))
        .unwrap_or(0)
}

fn stop(path: &Path, summary: &str, is_directory: bool, descendants: usize) -> ActionOutcome {
    ActionOutcome::Stop(presentation::move_review(
        path,
        summary,
        is_directory,
        descendants,
    ))
}
