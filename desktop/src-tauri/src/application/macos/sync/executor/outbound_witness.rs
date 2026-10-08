//! Complete terminal remote witnesses for outbound folder moves.

use std::path::Path;

use shellx_drive_desktop_core::{
    capture_folder_remote_witness, folder_remote_witness_matches, DriveHttpClient,
    FolderMovePrecondition, RemoteEntry, RemoteFile, Result as CoreResult, SyncPair, SyncRoot,
};

use super::remote;

pub(super) fn capture(
    planned: &FolderMovePrecondition,
    remote_id: &str,
    pair: &SyncPair,
    current: &[RemoteEntry],
) -> Option<FolderMovePrecondition> {
    let mut exact = planned.clone();
    exact.remote_witness =
        capture_folder_remote_witness(remote_id, pair.remote_root_id.as_deref(), current);
    exact.remote_witness.as_ref()?;
    Some(exact)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn terminal_matches(
    client: &DriveHttpClient,
    token: &str,
    pair: &SyncPair,
    root: &SyncRoot,
    source: &RemoteEntry,
    moved: &RemoteFile,
    destination: &Path,
    folder: Option<&FolderMovePrecondition>,
) -> CoreResult<bool> {
    if let Some(folder) = folder {
        let Some(expected) = moved_folder_precondition(folder, moved, destination) else {
            return Ok(false);
        };
        let current = remote::fresh_entries(client, token, root).await?;
        return Ok(folder_remote_witness_matches(
            &expected,
            pair.remote_root_id.as_deref(),
            &current,
        ));
    }
    let mut expected = source.clone();
    expected.parent_id = moved.parent_id.clone();
    expected.name = moved.name.clone();
    expected.revision = moved.revision;
    remote::fresh_file_matches(client, token, pair, root, &expected, destination).await
}

pub(super) fn moved_folder_precondition(
    folder: &FolderMovePrecondition,
    moved: &RemoteFile,
    destination: &Path,
) -> Option<FolderMovePrecondition> {
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
