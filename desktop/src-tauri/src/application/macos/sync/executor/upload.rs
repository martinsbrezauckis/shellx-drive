//! Snapshot-backed Drive create and replacement transfers.

use shellx_drive_desktop_core::{
    created_remote_response_matches, updated_remote_response_matches, DriveHttpClient,
    ExistingFileTransfer, RemoteEntryKind, RemoteFileKind, Result as CoreResult, SyncPair,
    SyncRoot,
};

use super::super::staging::upload_snapshot;
use super::operations::ActionOutcome;
use super::{presentation, remote};

fn require_terminal_upload_marker(
    guard: &crate::platform::unix::filesystem::UnixRootGuard,
    pair: &SyncPair,
    owned: &shellx_drive_desktop_core::OwnedStagingRoot,
    batch: &std::path::Path,
) -> CoreResult<()> {
    if let Err(error) = remote::require_pair_marker(guard, pair) {
        owned.remove_batch(batch)?;
        return Err(error);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn new(
    guard: &crate::platform::unix::filesystem::UnixRootGuard,
    client: &DriveHttpClient,
    token: &str,
    pair: &SyncPair,
    root: &SyncRoot,
    path: &std::path::Path,
    is_directory: bool,
    local_entry: &shellx_drive_desktop_core::LocalEntry,
) -> CoreResult<ActionOutcome> {
    remote::require_pair_marker(guard, pair)?;
    remote::require_write_grant(root)?;
    let current = remote::fresh_writable_entries(client, token, root).await?;
    let folders = remote::folder_ids(&current, pair.remote_root_id.as_deref())?;
    let parent = remote::parent(&folders, pair, path)?;
    let name = remote::leaf(path)?;
    if is_directory {
        let actual = guard.local_directory_identity(path)?;
        if local_entry
            .directory_identity
            .as_ref()
            .is_some_and(|planned| planned != &actual)
        {
            return Ok(ActionOutcome::Review(presentation::move_review(
                path,
                "The local folder changed before Drive could create it.",
                true,
                0,
            )));
        }
        remote::require_pair_marker(guard, pair)?;
        let created = client
            .create_folder(token, &pair.workspace_id, parent.as_deref(), name)
            .await?;
        return Ok(
            if created_remote_response_matches(
                &created,
                &pair.workspace_id,
                parent.as_deref(),
                name,
                RemoteFileKind::Folder,
                None,
            ) {
                ActionOutcome::Continue
            } else {
                ActionOutcome::Review(presentation::move_review(
                    path,
                    "Drive did not confirm the exact created folder.",
                    true,
                    0,
                ))
            },
        );
    }
    let snapshot = upload_snapshot(guard, pair, path, local_entry)?;
    let (owned, batch, file, local) = snapshot.into_parts();
    require_terminal_upload_marker(guard, pair, &owned, &batch)?;
    let created = client
        .upload_new_file_from_reader(
            token,
            &pair.workspace_id,
            parent.as_deref(),
            name,
            file,
            local.size_bytes,
        )
        .await;
    owned.remove_batch(&batch)?;
    let created = created?;
    Ok(
        if created_remote_response_matches(
            &created,
            &pair.workspace_id,
            parent.as_deref(),
            name,
            RemoteFileKind::File,
            local.content_hash.as_deref(),
        ) {
            ActionOutcome::Continue
        } else {
            ActionOutcome::Review(presentation::move_review(
                path,
                "Drive did not confirm the exact uploaded file.",
                false,
                0,
            ))
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn existing(
    guard: &crate::platform::unix::filesystem::UnixRootGuard,
    client: &DriveHttpClient,
    token: &str,
    pair: &SyncPair,
    root: &SyncRoot,
    remote_id: &str,
    path: &std::path::Path,
    revision: i64,
    planned: &shellx_drive_desktop_core::LocalEntry,
) -> CoreResult<ActionOutcome> {
    remote::require_pair_marker(guard, pair)?;
    remote::require_write_grant(root)?;
    let current = remote::fresh_writable_entries(client, token, root).await?;
    let Some(source) = current.iter().find(|entry| {
        entry.id == remote_id
            && !entry.trashed
            && entry.kind == RemoteEntryKind::File
            && entry.revision == revision
    }) else {
        return Ok(ActionOutcome::Review(presentation::conflict_review(
            remote_id, path,
        )));
    };
    let snapshot = upload_snapshot(guard, pair, path, planned)?;
    let (owned, batch, file, local) = snapshot.into_parts();
    require_terminal_upload_marker(guard, pair, &owned, &batch)?;
    let transfer = client
        .replace_existing_file_from_reader(token, remote_id, revision, file, local.size_bytes)
        .await;
    owned.remove_batch(&batch)?;
    Ok(match transfer? {
        ExistingFileTransfer::Updated(updated)
            if updated_remote_response_matches(
                &updated,
                remote_id,
                &pair.workspace_id,
                revision,
                source,
                local.content_hash.as_deref(),
                local.size_bytes,
            ) =>
        {
            ActionOutcome::Continue
        }
        ExistingFileTransfer::Updated(_) | ExistingFileTransfer::Conflict => {
            ActionOutcome::Review(presentation::conflict_review(remote_id, path))
        }
        ExistingFileTransfer::UnsupportedResumableReplacement { .. } => ActionOutcome::Review(
            presentation::unsupported_review(remote_id, path, local.size_bytes),
        ),
    })
}

#[cfg(test)]
mod tests;
