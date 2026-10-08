//! Terminal reconciliation action dispatch for the Linux adapter.

use super::*;

pub(super) fn action_rank(action: &SyncAction) -> u8 {
    match action {
        SyncAction::EnsureLocalDirectory { .. } => 0,
        SyncAction::MoveLocal { .. } => 1,
        SyncAction::Download { .. } => 2,
        SyncAction::UploadNew {
            is_directory: true, ..
        } => 3,
        SyncAction::UploadNew { .. } => 4,
        SyncAction::UploadExisting { .. } | SyncAction::MoveRemote { .. } => 5,
        SyncAction::WriteRemoteConflictCopy { .. } => 6,
    }
}

pub(super) fn action_path(action: &SyncAction) -> &Path {
    match action {
        SyncAction::EnsureLocalDirectory { relative_path, .. }
        | SyncAction::Download { relative_path, .. }
        | SyncAction::UploadNew { relative_path, .. }
        | SyncAction::UploadExisting { relative_path, .. } => relative_path,
        SyncAction::MoveLocal { to, .. } | SyncAction::MoveRemote { to, .. } => to,
        SyncAction::WriteRemoteConflictCopy { conflict_path, .. } => conflict_path,
    }
}

mod moves;
#[cfg(test)]
pub(super) use moves::{destination_is_available, moved_folder_precondition};

// Keep cancellation and filesystem authority explicit at the reconciliation dispatch boundary.
#[allow(clippy::too_many_arguments)]
pub(super) async fn execute_actions(
    run: &SyncRun,
    client: &DriveHttpClient,
    token: &str,
    pair: &SyncPair,
    guard: &UnixRootGuard,
    sync_root: &SyncRoot,
    remote: &[RemoteEntry],
    actions: &[SyncAction],
) -> CoreResult<Vec<ReviewItem>> {
    let mut reviews = Vec::new();
    let mut ordered = actions.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|action| {
        (
            action_rank(action),
            action_path(action).components().count(),
        )
    });
    for action in ordered {
        run.ensure_not_cancelled()?;
        match action {
            SyncAction::EnsureLocalDirectory { relative_path, .. } => {
                guard.ensure_directory(relative_path)?
            }
            SyncAction::Download {
                remote_id,
                relative_path,
                revision,
                precondition,
            } => {
                let file = remote
                    .iter()
                    .find(|file| file.id == *remote_id && !file.trashed)
                    .ok_or_else(|| {
                        DesktopError::InvalidState(
                            "Drive download target disappeared before transfer".to_string(),
                        )
                    })?;
                if file.kind != RemoteEntryKind::File || file.revision != *revision {
                    return Err(DesktopError::InvalidState(
                        "Drive download target changed before transfer".to_string(),
                    ));
                }
                if let Some(review) = download_file(
                    client,
                    token,
                    pair,
                    guard,
                    sync_root,
                    file,
                    relative_path,
                    relative_path,
                    precondition,
                )
                .await?
                {
                    reviews.push(review);
                    break;
                }
            }
            SyncAction::UploadNew {
                relative_path,
                is_directory,
                local,
            } => {
                require_pair_marker(guard, pair)?;
                require_write_grant(sync_root)?;
                let current = fresh_writable_remote_entries(client, token, sync_root).await?;
                let current_folders = remote_folder_ids(&current, pair.remote_root_id.as_deref())?;
                let parent = remote_parent(&current_folders, pair, relative_path)?;
                let name = leaf(relative_path)?;
                if *is_directory {
                    let current_local = guard.local_directory_identity(relative_path)?;
                    if local
                        .directory_identity
                        .as_ref()
                        .is_some_and(|planned| planned != &current_local)
                    {
                        reviews.push(move_review(
                            relative_path,
                            "The local folder changed before Drive could create it.",
                            true,
                            0,
                        ));
                        continue;
                    }
                    require_pair_marker(guard, pair)?;
                    let created = client
                        .create_folder(token, &pair.workspace_id, parent.as_deref(), name)
                        .await?;
                    if !created_remote_response_matches(
                        &created,
                        &pair.workspace_id,
                        parent.as_deref(),
                        name,
                        RemoteFileKind::Folder,
                        None,
                    ) {
                        reviews.push(move_review(
                            relative_path,
                            "Drive did not confirm the exact created folder.",
                            true,
                            0,
                        ));
                        continue;
                    }
                } else {
                    let UploadSnapshot {
                        area,
                        batch,
                        file,
                        size_bytes,
                    } = upload_snapshot(guard, pair, relative_path, local)?;
                    let created = async {
                        require_pair_marker(guard, pair)?;
                        client
                            .upload_new_file_from_reader(
                                token,
                                &pair.workspace_id,
                                parent.as_deref(),
                                name,
                                file,
                                size_bytes,
                            )
                            .await
                    }
                    .await;
                    area.remove_batch(&batch)?;
                    let created = created?;
                    if !created_remote_response_matches(
                        &created,
                        &pair.workspace_id,
                        parent.as_deref(),
                        name,
                        RemoteFileKind::File,
                        local.content_hash.as_deref(),
                    ) {
                        reviews.push(move_review(
                            relative_path,
                            "Drive did not confirm the exact uploaded file.",
                            false,
                            0,
                        ));
                    }
                }
            }
            SyncAction::UploadExisting {
                remote_id,
                relative_path,
                base_revision,
                local,
            } => {
                require_pair_marker(guard, pair)?;
                require_write_grant(sync_root)?;
                let current_remote =
                    fresh_writable_remote_entries(client, token, sync_root).await?;
                let source_remote = current_remote.iter().find(|entry| {
                    entry.id == *remote_id
                        && !entry.trashed
                        && entry.kind == RemoteEntryKind::File
                        && entry.revision == *base_revision
                });
                let Some(source_remote) = source_remote else {
                    reviews.push(conflict_review(remote_id, relative_path));
                    continue;
                };
                let UploadSnapshot {
                    area,
                    batch,
                    file,
                    size_bytes,
                } = upload_snapshot(guard, pair, relative_path, local)?;
                let transfer = async {
                    require_pair_marker(guard, pair)?;
                    client
                        .replace_existing_file_from_reader(
                            token,
                            remote_id,
                            *base_revision,
                            file,
                            size_bytes,
                        )
                        .await
                }
                .await;
                area.remove_batch(&batch)?;
                match transfer? {
                    ExistingFileTransfer::Updated(updated)
                        if updated_remote_response_matches(
                            &updated,
                            remote_id,
                            &pair.workspace_id,
                            *base_revision,
                            source_remote,
                            local.content_hash.as_deref(),
                            local.size_bytes,
                        ) => {}
                    ExistingFileTransfer::Updated(_) => {
                        reviews.push(conflict_review(remote_id, relative_path))
                    }
                    ExistingFileTransfer::Conflict => {
                        reviews.push(conflict_review(remote_id, relative_path))
                    }
                    ExistingFileTransfer::UnsupportedResumableReplacement { .. } => reviews.push(
                        unsupported_review(remote_id, relative_path, local.size_bytes),
                    ),
                }
            }
            SyncAction::MoveLocal {
                remote_id,
                from,
                to,
                precondition,
                folder_precondition,
            } => {
                if let Some(review) = moves::execute_local(
                    client,
                    token,
                    pair,
                    guard,
                    sync_root,
                    remote,
                    remote_id,
                    from,
                    to,
                    precondition,
                    folder_precondition.as_ref(),
                )
                .await?
                {
                    reviews.push(review);
                    break;
                }
            }
            SyncAction::MoveRemote {
                remote_id,
                from,
                to,
                base_revision,
                folder_precondition,
            } => {
                if let Some(review) = moves::execute_remote(
                    client,
                    token,
                    pair,
                    guard,
                    sync_root,
                    remote_id,
                    from,
                    to,
                    *base_revision,
                    folder_precondition.as_ref(),
                )
                .await?
                {
                    reviews.push(review);
                    break;
                }
            }
            SyncAction::WriteRemoteConflictCopy {
                remote_id,
                local_path,
                conflict_path,
            } => {
                let file = remote
                    .iter()
                    .find(|file| file.id == *remote_id && !file.trashed)
                    .ok_or_else(|| {
                        DesktopError::InvalidState(
                            "Drive conflict source disappeared before download".to_string(),
                        )
                    })?;
                if file.kind != RemoteEntryKind::File {
                    return Err(DesktopError::InvalidState(
                        "Drive conflict source is not a regular file".to_string(),
                    ));
                }
                if let Some(review) = download_file(
                    client,
                    token,
                    pair,
                    guard,
                    sync_root,
                    file,
                    local_path,
                    conflict_path,
                    &DownloadPrecondition::Absent,
                )
                .await?
                {
                    reviews.push(review);
                    break;
                }
            }
        }
        run.ensure_not_cancelled()?;
    }
    Ok(reviews)
}
