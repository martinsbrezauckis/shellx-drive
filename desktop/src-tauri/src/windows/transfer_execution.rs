//! Windows transfer execution, checked filesystem publication, and baseline finalization.

use super::*;

#[cfg(test)]
pub(super) fn local_read_budget_for_sync_pass() -> ReadBudget {
    // One pass may scan at admission and finalization, plus revalidate a
    // moved subtree before and after publication. Every one of those reads
    // shares this finite allowance.
    ReadBudget::new(
        LocalScanLimits::default()
            .max_total_file_bytes
            .saturating_mul(6),
    )
}

use super::{
    handle_relative_file::{create_new_file_at, delete_open_file, open_create_parent},
    verified_staging::{rename_open_file_at, VerifiedStagedFile},
};

pub(super) fn replacement_conflict_review(remote_id: &str, path: &Path) -> ReviewItem {
    ReviewItem {
            id: format!("replacement-conflict-{remote_id}"),
            kind: ReviewKind::ContentConflict,
            relative_path: path.to_path_buf(),
            descendant_count: 0,
            is_directory: false,
            summary: "Drive kept the newer remote file and saved this stale replacement as a separate conflict copy. Your local replacement remains untouched.".to_string(),
            actions: vec![ReviewAction::OpenConflictCopies],
        }
}

pub(super) fn unsupported_replacement_review(
    remote_id: &str,
    path: &Path,
    size_bytes: u64,
) -> ReviewItem {
    ReviewItem {
        id: format!("replacement-unsupported-{remote_id}"),
        kind: ReviewKind::UnsupportedTransfer,
        relative_path: path.to_path_buf(),
        descendant_count: 0,
        is_directory: false,
        summary: format!(
            "Drive did not accept its resumable update endpoint for this {size_bytes}-byte replacement. The local and current remote copies remain untouched."
        ),
        actions: vec![ReviewAction::RetryWhenServerSupportsResumableReplacement],
    }
}

pub(super) fn action_rank(action: &SyncAction) -> u8 {
    match action {
        SyncAction::EnsureLocalDirectory { .. } => 0,
        // An inbound rename with a changed body moves the known baseline
        // body first, then downloads/replaces at its new path.
        SyncAction::MoveLocal { .. } => 1,
        // A folder root metadata PATCH must complete before descendant
        // body updates use the post-move effective paths.
        SyncAction::MoveRemote {
            folder_precondition: Some(_),
            ..
        } => 1,
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

pub(super) fn remote_folder_ids(
    remote: &[RemoteEntry],
    remote_paths: &BTreeMap<String, PathBuf>,
) -> HashMap<PathBuf, String> {
    remote
        .iter()
        .filter(|entry| !entry.trashed && entry.kind == RemoteEntryKind::Folder)
        .filter_map(|entry| {
            remote_paths
                .get(&entry.id)
                .map(|path| (path.clone(), entry.id.clone()))
        })
        .collect()
}

pub(super) fn remote_parent_id(
    pair: &SyncPair,
    folder_ids: &HashMap<PathBuf, String>,
    relative_path: &Path,
) -> CoreResult<Option<String>> {
    let parent = relative_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    match parent {
        None => Ok(pair.remote_root_id.clone()),
        Some(parent) => folder_ids.get(parent).cloned().map(Some).ok_or_else(|| {
            DesktopError::InvalidState(format!(
                "Drive parent folder was not available for {}",
                relative_path.display()
            ))
        }),
    }
}

pub(super) fn local_target(root: &Path, relative_path: &Path) -> CoreResult<PathBuf> {
    shellx_drive_desktop_core::validate_local_relative(relative_path)
        .map_err(|issue| DesktopError::UnsafePath(issue.reason))?;
    let target = root.join(relative_path);
    if !target.starts_with(root) {
        return Err(DesktopError::UnsafePath(format!(
            "target escapes the selected local root: {}",
            relative_path.display()
        )));
    }
    Ok(target)
}

pub(super) fn local_leaf_name(relative_path: &Path) -> CoreResult<&str> {
    relative_path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| DesktopError::UnsafePath("path has no Unicode file name".to_string()))
}

pub(super) fn ensure_local_directory(root: &Path, relative_path: &Path) -> CoreResult<()> {
    if relative_path.as_os_str().is_empty() {
        // A root-level staged payload already has its directory: the owned
        // batch itself. Pin that exact root to validate it without passing an
        // intentionally empty file path through `local_target`.
        let _root_pins = pin_checked_rename_directory_chain(root, root)?;
        return Ok(());
    }
    let target = local_target(root, relative_path)?;
    let relative = target.strip_prefix(root).map_err(|_| {
        DesktopError::UnsafePath(format!(
            "Drive folder escapes the selected root: {}",
            relative_path.display()
        ))
    })?;
    let mut current = root.to_path_buf();
    // Create exactly one component while every existing ancestor is held
    // without FILE_SHARE_DELETE. If another process wins the create race,
    // the immediate no-reparse open below either binds a real directory or
    // rejects its junction/reparse point before any child is traversed.
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(DesktopError::UnsafePath(
                "Drive folder has a non-normal path component".to_string(),
            ));
        };
        let _parent_pins = pin_checked_rename_directory_chain(root, &current)?;
        let child = current.join(name);
        match fs::create_dir(&child) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(DesktopError::Io(error)),
        }
        let _child_pin = open_checked_rename_directory(&child)?;
        current = child;
    }
    Ok(())
}

pub(super) fn ensure_local_parent(path: &Path) -> CoreResult<()> {
    let parent = path.parent().ok_or_else(|| {
        DesktopError::UnsafePath("target has no local parent directory".to_string())
    })?;
    fs::create_dir_all(parent)?;
    Ok(())
}

pub(super) fn open_checked_upload_source(root: &Path, path: &Path) -> CoreResult<fs::File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    // Allow readers and deletion/rename semantics, but not a competing
    // writer while the immutable snapshot is copied. This excludes
    // FILE_SHARE_WRITE at the actual Windows handle boundary.
    const SNAPSHOT_SHARE_MODE: u32 = FILE_SHARE_READ | FILE_SHARE_DELETE;
    const _: () = assert!(SNAPSHOT_SHARE_MODE & FILE_SHARE_WRITE == 0);

    let parent = path.parent().ok_or_else(|| {
        DesktopError::UnsafePath("upload source has no parent directory".to_string())
    })?;
    // Keep every directory from the volume root through the source parent
    // open without delete sharing while the leaf is opened. A descendant
    // junction cannot be swapped in and restored around this open.
    let _parent_pins = pin_checked_rename_directory_chain(root, parent)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(DesktopError::UnsafePath(format!(
            "upload source is not a regular file: {}",
            path.display()
        )));
    }
    // Opening the reparse point itself prevents this source handle from
    // silently following a link swapped in after the pathname check.
    let source = fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .share_mode(SNAPSHOT_SHARE_MODE)
        .open(path)?;
    if source.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(DesktopError::UnsafeLink(path.to_path_buf()));
    }
    shellx_drive_desktop_core::ensure_single_linked_regular_file(&source, path)?;
    Ok(source)
}

pub(super) fn snapshot_upload_source(
    root: &Path,
    relative_path: &Path,
    local_read_budget: &mut ReadBudget,
) -> CoreResult<UploadSnapshot> {
    let source_path = local_target(root, relative_path)?;
    let boundary = capture_local_operation_boundary(root, &source_path)?;
    let mut source = open_checked_upload_source(root, &source_path)?;
    let source_metadata = source.metadata()?;
    let max_file_bytes = LocalScanLimits::default().max_file_bytes;
    if source_metadata.len() > max_file_bytes {
        return Err(DesktopError::InvalidState(format!(
            "local upload source exceeds the {max_file_bytes}-byte scan limit"
        )));
    }
    local_read_budget.charge(source_metadata.len())?;
    let staging_root = upload_staging_root(root)?;
    let (area, batch) = create_owned_staging_batch(root, &staging_root, "upload")?;
    let payload = batch.join("payload");
    let snapshot = (|| -> CoreResult<(LocalEntry, fs::File)> {
        let _staging_pins = pin_checked_rename_directory_chain(area.root(), &batch)?;
        let create_parent = open_create_parent(&batch)?;
        let payload_leaf = payload.file_name().ok_or_else(|| {
            DesktopError::UnsafePath("upload snapshot payload has no leaf".to_string())
        })?;
        let mut destination = create_new_file_at(
            &create_parent,
            payload_leaf,
            windows_sys::Win32::Foundation::GENERIC_READ
                | windows_sys::Win32::Foundation::GENERIC_WRITE
                | windows_sys::Win32::Storage::FileSystem::READ_CONTROL
                | windows_sys::Win32::Storage::FileSystem::WRITE_DAC
                | windows_sys::Win32::Storage::FileSystem::WRITE_OWNER,
        )?;
        shellx_drive_desktop_core::validate_private_staging_file(&destination)?;
        let (content_hash, copied) =
            copy_and_hash_reader_bounded(&mut source, &mut destination, max_file_bytes)?;
        destination.sync_all()?;
        destination.seek(std::io::SeekFrom::Start(0))?;
        verify_local_operation_boundary(&boundary)?;
        if copied != source_metadata.len() {
            return Err(DesktopError::InvalidState(
                "local upload source changed while its immutable snapshot was made".to_string(),
            ));
        }
        Ok((
            LocalEntry {
                relative_path: relative_path.to_path_buf(),
                content_hash: Some(content_hash),
                size_bytes: copied,
                is_directory: false,
                directory_identity: None,
            },
            destination,
        ))
    })();
    match snapshot {
        Ok((local, payload_file)) => Ok(UploadSnapshot {
            area,
            batch,
            payload_file: Mutex::new(Some(payload_file)),
            local,
        }),
        Err(error) => {
            let _ = retire_owned_staging_batch(&area, &batch);
            Err(error)
        }
    }
}

pub(super) fn upload_source_still_matches(
    root: &Path,
    snapshot: &UploadSnapshot,
    local_read_budget: &mut ReadBudget,
) -> CoreResult<bool> {
    Ok(
        current_local_entry_with_budget(root, &snapshot.local.relative_path, local_read_budget)?
            .is_some_and(|current| current == snapshot.local),
    )
}

pub(super) fn plan_gate(
    planned_local: &LocalEntry,
    snapshot: &UploadSnapshot,
) -> Option<NonDeleteExecution> {
    if shellx_drive_desktop_core::upload_precondition_matches(planned_local, &snapshot.local) {
        return None;
    }
    let _ = retire_upload_snapshot(snapshot);
    Some(NonDeleteExecution::NeedsReview(vec![
        upload_source_race_review(&planned_local.relative_path),
    ]))
}

pub(super) fn verify_upload_snapshot(snapshot: &UploadSnapshot) -> CoreResult<bool> {
    let mut file = snapshot
        .payload_file
        .lock()
        .expect("upload snapshot lock")
        .as_ref()
        .ok_or_else(|| {
            DesktopError::InvalidState("upload snapshot is already retired".to_string())
        })?
        .try_clone()?;
    file.seek(std::io::SeekFrom::Start(0))?;
    let (actual_hash, read) = hash_reader_bounded(&mut file, snapshot.local.size_bytes)?;
    Ok(read == snapshot.local.size_bytes
        && snapshot.local.content_hash.as_deref() == Some(actual_hash.as_str()))
}

pub(super) fn open_upload_snapshot(snapshot: &UploadSnapshot) -> CoreResult<fs::File> {
    let mut file = snapshot
        .payload_file
        .lock()
        .expect("upload snapshot lock")
        .as_ref()
        .ok_or_else(|| {
            DesktopError::InvalidState("upload snapshot is already retired".to_string())
        })?
        .try_clone()?;
    file.seek(std::io::SeekFrom::Start(0))?;
    Ok(file)
}

pub(super) fn upload_source_race_review(path: &Path) -> ReviewItem {
    ReviewItem {
            id: format!("upload-race:{}", path.display()),
            kind: ReviewKind::ContentConflict,
            relative_path: path.to_path_buf(),
            descendant_count: 0,
            is_directory: false,
            summary: "Local bytes changed while an immutable upload snapshot was in flight. The snapshot batch was discarded and the current local file was left untouched for review.".to_string(),
            actions: vec![ReviewAction::OpenConflictCopies],
        }
}

pub(super) fn upload_snapshot_failure_review(path: &Path, error: &DesktopError) -> ReviewItem {
    if matches!(error, DesktopError::UnsafeLink(_)) {
        return ReviewItem {
            id: format!("upload-unsafe-link:{}", path.display()),
            kind: ReviewKind::UnsafeLink,
            relative_path: path.to_path_buf(),
            descendant_count: 0,
            is_directory: false,
            summary: "The local file is a symbolic link, reparse point, or filesystem hard link. Drive did not read or upload it; replace it with an independent regular file, then recheck.".to_string(),
            actions: Vec::new(),
        };
    }
    upload_source_race_review(path)
}

pub(super) fn retire_upload_snapshot(snapshot: &UploadSnapshot) -> CoreResult<()> {
    snapshot
        .payload_file
        .lock()
        .expect("upload snapshot lock")
        .take();
    retire_owned_staging_batch(&snapshot.area, &snapshot.batch)
}

pub(super) fn remote_move_review(path: &Path, reason: &str) -> ReviewItem {
    ReviewItem {
        id: format!("remote-move-review:{}", path.display()),
        kind: ReviewKind::PathConflict,
        relative_path: path.to_path_buf(),
        descendant_count: 0,
        is_directory: false,
        summary: format!(
            "{reason} The local rename and current Drive item are preserved; no duplicate was uploaded."
        ),
        actions: vec![
            ReviewAction::RenameLocalCopy,
            ReviewAction::OpenConflictCopies,
        ],
    }
}

pub(super) fn inbound_move_review(from: &Path, to: &Path) -> ReviewItem {
    ReviewItem {
        id: format!("inbound-move-race:{}:{}", from.display(), to.display()),
        kind: ReviewKind::PathConflict,
        relative_path: to.to_path_buf(),
        descendant_count: 0,
        is_directory: false,
        summary: format!(
            "Drive could not atomically move the unchanged local file from {} to {}. Nothing was copied or overwritten, and no backup was created; verify both paths before rechecking.",
            from.display(),
            to.display(),
        ),
        actions: vec![
            ReviewAction::RenameLocalCopy,
            ReviewAction::OpenConflictCopies,
        ],
    }
}

pub(super) fn inbound_folder_move_review(
    from: &Path,
    to: &Path,
    precondition: &FolderMovePrecondition,
) -> ReviewItem {
    ReviewItem {
        id: format!(
            "inbound-folder-move-race:{}:{}",
            from.display(),
            to.display()
        ),
        kind: ReviewKind::PathConflict,
        relative_path: to.to_path_buf(),
        descendant_count: precondition.entries.len().saturating_sub(1),
        is_directory: true,
        summary: format!(
            "Drive could not atomically move the exact unchanged local folder from {} to {}. Nothing in the subtree was copied, overwritten, uploaded, or downloaded; inspect both paths before rechecking.",
            from.display(),
            to.display(),
        ),
        actions: vec![
            ReviewAction::RenameLocalCopy,
            ReviewAction::OpenConflictCopies,
        ],
    }
}

pub(super) fn inbound_folder_move_preflight_review(
    from: &Path,
    to: &Path,
    precondition: &FolderMovePrecondition,
) -> ReviewItem {
    ReviewItem {
        id: format!(
            "inbound-folder-move-drive-preflight:{}:{}",
            from.display(),
            to.display()
        ),
        kind: ReviewKind::PathConflict,
        relative_path: to.to_path_buf(),
        descendant_count: precondition.entries.len().saturating_sub(1),
        is_directory: true,
        summary: format!(
            "Drive changed the tracked folder subtree before its local move from {} to {} could start. The local folder was left in place; nothing in this subtree was moved, copied, overwritten, uploaded, or downloaded.",
            from.display(),
            to.display(),
        ),
        actions: vec![
            ReviewAction::RenameLocalCopy,
            ReviewAction::OpenConflictCopies,
        ],
    }
}

pub(super) fn inbound_folder_move_postmove_review(
    from: &Path,
    to: &Path,
    precondition: &FolderMovePrecondition,
) -> ReviewItem {
    ReviewItem {
        id: format!(
            "inbound-folder-move-drive-postmove:{}:{}",
            from.display(),
            to.display()
        ),
        kind: ReviewKind::PathConflict,
        relative_path: to.to_path_buf(),
        descendant_count: precondition.entries.len().saturating_sub(1),
        is_directory: true,
        summary: format!(
            "The local folder move from {} to {} completed, but Drive changed again before any descendant action or baseline update could run. No further local or Drive mutation was attempted; the prior baseline was retained for review.",
            from.display(),
            to.display(),
        ),
        actions: vec![
            ReviewAction::RenameLocalCopy,
            ReviewAction::OpenConflictCopies,
        ],
    }
}

/// Executor-level witness seam for the two refetches around a native
/// inbound folder root move. Returning `NeedsReview` exits the enclosing
/// non-delete loop, so no planned child action can run and the caller
/// retains the prior baseline instead of adopting an unchecked subtree.
pub(super) fn execute_inbound_folder_move_preflight<Move>(
    from: &Path,
    to: &Path,
    precondition: &FolderMovePrecondition,
    preflight_matches: bool,
    native_move: Move,
) -> CoreResult<NonDeleteExecution>
where
    Move: FnOnce() -> CoreResult<()>,
{
    if !preflight_matches {
        return Ok(NonDeleteExecution::NeedsReview(vec![
            inbound_folder_move_preflight_review(from, to, precondition),
        ]));
    }
    if native_move().is_err() {
        return Ok(NonDeleteExecution::NeedsReview(vec![
            inbound_folder_move_review(from, to, precondition),
        ]));
    }
    Ok(NonDeleteExecution::Complete)
}

pub(super) fn finish_inbound_folder_move_postflight(
    from: &Path,
    to: &Path,
    precondition: &FolderMovePrecondition,
    postflight_matches: bool,
) -> NonDeleteExecution {
    if !postflight_matches {
        return NonDeleteExecution::NeedsReview(vec![inbound_folder_move_postmove_review(
            from,
            to,
            precondition,
        )]);
    }
    NonDeleteExecution::Complete
}

pub(super) fn remote_folder_move_review(
    path: &Path,
    precondition: &FolderMovePrecondition,
) -> ReviewItem {
    ReviewItem {
            id: format!("remote-folder-move-review:{}", path.display()),
            kind: ReviewKind::PathConflict,
            relative_path: path.to_path_buf(),
            descendant_count: precondition.entries.len().saturating_sub(1),
            is_directory: true,
            summary: "The local folder changed after its move was planned, so Drive was not asked to move the folder. Nothing in that subtree was uploaded or overwritten.".to_string(),
            actions: vec![ReviewAction::RenameLocalCopy, ReviewAction::OpenConflictCopies],
        }
}

pub(super) fn finish_outbound_folder_move_postpatch(
    path: &Path,
    precondition: &FolderMovePrecondition,
    local_subtree_still_matches: bool,
) -> NonDeleteExecution {
    if !local_subtree_still_matches {
        return NonDeleteExecution::NeedsReview(vec![ReviewItem {
                id: format!("remote-folder-move-postpatch:{}", path.display()),
                kind: ReviewKind::PathConflict,
                relative_path: path.to_path_buf(),
                descendant_count: precondition.entries.len().saturating_sub(1),
                is_directory: true,
                summary: "Drive accepted the folder rename, but the local folder subtree changed before remaining sync actions could run. No child action or baseline update was attempted; the prior baseline was retained for review.".to_string(),
                actions: vec![ReviewAction::RenameLocalCopy, ReviewAction::OpenConflictCopies],
            }]);
    }
    NonDeleteExecution::Complete
}

pub(super) async fn inbound_folder_remote_witness_matches_now(
    client: &DriveHttpClient,
    token: &str,
    pair: &SyncPair,
    sync_root: &SyncRoot,
    precondition: &FolderMovePrecondition,
) -> CoreResult<bool> {
    let manifest = client.sync_root_manifest(token, sync_root).await?;
    let remote = manifest
        .files
        .into_iter()
        .map(remote_entry)
        .collect::<CoreResult<Vec<_>>>()?;
    Ok(folder_remote_witness_matches(
        precondition,
        pair.remote_root_id.as_deref(),
        &remote,
    ))
}

#[cfg(test)]
pub(super) fn move_unchanged_local_path(
    root: &Path,
    from: &Path,
    to: &Path,
    precondition: &DownloadPrecondition,
) -> CoreResult<()> {
    let mut local_read_budget = local_read_budget_for_sync_pass();
    move_unchanged_local_path_before_native_with_budget(
        root,
        from,
        to,
        precondition,
        &mut local_read_budget,
        || Ok(()),
    )
}

pub(super) fn move_unchanged_local_path_with_budget(
    root: &Path,
    from: &Path,
    to: &Path,
    precondition: &DownloadPrecondition,
    local_read_budget: &mut ReadBudget,
) -> CoreResult<()> {
    move_unchanged_local_path_before_native_with_budget(
        root,
        from,
        to,
        precondition,
        local_read_budget,
        || Ok(()),
    )
}

#[cfg(test)]
pub(super) fn move_unchanged_local_path_before_native<F>(
    root: &Path,
    from: &Path,
    to: &Path,
    precondition: &DownloadPrecondition,
    before_native: F,
) -> CoreResult<()>
where
    F: FnOnce() -> CoreResult<()>,
{
    let mut local_read_budget = local_read_budget_for_sync_pass();
    move_unchanged_local_path_before_native_with_budget(
        root,
        from,
        to,
        precondition,
        &mut local_read_budget,
        before_native,
    )
}

pub(super) fn move_unchanged_local_path_before_native_with_budget<F>(
    root: &Path,
    from: &Path,
    to: &Path,
    precondition: &DownloadPrecondition,
    local_read_budget: &mut ReadBudget,
    before_native: F,
) -> CoreResult<()>
where
    F: FnOnce() -> CoreResult<()>,
{
    let source = local_target(root, from)?;
    let destination = local_target(root, to)?;
    require_existing_local_move_parent(root, &destination)?;
    let current_source = current_local_entry_with_budget(root, from, local_read_budget)?;
    if !download_precondition_matches(precondition, current_source.as_ref()) {
        return Err(DesktopError::InvalidState(
            "local source changed before Drive could apply the remote move".to_string(),
        ));
    }
    if current_local_entry_with_budget(root, to, local_read_budget)?.is_some() {
        return Err(DesktopError::InvalidState(
            "Drive move destination is already occupied".to_string(),
        ));
    }
    move_existing_entry_by_verified_parent(root, &source, &destination, root, || {
        if !download_precondition_matches(
            precondition,
            current_local_entry_with_budget(root, from, local_read_budget)?.as_ref(),
        ) || current_local_entry_with_budget(root, to, local_read_budget)?.is_some()
        {
            return Err(DesktopError::InvalidState(
                "local move inputs changed before the native rename".to_string(),
            ));
        }
        before_native()
    })
}

#[cfg(test)]
pub(super) fn folder_move_source_still_matches(
    root: &Path,
    folder_root: &Path,
    precondition: &FolderMovePrecondition,
) -> CoreResult<bool> {
    let mut local_read_budget = local_read_budget_for_sync_pass();
    folder_move_source_still_matches_with_budget(
        root,
        folder_root,
        precondition,
        &mut local_read_budget,
    )
}

pub(super) fn folder_move_source_still_matches_with_budget(
    root: &Path,
    folder_root: &Path,
    precondition: &FolderMovePrecondition,
    local_read_budget: &mut ReadBudget,
) -> CoreResult<bool> {
    if capture_directory_identity(root, folder_root).ok().as_ref() != Some(&precondition.identity) {
        return Ok(false);
    }
    // Strict scanning rejects reparse points and unsupported local entries;
    // compare all saved rows so a child edit/add/remove cannot ride along
    // with an otherwise valid root identity.
    let inspection =
        inspect_local_tree_with_directory_identities_with_budget(root, local_read_budget)?;
    if !inspection.issues.is_empty() {
        return Ok(false);
    }
    let local = inspection.entries;
    Ok(
        shellx_drive_desktop_core::folder_subtree_matches_precondition(
            precondition,
            folder_root,
            &local,
        ),
    )
}

#[cfg(test)]
pub(super) fn move_unchanged_local_folder(
    root: &Path,
    from: &Path,
    to: &Path,
    precondition: &DownloadPrecondition,
    folder_precondition: &FolderMovePrecondition,
) -> CoreResult<()> {
    let mut local_read_budget = local_read_budget_for_sync_pass();
    move_unchanged_local_folder_with_budget(
        root,
        from,
        to,
        precondition,
        folder_precondition,
        &mut local_read_budget,
    )
}

pub(super) fn move_unchanged_local_folder_with_budget(
    root: &Path,
    from: &Path,
    to: &Path,
    precondition: &DownloadPrecondition,
    folder_precondition: &FolderMovePrecondition,
    local_read_budget: &mut ReadBudget,
) -> CoreResult<()> {
    move_unchanged_local_folder_before_native_with_budget(
        root,
        from,
        to,
        precondition,
        folder_precondition,
        local_read_budget,
        || Ok(()),
    )
}

pub(super) fn move_unchanged_local_folder_before_native_with_budget<F>(
    root: &Path,
    from: &Path,
    to: &Path,
    precondition: &DownloadPrecondition,
    folder_precondition: &FolderMovePrecondition,
    local_read_budget: &mut ReadBudget,
    before_native: F,
) -> CoreResult<()>
where
    F: FnOnce() -> CoreResult<()>,
{
    let source = local_target(root, from)?;
    let destination = local_target(root, to)?;
    require_existing_local_move_parent(root, &destination)?;
    let current_source = current_local_entry_with_budget(root, from, local_read_budget)?;
    if !download_precondition_matches(precondition, current_source.as_ref())
        || !folder_move_source_still_matches_with_budget(
            root,
            from,
            folder_precondition,
            local_read_budget,
        )?
    {
        return Err(DesktopError::InvalidState(
                "local folder subtree or NTFS identity changed before Drive could apply the remote move"
                    .to_string(),
            ));
    }
    // A completed inbound move is recognised by the planner. A pending
    // native move always needs a wholly absent destination subtree; never
    // merge or replace a user-created folder.
    if current_local_entry_with_budget(root, to, local_read_budget)?.is_some() {
        return Err(DesktopError::InvalidState(
            "Drive folder move destination is already occupied".to_string(),
        ));
    }
    move_existing_entry_by_verified_parent(root, &source, &destination, root, || {
        if !download_precondition_matches(
            precondition,
            current_local_entry_with_budget(root, from, local_read_budget)?.as_ref(),
        ) || !folder_move_source_still_matches_with_budget(
            root,
            from,
            folder_precondition,
            local_read_budget,
        )? || current_local_entry_with_budget(root, to, local_read_budget)?.is_some()
        {
            return Err(DesktopError::InvalidState(
                "local folder move inputs changed before the native rename".to_string(),
            ));
        }
        before_native()
    })
}

/// The handle-relative rename never creates a parent. Requiring a parent that
/// was separately planned/verified avoids `create_dir_all` walking a
/// junction or reparse point before the move's no-follow boundary checks.
pub(super) fn require_existing_local_move_parent(
    root: &Path,
    destination: &Path,
) -> CoreResult<()> {
    let parent = destination.parent().ok_or_else(|| {
        DesktopError::UnsafePath("move destination has no local parent".to_string())
    })?;
    // Capture the destination rather than the parent itself. For a root-level
    // move the parent is exactly `root`, whose relative path is intentionally
    // empty and therefore is not a valid file path. Capturing the destination
    // still pins and verifies the root plus every existing parent component,
    // while also failing closed if a destination appears during this check.
    let boundary = capture_local_operation_boundary(root, destination)?;
    if !fs::symlink_metadata(parent)?.is_dir() {
        return Err(DesktopError::UnsafePath(
            "move destination parent is not a verified directory".to_string(),
        ));
    }
    verify_local_operation_boundary(&boundary)
}

/// Open a no-reparse source handle with `DELETE` access and keep it live
/// through `SetFileInformationByHandle`. The source is therefore the
/// checked object even if its pathname changes while an operation is
/// pending.
pub(super) fn open_checked_rename_source(root: &Path, source: &Path) -> CoreResult<fs::File> {
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let boundary = capture_local_operation_boundary(root, source)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .access_mode(DELETE | FILE_READ_ATTRIBUTES)
        // Withhold FILE_SHARE_DELETE until the rename completes. This
        // blocks an attacker from moving/deleting this opened source or
        // any separately pinned ancestor during the final window.
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(source)?;
    if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(DesktopError::UnsafeLink(source.to_path_buf()));
    }
    verify_local_operation_boundary(&boundary)?;
    Ok(file)
}

/// Open one no-reparse directory with FILE_SHARE_DELETE deliberately
/// withheld. Holding the handle prevents a concurrent rename/delete of
/// that directory until the native rename returns.
pub(super) fn open_checked_rename_directory(path: &Path) -> CoreResult<fs::File> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_TRAVERSE,
    };

    let file = fs::OpenOptions::new()
        .read(true)
        .access_mode(FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | FILE_TRAVERSE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(DesktopError::UnsafeLink(path.to_path_buf()));
    }
    Ok(file)
}

/// Open the exact destination parent with the add-child access used while
/// resolving `FILE_RENAME_INFO::RootDirectory`. Keeping this separate means
/// read-only ancestor pins never require write rights.
pub(super) fn open_checked_rename_target_directory(
    path: &Path,
    source_is_directory: bool,
) -> CoreResult<fs::File> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
        FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, SYNCHRONIZE,
    };

    let add_child = if source_is_directory {
        FILE_ADD_SUBDIRECTORY
    } else {
        FILE_ADD_FILE
    };
    let file = fs::OpenOptions::new()
        .read(true)
        .access_mode(
            FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | FILE_TRAVERSE | SYNCHRONIZE | add_child,
        )
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(DesktopError::UnsafeLink(path.to_path_buf()));
    }
    Ok(file)
}

/// Pin every absolute directory component from the Windows volume/share
/// root through `path`. Each handle rejects reparse points and withholds
/// delete sharing, so no already-checked ancestor can be renamed or
/// replaced while the returned vector remains live.
pub(super) fn pin_absolute_directory_chain(path: &Path) -> CoreResult<Vec<fs::File>> {
    use std::path::Component;

    if !path.is_absolute() {
        return Err(DesktopError::UnsafePath(format!(
            "local root is not absolute: {}",
            path.display()
        )));
    }

    let mut current = PathBuf::new();
    let mut handles = Vec::new();
    let mut saw_root = false;
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => {
                current.push(component.as_os_str());
                handles.push(open_checked_rename_directory(&current)?);
                saw_root = true;
            }
            Component::Normal(name) if saw_root => {
                current.push(name);
                handles.push(open_checked_rename_directory(&current)?);
            }
            Component::Normal(_) | Component::CurDir | Component::ParentDir => {
                return Err(DesktopError::UnsafePath(format!(
                    "local root contains an unsafe absolute component: {}",
                    path.display()
                )));
            }
        }
    }
    if !saw_root || handles.is_empty() {
        return Err(DesktopError::UnsafePath(format!(
            "local root has no pinnable Windows root: {}",
            path.display()
        )));
    }
    Ok(handles)
}

/// Hold the checked pin root and every existing directory through the
/// final destination parent. `RootDirectory` alone binds the leaf's
/// parent, but these no-delete handles also prevent that parent or any
/// ancestor from being renamed out of the intended tree during the call.
pub(super) fn pin_checked_rename_directory_chain(
    root: &Path,
    parent: &Path,
) -> CoreResult<Vec<fs::File>> {
    let relative = parent.strip_prefix(root).map_err(|_| {
        DesktopError::UnsafePath(format!(
            "rename parent escapes its checked root: {}",
            parent.display()
        ))
    })?;
    let boundary = if relative.as_os_str().is_empty() {
        None
    } else {
        Some(capture_local_operation_boundary(root, parent)?)
    };
    let mut handles = pin_absolute_directory_chain(root)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(DesktopError::UnsafePath(
                "rename parent has a non-normal relative component".to_string(),
            ));
        };
        current.push(name);
        handles.push(open_checked_rename_directory(&current)?);
    }
    if let Some(boundary) = boundary.as_ref() {
        verify_local_operation_boundary(boundary)?;
    }
    Ok(handles)
}

/// Rename an existing source into a checked destination-parent handle with
/// a single leaf name and `ReplaceIfExists=false`. Holding both handles
/// closes the final pathname-parent reparse swap: Windows resolves the
/// destination relative to `RootDirectory`, never the later pathname.
fn rename_existing_entry_by_verified_parent<F>(
    source_root: &Path,
    source: &Path,
    destination: &Path,
    destination_pin_root: &Path,
    replace_if_exists: bool,
    before_native: F,
) -> CoreResult<()>
where
    F: FnOnce() -> CoreResult<()>,
{
    let parent = destination.parent().ok_or_else(|| {
        DesktopError::UnsafePath("move destination has no local parent".to_string())
    })?;
    let leaf = destination.file_name().ok_or_else(|| {
        DesktopError::UnsafePath("move destination has no local leaf name".to_string())
    })?;
    // Pin source-root ancestry too: even though the source object is
    // handle-bound, this prevents its intended in-root containment from
    // being renamed away while its final precondition is checked.
    let source_parent = source
        .parent()
        .ok_or_else(|| DesktopError::UnsafePath("move source has no local parent".to_string()))?;
    let _source_pins = pin_checked_rename_directory_chain(source_root, source_parent)?;
    let source_handle = open_checked_rename_source(source_root, source)?;
    let source_is_directory = source_handle.metadata()?.is_dir();
    let destination_pins = pin_checked_rename_directory_chain(destination_pin_root, parent)?;
    destination_pins.last().ok_or_else(|| {
        DesktopError::UnsafePath("move destination has no pinned parent".to_string())
    })?;
    let parent_handle = open_checked_rename_target_directory(parent, source_is_directory)?;

    // This deterministic seam runs only after both directory objects are
    // bound. Tests may replace the visible parent pathname here; either
    // the operation fails closed or it lands in this still-open original
    // parent handle, never in the substituted junction target.
    before_native()?;

    rename_open_file_at(&source_handle, &parent_handle, leaf, replace_if_exists)
}

pub(super) fn move_existing_entry_by_verified_parent<F>(
    source_root: &Path,
    source: &Path,
    destination: &Path,
    destination_pin_root: &Path,
    before_native: F,
) -> CoreResult<()>
where
    F: FnOnce() -> CoreResult<()>,
{
    rename_existing_entry_by_verified_parent(
        source_root,
        source,
        destination,
        destination_pin_root,
        false,
        before_native,
    )
}

#[cfg(test)]
pub(super) fn replace_existing_entry_by_verified_parent<F>(
    source_root: &Path,
    source: &Path,
    destination: &Path,
    destination_pin_root: &Path,
    before_native: F,
) -> CoreResult<()>
where
    F: FnOnce() -> CoreResult<()>,
{
    rename_existing_entry_by_verified_parent(
        source_root,
        source,
        destination,
        destination_pin_root,
        true,
        before_native,
    )
}

pub(super) struct RemoteBodySpec<'a> {
    pub(super) remote_id: &'a str,
    pub(super) expected_hash: Option<&'a str>,
    pub(super) expected_size: u64,
}

pub(super) async fn write_remote_body(
    client: &DriveHttpClient,
    token: &str,
    root: &Path,
    relative_path: &Path,
    remote: RemoteBodySpec<'_>,
    precondition: &DownloadPrecondition,
    local_read_budget: &mut ReadBudget,
) -> CoreResult<DownloadPublication> {
    let destination = local_target(root, relative_path)?;
    let destination_boundary = capture_local_operation_boundary(root, &destination)?;
    ensure_windows_download_free_space(root, remote.expected_size)?;
    let staging_root = download_staging_root(root)?;
    let (staging_area, batch) = create_owned_staging_batch(root, &staging_root, "download")?;
    let staged = batch.join("payload");
    let verified = match write_remote_body_to_path(
        client,
        token,
        &staging_area,
        &batch,
        &staged,
        remote,
    )
    .await
    {
        Ok(verified) => verified,
        Err(error) => {
            let _ = retire_owned_staging_batch(&staging_area, &batch);
            return Err(error);
        }
    };
    let publication = publish_staged_download_with_budget(
        root,
        relative_path,
        &destination,
        &staged,
        &verified,
        precondition,
        &destination_boundary,
        local_read_budget,
        Some((&staging_area, &batch)),
    );
    drop(verified);
    if publication.is_err() || matches!(&publication, Ok(DownloadPublication::NeedsReview { .. })) {
        let _ = retire_owned_staging_batch(&staging_area, &batch);
    } else {
        retire_owned_staging_batch(&staging_area, &batch)?;
    }
    publication
}

/// Download a verified body into a caller-selected path. Restore uses this
/// only inside an app-owned sibling staging directory; normal mirror work
/// reaches it through `write_remote_body` after validating the pair root.
pub(super) async fn write_remote_body_to_path(
    client: &DriveHttpClient,
    token: &str,
    staging_area: &OwnedStagingRoot,
    batch: &Path,
    destination: &Path,
    remote: RemoteBodySpec<'_>,
) -> CoreResult<VerifiedStagedFile> {
    ensure_windows_download_free_space(staging_area.root(), remote.expected_size)?;
    if batch.parent() != Some(staging_area.root()) || !destination.starts_with(batch) {
        return Err(DesktopError::UnsafePath(
            "private staging destination escapes its owned batch".to_string(),
        ));
    }
    let parent = destination.parent().ok_or_else(|| {
        DesktopError::UnsafePath("private staging destination has no parent".to_string())
    })?;
    let parent_relative = parent.strip_prefix(batch).map_err(|_| {
        DesktopError::UnsafePath("private staging parent escapes its batch".to_string())
    })?;
    ensure_local_directory(batch, parent_relative)?;
    // Hold the complete existing directory chain without delete sharing
    // until the create-new payload handle is open.
    let _staging_pins = pin_checked_rename_directory_chain(batch, parent)?;
    let create_parent = open_create_parent(parent)?;
    let destination_leaf = destination.file_name().ok_or_else(|| {
        DesktopError::UnsafePath("private staging destination has no leaf".to_string())
    })?;
    let mut file = create_new_file_at(
        &create_parent,
        destination_leaf,
        windows_sys::Win32::Foundation::GENERIC_WRITE
            | windows_sys::Win32::Storage::FileSystem::DELETE
            | windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES
            | windows_sys::Win32::Storage::FileSystem::READ_CONTROL
            | windows_sys::Win32::Storage::FileSystem::WRITE_DAC
            | windows_sys::Win32::Storage::FileSystem::WRITE_OWNER,
    )?;
    // Narrow the newly-created payload before remote bytes enter it. The
    // staging directory is private too, but the file carries its own protected
    // current-user-only DACL so a later directory ACL change cannot expose it.
    shellx_drive_desktop_core::validate_private_staging_file(&file)?;
    let mut hasher = Sha256::new();
    let transfer = client
        .download_file_chunks(token, remote.remote_id, remote.expected_size, |chunk| {
            hasher.update(chunk);
            file.write_all(chunk)
        })
        .await;
    if let Err(error) = transfer {
        let _ = delete_open_file(&file);
        drop(file);
        return Err(error);
    }
    file.sync_all()?;
    let actual_hash = hex_digest(hasher.finalize().as_slice());
    if remote.expected_hash != Some(actual_hash.as_str()) {
        let _ = delete_open_file(&file);
        drop(file);
        return Err(DesktopError::InvalidState(format!(
            "downloaded body hash did not match Drive for {}",
            destination.display()
        )));
    }
    shellx_drive_desktop_core::validate_private_staging_file(&file)?;
    Ok(VerifiedStagedFile(file))
}

pub(super) fn remote_download_size(remote: &RemoteEntry) -> CoreResult<u64> {
    remote.size_bytes.ok_or_else(|| {
        DesktopError::InvalidState(format!(
            "Drive manifest omitted the size of remote file {}",
            remote.id
        ))
    })
}

pub(super) fn ensure_windows_download_free_space(
    path: &Path,
    payload_bytes: u64,
) -> CoreResult<()> {
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

    let required = payload_bytes
        .checked_add(DESKTOP_SYNC_FREE_SPACE_RESERVE_BYTES)
        .ok_or_else(|| {
            DesktopError::InvalidState(
                "sync download free-space requirement overflowed".to_string(),
            )
        })?;
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut available = 0u64;
    let result = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut available,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if result == 0 {
        return Err(DesktopError::Io(std::io::Error::last_os_error()));
    }
    if available < required {
        return Err(DesktopError::InvalidState(format!(
            "sync download requires {required} free bytes including reserve; only {available} are available"
        )));
    }
    Ok(())
}

pub(super) fn open_owned_staging(
    local_root: &Path,
    staging_root: &Path,
    kind: &str,
) -> CoreResult<OwnedStagingRoot> {
    let area = initialize_owned_staging_root(local_root, staging_root, kind)?;
    // Prevent replacement of the staging root or any absolute ancestor
    // while aged cleanup resolves batch paths.
    let _root_pins = pin_absolute_directory_chain(area.root())?;
    // A startup/next-run sweep has one fixed scope: only marker-bound
    // batches older than a day. Unknown children make this return an error
    // before anything is deleted.
    area.cleanup_aged_batches(Duration::from_secs(24 * 60 * 60))?;
    Ok(area)
}

pub(super) fn create_owned_staging_batch(
    local_root: &Path,
    staging_root: &Path,
    kind: &str,
) -> CoreResult<(OwnedStagingRoot, PathBuf)> {
    let area = open_owned_staging(local_root, staging_root, kind)?;
    let batch = area.create_batch(NEXT_STAGING_BATCH.fetch_add(1, Ordering::AcqRel))?;
    Ok((area, batch))
}

pub(super) fn retire_owned_staging_batch(area: &OwnedStagingRoot, batch: &Path) -> CoreResult<()> {
    // `remove_dir_all` does not follow the final symlink/reparse point, and
    // these pins prevent every staging-root ancestor from being redirected
    // between marker validation and recursive cleanup.
    let _root_pins = pin_absolute_directory_chain(area.root())?;
    area.remove_batch(batch)
}

pub(super) fn current_local_entry_with_budget(
    root: &Path,
    relative_path: &Path,
    local_read_budget: &mut ReadBudget,
) -> CoreResult<Option<LocalEntry>> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let target = local_target(root, relative_path)?;
    let boundary = capture_local_operation_boundary(root, &target)?;
    let metadata = match fs::symlink_metadata(&target) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(DesktopError::Io(error)),
    };
    if metadata.is_dir() {
        verify_local_operation_boundary(&boundary)?;
        return Ok(Some(LocalEntry {
            relative_path: relative_path.to_path_buf(),
            content_hash: None,
            size_bytes: 0,
            is_directory: true,
            directory_identity: None,
        }));
    }
    if !metadata.is_file() {
        return Err(DesktopError::UnsafePath(format!(
            "download destination is not a regular file: {}",
            relative_path.display()
        )));
    }
    // Open the reparse point itself and stream only this target. This is
    // intentionally not a full-tree rescan for each planned download.
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&target)?;
    if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(DesktopError::UnsafeLink(target));
    }
    shellx_drive_desktop_core::ensure_single_linked_regular_file(&file, &target)?;
    let opened_metadata = file.metadata()?;
    let max_file_bytes = LocalScanLimits::default().max_file_bytes;
    if opened_metadata.len() > max_file_bytes {
        return Err(DesktopError::InvalidState(format!(
            "local file exceeds the {max_file_bytes}-byte scan limit: {}",
            relative_path.display()
        )));
    }
    local_read_budget.charge(opened_metadata.len())?;
    let (content_hash, actual_bytes) =
        shellx_drive_desktop_core::hash_reader_bounded(&mut file, opened_metadata.len())?;
    if actual_bytes != opened_metadata.len() {
        return Err(DesktopError::InvalidState(
            "local file changed while its post-scan state was read".to_string(),
        ));
    }
    verify_local_operation_boundary(&boundary)?;
    Ok(Some(LocalEntry {
        relative_path: relative_path.to_path_buf(),
        content_hash: Some(content_hash),
        size_bytes: actual_bytes,
        is_directory: false,
        directory_identity: None,
    }))
}

#[cfg(test)]
pub(super) fn verify_and_build_baseline(
    pair: &SyncPair,
    remote: &[RemoteEntry],
    prior_baseline: &BTreeMap<String, BaselineEntry>,
) -> CoreResult<BaselineFinalization> {
    let mut local_read_budget = local_read_budget_for_sync_pass();
    verify_and_build_baseline_with_budget(pair, remote, prior_baseline, &mut local_read_budget)
}

pub(super) fn verify_and_build_baseline_with_budget(
    pair: &SyncPair,
    remote: &[RemoteEntry],
    prior_baseline: &BTreeMap<String, BaselineEntry>,
    local_read_budget: &mut ReadBudget,
) -> CoreResult<BaselineFinalization> {
    ensure_tree_has_no_links(&pair.local_root)?;
    let remote_paths = map_remote_paths(remote, pair.remote_root_id.as_deref())?;
    let inspection = inspect_local_tree_with_directory_identities_with_budget(
        &pair.local_root,
        local_read_budget,
    )?;
    if let Some(issue) = inspection.issues.first() {
        return Err(DesktopError::UnsafePath(format!(
            "{}: {}",
            issue.path.display(),
            issue.reason
        )));
    }
    let local = inspection.entries;
    let local_by_path = local
        .iter()
        .map(|entry| (entry.relative_path.as_path(), entry))
        .collect::<HashMap<_, _>>();
    // The post-move Drive witness closes the action-time race, but Drive
    // can still change once more between that postflight and this final
    // fresh manifest. If the saved folder identity appears exactly once
    // at an intermediate local Q while the same remote ID now maps to R,
    // report that truthful P→Q→R state rather than treating missing R as
    // a generic publication error or adopting Q under R's remote ID.
    let mut moved_again = Vec::<(&BaselineEntry, PathBuf, PathBuf, bool)>::new();
    for remote in remote.iter().filter(|entry| !entry.trashed) {
        if remote.kind != RemoteEntryKind::Folder {
            continue;
        }
        let Some(saved) = prior_baseline.get(&remote.id) else {
            continue;
        };
        let Some(identity) = saved.directory_identity.as_ref() else {
            continue;
        };
        let Some(expected_path) = remote_paths.get(&remote.id) else {
            continue;
        };
        let matches = local
            .iter()
            .filter(|entry| {
                entry.is_directory && entry.directory_identity.as_ref() == Some(identity)
            })
            .map(|entry| entry.relative_path.clone())
            .collect::<Vec<_>>();
        if matches.len() == 1 && matches[0] != saved.relative_path && matches[0] != *expected_path {
            let destination_is_occupied = local_by_path
                .get(expected_path.as_path())
                .is_some_and(|entry| entry.directory_identity.as_ref() != Some(identity));
            moved_again.push((
                saved,
                matches[0].clone(),
                expected_path.clone(),
                destination_is_occupied,
            ));
        }
    }
    if let Some((saved, intermediate_path, expected_path, destination_is_occupied)) =
        moved_again.into_iter().min_by(
            |(left, left_intermediate, _, _), (right, right_intermediate, _, _)| {
                left.relative_path
                    .components()
                    .count()
                    .cmp(&right.relative_path.components().count())
                    .then_with(|| left_intermediate.cmp(right_intermediate))
            },
        )
    {
        let descendant_count = prior_baseline
            .values()
            .filter(|entry| entry.relative_path.starts_with(&saved.relative_path))
            .count()
            .saturating_sub(1);
        return Ok(BaselineFinalization::NeedsReview(ReviewItem {
            id: format!(
                "final-folder-moved-again:{}:{}:{}",
                saved.relative_path.display(),
                intermediate_path.display(),
                expected_path.display()
            ),
            kind: ReviewKind::PathConflict,
            relative_path: intermediate_path.clone(),
            descendant_count,
            is_directory: true,
            summary: if destination_is_occupied {
                format!(
                    "The local folder move from {} to {} completed, but Drive moved the same tracked folder again to {} before final verification; that new local destination is already occupied by a different local item. The prior baseline was retained and no further descendant action ran; inspect both Drive and local locations before rechecking.",
                    saved.relative_path.display(),
                    intermediate_path.display(),
                    expected_path.display(),
                )
            } else {
                format!(
                    "The local folder move from {} to {} completed, but Drive moved the same tracked folder again to {} before final verification. The prior baseline was retained and no further descendant action ran; inspect both Drive and local locations before rechecking.",
                    saved.relative_path.display(),
                    intermediate_path.display(),
                    expected_path.display(),
                )
            },
            actions: vec![
                ReviewAction::RenameLocalCopy,
                ReviewAction::OpenConflictCopies,
            ],
        }));
    }
    let mut baseline = BTreeMap::new();
    let mut identity_mismatches = Vec::<PathBuf>::new();
    for remote in remote.iter().filter(|entry| !entry.trashed) {
        let Some(path) = remote_paths.get(&remote.id) else {
            continue;
        };
        let local = local_by_path.get(path.as_path()).ok_or_else(|| {
            DesktopError::InvalidState(format!(
                "Drive item did not publish locally: {}",
                path.display()
            ))
        })?;
        if !same_kind(remote, local.is_directory)
            || (!local.is_directory && local.content_hash != remote.content_hash)
        {
            return Err(DesktopError::InvalidState(format!(
                "Drive and local bytes differ after sync: {}",
                path.display()
            )));
        }
        if remote.kind == RemoteEntryKind::Folder
            && prior_baseline
                .get(&remote.id)
                .and_then(|saved| saved.directory_identity.as_ref())
                .is_some_and(|saved_identity| {
                    local.directory_identity.as_ref() != Some(saved_identity)
                })
        {
            identity_mismatches.push(path.clone());
        }
        baseline.insert(
            remote.id.clone(),
            BaselineEntry {
                remote_id: remote.id.clone(),
                parent_id: remote.parent_id.clone(),
                relative_path: path.clone(),
                kind: match remote.kind {
                    RemoteEntryKind::File => "file".to_string(),
                    RemoteEntryKind::Folder => "folder".to_string(),
                },
                content_hash: remote.content_hash.clone(),
                revision: remote.revision,
                directory_identity: local.directory_identity.clone(),
            },
        );
    }
    for local in &local {
        if !remote_paths
            .values()
            .any(|path| path == &local.relative_path)
        {
            return Err(DesktopError::InvalidState(format!(
                "local item did not publish to Drive: {}",
                local.relative_path.display()
            )));
        }
    }
    if let Some(path) = identity_mismatches.into_iter().min_by(|left, right| {
        left.components()
            .count()
            .cmp(&right.components().count())
            .then_with(|| left.cmp(right))
    }) {
        let descendant_count = remote_paths
            .values()
            .filter(|candidate| candidate.starts_with(&path))
            .count()
            .saturating_sub(1);
        return Ok(BaselineFinalization::NeedsReview(ReviewItem {
                id: format!("final-folder-identity:{}", path.display()),
                kind: ReviewKind::PathConflict,
                relative_path: path,
                descendant_count,
                is_directory: true,
                summary: "A tracked folder identity changed after the planned operation completed. The current local folder was left in place and the prior baseline was retained; inspect the folder and recheck before any further sync.".to_string(),
                actions: vec![ReviewAction::RenameLocalCopy, ReviewAction::OpenConflictCopies],
            }));
    }
    Ok(BaselineFinalization::Complete(baseline))
}

pub(super) fn same_kind(remote: &RemoteEntry, local_is_directory: bool) -> bool {
    matches!(
        (&remote.kind, local_is_directory),
        (RemoteEntryKind::File, false) | (RemoteEntryKind::Folder, true)
    )
}
