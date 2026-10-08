//! Descriptor-observed local preconditions for Linux reconciliation.

use super::*;

pub(super) fn local_move_matches(
    guard: &UnixRootGuard,
    pair: &SyncPair,
    source: &Path,
    precondition: &DownloadPrecondition,
    folder_precondition: Option<&shellx_drive_desktop_core::FolderMovePrecondition>,
) -> CoreResult<bool> {
    let current = match folder_precondition {
        Some(_) => Some(LocalEntry {
            relative_path: source.to_path_buf(),
            content_hash: None,
            size_bytes: 0,
            is_directory: true,
            directory_identity: Some(guard.local_directory_identity(source)?),
        }),
        None => match guard.local_regular_entry(source) {
            Ok(entry) => Some(entry),
            Err(DesktopError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Ok(false),
        },
    };
    if !download_precondition_matches(precondition, current.as_ref()) {
        return Ok(false);
    }
    let Some(folder) = folder_precondition else {
        return Ok(true);
    };
    let local = local_entries_with_directory_identities(guard, pair)?;
    Ok(folder_subtree_matches_precondition(folder, source, &local))
}

pub(super) fn outbound_local_move_matches(
    guard: &UnixRootGuard,
    pair: &SyncPair,
    destination: &Path,
    remote: &RemoteEntry,
    folder_precondition: Option<&shellx_drive_desktop_core::FolderMovePrecondition>,
) -> CoreResult<bool> {
    match (remote.kind.clone(), folder_precondition) {
        (RemoteEntryKind::File, None) => {
            let local = match guard.local_regular_entry(destination) {
                Ok(entry) => entry,
                Err(_) => return Ok(false),
            };
            Ok(local.content_hash == remote.content_hash
                && local.size_bytes == remote.size_bytes.unwrap_or(u64::MAX))
        }
        (RemoteEntryKind::Folder, Some(folder)) => {
            if guard.local_directory_identity(destination).ok().as_ref() != Some(&folder.identity) {
                return Ok(false);
            }
            let local = local_entries_with_directory_identities(guard, pair)?;
            Ok(folder_subtree_matches_precondition(
                folder,
                destination,
                &local,
            ))
        }
        _ => Ok(false),
    }
}

pub(super) fn local_entries_with_directory_identities(
    guard: &UnixRootGuard,
    pair: &SyncPair,
) -> CoreResult<Vec<LocalEntry>> {
    ensure_tree_has_no_links(&pair.local_root)?;
    let mut local = inspect_local_tree(&pair.local_root)?;
    if !local.issues.is_empty() {
        return Err(DesktopError::UnsafePath(
            "local Drive tree contains an unsupported path while a move was pending".to_string(),
        ));
    }
    for entry in local.entries.iter_mut().filter(|entry| entry.is_directory) {
        entry.directory_identity = Some(guard.local_directory_identity(&entry.relative_path)?);
    }
    Ok(local.entries)
}

/// Final hashing consumes the same cycle budget as planning and retries.
pub(super) fn final_local_entries(
    run: &SyncRun,
    local_reads: &mut ReadBudget,
    guard: &UnixRootGuard,
    pair: &SyncPair,
) -> CoreResult<Vec<LocalEntry>> {
    ensure_tree_has_no_links(&pair.local_root)?;
    let mut local =
        inspect_local_tree_with_budget_and_cancellation(&pair.local_root, local_reads, || {
            run.ensure_not_cancelled()
        })?;
    if !local.issues.is_empty() {
        return Err(DesktopError::UnsafePath(
            "local Drive tree contains an unsupported path during final reconciliation".to_string(),
        ));
    }
    guard.observe_directory_identities(&mut local, || run.ensure_not_cancelled())?;
    Ok(local.entries)
}
