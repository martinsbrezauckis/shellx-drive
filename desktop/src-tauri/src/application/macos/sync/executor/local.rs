//! Descriptor-bound local witnesses for terminal moves.

use std::path::Path;

use shellx_drive_desktop_core::{
    download_precondition_matches, ensure_tree_has_no_links, folder_subtree_matches_precondition,
    DesktopError, DownloadPrecondition, LocalEntry, RemoteEntry, RemoteEntryKind,
    Result as CoreResult, SyncPair,
};

pub(super) fn download_matches(
    guard: &crate::platform::unix::filesystem::UnixRootGuard,
    destination: &Path,
    expected: &DownloadPrecondition,
) -> CoreResult<bool> {
    match expected {
        DownloadPrecondition::Absent => guard.local_entry_is_absent(destination),
        DownloadPrecondition::ExactLocal { .. } => {
            let current = match guard.local_regular_entry(destination) {
                Ok(current) => Some(current),
                Err(DesktopError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    None
                }
                Err(_) => return Ok(false),
            };
            Ok(download_precondition_matches(expected, current.as_ref()))
        }
    }
}

pub(super) fn planned_entry(path: &Path, expected: &DownloadPrecondition) -> Option<LocalEntry> {
    let DownloadPrecondition::ExactLocal {
        content_hash,
        size_bytes,
        is_directory,
    } = expected
    else {
        return None;
    };
    Some(LocalEntry {
        relative_path: path.to_path_buf(),
        content_hash: content_hash.clone(),
        size_bytes: *size_bytes,
        is_directory: *is_directory,
        directory_identity: None,
    })
}

pub(super) fn inbound_move_matches(
    guard: &crate::platform::unix::filesystem::UnixRootGuard,
    pair: &SyncPair,
    source: &Path,
    precondition: &DownloadPrecondition,
    folder: Option<&shellx_drive_desktop_core::FolderMovePrecondition>,
) -> CoreResult<bool> {
    let current = match folder {
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
    let Some(folder) = folder else {
        return Ok(true);
    };
    Ok(folder_subtree_matches_precondition(
        folder,
        source,
        &entries(guard, pair)?,
    ))
}

pub(super) fn outbound_move_matches(
    guard: &crate::platform::unix::filesystem::UnixRootGuard,
    pair: &SyncPair,
    destination: &Path,
    remote: &RemoteEntry,
    folder: Option<&shellx_drive_desktop_core::FolderMovePrecondition>,
) -> CoreResult<bool> {
    match (remote.kind.clone(), folder) {
        (RemoteEntryKind::File, None) => match guard.local_regular_entry(destination) {
            Ok(local) => Ok(local.content_hash == remote.content_hash
                && local.size_bytes == remote.size_bytes.unwrap_or(u64::MAX)),
            Err(_) => Ok(false),
        },
        (RemoteEntryKind::Folder, Some(folder)) => {
            if guard.local_directory_identity(destination).ok().as_ref() != Some(&folder.identity) {
                return Ok(false);
            }
            Ok(folder_subtree_matches_precondition(
                folder,
                destination,
                &entries(guard, pair)?,
            ))
        }
        _ => Ok(false),
    }
}

pub(super) fn entries(
    guard: &crate::platform::unix::filesystem::UnixRootGuard,
    pair: &SyncPair,
) -> CoreResult<Vec<LocalEntry>> {
    ensure_tree_has_no_links(&pair.local_root)?;
    let mut local = shellx_drive_desktop_core::inspect_local_tree(&pair.local_root)?;
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
