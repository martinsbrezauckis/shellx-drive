use std::path::Path;

use shellx_drive_desktop_core::{
    map_remote_paths, BaselineEntry, DesktopError, RemoteEntry, RemoteEntryKind,
    Result as CoreResult, SyncPair,
};

pub(super) fn expected_kind(entry: &BaselineEntry) -> CoreResult<RemoteEntryKind> {
    match entry.kind.as_str() {
        "folder" => Ok(RemoteEntryKind::Folder),
        "file" => Ok(RemoteEntryKind::File),
        _ => Err(DesktopError::InvalidState(
            "the saved restore tree has an unknown item kind".to_string(),
        )),
    }
}

pub(super) fn validate_tree(
    saved: &[&BaselineEntry],
    pair: &SyncPair,
    remote: &[RemoteEntry],
) -> CoreResult<()> {
    let paths = map_remote_paths(remote, pair.remote_root_id.as_deref())?;
    for entry in saved {
        let expected = expected_kind(entry)?;
        let valid = remote
            .iter()
            .find(|current| current.id == entry.remote_id && !current.trashed)
            .is_some_and(|current| {
                current.kind == expected
                    && current.revision == entry.revision
                    && current.content_hash == entry.content_hash
                    && paths.get(&current.id) == Some(&entry.relative_path)
            });
        if !valid {
            return Err(DesktopError::InvalidState(
                "Drive changed this restore tree; no local bytes were overwritten".to_string(),
            ));
        }
    }
    Ok(())
}

pub(super) fn staged_relative(root: &Path, entry: &Path) -> CoreResult<std::path::PathBuf> {
    let relative = entry.strip_prefix(root).map_err(|_| {
        DesktopError::InvalidState(
            "the reviewed restore tree has an invalid descendant".to_string(),
        )
    })?;
    let staged = Path::new("payload").join(relative);
    shellx_drive_desktop_core::validate_local_relative(&staged)
        .map_err(|issue| DesktopError::UnsafePath(issue.reason))?;
    Ok(staged)
}
