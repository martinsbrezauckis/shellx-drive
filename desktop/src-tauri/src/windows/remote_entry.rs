//! Conversion of server file metadata into the desktop reconciliation model.

use shellx_drive_desktop_core::{
    DesktopError, RemoteEntry, RemoteEntryKind, RemoteFile, RemoteFileKind, Result as CoreResult,
};

pub(super) fn remote_entry(file: RemoteFile) -> CoreResult<RemoteEntry> {
    let size_bytes = file
        .size_bytes
        .map(|size| {
            u64::try_from(size).map_err(|_| {
                DesktopError::InvalidState("server reported a negative file size".to_string())
            })
        })
        .transpose()?;
    Ok(RemoteEntry {
        id: file.id,
        parent_id: file.parent_id,
        name: file.name,
        kind: match file.kind {
            RemoteFileKind::File => RemoteEntryKind::File,
            RemoteFileKind::Folder => RemoteEntryKind::Folder,
        },
        revision: file.revision,
        content_hash: file.content_hash,
        size_bytes,
        trashed: file.trashed,
    })
}
