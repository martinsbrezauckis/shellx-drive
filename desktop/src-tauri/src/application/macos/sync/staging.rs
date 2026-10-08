//! Private staging for macOS transfers before descriptor-bound publication.

use std::{
    fs,
    io::{Seek, SeekFrom, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::platform::unix::download_space::{finish_failed_download, DownloadSpaceBudget};
use shellx_drive_desktop_core::{
    copy_and_hash_reader_bounded, download_staging_root, hash_reader_bounded,
    initialize_owned_staging_root, upload_precondition_matches, DesktopError, DriveHttpClient,
    LocalEntry, LocalScanLimits, RemoteEntry, RemoteEntryKind, RemoteFile, RemoteFileKind,
};

static NEXT_STAGING_BATCH: AtomicU64 = AtomicU64::new(0);

/// A verified remote body held in a private batch until the caller has
/// performed its terminal remote and local precondition checks.
pub(super) struct DownloadSnapshot {
    owned: shellx_drive_desktop_core::OwnedStagingRoot,
    batch: PathBuf,
    staged: PathBuf,
}

impl DownloadSnapshot {
    pub(super) fn into_parts(
        self,
    ) -> (
        shellx_drive_desktop_core::OwnedStagingRoot,
        PathBuf,
        PathBuf,
    ) {
        (self.owned, self.batch, self.staged)
    }
}

pub(super) async fn download_snapshot(
    client: &DriveHttpClient,
    token: &str,
    pair: &shellx_drive_desktop_core::SyncPair,
    remote: &RemoteEntry,
    recovery_bytes: u64,
) -> shellx_drive_desktop_core::Result<DownloadSnapshot> {
    let size = remote.size_bytes.ok_or_else(|| {
        DesktopError::InvalidState("Drive file manifest omitted its byte size".to_string())
    })?;
    let expected_hash = remote.content_hash.as_deref().ok_or_else(|| {
        DesktopError::InvalidState("Drive file manifest omitted its content hash".to_string())
    })?;
    let staging_root = download_staging_root(&pair.local_root)?;
    let mut space = DownloadSpaceBudget::new(size, recovery_bytes);
    space.check_path(&pair.local_root)?;
    let owned = initialize_owned_staging_root(&pair.local_root, &staging_root, "download")?;
    let batch = owned.create_batch(NEXT_STAGING_BATCH.fetch_add(1, Ordering::AcqRel))?;
    let staged = batch.join("payload");
    let result = async {
        let mut destination = create_download_payload(&staged)?;
        shellx_drive_desktop_core::validate_private_staging_file(&destination)?;
        space.check_file(&destination)?;
        client
            .download_file_chunks(token, &remote.id, size, |chunk| {
                space.write_chunk(&mut destination, chunk)
            })
            .await?;
        destination.sync_all()?;
        destination.seek(SeekFrom::Start(0))?;
        let (hash, downloaded) =
            hash_reader_bounded(&destination, LocalScanLimits::default().max_file_bytes)?;
        if downloaded != size || expected_hash != hash {
            return Err(DesktopError::InvalidState(
                "Drive download did not match its scoped manifest bytes".to_string(),
            ));
        }
        drop(destination);
        owned.validate_for_publication(&batch)?;
        Ok(())
    }
    .await;
    match result {
        Ok(()) => Ok(DownloadSnapshot {
            owned,
            batch,
            staged,
        }),
        Err(error) => {
            finish_failed_download(&owned, &batch, false)?;
            Err(error)
        }
    }
}

/// The download body is hashed through this same descriptor after its durable
/// write. Keep read access explicit: a write-only Darwin descriptor reports
/// EBADF when the bounded verifier reads it back.
fn create_download_payload(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

pub(super) struct UploadSnapshot {
    owned: shellx_drive_desktop_core::OwnedStagingRoot,
    batch: PathBuf,
    file: fs::File,
    local: LocalEntry,
}

impl UploadSnapshot {
    pub(super) fn into_parts(
        self,
    ) -> (
        shellx_drive_desktop_core::OwnedStagingRoot,
        PathBuf,
        fs::File,
        LocalEntry,
    ) {
        (self.owned, self.batch, self.file, self.local)
    }
}

pub(super) fn upload_snapshot(
    guard: &crate::platform::unix::filesystem::UnixRootGuard,
    pair: &shellx_drive_desktop_core::SyncPair,
    relative_path: &Path,
    planned: &LocalEntry,
) -> shellx_drive_desktop_core::Result<UploadSnapshot> {
    if planned.is_directory {
        return Err(DesktopError::InvalidState(
            "a directory cannot be used as a file upload source".to_string(),
        ));
    }
    let mut source = guard.open_regular_file(relative_path)?;
    let size = source.metadata()?.len();
    if size > LocalScanLimits::default().max_file_bytes {
        return Err(DesktopError::InvalidState(
            "local upload source exceeds the desktop sync size limit".to_string(),
        ));
    }
    let staging_root = shellx_drive_desktop_core::upload_staging_root(&pair.local_root)?;
    let owned = initialize_owned_staging_root(&pair.local_root, &staging_root, "upload")?;
    let batch = owned.create_batch(NEXT_STAGING_BATCH.fetch_add(1, Ordering::AcqRel))?;
    let payload = batch.join("payload");
    let result = (|| -> shellx_drive_desktop_core::Result<(fs::File, LocalEntry)> {
        let mut destination = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&payload)?;
        shellx_drive_desktop_core::validate_private_staging_file(&destination)?;
        let (content_hash, copied) = copy_and_hash_reader_bounded(
            &mut source,
            &mut destination,
            LocalScanLimits::default().max_file_bytes,
        )?;
        destination.sync_all()?;
        let snapshot = LocalEntry {
            relative_path: relative_path.to_path_buf(),
            content_hash: Some(content_hash),
            size_bytes: copied,
            is_directory: false,
            directory_identity: None,
        };
        if !upload_precondition_matches(planned, &snapshot) {
            return Err(DesktopError::InvalidState(
                "local source changed while macOS prepared its private upload snapshot".to_string(),
            ));
        }
        destination.seek(SeekFrom::Start(0))?;
        Ok((destination, snapshot))
    })();
    match result {
        Ok((file, local)) => Ok(UploadSnapshot {
            owned,
            batch,
            file,
            local,
        }),
        Err(error) => {
            let _ = owned.remove_batch(&batch);
            Err(error)
        }
    }
}

pub(in crate::application::macos) fn remote_entry_for_review(
    file: RemoteFile,
) -> shellx_drive_desktop_core::Result<RemoteEntry> {
    let size_bytes = file
        .size_bytes
        .map(u64::try_from)
        .transpose()
        .map_err(|_| DesktopError::InvalidState("Drive file size was negative".to_string()))?;
    Ok(RemoteEntry {
        id: file.id,
        parent_id: file.parent_id,
        name: file.name,
        kind: match file.kind {
            RemoteFileKind::File => RemoteEntryKind::File,
            RemoteFileKind::Folder => RemoteEntryKind::Folder,
        },
        revision: file.revision,
        trashed: file.trashed,
        content_hash: file.content_hash,
        size_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn downloaded_payload_handle_is_readable_after_durable_write() {
        let directory = tempfile::tempdir().expect("temporary staging directory");
        let path = directory.path().join("payload");
        let mut payload = create_download_payload(&path).expect("private payload descriptor");
        payload
            .write_all(b"fixture remote bytes")
            .expect("write fixture bytes");
        payload.sync_all().expect("durable fixture bytes");
        payload
            .seek(SeekFrom::Start(0))
            .expect("rewind fixture payload");

        let (_, bytes) = hash_reader_bounded(&payload, LocalScanLimits::default().max_file_bytes)
            .expect("read back the downloaded payload through its original descriptor");
        assert_eq!(bytes, b"fixture remote bytes".len() as u64);
    }
}
