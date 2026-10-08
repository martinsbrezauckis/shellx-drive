//! Staged transfer and remote-authority terminal checks.

use std::{
    os::unix::fs::OpenOptionsExt,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use shellx_drive_desktop_core::{
    copy_and_hash_reader_bounded, upload_precondition_matches, upload_staging_root,
    LocalScanLimits, OwnedStagingRoot,
};

use super::*;
use crate::platform::unix::download_space::{
    create_private_staged_file, finish_failed_download, replacement_recovery_bytes,
    DownloadSpaceBudget,
};

static NEXT_UPLOAD_BATCH: AtomicU64 = AtomicU64::new(0);

pub(super) struct UploadSnapshot {
    pub area: OwnedStagingRoot,
    pub batch: PathBuf,
    pub file: fs::File,
    pub size_bytes: u64,
}

pub(super) fn upload_snapshot(
    guard: &UnixRootGuard,
    pair: &SyncPair,
    relative_path: &Path,
    expected: &LocalEntry,
) -> CoreResult<UploadSnapshot> {
    if expected.is_directory {
        return Err(DesktopError::InvalidState(
            "a directory cannot be used as a file upload source".to_string(),
        ));
    }
    let mut source = guard.open_regular_file(relative_path)?;
    let size_bytes = source.metadata()?.len();
    let max_bytes = LocalScanLimits::default().max_file_bytes;
    if size_bytes > max_bytes {
        return Err(DesktopError::InvalidState(
            "local upload source exceeds the desktop sync size limit".to_string(),
        ));
    }
    let staging_root = upload_staging_root(&pair.local_root)?;
    let area = initialize_owned_staging_root(&pair.local_root, &staging_root, "upload")?;
    area.cleanup_aged_batches(Duration::from_secs(24 * 60 * 60))?;
    let batch = area.create_batch(NEXT_UPLOAD_BATCH.fetch_add(1, Ordering::AcqRel))?;
    let payload = batch.join("payload");
    let result = (|| -> CoreResult<(fs::File, u64)> {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&payload)?;
        validate_private_staging_file(&file)?;
        let (hash, copied) = copy_and_hash_reader_bounded(&mut source, &mut file, max_bytes)?;
        file.sync_all()?;
        let snapshot = LocalEntry {
            relative_path: relative_path.to_path_buf(),
            content_hash: Some(hash),
            size_bytes: copied,
            is_directory: false,
            directory_identity: None,
        };
        if !upload_precondition_matches(expected, &snapshot) {
            return Err(DesktopError::UnsafePath(
                "local upload source changed while its private snapshot was made".to_string(),
            ));
        }
        file.seek(SeekFrom::Start(0))?;
        area.validate_for_publication(&batch)?;
        Ok((file, copied))
    })();
    match result {
        Ok((file, size_bytes)) => Ok(UploadSnapshot {
            area,
            batch,
            file,
            size_bytes,
        }),
        Err(error) => {
            let _ = area.remove_batch(&batch);
            Err(error)
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn download_file(
    client: &DriveHttpClient,
    token: &str,
    pair: &SyncPair,
    guard: &UnixRootGuard,
    sync_root: &SyncRoot,
    remote: &RemoteEntry,
    source_path: &Path,
    destination: &Path,
    precondition: &DownloadPrecondition,
) -> CoreResult<Option<ReviewItem>> {
    let size = remote.size_bytes.ok_or_else(|| {
        DesktopError::InvalidState("Drive file is missing its byte size".to_string())
    })?;
    let expected_hash = remote.content_hash.as_deref().ok_or_else(|| {
        DesktopError::InvalidState("Drive file is missing its content hash".to_string())
    })?;
    let recovery_bytes = replacement_recovery_bytes(precondition);
    let mut space = DownloadSpaceBudget::new(size, recovery_bytes);
    space.check_path(&pair.local_root)?;
    if let Some(parent) = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        guard.ensure_directory(parent)?;
    }
    let area = initialize_owned_staging_root(
        &pair.local_root,
        &download_staging_root(&pair.local_root)?,
        "download",
    )?;
    let batch = area.create_batch(remote.revision.unsigned_abs())?;
    let staged = batch.join("payload");
    let result = async {
        let mut sink = create_private_staged_file(&staged)?;
        space.check_file(&sink)?;
        client
            .download_file_chunks(token, &remote.id, size, |chunk| {
                space.write_chunk(&mut sink, chunk)
            })
            .await?;
        sink.sync_all()?;
        drop(sink);
        let hash =
            shellx_drive_desktop_core::hash_reader_bounded(fs::File::open(&staged)?, size)?.0;
        if hash != expected_hash {
            return Err(DesktopError::InvalidState(
                "Drive download hash did not match its manifest".to_string(),
            ));
        }
        area.validate_for_publication(&batch)?;
        if !fresh_remote_file_matches(client, token, pair, sync_root, remote, source_path).await? {
            return Ok(ReplacingPublication::NeedsReview {
                recovery_leaf: None,
            });
        }
        require_pair_marker(guard, pair)?;
        if !download_precondition_matches_now(guard, destination, precondition)? {
            return Ok(ReplacingPublication::NeedsReview {
                recovery_leaf: None,
            });
        }
        match precondition {
            DownloadPrecondition::Absent => {
                match guard.publish_staged_file(&staged, destination, false) {
                    Ok(()) => Ok(ReplacingPublication::Published),
                    Err(_) => Ok(ReplacingPublication::NeedsReview {
                        recovery_leaf: None,
                    }),
                }
            }
            DownloadPrecondition::ExactLocal {
                content_hash,
                size_bytes,
                is_directory,
            } => {
                DownloadSpaceBudget::new(0, recovery_bytes).check_path(&batch)?;
                let planned = LocalEntry {
                    relative_path: destination.to_path_buf(),
                    content_hash: content_hash.clone(),
                    size_bytes: *size_bytes,
                    is_directory: *is_directory,
                    directory_identity: None,
                };
                let Some(prepared) =
                    guard.prepare_staged_file_replacement(&staged, destination, &planned)?
                else {
                    return Ok(ReplacingPublication::NeedsReview {
                        recovery_leaf: None,
                    });
                };
                if !fresh_remote_file_matches(client, token, pair, sync_root, remote, source_path)
                    .await?
                {
                    return Ok(ReplacingPublication::NeedsReview {
                        recovery_leaf: None,
                    });
                }
                prepared.publish(guard, || require_pair_marker(guard, pair))
            }
        }
    }
    .await;
    match result {
        Ok(ReplacingPublication::Published) => {
            area.remove_batch(&batch)?;
            Ok(None)
        }
        Ok(ReplacingPublication::NeedsReview { recovery_leaf }) => {
            let exchange_completed = recovery_leaf.is_some();
            finish_failed_download(&area, &batch, exchange_completed)?;
            Ok(Some(replacement_review(
                destination,
                exchange_completed.then_some(batch.as_path()),
            )))
        }
        Err(error) => {
            finish_failed_download(&area, &batch, false)?;
            Err(error)
        }
    }
}

pub(super) async fn fresh_remote_entries(
    client: &DriveHttpClient,
    token: &str,
    sync_root: &SyncRoot,
) -> CoreResult<Vec<RemoteEntry>> {
    Ok(fresh_remote_manifest(client, token, sync_root).await?.1)
}

pub(super) async fn fresh_writable_remote_entries(
    client: &DriveHttpClient,
    token: &str,
    sync_root: &SyncRoot,
) -> CoreResult<Vec<RemoteEntry>> {
    let (current_root, entries) = fresh_remote_manifest(client, token, sync_root).await?;
    require_write_grant(&current_root)?;
    Ok(entries)
}

pub(in crate::application::linux) async fn fresh_remote_manifest(
    client: &DriveHttpClient,
    token: &str,
    sync_root: &SyncRoot,
) -> CoreResult<(SyncRoot, Vec<RemoteEntry>)> {
    let manifest = client.sync_root_manifest(token, sync_root).await?;
    if !manifest.root.same_manifest_subject(sync_root) || !manifest.root.is_available_at(Utc::now())
    {
        return Err(DesktopError::InvalidState(
            "Drive root authority changed before the terminal sync operation".to_string(),
        ));
    }
    let root = manifest.root;
    let files = manifest
        .files
        .into_iter()
        .map(remote_entry)
        .collect::<CoreResult<Vec<_>>>()?;
    Ok((root, files))
}

pub(super) async fn fresh_remote_file_matches(
    client: &DriveHttpClient,
    token: &str,
    pair: &SyncPair,
    sync_root: &SyncRoot,
    expected: &RemoteEntry,
    expected_path: &Path,
) -> CoreResult<bool> {
    let manifest = client.sync_root_manifest(token, sync_root).await?;
    if !manifest.root.same_manifest_subject(sync_root) || !manifest.root.is_available_at(Utc::now())
    {
        return Ok(false);
    }
    let remote = manifest
        .files
        .into_iter()
        .map(remote_entry)
        .collect::<CoreResult<Vec<_>>>()?;
    let paths = match map_remote_paths(&remote, pair.remote_root_id.as_deref()) {
        Ok(paths) => paths,
        Err(_) => return Ok(false),
    };
    Ok(remote.iter().any(|current| {
        current.id == expected.id
            && !current.trashed
            && current.kind == expected.kind
            && current.revision == expected.revision
            && current.content_hash == expected.content_hash
            && current.size_bytes == expected.size_bytes
            && paths
                .get(&current.id)
                .is_some_and(|path| path == expected_path)
    }))
}

pub(super) fn require_pair_marker(guard: &UnixRootGuard, pair: &SyncPair) -> CoreResult<()> {
    guard.ensure_identity("paired-root terminal boundary")?;
    guard.require_exact_pair_marker(&shellx_drive_desktop_core::PairMarker::from(pair))
}

pub(super) fn require_write_grant(sync_root: &SyncRoot) -> CoreResult<()> {
    if sync_root.is_available_at(Utc::now()) && sync_root.role.may_write() {
        Ok(())
    } else {
        Err(DesktopError::InvalidState(
            "Drive access is no longer allowed to change this root".to_string(),
        ))
    }
}

pub(crate) fn require_write_grant_at_terminal(sync_root: &SyncRoot) -> CoreResult<()> {
    require_write_grant(sync_root)
}

pub(super) fn download_precondition_matches_now(
    guard: &UnixRootGuard,
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
