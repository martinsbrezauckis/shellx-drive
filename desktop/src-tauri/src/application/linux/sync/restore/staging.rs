//! Bounded descriptor-rooted downloads for a reviewed restore batch.

use std::io::{Seek, SeekFrom};

use crate::platform::unix::download_space::DownloadSpaceBudget;
use shellx_drive_desktop_core::{
    hash_reader_bounded, DesktopError, DriveHttpClient, LocalScanLimits, RemoteEntry,
    Result as CoreResult,
};

pub(super) async fn stage_file(
    guard: &crate::platform::unix::filesystem::UnixRootGuard,
    client: &DriveHttpClient,
    token: &str,
    remote: &RemoteEntry,
    relative: &std::path::Path,
) -> CoreResult<()> {
    let size = remote.size_bytes.ok_or_else(|| {
        DesktopError::InvalidState("Drive omitted a restore file size".to_string())
    })?;
    let expected = remote.content_hash.as_deref().ok_or_else(|| {
        DesktopError::InvalidState("Drive omitted a restore file hash".to_string())
    })?;
    let mut space = DownloadSpaceBudget::new(size, 0);
    space.check_file(guard.root_descriptor())?;
    if let Some(parent) = relative
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        guard.ensure_directory(parent)?;
    }
    if !guard.local_entry_is_absent(relative)? {
        return Err(DesktopError::InvalidState(
            "private restore staging is occupied".to_string(),
        ));
    }
    let mut file = guard.create_private_staging_file(relative)?;
    space.check_file(&file)?;
    client
        .download_file_chunks(token, &remote.id, size, |chunk| {
            space.write_chunk(&mut file, chunk)
        })
        .await?;
    file.sync_all()?;
    file.seek(SeekFrom::Start(0))?;
    let (hash, bytes) = hash_reader_bounded(&file, LocalScanLimits::default().max_file_bytes)?;
    if bytes != size || hash != expected {
        return Err(DesktopError::InvalidState(
            "Drive restore body did not match its scoped manifest bytes".to_string(),
        ));
    }
    Ok(())
}
