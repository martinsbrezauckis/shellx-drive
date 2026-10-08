//! Snapshot download and replacement publication.

use std::path::Path;

use shellx_drive_desktop_core::{
    DesktopError, DownloadPrecondition, DriveHttpClient, RemoteEntry, Result as CoreResult,
    ReviewItem, SyncPair, SyncRoot,
};

use super::super::staging::download_snapshot;
use super::presentation::needs_review;
use super::{local, presentation, remote};
use crate::platform::unix::download_space::{
    finish_failed_download, replacement_recovery_bytes, DownloadSpaceBudget,
};
use crate::platform::unix::filesystem::ReplacingPublication;

#[allow(clippy::too_many_arguments)]
pub(super) async fn download(
    guard: &crate::platform::unix::filesystem::UnixRootGuard,
    client: &DriveHttpClient,
    token: &str,
    pair: &SyncPair,
    root: &SyncRoot,
    file: &RemoteEntry,
    source_path: &Path,
    destination: &Path,
    precondition: &DownloadPrecondition,
) -> CoreResult<Option<ReviewItem>> {
    if let Some(parent) = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        guard.ensure_directory(parent)?;
    }
    let recovery_bytes = replacement_recovery_bytes(precondition);
    let (owned, batch, staged) = download_snapshot(client, token, pair, file, recovery_bytes)
        .await?
        .into_parts();
    let result = async {
        if !remote::fresh_file_matches(client, token, pair, root, file, source_path).await? {
            return Ok(needs_review());
        }
        remote::require_pair_marker(guard, pair)?;
        if !local::download_matches(guard, destination, precondition)? {
            return Ok(needs_review());
        }
        match precondition {
            DownloadPrecondition::Absent => Ok(
                match guard.publish_staged_file(&staged, destination, false) {
                    Ok(()) => ReplacingPublication::Published,
                    Err(_) => needs_review(),
                },
            ),
            DownloadPrecondition::ExactLocal { .. } => {
                DownloadSpaceBudget::new(0, recovery_bytes).check_path(&batch)?;
                let planned = local::planned_entry(destination, precondition)
                    .expect("an exact precondition always carries a planned local row");
                let Some(prepared) =
                    guard.prepare_staged_file_replacement(&staged, destination, &planned)?
                else {
                    return Ok(needs_review());
                };
                if !remote::fresh_file_matches(client, token, pair, root, file, source_path).await?
                {
                    return Ok(needs_review());
                }
                prepared.publish(guard, || {
                    remote::require_pair_marker(guard, pair)?;
                    if !local::download_matches(guard, destination, precondition)? {
                        return Err(DesktopError::UnsafePath(
                            "local replacement input changed before publication".to_string(),
                        ));
                    }
                    Ok(())
                })
            }
        }
    }
    .await;
    match result {
        Ok(ReplacingPublication::Published) => {
            owned.remove_batch(&batch)?;
            Ok(None)
        }
        Ok(ReplacingPublication::NeedsReview { recovery_leaf }) => {
            let exchange_completed = recovery_leaf.is_some();
            finish_failed_download(&owned, &batch, exchange_completed)?;
            Ok(Some(presentation::replacement_review(
                destination,
                exchange_completed.then_some(batch.as_path()),
            )))
        }
        Err(error) => {
            finish_failed_download(&owned, &batch, false)?;
            Err(error)
        }
    }
}
