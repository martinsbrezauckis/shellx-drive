//! Atomic Linux publication of a fully staged reviewed local restore.

use std::sync::atomic::{AtomicU64, Ordering};

use shellx_drive_desktop_core::{
    ensure_tree_has_no_links, initialize_owned_staging_root, map_remote_paths,
    restore_staging_root, reviewed_remote_subtree_matches_baseline, BaselineEntry, DesktopError,
    DesktopState, DriveHttpClient, RemoteEntry, RemoteEntryKind, Result as CoreResult, ReviewItem,
    SyncCycleBudget, SyncPair, SyncPassLimits, SyncRoot,
};

use super::super::reconcile;

mod staging;
#[cfg(test)]
mod tests;

static NEXT_RESTORE_BATCH: AtomicU64 = AtomicU64::new(0);

#[allow(clippy::too_many_arguments)]
pub(super) async fn restore_local(
    guard: &crate::platform::unix::filesystem::UnixRootGuard,
    client: &DriveHttpClient,
    token: &str,
    pair: &SyncPair,
    root: &SyncRoot,
    state: &DesktopState,
    item: &ReviewItem,
    remote: &[RemoteEntry],
    budget: &mut SyncCycleBudget,
) -> CoreResult<()> {
    let (mut saved, is_directory) = reviewed_saved_tree(state, item, pair, remote)?;
    if !guard.local_entry_is_absent(&item.relative_path)? {
        return Err(DesktopError::InvalidState(
            "the local restore destination is occupied; no bytes were overwritten".to_string(),
        ));
    }
    saved.sort_by_key(|entry| {
        (
            !entry.kind.eq_ignore_ascii_case("folder"),
            entry.relative_path.components().count(),
        )
    });
    let (folders, files, expected, download_bytes) = download_plan(&saved, pair, remote)?;
    budget.admit_extra(
        folders.len() + files.len(),
        files.len(),
        download_bytes,
        files.len(),
    )?;
    let owned = initialize_owned_staging_root(
        &pair.local_root,
        &restore_staging_root(&pair.local_root)?,
        "restore",
    )?;
    let batch = owned.create_batch(NEXT_RESTORE_BATCH.fetch_add(1, Ordering::AcqRel))?;
    let payload = batch.join("payload");
    let staging_guard = crate::platform::unix::filesystem::UnixRootGuard::acquire(&batch, None)?;
    let result = async {
        for path in folders {
            staging_guard.ensure_directory(&staged_relative(&item.relative_path, &path)?)?;
        }
        for (path, remote) in files {
            staging::stage_file(
                &staging_guard,
                client,
                token,
                &remote,
                &staged_relative(&item.relative_path, &path)?,
            )
            .await?;
        }
        owned.validate_for_publication(&batch)?;
        ensure_tree_has_no_links(&batch)?;
        verify_terminal_tree(client, token, pair, root, state, item, &expected).await?;
        guard.publish_staged_entry_noreplace(&payload, &item.relative_path, is_directory, || {
            guard.require_exact_pair_marker(&shellx_drive_desktop_core::PairMarker::from(pair))?;
            owned.validate_for_publication(&batch)?;
            ensure_tree_has_no_links(&batch)?;
            if !guard.local_entry_is_absent(&item.relative_path)? {
                return Err(DesktopError::InvalidState(
                    "the local restore destination became occupied; no bytes were overwritten"
                        .to_string(),
                ));
            }
            Ok(())
        })
    }
    .await;
    let cleanup = owned.remove_batch(&batch);
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
    }
}

fn reviewed_saved_tree<'a>(
    state: &'a DesktopState,
    item: &ReviewItem,
    pair: &SyncPair,
    remote: &[RemoteEntry],
) -> CoreResult<(Vec<&'a BaselineEntry>, bool)> {
    let saved = state
        .baseline
        .values()
        .filter(|entry| {
            entry.relative_path == item.relative_path
                || entry.relative_path.starts_with(&item.relative_path)
        })
        .collect::<Vec<_>>();
    if saved.is_empty() || saved.len().saturating_sub(1) != item.descendant_count {
        return Err(DesktopError::InvalidState(
            "the saved local restore tree no longer matches the reviewed descendant impact"
                .to_string(),
        ));
    }
    let is_directory = restore_kind(&saved, item)?;
    reviewed_remote_subtree_matches_baseline(
        item,
        &state.baseline,
        pair.remote_root_id.as_deref(),
        remote,
    )?;
    Ok((saved, is_directory))
}

fn restore_kind(saved: &[&BaselineEntry], item: &ReviewItem) -> CoreResult<bool> {
    let directory = saved
        .iter()
        .find(|entry| entry.relative_path == item.relative_path)
        .map(|entry| entry.kind.eq_ignore_ascii_case("folder"))
        .ok_or_else(|| {
            DesktopError::InvalidState("the saved restore root is missing".to_string())
        })?;
    if directory != item.is_directory || (!directory && saved.len() != 1) {
        return Err(DesktopError::InvalidState(
            "the reviewed local restore root changed kind; no bytes were written".to_string(),
        ));
    }
    Ok(directory)
}

type DownloadPlan = (
    Vec<std::path::PathBuf>,
    Vec<(std::path::PathBuf, RemoteEntry)>,
    Vec<RemoteEntry>,
    u64,
);

fn download_plan(
    saved: &[&BaselineEntry],
    pair: &SyncPair,
    remote: &[RemoteEntry],
) -> CoreResult<DownloadPlan> {
    let paths = map_remote_paths(remote, pair.remote_root_id.as_deref())?;
    let mut folders = Vec::new();
    let mut files = Vec::new();
    let mut expected = Vec::new();
    let mut bytes = 0_u64;
    for entry in saved {
        let current = remote
            .iter()
            .find(|current| {
                current.id == entry.remote_id
                    && !current.trashed
                    && paths.get(&current.id) == Some(&entry.relative_path)
            })
            .ok_or_else(|| {
                DesktopError::InvalidState("Drive changed this restore tree".to_string())
            })?;
        expected.push(current.clone());
        if current.kind == RemoteEntryKind::Folder {
            folders.push(entry.relative_path.clone());
        } else {
            let size = current.size_bytes.ok_or_else(|| {
                DesktopError::InvalidState("Drive omitted a restore file size".to_string())
            })?;
            if current.content_hash.is_none() {
                return Err(DesktopError::InvalidState(
                    "Drive omitted a restore file hash".to_string(),
                ));
            }
            bytes = bytes.checked_add(size).ok_or_else(|| {
                DesktopError::InvalidState("local restore bytes overflowed".to_string())
            })?;
            files.push((entry.relative_path.clone(), current.clone()));
        }
    }
    let limits = SyncPassLimits::default();
    if files.len() > limits.max_downloads || bytes > limits.max_download_bytes {
        return Err(DesktopError::InvalidState(
            "the saved local restore tree exceeds the desktop sync pass limit".to_string(),
        ));
    }
    Ok((folders, files, expected, bytes))
}

async fn verify_terminal_tree(
    client: &DriveHttpClient,
    token: &str,
    pair: &SyncPair,
    root: &SyncRoot,
    state: &DesktopState,
    item: &ReviewItem,
    expected: &[RemoteEntry],
) -> CoreResult<()> {
    let (_, current) = reconcile::fresh_remote_manifest(client, token, root).await?;
    terminal_tree_matches(pair, state, item, expected, &current)
}

fn terminal_tree_matches(
    pair: &SyncPair,
    state: &DesktopState,
    item: &ReviewItem,
    expected: &[RemoteEntry],
    current: &[RemoteEntry],
) -> CoreResult<()> {
    reviewed_remote_subtree_matches_baseline(
        item,
        &state.baseline,
        pair.remote_root_id.as_deref(),
        current,
    )?;
    if expected.iter().any(|entry| !current.contains(entry)) {
        return Err(DesktopError::InvalidState(
            "Drive changed this restore tree before local publication".to_string(),
        ));
    }
    Ok(())
}

fn staged_relative(
    root: &std::path::Path,
    entry: &std::path::Path,
) -> CoreResult<std::path::PathBuf> {
    let relative = entry.strip_prefix(root).map_err(|_| {
        DesktopError::InvalidState(
            "the reviewed restore tree has an invalid descendant".to_string(),
        )
    })?;
    let staged = std::path::Path::new("payload").join(relative);
    shellx_drive_desktop_core::validate_local_relative(&staged)
        .map_err(|issue| DesktopError::UnsafePath(issue.reason))?;
    Ok(staged)
}
