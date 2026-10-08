//! Atomic macOS publication of a fully staged reviewed restore tree.

use std::sync::atomic::{AtomicU64, Ordering};

use shellx_drive_desktop_core::{
    ensure_tree_has_no_links, initialize_owned_staging_root, map_remote_paths,
    restore_staging_root, reviewed_remote_subtree_matches_baseline, DesktopError, DriveHttpClient,
    RemoteEntry, RemoteEntryKind, Result as CoreResult, ReviewItem, SyncCycleBudget, SyncPair,
    SyncPassLimits,
};

use super::super::sync;

mod saved_tree;
mod staging;
mod validation;

static NEXT_RESTORE_BATCH: AtomicU64 = AtomicU64::new(0);

/// The bounded current-tree download plan for one reviewed local restore.
struct RestoreDownloadPlan<'a> {
    folders: Vec<std::path::PathBuf>,
    files: Vec<(std::path::PathBuf, &'a RemoteEntry)>,
    bytes: u64,
}

pub(super) async fn restore_local(
    guard: &crate::platform::unix::filesystem::UnixRootGuard,
    client: &DriveHttpClient,
    token: &str,
    pair: &SyncPair,
    state: &shellx_drive_desktop_core::DesktopState,
    item: &ReviewItem,
    remote: &[RemoteEntry],
    budget: &mut SyncCycleBudget,
) -> CoreResult<()> {
    reviewed_remote_subtree_matches_baseline(
        item,
        &state.baseline,
        pair.remote_root_id.as_deref(),
        remote,
    )?;
    let (mut saved, is_directory) = saved_tree::load(state, item)?;
    if !guard.local_entry_is_absent(&item.relative_path)? {
        return Err(DesktopError::InvalidState(
            "the local restore destination is occupied; no bytes were overwritten".to_string(),
        ));
    }
    saved.sort_by_key(|entry| {
        (
            if entry.kind.eq_ignore_ascii_case("folder") {
                0
            } else {
                1
            },
            entry.relative_path.components().count(),
        )
    });
    let plan = download_plan(&saved, pair, remote)?;
    budget.admit_extra(
        plan.files.len() + plan.folders.len(),
        plan.files.len(),
        plan.bytes,
        plan.files.len(),
    )?;
    let staging_root = restore_staging_root(&pair.local_root)?;
    let owned = initialize_owned_staging_root(&pair.local_root, &staging_root, "restore")?;
    let batch = owned.create_batch(NEXT_RESTORE_BATCH.fetch_add(1, Ordering::AcqRel))?;
    let payload = batch.join("payload");
    let result = async {
        let staging_guard =
            crate::platform::unix::filesystem::UnixRootGuard::acquire(&batch, None)?;
        for path in plan.folders {
            staging_guard
                .ensure_directory(&validation::staged_relative(&item.relative_path, &path)?)?;
        }
        for (path, remote) in plan.files {
            staging::stage_file(
                &staging_guard,
                client,
                token,
                remote,
                &validation::staged_relative(&item.relative_path, &path)?,
            )
            .await?;
        }
        owned.validate_for_publication(&batch)?;
        ensure_tree_has_no_links(&batch)?;
        verify_staged_tree(client, token, pair, state, item, &saved).await?;
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
    match result {
        Ok(()) => owned.remove_batch(&batch),
        Err(error) => {
            let _ = owned.remove_batch(&batch);
            Err(error)
        }
    }
}

fn download_plan<'a>(
    saved: &[&shellx_drive_desktop_core::BaselineEntry],
    pair: &SyncPair,
    remote: &'a [RemoteEntry],
) -> CoreResult<RestoreDownloadPlan<'a>> {
    validation::validate_tree(saved, pair, remote)?;
    let paths = map_remote_paths(remote, pair.remote_root_id.as_deref())?;
    let mut folders = Vec::new();
    let mut files = Vec::new();
    let mut bytes = 0_u64;
    for entry in saved {
        let current = remote
            .iter()
            .find(|current| {
                current.id == entry.remote_id
                    && !current.trashed
                    && paths.get(&current.id) == Some(&entry.relative_path)
            })
            .expect("validated exact remote entry");
        if current.kind == RemoteEntryKind::Folder {
            folders.push(entry.relative_path.clone());
        } else {
            let size = current.size_bytes.ok_or_else(|| {
                DesktopError::InvalidState(
                    "Drive omitted a file size in this local restore tree".to_string(),
                )
            })?;
            if current.content_hash.is_none() {
                return Err(DesktopError::InvalidState(
                    "Drive omitted a file hash in this local restore tree".to_string(),
                ));
            }
            bytes = bytes.checked_add(size).ok_or_else(|| {
                DesktopError::InvalidState("local restore download bytes overflowed".to_string())
            })?;
            files.push((entry.relative_path.clone(), current));
        }
    }
    let limits = SyncPassLimits::default();
    if files.len() > limits.max_downloads || bytes > limits.max_download_bytes {
        return Err(DesktopError::InvalidState(
            "the saved local restore tree exceeds the desktop sync pass limit".to_string(),
        ));
    }
    Ok(RestoreDownloadPlan {
        folders,
        files,
        bytes,
    })
}

async fn verify_staged_tree(
    client: &DriveHttpClient,
    token: &str,
    pair: &SyncPair,
    state: &shellx_drive_desktop_core::DesktopState,
    item: &ReviewItem,
    saved: &[&shellx_drive_desktop_core::BaselineEntry],
) -> CoreResult<()> {
    let metadata = state.sync_root_for_pair(pair).ok_or_else(|| {
        DesktopError::InvalidState(
            "this Drive location no longer has current root authority".to_string(),
        )
    })?;
    let manifest = client.sync_root_manifest(token, &metadata.root).await?;
    if !manifest.root.same_manifest_subject(&metadata.root)
        || !manifest.root.is_available_at(chrono::Utc::now())
    {
        return Err(DesktopError::InvalidState(
            "Drive root authority changed before local restore publication".to_string(),
        ));
    }
    let remote = manifest
        .files
        .into_iter()
        .map(sync::remote_entry_for_review)
        .collect::<CoreResult<Vec<_>>>()?;
    shellx_drive_desktop_core::validate_sync_pass(&remote, &[], SyncPassLimits::default())?;
    reviewed_remote_subtree_matches_baseline(
        item,
        &state.baseline,
        pair.remote_root_id.as_deref(),
        &remote,
    )?;
    validation::validate_tree(saved, pair, &remote)
}
