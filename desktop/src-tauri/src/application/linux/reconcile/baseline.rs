//! Baseline finalization and manifest-row decoding.

use super::*;

pub(super) fn finish_baseline(
    run: &mut SyncRun,
    local_reads: &mut ReadBudget,
    pair: &SyncPair,
    guard: &UnixRootGuard,
    remote: &[RemoteEntry],
) -> CoreResult<SyncAttemptDisposition> {
    run.ensure_not_cancelled()?;
    require_pair_marker(guard, pair)?;
    let paths = map_remote_paths(remote, pair.remote_root_id.as_deref())?;
    let local = final_local_entries(run, local_reads, guard, pair)?;
    require_pair_marker(guard, pair)?;
    // Retain the prior baseline if either tree gained or lost an item after
    // planning. Dropping a remotely deleted entry while its local copy remains
    // would otherwise turn that copy into an untracked upload on the next pass.
    if paths.len() != local.len() {
        return Ok(SyncAttemptDisposition::TreeChanged);
    }
    let local = local
        .into_iter()
        .map(|entry| (entry.relative_path.clone(), entry))
        .collect::<BTreeMap<_, _>>();
    let live_remote = remote
        .iter()
        .filter(|entry| !entry.trashed)
        .map(|entry| (entry.id.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut baseline = BTreeMap::new();
    // The selected remote folder represents the local root itself and is
    // intentionally absent from the path map. Only mapped descendants enter
    // the baseline, with each path still bound to its exact live manifest row.
    for (id, path) in paths {
        let entry = live_remote.get(id.as_str()).ok_or_else(|| {
            DesktopError::InvalidState("Drive entry escaped its selected root".to_string())
        })?;
        let Some(local) = local.get(&path) else {
            return Ok(SyncAttemptDisposition::TreeChanged);
        };
        let folder = entry.kind == RemoteEntryKind::Folder;
        let file_matches =
            entry.content_hash == local.content_hash && entry.size_bytes == Some(local.size_bytes);
        if folder != local.is_directory || (!folder && !file_matches) {
            return Ok(SyncAttemptDisposition::TreeChanged);
        }
        baseline.insert(
            entry.id.clone(),
            BaselineEntry {
                remote_id: entry.id.clone(),
                parent_id: entry.parent_id.clone(),
                relative_path: path.clone(),
                kind: if folder { "folder" } else { "file" }.to_string(),
                content_hash: entry.content_hash.clone(),
                revision: entry.revision,
                directory_identity: local.directory_identity.clone(),
            },
        );
    }
    run.ensure_not_cancelled()?;
    run.record_success(baseline, Utc::now());
    run.append_active_activity(shellx_drive_desktop_core::ActivityEntry {
        at: Utc::now(),
        direction: "Sync".to_string(),
        relative_path: PathBuf::new(),
        result: "Linux Drive reconciliation completed.".to_string(),
    });
    Ok(SyncAttemptDisposition::Complete)
}

pub(super) fn remote_entry(file: shellx_drive_desktop_core::RemoteFile) -> CoreResult<RemoteEntry> {
    Ok(RemoteEntry {
        id: file.id,
        parent_id: file.parent_id,
        name: file.name,
        kind: match file.kind {
            shellx_drive_desktop_core::RemoteFileKind::File => RemoteEntryKind::File,
            shellx_drive_desktop_core::RemoteFileKind::Folder => RemoteEntryKind::Folder,
        },
        revision: file.revision,
        content_hash: file.content_hash,
        size_bytes: file
            .size_bytes
            .map(u64::try_from)
            .transpose()
            .map_err(|_| {
                DesktopError::InvalidState("Drive returned a negative file size".to_string())
            })?,
        trashed: file.trashed,
    })
}
