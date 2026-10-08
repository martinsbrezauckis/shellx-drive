//! Exact local/Drive closure before advancing a macOS baseline.

use std::collections::BTreeMap;

use chrono::Utc;
use shellx_drive_desktop_core::{
    map_remote_paths, BaselineEntry, DesktopError, RemoteEntry, RemoteEntryKind,
    Result as CoreResult, SyncPair, SyncRun,
};

use super::executor;

pub(super) fn finish(
    run: &mut SyncRun,
    pair: &SyncPair,
    guard: &crate::platform::unix::filesystem::UnixRootGuard,
    entries: &[RemoteEntry],
) -> CoreResult<()> {
    guard.require_exact_pair_marker(&shellx_drive_desktop_core::PairMarker::from(pair))?;
    let paths = map_remote_paths(entries, pair.remote_root_id.as_deref())?;
    let local = executor::local_entries(guard, pair)?;
    guard.require_exact_pair_marker(&shellx_drive_desktop_core::PairMarker::from(pair))?;
    if paths.len() != local.len() {
        return Err(diverged());
    }
    let local = local
        .into_iter()
        .map(|entry| (entry.relative_path.clone(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut baseline = BTreeMap::new();
    for (id, path) in paths {
        let entry = entries
            .iter()
            .find(|entry| entry.id == id && !entry.trashed)
            .ok_or_else(diverged)?;
        let local = local.get(&path).ok_or_else(diverged)?;
        let folder = entry.kind == RemoteEntryKind::Folder;
        let file_matches =
            entry.content_hash == local.content_hash && entry.size_bytes == Some(local.size_bytes);
        if folder != local.is_directory || (!folder && !file_matches) {
            return Err(diverged());
        }
        let prior_identity = run
            .state()
            .baseline
            .get(&id)
            .and_then(|saved| saved.directory_identity.as_ref());
        if folder && prior_identity.is_some() && prior_identity != local.directory_identity.as_ref()
        {
            return Err(diverged());
        }
        baseline.insert(
            id.clone(),
            BaselineEntry {
                remote_id: id,
                parent_id: entry.parent_id.clone(),
                relative_path: path,
                kind: if folder { "folder" } else { "file" }.to_string(),
                content_hash: entry.content_hash.clone(),
                revision: entry.revision,
                directory_identity: local.directory_identity.clone(),
            },
        );
    }
    run.record_success(baseline, Utc::now());
    Ok(())
}

fn diverged() -> DesktopError {
    DesktopError::InvalidState(
        "local and Drive trees diverged before the macOS baseline could be saved".to_string(),
    )
}
