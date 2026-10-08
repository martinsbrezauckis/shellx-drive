//! Fresh scoped-remote witnesses and path resolution.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use chrono::Utc;
use shellx_drive_desktop_core::{
    map_remote_paths, DesktopError, DriveHttpClient, RemoteEntry, RemoteEntryKind,
    Result as CoreResult, SyncPair, SyncRoot,
};

use super::super::staging::remote_entry_for_review;
use super::remote_match;

pub(super) async fn fresh_entries(
    client: &DriveHttpClient,
    token: &str,
    root: &SyncRoot,
) -> CoreResult<Vec<RemoteEntry>> {
    Ok(fresh_manifest(client, token, root).await?.1)
}

pub(super) async fn fresh_writable_entries(
    client: &DriveHttpClient,
    token: &str,
    root: &SyncRoot,
) -> CoreResult<Vec<RemoteEntry>> {
    let (current, entries) = fresh_manifest(client, token, root).await?;
    require_write_grant(&current)?;
    Ok(entries)
}

async fn fresh_manifest(
    client: &DriveHttpClient,
    token: &str,
    root: &SyncRoot,
) -> CoreResult<(SyncRoot, Vec<RemoteEntry>)> {
    let manifest = client.sync_root_manifest(token, root).await?;
    if !manifest.root.same_manifest_subject(root) || !manifest.root.is_available_at(Utc::now()) {
        return Err(DesktopError::InvalidState(
            "Drive root authority changed before the terminal sync operation".to_string(),
        ));
    }
    let entries = manifest
        .files
        .into_iter()
        .map(remote_entry_for_review)
        .collect::<CoreResult<_>>()?;
    Ok((manifest.root, entries))
}

pub(super) async fn fresh_file_matches(
    client: &DriveHttpClient,
    token: &str,
    pair: &SyncPair,
    root: &SyncRoot,
    expected: &RemoteEntry,
    expected_path: &Path,
) -> CoreResult<bool> {
    let manifest = client.sync_root_manifest(token, root).await?;
    if !manifest.root.same_manifest_subject(root) || !manifest.root.is_available_at(Utc::now()) {
        return Ok(false);
    }
    let entries = manifest
        .files
        .into_iter()
        .map(remote_entry_for_review)
        .collect::<CoreResult<Vec<_>>>()?;
    Ok(remote_match::exact_file(
        &entries,
        pair.remote_root_id.as_deref(),
        expected,
        expected_path,
    ))
}

pub(super) fn require_pair_marker(
    guard: &crate::platform::unix::filesystem::UnixRootGuard,
    pair: &SyncPair,
) -> CoreResult<()> {
    guard.ensure_identity("paired-root terminal boundary")?;
    guard.require_exact_pair_marker(&shellx_drive_desktop_core::PairMarker::from(pair))
}

pub(super) fn require_write_grant(root: &SyncRoot) -> CoreResult<()> {
    if root.is_available_at(Utc::now()) && root.role.may_write() {
        Ok(())
    } else {
        Err(DesktopError::InvalidState(
            "Drive access is no longer allowed to change this root".to_string(),
        ))
    }
}

pub(super) fn folder_ids(
    remote: &[RemoteEntry],
    selected: Option<&str>,
) -> CoreResult<HashMap<PathBuf, String>> {
    Ok(map_remote_paths(remote, selected)?
        .into_iter()
        .filter_map(|(id, path)| {
            remote
                .iter()
                .find(|entry| {
                    entry.id == id && !entry.trashed && entry.kind == RemoteEntryKind::Folder
                })
                .map(|entry| (path, entry.id.clone()))
        })
        .collect())
}

pub(super) fn parent(
    folders: &HashMap<PathBuf, String>,
    pair: &SyncPair,
    path: &Path,
) -> CoreResult<Option<String>> {
    match path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        None => Ok(pair.remote_root_id.clone()),
        Some(parent) => folders.get(parent).cloned().map(Some).ok_or_else(|| {
            DesktopError::InvalidState(format!(
                "Drive parent folder is unavailable for {}",
                path.display()
            ))
        }),
    }
}

pub(super) fn leaf(path: &Path) -> CoreResult<&str> {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| DesktopError::UnsafePath("Drive path has no Unicode file name".to_string()))
}
