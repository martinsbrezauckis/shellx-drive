//! Descriptor-bound macOS retained-local recovery.
//!
//! A confirmed local-copy removal never recursively deletes user data. It
//! moves the exact checked entry (or complete access-removed root) into a
//! private sibling recovery batch with Darwin's atomic no-replace rename.

use std::{
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
};

use chrono::Utc;
use shellx_drive_desktop_core::{
    ensure_private_staging_directory, ensure_tree_has_no_links, inspect_local_tree,
    reviewed_local_subtree_matches_baseline, DesktopError, DesktopState, RemoteEntry,
    Result as CoreResult, ReviewItem, SyncPair,
};

pub(super) fn recover_local(
    pair: &SyncPair,
    state: &DesktopState,
    item: &ReviewItem,
    guard: &crate::platform::unix::filesystem::UnixRootGuard,
    remote: &[RemoteEntry],
) -> CoreResult<PathBuf> {
    let baseline = state
        .baseline
        .values()
        .find(|entry| entry.relative_path == item.relative_path)
        .ok_or_else(|| {
            DesktopError::InvalidState("the review has no matching saved baseline".to_string())
        })?;
    if remote
        .iter()
        .any(|entry| entry.id == baseline.remote_id && !entry.trashed)
    {
        return Err(DesktopError::InvalidState(
            "Drive restored this reviewed item after confirmation; local bytes were left in place"
                .to_string(),
        ));
    }
    checked_recovery_local_entries(pair, state, item, guard)?;
    let recovery = recovery_destination(pair, &item.id, Some(&item.relative_path))?;
    guard.move_entry_to_recovery(&item.relative_path, &recovery, item.is_directory, || {
        guard.require_exact_pair_marker(&shellx_drive_desktop_core::PairMarker::from(pair))?;
        checked_recovery_local_entries(pair, state, item, guard)
    })?;
    Ok(recovery)
}

pub(super) fn remove_retained_root(
    pair: &SyncPair,
    guard: &crate::platform::unix::filesystem::UnixRootGuard,
) -> CoreResult<PathBuf> {
    let root_leaf = pair.local_root.file_name().ok_or_else(|| {
        DesktopError::UnsafePath("the paired Drive root has no local leaf".to_string())
    })?;
    let recovery = recovery_destination(pair, "retained-root", Some(Path::new(root_leaf)))?;
    let marker = shellx_drive_desktop_core::PairMarker::from(pair);
    guard.move_complete_root_to_recovery(&marker, &recovery, || {
        guard.require_exact_pair_marker(&marker)?;
        ensure_tree_has_no_links(&pair.local_root)?;
        Ok(())
    })?;
    Ok(recovery)
}

pub(super) fn rollback_retained_root(pair: &SyncPair, recovery: &Path) -> CoreResult<()> {
    let guard = crate::platform::unix::filesystem::UnixRootGuard::acquire(
        recovery,
        pair.local_root_identity.as_ref(),
    )?;
    guard.move_complete_root_to_recovery(
        &shellx_drive_desktop_core::PairMarker::from(pair),
        &pair.local_root,
        || Ok(()),
    )
}

fn checked_recovery_local_entries(
    pair: &SyncPair,
    state: &DesktopState,
    item: &ReviewItem,
    guard: &crate::platform::unix::filesystem::UnixRootGuard,
) -> CoreResult<()> {
    ensure_tree_has_no_links(&pair.local_root)?;
    let mut local = inspect_local_tree(&pair.local_root)?;
    if !local.issues.is_empty() {
        return Err(DesktopError::UnsafePath(
            "the reviewed local subtree contains an unsupported path; no recovery move was attempted"
                .to_string(),
        ));
    }
    for entry in local.entries.iter_mut().filter(|entry| entry.is_directory) {
        entry.directory_identity = Some(guard.local_directory_identity(&entry.relative_path)?);
    }
    reviewed_local_subtree_matches_baseline(item, &state.baseline, &local.entries)?;
    let affected = local
        .entries
        .iter()
        .filter(|entry| {
            entry.relative_path == item.relative_path
                || entry.relative_path.starts_with(&item.relative_path)
        })
        .count();
    if affected == 0 || affected.saturating_sub(1) != item.descendant_count {
        return Err(DesktopError::InvalidState(
            "the reviewed local subtree changed after confirmation; no recovery move was attempted"
                .to_string(),
        ));
    }
    Ok(())
}

fn recovery_destination(
    pair: &SyncPair,
    label: &str,
    relative: Option<&Path>,
) -> CoreResult<PathBuf> {
    let parent = pair.local_root.parent().ok_or_else(|| {
        DesktopError::UnsafePath("the selected Drive root has no recovery parent".to_string())
    })?;
    let recovery_root = parent.join(".shellx-drive-recovery");
    if recovery_root.starts_with(&pair.local_root) {
        return Err(DesktopError::UnsafePath(
            "recovery area must stay outside the paired root".to_string(),
        ));
    }
    ensure_private_staging_directory(&recovery_root)?;
    ensure_tree_has_no_links(&recovery_root)?;
    let safe_label = label
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '-')
        .collect::<String>();
    let relative = relative.ok_or_else(|| {
        DesktopError::UnsafePath("recovery destination requires a local entry".to_string())
    })?;
    if relative.as_os_str().is_empty() {
        return Err(DesktopError::UnsafePath(
            "recovery destination requires the paired root leaf".to_string(),
        ));
    }
    for attempt in 0..8_u8 {
        let batch = recovery_root.join(format!(
            "{}-{}-{attempt:02}",
            Utc::now().format("%Y%m%d-%H%M%S%f"),
            if safe_label.is_empty() {
                "review"
            } else {
                &safe_label
            },
        ));
        match std::fs::DirBuilder::new().mode(0o700).create(&batch) {
            Ok(()) => {
                ensure_private_staging_directory(&batch)?;
                let batch_guard =
                    crate::platform::unix::filesystem::UnixRootGuard::acquire(&batch, None)?;
                if let Some(parent) = relative
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                {
                    batch_guard.ensure_directory(parent)?;
                }
                return Ok(batch.join(relative));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(DesktopError::Io(error)),
        }
    }
    Err(DesktopError::InvalidState(
        "could not allocate a private recovery destination; local bytes were left in place"
            .to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_destination_requires_a_local_entry() {
        let pair = SyncPair {
            server_url: "https://drive.example.test".to_string(),
            account_email: "person@example.test".to_string(),
            workspace_id: "workspace".to_string(),
            workspace_name: "Workspace".to_string(),
            remote_root_id: None,
            remote_root_name: None,
            local_root: PathBuf::from("/tmp/Drive"),
            local_root_identity: None,
        };
        assert!(recovery_destination(&pair, "review", None).is_err());
    }
}
