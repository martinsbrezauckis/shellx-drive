//! Local-only retained-root recovery.

use super::super::*;

pub(super) fn move_retained_root_to_recovery(pair: &SyncPair) -> CoreResult<PathBuf> {
    ensure_tree_has_no_links(&pair.local_root)?;
    let parent = pair.local_root.parent().ok_or_else(|| {
        DesktopError::UnsafePath(
            "the retained Drive location has no parent for a recovery area".to_string(),
        )
    })?;
    let leaf = pair.local_root.file_name().ok_or_else(|| {
        DesktopError::UnsafePath("the retained Drive location has no local leaf name".to_string())
    })?;
    let recovery_root = parent.join(".shellx-drive-recovery");
    ensure_private_staging_directory(&recovery_root)?;
    ensure_tree_has_no_links(&recovery_root)?;
    let batch = recovery_root.join(format!(
        "{}-retained-root",
        Utc::now().format("%Y%m%d-%H%M%S")
    ));
    let destination = batch.join(leaf);
    if batch.exists() || destination.exists() {
        return Err(DesktopError::InvalidState(
            "the retained-root recovery destination is occupied; local bytes were left in place"
                .to_string(),
        ));
    }
    ensure_private_staging_directory(&batch)?;
    let _pins = pin_absolute_directory_chain(&batch)?;
    move_existing_entry_by_verified_parent(
        parent,
        &pair.local_root,
        &destination,
        &recovery_root,
        || {
            pair_marker::require_exact(&pair.local_root, &PairMarker::from(pair))?;
            ensure_tree_has_no_links(&pair.local_root)?;
            if destination.exists() {
                return Err(DesktopError::InvalidState(
                "the retained-root recovery destination became occupied; local bytes were left in place".to_string(),
            ));
            }
            Ok(())
        },
    )?;
    Ok(destination)
}

/// Best-effort rollback when durable pair-state removal fails after the local
/// rename. A successful rollback leaves both the original marker and active
/// state intact, so retry remains truthful rather than stranding bytes.
pub(super) fn restore_retained_root_after_state_failure(
    pair: &SyncPair,
    recovery: &Path,
) -> CoreResult<()> {
    let parent = pair.local_root.parent().ok_or_else(|| {
        DesktopError::UnsafePath("the retained Drive location has no parent".to_string())
    })?;
    let recovery_root = recovery.parent().and_then(Path::parent).ok_or_else(|| {
        DesktopError::UnsafePath("retained-root recovery path has no batch parent".to_string())
    })?;
    if pair.local_root.exists() {
        return Err(DesktopError::InvalidState(
            "the original retained-root path became occupied; recovery bytes were left in place"
                .to_string(),
        ));
    }
    move_existing_entry_by_verified_parent(
        recovery_root,
        recovery,
        &pair.local_root,
        parent,
        || {
            pair_marker::require_exact(recovery, &PairMarker::from(pair))?;
            ensure_tree_has_no_links(recovery)?;
            if pair.local_root.exists() {
                return Err(DesktopError::InvalidState(
                    "the original retained-root path became occupied; recovery bytes were left in place"
                        .to_string(),
                ));
            }
            Ok(())
        },
    )
}
