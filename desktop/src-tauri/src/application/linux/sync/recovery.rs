use super::*;

pub(super) fn checked_recovery_local_entries(
    pair: &SyncPair,
    state: &shellx_drive_desktop_core::DesktopState,
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

pub(super) fn recovery_destination(
    pair: &SyncPair,
    label: &str,
    relative: Option<&Path>,
) -> CoreResult<PathBuf> {
    let parent = pair.local_root.parent().ok_or_else(|| {
        DesktopError::UnsafePath("the selected Drive root has no recovery parent".to_string())
    })?;
    let recovery_root = parent.join(".shellx-drive-recovery");
    ensure_private_staging_directory(&recovery_root)?;
    let safe_label = label
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '-')
        .collect::<String>();
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
                let relative = relative.unwrap_or_else(|| Path::new(""));
                if let Some(parent) = relative
                    .parent()
                    .filter(|path| !path.as_os_str().is_empty())
                {
                    batch_guard.ensure_directory(parent)?;
                }
                let destination = if relative.as_os_str().is_empty() {
                    return Err(DesktopError::UnsafePath(
                        "recovery destination requires the paired root leaf".to_string(),
                    ));
                } else {
                    batch.join(relative)
                };
                return Ok(destination);
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
