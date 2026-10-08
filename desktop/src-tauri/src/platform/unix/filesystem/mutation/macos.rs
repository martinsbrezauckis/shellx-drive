//! macOS private-recovery replacement body.

use std::{
    ffi::OsString,
    fs,
    io::{Seek, SeekFrom},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use shellx_drive_desktop_core::{
    copy_and_hash_reader_bounded, ensure_single_linked_regular_file, validate_private_staging_file,
    DesktopError, LocalEntry, LocalScanLimits, Result as CoreResult,
};

use super::{
    super::{
        descriptor::{
            destination_parent, device_number, entry_at_matches, file_identity,
            open_absolute_parent, open_regular_file_at, rename_exchange_at, FileIdentity,
        },
        ReplacingPublication, UnixRootGuard,
    },
    file_matches_local_entry,
};

pub(crate) struct MacOsPreparedReplacement {
    destination_parent: fs::File,
    destination_leaf: OsString,
    staging_parent: fs::File,
    staging_leaf: OsString,
    staged: fs::File,
    staged_identity: FileIdentity,
    existing: fs::File,
    existing_identity: FileIdentity,
    expected_local: LocalEntry,
    relative_destination: PathBuf,
    private_recovery: PathBuf,
}

/// Prepare an independent recovery body without publishing any scratch name
/// into the mirror. The caller may await one final remote witness before using
/// [`MacOsPreparedReplacement::publish`].
pub(crate) fn prepare_staged_file_replacement(
    guard: &UnixRootGuard,
    staged: &Path,
    relative_destination: &Path,
    expected_local: &LocalEntry,
) -> CoreResult<Option<MacOsPreparedReplacement>> {
    guard.ensure_identity("replacement preparation")?;
    let (destination_parent, destination_leaf) = destination_parent(guard, relative_destination)?;
    let (staging_parent, staging_leaf) = open_absolute_parent(staged)?;
    let staged_file = open_regular_file_at(&staging_parent, &staging_leaf)?;
    validate_private_staging_file(&staged_file)?;
    ensure_single_linked_regular_file(&staged_file, staged)?;
    if device_number(&staging_parent)? != device_number(&destination_parent)? {
        return Err(DesktopError::UnsafePath(
            "private staging and the selected Drive folder are on different filesystems"
                .to_string(),
        ));
    }

    let existing = open_regular_file_at(&destination_parent, &destination_leaf)?;
    ensure_single_linked_regular_file(&existing, relative_destination)?;
    let existing_identity = file_identity(&existing)?;
    if !file_matches_local_entry(&existing, expected_local)? {
        return Ok(None);
    }
    let staged_identity = file_identity(&staged_file)?;
    let private_recovery = recovery_staging_path(staged)?;
    copy_open_file_to_private_staging(&existing, relative_destination, &private_recovery)?;
    if !current_destination_matches(
        guard,
        &destination_parent,
        &destination_leaf,
        &existing,
        existing_identity,
        expected_local,
        relative_destination,
    )? || !private_recovery_matches(&private_recovery, expected_local)?
    {
        return Ok(None);
    }
    Ok(Some(MacOsPreparedReplacement {
        destination_parent,
        destination_leaf,
        staging_parent,
        staging_leaf,
        staged: staged_file,
        staged_identity,
        existing,
        existing_identity,
        expected_local: expected_local.clone(),
        relative_destination: relative_destination.to_path_buf(),
        private_recovery,
    }))
}

impl MacOsPreparedReplacement {
    /// Publish only after the caller has refreshed its remote witness. Every
    /// uncertain outcome leaves the downloaded and prior local bodies in the
    /// caller-owned private batch for explicit review.
    pub(crate) fn publish<F>(
        self,
        guard: &UnixRootGuard,
        mut revalidate_local: F,
    ) -> CoreResult<ReplacingPublication>
    where
        F: FnMut() -> CoreResult<()>,
    {
        let mut exchange_completed = false;
        let result: CoreResult<ReplacingPublication> = (|| {
            guard.ensure_identity("replacement publication")?;
            if !current_destination_matches(
                guard,
                &self.destination_parent,
                &self.destination_leaf,
                &self.existing,
                self.existing_identity,
                &self.expected_local,
                &self.relative_destination,
            )? {
                return Ok(ReplacingPublication::NeedsReview {
                    recovery_leaf: None,
                });
            }
            revalidate_local()?;
            validate_private_staging_file(&self.staged)?;
            if !current_destination_matches(
                guard,
                &self.destination_parent,
                &self.destination_leaf,
                &self.existing,
                self.existing_identity,
                &self.expected_local,
                &self.relative_destination,
            )? || !entry_at_matches(
                &self.staging_parent,
                &self.staging_leaf,
                self.staged_identity,
            )? || !private_recovery_matches(&self.private_recovery, &self.expected_local)?
            {
                return Ok(ReplacingPublication::NeedsReview {
                    recovery_leaf: None,
                });
            }
            rename_exchange_at(
                &self.staging_parent,
                &self.staging_leaf,
                &self.destination_parent,
                &self.destination_leaf,
            )?;
            exchange_completed = true;
            if !entry_at_matches(
                &self.destination_parent,
                &self.destination_leaf,
                self.staged_identity,
            )? || !entry_at_matches(
                &self.staging_parent,
                &self.staging_leaf,
                self.existing_identity,
            )? || !file_matches_local_entry(
                &open_regular_file_at(&self.staging_parent, &self.staging_leaf)?,
                &self.expected_local,
            )? || !private_recovery_matches(&self.private_recovery, &self.expected_local)?
            {
                return Ok(ReplacingPublication::NeedsReview {
                    recovery_leaf: Some("local-recovery".to_string()),
                });
            }
            Ok(ReplacingPublication::Published)
        })();

        match result {
            Ok(outcome) => Ok(outcome),
            Err(_) => Ok(ReplacingPublication::NeedsReview {
                recovery_leaf: exchange_completed.then(|| "local-recovery".to_string()),
            }),
        }
    }
}

fn current_destination_matches(
    guard: &UnixRootGuard,
    parent: &fs::File,
    leaf: &std::ffi::OsStr,
    existing: &fs::File,
    expected_identity: FileIdentity,
    expected_local: &LocalEntry,
    relative_destination: &Path,
) -> CoreResult<bool> {
    guard.ensure_identity("replacement local witness")?;
    if !entry_at_matches(parent, leaf, expected_identity)? {
        return Ok(false);
    }
    ensure_single_linked_regular_file(existing, relative_destination)?;
    file_matches_local_entry(existing, expected_local)
}

fn recovery_staging_path(staged: &Path) -> CoreResult<PathBuf> {
    let parent = staged.parent().ok_or_else(|| {
        DesktopError::UnsafePath("private staged file has no parent directory".to_string())
    })?;
    Ok(parent.join("local-recovery"))
}

fn private_recovery_matches(path: &Path, expected: &LocalEntry) -> CoreResult<bool> {
    let (parent, leaf) = open_absolute_parent(path)?;
    let recovery = open_regular_file_at(&parent, &leaf)?;
    validate_private_staging_file(&recovery)?;
    ensure_single_linked_regular_file(&recovery, path)?;
    file_matches_local_entry(&recovery, expected)
}

fn copy_open_file_to_private_staging(
    source: &fs::File,
    relative_source: &Path,
    destination: &Path,
) -> CoreResult<()> {
    ensure_single_linked_regular_file(source, relative_source)?;
    let before = file_identity(source)?;
    if before.size > LocalScanLimits::default().max_file_bytes {
        return Err(DesktopError::InvalidState(
            "local recovery source exceeds the desktop sync size limit".to_string(),
        ));
    }
    let mut reader = source.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut writer = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(destination)?;
    shellx_drive_desktop_core::protect_new_private_staging_file(&writer)?;
    let (_, copied) = copy_and_hash_reader_bounded(
        &mut reader,
        &mut writer,
        LocalScanLimits::default().max_file_bytes,
    )?;
    writer.sync_all()?;
    if copied != before.size || file_identity(source)? != before {
        return Err(DesktopError::UnsafePath(
            "local source changed while its macOS recovery copy was prepared".to_string(),
        ));
    }
    Ok(())
}
