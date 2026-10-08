//! Linux descriptor-exchange replacement body.

use std::{
    ffi::OsString,
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

use shellx_drive_desktop_core::{
    ensure_single_linked_regular_file, validate_private_staging_file, DesktopError, LocalEntry,
    Result as CoreResult,
};

use super::{
    super::{
        descriptor::{
            create_regular_file_at, destination_parent, device_number, entry_at_matches,
            file_identity, open_absolute_parent, open_regular_file_at, rename_exchange_at,
            FileIdentity,
        },
        ReplacingPublication, UnixRootGuard,
    },
    file_matches_local_entry,
};

pub(crate) struct LinuxPreparedReplacement {
    destination_parent: fs::File,
    destination_leaf: OsString,
    staging_parent: fs::File,
    staging_leaf: OsString,
    staged_identity: FileIdentity,
    existing: fs::File,
    existing_identity: FileIdentity,
    expected_local: LocalEntry,
    recovery_leaf: OsString,
    recovery_identity: FileIdentity,
}

/// Copy the exact checked local body into the caller-owned private download
/// batch. No recovery name or extra hard link is ever published into the
/// scanned Drive root. The caller may await one final remote witness before
/// publication.
pub(crate) fn prepare_staged_file_replacement(
    guard: &UnixRootGuard,
    staged: &Path,
    relative_destination: &Path,
    expected_local: &LocalEntry,
) -> CoreResult<Option<LinuxPreparedReplacement>> {
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
    let recovery_leaf = OsString::from("local-recovery");
    let mut recovery = create_regular_file_at(&staging_parent, &recovery_leaf)?;
    let mut source = existing.try_clone()?;
    source.seek(SeekFrom::Start(0))?;
    let copy_limit = expected_local.size_bytes.checked_add(1).ok_or_else(|| {
        DesktopError::InvalidState("local replacement size overflowed".to_string())
    })?;
    let copied = std::io::copy(&mut source.take(copy_limit), &mut recovery)?;
    recovery.flush()?;
    recovery.sync_all()?;
    recovery.seek(SeekFrom::Start(0))?;
    validate_private_staging_file(&recovery)?;
    ensure_single_linked_regular_file(&recovery, Path::new(&recovery_leaf))?;
    let recovery_identity = file_identity(&recovery)?;
    if copied != expected_local.size_bytes
        || !file_matches_local_entry(&recovery, expected_local)?
        || !file_matches_local_entry(&existing, expected_local)?
    {
        return Ok(None);
    }
    Ok(Some(LinuxPreparedReplacement {
        destination_parent,
        destination_leaf,
        staging_parent,
        staging_leaf,
        staged_identity,
        existing,
        existing_identity,
        expected_local: expected_local.clone(),
        recovery_leaf,
        recovery_identity,
    }))
}

impl LinuxPreparedReplacement {
    /// Exchange only after the caller refreshed its remote witness. Any
    /// uncertain outcome keeps both old and downloaded bytes in the private
    /// batch for an explicit review.
    pub(crate) fn publish<F>(
        self,
        guard: &UnixRootGuard,
        revalidate_local: F,
    ) -> CoreResult<ReplacingPublication>
    where
        F: FnOnce() -> CoreResult<()>,
    {
        let mut exchange_completed = false;
        let result: CoreResult<ReplacingPublication> = (|| {
            guard.ensure_identity("replacement publication")?;
            if !self.current_destination_matches()? || !self.private_recovery_matches()? {
                return Ok(ReplacingPublication::NeedsReview {
                    recovery_leaf: None,
                });
            }
            revalidate_local()?;
            if !self.current_destination_matches()? || !self.private_recovery_matches()? {
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
            )? || !self.private_recovery_matches()?
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

    fn current_destination_matches(&self) -> CoreResult<bool> {
        Ok(entry_at_matches(
            &self.destination_parent,
            &self.destination_leaf,
            self.existing_identity,
        )? && file_matches_local_entry(&self.existing, &self.expected_local)?)
    }

    fn private_recovery_matches(&self) -> CoreResult<bool> {
        Ok(entry_at_matches(
            &self.staging_parent,
            &self.recovery_leaf,
            self.recovery_identity,
        )? && file_matches_local_entry(
            &open_regular_file_at(&self.staging_parent, &self.recovery_leaf)?,
            &self.expected_local,
        )?)
    }
}
