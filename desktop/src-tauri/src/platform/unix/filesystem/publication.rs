//! Staged-file publication into a descriptor-bound Unix Drive root.

use std::path::Path;

use shellx_drive_desktop_core::{
    ensure_single_linked_regular_file, validate_private_staging_file, DesktopError,
    Result as CoreResult,
};

use super::{
    descriptor::{
        destination_parent, device_number, ensure_identity, open_absolute_parent,
        open_regular_file_at, rename_at, unlink_at,
    },
    UnixRootGuard,
};

pub(super) fn publish_staged_file(
    guard: &UnixRootGuard,
    staged: &Path,
    relative_destination: &Path,
    replace_existing: bool,
) -> CoreResult<()> {
    ensure_identity(guard, "publication")?;
    let (destination_parent, destination_leaf) = destination_parent(guard, relative_destination)?;
    let (staging_parent, staging_leaf) = open_absolute_parent(staged)?;
    let staging = open_regular_file_at(&staging_parent, &staging_leaf)?;
    validate_private_staging_file(&staging)?;
    ensure_single_linked_regular_file(&staging, staged)?;
    if device_number(&staging_parent)? != device_number(&destination_parent)? {
        return Err(DesktopError::UnsafePath(
            "private staging and the selected Drive folder are on different filesystems"
                .to_string(),
        ));
    }
    if replace_existing {
        let existing = open_regular_file_at(&destination_parent, &destination_leaf)?;
        ensure_single_linked_regular_file(&existing, relative_destination)?;
        rename_at(
            &staging_parent,
            &staging_leaf,
            &destination_parent,
            &destination_leaf,
        )
    } else {
        super::descriptor::link_at(
            &staging_parent,
            &staging_leaf,
            &destination_parent,
            &destination_leaf,
        )?;
        unlink_at(&staging_parent, &staging_leaf)
    }
}
