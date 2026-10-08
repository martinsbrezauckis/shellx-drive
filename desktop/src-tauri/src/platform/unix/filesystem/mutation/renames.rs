//! Cross-platform descriptor-bound no-replace mutation primitives.

use std::{fs, path::Path};

use shellx_drive_desktop_core::{
    ensure_single_linked_regular_file, ensure_tree_has_no_links, validate_private_staging_file,
    DesktopError, PairMarker, Result as CoreResult,
};

use super::super::{
    descriptor::{
        destination_parent, device_number, directory_identity, entry_at_matches, file_identity,
        open_absolute_parent, open_entry_at, rename_noreplace_at,
    },
    UnixRootGuard,
};

pub(crate) fn move_entry_noreplace<F>(
    guard: &UnixRootGuard,
    relative_source: &Path,
    relative_destination: &Path,
    is_directory: bool,
    revalidate: F,
) -> CoreResult<()>
where
    F: FnOnce() -> CoreResult<()>,
{
    let (source_parent, source_leaf) = destination_parent(guard, relative_source)?;
    let (destination_parent, destination_leaf) = destination_parent(guard, relative_destination)?;
    move_checked_entry(
        guard,
        &source_parent,
        &source_leaf,
        &destination_parent,
        &destination_leaf,
        is_directory,
        revalidate,
    )
}

pub(crate) fn move_entry_to_recovery<F>(
    guard: &UnixRootGuard,
    relative_source: &Path,
    absolute_destination: &Path,
    is_directory: bool,
    revalidate: F,
) -> CoreResult<()>
where
    F: FnOnce() -> CoreResult<()>,
{
    let (source_parent, source_leaf) = destination_parent(guard, relative_source)?;
    let (destination_parent, destination_leaf) = open_absolute_parent(absolute_destination)?;
    move_checked_entry(
        guard,
        &source_parent,
        &source_leaf,
        &destination_parent,
        &destination_leaf,
        is_directory,
        revalidate,
    )
}

/// Publish a complete private staging payload through an atomic descriptor-
/// relative no-replace rename, so a reviewed folder restore is never partial.
pub(crate) fn publish_staged_entry_noreplace<F>(
    guard: &UnixRootGuard,
    staged: &Path,
    relative_destination: &Path,
    is_directory: bool,
    revalidate: F,
) -> CoreResult<()>
where
    F: FnOnce() -> CoreResult<()>,
{
    guard.ensure_identity("staged tree publication preparation")?;
    let (destination_parent, destination_leaf) = destination_parent(guard, relative_destination)?;
    let (staging_parent, staging_leaf) = open_absolute_parent(staged)?;
    let staging = open_entry_at(&staging_parent, &staging_leaf, is_directory)?;
    let expected = file_identity(&staging)?;
    if expected.is_directory != is_directory {
        return Err(DesktopError::UnsafePath(
            "private staged publication has the wrong entry kind".to_string(),
        ));
    }
    if is_directory {
        ensure_tree_has_no_links(staged)?;
    } else {
        validate_private_staging_file(&staging)?;
        ensure_single_linked_regular_file(&staging, staged)?;
    }
    if device_number(&staging_parent)? != device_number(&destination_parent)? {
        return Err(DesktopError::UnsafePath(
            "private staging and the selected Drive folder are on different filesystems"
                .to_string(),
        ));
    }
    revalidate()?;
    guard.ensure_identity("staged tree publication")?;
    if !entry_at_matches(&staging_parent, &staging_leaf, expected)? {
        return Err(DesktopError::UnsafePath(
            "private staged publication changed before its native move".to_string(),
        ));
    }
    if is_directory {
        ensure_tree_has_no_links(staged)?;
    } else {
        ensure_single_linked_regular_file(&staging, staged)?;
    }
    rename_noreplace_at(
        &staging_parent,
        &staging_leaf,
        &destination_parent,
        &destination_leaf,
    )?;
    if !entry_at_matches(&destination_parent, &destination_leaf, expected)? {
        return Err(DesktopError::UnsafePath(
            "published destination did not retain the exact staged entry".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn move_complete_root_to_recovery<F>(
    guard: &UnixRootGuard,
    marker: &PairMarker,
    absolute_destination: &Path,
    revalidate: F,
) -> CoreResult<()>
where
    F: FnOnce() -> CoreResult<()>,
{
    guard.ensure_identity("retained-root recovery preparation")?;
    guard.require_exact_pair_marker(marker)?;
    let (source_parent, source_leaf) = open_absolute_parent(&guard.path)?;
    let source_root = open_entry_at(&source_parent, &source_leaf, true)?;
    if directory_identity(&source_root)? != *guard.identity() {
        return Err(DesktopError::UnsafePath(
            "the retained Drive root path no longer names the verified paired directory"
                .to_string(),
        ));
    }
    let (destination_parent, destination_leaf) = open_absolute_parent(absolute_destination)?;
    move_checked_entry(
        guard,
        &source_parent,
        &source_leaf,
        &destination_parent,
        &destination_leaf,
        true,
        || {
            guard.require_exact_pair_marker(marker)?;
            revalidate()
        },
    )
}

fn move_checked_entry<F>(
    guard: &UnixRootGuard,
    source_parent: &fs::File,
    source_leaf: &std::ffi::OsStr,
    destination_parent: &fs::File,
    destination_leaf: &std::ffi::OsStr,
    is_directory: bool,
    revalidate: F,
) -> CoreResult<()>
where
    F: FnOnce() -> CoreResult<()>,
{
    guard.ensure_identity("rename preparation")?;
    if device_number(source_parent)? != device_number(destination_parent)? {
        return Err(DesktopError::UnsafePath(
            "recovery and selected Drive folders are on different filesystems".to_string(),
        ));
    }
    let source = open_entry_at(source_parent, source_leaf, is_directory)?;
    if !is_directory {
        ensure_single_linked_regular_file(&source, Path::new(source_leaf))?;
    }
    let expected = file_identity(&source)?;
    revalidate()?;
    guard.ensure_identity("rename publication")?;
    if !entry_at_matches(source_parent, source_leaf, expected)? {
        return Err(DesktopError::UnsafePath(
            "local source changed before its descriptor-bound rename".to_string(),
        ));
    }
    // The kernel refuses an occupied destination atomically. No caller may
    // turn an observed absence into replacement by racing a new file in.
    rename_noreplace_at(
        source_parent,
        source_leaf,
        destination_parent,
        destination_leaf,
    )?;
    if !entry_at_matches(destination_parent, destination_leaf, expected)? {
        return Err(DesktopError::UnsafePath(
            "rename destination did not retain the exact checked source".to_string(),
        ));
    }
    Ok(())
}
