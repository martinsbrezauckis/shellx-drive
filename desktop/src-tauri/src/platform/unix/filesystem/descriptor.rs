//! Openat-based descriptor and identity operations for a Unix Drive root.

mod child_root;
mod mutations;

pub(super) use child_root::*;
pub(super) use mutations::*;

use std::{
    ffi::{CString, OsStr, OsString},
    fs,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path},
};

use shellx_drive_desktop_core::{
    ensure_single_linked_regular_file, ensure_tree_has_no_links, validate_local_relative,
    validate_private_staging_file, DesktopError, DirectoryIdentity, DirectoryIdentityPlatform,
    LocalEntry, LocalScanLimits, Result as CoreResult,
};

use super::UnixRootGuard;

pub(super) fn acquire(
    root: &Path,
    expected: Option<&DirectoryIdentity>,
) -> CoreResult<UnixRootGuard> {
    ensure_tree_has_no_links(root)?;
    let root_file = open_absolute_directory(root)?;
    let identity = directory_identity(&root_file)?;
    if let Some(expected) = expected {
        if expected.platform != DirectoryIdentityPlatform::Unix {
            return Err(DesktopError::InvalidState(
                "the selected Drive folder has a non-Unix identity; pair it again".to_string(),
            ));
        }
        if expected != &identity {
            return Err(DesktopError::UnsafePath(format!(
                "the configured Drive folder was replaced: {}",
                root.display()
            )));
        }
    }
    Ok(UnixRootGuard {
        root: root_file,
        identity,
        path: root.to_path_buf(),
    })
}

pub(super) fn local_regular_entry(
    guard: &UnixRootGuard,
    relative: &Path,
) -> CoreResult<LocalEntry> {
    let mut file = open_regular_file(guard, relative)?;
    let before = file_identity(&file)?;
    let maximum = LocalScanLimits::default().max_file_bytes;
    if before.size > maximum {
        return Err(DesktopError::InvalidState(format!(
            "local file exceeds the {maximum}-byte desktop scan limit: {}",
            relative.display()
        )));
    }
    let (content_hash, bytes) = shellx_drive_desktop_core::hash_reader_bounded(&mut file, maximum)?;
    if bytes != before.size || file_identity(&file)? != before {
        return Err(DesktopError::UnsafePath(
            "local source changed while its descriptor-bound row was inspected".to_string(),
        ));
    }
    Ok(LocalEntry {
        relative_path: relative.to_path_buf(),
        content_hash: Some(content_hash),
        size_bytes: bytes,
        is_directory: false,
        directory_identity: None,
    })
}

pub(super) fn local_entry_is_absent(guard: &UnixRootGuard, relative: &Path) -> CoreResult<bool> {
    ensure_identity(guard, "destination absence observation")?;
    let (parent, leaf) = destination_parent(guard, relative)?;
    let leaf = c_string(&leaf)?;
    let mut metadata = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            &mut metadata,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        return Ok(false);
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::NotFound {
        Ok(true)
    } else {
        Err(DesktopError::Io(error))
    }
}

pub(super) fn local_directory_identity(
    guard: &UnixRootGuard,
    relative: &Path,
) -> CoreResult<DirectoryIdentity> {
    ensure_identity(guard, "directory identity observation")?;
    if relative.as_os_str().is_empty() {
        return directory_identity(&guard.root);
    }
    validate_local_relative(relative).map_err(|issue| DesktopError::UnsafePath(issue.reason))?;
    let mut directory = guard.root.try_clone()?;
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(DesktopError::UnsafePath(
                "Drive folder has an unsafe path component".to_string(),
            ));
        };
        directory = open_directory_at(&directory, component)?;
    }
    directory_identity(&directory)
}

pub(super) fn create_private_staging_file(
    guard: &UnixRootGuard,
    relative: &Path,
) -> CoreResult<fs::File> {
    ensure_identity(guard, "private staging creation")?;
    let (parent, leaf) = destination_parent(guard, relative)?;
    let file = create_regular_file_at(&parent, &leaf)?;
    validate_private_staging_file(&file)?;
    Ok(file)
}

pub(super) fn open_regular_file(guard: &UnixRootGuard, relative: &Path) -> CoreResult<fs::File> {
    ensure_identity(guard, "local source opening")?;
    let (parent, leaf) = destination_parent(guard, relative)?;
    let file = open_regular_file_at(&parent, &leaf)?;
    ensure_single_linked_regular_file(&file, relative)?;
    Ok(file)
}

pub(super) fn ensure_identity(guard: &UnixRootGuard, operation: &str) -> CoreResult<()> {
    // The held descriptor proves the originally selected inode remains a
    // directory. Re-open the configured absolute path too: otherwise an
    // attacker could rename that directory aside and put a different directory
    // at the configured path while the stale descriptor still looked valid.
    let current = open_absolute_directory(&guard.path)?;
    if directory_identity(&guard.root)? != guard.identity
        || directory_identity(&current)? != guard.identity
    {
        return Err(DesktopError::UnsafePath(format!(
            "the selected Drive root or its configured path changed during {operation}"
        )));
    }
    Ok(())
}

pub(super) fn destination_parent(
    guard: &UnixRootGuard,
    relative: &Path,
) -> CoreResult<(fs::File, OsString)> {
    validate_local_relative(relative).map_err(|issue| DesktopError::UnsafePath(issue.reason))?;
    let mut components = relative.components().collect::<Vec<_>>();
    let leaf = match components.pop() {
        Some(Component::Normal(leaf)) => leaf.to_os_string(),
        _ => {
            return Err(DesktopError::UnsafePath(
                "publication destination has no normal leaf".to_string(),
            ));
        }
    };
    let mut parent = guard.root.try_clone()?;
    for component in components {
        let Component::Normal(component) = component else {
            return Err(DesktopError::UnsafePath(
                "publication destination has an unsafe component".to_string(),
            ));
        };
        parent = open_directory_at(&parent, component)?;
    }
    Ok((parent, leaf))
}

pub(super) fn open_absolute_parent(path: &Path) -> CoreResult<(fs::File, OsString)> {
    let parent = path.parent().ok_or_else(|| {
        DesktopError::UnsafePath("private staged file has no parent directory".to_string())
    })?;
    let leaf = path.file_name().ok_or_else(|| {
        DesktopError::UnsafePath("private staged file has no normal leaf".to_string())
    })?;
    Ok((open_absolute_directory(parent)?, leaf.to_os_string()))
}

fn open_absolute_directory(path: &Path) -> CoreResult<fs::File> {
    if !path.is_absolute() {
        return Err(DesktopError::UnsafePath(format!(
            "Unix filesystem boundary requires an absolute directory: {}",
            path.display()
        )));
    }
    let mut directory = open_directory_path(OsStr::new("/"))?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(component) => directory = open_directory_at(&directory, component)?,
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(DesktopError::UnsafePath(format!(
                    "Unix filesystem boundary rejects an unsafe directory component: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(directory)
}

fn open_directory_path(path: &OsStr) -> CoreResult<fs::File> {
    let path = c_string(path)?;
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    file_from_descriptor(descriptor, "open Drive root directory")
}

pub(super) fn open_directory_at(parent: &fs::File, name: &OsStr) -> CoreResult<fs::File> {
    let name = c_string(name)?;
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    file_from_descriptor(descriptor, "open Drive directory")
}

pub(super) fn open_regular_file_at(parent: &fs::File, name: &OsStr) -> CoreResult<fs::File> {
    let name = c_string(name)?;
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            // A changed leaf may be a FIFO. Open without waiting for a writer,
            // then admit only the regular inode observed on this descriptor.
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    let file = file_from_descriptor(descriptor, "open regular file")?;
    if !file.metadata()?.is_file() {
        return Err(DesktopError::UnsafePath(
            "filesystem object is not a regular file".to_string(),
        ));
    }
    Ok(file)
}

pub(super) fn create_regular_file_at(parent: &fs::File, name: &OsStr) -> CoreResult<fs::File> {
    let name = c_string(name)?;
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    let file = file_from_descriptor(descriptor, "create regular file")?;
    if !file.metadata()?.is_file() {
        return Err(DesktopError::UnsafePath(
            "created filesystem object is not a regular file".to_string(),
        ));
    }
    Ok(file)
}

fn mkdir_at(parent: &fs::File, name: &OsStr) -> CoreResult<()> {
    let name = c_string(name)?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(DesktopError::Io(error));
        }
    }
    Ok(())
}

fn file_from_descriptor(descriptor: libc::c_int, operation: &str) -> CoreResult<fs::File> {
    if descriptor < 0 {
        return Err(DesktopError::Io(std::io::Error::last_os_error()));
    }
    let file = unsafe { fs::File::from_raw_fd(descriptor) };
    if !file.metadata()?.is_dir() && operation.contains("directory") {
        return Err(DesktopError::UnsafePath(format!(
            "{operation} did not resolve a directory"
        )));
    }
    Ok(file)
}

pub(super) fn directory_identity(directory: &fs::File) -> CoreResult<DirectoryIdentity> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir() {
        return Err(DesktopError::UnsafePath(
            "native directory identity was requested for a non-directory".to_string(),
        ));
    }
    Ok(DirectoryIdentity::unix(metadata.dev(), metadata.ino()))
}

pub(super) fn device_number(directory: &fs::File) -> CoreResult<u64> {
    Ok(directory.metadata()?.dev())
}
