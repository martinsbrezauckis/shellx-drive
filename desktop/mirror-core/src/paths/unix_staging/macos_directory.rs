//! Open private directories through pinned, no-follow parent descriptors.

use std::{
    ffi::{CStr, CString, OsStr},
    fs,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path},
};

use crate::{DesktopError, Result};

use super::{macos_acl, validate_owner_private};

const DIRECTORY_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;

fn name(value: &OsStr) -> Result<CString> {
    CString::new(value.as_bytes())
        .map_err(|_| DesktopError::UnsafePath("private staging path contains a NUL".into()))
}

fn from_fd(fd: libc::c_int) -> Result<fs::File> {
    if fd < 0 {
        return Err(DesktopError::Io(std::io::Error::last_os_error()));
    }
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

pub(super) fn open_directory(path: &Path) -> Result<fs::File> {
    let base = if path.is_absolute() { c"/" } else { c"." };
    let mut directory = from_fd(unsafe { libc::open(base.as_ptr(), DIRECTORY_FLAGS) })?;
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => {
                let part = name(part)?;
                directory = from_fd(unsafe {
                    libc::openat(directory.as_raw_fd(), part.as_ptr(), DIRECTORY_FLAGS)
                })?;
            }
            _ => {
                return Err(DesktopError::UnsafePath(
                    "private staging has an unsafe directory component".into(),
                ))
            }
        }
    }
    Ok(directory)
}

pub(in crate::paths) fn validate_private_directory(path: &Path) -> Result<()> {
    let directory = open_directory(path)?;
    validate_owner_private(&directory.metadata()?, path, true)?;
    macos_acl::validate(&directory)
}

pub(in crate::paths) fn create_private_directory(path: &Path) -> Result<()> {
    let parent_path = path.parent().ok_or_else(|| {
        DesktopError::UnsafePath("private staging directory has no parent".into())
    })?;
    let leaf = name(path.file_name().ok_or_else(|| {
        DesktopError::UnsafePath("private staging directory has no leaf".into())
    })?)?;
    let parent = open_directory(parent_path)?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), leaf.as_ptr(), 0o700) } != 0 {
        return Err(DesktopError::Io(std::io::Error::last_os_error()));
    }
    let mut created = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            leaf.as_ptr(),
            &mut created,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(DesktopError::Io(std::io::Error::last_os_error()));
    }
    let directory =
        from_fd(unsafe { libc::openat(parent.as_raw_fd(), leaf.as_ptr(), DIRECTORY_FLAGS) })?;
    let before = directory.metadata()?;
    validate_owner_private(&before, path, true)?;
    if before.dev() != created.st_dev as u64
        || before.ino() != created.st_ino
        || before.nlink() == 0
    {
        return Err(DesktopError::UnsafePath(
            "new private staging directory changed before protection".into(),
        ));
    }
    ensure_empty(&directory)?;
    macos_acl::clear(&directory)?;
    let after = directory.metadata()?;
    if (
        before.dev(),
        before.ino(),
        before.uid(),
        before.mode(),
        before.nlink(),
    ) != (
        after.dev(),
        after.ino(),
        after.uid(),
        after.mode(),
        after.nlink(),
    ) {
        return Err(DesktopError::UnsafePath(
            "new private staging directory changed during protection".into(),
        ));
    }
    ensure_empty(&directory)?;
    validate_owner_private(&after, path, true)?;
    macos_acl::validate(&directory)?;
    let current = open_directory(path)?.metadata()?;
    if current.dev() != before.dev() || current.ino() != before.ino() {
        return Err(DesktopError::UnsafePath(
            "new private staging directory path changed during protection".into(),
        ));
    }
    Ok(())
}

fn ensure_empty(directory: &fs::File) -> Result<()> {
    // fdopendir owns this duplicate; the admitted directory FD stays retained.
    let duplicate = unsafe { libc::dup(directory.as_raw_fd()) };
    if duplicate < 0 {
        return Err(DesktopError::Io(std::io::Error::last_os_error()));
    }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(duplicate) };
        return Err(DesktopError::Io(error));
    }
    let result = (|| {
        unsafe { libc::rewinddir(stream) };
        loop {
            unsafe { *libc::__error() = 0 };
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                let error = std::io::Error::last_os_error();
                return if error.raw_os_error() == Some(0) {
                    Ok(())
                } else {
                    Err(DesktopError::Io(error))
                };
            }
            let entry_name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if entry_name != b"." && entry_name != b".." {
                return Err(DesktopError::UnsafePath(
                    "new private staging directory is not empty".into(),
                ));
            }
        }
    })();
    unsafe { libc::closedir(stream) };
    result
}
