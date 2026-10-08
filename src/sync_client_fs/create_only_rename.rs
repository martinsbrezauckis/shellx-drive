//! Atomic, create-only moves within the already-open sync cache tree.

use std::{io, path::Path};

use super::SafeCacheRoot;

pub(super) fn rename_new(
    root: &SafeCacheRoot,
    source: &Path,
    destination: &Path,
) -> io::Result<()> {
    if source == destination {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sync source and destination are the same",
        ));
    }
    rename_platform(root, source, destination)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn rename_platform(root: &SafeCacheRoot, source: &Path, destination: &Path) -> io::Result<()> {
    use std::{
        ffi::CString,
        os::{fd::AsRawFd, unix::ffi::OsStrExt},
    };

    let source_parent = source.parent().unwrap_or_else(|| Path::new(""));
    let destination_parent = destination.parent().unwrap_or_else(|| Path::new(""));
    let source_pins = super::platform::pin_directory(root, source_parent, false)?;
    let destination_pins = super::platform::pin_directory(root, destination_parent, false)?;
    let source_parent = source_pins.last().expect("root pin exists");
    let destination_parent = destination_pins.last().expect("root pin exists");
    let source_leaf = leaf_name(source)?;
    let destination_leaf = leaf_name(destination)?;
    let source_leaf = CString::new(source_leaf.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "sync path contains NUL"))?;
    let destination_leaf = CString::new(destination_leaf.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "sync path contains NUL"))?;

    #[cfg(target_os = "linux")]
    let result = unsafe {
        libc::renameat2(
            source_parent.as_raw_fd(),
            source_leaf.as_ptr(),
            destination_parent.as_raw_fd(),
            destination_leaf.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(target_os = "macos")]
    let result = unsafe {
        libc::renameatx_np(
            source_parent.as_raw_fd(),
            source_leaf.as_ptr(),
            destination_parent.as_raw_fd(),
            destination_leaf.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn rename_platform(root: &SafeCacheRoot, source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::MoveFileExW;

    let source_parent = source.parent().unwrap_or_else(|| Path::new(""));
    let destination_parent = destination.parent().unwrap_or_else(|| Path::new(""));
    let (_source_pins, source_parent) = super::platform::pin_directory(root, source_parent, false)?;
    let (_destination_pins, destination_parent) =
        super::platform::pin_directory(root, destination_parent, false)?;
    let source_leaf = leaf_name(source)?.encode_wide().collect::<Vec<_>>();
    let destination_leaf = leaf_name(destination)?.encode_wide().collect::<Vec<_>>();
    let mut source_name = super::platform::pinned_destination_name(&source_parent, &source_leaf)?;
    let mut destination_name =
        super::platform::pinned_destination_name(&destination_parent, &destination_leaf)?;
    source_name.push(0);
    destination_name.push(0);
    // With neither REPLACE_EXISTING nor COPY_ALLOWED, this is a single move
    // that fails on a destination collision or a cross-volume source.
    if unsafe { MoveFileExW(source_name.as_ptr(), destination_name.as_ptr(), 0) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn rename_platform(_root: &SafeCacheRoot, _source: &Path, _destination: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic create-only sync rename is unsupported on this platform",
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn leaf_name(path: &Path) -> io::Result<&std::ffi::OsStr> {
    path.file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "sync path has no leaf"))
}
