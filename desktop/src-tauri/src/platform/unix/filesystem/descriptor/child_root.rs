//! Initial child-root creation and pairing through the selected base descriptor.

use std::{
    fs,
    os::fd::AsRawFd,
    path::{Component, Path},
};

use shellx_drive_desktop_core::{
    ensure_tree_has_no_links, validate_local_relative, DesktopError, PairMarker,
    PairMarkerDisposition, Result as CoreResult,
};

use super::{
    device_number, directory_identity, ensure_identity, mkdir_at, open_directory_at, UnixRootGuard,
};

#[cfg(all(target_os = "linux", test))]
unsafe fn errno_slot() -> *mut libc::c_int {
    libc::__errno_location()
}

#[cfg(target_os = "macos")]
unsafe fn errno_slot() -> *mut libc::c_int {
    libc::__error()
}

pub(crate) fn ensure_directory(guard: &UnixRootGuard, relative: &Path) -> CoreResult<()> {
    open_or_create_directory(guard, relative, false).map(|_| ())
}

fn open_or_create_directory(
    guard: &UnixRootGuard,
    relative: &Path,
    reject_mounts: bool,
) -> CoreResult<fs::File> {
    ensure_identity(guard, "directory creation")?;
    if relative.as_os_str().is_empty() {
        return Ok(guard.root.try_clone()?);
    }
    validate_local_relative(relative).map_err(|issue| DesktopError::UnsafePath(issue.reason))?;
    let mut parent = guard.root.try_clone()?;
    let base_device = reject_mounts.then(|| device_number(&parent)).transpose()?;
    #[cfg(target_os = "linux")]
    let base_mount = reject_mounts.then(|| mount_number(&parent)).transpose()?;
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(DesktopError::UnsafePath(
                "Drive folder has an unsafe path component".to_string(),
            ));
        };
        let child = match open_directory_at(&parent, component) {
            Ok(child) => child,
            Err(DesktopError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                mkdir_at(&parent, component)?;
                open_directory_at(&parent, component)?
            }
            Err(error) => return Err(error),
        };
        if let Some(device) = base_device {
            if device_number(&child)? != device {
                return Err(DesktopError::UnsafePath(
                    "Drive folder crosses a mounted filesystem".to_string(),
                ));
            }
        }
        #[cfg(target_os = "linux")]
        if let Some(mount) = base_mount {
            if mount_number(&child)? != mount {
                return Err(DesktopError::UnsafePath(
                    "Drive folder crosses a mounted filesystem".to_string(),
                ));
            }
        }
        parent = child;
    }
    Ok(parent)
}

pub(crate) fn ensure_child_root(
    guard: &UnixRootGuard,
    relative: &Path,
) -> CoreResult<UnixRootGuard> {
    ensure_child_root_with_hook(guard, relative, || {})
}

pub(crate) fn ensure_child_root_with_hook<F: FnOnce()>(
    guard: &UnixRootGuard,
    relative: &Path,
    before_binding_check: F,
) -> CoreResult<UnixRootGuard> {
    validate_local_relative(relative).map_err(|issue| DesktopError::UnsafePath(issue.reason))?;
    let child = open_or_create_directory(guard, relative, true)?;
    let identity = directory_identity(&child)?;
    let child_guard = UnixRootGuard {
        root: child,
        identity,
        path: guard.path.join(relative),
    };
    before_binding_check();
    ensure_tree_has_no_links(&child_guard.path)?;
    verify_child_binding(guard, relative, &child_guard)?;
    Ok(child_guard)
}

fn verify_child_binding(
    base: &UnixRootGuard,
    relative: &Path,
    child: &UnixRootGuard,
) -> CoreResult<()> {
    if base.path.join(relative) != child.path {
        return Err(DesktopError::UnsafePath(
            "Drive child root is not below the selected base".to_string(),
        ));
    }
    let mut current = base.root.try_clone()?;
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(DesktopError::UnsafePath(
                "Drive child root has an unsafe path component".to_string(),
            ));
        };
        current = open_directory_at(&current, component)?;
    }
    if directory_identity(&current)? != child.identity {
        return Err(DesktopError::UnsafePath(
            "Drive child root changed during initial pairing".to_string(),
        ));
    }
    #[cfg(target_os = "linux")]
    if mount_number(&current)? != mount_number(&child.root)? {
        return Err(DesktopError::UnsafePath(
            "Drive child root crossed a mounted filesystem during initial pairing".to_string(),
        ));
    }
    base.ensure_identity("child root binding")?;
    Ok(())
}

pub(crate) fn write_or_recognize_child_pair_marker(
    base: &UnixRootGuard,
    relative: &Path,
    child: &UnixRootGuard,
    marker: &PairMarker,
) -> CoreResult<PairMarkerDisposition> {
    write_or_recognize_child_pair_marker_with_hook(base, relative, child, marker, || {})
}

pub(crate) fn write_or_recognize_child_pair_marker_with_hook<F: FnOnce()>(
    base: &UnixRootGuard,
    relative: &Path,
    child: &UnixRootGuard,
    marker: &PairMarker,
    after_publication: F,
) -> CoreResult<PairMarkerDisposition> {
    verify_child_binding(base, relative, child)?;
    let disposition = super::super::marker::write_or_recognize(child, marker)?;
    after_publication();
    if let Err(error) = verify_child_binding(base, relative, child) {
        if disposition == PairMarkerDisposition::Created {
            super::super::marker::remove_exact(child, marker)?;
        }
        return Err(error);
    }
    Ok(disposition)
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn ensure_empty_root(guard: &UnixRootGuard) -> CoreResult<()> {
    let descriptor = unsafe { libc::dup(guard.root.as_raw_fd()) };
    if descriptor < 0 {
        return Err(DesktopError::Io(std::io::Error::last_os_error()));
    }
    let stream = unsafe { libc::fdopendir(descriptor) };
    if stream.is_null() {
        unsafe { libc::close(descriptor) };
        return Err(DesktopError::Io(std::io::Error::last_os_error()));
    }
    // `dup` shares the open-directory offset. Reset it for repeated empty
    // checks on the same pinned root.
    unsafe { libc::rewinddir(stream) };
    let result = loop {
        unsafe { *errno_slot() = 0 };
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            break if error.raw_os_error() == Some(0) {
                Ok(())
            } else {
                Err(DesktopError::Io(error))
            };
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"."
            && name != b".."
            && name != super::super::marker::PAIR_MARKER_FILE.as_bytes()
        {
            break Err(DesktopError::LocalFolderNotEmpty(guard.path.clone()));
        }
    };
    unsafe { libc::closedir(stream) };
    result
}

#[cfg(target_os = "linux")]
fn mount_number(directory: &fs::File) -> CoreResult<u64> {
    let mut metadata = unsafe { std::mem::zeroed::<libc::statx>() };
    let result = unsafe {
        libc::statx(
            directory.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            libc::STATX_MNT_ID,
            &mut metadata,
        )
    };
    if result != 0 {
        return Err(DesktopError::Io(std::io::Error::last_os_error()));
    }
    if metadata.stx_mask & libc::STATX_MNT_ID == 0 {
        return Err(DesktopError::UnsafePath(
            "Drive folder mount identity is unavailable".to_string(),
        ));
    }
    Ok(metadata.stx_mnt_id)
}
