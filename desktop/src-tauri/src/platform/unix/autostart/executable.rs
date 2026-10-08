//! Stable executable admission for Unix launch-at-login.

use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

#[cfg(target_os = "linux")]
use std::path::Component;

use shellx_drive_desktop_core::{DesktopError, Result as CoreResult};

pub(super) fn select_stable_executable(
    current: &Path,
    _appimage: Option<&OsStr>,
) -> CoreResult<PathBuf> {
    #[cfg(target_os = "linux")]
    if let Some(appimage) = _appimage {
        let appimage = Path::new(appimage);
        if path_is_transient_appimage_location(appimage)? {
            return Err(transient_appimage_error());
        }
        return validate_stable_executable(appimage, true);
    }
    #[cfg(target_os = "linux")]
    if path_is_transient_appimage_location(current)? {
        return Err(transient_appimage_error());
    }
    validate_stable_executable(current, false)
}

pub(super) fn validate_stable_executable(
    path: &Path,
    require_current_user_owner: bool,
) -> CoreResult<PathBuf> {
    use std::os::unix::fs::MetadataExt;

    if !path.is_absolute() {
        return Err(unsafe_executable_error());
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(unsafe_executable_error());
    }
    let current_user = unsafe { libc::geteuid() };
    if (require_current_user_owner && metadata.uid() != current_user)
        || (!require_current_user_owner && metadata.uid() != current_user && metadata.uid() != 0)
    {
        return Err(unsafe_executable_error());
    }
    let canonical = fs::canonicalize(path)?;
    let canonical_metadata = fs::symlink_metadata(&canonical)?;
    if canonical_metadata.file_type().is_symlink()
        || !canonical_metadata.is_file()
        || canonical_metadata.mode() & 0o022 != 0
        || (canonical_metadata.uid() != current_user && canonical_metadata.uid() != 0)
    {
        return Err(unsafe_executable_error());
    }
    for ancestor in canonical.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(ancestor)?;
        let forbidden_write = metadata.mode() & 0o022 != 0;
        #[cfg(target_os = "macos")]
        let forbidden_write = forbidden_write
            && !macos_system_applications_is_trusted(
                ancestor,
                metadata.uid(),
                metadata.gid(),
                metadata.mode(),
                system_admin_group(),
            );
        if !metadata.is_dir()
            || forbidden_write
            || (metadata.uid() != current_user && metadata.uid() != 0)
        {
            return Err(unsafe_executable_error());
        }
    }
    Ok(canonical)
}

// macOS normally installs apps below root-owned, admin-group-writable
// /Applications. Only that exact canonical ancestor gets this exception;
// executable, bundle directories and every other ancestor stay strict.
#[cfg(any(target_os = "macos", test))]
pub(super) fn macos_system_applications_is_trusted(
    path: &Path,
    owner: u32,
    group: u32,
    mode: u32,
    admin_group: Option<u32>,
) -> bool {
    path == Path::new("/Applications")
        && owner == 0
        && mode & 0o002 == 0
        && admin_group == Some(group)
}

#[cfg(target_os = "macos")]
fn system_admin_group() -> Option<u32> {
    let mut group: libc::group = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    let mut buffer = [0_u8; 16 * 1024];
    let status = unsafe {
        libc::getgrnam_r(
            b"admin\0".as_ptr().cast(),
            &mut group,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    // A missing group or failed lookup cannot relax the ancestry check.
    (status == 0 && !result.is_null()).then_some(group.gr_gid)
}

fn unsafe_executable_error() -> DesktopError {
    #[cfg(target_os = "macos")]
    let message = "macOS launch-at-login requires a regular app executable and trusted installation folders; move the app to /Applications or a stable private folder you own and try again";
    #[cfg(target_os = "linux")]
    let message = "launch-at-login requires a regular executable and parent folders owned by you or root, without group or world write access; move the AppImage to a stable private folder and try again";
    DesktopError::InvalidState(message.to_string())
}

#[cfg(target_os = "linux")]
pub(super) fn path_is_transient_appimage_location(path: &Path) -> CoreResult<bool> {
    if [
        Path::new("/tmp"),
        Path::new("/var/tmp"),
        Path::new("/dev/shm"),
    ]
    .iter()
    .any(|temporary| path.starts_with(temporary))
    {
        return Ok(true);
    }
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        let runtime = Path::new(&runtime);
        if runtime.is_absolute() && path.starts_with(runtime) {
            return Ok(true);
        }
    }
    if path.components().any(|component| matches!(component, Component::Normal(name) if name.to_string_lossy().starts_with(".mount_"))) {
        return Ok(true);
    }
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").map_err(DesktopError::Io)?;
    Ok(mountinfo.lines().any(|line| {
        let Some((left, right)) = line.split_once(" - ") else {
            return false;
        };
        let Some(mountpoint) = left
            .split_whitespace()
            .nth(4)
            .and_then(unescape_mountinfo_path)
        else {
            return false;
        };
        let filesystem = right.split_whitespace().next().unwrap_or_default();
        filesystem.starts_with("fuse") && path.starts_with(mountpoint)
    }))
}

#[cfg(target_os = "linux")]
fn transient_appimage_error() -> DesktopError {
    DesktopError::InvalidState(
        "AppImage launch-at-login needs the original AppImage in a stable folder you own; move it out of temporary storage or the runtime mount and enable it again".to_string(),
    )
}

#[cfg(target_os = "linux")]
fn unescape_mountinfo_path(value: &str) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;

    let mut bytes = Vec::with_capacity(value.len());
    let raw = value.as_bytes();
    let mut index = 0;
    while index < raw.len() {
        if raw[index] == b'\\'
            && index + 3 < raw.len()
            && raw[index + 1..index + 4].iter().all(u8::is_ascii_digit)
        {
            let octal = std::str::from_utf8(&raw[index + 1..index + 4]).ok()?;
            bytes.push(u8::from_str_radix(octal, 8).ok()?);
            index += 4;
        } else {
            bytes.push(raw[index]);
            index += 1;
        }
    }
    Some(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
}
