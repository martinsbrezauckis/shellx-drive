use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileIdentity {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) size: u64,
    pub(crate) is_directory: bool,
}

pub(crate) fn file_identity(file: &fs::File) -> CoreResult<FileIdentity> {
    let metadata = file.metadata()?;
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.len(),
        is_directory: metadata.is_dir(),
    })
}

pub(crate) fn open_entry_at(
    parent: &fs::File,
    name: &OsStr,
    is_directory: bool,
) -> CoreResult<fs::File> {
    if is_directory {
        open_directory_at(parent, name)
    } else {
        open_regular_file_at(parent, name)
    }
}

pub(crate) fn entry_at_matches(
    parent: &fs::File,
    name: &OsStr,
    expected: FileIdentity,
) -> CoreResult<bool> {
    let file = open_entry_at(parent, name, expected.is_directory)?;
    Ok(file_identity(&file)? == expected)
}

pub(crate) fn c_string(value: &OsStr) -> CoreResult<CString> {
    CString::new(value.as_bytes())
        .map_err(|_| DesktopError::UnsafePath("filesystem path contains a NUL byte".to_string()))
}

pub(crate) fn link_at(
    source_parent: &fs::File,
    source: &OsStr,
    destination_parent: &fs::File,
    destination: &OsStr,
) -> CoreResult<()> {
    let source = c_string(source)?;
    let destination = c_string(destination)?;
    if unsafe {
        libc::linkat(
            source_parent.as_raw_fd(),
            source.as_ptr(),
            destination_parent.as_raw_fd(),
            destination.as_ptr(),
            0,
        )
    } != 0
    {
        return Err(DesktopError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

pub(crate) fn rename_at(
    source_parent: &fs::File,
    source: &OsStr,
    destination_parent: &fs::File,
    destination: &OsStr,
) -> CoreResult<()> {
    let source = c_string(source)?;
    let destination = c_string(destination)?;
    if unsafe {
        libc::renameat(
            source_parent.as_raw_fd(),
            source.as_ptr(),
            destination_parent.as_raw_fd(),
            destination.as_ptr(),
        )
    } != 0
    {
        return Err(DesktopError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Linux has the two kernel primitives necessary to make these terminal
/// operations no-replace or exchange-only. macOS provides corresponding
/// descriptor-relative `renameatx_np` flags. Do not emulate either operation
/// with check-then-rename on another Unix target.
#[cfg(target_os = "linux")]
fn renameat2(
    source_parent: &fs::File,
    source: &OsStr,
    destination_parent: &fs::File,
    destination: &OsStr,
    flags: libc::c_uint,
) -> CoreResult<()> {
    let source = c_string(source)?;
    let destination = c_string(destination)?;
    if unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            source_parent.as_raw_fd(),
            source.as_ptr(),
            destination_parent.as_raw_fd(),
            destination.as_ptr(),
            flags,
        )
    } != 0
    {
        return Err(DesktopError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn rename_noreplace_at(
    source_parent: &fs::File,
    source: &OsStr,
    destination_parent: &fs::File,
    destination: &OsStr,
) -> CoreResult<()> {
    renameat2(source_parent, source, destination_parent, destination, 1)
}

#[cfg(target_os = "macos")]
pub(crate) fn rename_noreplace_at(
    source_parent: &fs::File,
    source: &OsStr,
    destination_parent: &fs::File,
    destination: &OsStr,
) -> CoreResult<()> {
    renameatx_np(
        source_parent,
        source,
        destination_parent,
        destination,
        libc::RENAME_EXCL,
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn rename_noreplace_at(
    _: &fs::File,
    _: &OsStr,
    _: &fs::File,
    _: &OsStr,
) -> CoreResult<()> {
    Err(DesktopError::InvalidState(
        "this Unix platform has no admitted atomic no-replace rename primitive".to_string(),
    ))
}

#[cfg(target_os = "linux")]
pub(crate) fn rename_exchange_at(
    source_parent: &fs::File,
    source: &OsStr,
    destination_parent: &fs::File,
    destination: &OsStr,
) -> CoreResult<()> {
    renameat2(source_parent, source, destination_parent, destination, 2)
}

#[cfg(target_os = "macos")]
pub(crate) fn rename_exchange_at(
    source_parent: &fs::File,
    source: &OsStr,
    destination_parent: &fs::File,
    destination: &OsStr,
) -> CoreResult<()> {
    renameatx_np(
        source_parent,
        source,
        destination_parent,
        destination,
        libc::RENAME_SWAP,
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn rename_exchange_at(
    _: &fs::File,
    _: &OsStr,
    _: &fs::File,
    _: &OsStr,
) -> CoreResult<()> {
    Err(DesktopError::InvalidState(
        "this Unix platform has no admitted atomic exchange primitive".to_string(),
    ))
}

#[cfg(target_os = "macos")]
fn renameatx_np(
    source_parent: &fs::File,
    source: &OsStr,
    destination_parent: &fs::File,
    destination: &OsStr,
    flags: libc::c_uint,
) -> CoreResult<()> {
    let source = c_string(source)?;
    let destination = c_string(destination)?;
    if unsafe {
        libc::renameatx_np(
            source_parent.as_raw_fd(),
            source.as_ptr(),
            destination_parent.as_raw_fd(),
            destination.as_ptr(),
            flags,
        )
    } != 0
    {
        return Err(DesktopError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

pub(crate) fn unlink_at(parent: &fs::File, leaf: &OsStr) -> CoreResult<()> {
    let leaf = c_string(leaf)?;
    if unsafe { libc::unlinkat(parent.as_raw_fd(), leaf.as_ptr(), 0) } != 0 {
        return Err(DesktopError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}
