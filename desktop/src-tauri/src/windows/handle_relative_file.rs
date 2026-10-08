//! Handle-relative Windows file creation and exact-handle cleanup.

use std::{
    ffi::OsStr,
    fs,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawHandle, FromRawHandle},
    },
    path::Path,
};

use shellx_drive_desktop_core::{DesktopError, Result as CoreResult};
use windows_sys::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            NtCreateFile, FILE_CREATE, FILE_NON_DIRECTORY_FILE, FILE_SYNCHRONOUS_IO_NONALERT,
        },
    },
    Win32::{
        Foundation::{
            RtlNtStatusToDosError, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, UNICODE_STRING,
        },
        Storage::FileSystem::{
            FileDispositionInfo, SetFileInformationByHandle, FILE_ADD_FILE, FILE_ATTRIBUTE_NORMAL,
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ, FILE_TRAVERSE, SYNCHRONIZE,
        },
        System::IO::IO_STATUS_BLOCK,
    },
};

fn nt_error(status: i32) -> DesktopError {
    DesktopError::Io(std::io::Error::from_raw_os_error(
        unsafe { RtlNtStatusToDosError(status) } as i32,
    ))
}

pub(super) fn open_create_parent(path: &Path) -> CoreResult<fs::File> {
    let directory = fs::OpenOptions::new()
        .read(true)
        .access_mode(FILE_ADD_FILE | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | FILE_TRAVERSE)
        // Freeze in-place reparse writes and directory replacement until the
        // handle-relative child create has completed.
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(DesktopError::UnsafeLink(path.to_path_buf()));
    }
    Ok(directory)
}

pub(super) fn create_new_file_at(
    parent: &fs::File,
    leaf: &OsStr,
    desired_access: u32,
) -> CoreResult<fs::File> {
    let mut wide = leaf.encode_wide().collect::<Vec<_>>();
    if wide.is_empty()
        || wide == [b'.' as u16]
        || wide == [b'.' as u16, b'.' as u16]
        || wide.iter().any(|unit| {
            *unit == 0
                || *unit == u16::from(b'\\')
                || *unit == u16::from(b'/')
                || *unit == u16::from(b':')
        })
    {
        return Err(DesktopError::UnsafePath(
            "handle-relative create requires one safe leaf name".to_string(),
        ));
    }
    let name_bytes = wide
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|bytes| u16::try_from(bytes).ok())
        .ok_or_else(|| DesktopError::InvalidState("create leaf is too large".to_string()))?;
    let name = UNICODE_STRING {
        Length: name_bytes,
        MaximumLength: name_bytes,
        Buffer: wide.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &name,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut handle = std::ptr::null_mut();
    let mut io_status = IO_STATUS_BLOCK::default();
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            desired_access | SYNCHRONIZE,
            &attributes,
            &mut io_status,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        return Err(nt_error(status));
    }
    if handle.is_null() {
        return Err(DesktopError::InvalidState(
            "NtCreateFile succeeded without a handle".to_string(),
        ));
    }
    Ok(unsafe { fs::File::from_raw_handle(handle) })
}

pub(super) fn delete_open_file(file: &fs::File) -> CoreResult<()> {
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        return Err(DesktopError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        io::Write,
        sync::atomic::{AtomicU64, Ordering},
    };

    use windows_sys::Win32::{
        Foundation::{GENERIC_READ, GENERIC_WRITE},
        Storage::FileSystem::DELETE,
    };

    use super::*;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn relative_create_binds_parent_and_exact_handle_cleanup() {
        let root = std::env::temp_dir().join(format!(
            "shellx-drive-relative-create-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::AcqRel)
        ));
        fs::create_dir(&root).unwrap();
        let parent = open_create_parent(&root).unwrap();
        assert!(fs::rename(&root, root.with_extension("moved")).is_err());
        let mut file = create_new_file_at(
            &parent,
            OsStr::new("payload"),
            GENERIC_READ | GENERIC_WRITE | DELETE,
        )
        .unwrap();
        file.write_all(b"bound").unwrap();
        assert!(create_new_file_at(&parent, OsStr::new("payload"), GENERIC_READ).is_err());
        delete_open_file(&file).unwrap();
        drop(file);
        drop(parent);
        assert!(!root.join("payload").exists());
        fs::remove_dir(root).unwrap();
    }
}
