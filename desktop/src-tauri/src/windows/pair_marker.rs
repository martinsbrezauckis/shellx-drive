use std::{
    ffi::{c_void, OsStr},
    fs,
    io::{Read, Write},
    mem::size_of,
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use shellx_drive_desktop_core::{
    ensure_empty_local_root, DesktopError, PairMarker, PairMarkerDisposition, Result as CoreResult,
};
use windows_sys::Win32::{
    Foundation::{GENERIC_READ, GENERIC_WRITE},
    Storage::FileSystem::{
        FileDispositionInfo, GetFileInformationByHandle, SetFileInformationByHandle,
        BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_INFO,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
        FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
    },
};

use super::{
    handle_relative_file::{create_new_file_at, delete_open_file, open_create_parent},
    transfer_execution::open_checked_rename_target_directory,
    verified_staging::rename_open_file_at,
};

pub(super) const MARKER_FILE: &str = ".shellx-drive-pair.json";
const MAX_MARKER_BYTES: u64 = 64 * 1024;
static NEXT_TEMP_MARKER: AtomicU64 = AtomicU64::new(0);

/// Publish the pair marker while the selected root and every absolute ancestor
/// are pinned as non-reparse directories. The final leaf is resolved against
/// the exact opened root object, not against a mutable pathname.
pub(super) fn write_or_recognize(
    root: &Path,
    marker: &PairMarker,
) -> CoreResult<PairMarkerDisposition> {
    let pins = pin_absolute_directory_chain(root)?;
    if existing_marker_matches(root, marker)? {
        ensure_only_pair_marker(root)?;
        return Ok(PairMarkerDisposition::ExistingIdentical);
    }
    ensure_empty_local_root(root)?;
    pins.last().ok_or_else(|| {
        DesktopError::UnsafePath("pair root has no pinned directory handle".to_string())
    })?;
    let create_parent = open_create_parent(root)?;
    let temporary_name = format!(
        ".shellx-drive-pair.{}.{}.next",
        std::process::id(),
        NEXT_TEMP_MARKER.fetch_add(1, Ordering::AcqRel)
    );
    let result = (|| {
        let body = serde_json::to_vec_pretty(marker)?;
        if body.len() as u64 > MAX_MARKER_BYTES {
            return Err(DesktopError::InvalidState(
                "pair marker exceeds its size limit".to_string(),
            ));
        }
        let mut file = create_new_file_at(
            &create_parent,
            OsStr::new(&temporary_name),
            GENERIC_READ | GENERIC_WRITE | DELETE,
        )?;
        // The create-parent handle denies directory write sharing. Drop it
        // after the relative create, then bind a separately validated parent
        // handle whose sharing permits Windows' internal rename work.
        drop(create_parent);
        let publication = (|| {
            let rename_target = open_checked_rename_target_directory(root, false)?;
            file.write_all(&body)?;
            file.sync_all()?;
            rename_open_file_at(&file, &rename_target, OsStr::new(MARKER_FILE), false)
        })();
        if publication.is_err() {
            let _ = delete_open_file(&file);
        }
        publication
    })();
    result.map(|()| PairMarkerDisposition::Created)
}

fn existing_marker_matches(root: &Path, expected: &PairMarker) -> CoreResult<bool> {
    let marker_path = root.join(MARKER_FILE);
    let mut marker = match fs::OpenOptions::new()
        .access_mode(GENERIC_READ | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&marker_path)
    {
        Ok(marker) => marker,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(DesktopError::Io(error)),
    };
    let metadata = marker.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(DesktopError::UnsafeLink(marker_path));
    }
    ensure_single_link(&marker, &marker_path)?;
    if metadata.len() > MAX_MARKER_BYTES {
        return Err(DesktopError::UnsafePath(
            "pair marker exceeds its size limit".to_string(),
        ));
    }
    let mut body = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    Read::by_ref(&mut marker)
        .take(MAX_MARKER_BYTES.saturating_add(1))
        .read_to_end(&mut body)?;
    if body.len() as u64 > MAX_MARKER_BYTES
        || serde_json::from_slice::<PairMarker>(&body).ok().as_ref() != Some(expected)
    {
        return Err(DesktopError::UnsafePath(
            "pair marker is malformed or belongs to another pair".to_string(),
        ));
    }
    Ok(true)
}

pub(super) fn require_exact(root: &Path, expected: &PairMarker) -> CoreResult<()> {
    if existing_marker_matches(root, expected)? {
        Ok(())
    } else {
        Err(DesktopError::InvalidState(
            "the configured Drive folder marker is missing; pair the folder again".to_string(),
        ))
    }
}

/// Cleanup after confirmed retirement may retry an already removed marker.
/// Any present marker must still belong to the exact disconnected pair.
pub(super) fn require_exact_or_absent(root: &Path, expected: &PairMarker) -> CoreResult<()> {
    existing_marker_matches(root, expected).map(|_| ())
}

fn ensure_single_link(file: &fs::File, path: &Path) -> CoreResult<()> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(DesktopError::Io(std::io::Error::last_os_error()));
    }
    if information.nNumberOfLinks != 1 {
        return Err(DesktopError::UnsafeLink(path.to_path_buf()));
    }
    Ok(())
}

fn ensure_only_pair_marker(root: &Path) -> CoreResult<()> {
    let mut entries = fs::read_dir(root)?;
    let entry = entries.next().transpose()?.ok_or_else(|| {
        DesktopError::UnsafePath("pair marker disappeared during setup".to_string())
    })?;
    if entry.file_name() != OsStr::new(MARKER_FILE) || entries.next().transpose()?.is_some() {
        return Err(DesktopError::LocalFolderNotEmpty(root.to_path_buf()));
    }
    Ok(())
}

/// Remove only the exact marker bound to the current pair. Missing markers are
/// harmless; a substituted file, reparse point, or mismatched marker fails
/// closed and is left untouched.
pub(super) fn remove(root: &Path, expected: &PairMarker) -> CoreResult<bool> {
    let pins = pin_absolute_directory_chain(root)?;
    let marker_path = root.join(MARKER_FILE);
    let mut marker = match fs::OpenOptions::new()
        .access_mode(GENERIC_READ | DELETE | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&marker_path)
    {
        Ok(marker) => marker,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(DesktopError::Io(error)),
    };
    let metadata = marker.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(DesktopError::UnsafeLink(marker_path));
    }
    ensure_single_link(&marker, &marker_path)?;
    if metadata.len() > MAX_MARKER_BYTES {
        return Err(DesktopError::UnsafePath(
            "pair marker exceeds its size limit".to_string(),
        ));
    }
    let mut body = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    Read::by_ref(&mut marker)
        .take(MAX_MARKER_BYTES.saturating_add(1))
        .read_to_end(&mut body)?;
    if body.len() as u64 > MAX_MARKER_BYTES
        || serde_json::from_slice::<PairMarker>(&body).ok().as_ref() != Some(expected)
    {
        return Err(DesktopError::UnsafePath(
            "pair marker is malformed or belongs to another pair".to_string(),
        ));
    }
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    let deleted = unsafe {
        SetFileInformationByHandle(
            marker.as_raw_handle(),
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast::<c_void>(),
            u32::try_from(size_of::<FILE_DISPOSITION_INFO>()).map_err(|_| {
                DesktopError::InvalidState("pair marker delete buffer is too large".to_string())
            })?,
        )
    };
    if deleted == 0 {
        return Err(DesktopError::Io(std::io::Error::last_os_error()));
    }
    drop(marker);
    drop(pins);
    Ok(true)
}

fn pin_absolute_directory_chain(path: &Path) -> CoreResult<Vec<fs::File>> {
    if !path.is_absolute() {
        return Err(DesktopError::UnsafePath(format!(
            "pair root is not absolute: {}",
            path.display()
        )));
    }
    let mut current = PathBuf::new();
    let mut handles = Vec::new();
    let mut saw_root = false;
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => {
                current.push(component.as_os_str());
                handles.push(open_pinned_directory(&current)?);
                saw_root = true;
            }
            Component::Normal(name) if saw_root => {
                current.push(name);
                handles.push(open_pinned_directory(&current)?);
            }
            Component::Normal(_) | Component::CurDir | Component::ParentDir => {
                return Err(DesktopError::UnsafePath(format!(
                    "pair root contains an unsafe component: {}",
                    path.display()
                )));
            }
        }
    }
    if !saw_root || handles.is_empty() {
        return Err(DesktopError::UnsafePath(
            "pair root has no pinnable Windows root".to_string(),
        ));
    }
    Ok(handles)
}

fn open_pinned_directory(path: &Path) -> CoreResult<fs::File> {
    let directory = fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | FILE_TRAVERSE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(DesktopError::UnsafeLink(path.to_path_buf()));
    }
    Ok(directory)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_publication_and_removal_use_the_pinned_absolute_path() {
        let root = std::env::temp_dir().join(format!(
            "shellx-drive-pair-marker-{}-{}",
            std::process::id(),
            NEXT_TEMP_MARKER.fetch_add(1, Ordering::AcqRel)
        ));
        fs::create_dir(&root).unwrap();
        let marker = PairMarker {
            schema_version: 1,
            workspace_id: "workspace-test".to_string(),
            remote_root_id: Some("folder-test".to_string()),
            server_url: "https://drive.example.test".to_string(),
            local_root_identity: None,
        };

        assert_eq!(
            write_or_recognize(&root, &marker).unwrap(),
            PairMarkerDisposition::Created
        );
        assert_eq!(
            write_or_recognize(&root, &marker).unwrap(),
            PairMarkerDisposition::ExistingIdentical
        );
        assert!(remove(&root, &marker).unwrap());
        fs::remove_dir(root).unwrap();
    }
}
