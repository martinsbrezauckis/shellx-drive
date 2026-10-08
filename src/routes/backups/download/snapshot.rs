use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    pin::Pin,
    task::{Context, Poll},
};

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, ReadBuf};

use crate::{
    error::{ApiError, ApiResult},
    fs_private,
    io_advice::CacheDroppingFile,
};

#[cfg(test)]
use super::super::catalog::v2_staging_root;

const SNAPSHOT_ALLOCATION_ATTEMPTS: usize = 32;
const SNAPSHOT_SUFFIX: &str = ".download-snapshot";
const SNAPSHOT_DIRECTORY: &str = ".backup-download-snapshots";

/// A private V2 download copy. Unix removes its directory entry before
/// streaming; other platforms remove it immediately after the stream closes.
pub(super) struct V2DownloadSnapshot {
    file: Option<File>,
    cleanup_path: Option<PathBuf>,
}

impl V2DownloadSnapshot {
    pub(super) fn into_stream(mut self) -> StagedV2Download {
        let file = self.file.take().expect("snapshot file is present");
        StagedV2Download {
            file: Some(CacheDroppingFile::from_std(file)),
            cleanup_path: self.cleanup_path.take(),
        }
    }
}

impl Drop for V2DownloadSnapshot {
    fn drop(&mut self) {
        drop(self.file.take());
        if let Some(path) = self.cleanup_path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

pub(super) struct StagedV2Download {
    file: Option<CacheDroppingFile>,
    cleanup_path: Option<PathBuf>,
}

impl AsyncRead for StagedV2Download {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(self.file.as_mut().expect("staged download file is present")).poll_read(cx, buffer)
    }
}

impl Drop for StagedV2Download {
    fn drop(&mut self) {
        drop(self.file.take());
        if let Some(path) = self.cleanup_path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

pub(super) fn snapshot_v2_archive(
    data_dir: &Path,
    archive_path: &Path,
    max_bytes: u64,
) -> ApiResult<(V2DownloadSnapshot, u64, String)> {
    let mut source = open_regular_archive(archive_path)?;
    let archive_bytes = source.metadata()?.len();
    if archive_bytes > max_bytes {
        return Err(ApiError::PayloadTooLarge(format!(
            "backup archive is {archive_bytes} bytes; limit is {max_bytes} bytes"
        )));
    }
    let mut snapshot = create_private_snapshot(data_dir)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut read_bytes = 0u64;
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        read_bytes = read_bytes.checked_add(read as u64).ok_or_else(|| {
            ApiError::PayloadTooLarge("backup archive length overflow".to_string())
        })?;
        if read_bytes > max_bytes {
            return Err(ApiError::PayloadTooLarge(
                "backup archive grew beyond its configured limit".to_string(),
            ));
        }
        snapshot
            .file
            .as_mut()
            .expect("snapshot file is present")
            .write_all(&buffer[..read])?;
        hasher.update(&buffer[..read]);
    }
    if read_bytes != archive_bytes {
        return Err(ApiError::Validation(
            "backup archive changed while being snapshotted".to_string(),
        ));
    }
    snapshot
        .file
        .as_mut()
        .expect("snapshot file is present")
        .seek(SeekFrom::Start(0))?;
    Ok((snapshot, archive_bytes, hex::encode(hasher.finalize())))
}

fn open_regular_archive(path: &Path) -> ApiResult<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(ApiError::Validation(
                "backup archive must be a real regular file, not a reparse point".to_string(),
            ));
        }
    }
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ApiError::Validation(
            "backup archive must be a real regular file".to_string(),
        ));
    }
    Ok(file)
}

pub(super) fn cleanup_download_snapshots(data_dir: &Path) -> ApiResult<()> {
    let root = data_dir.join(SNAPSHOT_DIRECTORY);
    let metadata = match fs::symlink_metadata(&root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    validate_private_snapshot_root(&root, &metadata)?;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with('.') && name.ends_with(SNAPSHOT_SUFFIX) && entry.file_type()?.is_file()
        {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn create_private_snapshot(data_dir: &Path) -> ApiResult<V2DownloadSnapshot> {
    let snapshot_root = private_snapshot_root(data_dir)?;
    for _ in 0..SNAPSHOT_ALLOCATION_ATTEMPTS {
        let path = snapshot_root.join(format!(".{}{}", uuid::Uuid::new_v4(), SNAPSHOT_SUFFIX));
        let mut options = OpenOptions::new();
        options.create_new(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;

            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        match options.open(&path) {
            Ok(file) => {
                #[cfg(windows)]
                fs_private::apply_private_file_handle(&file)?;
                #[allow(unused_mut)]
                let mut snapshot = V2DownloadSnapshot {
                    file: Some(file),
                    cleanup_path: Some(path),
                };
                #[cfg(unix)]
                {
                    let path = snapshot
                        .cleanup_path
                        .take()
                        .expect("snapshot path is present");
                    if let Err(error) = fs::remove_file(&path) {
                        snapshot.cleanup_path = Some(path);
                        return Err(error.into());
                    }
                }
                return Ok(snapshot);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(ApiError::Maintenance(
        "could not allocate a private backup download snapshot".to_string(),
    ))
}

fn private_snapshot_root(data_dir: &Path) -> ApiResult<PathBuf> {
    let root = data_dir.join(SNAPSHOT_DIRECTORY);
    match fs::create_dir(&root) {
        Ok(()) => {
            if let Err(error) = fs_private::set_dir_private(&root) {
                let _ = fs::remove_dir(&root);
                return Err(error.into());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    validate_private_snapshot_root(&root, &fs::symlink_metadata(&root)?)?;
    Ok(root)
}

fn validate_private_snapshot_root(_root: &Path, metadata: &fs::Metadata) -> ApiResult<()> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ApiError::Validation(
            "backup download snapshot root must be a real private directory".to_string(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(ApiError::Validation(
                "backup download snapshot root must be private".to_string(),
            ));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        };

        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
        let root_handle = options.open(_root)?;
        fs_private::verify_private_dir_handle(&root_handle)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_does_not_follow_a_later_in_place_archive_mutation() {
        let data_dir = tempfile::tempdir().unwrap();
        let archive = data_dir.path().join("fixture.sxdbackup");
        std::fs::write(&archive, b"original archive bytes").unwrap();
        let (mut snapshot, bytes, digest) =
            snapshot_v2_archive(data_dir.path(), &archive, 1024).unwrap();

        std::fs::write(&archive, b"mutated! archive bytes").unwrap();
        let mut copied = Vec::new();
        snapshot
            .file
            .as_mut()
            .unwrap()
            .read_to_end(&mut copied)
            .unwrap();
        assert_eq!(copied, b"original archive bytes");
        assert_eq!(bytes, copied.len() as u64);
        assert_eq!(digest, hex::encode(Sha256::digest(&copied)));
        assert_eq!(
            private_snapshot_root(data_dir.path()).unwrap(),
            data_dir.path().join(SNAPSHOT_DIRECTORY)
        );
        assert_ne!(
            private_snapshot_root(data_dir.path()).unwrap(),
            v2_staging_root(data_dir.path())
        );
    }

    #[test]
    fn cleanup_removes_only_named_snapshot_files_from_the_isolated_root() {
        let data_dir = tempfile::tempdir().unwrap();
        let root = private_snapshot_root(data_dir.path()).unwrap();
        let stale = root.join(".stale.download-snapshot");
        let unrelated = root.join("keep.txt");
        std::fs::write(&stale, b"stale").unwrap();
        std::fs::write(&unrelated, b"keep").unwrap();

        cleanup_download_snapshots(data_dir.path()).unwrap();
        assert!(!stale.exists());
        assert!(unrelated.exists());
    }

    #[cfg(unix)]
    #[test]
    fn unix_snapshot_is_unlinked_before_copying() {
        let data_dir = tempfile::tempdir().unwrap();
        let snapshot = create_private_snapshot(data_dir.path()).unwrap();
        assert!(snapshot.cleanup_path.is_none());
        assert!(
            fs::read_dir(private_snapshot_root(data_dir.path()).unwrap())
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn secure_open_rejects_links_and_nonfiles_without_blocking() {
        use std::{ffi::CString, os::unix::fs::symlink};

        let data_dir = tempfile::tempdir().unwrap();
        let archive = data_dir.path().join("fixture.sxdbackup");
        std::fs::write(&archive, b"fixture").unwrap();
        let link = data_dir.path().join("fixture-link.sxdbackup");
        symlink(&archive, &link).unwrap();
        assert!(open_regular_archive(&link).is_err());

        let fifo = data_dir.path().join("fixture-fifo.sxdbackup");
        let fifo_c = CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `fifo_c` is a valid NUL-terminated path and the mode is valid.
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        assert!(open_regular_archive(&fifo).is_err());
    }
}
