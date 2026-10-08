//! Bounded catalog IO in derived, owner-private directories.

use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use shellx_drive_desktop_core::{
    ensure_private_staging_directory, validate_private_staging_file, DesktopError,
    Result as CoreResult, StateStore,
};

use super::model::{
    invalid, validate_id, AppCatalog, ConnectionStorage, LEGACY_CONNECTION_ID, MAX_CONNECTIONS,
};

const MAX_CATALOG_BYTES: u64 = 512 * 1024;
const PRIVATE_DIRECTORY: &str = ".shellx-drive-private";

pub(super) struct CatalogStore {
    legacy_path: PathBuf,
    root: DirectoryPin,
    profiles: DirectoryPin,
    _private: DirectoryPin,
}

impl CatalogStore {
    pub(super) fn new(legacy_path: &Path) -> CoreResult<Self> {
        let parent = legacy_path
            .parent()
            .ok_or_else(|| invalid("legacy state path has no parent"))?;
        if !legacy_path.is_absolute()
            || legacy_path.file_name() != Some(std::ffi::OsStr::new("state.json"))
        {
            return Err(invalid(
                "connection storage requires the canonical legacy state path",
            ));
        }
        fs::create_dir_all(parent)?;
        let private = protected_directory(&parent.join(PRIVATE_DIRECTORY))?;
        let root = protected_directory(&private.path.join("connections-v1"))?;
        let profiles = protected_directory(&root.path.join("profiles"))?;
        Ok(Self {
            legacy_path: legacy_path.to_path_buf(),
            root,
            profiles,
            _private: private,
        })
    }

    pub(super) fn verify(&self) -> CoreResult<()> {
        self._private.verify()?;
        self.root.verify()?;
        self.profiles.verify()
    }

    pub(super) fn load(&self) -> CoreResult<Option<AppCatalog>> {
        self.verify()?;
        let path = self.root.path.join("catalog.json");
        let mut file = match open_catalog_file(&path) {
            Ok(file) => file,
            Err(DesktopError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None)
            }
            Err(error) => return Err(error),
        };
        validate_private_staging_file(&file)?;
        if file.metadata()?.len() > MAX_CATALOG_BYTES {
            return Err(invalid("connection catalog exceeds its size limit"));
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(MAX_CATALOG_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_CATALOG_BYTES {
            return Err(invalid("connection catalog exceeds its size limit"));
        }
        let catalog: AppCatalog = serde_json::from_slice(&bytes)?;
        catalog.validate()?;
        self.verify()?;
        Ok(Some(catalog))
    }

    pub(super) fn save(&self, catalog: &AppCatalog) -> CoreResult<()> {
        self.verify()?;
        catalog.validate()?;
        let bytes = serde_json::to_vec_pretty(catalog)?;
        if bytes.len() as u64 > MAX_CATALOG_BYTES {
            return Err(invalid("connection catalog exceeds its size limit"));
        }
        let destination = self.root.path.join("catalog.json");
        match fs::symlink_metadata(&destination) {
            Ok(_) => {
                let existing = open_catalog_file(&destination)?;
                validate_private_staging_file(&existing)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut next = new_catalog_file(&self.root.path)?;
        validate_private_staging_file(next.as_file())?;
        next.write_all(&bytes)?;
        next.as_file().sync_all()?;
        self.verify()?;
        persist_catalog_file(next, &destination)?;
        #[cfg(unix)]
        self.root.file.sync_all()?;
        self.verify()
    }

    pub(super) fn profile_store(
        &self,
        id: &str,
        storage: &ConnectionStorage,
    ) -> CoreResult<StateStore> {
        self.verify()?;
        validate_id(id)?;
        if *storage == ConnectionStorage::Legacy {
            if id != LEGACY_CONNECTION_ID {
                return Err(invalid("invalid legacy connection ID"));
            }
            return Ok(StateStore::new(&self.legacy_path));
        }
        if id == LEGACY_CONNECTION_ID {
            return Err(invalid("legacy ID cannot own a profile directory"));
        }
        Ok(StateStore::new(
            self.profiles.path.join(id).join("state.json"),
        ))
    }

    pub(super) fn create_profile(&self, id: &str) -> CoreResult<StateStore> {
        let store = self.profile_store(id, &ConnectionStorage::Profile)?;
        let directory = protected_directory(store.path().parent().expect("derived state parent"))?;
        directory.verify()?;
        self.verify()?;
        Ok(store)
    }

    pub(super) fn require_state_file(
        &self,
        id: &str,
        storage: &ConnectionStorage,
    ) -> CoreResult<StateStore> {
        let store = self.profile_store(id, storage)?;
        if *storage == ConnectionStorage::Profile {
            let parent = store.path().parent().expect("derived state parent");
            let directory = DirectoryPin::open(parent)?;
            ensure_private_staging_directory(parent)?;
            directory.verify()?;
        }
        let _file = open_regular_file(store.path())?;
        self.verify()?;
        Ok(store)
    }

    /// Keep interrupted state creation visible; never adopt arbitrary names.
    pub(super) fn profile_ids(&self) -> CoreResult<Vec<String>> {
        self.verify()?;
        let mut ids = Vec::new();
        for entry in fs::read_dir(&self.profiles.path)? {
            let entry = entry?;
            let id = entry
                .file_name()
                .into_string()
                .map_err(|_| invalid("invalid connection directory name"))?;
            validate_id(&id)?;
            if id == LEGACY_CONNECTION_ID {
                return Err(invalid("legacy profile directory is invalid"));
            }
            DirectoryPin::open(&entry.path())?;
            ids.push(id);
            if ids.len() > MAX_CONNECTIONS + 256 {
                return Err(invalid("too many retained connection directories"));
            }
        }
        ids.sort();
        self.verify()?;
        Ok(ids)
    }
}

struct DirectoryPin {
    path: PathBuf,
    file: fs::File,
    identity: FileIdentity,
}

impl DirectoryPin {
    fn open(path: &Path) -> CoreResult<Self> {
        reject_link(path)?;
        let file = open_no_follow(path, true, false)?;
        if !file.metadata()?.is_dir() {
            return Err(invalid("connection storage directory is not a directory"));
        }
        let identity = file_identity(&file)?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            identity,
        })
    }

    fn verify(&self) -> CoreResult<()> {
        let current = Self::open(&self.path)?;
        if current.identity != self.identity || file_identity(&self.file)? != self.identity {
            return Err(invalid("connection storage directory identity changed"));
        }
        Ok(())
    }
}

fn protected_directory(path: &Path) -> CoreResult<DirectoryPin> {
    ensure_private_staging_directory(path)?;
    DirectoryPin::open(path)
}

fn open_regular_file(path: &Path) -> CoreResult<fs::File> {
    open_regular_file_with_acl_access(path, false)
}

fn open_catalog_file(path: &Path) -> CoreResult<fs::File> {
    // Windows' shared validator applies the protected owner-only DACL as well
    // as checking it. Both new and reopened catalog handles need those rights.
    open_regular_file_with_acl_access(path, true)
}

fn open_regular_file_with_acl_access(path: &Path, protect_acl: bool) -> CoreResult<fs::File> {
    reject_link(path)?;
    let file = open_no_follow(path, false, protect_acl)?;
    shellx_drive_desktop_core::ensure_single_linked_regular_file(&file, path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("connection state is not a regular file"));
    }
    Ok(file)
}

fn reject_link(path: &Path) -> CoreResult<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(DesktopError::UnsafeLink(path.to_path_buf()));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(DesktopError::UnsafeLink(path.to_path_buf()));
        }
    }
    Ok(())
}

fn open_no_follow(path: &Path, directory: bool, _protect_acl: bool) -> CoreResult<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(
            libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK
                | if directory { libc::O_DIRECTORY } else { 0 },
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::{
            Foundation::GENERIC_READ,
            Storage::FileSystem::{
                FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
            },
        };
        let access = if directory {
            FILE_READ_ATTRIBUTES
        } else {
            GENERIC_READ
                | if _protect_acl {
                    READ_CONTROL | WRITE_DAC | WRITE_OWNER
                } else {
                    0
                }
        };
        // OPEN_REPARSE_POINT prevents following the leaf; BACKUP_SEMANTICS opens directories.
        options
            .access_mode(access)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(
                FILE_FLAG_OPEN_REPARSE_POINT
                    | if directory {
                        FILE_FLAG_BACKUP_SEMANTICS
                    } else {
                        0
                    },
            );
    }
    let file = options.open(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if file.metadata()?.file_attributes() & 0x400 != 0 {
            return Err(DesktopError::UnsafeLink(path.to_path_buf()));
        }
    }
    Ok(file)
}

fn new_catalog_file(directory: &Path) -> std::io::Result<tempfile::NamedTempFile> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(".catalog-").suffix(".next");
    #[cfg(unix)]
    {
        builder.tempfile_in(directory)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::{
            Foundation::{GENERIC_READ, GENERIC_WRITE},
            Storage::FileSystem::{
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
                READ_CONTROL, WRITE_DAC, WRITE_OWNER,
            },
        };
        // CREATE_NEW keeps the random name exclusive. The already-protected
        // parent supplies a private inherited ACL until the validator protects
        // the file's own DACL. A generic read/write tempfile handle cannot do that.
        builder.make_in(directory, |path| {
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .access_mode(GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC | WRITE_OWNER)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)
        })
    }
}

fn persist_catalog_file(next: tempfile::NamedTempFile, destination: &Path) -> CoreResult<()> {
    #[cfg(unix)]
    {
        next.persist(destination).map_err(|error| error.error)?;
        Ok(())
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::{
            MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        };
        let source_wide = shellx_drive_desktop_core::windows_absolute_path_wide(next.path())?;
        let destination_wide = shellx_drive_desktop_core::windows_absolute_path_wide(destination)?;
        // Source and destination are in the same pinned directory. Do not
        // permit copy/delete fallback or try to flush a Windows directory handle.
        if unsafe {
            MoveFileExW(
                source_wide.as_ptr(),
                destination_wide.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut next = next;
        next.disable_cleanup(true);
        Ok(())
    }
}

#[derive(Eq, PartialEq)]
struct FileIdentity(u64, [u8; 16]);

fn file_identity(file: &fs::File) -> CoreResult<FileIdentity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        let mut id = [0; 16];
        id[..8].copy_from_slice(&metadata.ino().to_le_bytes());
        Ok(FileIdentity(metadata.dev(), id))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            FileIdInfo, GetFileInformationByHandleEx, FILE_ID_INFO,
        };
        let mut info = FILE_ID_INFO::default();
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileIdInfo,
                (&mut info as *mut FILE_ID_INFO).cast(),
                std::mem::size_of::<FILE_ID_INFO>() as u32,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(FileIdentity(
            info.VolumeSerialNumber,
            info.FileId.Identifier,
        ))
    }
}
