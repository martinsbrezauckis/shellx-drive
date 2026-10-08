//! Handle-relative cache publication for the bundled sync client.
//!
//! Remote bodies are streamed into a private temporary leaf and renamed from
//! the same already-open parent directory. Directory components are opened
//! no-follow one at a time; on Windows every ancestor is also held without
//! `FILE_SHARE_DELETE`, preventing junction substitution in the final window.

use std::{
    ffi::OsString,
    fs,
    io::{self, Read, Seek},
    path::{Component, Path, PathBuf},
};

use cap_fs_ext::DirExt;
use cap_std::{ambient_authority, fs::Dir};
use sha2::{Digest, Sha256};

#[path = "sync_client_fs/create_only_rename.rs"]
mod create_only_rename;
#[path = "sync_client_fs/recovery_usage.rs"]
mod recovery_usage;
#[cfg(unix)]
#[path = "sync_client_fs/unix_security.rs"]
mod unix_security;

pub(crate) struct SafeCacheRoot {
    path: PathBuf,
    dir: Dir,
}

impl SafeCacheRoot {
    fn open(path: &Path) -> io::Result<Self> {
        if path.as_os_str().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sync cache root must not be empty",
            ));
        }
        let mut components = path.components().peekable();
        let mut anchor = PathBuf::new();
        if path.is_absolute() {
            while components.peek().is_some_and(|component| {
                matches!(component, Component::Prefix(_) | Component::RootDir)
            }) {
                anchor.push(
                    components
                        .next()
                        .expect("peeked absolute anchor component")
                        .as_os_str(),
                );
            }
        } else {
            anchor.push(".");
        }
        let mut dir = Dir::open_ambient_dir(&anchor, ambient_authority())?;
        while let Some(component) = components.next() {
            match component {
                Component::CurDir => continue,
                Component::Normal(name) => {
                    let is_cache_root = components
                        .clone()
                        .all(|remaining| matches!(remaining, Component::CurDir));
                    let created = if is_cache_root {
                        platform::create_cache_root_entry(&dir, name)?
                    } else {
                        match dir.create_dir(name) {
                            Ok(()) => true,
                            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
                            Err(error) => return Err(error),
                        }
                    };
                    dir = if is_cache_root {
                        platform::open_cache_root_entry(&dir, name, created)?
                    } else {
                        dir.open_dir_nofollow(name)?
                    };
                }
                Component::ParentDir | Component::Prefix(_) | Component::RootDir => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "sync cache root must not contain parent traversal",
                    ));
                }
            }
        }
        platform::verify_cache_root(&dir)?;
        if !dir.dir_metadata()?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sync cache root must be a directory",
            ));
        }
        Ok(Self {
            path: path.to_path_buf(),
            dir,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Move a local body without replacing a destination the server selected
    /// or another local writer created. The source removal and destination
    /// creation must be one operation so a local writer cannot rebind the
    /// source between a link and an unlink.
    pub(crate) fn rename_new(&self, source: &Path, destination: &Path) -> io::Result<()> {
        let source = self.relative(source)?;
        let destination = self.relative(destination)?;
        create_only_rename::rename_new(self, source, destination)
    }

    pub(crate) fn regular_file_len(&self, path: &Path) -> io::Result<u64> {
        SafeCacheInput::open(self, path).map(|input| input.length())
    }

    pub(crate) fn regular_file_names(
        &self,
        directory: &Path,
        max_entries: usize,
        max_encoded_name_bytes: usize,
    ) -> io::Result<Vec<OsString>> {
        let relative = self.relative(directory)?;
        validate_relative(relative)?;
        let directory = platform::open_existing_directory(self, relative)?;
        let mut names = Vec::new();
        let mut entries_seen = 0usize;
        let mut encoded_name_bytes = 0usize;
        for entry in directory.entries()? {
            let entry = entry?;
            entries_seen = entries_seen.checked_add(1).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sync local directory entry count overflowed",
                )
            })?;
            if entries_seen > max_entries {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sync local file discovery exceeds its entry budget",
                ));
            }
            if entry.file_type()?.is_file() {
                let name = entry.file_name();
                let next_bytes = encoded_name_bytes
                    .checked_add(name.as_encoded_bytes().len())
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "sync local filename byte count overflowed",
                        )
                    })?;
                if next_bytes > max_encoded_name_bytes {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "sync local file discovery exceeds its filename budget",
                    ));
                }
                encoded_name_bytes = next_bytes;
                names.push(name);
            }
        }
        Ok(names)
    }

    pub(crate) fn is_empty(&self) -> io::Result<bool> {
        Ok(self.dir.entries()?.next().transpose()?.is_none())
    }

    fn relative<'a>(&self, path: &'a Path) -> io::Result<&'a Path> {
        let relative = path.strip_prefix(&self.path).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "sync path escapes its cache root",
            )
        })?;
        validate_relative(relative)?;
        Ok(relative)
    }
}

pub(crate) struct SafeDownloadTarget {
    file: Option<fs::File>,
    backend: Backend,
    committed: bool,
}

struct SafeCacheInput {
    file: fs::File,
    length: u64,
}

impl SafeCacheInput {
    fn open(root: &SafeCacheRoot, source: &Path) -> io::Result<Self> {
        platform::open_input(root, source)
    }

    pub(crate) fn file_mut(&mut self) -> &mut fs::File {
        &mut self.file
    }

    pub(crate) fn length(&self) -> u64 {
        self.length
    }
}

pub(crate) struct SafeLocalSnapshot {
    input: SafeCacheInput,
    hash: String,
}

impl SafeLocalSnapshot {
    pub(crate) fn open(root: &SafeCacheRoot, source: &Path, max_bytes: u64) -> io::Result<Self> {
        let input = SafeCacheInput::open(root, source)?;
        hash_snapshot(input, max_bytes)
    }

    pub(crate) fn length(&self) -> u64 {
        self.input.length()
    }

    pub(crate) fn hash(&self) -> &str {
        &self.hash
    }

    pub(crate) fn rewind(&mut self) -> io::Result<()> {
        self.input.file_mut().rewind()
    }

    pub(crate) fn file_mut(&mut self) -> &mut fs::File {
        self.input.file_mut()
    }

    pub(crate) fn read_all(&mut self) -> io::Result<Vec<u8>> {
        self.rewind()?;
        let capacity = usize::try_from(self.length())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "sync input is too large"))?;
        let read_limit = self.length().saturating_add(1);
        let mut bytes = Vec::with_capacity(capacity);
        self.file_mut().take(read_limit).read_to_end(&mut bytes)?;
        if bytes.len() != capacity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "local sync input changed while it was being read",
            ));
        }
        if hex::encode(Sha256::digest(&bytes)) != self.hash {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "local sync input changed after its snapshot was hashed",
            ));
        }
        Ok(bytes)
    }
}

fn hash_snapshot(mut input: SafeCacheInput, max_bytes: u64) -> io::Result<SafeLocalSnapshot> {
    if input.length() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("local sync input exceeds the {max_bytes}-byte upload limit"),
        ));
    }
    let expected = input.length();
    let mut read = 0_u64;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = input.file_mut().read(&mut buffer)?;
        if count == 0 {
            break;
        }
        read = read.checked_add(count as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "local sync input size overflow")
        })?;
        if read > expected || read > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "local sync input changed while it was being hashed",
            ));
        }
        hasher.update(&buffer[..count]);
    }
    if read != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "local sync input changed while it was being hashed",
        ));
    }
    input.file_mut().rewind()?;
    Ok(SafeLocalSnapshot {
        input,
        hash: hex::encode(hasher.finalize()),
    })
}

impl SafeDownloadTarget {
    pub(crate) fn begin(root: &SafeCacheRoot, destination: &Path) -> io::Result<Self> {
        platform::begin(root, destination)
    }

    pub(crate) fn file_mut(&mut self) -> &mut fs::File {
        self.file
            .as_mut()
            .expect("download target file exists until commit")
    }

    pub(crate) fn commit(mut self) -> io::Result<()> {
        self.file_mut().sync_all()?;
        platform::commit(&mut self)?;
        self.committed = true;
        Ok(())
    }

    pub(crate) fn commit_new(mut self) -> io::Result<()> {
        self.file_mut().sync_all()?;
        platform::commit_new(&mut self)?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for SafeDownloadTarget {
    fn drop(&mut self) {
        if !self.committed {
            platform::cleanup(self);
        }
    }
}

pub(crate) fn ensure_cache_root(root: &Path) -> io::Result<SafeCacheRoot> {
    SafeCacheRoot::open(root)
}

pub(crate) fn ensure_cache_directory(root: &SafeCacheRoot, relative: &Path) -> io::Result<PathBuf> {
    validate_relative(relative)?;
    platform::ensure_directory(root, relative)?;
    Ok(root.path().join(relative))
}

fn validate_relative(relative: &Path) -> io::Result<()> {
    if relative.as_os_str().is_empty() {
        return Ok(());
    }
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sync cache path must contain only normal relative components",
        ));
    }
    Ok(())
}

fn destination_parts<'a>(
    root: &SafeCacheRoot,
    destination: &'a Path,
) -> io::Result<(&'a Path, &'a std::ffi::OsStr)> {
    let relative = root.relative(destination)?;
    let leaf = relative.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "sync destination has no leaf")
    })?;
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    Ok((parent, leaf))
}

#[cfg(unix)]
struct Backend {
    parent: fs::File,
    temporary: std::ffi::CString,
    destination: std::ffi::CString,
}

#[cfg(windows)]
struct Backend {
    _pins: Vec<fs::File>,
    parent: Dir,
    temporary_leaf: OsString,
    destination_leaf: Vec<u16>,
}

#[cfg(not(any(unix, windows)))]
struct Backend;

#[cfg(unix)]
mod platform {
    use std::{
        ffi::{CString, OsStr},
        fs, io,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::ffi::OsStrExt,
        },
        path::{Component, Path},
    };

    use cap_std::fs::{Dir, DirBuilder, DirBuilderExt as _};

    use super::{
        destination_parts, unix_security, Backend, SafeCacheInput, SafeCacheRoot,
        SafeDownloadTarget,
    };

    pub(super) fn create_cache_root_entry(parent: &Dir, name: &OsStr) -> io::Result<bool> {
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        match parent.create_dir_with(name, &builder) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(super) fn open_cache_root_entry(
        parent: &Dir,
        name: &OsStr,
        _created: bool,
    ) -> io::Result<Dir> {
        let parent = parent.try_clone()?.into_std_file();
        let directory = open_child(&parent, name)?;
        unix_security::verify_directory(&directory)?;
        Ok(Dir::from_std_file(directory))
    }

    pub(super) fn verify_cache_root(dir: &Dir) -> io::Result<()> {
        unix_security::verify_directory(&dir.try_clone()?.into_std_file())
    }

    fn c_string(value: &OsStr) -> io::Result<CString> {
        CString::new(value.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "sync path contains NUL"))
    }

    fn open_child(parent: &fs::File, name: &OsStr) -> io::Result<fs::File> {
        let name = c_string(name)?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { fs::File::from_raw_fd(fd) })
        }
    }

    fn sync_directory(parent: &fs::File) -> io::Result<()> {
        let dot = c_string(OsStr::new("."))?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                dot.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        unsafe { fs::File::from_raw_fd(fd) }.sync_all()
    }

    pub(super) fn pin_directory(
        root: &SafeCacheRoot,
        relative: &Path,
        create: bool,
    ) -> io::Result<Vec<fs::File>> {
        let root_pin = root.dir.try_clone()?.into_std_file();
        unix_security::verify_directory(&root_pin)?;
        let mut pins = vec![root_pin];
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "sync path has a non-normal component",
                ));
            };
            let parent = pins.last().expect("root pin exists");
            if create {
                let name_c = c_string(name)?;
                let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name_c.as_ptr(), 0o700) };
                if result != 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::AlreadyExists {
                        return Err(error);
                    }
                }
            }
            let child = open_child(parent, name)?;
            unix_security::verify_directory(&child)?;
            pins.push(child);
        }
        Ok(pins)
    }

    pub(super) fn ensure_directory(root: &SafeCacheRoot, relative: &Path) -> io::Result<()> {
        pin_directory(root, relative, true).map(drop)
    }

    pub(super) fn open_existing_directory(
        root: &SafeCacheRoot,
        relative: &Path,
    ) -> io::Result<Dir> {
        let mut pins = pin_directory(root, relative, false)?;
        let directory = pins.pop().expect("root pin exists");
        Ok(Dir::from_std_file(directory))
    }

    pub(super) fn open_input(root: &SafeCacheRoot, source: &Path) -> io::Result<SafeCacheInput> {
        let (relative_parent, source_leaf) = destination_parts(root, source)?;
        let mut pins = pin_directory(root, relative_parent, false)?;
        let parent = pins.pop().expect("root pin exists");
        let source_leaf = c_string(source_leaf)?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                source_leaf.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { fs::File::from_raw_fd(fd) };
        let metadata = unix_security::verify_input_file(&file)?;
        Ok(SafeCacheInput {
            length: metadata.len(),
            file,
        })
    }

    pub(super) fn begin(
        root: &SafeCacheRoot,
        destination: &Path,
    ) -> io::Result<SafeDownloadTarget> {
        let (relative_parent, destination_leaf) = destination_parts(root, destination)?;
        let mut pins = pin_directory(root, relative_parent, false)?;
        let parent = pins.pop().expect("root pin exists");
        let destination = c_string(destination_leaf)?;
        for _ in 0..32 {
            let temporary = c_string(std::ffi::OsStr::new(&format!(
                ".shellx-download-{}",
                uuid::Uuid::new_v4()
            )))?;
            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    temporary.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd >= 0 {
                return Ok(SafeDownloadTarget {
                    file: Some(unsafe { fs::File::from_raw_fd(fd) }),
                    backend: Backend {
                        parent,
                        temporary,
                        destination,
                    },
                    committed: false,
                });
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a private sync download leaf",
        ))
    }

    pub(super) fn commit(target: &mut SafeDownloadTarget) -> io::Result<()> {
        let result = unsafe {
            libc::renameat(
                target.backend.parent.as_raw_fd(),
                target.backend.temporary.as_ptr(),
                target.backend.parent.as_raw_fd(),
                target.backend.destination.as_ptr(),
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        target.file.take();
        sync_directory(&target.backend.parent)?;
        Ok(())
    }

    pub(super) fn commit_new(target: &mut SafeDownloadTarget) -> io::Result<()> {
        let result = unsafe {
            libc::linkat(
                target.backend.parent.as_raw_fd(),
                target.backend.temporary.as_ptr(),
                target.backend.parent.as_raw_fd(),
                target.backend.destination.as_ptr(),
                0,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe {
            libc::unlinkat(
                target.backend.parent.as_raw_fd(),
                target.backend.temporary.as_ptr(),
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        target.file.take();
        sync_directory(&target.backend.parent)?;
        Ok(())
    }

    pub(super) fn cleanup(target: &mut SafeDownloadTarget) {
        target.file.take();
        unsafe {
            libc::unlinkat(
                target.backend.parent.as_raw_fd(),
                target.backend.temporary.as_ptr(),
                0,
            );
        }
    }
}

#[cfg(windows)]
mod platform {
    use std::{
        ffi::c_void,
        fs, io,
        mem::size_of,
        os::windows::{ffi::OsStrExt, fs::MetadataExt, io::AsRawHandle},
        path::{Component, Path},
    };

    use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
    use cap_std::fs::{Dir, OpenOptions, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FileRenameInfo, GetFinalPathNameByHandleW, SetFileInformationByHandle, DELETE,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_RENAME_INFO,
        FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
    };

    use super::{destination_parts, Backend, SafeCacheInput, SafeCacheRoot, SafeDownloadTarget};

    fn open_private_directory_handle(
        parent: &Dir,
        name: &std::ffi::OsStr,
        for_initialization: bool,
    ) -> io::Result<fs::File> {
        let mut options = OpenOptions::new();
        let access = FILE_GENERIC_READ
            | FILE_READ_ATTRIBUTES
            | if for_initialization { WRITE_DAC } else { 0 };
        options
            .access_mode(access)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .follow(FollowSymlinks::No);
        let file = parent.open_with(Path::new(name), &options)?.into_std();
        let metadata = file.metadata()?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sync cache directory must be a real non-reparse directory",
            ));
        }
        Ok(file)
    }

    fn secure_directory_handle(file: &fs::File, created: bool) -> io::Result<()> {
        if created {
            crate::fs_private::apply_private_dir_handle(file)
        } else {
            crate::fs_private::verify_private_dir_handle(file)
        }
    }

    pub(super) fn create_cache_root_entry(
        parent: &Dir,
        name: &std::ffi::OsStr,
    ) -> io::Result<bool> {
        match parent.create_dir(name) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(super) fn open_cache_root_entry(
        parent: &Dir,
        name: &std::ffi::OsStr,
        created: bool,
    ) -> io::Result<Dir> {
        let file = open_private_directory_handle(parent, name, created)?;
        secure_directory_handle(&file, created)?;
        Ok(Dir::from_std_file(file))
    }

    pub(super) fn verify_cache_root(dir: &Dir) -> io::Result<()> {
        crate::fs_private::verify_private_dir_handle(&dir.try_clone()?.into_std_file())
    }

    pub(super) fn pin_directory(
        root: &SafeCacheRoot,
        relative: &Path,
        create: bool,
    ) -> io::Result<(Vec<fs::File>, Dir)> {
        let mut current = root.dir.try_clone()?;
        let mut pins = vec![current.try_clone()?.into_std_file()];
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "sync path has a non-normal component",
                ));
            };
            let created = if create {
                match current.create_dir(name) {
                    Ok(()) => true,
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
                    Err(error) => return Err(error),
                }
            } else {
                false
            };
            let private_pin = open_private_directory_handle(&current, name, created)?;
            secure_directory_handle(&private_pin, created)?;
            let child = Dir::from_std_file(private_pin.try_clone()?);
            pins.push(private_pin);
            current = child;
        }
        Ok((pins, current))
    }

    pub(super) fn ensure_directory(root: &SafeCacheRoot, relative: &Path) -> io::Result<()> {
        pin_directory(root, relative, true).map(drop)
    }

    pub(super) fn open_existing_directory(
        root: &SafeCacheRoot,
        relative: &Path,
    ) -> io::Result<Dir> {
        pin_directory(root, relative, false).map(|(_, directory)| directory)
    }

    pub(super) fn open_input(root: &SafeCacheRoot, source: &Path) -> io::Result<SafeCacheInput> {
        let (relative_parent, source_leaf) = destination_parts(root, source)?;
        let (pins, parent) = pin_directory(root, relative_parent, false)?;
        let _pins = pins;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .access_mode(FILE_GENERIC_READ | FILE_READ_ATTRIBUTES | READ_CONTROL)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .follow(FollowSymlinks::No);
        let file = parent.open_with(source_leaf, &options)?.into_std();
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "sync input leaf must be a regular non-reparse file",
            ));
        }
        crate::fs_private::verify_private_file_handle(&file)?;
        Ok(SafeCacheInput {
            length: metadata.len(),
            file,
        })
    }

    pub(super) fn begin(
        root: &SafeCacheRoot,
        destination: &Path,
    ) -> io::Result<SafeDownloadTarget> {
        let (relative_parent, destination_leaf) = destination_parts(root, destination)?;
        let (pins, parent) = pin_directory(root, relative_parent, false)?;
        let destination_leaf = destination_leaf.encode_wide().collect::<Vec<_>>();
        for _ in 0..32 {
            let temporary_leaf =
                std::ffi::OsString::from(format!(".shellx-download-{}", uuid::Uuid::new_v4()));
            let mut options = OpenOptions::new();
            options
                .write(true)
                .create_new(true)
                .access_mode(
                    FILE_GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC,
                )
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .follow(FollowSymlinks::No);
            let result = parent.open_with(Path::new(&temporary_leaf), &options);
            match result {
                Ok(file) => {
                    let file = file.into_std();
                    if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "sync staging leaf is a reparse point",
                        ));
                    }
                    crate::fs_private::apply_private_file_handle(&file)?;
                    return Ok(SafeDownloadTarget {
                        file: Some(file),
                        backend: Backend {
                            _pins: pins,
                            parent,
                            temporary_leaf,
                            destination_leaf,
                        },
                        committed: false,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a private sync download leaf",
        ))
    }

    pub(super) fn commit(target: &mut SafeDownloadTarget) -> io::Result<()> {
        commit_with_replace(target, true)
    }

    pub(super) fn commit_new(target: &mut SafeDownloadTarget) -> io::Result<()> {
        commit_with_replace(target, false)
    }

    pub(super) fn pinned_destination_name(parent: &Dir, leaf: &[u16]) -> io::Result<Vec<u16>> {
        // Win32 rejected FileRenameInfo with RootDirectory on the native test
        // host. Derive the full name from the ACL-checked, no-delete-share
        // parent handle so the caller's original path cannot be substituted.
        let mut name = vec![0_u16; 512];
        loop {
            let length = unsafe {
                GetFinalPathNameByHandleW(
                    parent.as_raw_handle(),
                    name.as_mut_ptr(),
                    u32::try_from(name.len()).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "sync path is too large")
                    })?,
                    0,
                )
            };
            if length == 0 {
                return Err(io::Error::last_os_error());
            }
            if (length as usize) < name.len() {
                name.truncate(length as usize);
                if name.len().saturating_add(1).saturating_add(leaf.len()) > 32_767 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "sync path is too large",
                    ));
                }
                if name.last() != Some(&u16::from(b'\\')) {
                    name.push(u16::from(b'\\'));
                }
                name.extend_from_slice(leaf);
                return Ok(name);
            }
            if length > 32_767 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "sync path is too large",
                ));
            }
            name.resize(length as usize + 1, 0);
        }
    }

    fn commit_with_replace(
        target: &mut SafeDownloadTarget,
        replace_if_exists: bool,
    ) -> io::Result<()> {
        let source = target.file.as_ref().expect("download source handle exists");
        crate::fs_private::verify_private_file_handle(source)?;
        let name =
            pinned_destination_name(&target.backend.parent, &target.backend.destination_leaf)?;
        let name_size = name
            .len()
            .checked_mul(size_of::<u16>())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "sync name is too large"))?;
        let header_size = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
        let buffer_size = size_of::<FILE_RENAME_INFO>()
            .checked_add(name_size)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "sync name is too large"))?;
        let word_size = size_of::<usize>();
        let mut storage = vec![0_usize; buffer_size.div_ceil(word_size)];
        let buffer = unsafe {
            std::slice::from_raw_parts_mut(
                storage.as_mut_ptr().cast::<u8>(),
                storage.len() * word_size,
            )
        };
        let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        unsafe {
            (*info).Anonymous.ReplaceIfExists = replace_if_exists;
            (*info).RootDirectory = std::ptr::null_mut();
            (*info).FileNameLength = u32::try_from(name_size).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "sync name is too large")
            })?;
            std::ptr::copy_nonoverlapping(
                name.as_ptr().cast::<u8>(),
                buffer.as_mut_ptr().add(header_size),
                name_size,
            );
            if SetFileInformationByHandle(
                source.as_raw_handle(),
                FileRenameInfo,
                buffer.as_ptr().cast::<c_void>(),
                u32::try_from(buffer_size).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "sync name is too large")
                })?,
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        crate::fs_private::verify_private_file_handle(source)?;
        target.file.take();
        Ok(())
    }

    pub(super) fn cleanup(target: &mut SafeDownloadTarget) {
        target.file.take();
        let _ = target
            .backend
            .parent
            .remove_file(Path::new(&target.backend.temporary_leaf));
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use std::{io, path::Path};

    use super::{SafeCacheInput, SafeCacheRoot, SafeDownloadTarget};

    pub(super) fn create_cache_root_entry(
        _parent: &cap_std::fs::Dir,
        _name: &std::ffi::OsStr,
    ) -> io::Result<bool> {
        unsupported()
    }

    pub(super) fn open_cache_root_entry(
        _parent: &cap_std::fs::Dir,
        _name: &std::ffi::OsStr,
        _created: bool,
    ) -> io::Result<cap_std::fs::Dir> {
        unsupported()
    }

    pub(super) fn verify_cache_root(_dir: &cap_std::fs::Dir) -> io::Result<()> {
        unsupported()
    }

    fn unsupported<T>() -> io::Result<T> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "handle-relative sync publication is unsupported on this platform",
        ))
    }

    pub(super) fn ensure_directory(_root: &SafeCacheRoot, _relative: &Path) -> io::Result<()> {
        unsupported()
    }
    pub(super) fn open_existing_directory(
        _root: &SafeCacheRoot,
        _relative: &Path,
    ) -> io::Result<cap_std::fs::Dir> {
        unsupported()
    }
    pub(super) fn open_input(_root: &SafeCacheRoot, _source: &Path) -> io::Result<SafeCacheInput> {
        unsupported()
    }
    pub(super) fn begin(
        _root: &SafeCacheRoot,
        _destination: &Path,
    ) -> io::Result<SafeDownloadTarget> {
        unsupported()
    }
    pub(super) fn commit(_target: &mut SafeDownloadTarget) -> io::Result<()> {
        unsupported()
    }
    pub(super) fn commit_new(_target: &mut SafeDownloadTarget) -> io::Result<()> {
        unsupported()
    }
    pub(super) fn cleanup(_target: &mut SafeDownloadTarget) {}
}

#[cfg(all(test, unix))]
#[path = "sync_client_fs/unix_test_support.rs"]
pub(crate) mod unix_test_support;

#[cfg(all(test, unix))]
mod tests {
    use std::{
        io::Write,
        os::unix::fs::{symlink, PermissionsExt},
        path::Path,
    };

    use super::{
        ensure_cache_directory, ensure_cache_root, unix_test_support::private_tempdir,
        SafeDownloadTarget, SafeLocalSnapshot,
    };

    #[test]
    fn nofollow_download_rejects_substituted_parent_link() {
        let temp = private_tempdir();
        let root = temp.path().join("cache");
        let outside = temp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let cache = ensure_cache_root(&root).unwrap();
        let content = ensure_cache_directory(&cache, Path::new("workspaces/id/content")).unwrap();
        std::fs::remove_dir(&content).unwrap();
        symlink(&outside, &content).unwrap();

        let result = SafeDownloadTarget::begin(&cache, &content.join("remote-id"));
        assert!(result.is_err());
        assert!(!outside.join("remote-id").exists());
    }

    #[test]
    fn nofollow_input_rejects_a_linked_leaf() {
        let temp = private_tempdir();
        let root = temp.path().join("cache");
        let outside = temp.path().join("outside-secret");
        std::fs::write(&outside, b"secret").unwrap();
        let cache = ensure_cache_root(&root).unwrap();
        let content = ensure_cache_directory(&cache, Path::new("workspaces/id/content")).unwrap();
        let linked = content.join("tracked-id");
        symlink(&outside, &linked).unwrap();

        assert!(SafeLocalSnapshot::open(&cache, &linked, 1024).is_err());
    }

    #[test]
    fn cache_root_creation_rejects_a_linked_ancestor() {
        let temp = private_tempdir();
        let outside = temp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let linked_parent = temp.path().join("linked-parent");
        symlink(&outside, &linked_parent).unwrap();

        assert!(ensure_cache_root(&linked_parent.join("cache")).is_err());
        assert!(!outside.join("cache").exists());
    }

    #[test]
    fn handle_relative_download_atomically_replaces_only_the_target_leaf() {
        let temp = private_tempdir();
        let root = temp.path().join("cache");
        let cache = ensure_cache_root(&root).unwrap();
        let content = ensure_cache_directory(&cache, Path::new("workspaces/id/content")).unwrap();
        let destination = content.join("remote-id");
        std::fs::write(&destination, b"old").unwrap();
        let mut target = SafeDownloadTarget::begin(&cache, &destination).unwrap();
        target.file_mut().write_all(b"verified remote").unwrap();
        target.commit().unwrap();

        assert_eq!(std::fs::read(destination).unwrap(), b"verified remote");
    }

    #[test]
    fn no_replace_publication_preserves_an_existing_profile_marker() {
        let temp = private_tempdir();
        let root = temp.path().join("cache");
        let cache = ensure_cache_root(&root).unwrap();
        let destination = root.join(".shellx-drive-sync-profile.json");
        std::fs::write(&destination, b"existing").unwrap();
        let mut target = SafeDownloadTarget::begin(&cache, &destination).unwrap();
        target.file_mut().write_all(b"replacement").unwrap();

        let error = target.commit_new().unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(destination).unwrap(), b"existing");
    }

    #[test]
    fn create_only_rename_preserves_both_local_bodies_on_id_collision() {
        let temp = private_tempdir();
        let root = temp.path().join("cache");
        let cache = ensure_cache_root(&root).unwrap();
        let content = ensure_cache_directory(&cache, Path::new("content")).unwrap();
        let source = content.join("new.txt");
        let destination = content.join("remote-id");
        std::fs::write(&source, b"new local").unwrap();
        std::fs::write(&destination, b"unsynced existing").unwrap();
        let error = cache.rename_new(&source, &destination).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(source).unwrap(), b"new local");
        assert_eq!(std::fs::read(destination).unwrap(), b"unsynced existing");
    }

    #[test]
    fn create_only_rename_moves_one_local_body_and_reports_its_length() {
        let temp = private_tempdir();
        let root = temp.path().join("cache");
        let cache = ensure_cache_root(&root).unwrap();
        let content = ensure_cache_directory(&cache, Path::new("content")).unwrap();
        let source = content.join("new.txt");
        let destination = content.join("remote-id");
        std::fs::write(&source, b"new local").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();

        cache.rename_new(&source, &destination).unwrap();

        assert!(!source.exists());
        assert_eq!(cache.regular_file_len(&destination).unwrap(), 9);
        assert_eq!(std::fs::read(destination).unwrap(), b"new local");
    }

    #[test]
    fn retained_root_capability_ignores_a_rebound_cache_path() {
        let temp = private_tempdir();
        let root = temp.path().join("cache");
        let cache = ensure_cache_root(&root).unwrap();
        let content = ensure_cache_directory(&cache, Path::new("workspaces/id/content")).unwrap();
        let original = temp.path().join("original-cache");
        std::fs::rename(&root, &original).unwrap();
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(outside.join("workspaces/id/content")).unwrap();
        symlink(&outside, &root).unwrap();

        let destination = root.join("workspaces/id/content/remote-id");
        let mut target = SafeDownloadTarget::begin(&cache, &destination).unwrap();
        target.file_mut().write_all(b"verified remote").unwrap();
        target.commit().unwrap();

        assert_eq!(
            std::fs::read(original.join("workspaces/id/content/remote-id")).unwrap(),
            b"verified remote"
        );
        assert!(!outside.join("workspaces/id/content/remote-id").exists());
        assert!(content.starts_with(&root));
    }

    #[test]
    fn regular_file_enumeration_enforces_entry_and_encoded_name_budgets() {
        let temp = private_tempdir();
        let root = temp.path().join("cache");
        let cache = ensure_cache_root(&root).unwrap();
        let content = ensure_cache_directory(&cache, Path::new("workspaces/id/content")).unwrap();
        std::fs::write(content.join("a"), b"one").unwrap();
        std::fs::write(content.join("b"), b"two").unwrap();

        assert!(cache.regular_file_names(&content, 1, 16).is_err());
        assert!(cache.regular_file_names(&content, 2, 1).is_err());
        assert_eq!(cache.regular_file_names(&content, 2, 2).unwrap().len(), 2);
        std::fs::create_dir(content.join("directory")).unwrap();
        assert!(cache.regular_file_names(&content, 2, 16).is_err());
    }
}

#[cfg(all(test, unix))]
#[path = "sync_client_fs/unix_security_tests.rs"]
mod unix_security_tests;

#[cfg(all(test, windows))]
#[path = "sync_client_fs/windows_tests.rs"]
mod windows_tests;
